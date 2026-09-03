#![no_main]

//! Mining-protocol semantics target (`channels_sv2`).
//!
//! The serialization targets can only find encoding bugs. The logic that
//! decides targets, carves up the extranonce search space, builds jobs and
//! accepts or rejects shares lives in `channels_sv2`, and the specification
//! states several properties of that logic which can be checked without
//! trusting the implementation:
//!
//! - **Target from hashrate (5.3.2 / 5.3.7)**: a higher nominal hashrate
//!   yields a harder (smaller) target and a higher share rate yields an easier
//!   one; `hash_rate_from_target` inverts `hash_rate_to_target`.
//! - **Extranonce allocation (5.1, 5.1.2.1, 5.2.3)**: the full extranonce is
//!   at most 32 bytes, every allocation owns a disjoint region of the search
//!   space (no allocated prefix is a prefix of another), standard-channel
//!   prefixes span the full extranonce size, capacity is exactly honoured and
//!   released slots become reusable.
//! - **Merkle root (5.3.16)**: recomputed independently from the coinbase
//!   built as `prefix + extranonce + suffix`, invariant under moving the
//!   prefix/extranonce boundary, and refused for non-coinbase transactions.
//! - **Channel lifecycle (5.3.2, 5.3.5, 5.3.7, 5.3.11-5.3.17, 7.2)**: an open
//!   channel's target never exceeds the requested maximum, a future job built
//!   from a template reconstructs into a coinbase that honours the template,
//!   `SetNewPrevHash` only activates a known future job, and every submitted
//!   share is accepted or rejected exactly as an independent header-hash
//!   computation says it should be, with share accounting matching.

use arbitrary::Arbitrary;
use binary_sv2::{Seq0255Owned, B032Owned, U256Owned};
use bitcoin::{
    absolute::LockTime,
    block::{Header as BlockHeader, Version as BlockVersion},
    consensus,
    hashes::{sha256d, Hash},
    transaction::{OutPoint, TxIn, TxOut, Version as TxVersion},
    Amount, BlockHash, CompactTarget, ScriptBuf, Sequence, Target, Transaction, TxMerkleNode,
    Witness,
};
use channels_sv2::{
    extranonce_manager::{
        bytes_needed, AllocatedExtranoncePrefix, ExtranonceAllocator, ExtranonceAllocatorError,
        MAX_EXTRANONCE_LEN,
    },
    merkle_root::{merkle_root_from_path, merkle_root_from_path_},
    server::{
        error::ExtendedChannelError,
        extended::ExtendedChannel,
        share_accounting::{ShareValidationError, ShareValidationResult},
    },
    target::{hash_rate_from_target, hash_rate_to_target},
    MAX_FUTURE_BLOCK_TIME, VERSION_ROLLING_MASK,
};
use libfuzzer_sys::fuzz_target;
use mining_sv2::SubmitSharesExtendedOwned;
use template_distribution_sv2::{NewTemplateOwned, SetNewPrevHashOwned};

const CHANNEL_ID: u32 = 7;
/// Difficulty-1 compact target (mainnet genesis). Blocks are ~2^-32 per share,
/// so `BlockFound` stays reachable without dominating.
const NBITS: u32 = 0x1d00_ffff;
const MAX_SCRIPT_SIG: usize = 100;

// ---------------------------------------------------------------------------
// Input model
// ---------------------------------------------------------------------------

#[derive(Arbitrary, Debug)]
struct TargetInput {
    hashrate_a: f32,
    hashrate_b: f32,
    shares_per_min: f32,
}

#[derive(Arbitrary, Debug)]
struct AllocatorInput {
    upstream_prefix: Vec<u8>,
    local_prefix: Vec<u8>,
    total_len: u8,
    max_channels: u8,
    min_rollable: u8,
    release_index: u8,
}

#[derive(Arbitrary, Debug)]
struct MerkleInput {
    tx_version: i32,
    script_prefix: Vec<u8>,
    extranonce: Vec<u8>,
    script_suffix: Vec<u8>,
    outputs: Vec<(u64, Vec<u8>)>,
    path: Vec<[u8; 32]>,
    shift: u8,
}

#[derive(Arbitrary, Debug)]
struct ShareInput {
    nonce: u32,
    /// Offset from the chain tip's `header_timestamp`.
    ntime_offset: i16,
    /// XOR-ed into the job version; masked according to `version_mode`.
    version_xor: u32,
    /// 0: untouched, 1: general-purpose bits only, 2: any bits.
    version_mode: u8,
    sequence_number: u32,
    extranonce: Vec<u8>,
    wrong_job_id: bool,
    wrong_extranonce_len: bool,
    /// Re-submit the previous share verbatim.
    repeat_previous: bool,
}

#[derive(Arbitrary, Debug)]
struct ChannelInput {
    local_prefix: Vec<u8>,
    rollable: u8,
    version_rolling_allowed: bool,
    max_target_le: [u8; 32],
    job_target_le: [u8; 32],
    hashrate: f32,
    shares_per_min: f32,
    template_id: u64,
    version: u32,
    coinbase_prefix: Vec<u8>,
    input_sequence: u32,
    value_remaining: u64,
    locktime: u32,
    template_output_script: Vec<u8>,
    reward_script: Vec<u8>,
    path: Vec<[u8; 32]>,
    prev_hash: [u8; 32],
    header_timestamp: u32,
    shares: Vec<ShareInput>,
    update_hashrate: f32,
    update_max_target_le: Option<[u8; 32]>,
}

#[derive(Arbitrary, Debug)]
enum FuzzInput {
    Target(TargetInput),
    Allocator(AllocatorInput),
    Merkle(MerkleInput),
    Channel(ChannelInput),
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn cap(v: &[u8], n: usize) -> Vec<u8> {
    v[..v.len().min(n)].to_vec()
}

/// Finite, non-negative float within `[lo, hi]`, else `None`.
fn sane(x: f32, lo: f64, hi: f64) -> Option<f64> {
    let x = x as f64;
    if !x.is_finite() || x.is_sign_negative() || x < lo || x > hi {
        None
    } else {
        Some(x)
    }
}

fn dsha256(bytes: &[u8]) -> [u8; 32] {
    sha256d::Hash::hash(bytes).to_byte_array()
}

fn fold_merkle(mut root: [u8; 32], path: &[[u8; 32]]) -> [u8; 32] {
    for node in path {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&root);
        buf.extend_from_slice(node);
        root = dsha256(&buf);
    }
    root
}

fn u256(bytes: [u8; 32]) -> U256Owned {
    bytes.into()
}

fn path_seq(path: &[[u8; 32]]) -> Seq0255Owned<U256Owned> {
    path.iter()
        .map(|n| u256(*n))
        .collect::<Vec<_>>()
        .try_into()
        .expect("path capped below 255")
}

fn is_prefix_free(a: &[u8], b: &[u8]) -> bool {
    !a.starts_with(b) && !b.starts_with(a)
}

// ---------------------------------------------------------------------------
// Section 1: hashrate <-> target
// ---------------------------------------------------------------------------

fn check_target(input: TargetInput) {
    let Some(spm) = sane(input.shares_per_min, 1e-3, 1e4) else {
        return;
    };
    let (Some(ha), Some(hb)) = (
        sane(input.hashrate_a, 0.0, 1e30),
        sane(input.hashrate_b, 0.0, 1e30),
    ) else {
        return;
    };

    let ta = hash_rate_to_target(ha, spm).expect("valid inputs");
    let tb = hash_rate_to_target(hb, spm).expect("valid inputs");
    if ha <= hb {
        assert!(
            ta >= tb,
            "more hashrate must not yield an easier target: {ha} -> {ta:?}, {hb} -> {tb:?}"
        );
    } else {
        assert!(
            ta <= tb,
            "less hashrate must not yield a harder target: {ha} -> {ta:?}, {hb} -> {tb:?}"
        );
    }
    assert_ne!(ta, Target::ZERO, "target must never be zero");

    let easier = hash_rate_to_target(ha, spm * 2.0).expect("valid inputs");
    assert!(easier >= ta, "more shares per minute must not yield a harder target");

    // Inverse relation on the domain where integer truncation is negligible.
    let hs = ha * 60.0 / spm;
    if (1e6..=1e30).contains(&hs) && spm <= 100.0 {
        let back = hash_rate_from_target(u256(ta.to_le_bytes()), spm)
            .expect("target derived from a hashrate is invertible");
        let rel = (back - ha).abs() / ha;
        assert!(
            rel <= 0.025,
            "hash_rate_from_target(hash_rate_to_target({ha}, {spm})) = {back}, relative error {rel}"
        );
    }

    // Negative or zero share rates must be refused, not produce a target.
    assert!(hash_rate_to_target(ha, 0.0).is_err());
    assert!(hash_rate_to_target(ha, -spm).is_err());
    assert!(hash_rate_to_target(-1.0, spm).is_err());
}

// ---------------------------------------------------------------------------
// Section 2: extranonce allocation
// ---------------------------------------------------------------------------

fn check_allocator(input: AllocatorInput) {
    let upstream = cap(&input.upstream_prefix, 40);
    let local = cap(&input.local_prefix, 40);
    let total = input.total_len % 48;
    let max_channels = input.max_channels as u32;

    let index_len = bytes_needed(max_channels);
    let prefix_len = upstream.len() + local.len() + index_len as usize;
    let expect_err = total > MAX_EXTRANONCE_LEN || max_channels == 0 || prefix_len > total as usize;

    let mut alloc = match ExtranonceAllocator::from_upstream_prefix(
        upstream.clone(),
        local.clone(),
        total,
        max_channels,
    ) {
        Err(e) => {
            assert!(expect_err, "valid allocator configuration rejected: {e:?}");
            return;
        }
        Ok(alloc) => {
            assert!(
                !expect_err,
                "invalid allocator configuration accepted: total={total} max_channels={max_channels} prefix_len={prefix_len}"
            );
            alloc
        }
    };

    assert_eq!(alloc.upstream_prefix(), &upstream[..]);
    assert_eq!(alloc.local_prefix(), &local[..]);
    assert_eq!(alloc.upstream_prefix_len() as usize, upstream.len());
    assert_eq!(alloc.local_prefix_len() as usize, local.len());
    assert_eq!(alloc.local_index_len(), index_len);
    assert_eq!(alloc.full_prefix_len() as usize, prefix_len);
    assert_eq!(alloc.total_extranonce_len(), total);
    assert_eq!(
        alloc.rollable_extranonce_size() as usize + prefix_len,
        total as usize,
        "prefix + rollable must equal the full extranonce (spec 5.1.2.1)"
    );
    assert!(alloc.max_channels() >= max_channels);
    assert_eq!(alloc.allocated_count(), 0);

    let rollable = alloc.rollable_extranonce_size();
    if rollable < u8::MAX {
        assert!(
            matches!(
                alloc.allocate_extended(rollable as usize + 1),
                Err(ExtranonceAllocatorError::InvalidRollableSize)
            ),
            "requesting more rollable bytes than exist must be refused (spec 5.3.4)"
        );
        assert_eq!(alloc.allocated_count(), 0, "a refused request must not consume a slot");
    }

    let mut live: Vec<(Vec<u8>, AllocatedExtranoncePrefix)> = Vec::new();
    let rounds = max_channels.min(64);
    for i in 0..rounds {
        let standard = (i + input.min_rollable as u32) % 3 == 0;
        let allocated = if standard {
            alloc.allocate_standard()
        } else {
            alloc.allocate_extended(input.min_rollable as usize % (rollable as usize + 1))
        }
        .unwrap_or_else(|e| panic!("allocation {i} of {max_channels} failed: {e:?}"));

        let bytes = allocated.as_bytes().to_vec();
        assert_eq!(allocated.len(), bytes.len());
        assert_eq!(allocated.upstream_prefix_len() as usize, upstream.len());
        assert!(bytes.len() <= MAX_EXTRANONCE_LEN as usize, "extranonce prefix over 32 bytes");
        assert!(bytes.starts_with(&upstream), "upstream bytes must be preserved (spec 5.1.2.1)");
        assert!(bytes[upstream.len()..].starts_with(&local));
        let expected_len = if standard { total as usize } else { prefix_len };
        assert_eq!(
            bytes.len(),
            expected_len,
            "{} channel prefix length (spec 5.2.3)",
            if standard { "standard" } else { "extended" }
        );
        for (other, _) in &live {
            assert!(
                is_prefix_free(&bytes, other),
                "overlapping search space: {bytes:02x?} vs {other:02x?} (spec 5.1)"
            );
        }
        live.push((bytes, allocated));
        assert_eq!(alloc.allocated_count(), i + 1);
    }

    if max_channels <= 64 {
        assert!(
            matches!(alloc.allocate_extended(0), Err(ExtranonceAllocatorError::CapacityExhausted)),
            "more than max_channels extended allocations"
        );
        assert!(
            matches!(alloc.allocate_standard(), Err(ExtranonceAllocatorError::CapacityExhausted)),
            "more than max_channels standard allocations"
        );
        assert_eq!(alloc.allocated_count(), rounds);
    }

    if !live.is_empty() {
        let idx = input.release_index as usize % live.len();
        let (freed, allocation) = live.remove(idx);
        drop(allocation);
        assert_eq!(
            alloc.allocated_count(),
            live.len() as u32,
            "dropping an allocation must free its slot"
        );
        let again = alloc.allocate_extended(0).expect("a freed slot must be reusable");
        let bytes = again.as_bytes().to_vec();
        for (other, _) in &live {
            assert!(is_prefix_free(&bytes, other), "reused slot overlaps a live allocation");
        }
        if max_channels <= 64 {
            assert_eq!(
                &bytes[..prefix_len],
                &freed[..prefix_len],
                "only the released slot was free"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Section 3: merkle root
// ---------------------------------------------------------------------------

fn coinbase_tx(version: i32, script_sig: Vec<u8>, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: TxVersion(version),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(script_sig),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    }
}

fn check_merkle(input: MerkleInput) {
    let prefix = cap(&input.script_prefix, 30);
    let extranonce = cap(&input.extranonce, 32);
    let suffix = cap(&input.script_suffix, 30);
    let path: Vec<[u8; 32]> = input.path.into_iter().take(16).collect();
    let outputs: Vec<TxOut> = input
        .outputs
        .iter()
        .take(4)
        .map(|(value, script)| TxOut {
            value: Amount::from_sat(value % 2_100_000_000_000_000),
            script_pubkey: ScriptBuf::from_bytes(cap(script, 40)),
        })
        .collect();

    let mut script_sig = prefix.clone();
    script_sig.extend_from_slice(&extranonce);
    script_sig.extend_from_slice(&suffix);
    let tx = coinbase_tx(input.tx_version, script_sig, outputs);
    let serialized = consensus::serialize(&tx);

    // version(4) + vin count(1) + outpoint(36) + script length varint(1, length < 0xfd)
    let split = 4 + 1 + 36 + 1 + prefix.len();
    assert_eq!(&serialized[split..split + extranonce.len()], &extranonce[..]);
    let tx_prefix = &serialized[..split];
    let tx_suffix = &serialized[split + extranonce.len()..];

    let txid = dsha256(&serialized);
    assert_eq!(txid, tx.compute_txid().to_byte_array());
    let expected = fold_merkle(txid, &path);

    assert_eq!(
        merkle_root_from_path(tx_prefix, tx_suffix, &extranonce, &path),
        Some(expected),
        "merkle root disagrees with the spec 5.3.16 computation"
    );
    assert_eq!(merkle_root_from_path_(txid, &path), expected);
    assert_eq!(
        merkle_root_from_path_(txid, &[] as &[[u8; 32]]),
        txid,
        "empty path yields the txid"
    );

    // Moving the prefix/extranonce boundary does not change the coinbase.
    let shift = input.shift as usize % (extranonce.len() + 1);
    let (moved, rest) = extranonce.split_at(shift);
    let mut shifted_prefix = tx_prefix.to_vec();
    shifted_prefix.extend_from_slice(moved);
    assert_eq!(
        merkle_root_from_path(&shifted_prefix, tx_suffix, rest, &path),
        Some(expected),
        "merkle root depends on where the prefix/extranonce split falls"
    );

    // One more path node folds exactly once more.
    let extra = [0x11u8; 32];
    let mut longer = path.clone();
    longer.push(extra);
    let mut buf = expected.to_vec();
    buf.extend_from_slice(&extra);
    assert_eq!(merkle_root_from_path_(txid, &longer), dsha256(&buf));

    // A transaction that is not a coinbase must be refused.
    let mut not_coinbase = tx.clone();
    not_coinbase.input[0].previous_output.vout = 0;
    let bad = consensus::serialize(&not_coinbase);
    assert_eq!(
        merkle_root_from_path(&bad[..split], &bad[split + extranonce.len()..], &extranonce, &path),
        None,
        "non-coinbase transaction accepted as coinbase"
    );
}

// ---------------------------------------------------------------------------
// Section 4: channel lifecycle
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq)]
enum Expected {
    Accept { block: bool },
    Duplicate,
    Reject,
    RejectExactly(&'static str),
}

struct Job {
    job_id: u32,
    version: u32,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
    path: Vec<[u8; 32]>,
    extranonce_prefix: Vec<u8>,
    rollable: usize,
    target: Target,
    prev_hash: [u8; 32],
    min_ntime: u32,
}

fn share_hash(job: &Job, share: &SubmitSharesExtendedOwned) -> BlockHash {
    let mut coinbase = job.prefix.clone();
    coinbase.extend_from_slice(&job.extranonce_prefix);
    coinbase.extend_from_slice(share.extranonce.as_bytes());
    coinbase.extend_from_slice(&job.suffix);
    let root = fold_merkle(dsha256(&coinbase), &job.path);
    BlockHeader {
        version: BlockVersion::from_consensus(share.version as i32),
        prev_blockhash: BlockHash::from_byte_array(job.prev_hash),
        merkle_root: TxMerkleNode::from_byte_array(root),
        time: share.ntime,
        bits: CompactTarget::from_consensus(NBITS),
        nonce: share.nonce,
    }
    .block_hash()
}

fn check_channel(input: ChannelInput) {
    let Some(spm) = sane(input.shares_per_min, 1e-3, 1e4) else {
        return;
    };
    // The channel stores `expected_share_per_minute` as f32 and recomputes
    // targets from it, so mirror that precision when predicting targets.
    let spm = (spm as f32) as f64;
    if !input.hashrate.is_finite() {
        return;
    }
    let local_prefix = cap(&input.local_prefix, 12);
    let rollable = (input.rollable % 16) as usize;
    let total = local_prefix.len() + 1 + rollable;
    if total > MAX_EXTRANONCE_LEN as usize {
        return;
    }
    let mut allocator = ExtranonceAllocator::new(local_prefix, total as u8, 4).unwrap();
    let prefix = allocator.allocate_extended(rollable).unwrap();
    assert_eq!(allocator.rollable_extranonce_size() as usize, rollable);
    let extranonce_prefix = prefix.as_bytes().to_vec();
    let max_target = Target::from_le_bytes(input.max_target_le);
    let vra = input.version_rolling_allowed;

    // --- Open (spec 5.3.4 / 5.3.5) -----------------------------------------
    let open = ExtendedChannel::new_for_pool(
        CHANNEL_ID,
        "user".to_string(),
        prefix,
        max_target,
        input.hashrate,
        vra,
        rollable as u16,
        4,
        spm as f32,
        "tag".to_string(),
    );
    // The channel opens iff the nominal hashrate yields a target; that is the
    // implementation's own gate, so mirror it rather than imposing a stricter
    // finiteness rule (the target math tolerates non-finite hashrates).
    let hashrate_ok = hash_rate_to_target(input.hashrate as f64, spm).is_ok();
    let mut channel = match open {
        Ok(channel) => {
            assert!(hashrate_ok, "channel opened with a hashrate that has no target: {}", input.hashrate);
            channel
        }
        Err(ExtendedChannelError::OpenChannelInvalidNominalHashrate(_)) => {
            assert!(!hashrate_ok, "nominal hashrate with a valid target refused: {}", input.hashrate);
            return;
        }
        // JobFactory constraints (e.g. scriptSig budget) are out of scope here.
        Err(_) => return,
    };
    let expected_target = hash_rate_to_target(input.hashrate as f64, spm)
        .unwrap()
        .min(max_target);
    assert_eq!(*channel.get_target(), expected_target, "initial target");
    assert!(*channel.get_target() <= max_target, "target above max_target (spec 5.3.2)");
    assert_eq!(*channel.get_requested_max_target(), max_target);
    assert_eq!(channel.get_channel_id(), CHANNEL_ID);
    assert_eq!(channel.get_extranonce_prefix(), &extranonce_prefix[..]);
    assert_eq!(channel.get_rollable_extranonce_size() as usize, rollable);
    assert_eq!(
        channel.get_full_extranonce_size(),
        extranonce_prefix.len() + rollable,
        "full extranonce = prefix + extranonce (spec 5.3.16)"
    );
    assert_eq!(channel.get_nominal_hashrate(), input.hashrate);
    assert!(channel.get_active_job().is_none());
    assert!(channel.get_chain_tip().is_none());

    // --- Template -> future job (spec 7.2, 5.3.16) --------------------------
    let coinbase_prefix = cap(&input.coinbase_prefix, 8);
    let template_output = TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(cap(&input.template_output_script, 40)),
    };
    let reward_output = TxOut {
        value: Amount::from_sat(input.value_remaining),
        script_pubkey: ScriptBuf::from_bytes(cap(&input.reward_script, 40)),
    };
    let path: Vec<[u8; 32]> = input.path.into_iter().take(8).collect();
    let template = NewTemplateOwned {
        template_id: input.template_id,
        future_template: true,
        version: input.version,
        coinbase_tx_version: 2,
        coinbase_prefix: coinbase_prefix.clone().try_into().unwrap(),
        coinbase_tx_input_sequence: input.input_sequence,
        coinbase_tx_value_remaining: input.value_remaining,
        coinbase_tx_outputs_count: 1,
        coinbase_tx_outputs: consensus::serialize(&template_output).try_into().unwrap(),
        coinbase_tx_locktime: input.locktime,
        merkle_path: path_seq(&path),
    };

    // Reward outputs that do not sum to coinbase_tx_value_remaining must be refused.
    if let Some(too_much) = input.value_remaining.checked_add(1) {
        let mut bad = reward_output.clone();
        bad.value = Amount::from_sat(too_much);
        assert!(
            channel.on_new_template(template.clone(), vec![bad]).is_err(),
            "reward outputs exceeding coinbase_tx_value_remaining accepted (spec 7.2)"
        );
        assert!(channel.get_future_job_id_from_template_id(input.template_id).is_none());
    }

    if channel
        .on_new_template(template.clone(), vec![reward_output.clone()])
        .is_err()
    {
        // JobFactory may reject e.g. an oversize scriptSig budget; nothing more to check.
        return;
    }
    assert!(channel.get_active_job().is_none(), "a future template must not activate a job");
    let job_id = channel
        .get_future_job_id_from_template_id(input.template_id)
        .expect("future job registered under its template id");
    let future = channel.get_future_job(job_id).expect("future job retrievable").clone();
    assert!(future.is_future());
    assert_eq!(future.get_job_id(), job_id);
    assert_eq!(future.get_version(), input.version, "job version must be the template version");
    assert_eq!(future.version_rolling_allowed(), vra);
    assert_eq!(future.get_extranonce_prefix(), &extranonce_prefix[..]);

    let msg = future.get_job_message().clone();
    assert_eq!(msg.channel_id, CHANNEL_ID);
    assert_eq!(msg.job_id, job_id);
    assert_eq!(msg.version, input.version);
    assert_eq!(msg.version_rolling_allowed, vra);
    assert!(msg.min_ntime.clone().into_inner().is_none(), "future job must have empty min_ntime");
    let msg_path: Vec<[u8; 32]> = msg
        .merkle_path
        .as_slice()
        .iter()
        .map(|n| n.clone().into_array())
        .collect();
    assert_eq!(msg_path, path, "merkle path must be forwarded unchanged");
    let job_prefix = msg.coinbase_tx_prefix.as_bytes().to_vec();
    let job_suffix = msg.coinbase_tx_suffix.as_bytes().to_vec();
    assert_eq!(
        future.get_coinbase_tx_prefix_without_bip141(),
        job_prefix,
        "validation prefix differs from the prefix sent to the miner"
    );
    assert_eq!(future.get_coinbase_tx_suffix_without_bip141(), job_suffix);

    // The coinbase reconstructed with a full-size extranonce must honour the template.
    let full_size = channel.get_full_extranonce_size();
    let mut coinbase = job_prefix.clone();
    coinbase.extend(std::iter::repeat(0u8).take(full_size));
    coinbase.extend_from_slice(&job_suffix);
    let tx: Transaction = consensus::deserialize(&coinbase)
        .expect("prefix + extranonce + suffix must be a transaction");
    assert!(tx.is_coinbase(), "job coinbase is not a coinbase transaction");
    assert_eq!(tx.version, TxVersion(2), "coinbase_tx_version not honoured");
    assert_eq!(
        tx.lock_time,
        LockTime::from_consensus(input.locktime),
        "coinbase_tx_locktime not honoured"
    );
    assert_eq!(tx.input.len(), 1);
    assert_eq!(
        tx.input[0].sequence,
        Sequence(input.input_sequence),
        "coinbase_tx_input_sequence not honoured"
    );
    let script_sig = tx.input[0].script_sig.as_bytes();
    assert!(script_sig.len() <= MAX_SCRIPT_SIG, "scriptSig longer than 100 bytes");
    assert!(
        script_sig.starts_with(&coinbase_prefix),
        "coinbase_prefix must lead the scriptSig (spec 7.2)"
    );
    assert!(
        script_sig.ends_with(&vec![0u8; full_size]),
        "the extranonce must be the trailing scriptSig bytes"
    );
    assert_eq!(tx.output.first(), Some(&reward_output), "reward outputs must come first (spec 6.3)");
    assert_eq!(tx.output.last(), Some(&template_output), "template outputs must follow (spec 7.2)");
    let out_sum: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    assert_eq!(out_sum, input.value_remaining, "coinbase value must equal coinbase_tx_value_remaining");

    // --- SetNewPrevHash (spec 5.3.17, 7.3) -----------------------------------
    let job_target = Target::from_le_bytes(input.job_target_le);
    channel.set_target(job_target);
    assert_eq!(*channel.get_target(), job_target);
    let network_target = Target::from_compact(CompactTarget::from_consensus(NBITS));
    let prev_hash = SetNewPrevHashOwned {
        template_id: input.template_id,
        prev_hash: u256(input.prev_hash),
        header_timestamp: input.header_timestamp,
        n_bits: NBITS,
        target: u256(network_target.to_le_bytes()),
    };
    let mut unknown = prev_hash.clone();
    unknown.template_id = input.template_id.wrapping_add(1);
    assert!(
        matches!(
            channel.on_set_new_prev_hash(unknown),
            Err(ExtendedChannelError::TemplateIdNotFound)
        ),
        "SetNewPrevHash for an unknown template must be refused (spec 5.3.17)"
    );
    assert!(channel.get_active_job().is_none());
    channel.on_set_new_prev_hash(prev_hash).expect("activate the future job");
    let active = channel.get_active_job().expect("job activated").clone();
    assert_eq!(active.get_job_id(), job_id);
    assert!(!active.is_future());
    assert_eq!(active.get_min_ntime().into_inner(), Some(input.header_timestamp));
    let tip = channel.get_chain_tip().expect("chain tip set").clone();
    assert_eq!(tip.min_ntime(), input.header_timestamp);
    assert_eq!(tip.nbits(), NBITS);
    assert_eq!(tip.prev_hash().into_array(), input.prev_hash);

    let job = Job {
        job_id,
        version: input.version,
        prefix: job_prefix,
        suffix: job_suffix,
        path,
        extranonce_prefix: extranonce_prefix.clone(),
        rollable,
        target: job_target,
        prev_hash: input.prev_hash,
        min_ntime: input.header_timestamp,
    };

    // --- Shares (spec 5.3.11 / 5.3.12 / 5.3.14 / 5.3.16) ----------------------
    let mut accepted = 0u32;
    let mut rejected = 0u32;
    let mut blocks = 0u32;
    let mut last_accepted_seq = channel.get_share_accounting().get_last_share_sequence_number();
    let mut seen: Vec<BlockHash> = Vec::new();
    let mut previous: Option<SubmitSharesExtendedOwned> = None;

    for s in input.shares.into_iter().take(24) {
        let share = match (&previous, s.repeat_previous) {
            (Some(prev), true) => prev.clone(),
            _ => {
                let mut extranonce = cap(&s.extranonce, 32);
                extranonce.resize(job.rollable, 0);
                if s.wrong_extranonce_len {
                    if extranonce.len() < 32 {
                        extranonce.push(0);
                    } else {
                        extranonce.pop();
                    }
                }
                let version = match s.version_mode % 3 {
                    0 => job.version,
                    1 => job.version ^ (s.version_xor & VERSION_ROLLING_MASK),
                    _ => job.version ^ s.version_xor,
                };
                SubmitSharesExtendedOwned {
                    channel_id: CHANNEL_ID,
                    sequence_number: s.sequence_number,
                    job_id: if s.wrong_job_id {
                        job.job_id.wrapping_add(1)
                    } else {
                        job.job_id
                    },
                    nonce: s.nonce,
                    ntime: job.min_ntime.wrapping_add_signed(s.ntime_offset as i32),
                    version,
                    extranonce: B032Owned::try_from(extranonce).unwrap(),
                }
            }
        };
        previous = Some(share.clone());

        // Independent verdict.
        let mut reasons: Vec<&'static str> = Vec::new();
        if share.job_id != job.job_id {
            reasons.push("invalid-job-id");
        }
        if share.extranonce.len() != job.rollable {
            reasons.push("bad-extranonce-size");
        }
        if share.ntime < job.min_ntime
            || share.ntime > job.min_ntime.saturating_add(MAX_FUTURE_BLOCK_TIME)
        {
            reasons.push("invalid-share");
        }
        if share.version != job.version {
            if !vra {
                reasons.push("version-rolling-not-allowed");
            } else if (share.version & !VERSION_ROLLING_MASK)
                != (job.version & !VERSION_ROLLING_MASK)
            {
                reasons.push("invalid-non-rollable-version-bit");
            }
        }
        let expected = if !reasons.is_empty() {
            if reasons.len() == 1 {
                Expected::RejectExactly(reasons[0])
            } else {
                Expected::Reject
            }
        } else {
            let hash = share_hash(&job, &share);
            let meets_job = Target::from_le_bytes(hash.to_byte_array()) <= job.target;
            let meets_network = network_target.is_met_by(hash);
            if meets_job || meets_network {
                if seen.contains(&hash) {
                    Expected::Duplicate
                } else {
                    seen.push(hash);
                    Expected::Accept { block: meets_network }
                }
            } else {
                Expected::RejectExactly("difficulty-too-low")
            }
        };

        let result = channel.validate_share(share.clone());
        match (&expected, &result) {
            (Expected::Accept { block: false }, Ok(ShareValidationResult::Valid(hash))) => {
                assert_eq!(hash.to_byte_array(), share_hash(&job, &share).to_byte_array());
                accepted += 1;
                last_accepted_seq = share.sequence_number;
            }
            (
                Expected::Accept { block: true },
                Ok(ShareValidationResult::BlockFound(hash, tid, coinbase)),
            ) => {
                assert_eq!(hash.to_byte_array(), share_hash(&job, &share).to_byte_array());
                assert_eq!(*tid, Some(input.template_id));
                let tx: Transaction = consensus::deserialize(coinbase).expect("block coinbase");
                assert!(tx.is_coinbase());
                accepted += 1;
                blocks += 1;
                last_accepted_seq = share.sequence_number;
            }
            (Expected::Duplicate, Err(ShareValidationError::DuplicateShare(_))) => rejected += 1,
            (Expected::Reject, Err(_)) => rejected += 1,
            (Expected::RejectExactly(code), Err(err)) => {
                let got = match err {
                    ShareValidationError::Invalid(c)
                    | ShareValidationError::Stale(c)
                    | ShareValidationError::InvalidJobId(c)
                    | ShareValidationError::DoesNotMeetTarget(c)
                    | ShareValidationError::VersionRollingNotAllowed(c)
                    | ShareValidationError::DuplicateShare(c)
                    | ShareValidationError::BadExtranonceSize(c) => *c,
                    other => panic!("unexpected rejection {other:?} for share {share:?}"),
                };
                assert_eq!(got, *code, "wrong rejection reason for share {share:?}");
                rejected += 1;
            }
            _ => panic!("expected {expected:?}, got {result:?} for share {share:?}"),
        }

        let acc = channel.get_share_accounting();
        assert_eq!(acc.get_shares_accepted(), accepted, "accepted share count");
        assert_eq!(acc.get_rejected_shares_count(), rejected, "rejected share count");
        assert_eq!(acc.get_blocks_found(), blocks, "blocks found count");
        assert_eq!(
            acc.get_last_share_sequence_number(),
            last_accepted_seq,
            "last accepted sequence number (spec 5.3.13)"
        );
    }

    // --- A new chain tip without future jobs makes the job stale (5.3.17) -----
    let next_tip = SetNewPrevHashOwned {
        template_id: input.template_id.wrapping_add(2),
        prev_hash: u256([0xAA; 32]),
        header_timestamp: input.header_timestamp,
        n_bits: NBITS,
        target: u256(network_target.to_le_bytes()),
    };
    channel.on_set_new_prev_hash(next_tip).expect("a chain tip with no future jobs is accepted");
    assert!(
        channel.get_active_job().is_none(),
        "no job may stay active across a chain tip without a matching future job"
    );
    let stale_share = SubmitSharesExtendedOwned {
        channel_id: CHANNEL_ID,
        sequence_number: u32::MAX,
        job_id: job.job_id,
        nonce: 0,
        ntime: job.min_ntime,
        version: job.version,
        extranonce: B032Owned::try_from(vec![0u8; job.rollable]).unwrap(),
    };
    assert!(
        matches!(
            channel.validate_share(stale_share),
            Err(ShareValidationError::Stale(_))
        ),
        "share on a job from a previous chain tip must be stale"
    );

    // --- UpdateChannel (spec 5.3.7) ----------------------------------------------
    if !input.update_hashrate.is_finite() {
        return;
    }
    let requested = input.update_max_target_le.map(Target::from_le_bytes);
    let before = *channel.get_target();
    let before_max = *channel.get_requested_max_target();
    let update_ok = hash_rate_to_target(input.update_hashrate as f64, spm).is_ok();
    match channel.update_channel(input.update_hashrate, requested) {
        Ok(()) => {
            assert!(update_ok, "UpdateChannel accepted hashrate {}", input.update_hashrate);
            let max = requested.unwrap_or(before_max);
            let expected = hash_rate_to_target(input.update_hashrate as f64, spm).unwrap().min(max);
            assert_eq!(*channel.get_target(), expected, "target after UpdateChannel");
            assert!(*channel.get_target() <= max, "target above the requested maximum (spec 5.3.7)");
            assert_eq!(*channel.get_requested_max_target(), max);
            assert_eq!(channel.get_nominal_hashrate(), input.update_hashrate);
        }
        Err(ExtendedChannelError::UpdateChannelInvalidNominalHashrate(_)) => {
            assert!(!update_ok, "valid UpdateChannel hashrate {} refused", input.update_hashrate);
            assert_eq!(*channel.get_target(), before, "a refused update must not change the target");
            assert_eq!(*channel.get_requested_max_target(), before_max);
        }
        Err(e) => panic!("unexpected UpdateChannel error: {e:?}"),
    }
}

fuzz_target!(|input: FuzzInput| match input {
    FuzzInput::Target(i) => check_target(i),
    FuzzInput::Allocator(i) => check_allocator(i),
    FuzzInput::Merkle(i) => check_merkle(i),
    FuzzInput::Channel(i) => check_channel(i),
});
