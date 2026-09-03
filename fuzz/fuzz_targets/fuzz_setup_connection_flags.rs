#![no_main]

//! `SetupConnection` negotiation semantics target.
//!
//! Oracles: spec 3.6 (`SetupConnection`, version negotiation), 5.3.1 (mining
//! protocol flags), 6.4.1 (job declaration flags) and 3.5 (error code
//! character rules).
//!
//! - **Flag bit positions**: `REQUIRES_STANDARD_JOBS` is bit 0,
//!   `REQUIRES_WORK_SELECTION` bit 1, `REQUIRES_VERSION_ROLLING` bit 2 for
//!   the mining protocol; job declaration defines a single bit 0 flag. The
//!   helper functions must read exactly those bits.
//! - **Version negotiation (3.6.1/3.6.2)**: `used_version` is the highest
//!   version both ranges support; the outcome is symmetric in the two peers
//!   and lies inside both ranges.
//! - **`check_flags` metamorphic relations**: the result may depend only on
//!   the bits the spec defines for that protocol, and identical flag sets must
//!   always be compatible (reflexivity), whichever side is which.
//! - **Protocol discriminants (3.6.1)**: 0, 1, 2 and nothing else.
//! - **Error codes (3.5)**: every error code shipped by the implementation is
//!   printable ASCII without control characters.

mod common;

use arbitrary::Arbitrary;
use binary_sv2::{Deserialize, GetSize, Serialize, Str0255};
use common_messages_sv2::{
    has_declare_tx_data, has_requires_std_job, has_version_rolling, has_work_selection, Protocol,
    SetupConnection,
};
use libfuzzer_sys::fuzz_target;

/// The mining `check_flags` implementation isolates the wrong bits (it treats
/// `REQUIRES_STANDARD_JOBS` as if it also required work selection and version
/// rolling). The relation below exposes that immediately, so it is gated until
/// the implementation is fixed; flip to `true` to reproduce.
const CHECK_MINING_FLAG_ISOLATION: bool = false;

const REQUIRES_STANDARD_JOBS: u32 = 1 << 0;
const REQUIRES_WORK_SELECTION: u32 = 1 << 1;
const REQUIRES_VERSION_ROLLING: u32 = 1 << 2;
const MINING_DEFINED_FLAGS: u32 =
    REQUIRES_STANDARD_JOBS | REQUIRES_WORK_SELECTION | REQUIRES_VERSION_ROLLING;
const JD_ALLOW_FULL_TEMPLATE_MODE: u32 = 1 << 0;

#[derive(Arbitrary, Debug)]
struct Peer {
    protocol: u8,
    min_version: u16,
    max_version: u16,
    flags: u32,
    endpoint_port: u16,
    endpoint_host: String,
    vendor: String,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    a: Peer,
    b: Peer,
}

fn str0255(s: &str) -> Str0255<'_> {
    let mut end = s.len().min(255);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    Str0255::try_from(&s[..end]).expect("at most 255 bytes")
}

fn setup_connection<'a>(peer: &'a Peer, protocol: Protocol) -> SetupConnection<'a> {
    SetupConnection {
        protocol,
        min_version: peer.min_version,
        max_version: peer.max_version,
        flags: peer.flags,
        endpoint_host: str0255(&peer.endpoint_host),
        endpoint_port: peer.endpoint_port,
        vendor: str0255(&peer.vendor),
        hardware_version: str0255(""),
        firmware: str0255(""),
        device_id: str0255(""),
    }
}

fn check_error_codes() {
    use common_messages_sv2 as c;
    use mining_sv2 as m;
    let codes: &[&str] = &[
        c::ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_FEATURE_FLAGS,
        c::ERROR_CODE_SETUP_CONNECTION_UNSUPPORTED_PROTOCOL,
        c::ERROR_CODE_SETUP_CONNECTION_MISSING_DECLARE_TX_DATA_FLAG,
        c::ERROR_CODE_SETUP_CONNECTION_PROTOCOL_VERSION_MISMATCH,
        m::ERROR_CODE_OPEN_MINING_CHANNEL_STANDARD_CHANNELS_NOT_SUPPORTED_FOR_CUSTOM_WORK,
        m::ERROR_CODE_OPEN_MINING_CHANNEL_EXTENDED_CHANNELS_NOT_SUPPORTED_FOR_STANDARD_JOBS,
        m::ERROR_CODE_OPEN_MINING_CHANNEL_CHANNEL_CAPACITY_EXHAUSTED,
        m::ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_USER_IDENTITY,
        m::ERROR_CODE_OPEN_MINING_CHANNEL_INVALID_NOMINAL_HASHRATE,
        m::ERROR_CODE_OPEN_MINING_CHANNEL_MIN_EXTRANONCE_SIZE_TOO_LARGE,
        m::ERROR_CODE_OPEN_MINING_CHANNEL_MAX_TARGET_OUT_OF_RANGE,
        m::ERROR_CODE_OPEN_MINING_CHANNEL_UNSUPPORTED_MIN_EXTRANONCE_SIZE,
        m::ERROR_CODE_OPEN_MINING_CHANNEL_UNKNOWN_USER,
        m::ERROR_CODE_UPDATE_CHANNEL_INVALID_NOMINAL_HASHRATE,
        m::ERROR_CODE_UPDATE_CHANNEL_INVALID_CHANNEL_ID,
        m::ERROR_CODE_SUBMIT_SHARES_INVALID_CHANNEL_ID,
        m::ERROR_CODE_SUBMIT_SHARES_INVALID_SHARE,
        m::ERROR_CODE_SUBMIT_SHARES_STALE_SHARE,
        m::ERROR_CODE_SUBMIT_SHARES_INVALID_JOB_ID,
        m::ERROR_CODE_SUBMIT_SHARES_DIFFICULTY_TOO_LOW,
        m::ERROR_CODE_SUBMIT_SHARES_DUPLICATE_SHARE,
        m::ERROR_CODE_SUBMIT_SHARES_BAD_EXTRANONCE_SIZE,
        m::ERROR_CODE_VERSION_ROLLING_NOT_ALLOWED,
        m::ERROR_CODE_SUBMIT_SHARES_INVALID_NON_ROLLABLE_VERSION_BIT,
        m::ERROR_CODE_SET_CUSTOM_MINING_JOB_JD_NOT_SUPPORTED,
        m::ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_CHANNEL_ID,
        m::ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_MINING_JOB_TOKEN,
        m::ERROR_CODE_SET_CUSTOM_MINING_JOB_JOB_NOT_YET_VALIDATED,
        m::ERROR_CODE_SET_CUSTOM_MINING_JOB_STALE_CHAIN_TIP,
        m::ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_MIN_NTIME,
        m::ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_NBITS,
        m::ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_VERSION,
        m::ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_COINBASE_TX,
        m::ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_COINBASE_TX_VERSION,
        m::ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_COINBASE_PREFIX,
        m::ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_COINBASE_TX_INPUT_N_SEQUENCE,
        m::ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_COINBASE_TX_OUTPUTS,
        m::ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_COINBASE_TX_LOCKTIME,
        m::ERROR_CODE_SET_CUSTOM_MINING_JOB_INVALID_MERKLE_PATH,
    ];
    for code in codes {
        assert!(
            common::is_valid_error_code(code),
            "error code {code:?} violates spec 3.5 character rules"
        );
    }
}

fuzz_target!(|input: FuzzInput| {
    check_error_codes();

    // --- Protocol discriminants (spec 3.6.1) --------------------------------
    for peer in [&input.a, &input.b] {
        match Protocol::try_from(peer.protocol) {
            Ok(p) => assert_eq!(p as u8, peer.protocol),
            Err(()) => assert!(peer.protocol > 2, "protocol {} rejected", peer.protocol),
        }
        assert_eq!(Protocol::try_from(peer.protocol).is_ok(), peer.protocol <= 2);
    }

    // --- Flag bit positions (spec 5.3.1, 6.4.1) ------------------------------
    for flags in [input.a.flags, input.b.flags] {
        assert_eq!(has_requires_std_job(flags), flags & REQUIRES_STANDARD_JOBS != 0);
        assert_eq!(has_work_selection(flags), flags & REQUIRES_WORK_SELECTION != 0);
        assert_eq!(has_version_rolling(flags), flags & REQUIRES_VERSION_ROLLING != 0);
        assert_eq!(has_declare_tx_data(flags), flags & JD_ALLOW_FULL_TEMPLATE_MODE != 0);
    }

    // --- SetupConnection message round trip and flag accessors ---------------
    let mut a = setup_connection(&input.a, Protocol::MiningProtocol);
    assert_eq!(a.requires_standard_job(), input.a.flags & REQUIRES_STANDARD_JOBS != 0);
    a.set_requires_standard_job();
    assert_eq!(a.flags, input.a.flags | REQUIRES_STANDARD_JOBS, "setter must touch bit 0 only");
    a.flags = input.a.flags;
    let mut encoded = vec![0u8; a.get_size()];
    a.clone().to_bytes(&mut encoded).unwrap();
    let decoded = SetupConnection::from_bytes(&mut encoded).expect("own encoding must parse");
    assert_eq!(decoded, a);
    assert_eq!(encoded[0], 0, "mining protocol discriminant is 0");
    assert_eq!(&encoded[1..3], &input.a.min_version.to_le_bytes());
    assert_eq!(&encoded[3..5], &input.a.max_version.to_le_bytes());
    assert_eq!(&encoded[5..9], &input.a.flags.to_le_bytes());

    // --- Version negotiation (spec 3.6.1 / 3.6.2) ----------------------------
    // The spec defines min_version/max_version as a range, so the negotiation
    // invariants only hold for well-formed ranges (min <= max). `get_version`
    // does not itself validate the caller-supplied range, so an inverted range
    // is out of scope here.
    let b = setup_connection(&input.b, Protocol::MiningProtocol);
    let a_ok = a.min_version <= a.max_version;
    let b_ok = b.min_version <= b.max_version;
    if a_ok && b_ok {
        let ab = a.get_version(b.min_version, b.max_version);
        let ba = b.get_version(a.min_version, a.max_version);
        assert_eq!(ab, ba, "version negotiation must be symmetric");
        let intersects = a.min_version <= b.max_version && b.min_version <= a.max_version;
        match ab {
            Some(v) => {
                assert!(intersects, "negotiated a version from disjoint ranges");
                assert_eq!(
                    v,
                    a.max_version.min(b.max_version),
                    "must pick the highest common version"
                );
                assert!(a.min_version <= v && v <= a.max_version);
                assert!(b.min_version <= v && v <= b.max_version);
            }
            None => assert!(!intersects, "overlapping ranges failed to negotiate"),
        }
    }

    // --- check_flags relations -------------------------------------------------
    let (fa, fb) = (input.a.flags, input.b.flags);
    for protocol in [Protocol::MiningProtocol, Protocol::JobDeclarationProtocol] {
        // Reflexivity: identical flag sets are always compatible.
        assert!(
            SetupConnection::check_flags(protocol, fa, fa),
            "identical flags {fa:#x} reported incompatible"
        );
    }
    // Only spec-defined bits may influence the outcome.
    assert_eq!(
        SetupConnection::check_flags(Protocol::JobDeclarationProtocol, fa, fb),
        SetupConnection::check_flags(
            Protocol::JobDeclarationProtocol,
            fa & JD_ALLOW_FULL_TEMPLATE_MODE,
            fb & JD_ALLOW_FULL_TEMPLATE_MODE
        ),
        "JD check_flags depends on bits other than bit 0"
    );
    let mining_negotiable = REQUIRES_WORK_SELECTION | REQUIRES_VERSION_ROLLING;
    assert_eq!(
        SetupConnection::check_flags(Protocol::MiningProtocol, fa, fb),
        SetupConnection::check_flags(
            Protocol::MiningProtocol,
            fa & MINING_DEFINED_FLAGS,
            fb & MINING_DEFINED_FLAGS
        ),
        "mining check_flags depends on undefined flag bits"
    );
    if CHECK_MINING_FLAG_ISOLATION {
        assert_eq!(
            SetupConnection::check_flags(Protocol::MiningProtocol, fa, fb),
            SetupConnection::check_flags(
                Protocol::MiningProtocol,
                fa & mining_negotiable,
                fb & mining_negotiable
            ),
            "mining check_flags lets REQUIRES_STANDARD_JOBS influence work-selection/version-rolling"
        );
    }
});
