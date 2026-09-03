#![no_main]

//! Noise handshake and encrypted framing conformance target.
//!
//! Oracle: `04-Protocol-Security.md`. The properties checked here are stated
//! by the specification and hold independently of the implementation:
//!
//! - **Handshake message sizes (4.5.1, 4.5.2)**: act 1 is a 64-byte EllSwift
//!   ephemeral key; act 2 is 64 + 80 + 90 = 234 bytes.
//! - **Certificate validity (4.5.3)**: with a known authority key the
//!   initiator MUST accept a certificate whose window contains its clock and
//!   MUST reject one that is expired or not yet valid (the implementation
//!   grants a 10 s clock-drift leeway; inside that band either outcome is
//!   accepted). A wrong authority key MUST be rejected regardless of time. An
//!   initiator without an authority key performs no certificate check.
//! - **Encrypted frame length (4.6)**: `22 + len + 16 * ceil(len / 65519)`
//!   bytes for a plaintext payload of `len` bytes, which the target computes
//!   itself from the constants in the spec, not from the implementation.
//! - **Transport round trip**: the decoder, pulling bytes at its own pace,
//!   consumes exactly the ciphertext and reproduces the frame bit for bit.
//! - **Integrity (4.4.1 AEAD)**: flipping any single bit of the ciphertext
//!   MUST make decoding fail; the decoder never yields a frame.
//! - **Nonce discipline (4.4.1)**: encrypting the same frame twice yields
//!   different ciphertext, a replayed ciphertext MUST fail, and ciphertexts
//!   delivered out of order MUST fail.

use arbitrary::Arbitrary;
use codec_sv2::{Error as CodecError, NoiseEncoder, StandardNoiseDecoder, State};
use framing_sv2::framing::{Frame, Sv2Frame};
use libfuzzer_sys::fuzz_target;
use noise_sv2::{
    Error as NoiseError, Initiator, Responder, ELLSWIFT_ENCODING_SIZE,
    INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE,
};
use parsers_sv2::AnyMessage;
use rand::{rngs::StdRng, SeedableRng};
use secp256k1::{Keypair, Secp256k1, XOnlyPublicKey};

type Message = AnyMessage<'static>;
type StdFrame = Sv2Frame<Message, Vec<u8>>;

// Constants from spec 4.6 ("Encrypted stratum message framing").
const SPEC_MAC_LEN: usize = 16;
const SPEC_MAX_CT_LEN: usize = 65535;
const SPEC_MAX_PT_LEN: usize = SPEC_MAX_CT_LEN - SPEC_MAC_LEN; // 65519
const SPEC_HEADER_LEN: usize = 6;
// Implementation-chosen clock leeway (see noise_sv2 signature_message.rs).
const CERT_TIME_LEEWAY: u32 = 10;
// Keeps a single iteration cheap: at most two full 65519-byte chunks plus a tail.
const MAX_EXTRA_CHUNKS: u8 = 2;

#[derive(Arbitrary, Debug, Clone, Copy, PartialEq)]
enum Authority {
    /// Initiator does not know any authority key: anonymous handshake.
    Unknown,
    /// Initiator knows the responder's authority key.
    Known,
    /// Initiator expects a different authority: handshake MUST fail.
    Wrong,
}

#[derive(Arbitrary, Debug)]
struct FuzzInput {
    rand_seed: u64,
    /// Responder clock when it signs its certificate.
    now_responder: u32,
    cert_validity: u32,
    /// Offset applied to the responder clock to obtain the initiator clock.
    initiator_clock_skew: i32,
    authority: Authority,
    msg_type: u8,
    ext_type: u16,
    payload: Vec<u8>,
    /// Number of extra full-size plaintext chunks prepended to the payload.
    extra_chunks: u8,
    /// Which act-2 byte to corrupt, if the handshake should be corrupted.
    handshake_corruption: Option<u32>,
    /// (byte index, bit index) to flip in the second ciphertext, if any.
    transport_corruption: Option<(u32, u8)>,
}

fn keypair(seed: u64) -> Keypair {
    let secp = Secp256k1::new();
    let mut rng = StdRng::seed_from_u64(seed);
    let (sk, _) = secp.generate_keypair(&mut rng);
    Keypair::from_secret_key(&secp, &sk)
}

fn xonly(kp: &Keypair) -> XOnlyPublicKey {
    kp.public_key().x_only_public_key().0
}

/// Spec 4.6: ciphertext length of a frame with `payload_len` plaintext bytes.
fn spec_encrypted_len(payload_len: usize) -> usize {
    let chunks = payload_len.div_ceil(SPEC_MAX_PT_LEN);
    SPEC_HEADER_LEN + SPEC_MAC_LEN + payload_len + chunks * SPEC_MAC_LEN
}

struct Session {
    initiator: State,
    responder: State,
}

/// Runs the handshake with deterministic keys and clocks. Returns `None` when
/// the handshake is expected (and observed) to fail.
fn handshake(input: &FuzzInput, corrupt: bool) -> Option<Session> {
    let authority_kp = keypair(input.rand_seed);
    let expected_pk = match input.authority {
        Authority::Unknown => None,
        Authority::Known => Some(xonly(&authority_kp)),
        Authority::Wrong => Some(xonly(&keypair(input.rand_seed ^ 0xcafe_babe_dead_beef))),
    };

    let mut init_rng = StdRng::seed_from_u64(input.rand_seed.rotate_left(17));
    let mut resp_rng = StdRng::seed_from_u64(input.rand_seed.rotate_left(41));
    let mut initiator = Initiator::new_with_rng(expected_pk, &mut init_rng);
    let mut responder = Responder::new_with_rng(authority_kp, input.cert_validity, &mut resp_rng);

    // Act 1 (spec 4.5.1): 64-byte EllSwift-encoded ephemeral key.
    let act1: [u8; ELLSWIFT_ENCODING_SIZE] = initiator.step_0().expect("act 1 never fails");

    // Act 2 (spec 4.5.2): e (64) || enc(s) (64 + 16) || enc(SIGNATURE_NOISE_MESSAGE) (74 + 16).
    let (mut act2, responder_engine) = responder
        .step_1_with_now_rng(act1, input.now_responder, &mut resp_rng)
        .expect("act 2 never fails on a well-formed act 1");
    assert_eq!(act2.len(), 234, "act 2 must be 64 + 80 + 90 bytes (spec 4.5.2)");
    assert_eq!(act2.len(), INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE);

    if corrupt {
        if let Some(idx) = input.handshake_corruption {
            act2[(idx as usize) % act2.len()] ^= 0x01;
        }
    }
    let corrupted = corrupt && input.handshake_corruption.is_some();

    let valid_from = input.now_responder;
    let not_valid_after = input.now_responder.saturating_add(input.cert_validity);
    let now_initiator = (input.now_responder as i64 + input.initiator_clock_skew as i64)
        .clamp(0, u32::MAX as i64) as u32;
    let inside_window = valid_from <= now_initiator && now_initiator <= not_valid_after;
    let outside_leeway = now_initiator < valid_from.saturating_sub(CERT_TIME_LEEWAY)
        || now_initiator > not_valid_after.saturating_add(CERT_TIME_LEEWAY);

    match initiator.step_2_with_now(act2, now_initiator) {
        Ok(initiator_engine) => {
            assert!(!corrupted, "a corrupted act 2 was accepted");
            match input.authority {
                Authority::Wrong => panic!("certificate from a wrong authority was accepted"),
                Authority::Known => assert!(
                    !outside_leeway,
                    "certificate accepted outside its validity window: valid_from={valid_from} not_valid_after={not_valid_after} now={now_initiator}"
                ),
                Authority::Unknown => {}
            }
            Some(Session {
                initiator: State::with_transport_mode(initiator_engine),
                responder: State::with_transport_mode(responder_engine),
            })
        }
        Err(err) => {
            if corrupted {
                return None;
            }
            match input.authority {
                Authority::Unknown => panic!("anonymous handshake failed: {err:?}"),
                Authority::Wrong => {
                    assert!(
                        matches!(err, NoiseError::InvalidCertificate(_)),
                        "wrong authority must be reported as an invalid certificate, got {err:?}"
                    );
                }
                Authority::Known => {
                    assert!(
                        !inside_window,
                        "certificate rejected inside its validity window: valid_from={valid_from} not_valid_after={not_valid_after} now={now_initiator} err={err:?}"
                    );
                    assert!(
                        matches!(err, NoiseError::InvalidCertificate(_)),
                        "expired certificate must be reported as invalid, got {err:?}"
                    );
                }
            }
            None
        }
    }
}

enum Decoded {
    Frame(Vec<u8>, usize),
    Rejected,
}

/// Feeds `ciphertext` to `decoder` at the decoder's own pace and reports what
/// came out and how many bytes were consumed.
fn decode(decoder: &mut StandardNoiseDecoder<Message>, state: &mut State, ciphertext: &[u8]) -> Decoded {
    let mut pos = 0usize;
    let mut idle_rounds = 0u8;
    loop {
        let writable = decoder.writable();
        let n = writable.len();
        if n == 0 {
            idle_rounds += 1;
            assert!(idle_rounds <= 2, "decoder repeatedly asked for zero bytes");
        } else {
            idle_rounds = 0;
            if pos + n > ciphertext.len() {
                // The decoder wants more than we have: the stream is rejected/incomplete.
                return Decoded::Rejected;
            }
            writable.copy_from_slice(&ciphertext[pos..pos + n]);
            pos += n;
        }
        match decoder.next_frame(state) {
            Ok(Frame::Sv2(frame)) => {
                let mut bytes = vec![0u8; frame.encoded_length()];
                frame.serialize(&mut bytes).unwrap();
                return Decoded::Frame(bytes, pos);
            }
            Ok(Frame::HandShake(_)) => panic!("handshake frame produced in transport mode"),
            Err(CodecError::MissingBytes(_)) => continue,
            Err(_) => return Decoded::Rejected,
        }
    }
}

fn build_frame(input: &FuzzInput) -> Option<Vec<u8>> {
    let extra = (input.extra_chunks % (MAX_EXTRA_CHUNKS + 1)) as usize;
    let mut payload = vec![0x5a; extra * SPEC_MAX_PT_LEN];
    payload.extend_from_slice(&input.payload);
    if payload.len() > 0x00ff_ffff {
        return None;
    }
    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(SPEC_HEADER_LEN + payload.len());
    frame.extend_from_slice(&input.ext_type.to_le_bytes());
    frame.push(input.msg_type);
    frame.extend_from_slice(&len.to_le_bytes()[..3]);
    frame.extend_from_slice(&payload);
    Some(frame)
}

fn encrypt(encoder: &mut NoiseEncoder<Message>, state: &mut State, frame: &[u8]) -> Vec<u8> {
    let sv2 = StdFrame::from_bytes(frame.to_vec()).expect("frame built with exact length");
    let out: Vec<u8> = encoder
        .encode(sv2.into(), state)
        .expect("encrypting in transport mode never fails");
    out
}

fuzz_target!(|input: FuzzInput| {
    let Some(frame) = build_frame(&input) else {
        return;
    };
    let payload_len = frame.len() - SPEC_HEADER_LEN;

    // A corrupted act 2 must be rejected (checked inside `handshake`).
    let _ = handshake(&input, true);

    // --- Session A: length, round trip, integrity, replay ------------------
    let Some(mut a) = handshake(&input, false) else {
        return;
    };
    let mut encoder = NoiseEncoder::<Message>::new();
    let mut decoder = StandardNoiseDecoder::<Message>::new();

    let c1 = encrypt(&mut encoder, &mut a.initiator, &frame);
    let c2 = encrypt(&mut encoder, &mut a.initiator, &frame);
    assert_eq!(
        c1.len(),
        spec_encrypted_len(payload_len),
        "ciphertext length disagrees with spec 4.6 for payload_len={payload_len}"
    );
    assert_eq!(c2.len(), c1.len());
    assert_ne!(c1, c2, "same plaintext encrypted twice must differ (nonce increments)");

    match decode(&mut decoder, &mut a.responder, &c1) {
        Decoded::Frame(bytes, consumed) => {
            assert_eq!(bytes, frame, "decrypted frame differs from the original");
            assert_eq!(consumed, c1.len(), "decoder consumed a different number of bytes");
        }
        Decoded::Rejected => panic!("valid ciphertext was rejected"),
    }

    match input.transport_corruption {
        Some((byte, bit)) => {
            let mut corrupted = c2.clone();
            let idx = (byte as usize) % corrupted.len();
            corrupted[idx] ^= 1 << (bit % 8);
            if let Decoded::Frame(_, _) = decode(&mut decoder, &mut a.responder, &corrupted) {
                panic!("ciphertext with a flipped bit at byte {idx} was accepted");
            }
        }
        None => {
            match decode(&mut decoder, &mut a.responder, &c2) {
                Decoded::Frame(bytes, _) => assert_eq!(bytes, frame),
                Decoded::Rejected => panic!("second valid ciphertext was rejected"),
            }
            // Replay of an already-consumed ciphertext must fail.
            let mut fresh_decoder = StandardNoiseDecoder::<Message>::new();
            if let Decoded::Frame(_, _) = decode(&mut fresh_decoder, &mut a.responder, &c1) {
                panic!("replayed ciphertext was accepted");
            }
        }
    }

    // --- Session B: out-of-order delivery -----------------------------------
    let Some(mut b) = handshake(&input, false) else {
        return;
    };
    let mut encoder = NoiseEncoder::<Message>::new();
    let mut decoder = StandardNoiseDecoder::<Message>::new();
    let _first = encrypt(&mut encoder, &mut b.initiator, &frame);
    let second = encrypt(&mut encoder, &mut b.initiator, &frame);
    if let Decoded::Frame(_, _) = decode(&mut decoder, &mut b.responder, &second) {
        panic!("out-of-order ciphertext was accepted");
    }
});
