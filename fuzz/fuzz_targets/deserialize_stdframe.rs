#![no_main]

//! Codec streaming target (plain, unencrypted transport).
//!
//! `codec_sv2::StandardDecoder` reconstructs frames from a byte stream by
//! repeatedly asking for exactly the number of bytes it still needs
//! (`writable()`), first for the six-byte header and then for the declared
//! payload (spec 3.2). This target checks the decoder against that model and
//! against the encoder:
//!
//! - **Encoder/decoder agreement**: encoding a frame yields exactly the bytes
//!   it was built from.
//! - **Framing boundaries**: two identical frames sent back to back must come
//!   out as exactly two frames, with the decoder never asking for bytes past a
//!   frame boundary, and every intermediate result being `MissingBytes`.
//! - **Request schedule (spec 3.2)**: a frame needs one request when its
//!   payload is empty (the header alone is the frame) and two otherwise.
//! - **Truncation**: after receiving a header the decoder must ask for exactly
//!   the declared payload length; a stream that ends early must leave the
//!   decoder still waiting, never yielding a frame.

use codec_sv2::{Encoder, Error, StandardDecoder, StandardSv2Frame};
use framing_sv2::SV2_FRAME_HEADER_SIZE;
use libfuzzer_sys::fuzz_target;
use parsers_sv2::AnyMessage;

type Message = AnyMessage<'static>;
type StdFrame = StandardSv2Frame<Message>;

fn frame_bytes(frame: StdFrame) -> Vec<u8> {
    let mut out = vec![0u8; frame.encoded_length()];
    frame.serialize(&mut out).unwrap();
    out
}

fuzz_target!(|data: &[u8]| {
    let Ok(frame) = StdFrame::from_bytes(data.to_vec()) else {
        return;
    };

    // --- Encoder agrees with the wire bytes ---------------------------------
    let mut encoder = Encoder::<Message>::new();
    let encoded = encoder
        .encode(frame.clone())
        .expect("encoding an exact frame must succeed");
    assert_eq!(&encoded[..], data, "encoder changed the frame bytes");

    // --- Two frames back to back ---------------------------------------------
    let stream = [data, data].concat();
    let mut decoder = StandardDecoder::<Message>::new();
    let mut pos = 0usize;
    let mut frames = 0usize;
    let mut requests = 0usize;
    while pos < stream.len() {
        let writable = decoder.writable();
        let n = writable.len();
        assert!(n > 0, "decoder asked for zero bytes while data was pending");
        assert!(
            pos + n <= stream.len(),
            "decoder asked for {n} bytes at offset {pos}, crossing a frame boundary"
        );
        writable.copy_from_slice(&stream[pos..pos + n]);
        pos += n;
        requests += 1;
        match decoder.next_frame() {
            Ok(decoded) => {
                frames += 1;
                assert_eq!(frame_bytes(decoded), data, "decoded frame differs from input");
            }
            Err(Error::MissingBytes(missing)) => {
                assert!(missing > 0, "MissingBytes(0) is not a valid hint");
            }
            Err(other) => panic!("unexpected decoder error on a valid stream: {other:?}"),
        }
    }
    assert_eq!(frames, 2, "two frames in, {frames} frames out");
    let payload_len = data.len() - SV2_FRAME_HEADER_SIZE;
    let expected_requests = if payload_len == 0 { 2 } else { 4 };
    assert_eq!(
        requests, expected_requests,
        "decoder should request header then payload for each frame (spec 3.2)"
    );

    // --- Truncated stream never yields a frame -------------------------------
    if payload_len > 0 {
        let mut decoder = StandardDecoder::<Message>::new();
        let header = decoder.writable();
        assert_eq!(header.len(), SV2_FRAME_HEADER_SIZE);
        header.copy_from_slice(&data[..SV2_FRAME_HEADER_SIZE]);
        match decoder.next_frame() {
            Err(Error::MissingBytes(missing)) => assert_eq!(
                missing, payload_len,
                "after the header the decoder must ask for exactly msg_length bytes"
            ),
            other => panic!("header alone must not complete a frame: {other:?}"),
        }
        assert_eq!(decoder.writable().len(), payload_len);
    }
});
