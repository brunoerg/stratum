#![no_main]

//! Sv2 frame conformance target.
//!
//! The previous version of this target only checked that a frame survived a
//! serialize/deserialize cycle. It never looked *inside* the frame, so a
//! parser that agreed with itself but disagreed with the specification could
//! not be caught. This target treats `03-Protocol-Overview.md` (framing) and
//! `08-Message-Types.md` (message-type table) as the oracle:
//!
//! - **Header layout (spec 3.2)**: `extension_type` U16 LE, `msg_type` U8,
//!   `msg_length` U24 LE, six bytes total. The header accessors must agree
//!   with an independent decoding of those bytes, and `size_hint` must agree
//!   with the declared length.
//! - **Message-type table (spec 08)**: a message parsed from a frame with
//!   `extension_type == 0` must report the `msg_type` found on the wire, and
//!   its `channel_msg` bit must match the table transcribed in `common.rs`.
//! - **Channel routing (spec 3.2.1)**: when the `channel_msg` bit is set the
//!   first four payload bytes are the U32 `channel_id`, and they must equal
//!   the `channel_id` field the parser produced.
//! - **Re-framing metamorphic relation**: framing the parsed message again
//!   with the implementation's own message type / extension type / channel
//!   bit must produce a header equivalent to the one on the wire, and the new
//!   frame must decode to an identical message and identical bytes.

mod common;

use binary_sv2::GetSize;
use framing_sv2::{
    framing::{SizeHint, Sv2Frame},
    header::Header,
    SV2_FRAME_HEADER_SIZE,
};
use libfuzzer_sys::fuzz_target;
use parsers_sv2::{AnyMessage, IsSv2Message};

type Frame = Sv2Frame<AnyMessage<'static>, Vec<u8>>;

const CHANNEL_MSG_MASK: u16 = 0x8000;

fn check_header_layout(data: &[u8]) {
    if data.len() < SV2_FRAME_HEADER_SIZE {
        assert!(
            Header::from_bytes(data).is_err(),
            "a header was decoded from fewer than {SV2_FRAME_HEADER_SIZE} bytes"
        );
        match Frame::size_hint(data) {
            SizeHint::Missing(missing) => assert_eq!(
                missing,
                SV2_FRAME_HEADER_SIZE - data.len(),
                "size hint for a partial header must ask for the rest of the header"
            ),
            other => panic!("partial header produced {other:?} instead of Missing"),
        }
        return;
    }

    let header = Header::from_bytes(data).expect("six or more bytes always hold a header");
    let wire_ext_type = u16::from_le_bytes([data[0], data[1]]);
    let wire_msg_type = data[2];
    let wire_len = u32::from_le_bytes([data[3], data[4], data[5], 0]) as usize;

    assert_eq!(header.ext_type(), wire_ext_type, "extension_type must be U16 LE");
    assert_eq!(header.msg_type(), wire_msg_type, "msg_type must be the third byte");
    assert_eq!(
        header.channel_msg(),
        wire_ext_type & CHANNEL_MSG_MASK != 0,
        "channel_msg is bit 15 of extension_type"
    );
    assert_eq!(
        header.ext_type_without_channel_msg(),
        wire_ext_type & !CHANNEL_MSG_MASK,
        "channel_msg bit must be ignored in extension lookup (spec 3.2.1)"
    );

    let expected_total = SV2_FRAME_HEADER_SIZE + wire_len;
    match Frame::size_hint(data) {
        SizeHint::Exact => assert_eq!(data.len(), expected_total),
        SizeHint::Missing(missing) => assert_eq!(data.len() + missing, expected_total),
        SizeHint::Surplus(surplus) => assert_eq!(data.len() - surplus, expected_total),
    }
}

/// Frames `message` with the implementation's own view of its type and returns
/// the serialized bytes.
fn reframe(message: AnyMessage<'_>) -> Vec<u8> {
    let msg_type = message.message_type();
    let ext_type = message.extension_type();
    let channel_bit = message.channel_bit();
    let frame = Sv2Frame::<AnyMessage<'_>, Vec<u8>>::from_message(
        message,
        msg_type,
        ext_type,
        channel_bit,
    )
    .expect("a message that came from a frame must fit in a frame");
    let mut out = vec![0u8; frame.encoded_length()];
    frame.serialize(&mut out).expect("serializing a parsed message must succeed");
    out
}

fuzz_target!(|data: &[u8]| {
    check_header_layout(data);

    let Ok(mut frame) = Frame::from_bytes(data.to_vec()) else {
        return;
    };
    let header = frame.get_header().expect("Sv2Frame always has a header");
    assert_eq!(frame.encoded_length(), data.len());

    let mut payload = frame.payload().to_vec();
    assert_eq!(payload, data[SV2_FRAME_HEADER_SIZE..]);

    let payload_len = payload.len();
    let Ok(message) = AnyMessage::try_from((header, payload.as_mut_slice())) else {
        return;
    };

    // --- Message-type table (spec 08) -------------------------------------
    let msg_type = message.message_type();
    let ext_type = message.extension_type();
    let channel_bit = message.channel_bit();
    assert_eq!(
        msg_type,
        header.msg_type(),
        "parsed message reports a different msg_type than the frame header"
    );
    assert_eq!(
        ext_type,
        header.ext_type_without_channel_msg(),
        "parsed message reports a different extension_type than the frame header"
    );
    if ext_type == 0 {
        let expected = common::spec_channel_bit(msg_type).unwrap_or_else(|| {
            panic!("parser accepted core message type {msg_type:#04x} which the spec does not define")
        });
        assert_eq!(
            channel_bit, expected,
            "channel_msg bit for message type {msg_type:#04x} disagrees with the spec table"
        );
    }

    // --- Channel routing (spec 3.2.1) --------------------------------------
    let size = message.get_size();
    assert!(
        size <= payload_len,
        "message size {size} exceeds payload length {payload_len}"
    );
    if ext_type == 0 && channel_bit {
        assert!(size >= 4, "channel messages start with a U32 channel_id");
        let wire_channel_id = u32::from_le_bytes([
            data[SV2_FRAME_HEADER_SIZE],
            data[SV2_FRAME_HEADER_SIZE + 1],
            data[SV2_FRAME_HEADER_SIZE + 2],
            data[SV2_FRAME_HEADER_SIZE + 3],
        ]);
        let parsed_channel_id = common::channel_id_of(&message)
            .unwrap_or_else(|| panic!("no channel_id accessor for channel message {msg_type:#04x}"));
        assert_eq!(
            parsed_channel_id, wire_channel_id,
            "channel_id must be the first four payload bytes (spec 3.2.1)"
        );
    }

    // --- Re-framing metamorphic relation -----------------------------------
    let display = message.to_string();
    let reframed = reframe(message);
    assert_eq!(reframed.len(), SV2_FRAME_HEADER_SIZE + size);

    let new_header = Header::from_bytes(&reframed).unwrap();
    assert_eq!(new_header.msg_type(), msg_type);
    assert_eq!(new_header.ext_type_without_channel_msg(), ext_type);
    assert_eq!(new_header.channel_msg(), channel_bit);
    if ext_type == 0 {
        // Core messages MUST carry extension_type 0 apart from the channel bit
        // (spec 3.4.1).
        assert_eq!(new_header.ext_type() & !CHANNEL_MSG_MASK, 0);
    }

    let mut frame2 = Frame::from_bytes(reframed.clone())
        .expect("a frame built by the implementation must be an exact frame");
    let mut payload2 = frame2.payload().to_vec();
    let message2 = AnyMessage::try_from((new_header, payload2.as_mut_slice()))
        .expect("bytes produced by the implementation must parse");
    assert_eq!(message2.to_string(), display, "re-framed message changed content");
    assert_eq!(message2.get_size(), size, "re-framed message changed size");
    assert_eq!(message2.message_type(), msg_type);
    assert_eq!(message2.channel_bit(), channel_bit);
    let reframed2 = reframe(message2);
    assert_eq!(reframed, reframed2, "framing is not stable");
});
