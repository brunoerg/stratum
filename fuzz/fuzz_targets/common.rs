use arbitrary::Unstructured;
use serde_json::Value;

/// Performs a round-trip serialization test for a message type.
///
/// This macro:
/// 1. Attempts to parse the input bytes into a message.
/// 2. Serializes the parsed message back into bytes.
/// 3. Parses those bytes again.
/// 4. Re-serializes and checks for byte-level stability.
/// 5. Verifies that the `Display` output is preserved across the round trip.
///
/// # Arguments
///
/// * `$msg_type` — A message type implementing `from_bytes`, `to_bytes`,
///   `get_size` and `Display`.
/// * `$data` — A byte buffer used as the initial source.
///
/// ```ignore
/// test_roundtrip!(MyMessage, input_bytes);
/// ```
/// Performs a round-trip serialization test for a message type and checks the
/// spec-derived structural properties every Sv2 message encoding must have.
///
/// This macro:
/// 1. Attempts to parse the input bytes into a message.
/// 2. Serializes the parsed message back into bytes.
/// 3. Parses those bytes again.
/// 4. Re-serializes and checks for byte-level stability.
/// 5. Verifies that the `Display` output is preserved across the round trip.
/// 6. Checks *prefix determinism*: Sv2 fields are self-delimiting (spec 3.1)
///    and TLV extension fields may follow the base message (spec 3.4.3), so
///    trailing bytes MUST NOT change the decoded message.
/// 7. Checks *no early success*: a strict prefix of a canonical encoding MUST
///    NOT decode successfully (otherwise the decoder read fewer bytes than the
///    data types demand, which is how field-boundary bugs manifest).
///
/// # Arguments
///
/// * `$msg_type` — A message type implementing `from_bytes`, `to_bytes`,
///   `get_size` and `Display`.
/// * `$data` — A byte buffer used as the initial source.
///
/// ```ignore
/// test_roundtrip!(MyMessage, input_bytes);
/// ```
#[macro_export]
macro_rules! test_roundtrip {
    ($msg_type:ty, $data:expr) => {{
        // Step 1: Try to parse the input bytes.
        // Invalid inputs are expected in fuzzing, so we silently ignore failures.
        let mut input = $data.clone();
        let input_len = input.len();
        if let Ok(parsed) = <$msg_type>::from_bytes(&mut input) {
            // Spec 3.1: every field is self-delimiting, so a successful decode can
            // never account for more bytes than were provided.
            let size = parsed.get_size();
            assert!(
                size <= input_len,
                "{}: decoded size {} exceeds input length {}",
                stringify!($msg_type),
                size,
                input_len
            );

            // Step 2: Serialize the successfully parsed message.
            let mut encoded_1 = vec![0u8; size];
            parsed
                .clone()
                .to_bytes(&mut encoded_1)
                .expect("Encoding failed after a successful parse");

            // Step 3: Parse the serialized bytes again.
            let mut encoded_1_clone = encoded_1.clone();
            let reparsed = <$msg_type>::from_bytes(&mut encoded_1_clone)
                .expect("Roundtrip failed: serializer produced invalid bytes");

            // Step 4: Serialize again and ensure byte-level stability.
            let mut encoded_2 = vec![0u8; reparsed.get_size()];
            reparsed
                .clone()
                .to_bytes(&mut encoded_2)
                .expect("Second encoding failed");

            assert_eq!(encoded_1, encoded_2, "Serialization is not stable");

            // Step 5: Verify that the content is preserved.
            //
            // Not all message types implement `Eq`, so we compare their `Display`
            // output instead. If both messages can be parsed successfully and
            // represent the same data, their formatted output should match.
            let display = parsed.to_string();
            assert_eq!(display, reparsed.to_string(), "Display output mismatch");

            // Step 6: Prefix determinism. Appending bytes after a complete message
            // (as TLV extension fields do, spec 3.4.3) must not alter what is decoded.
            let mut with_trailing = encoded_1.clone();
            with_trailing.extend_from_slice(&$crate::common::TRAILING_JUNK);
            let with_trailing_parsed = <$msg_type>::from_bytes(&mut with_trailing).expect(concat!(
                stringify!($msg_type),
                ": trailing bytes after a complete message must be ignored"
            ));
            assert_eq!(
                with_trailing_parsed.to_string(),
                display,
                "{}: trailing bytes changed the decoded message",
                stringify!($msg_type)
            );
            assert_eq!(
                with_trailing_parsed.get_size(),
                size,
                "{}: trailing bytes changed the decoded size",
                stringify!($msg_type)
            );

            // Step 7: No strict prefix of a canonical encoding may decode successfully.
            for cut in $crate::common::prefix_cuts(encoded_1.len()) {
                let mut truncated = encoded_1[..cut].to_vec();
                assert!(
                    <$msg_type>::from_bytes(&mut truncated).is_err(),
                    "{}: a strict prefix ({} of {} bytes) decoded successfully",
                    stringify!($msg_type),
                    cut,
                    encoded_1.len()
                );
            }
        };
    }};
}

#[macro_export]
macro_rules! test_datatype_roundtrip {
    // ---- special rule for bool ----
    // Bool has a non-canonical encoding in the spec: only the lowest bit is meaningful.
    // Multiple byte values can parse to the same logical bool, so we cannot require a
    // strict byte-for-byte roundtrip. Instead we check semantic stability and canonicalization.
    (bool, $data:expr) => {{
        let mut input = $data.clone();

        // Only run the roundtrip checks if parsing succeeds. Invalid inputs are ignored,
        // because this macro validates stability of valid encodings, not rejection behavior.
        if let Ok(parsed) = bool::from_bytes(&mut input) {
            // Allocate exactly the number of bytes required by the parsed value.
            // This ensures we test the canonical serialized size.
            let mut encoded = vec![0u8; parsed.get_size()];

            // A successful parse must always be serializable.
            parsed
                .to_bytes(&mut encoded)
                .expect("Bool encoding failed after a successfull parse");

            // Bytes produced by serialization must always be parseable again.
            let reparsed = bool::from_bytes(&mut encoded)
                .expect("The bytes generated from a valid bool should be parseable");

            // Logical value must be preserved by parse → serialize → parse.
            assert_eq!(parsed, reparsed, "Bool roundtrip is not stable");

            // Because only the lowest bit is significant, we compare the semantic bit,
            // not the full original byte. This verifies canonical encoding.
            assert_eq!(input[0] & 1, encoded[0], "Bool serialization is not stable");
        }
    }};

    // ---- special rule for f32 ----
    // Floats require bit-level comparison IEEE-754.
    (f32, $data:expr) => {{
        let mut input = $data.clone();

        // Only validate successful parses; invalid encodings are outside this macro’s scope.
        if let Ok(parsed) = f32::from_bytes(&mut input) {
            // Allocate the exact canonical size of the float representation.
            let mut encoded = vec![0u8; parsed.get_size()];

            // A successfully parsed float must serialize without failure.
            parsed
                .to_bytes(&mut encoded)
                .expect("Encoding failed after a successful parse");

            // Serialized bytes must be parseable back into a float.
            let reparsed = f32::from_bytes(&mut encoded)
                .expect("The bytes generated from a valid datatype should be parseable");

            // Compare raw bits to enforce strict roundtrip stability, including NaN payloads.
            assert_eq!(
                parsed.to_bits(),
                reparsed.to_bits(),
                "Float roundtrip is not bit-stable"
            );

            // Ensure serialization is canonical: re-encoding must match the consumed input.
            assert_eq!(
                encoded,
                input[..encoded.len()],
                "Serialization is not stable"
            );
        }
    }};

    // ---- generic rule ----
    ($datatype:ty, $data:expr) => {{
        let mut input = $data.clone();
        let input_bytes = input.clone();

        // Only test successful parses; this macro checks roundtrip invariants.
        if let Ok(parsed) = <$datatype>::from_bytes(&mut input) {
            // Allocate exactly the canonical serialized size.
            let mut encoded = vec![0u8; parsed.get_size()];

            // A parsed value must always serialize successfully.
            parsed.clone().to_bytes(&mut encoded).expect(concat!(
                stringify!($datatype),
                ": Encoding failed after a successful parse"
            ));

            // Serialized bytes must be parseable again into the same datatype.
            let reparsed = <$datatype>::from_bytes(&mut encoded).expect(concat!(
                stringify!($datatype),
                ": The bytes generated from a valid datatype should be parseable"
            ));

            // Semantic equality after roundtrip is required.
            assert_eq!(
                parsed,
                reparsed,
                "{}: The roundtrip should produce the same message",
                stringify!($datatype)
            );

            // reserialization must match the consumed input bytes.
            assert_eq!(
                encoded,
                input_bytes[..encoded.len()],
                "{}: Serialization is not stable",
                stringify!($datatype)
            );

            // Spec 3.1: data types are self-delimiting, so trailing bytes are ignored
            // and no strict prefix of a valid encoding is itself a valid encoding.
            let mut with_trailing = encoded.clone();
            with_trailing.extend_from_slice(&$crate::common::TRAILING_JUNK);
            let with_trailing_parsed = <$datatype>::from_bytes(&mut with_trailing).expect(concat!(
                stringify!($datatype),
                ": trailing bytes after a complete value must be ignored"
            ));
            assert_eq!(
                parsed,
                with_trailing_parsed,
                "{}: trailing bytes changed the decoded value",
                stringify!($datatype)
            );
            for cut in $crate::common::prefix_cuts(encoded.len()) {
                let mut truncated = encoded[..cut].to_vec();
                assert!(
                    <$datatype>::from_bytes(&mut truncated).is_err(),
                    "{}: a strict prefix ({} of {} bytes) decoded successfully",
                    stringify!($datatype),
                    cut,
                    encoded.len()
                );
            }
        }
    }};
}

/// WARNING: Generated with OpenAI's GPT-5.5 free model
///
/// Generate an arbitrary [`Value`] with bounded recursion depth.
///
/// Used by the SV1 fuzz targets (`fuzz_sv1_wire`, `fuzz_sv1_method_parsers`)
/// to construct random JSON inputs that exercise `serde_json::from_value`
/// and the `TryFrom` parsers.
#[allow(dead_code)]
pub fn gen_json_value(u: &mut Unstructured<'_>, depth: u8) -> arbitrary::Result<Value> {
    if depth == 0 {
        return Ok(Value::Null);
    }
    Ok(match u.int_in_range(0..=7)? {
        0 => Value::Null,
        1 => Value::Bool(u.arbitrary()?),
        2 => {
            let n: i64 = u.arbitrary()?;
            Value::Number(serde_json::Number::from(n))
        }
        3 => {
            let n: f64 = u.arbitrary()?;
            serde_json::Number::from_f64(n)
                .map(Value::Number)
                .unwrap_or(Value::Null)
        }
        4 => Value::String(u.arbitrary()?),
        5 => {
            let len = u.int_in_range(0..=3)?;
            let mut arr = Vec::with_capacity(len);
            for _ in 0..len {
                arr.push(gen_json_value(u, depth.saturating_sub(1))?);
            }
            Value::Array(arr)
        }
        6 | 7 | _ => {
            let len = u.int_in_range(0..=3)?;
            let mut map = serde_json::Map::new();
            for _ in 0..len {
                let key: String = u.arbitrary()?;
                let val = gen_json_value(u, depth.saturating_sub(1))?;
                map.insert(key, val);
            }
            Value::Object(map)
        }
    })
}

/// Bytes appended after a complete encoding to check prefix determinism.
#[allow(dead_code)]
pub const TRAILING_JUNK: [u8; 6] = [0xAB, 0xCD, 0x00, 0xFF, 0x7F, 0x01];

/// Strict-prefix lengths worth checking for an encoding of `len` bytes:
/// one byte short, the midpoint, and the empty buffer.
#[allow(dead_code)]
pub fn prefix_cuts(len: usize) -> Vec<usize> {
    if len == 0 {
        return Vec::new();
    }
    let mut cuts = vec![len - 1, len / 2, 0];
    cuts.sort_unstable();
    cuts.dedup();
    cuts
}

/// The `channel_msg` bit each core message type MUST carry, transcribed from
/// the specification's message-type table (`08-Message-Types.md`).
///
/// Returns `None` for message types the specification does not define
/// (including `0x1e`, which is reserved).
#[allow(dead_code)]
pub fn spec_channel_bit(msg_type: u8) -> Option<bool> {
    Some(match msg_type {
        // Common
        0x00 => false, // SetupConnection
        0x01 => false, // SetupConnection.Success
        0x02 => false, // SetupConnection.Error
        0x03 => true,  // ChannelEndpointChanged
        0x04 => false, // Reconnect
        // Mining
        0x10 => false, // OpenStandardMiningChannel
        0x11 => false, // OpenStandardMiningChannel.Success
        0x12 => false, // OpenMiningChannel.Error
        0x13 => false, // OpenExtendedMiningChannel
        0x14 => false, // OpenExtendedMiningChannel.Success
        0x15 => true,  // NewMiningJob
        0x16 => true,  // UpdateChannel
        0x17 => true,  // UpdateChannel.Error
        0x18 => true,  // CloseChannel
        0x19 => true,  // SetExtranoncePrefix
        0x1a => true,  // SubmitSharesStandard
        0x1b => true,  // SubmitSharesExtended
        0x1c => true,  // SubmitShares.Success
        0x1d => true,  // SubmitShares.Error
        0x1f => true,  // NewExtendedMiningJob
        0x20 => true,  // SetNewPrevHash (mining)
        0x21 => true,  // SetTarget
        0x22 => true,  // SetCustomMiningJob
        0x23 => true,  // SetCustomMiningJob.Success
        0x24 => true,  // SetCustomMiningJob.Error
        0x25 => false, // SetGroupChannel
        // Job Declaration: channel_msg is always unset (spec 3.2.1)
        0x50 | 0x51 | 0x55 | 0x56 | 0x57 | 0x58 | 0x59 | 0x60 => false,
        // Template Distribution: channel_msg is always unset (spec 3.2.1)
        0x70..=0x76 => false,
        _ => return None,
    })
}

/// The `channel_id` a channel message (one whose `channel_msg` bit is set)
/// carries as its first field. Spec 3.2.1 requires those four bytes to be
/// the first four bytes of the frame payload.
#[allow(dead_code)]
pub fn channel_id_of(message: &parsers_sv2::AnyMessage<'_>) -> Option<u32> {
    use parsers_sv2::{AnyMessage, CommonMessages, Mining};
    Some(match message {
        AnyMessage::Common(CommonMessages::ChannelEndpointChanged(m)) => m.channel_id,
        AnyMessage::Mining(m) => match m {
            Mining::CloseChannel(m) => m.channel_id,
            Mining::NewExtendedMiningJob(m) => m.channel_id,
            Mining::NewMiningJob(m) => m.channel_id,
            Mining::SetCustomMiningJob(m) => m.channel_id,
            Mining::SetCustomMiningJobError(m) => m.channel_id,
            Mining::SetCustomMiningJobSuccess(m) => m.channel_id,
            Mining::SetExtranoncePrefix(m) => m.channel_id,
            Mining::SetNewPrevHash(m) => m.channel_id,
            Mining::SetTarget(m) => m.channel_id,
            Mining::SubmitSharesError(m) => m.channel_id,
            Mining::SubmitSharesExtended(m) => m.channel_id,
            Mining::SubmitSharesStandard(m) => m.channel_id,
            Mining::SubmitSharesSuccess(m) => m.channel_id,
            Mining::UpdateChannel(m) => m.channel_id,
            Mining::UpdateChannelError(m) => m.channel_id,
            _ => return None,
        },
        _ => return None,
    })
}

/// Spec 3.5: error codes (and other human-readable string codes such as
/// `CloseChannel.reason_code`) MUST NOT include control characters and SHOULD
/// be printable ASCII. Returns `true` when `code` satisfies the MUST clause
/// and the SHOULD clause, which every code shipped by this implementation
/// is expected to meet.
#[allow(dead_code)]
pub fn is_valid_error_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 255
        && code.bytes().all(|b| (0x20..=0x7e).contains(&b))
}
