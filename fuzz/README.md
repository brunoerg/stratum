# Fuzzing

This crate uses **cargo-fuzz** to test the robustness of the codebase.

## Requirements

Before running, install LLVM tools. Instructions:
[https://doc.rust-lang.org/stable/rustc/instrument-coverage.html#installing-llvm-coverage-tool](https://doc.rust-lang.org/stable/rustc/instrument-coverage.html#installing-llvm-coverage-tool)

Then install `cargo-fuzz`:

```sh
cargo install cargo-fuzz
```

Also, make sure you are on the nightly toolchain.

## Running Fuzz Targets

All fuzz targets live under:

```
fuzz/fuzz_targets/
```

To run one:

```sh
cargo +nightly fuzz run <target-name>
```

Example:

```sh
cargo +nightly fuzz run deserialize_setup_connection
```

Artifacts and crash cases are written to:

```
fuzz/artifacts/<target-name>/
```

If you find a crash that might indicate a **security issue**, please report it through our responsible disclosure process.
See [SECURITY](../SECURITY.md).

## Listing Available Targets

You can list all existing targets with:

```sh
cargo +nightly fuzz list
```

This is useful when adding new targets or exploring what’s already covered.

## Kinds of Target

Targets fall into two groups.

**Round-trip / structural targets** decode fuzzer bytes, re-encode, and check
the result is stable. Beyond the parse→serialize→parse cycle, the shared
`test_roundtrip!` / `test_datatype_roundtrip!` macros in `common.rs` also assert
spec-derived structural properties: a decode never consumes more bytes than it
was given, appending trailing bytes never changes the decoded value (SV2 fields
are self-delimiting and TLV extension fields may follow a message, spec 3.1 and
3.4.3), and no strict prefix of a canonical encoding decodes on its own.

* `end_to_end_serialization_for_*` — messages of each subprotocol.
* `end_to_end_serialization_for_datatypes` — the primitive SV2 data types.
* `deserialize_sv2frame` — frame header layout (spec 3.2), the message-type
  table and `channel_msg` bit (spec 08 / 3.2.1), the `channel_id` routing prefix,
  and a re-framing metamorphic relation.
* `deserialize_stdframe` — the streaming `codec_sv2` decoder: two frames in
  yield exactly two frames out, header-then-payload request schedule, and
  truncated streams never yield a frame.

**Semantic / metamorphic targets** build valid protocol state and check
properties the specification states about behaviour, so they can surface logic
bugs rather than only crashes. Each property is re-derived independently of the
implementation (the target computes the expected target, merkle root, ciphertext
length, share verdict, etc. itself and compares).

* `fuzz_setup_connection_flags` — flag bit positions (spec 5.3.1 / 6.4.1),
  version negotiation (spec 3.6), `check_flags` relations, protocol
  discriminants, and error-code character rules (spec 3.5).
* `fuzz_noise_codec_spec` — Noise handshake message sizes, certificate validity
  window and authority checks, encrypted-frame length, transport round trip, and
  integrity/nonce properties (spec 4.4–4.6).
* `fuzz_mining_channel_semantics` — `channels_sv2` logic: target vs. hashrate
  monotonicity and inversion, extranonce allocation (≤ 32 bytes, disjoint
  search space, capacity, reuse), merkle-root computation, and the full channel
  lifecycle including share validation with independently-computed verdicts.

When adding a metamorphic target, keep the oracle within the domain the spec
actually defines (for example, only assert version-negotiation invariants for
well-formed `min <= max` ranges) so that malformed but tolerated inputs do not
produce false positives.

## Working With the Seed Corpus

Each fuzz target has a corpus under:

```
fuzz/corpus/<target-name>/
```

These seeds guide fuzzing toward interesting states. Improving the corpus is one of the most impactful contributions you can make here.

To stay in sync with the shared corpus used across Stratum projects, follow the instructions here:

[https://github.com/stratum-mining/stratum-fuzzing-corpus/blob/main/scripts/readme.md](https://github.com/stratum-mining/stratum-fuzzing-corpus/blob/main/scripts/readme.md)

That repository covers:

* How to fetch and sync the shared corpus
* How to add new seeds
* How to run corpus-merging scripts
* How to submit contributions upstream

