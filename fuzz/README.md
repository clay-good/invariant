# `fuzz/`

`cargo-fuzz` harness for the Invariant Robotics validator. Seven
targets, each exercising a different layer of the validation pipeline.

| Target | Input shape | Layer exercised |
|--------|-------------|-----------------|
| `fuzz_command_json` | Bytes → `Command` JSON | serde_json deserialisation |
| `fuzz_profile_json` | Bytes → `RobotProfile` JSON | profile deserialise + `Validate::validate` |
| `fuzz_pca_chain`    | Bytes → base64 → `Vec<SignedPca>` → `verify_chain` | authority chain parsing + Ed25519 verify |
| `fuzz_validate_pipeline` | Bytes → `Command` → `ValidatorConfig::validate` | end-to-end (the headline target) |
| `bridge_handle_line` | Bytes → split on `\n` → `IncomingMessage` | Isaac Lab bridge framing + parse path (v12-N-12) |
| `fuzz_cose_envelope` | Bytes → single-hop `SignedPca.raw` → `verify_chain` | inner COSE_Sign1 CBOR parser, header + payload decode (v11 2.11 N-07) |
| `fuzz_json_bomb` | Bytes → bracket-wrapped JSON → `Command` + `serde_json::Value` | depth-bound + adversarial JSON shapes (v11 2.11 N-06) |

## Spec coverage — v11 2.11 Category N (wire-shape rows)

The six wire-shape Category N rows are bound to libFuzzer targets here.
`fuzz_command_json` is a coverage-guided grammar fuzzer by construction
(libFuzzer mutates byte sequences against the typed `Command`
deserialiser), so N-03 (grammar fuzz), N-04 (coverage-guided), and N-09
(type confusion) are all covered by it; the four typed-`Command`
Category N rows (N-01 / N-02 / N-08 / N-10) ship as `ScenarioType`
generators per v11 2.11.

| Spec ID | Target | Notes |
|---------|--------|-------|
| N-03 grammar fuzz     | `fuzz_command_json`      | libFuzzer mutates against the typed `Command` JSON grammar |
| N-04 coverage-guided  | `fuzz_validate_pipeline` | every cargo-fuzz target is coverage-guided by libFuzzer; this is the headline end-to-end one |
| N-05 differential     | `fuzz_validate_pipeline` | a single Command is admitted *or* rejected; the differential is between the typed deserialiser, the validator, and the audit-log emit path — same target catches divergence between the three |
| N-06 JSON bomb        | `fuzz_json_bomb`         | deeply-nested + adversarial JSON shapes (depth wrapper cycles 0..16) |
| N-07 COSE-CBOR        | `fuzz_cose_envelope`     | inner CBOR / protected-header / payload decode of `SignedPca.raw` |
| N-09 type confusion   | `fuzz_command_json`      | libFuzzer naturally generates type-confused JSON (numbers as strings, arrays as objects, etc.) against the typed deserialiser |

## Prerequisites

```sh
cargo install cargo-fuzz
rustup install nightly  # cargo-fuzz uses nightly libFuzzer
```

## Seeding the corpora (v12-N-20)

`cargo fuzz` benefits enormously from a non-empty starting corpus — without
seeds, libFuzzer starts from empty/random bytes and may take hours to find
its way into the JSON-parsing path.

Run [`seed_corpora.sh`](seed_corpora.sh) once before the first
`cargo fuzz run`, and re-run any time the source fixtures change:

```sh
bash fuzz/seed_corpora.sh
```

The script populates `fuzz/corpus/<target>/` with at least 8 seeds per
target. Sources:

- **`fuzz_command_json`** — `examples/robotics/safe-command.json`,
  `examples/robotics/dangerous-command.json`, plus six synthetic shapes
  (empty object, null-joints, NaN velocity, Unicode source, oversized
  sequence, BOM-prefixed).
- **`fuzz_profile_json`** — first eight built-in profiles from
  `profiles/robotics/`, plus an empty-object seed.
- **`fuzz_pca_chain`** — eight hand-rolled chains produced by an inline
  Python helper (empty / single-hop / two-hop / wildcard-only / expired /
  future-nbf / non-base64 / empty-bytes). The chains are deliberately
  unsigned-or-bogus-signed so the fuzzer can push past base64 and JSON
  parsing without needing a private key.
- **`fuzz_validate_pipeline`** — reuses the `fuzz_command_json` corpus
  (same input shape; the validator consumes a `Command` then runs the
  full pipeline).
- **`bridge_handle_line`** — eight newline-framed seeds (heartbeat,
  heartbeat-false, empty, blank-only, two-frames, malformed JSON,
  embedded NUL, minimal command). Lines longer than
  `FUZZ_BRIDGE_MAX_LINE_BYTES` (8 KiB) short-circuit to the `Oversize`
  classification without touching the JSON parser. The fuzz target
  also asserts `results.len() == input.split('\n').count()` so the
  framing contract is observable from outside.

## Capturing fresh corpora

The synthetic seeds are minimal by design. To improve coverage with
realistic shapes:

- For `fuzz_command_json` / `fuzz_validate_pipeline`, run a campaign
  with `cargo run -p invariant-cli -- robotics validate ...` and copy
  the command JSON files it consumes into the corpus directory.
- For `fuzz_pca_chain`, dump a chain produced by `invariant robotics
  intent` followed by signing, then copy the base64 blob.
- For `fuzz_profile_json`, copy any in-house profile JSON.

`cargo-fuzz` will dedup new inputs against the existing corpus
automatically.

## Running a target

```sh
cargo fuzz run fuzz_validate_pipeline -- -runs=1000000
```

On a seeded corpus, the first 1 000 runs should hit at least one new
path on every target.

## Nightly CI

`fuzz_validate_pipeline` runs for 5 minutes on the nightly CI job
([scheduled separately](../.github/workflows/) — wired up by
v11 5.10 / v12 N-12 once those prompts land).
