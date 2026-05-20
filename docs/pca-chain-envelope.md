# PCA Chain Envelope (v11-5.15.3)

The on-the-wire format for a Principal-issued Capability Authorisation
chain. Operators and integrators read this when they need to
hand-construct, log, or fuzz a chain. Cross-references
`docs/robotics/spec.md` §2.3 (chain semantics) and §3.2 (verification
invariants A1–A4).

## Layout

A chain is **base64(`Vec<SignedPca>` serialised as JSON)**. Each hop is:

```text
SignedPca := {
    "pca":       Pca,         // claim
    "signature": <base64>     // Ed25519 over canonical-bytes(Pca) (64 bytes raw)
}

Pca := {
    "p_0":  <string>,                                // root principal
    "ops":  [ <op string>, … ],                      // BTreeSet, lex-sorted
    "kid":  <string>,                                // signing key id
    "exp":  <RFC3339 string | null>,                 // expiry
    "nbf":  <RFC3339 string | null>                  // not-before
}
```

The outer container is `Vec<SignedPca>` — JSON array, **not** newline-
delimited. The whole array is base64-encoded so it survives transport in
the `command.authority.pca_chain` string field.

`Operation` strings (`"actuate:left_arm:*"`, `"sense:vision:*"`) follow the
`<verb>:<target>:<leaf>` shape with `*` denoting wildcard. Validation rules
live in `crates/invariant-core/src/models/authority.rs::Operation::new`.

## Version negotiation

Pre-v11 chains do not include a `predecessor_digest`. Post-v11-1.2 chains
add `predecessor_digest: [u8; 32]` to every hop (the SHA-256 of the
parent's `canonical_bytes`); the root hop carries `[0; 32]`. Verification
rejects non-zero root digests and any mismatch at index ≥ 1.

`format_version` lives on the **proof package manifest** that *contains*
chains (v12-N-5), not on the chain itself. The chain envelope shape above
is the same across versions; the only delta is the predecessor-digest
field. Detecting an old-format chain is done by absence of the field.

## Maximum size

| Limit | Value | Source |
|-------|-------|--------|
| Max hops per chain | 32 | `AuthorityError::ChainTooLong` (`max = 32`) |
| Max chain bytes (after base64) | 16 KiB | `fuzz_pca_chain` upper bound; matches operator runbook |
| Max single-op string length | 256 chars | `Operation::new` validator |
| Max `kid` length | 64 chars | `KeyFileError::*` validators |

Chains exceeding any limit must be rejected with a typed error, never
silently truncated.

## Hex examples

### One-hop chain (placeholder signature, will fail crypto)

JSON (pre-base64):

```json
[
  {
    "pca": {
      "p_0": "alice",
      "ops": ["actuate:left_arm:*"],
      "kid": "key-1",
      "exp": null,
      "nbf": null
    },
    "signature": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  }
]
```

Base64 of the array (line-broken for readability):

```text
W3sicGNhIjp7InBfMCI6ImFsaWNlIiwib3BzIjpbImFjdHVhdGU6bGVmdF9hcm06KiJdLCJraWQiOiJrZXktMSIs
ImV4cCI6bnVsbCwibmJmIjpudWxsfSwic2lnbmF0dXJlIjoiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEifV0=
```

### Two-hop chain

```json
[
  {"pca":{"p_0":"alice","ops":["actuate:*"],"kid":"key-1","exp":null,"nbf":null},
   "signature":"<base64 64-byte sig>"},
  {"pca":{"p_0":"alice","ops":["actuate:right_arm:*"],"kid":"key-2","exp":null,"nbf":null},
   "signature":"<base64 64-byte sig>"}
]
```

Note `p_0` is identical across both hops (A1 provenance). Hop 1's `ops` is
a subset of hop 0's `ops` (A2 monotonicity). Hop 0's signature is checked
against the `key-1` key in the trusted set; hop 1's against `key-2`.

## Ten malformation classes the fuzzer must cover

These are the inputs the bridge / chain verifier sees in the wild and that
[`fuzz_pca_chain`](../fuzz/fuzz_targets/fuzz_pca_chain.rs) (v11 5.10 / v12
N-20) must keep crashing-free:

1. **Not base64** — random bytes outside the base64 alphabet. Early-return
   path; the rest of the verifier is never reached.
2. **Base64 but not JSON** — valid base64 that decodes to garbage. JSON
   parse error.
3. **JSON but not an array** — e.g. `"hello"` or `{}` base64-encoded. serde
   rejects with type-mismatch.
4. **Empty array** — `[]`. Accepted shape; `EmptyChain` rejection.
5. **Single hop with zero `ops`** — empty BTreeSet. A2 vacuously holds but
   `InsufficientOps` fires on the command path.
6. **Hop with non-monotonic ops** — child grants `actuate:base:*` when
   parent only grants `actuate:arm:*`. Triggers `MonotonicityViolation`.
7. **Wildcard-only chain** — `[{"ops":["*"]}]`. Accepted, maximum
   authority; covered by `wildcard-only.b64` corpus seed.
8. **Expired hop** — `exp` in the past. Triggers `Expired`.
9. **Future-`nbf` hop** — `nbf` after `now`. Triggers `NotYetValid`.
10. **Cross-chain splice** — hop from chain B inserted into chain A.
    Pre-v11-1.2: signature still verifies (root identity unchanged), so
    only the application catches it. Post-v11-1.2:
    `PredecessorDigestMismatch`.

The `fuzz_pca_chain` corpus seeds (v12-N-20) cover classes 1–9; class 10
needs a paired chain fixture which is queued under v11 1.2.
