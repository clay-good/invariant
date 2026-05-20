#!/usr/bin/env bash
# Seed fuzz corpora from real fixtures committed elsewhere in the repo.
#
# `cargo fuzz` benefits enormously from a non-empty starting corpus —
# coverage-guided fuzzers need a foothold to mutate from. Without seeded
# inputs, libFuzzer starts from empty/random bytes and may take hours to
# find its way into the JSON parsing path.
#
# This script copies (or, for inputs we don't have on hand, generates)
# at least 8 representative starting inputs per fuzz target into
# `fuzz/corpus/<target>/`. Run it before the first `cargo fuzz run`,
# and re-run any time the source fixtures change.
#
# v12-N-20.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FUZZ_DIR="${REPO_ROOT}/fuzz"
CORPUS_ROOT="${FUZZ_DIR}/corpus"
EXAMPLES_ROBOTICS="${REPO_ROOT}/examples/robotics"
PROFILES_ROBOTICS="${REPO_ROOT}/profiles/robotics"

mkdir -p \
    "${CORPUS_ROOT}/fuzz_command_json" \
    "${CORPUS_ROOT}/fuzz_profile_json" \
    "${CORPUS_ROOT}/fuzz_pca_chain" \
    "${CORPUS_ROOT}/fuzz_validate_pipeline" \
    "${CORPUS_ROOT}/bridge_handle_line" \
    "${CORPUS_ROOT}/fuzz_cose_envelope" \
    "${CORPUS_ROOT}/fuzz_json_bomb"

# ----------------------------------------------------------------------
# fuzz_command_json — arbitrary bytes interpreted as a Command JSON.
#
# Seeds: real example command files + a handful of small synthetic
# variants the fuzzer can mutate cheaply.
# ----------------------------------------------------------------------
echo "[seed] fuzz_command_json"
cp "${EXAMPLES_ROBOTICS}/safe-command.json"      "${CORPUS_ROOT}/fuzz_command_json/safe-command.json"
cp "${EXAMPLES_ROBOTICS}/dangerous-command.json" "${CORPUS_ROOT}/fuzz_command_json/dangerous-command.json"

# Six tiny synthetic seeds (well under 1 KiB each) covering common
# command-shape edge cases the example files don't reach.
cat > "${CORPUS_ROOT}/fuzz_command_json/empty-object.json" <<'EOF'
{}
EOF

cat > "${CORPUS_ROOT}/fuzz_command_json/null-joints.json" <<'EOF'
{"timestamp":"2026-01-01T00:00:00Z","source":"x","sequence":0,"joint_states":null,"delta_time":0.01,"authority":{"pca_chain":"","required_ops":[]}}
EOF

cat > "${CORPUS_ROOT}/fuzz_command_json/nan-velocity.json" <<'EOF'
{"timestamp":"2026-01-01T00:00:00Z","source":"x","sequence":0,"joint_states":[{"name":"j1","position":0.0,"velocity":"NaN","effort":0.0}],"delta_time":0.01,"authority":{"pca_chain":"","required_ops":[]}}
EOF

cat > "${CORPUS_ROOT}/fuzz_command_json/unicode-source.json" <<'EOF'
{"timestamp":"2026-01-01T00:00:00Z","source":"ééé","sequence":0,"joint_states":[],"delta_time":0.0,"authority":{"pca_chain":"","required_ops":[]}}
EOF

cat > "${CORPUS_ROOT}/fuzz_command_json/oversized-seq.json" <<'EOF'
{"timestamp":"2026-01-01T00:00:00Z","source":"x","sequence":18446744073709551615,"joint_states":[],"delta_time":0.0,"authority":{"pca_chain":"","required_ops":[]}}
EOF

cat > "${CORPUS_ROOT}/fuzz_command_json/bom-prefixed.json" <<'EOF'
{"timestamp":"2026-01-01T00:00:00Z","source":"x","sequence":1,"joint_states":[],"delta_time":0.01,"authority":{"pca_chain":"","required_ops":[]}}
EOF

# ----------------------------------------------------------------------
# fuzz_profile_json — arbitrary bytes interpreted as a RobotProfile JSON.
#
# Seeds: every built-in robot profile + the empty-object case the loader
# must reject without panicking.
# ----------------------------------------------------------------------
echo "[seed] fuzz_profile_json"
i=0
for profile in "${PROFILES_ROBOTICS}"/*.json; do
    name="$(basename "${profile}")"
    cp "${profile}" "${CORPUS_ROOT}/fuzz_profile_json/${name}"
    i=$((i + 1))
    if [[ $i -ge 8 ]]; then
        break
    fi
done
cat > "${CORPUS_ROOT}/fuzz_profile_json/empty-object.json" <<'EOF'
{}
EOF

# ----------------------------------------------------------------------
# fuzz_pca_chain — arbitrary bytes interpreted as a base64-encoded
# `Vec<SignedPca>`. We don't have committed chain fixtures yet, so we
# generate eight short base64 payloads programmatically.
# ----------------------------------------------------------------------
echo "[seed] fuzz_pca_chain"
python3 - "${CORPUS_ROOT}/fuzz_pca_chain" <<'PY'
import base64
import json
import os
import sys

out_dir = sys.argv[1]
os.makedirs(out_dir, exist_ok=True)

# An empty Vec<SignedPca> base64-encoded — exercises the "no hops" path.
empty: list = []

# Single-hop chain with placeholder signature (will fail crypto, but
# parses cleanly and pushes the fuzzer past JSON deserialization).
single = [
    {
        "pca": {
            "p_0": "alice",
            "ops": ["actuate:left_arm:*"],
            "kid": "key-1",
            "exp": None,
            "nbf": None,
        },
        "signature": "AAAA" * 22,  # 88 chars ≈ 64 bytes, padding-free
    }
]

# Two-hop chain.
two_hop = [
    {
        "pca": {
            "p_0": "alice",
            "ops": ["actuate:*"],
            "kid": "key-1",
            "exp": None,
            "nbf": None,
        },
        "signature": "BBBB" * 22,
    },
    {
        "pca": {
            "p_0": "alice",
            "ops": ["actuate:right_arm:*"],
            "kid": "key-2",
            "exp": None,
            "nbf": None,
        },
        "signature": "CCCC" * 22,
    },
]

seeds = {
    "empty-chain.b64": empty,
    "single-hop.b64": single,
    "two-hop.b64": two_hop,
    "wildcard-only.b64": [
        {
            "pca": {"p_0": "root", "ops": ["*"], "kid": "k", "exp": None, "nbf": None},
            "signature": "ZZZZ" * 22,
        }
    ],
    "expired-hop.b64": [
        {
            "pca": {
                "p_0": "alice",
                "ops": ["actuate:*"],
                "kid": "key-1",
                "exp": "2020-01-01T00:00:00Z",
                "nbf": None,
            },
            "signature": "DDDD" * 22,
        }
    ],
    "future-nbf.b64": [
        {
            "pca": {
                "p_0": "alice",
                "ops": ["actuate:*"],
                "kid": "key-1",
                "exp": None,
                "nbf": "2099-01-01T00:00:00Z",
            },
            "signature": "EEEE" * 22,
        }
    ],
}

# Five raw-bytes seeds for the "not even base64" path libFuzzer should
# also probe.
for name, payload in seeds.items():
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    with open(os.path.join(out_dir, name), "w") as fh:
        fh.write(encoded)

# Two non-base64 seeds so libFuzzer exercises the early-return path.
with open(os.path.join(out_dir, "not-base64.txt"), "wb") as fh:
    fh.write(b"\x00\xff\x7f garbage ====")
with open(os.path.join(out_dir, "empty-bytes.bin"), "wb") as fh:
    pass

print(f"wrote {len(seeds) + 2} seeds to {out_dir}")
PY

# ----------------------------------------------------------------------
# bridge_handle_line — newline-framed JSON from the Isaac Lab bridge.
# Each seed is one or more `\n`-separated lines that should parse
# cleanly (heartbeat, command, blank lines) or exercise the bounded
# read / malformed paths.
# ----------------------------------------------------------------------
echo "[seed] bridge_handle_line"
printf '{"heartbeat":true}\n'                                      > "${CORPUS_ROOT}/bridge_handle_line/heartbeat.txt"
printf '{"heartbeat":false}\n'                                     > "${CORPUS_ROOT}/bridge_handle_line/heartbeat-false.txt"
printf ''                                                          > "${CORPUS_ROOT}/bridge_handle_line/empty.txt"
printf '\n\n\n'                                                    > "${CORPUS_ROOT}/bridge_handle_line/blank-lines.txt"
printf '{"heartbeat":true}\n{"heartbeat":true}\n'                  > "${CORPUS_ROOT}/bridge_handle_line/two-frames.txt"
printf '{not json\n'                                               > "${CORPUS_ROOT}/bridge_handle_line/malformed.txt"
printf '{"heartbeat":true}\x00trailing'                            > "${CORPUS_ROOT}/bridge_handle_line/nul-byte.bin"
printf '%s\n' '{"timestamp":"2026-01-01T00:00:00Z","source":"x","sequence":1,"joint_states":[],"delta_time":0.01,"authority":{"pca_chain":"","required_ops":[]}}' \
    > "${CORPUS_ROOT}/bridge_handle_line/partial-command.txt"

# ----------------------------------------------------------------------
# fuzz_validate_pipeline — same input shape as fuzz_command_json (it
# deserialises a Command then drives the full validator). Reuse the
# command corpus so the validator-pipeline target inherits real and
# synthetic command shapes.
# ----------------------------------------------------------------------
echo "[seed] fuzz_validate_pipeline (reuses fuzz_command_json corpus)"
cp "${CORPUS_ROOT}/fuzz_command_json"/*.json \
   "${CORPUS_ROOT}/fuzz_validate_pipeline/"

# ----------------------------------------------------------------------
# fuzz_cose_envelope — raw bytes interpreted as a single-hop
# SignedPca.raw (inner COSE_Sign1 CBOR). v11 2.11 N-07. Seeds are
# minimal CBOR shapes the parser must reject cleanly: the empty byte
# string, a single 0x00 byte, an obviously non-CBOR ASCII payload, a
# fixed CBOR array prefix, and four cycled junk patterns.
# ----------------------------------------------------------------------
echo "[seed] fuzz_cose_envelope"
printf ''                                                          > "${CORPUS_ROOT}/fuzz_cose_envelope/empty.bin"
printf '\x00'                                                      > "${CORPUS_ROOT}/fuzz_cose_envelope/single-null-byte.bin"
printf 'not cose'                                                  > "${CORPUS_ROOT}/fuzz_cose_envelope/ascii-not-cose.bin"
printf '\x84'                                                      > "${CORPUS_ROOT}/fuzz_cose_envelope/cbor-array-4-prefix.bin"
printf '\xd2\x84'                                                  > "${CORPUS_ROOT}/fuzz_cose_envelope/cose-sign1-tag-prefix.bin"
printf '\x84\x40\xa0\x40\x40'                                      > "${CORPUS_ROOT}/fuzz_cose_envelope/four-empty-bstr.bin"
printf '\xff\xff\xff\xff\xff\xff\xff\xff'                          > "${CORPUS_ROOT}/fuzz_cose_envelope/all-ones.bin"
printf '\xa1\x18\x40\x18\x40'                                      > "${CORPUS_ROOT}/fuzz_cose_envelope/cbor-map-one-entry.bin"

# ----------------------------------------------------------------------
# fuzz_json_bomb — JSON shapes that stress depth + adversarial parsing.
# v11 2.11 N-06. First byte selects nesting depth in the fuzz harness;
# remaining bytes form the JSON body. Seeds: deeply-nested arrays,
# repeated keys, oversized exponents, NaN/∞, BOM-prefix, empty.
# ----------------------------------------------------------------------
echo "[seed] fuzz_json_bomb"
printf '\x00'                                                      > "${CORPUS_ROOT}/fuzz_json_bomb/depth-0.bin"
printf '\x10[[[[[[[[[[[[[[[[42]]]]]]]]]]]]]]]]'                    > "${CORPUS_ROOT}/fuzz_json_bomb/depth-16-array.bin"
printf '\x08{"a":1,"a":2,"a":3}'                                   > "${CORPUS_ROOT}/fuzz_json_bomb/repeated-keys.bin"
printf '\x00{"x":1e9999999}'                                       > "${CORPUS_ROOT}/fuzz_json_bomb/huge-exponent.bin"
printf '\x00{"x":NaN}'                                             > "${CORPUS_ROOT}/fuzz_json_bomb/nan-literal.bin"
printf '\x00\xef\xbb\xbf{"x":1}'                                   > "${CORPUS_ROOT}/fuzz_json_bomb/bom-prefix.bin"
printf '\x00null'                                                  > "${CORPUS_ROOT}/fuzz_json_bomb/just-null.bin"
printf '\x00""'                                                    > "${CORPUS_ROOT}/fuzz_json_bomb/empty-string.bin"

# Summary.
echo
echo "Corpus counts:"
for d in "${CORPUS_ROOT}"/*; do
    target="$(basename "${d}")"
    count="$(find "${d}" -type f | wc -l | tr -d ' ')"
    echo "  ${target}: ${count} seed(s)"
done
