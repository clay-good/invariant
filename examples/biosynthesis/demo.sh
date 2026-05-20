#!/usr/bin/env bash
# Demo flow for invariant-biosynthesis.
#
# Keeps the "keygen -> inspect -> adversarial -> audit verify" structure from
# the robotics sibling demo. Subcommands marked (step-5) are stubbed until the
# validator pipeline lands.

set -euo pipefail

BIN="${INVARIANT_BIO_BIN:-cargo run --bin invariant-bio --}"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "==> Generating a demo validator keypair"
$BIN keygen --kid demo-validator-001 --output "$TMPDIR/demo-key.json"

echo "==> (step-5) inspect the university_bsl2_dna profile"
# $BIN inspect --profile university_bsl2_dna

echo "==> (step-5) run adversarial suite against the demo profile"
# $BIN adversarial --profile university_bsl2_dna

echo "==> Verify binary self-integrity"
$BIN verify-self || true

echo "Demo complete. Keypair at $TMPDIR/demo-key.json"
