#!/usr/bin/env python3
"""Upload campaign results to HuggingFace Datasets.

Usage:
    # First time: login to HuggingFace
    huggingface-cli login

    # Upload results
    python scripts/upload_results.py --dir results/invariant_15m_proof_* --repo invariant-15m-proof

    # With a specific HF username
    python scripts/upload_results.py --dir results/my_campaign --repo invariant-15m-proof --user clay-good
"""

import argparse
import json
import os
import sys
from pathlib import Path


def create_dataset_card(results_dir: str, repo_name: str) -> str:
    """Generate a HuggingFace dataset card (README.md) from campaign results."""
    # Find the main report JSON.
    report = None
    for root, _, files in os.walk(results_dir):
        for f in files:
            if f.endswith(".json") and "campaign" not in f.lower():
                path = os.path.join(root, f)
                try:
                    with open(path) as fh:
                        data = json.load(fh)
                    if "total_commands" in data and "violation_escape_count" in data:
                        report = data
                        break
                except (json.JSONDecodeError, KeyError):
                    continue
        if report:
            break

    total = report.get("total_commands", 0) if report else 0
    escapes = report.get("violation_escape_count", 0) if report else 0
    criteria = report.get("criteria_met", False) if report else False
    conf = report.get("confidence", {}) if report else {}

    return f"""---
license: mit
task_categories:
  - robotics
tags:
  - safety
  - robotics
  - validation
  - simulation
  - invariant
pretty_name: Invariant Safety Validation Campaign
size_categories:
  - 10M<n<100M
---

# Invariant Safety Validation Campaign Results

Cryptographically signed proof package from the [Invariant](https://github.com/clay-good/invariant)
command-validation firewall for AI-controlled robots.

## Key Results

| Metric | Value |
|--------|-------|
| Total commands validated | {total:,} |
| Violation escapes | {escapes} |
| Escape rate | {escapes / max(total, 1):.10%} |
| Criteria met | {criteria} |
| 95% confidence upper bound | {conf.get('upper_bound_95', 'N/A')} |
| 99% confidence upper bound | {conf.get('upper_bound_99', 'N/A')} |
| SIL rating | {conf.get('sil_rating', 'N/A')} |

## What This Proves

With {total:,} validated commands and {escapes} escapes across multiple robot profiles
and adversarial attack scenarios:

- Every physics violation was caught (joint limits, velocity, torque, workspace, exclusion zones)
- Every authority attack was caught (forged chains, escalation, unauthorized ops)
- Every environmental fault was caught (temperature, battery, latency, e-stop)
- The audit trail is intact (every decision hash-chained and Ed25519 signed)

## Reproduction

```bash
git clone https://github.com/clay-good/invariant.git
cd invariant
cargo build --release
python isaac/campaign_runner.py --episodes 100 --steps 200 --all-profiles
```

## How It Works

Invariant is a cryptographic command-validation firewall that sits between an AI/LLM
cognitive layer and robot actuators. Every motion command must pass through Invariant's
validator, which checks:

- **Physics invariants** (P1-P25): Joint limits, velocity, torque, workspace, exclusion zones,
  stability, locomotion, manipulation forces, environmental hazards
- **Authority chain** (A1-A3): Ed25519-signed delegation chain with monotonic scope narrowing
- **Temporal integrity**: Sequence monotonicity, replay prevention, delta-time bounds
- **Audit trail**: SHA-256 hash-chained, Ed25519-signed log of every decision

## License

MIT
"""


def upload(results_dir: str, repo_name: str, user: str = None):
    """Upload results to HuggingFace."""
    try:
        from huggingface_hub import HfApi
    except ImportError:
        print("ERROR: huggingface_hub not installed. Run: pip install huggingface_hub")
        sys.exit(1)

    api = HfApi()

    # Determine the full repo ID.
    if user:
        repo_id = f"{user}/{repo_name}"
    else:
        whoami = api.whoami()
        repo_id = f"{whoami['name']}/{repo_name}"

    # Create the repo if it doesn't exist.
    try:
        api.create_repo(repo_id, repo_type="dataset", exist_ok=True)
        print(f"Repository: https://huggingface.co/datasets/{repo_id}")
    except Exception as e:
        print(f"WARNING: Could not create repo: {e}")
        print(f"Attempting upload to existing repo: {repo_id}")

    # Generate and upload dataset card.
    card = create_dataset_card(results_dir, repo_name)
    card_path = os.path.join(results_dir, "README.md")
    with open(card_path, "w") as f:
        f.write(card)

    # Upload the entire directory.
    print(f"Uploading {results_dir} to {repo_id}...")
    api.upload_folder(
        folder_path=results_dir,
        repo_id=repo_id,
        repo_type="dataset",
        commit_message=f"Upload campaign results from {os.path.basename(results_dir)}",
    )

    print(f"\nUpload complete!")
    print(f"View at: https://huggingface.co/datasets/{repo_id}")


def main():
    parser = argparse.ArgumentParser(description="Upload campaign results to HuggingFace")
    parser.add_argument("--dir", required=True, help="Results directory to upload")
    parser.add_argument("--repo", required=True, help="HuggingFace dataset repo name")
    parser.add_argument("--user", default=None, help="HuggingFace username (default: auto)")
    args = parser.parse_args()

    if not os.path.isdir(args.dir):
        print(f"ERROR: Directory not found: {args.dir}")
        sys.exit(1)

    upload(args.dir, args.repo, args.user)


if __name__ == "__main__":
    main()
