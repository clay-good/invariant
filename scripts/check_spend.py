"""Cost-projection helpers for ``run_15m_campaign.sh`` (v12-N-7).

The 15M campaign runs in shards over many hours of GPU time. Operators set
``MAX_USD`` to put a ceiling on the total spend; before each shard the runner
calls into this module to project the *final* cost given how far along we
are. If the projection exceeds ``MAX_USD``, the runner aborts cleanly before
starting a new shard.

The math is deliberately conservative: linear extrapolation of elapsed
wall-clock time against the fraction of total work that has completed. We do
not have a real billing API to query, so the projection lives or dies by the
caller-supplied ``hourly_usd`` rate. Document the assumed rate alongside the
``MAX_USD`` invocation so it can be reconciled against the actual invoice
after the campaign closes.

Public API:

* :func:`project_total_spend(elapsed_seconds, fraction_complete, hourly_usd)`
* :func:`should_abort(elapsed_seconds, fraction_complete, hourly_usd, max_usd)`
* CLI entrypoint that emits a single-line ``OK`` / ``ABORT`` verdict so the
  shell wrapper can branch on the exit code.

All inputs are validated; bad inputs raise ``ValueError`` rather than
silently returning zero.
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional


def project_total_spend(
    elapsed_seconds: float,
    fraction_complete: float,
    hourly_usd: float,
) -> float:
    """Project the final spend in USD.

    ``elapsed_seconds`` is the wall-clock time spent so far on the campaign
    (not on the current shard). ``fraction_complete`` is in the open
    interval (0, 1]: the share of the *total* work that has finished. The
    rate ``hourly_usd`` is the operator's per-hour budget assumption.

    Returns the projected total cost in USD. Linear extrapolation only; no
    smoothing, no startup-cost amortisation. The caller compares the result
    against ``MAX_USD``.
    """
    if elapsed_seconds < 0:
        raise ValueError(f"elapsed_seconds must be non-negative, got {elapsed_seconds}")
    if not (0 < fraction_complete <= 1.0):
        raise ValueError(
            f"fraction_complete must be in (0, 1], got {fraction_complete}"
        )
    if hourly_usd < 0:
        raise ValueError(f"hourly_usd must be non-negative, got {hourly_usd}")

    spent = (elapsed_seconds / 3600.0) * hourly_usd
    return spent / fraction_complete


def should_abort(
    elapsed_seconds: float,
    fraction_complete: float,
    hourly_usd: float,
    max_usd: float,
) -> bool:
    """True iff the projected total spend strictly exceeds ``max_usd``.

    Edge cases:

    * ``max_usd == 0`` is a dry-run guard — abort before the first shard so
      operators can verify the script wiring without burning compute.
    * Projection at exactly ``max_usd`` does *not* abort; only strict excess
      is grounds for abort. This gives operators a single-decimal ceiling
      without rounding flakiness.
    """
    if max_usd < 0:
        raise ValueError(f"max_usd must be non-negative, got {max_usd}")
    if max_usd == 0:
        return True
    projected = project_total_spend(elapsed_seconds, fraction_complete, hourly_usd)
    return projected > max_usd


def _parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Project campaign spend and emit OK / ABORT for the 15m runner.",
    )
    parser.add_argument(
        "--elapsed-seconds",
        type=float,
        required=True,
        help="Wall-clock seconds spent on the campaign so far.",
    )
    parser.add_argument(
        "--fraction-complete",
        type=float,
        required=True,
        help="Share of total work completed, in (0, 1].",
    )
    parser.add_argument(
        "--hourly-usd",
        type=float,
        required=True,
        help="Assumed per-hour cost in USD.",
    )
    parser.add_argument(
        "--max-usd",
        type=float,
        required=True,
        help="Hard ceiling on the projected total spend.",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = _parse_args(argv)
    try:
        projected = project_total_spend(
            args.elapsed_seconds, args.fraction_complete, args.hourly_usd
        )
    except ValueError as e:
        print(f"check_spend: invalid input: {e}", file=sys.stderr)
        return 2

    if args.max_usd == 0:
        print(
            f"ABORT projected=${projected:.2f} ceiling=$0.00 "
            f"(MAX_USD=0 is a dry-run abort)"
        )
        return 1

    if projected > args.max_usd:
        print(
            f"ABORT projected=${projected:.2f} ceiling=${args.max_usd:.2f}"
        )
        return 1

    print(f"OK projected=${projected:.2f} ceiling=${args.max_usd:.2f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
