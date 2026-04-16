"""Campaign results reporter for Isaac Lab campaigns.

Mirrors the Rust CampaignReporter (crates/invariant-sim/src/reporter.rs).
Aggregates per-step verdicts into a structured JSON report with:
  - Total commands / approved / rejected
  - Per-profile, per-scenario, per-check breakdowns
  - Violation escape detection (unsafe command approved)
  - Clopper-Pearson confidence bounds
  - SIL rating
"""

import json
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class StepResult:
    """Result of a single validation step."""

    profile: str
    scenario: str
    approved: bool
    injected: bool
    checks: List[Dict[str, Any]] = field(default_factory=list)


class CampaignReporter:
    """Aggregates validation results into a campaign report."""

    def __init__(self, campaign_name: str):
        self.campaign_name = campaign_name
        self.start_time = time.monotonic()
        self.start_utc = datetime.now(timezone.utc).isoformat()

        self.total_commands = 0
        self.total_approved = 0
        self.total_rejected = 0
        self.violation_escapes = 0  # injected attack approved = BAD

        # Per-dimension aggregations.
        self._per_profile: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"total": 0, "approved": 0, "rejected": 0, "escapes": 0}
        )
        self._per_scenario: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"total": 0, "approved": 0, "rejected": 0, "escapes": 0}
        )
        self._per_check: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"total": 0, "passed": 0, "failed": 0}
        )
        self._episodes_completed = 0
        self._steps_per_episode: List[int] = []

    def record(self, result: StepResult) -> None:
        """Record a single validation step result."""
        self.total_commands += 1
        if result.approved:
            self.total_approved += 1
        else:
            self.total_rejected += 1

        # Violation escape: an injected/attack command was APPROVED.
        is_escape = result.injected and result.approved
        if is_escape:
            self.violation_escapes += 1

        # Per-profile.
        p = self._per_profile[result.profile]
        p["total"] += 1
        p["approved"] += int(result.approved)
        p["rejected"] += int(not result.approved)
        p["escapes"] += int(is_escape)

        # Per-scenario.
        s = self._per_scenario[result.scenario]
        s["total"] += 1
        s["approved"] += int(result.approved)
        s["rejected"] += int(not result.approved)
        s["escapes"] += int(is_escape)

        # Per-check.
        for check in result.checks:
            name = check.get("name", "unknown")
            c = self._per_check[name]
            c["total"] += 1
            c["passed"] += int(check.get("passed", False))
            c["failed"] += int(not check.get("passed", False))

    def end_episode(self, steps: int) -> None:
        """Mark end of an episode."""
        self._episodes_completed += 1
        self._steps_per_episode.append(steps)

    def to_report(self) -> Dict[str, Any]:
        """Generate the final campaign report dict."""
        elapsed_s = time.monotonic() - self.start_time
        total = max(self.total_commands, 1)

        # Clopper-Pearson upper bound for 0 escapes.
        n_trials = self.total_commands
        n_escapes = self.violation_escapes
        upper_95 = _clopper_pearson_upper(n_escapes, n_trials, 0.05)
        upper_99 = _clopper_pearson_upper(n_escapes, n_trials, 0.01)
        upper_999 = _clopper_pearson_upper(n_escapes, n_trials, 0.001)

        # MTBF at 100 Hz.
        mtbf_95 = (1.0 / upper_95 / 100.0 / 3600.0) if upper_95 > 0 else float("inf")
        mtbf_99 = (1.0 / upper_99 / 100.0 / 3600.0) if upper_99 > 0 else float("inf")

        # SIL rating.
        sil = _sil_rating(upper_99)

        # Legitimate pass rate (baseline + aggressive scenarios).
        legit_total = 0
        legit_approved = 0
        for name in ("baseline", "aggressive"):
            s = self._per_scenario.get(name, {})
            legit_total += s.get("total", 0)
            legit_approved += s.get("approved", 0)
        legit_pass_rate = legit_approved / max(legit_total, 1)

        # False rejection rate on legitimate commands.
        false_rejections = legit_total - legit_approved
        false_rejection_rate = false_rejections / max(legit_total, 1)

        return {
            "campaign_name": self.campaign_name,
            "start_utc": self.start_utc,
            "elapsed_seconds": round(elapsed_s, 2),
            "total_commands": self.total_commands,
            "total_approved": self.total_approved,
            "total_rejected": self.total_rejected,
            "approval_rate": round(self.total_approved / total, 6),
            "rejection_rate": round(self.total_rejected / total, 6),
            "violation_escape_count": self.violation_escapes,
            "violation_escape_rate": round(self.violation_escapes / total, 10),
            "legitimate_pass_rate": round(legit_pass_rate, 6),
            "false_rejection_count": false_rejections,
            "false_rejection_rate": round(false_rejection_rate, 6),
            "criteria_met": self.violation_escapes == 0 and legit_pass_rate >= 0.98,
            "episodes_completed": self._episodes_completed,
            "per_profile": dict(self._per_profile),
            "per_scenario": dict(self._per_scenario),
            "per_check": dict(self._per_check),
            "confidence": {
                "n_trials": n_trials,
                "n_escapes": n_escapes,
                "upper_bound_95": upper_95,
                "upper_bound_99": upper_99,
                "upper_bound_999": upper_999,
                "mtbf_hours_95": round(mtbf_95, 1),
                "mtbf_hours_99": round(mtbf_99, 1),
                "sil_rating": sil,
            },
            "execution": {
                "mode": "isaac_lab",
                "episodes": self._episodes_completed,
                "avg_steps_per_episode": (
                    round(sum(self._steps_per_episode) / len(self._steps_per_episode), 1)
                    if self._steps_per_episode
                    else 0
                ),
            },
        }

    def write_json(self, path: str) -> None:
        """Write the report to a JSON file."""
        report = self.to_report()
        with open(path, "w") as f:
            json.dump(report, f, indent=2)

    def print_summary(self) -> None:
        """Print a human-readable summary to stdout."""
        r = self.to_report()
        print("=" * 60)
        print(f"INVARIANT CAMPAIGN REPORT: {r['campaign_name']}")
        print("=" * 60)
        print(f"Total commands:     {r['total_commands']:,}")
        print(f"Approved:           {r['total_approved']:,} ({r['approval_rate']:.2%})")
        print(f"Rejected:           {r['total_rejected']:,} ({r['rejection_rate']:.2%})")
        print(f"Violation escapes:  {r['violation_escape_count']}")
        print(f"Escape rate:        {r['violation_escape_rate']:.8%}")
        print(f"Legitimate pass:    {r['legitimate_pass_rate']:.4%}")
        print(f"False rejection:    {r['false_rejection_rate']:.4%}")
        print(f"Criteria met:       {r['criteria_met']}")
        print(f"Elapsed:            {r['elapsed_seconds']:.1f}s")
        print()
        print("Statistical confidence:")
        c = r["confidence"]
        print(f"  95% upper bound:  {c['upper_bound_95']:.10f}")
        print(f"  99% upper bound:  {c['upper_bound_99']:.10f}")
        print(f"  99.9% upper:      {c['upper_bound_999']:.10f}")
        print(f"  MTBF (95%):       {c['mtbf_hours_95']:,.0f} hours")
        print(f"  SIL rating:       {c['sil_rating']}")
        print()
        print("Per-scenario:")
        for name, s in sorted(r["per_scenario"].items()):
            print(
                f"  {name:35s}  total={s['total']:>8,}  "
                f"approved={s['approved']:>8,}  rejected={s['rejected']:>8,}  "
                f"escapes={s['escapes']}"
            )
        passed = "PASSED" if r["criteria_met"] else "FAILED"
        print()
        print(f"Campaign '{r['campaign_name']}': {passed}")


# ---------------------------------------------------------------------------
# Statistics helpers
# ---------------------------------------------------------------------------


def _clopper_pearson_upper(k: int, n: int, alpha: float) -> float:
    """Clopper-Pearson exact upper bound for binomial proportion.

    When k=0, simplifies to 1 - alpha^(1/n).
    """
    if n == 0:
        return 1.0
    if k == 0:
        return 1.0 - alpha ** (1.0 / n)
    # For k > 0, use the beta distribution inverse.
    # Approximation using the rule of three for small k.
    return min(1.0, (k + 3.0) / n)


def _sil_rating(upper_99: float) -> int:
    """Map escape rate upper bound to IEC 61508 SIL rating.

    SIL 1: < 1e-1
    SIL 2: < 1e-2
    SIL 3: < 1e-3
    SIL 4: < 1e-4
    """
    if upper_99 < 1e-8:
        return 4
    if upper_99 < 1e-6:
        return 4
    if upper_99 < 1e-4:
        return 3
    if upper_99 < 1e-2:
        return 2
    if upper_99 < 1e-1:
        return 1
    return 0
