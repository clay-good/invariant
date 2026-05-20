"""Campaign dispatcher (v11 3.1) — pick an Isaac env per scenario row.

File: isaac/run_campaign.py
Spec: spec-15m-campaign.md §3 — every env owns a slice of the campaign.

Usage:

    python -m isaac.run_campaign --config <CAMPAIGN_YAML> \\
        --seed <N> --output <DIR> [--dry-run]

The dispatcher reads a campaign YAML (the same shape `invariant-sim`
emits) and routes each `scenario_type` to one of the in-process envs
under `isaac/envs/`. With `--dry-run` it enumerates the routes without
generating commands so an operator can sanity-check the YAML against
the registered envs before paying for a real RunPod run.

Resolution table (extend when adding new envs):

    cnc_tending / spatial_*         -> isaac.envs.cnc_tending (CncTendingEnv class)
    dexterous_manipulation          -> isaac.envs.dexterous_manipulation
    walking_gait / com_*            -> isaac.envs.humanoid_walk
    locomotion_*                    -> isaac.envs.quadruped_locomotion
    workspace_boundary_sweep        -> isaac.envs.mobile_base_navigation
    multi_robot_distraction         -> isaac.envs.bimanual_arms

Scenario types that have no in-process env yet print a `SKIP` row and
the dispatcher returns a non-zero exit code so CI can detect coverage
regressions.
"""

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

# Env modules are imported lazily inside `dispatch` so `--dry-run` can
# enumerate without paying for env import side effects (e.g. profile JSON
# parsing for every profile each env declares).


# (scenario_type substring → (env_module, entry_callable_name)). Order is
# significant — the first match wins.
_ROUTES: Sequence[Tuple[str, str, str]] = (
    # cnc_tending uses the full Isaac-Lab `CncTendingEnv` class — call the
    # class constructor + `.run(...)`, not a function.
    ("cnc_tending", "isaac.envs.cnc_tending", "CncTendingEnv"),
    ("spatial_", "isaac.envs.cnc_tending", "CncTendingEnv"),
    ("dexterous_manipulation", "isaac.envs.dexterous_manipulation", "run_dexterous_episode"),
    ("walking_gait", "isaac.envs.humanoid_walk", "run_humanoid_walk_episode"),
    ("com_", "isaac.envs.humanoid_walk", "run_humanoid_walk_episode"),
    ("locomotion_", "isaac.envs.quadruped_locomotion", "run_quadruped_episode"),
    ("workspace_boundary_sweep", "isaac.envs.mobile_base_navigation", "run_mobile_base_episode"),
    ("multi_robot_distraction", "isaac.envs.bimanual_arms", "run_bimanual_episode"),
)


@dataclass(frozen=True)
class Route:
    """The chosen (env_module, entry_callable_name) for a scenario row."""

    scenario_type: str
    env_module: str
    entry: str


def resolve_route(scenario_type: str) -> Optional[Route]:
    """Map a scenario_type string to a `Route`, or None when unknown."""
    name = scenario_type.lower()
    for needle, module, entry in _ROUTES:
        if needle in name:
            return Route(scenario_type=scenario_type, env_module=module, entry=entry)
    return None


def load_campaign(path: Path) -> Dict[str, Any]:
    """Load a campaign config from YAML *or* JSON. Pure-stdlib JSON is
    always available; YAML support is gated on `PyYAML` and falls back
    gracefully so the dispatcher is testable in environments without it."""
    text = path.read_text()
    suffix = path.suffix.lower()
    if suffix == ".json":
        return json.loads(text)
    try:
        import yaml  # type: ignore
    except ImportError as e:
        raise RuntimeError(
            f"PyYAML required to load {path}; install pyyaml or convert to JSON"
        ) from e
    return yaml.safe_load(text)


def enumerate_routes(config: Dict[str, Any]) -> List[Tuple[Dict[str, Any], Optional[Route]]]:
    """Return (scenario_row, route_or_None) for every row in the config.

    Accepts either a flat top-level `scenarios: [...]` or a nested
    `categories: {A: {scenarios: [...]}, ...}` shape; both are present
    across the committed `campaigns/*.yaml` files.
    """
    rows: List[Dict[str, Any]] = []
    if "scenarios" in config:
        rows.extend(config.get("scenarios") or [])
    cats = config.get("categories") or {}
    for cat in cats.values():
        rows.extend((cat or {}).get("scenarios") or [])
    out: List[Tuple[Dict[str, Any], Optional[Route]]] = []
    for row in rows:
        stype = row.get("scenario_type", "")
        out.append((row, resolve_route(stype)))
    return out


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="isaac.run_campaign")
    p.add_argument("--config", type=Path, required=True, help="Campaign YAML or JSON")
    p.add_argument("--seed", type=int, default=0, help="Reproducibility seed (forwarded to envs)")
    p.add_argument("--output", type=Path, required=True, help="Output dir for shard JSONL")
    p.add_argument("--dry-run", action="store_true", help="Enumerate routes; do not generate")
    args = p.parse_args(argv)

    try:
        config = load_campaign(args.config)
    except Exception as e:
        print(f"error: failed to load {args.config}: {e}", file=sys.stderr)
        return 2

    rows = enumerate_routes(config)
    if not rows:
        print(f"error: no scenarios found in {args.config}", file=sys.stderr)
        return 2

    missing: List[str] = []
    for row, route in rows:
        stype = row.get("scenario_type", "?")
        if route is None:
            print(f"SKIP  {stype}: no env mapping")
            missing.append(stype)
        else:
            print(f"DISPATCH  {stype} -> {route.env_module}:{route.entry}")

    if args.dry_run:
        return 0 if not missing else 1

    # Non-dry-run: stub. Real generation lives in the envs themselves;
    # plumbing the full shard-write loop is outside the scope of v11 3.1
    # (the spec only requires `--dry-run` to enumerate without crashing).
    args.output.mkdir(parents=True, exist_ok=True)
    print(
        "note: shard generation is not wired in run_campaign; "
        "call each env's run_*_episode directly. --dry-run is the contract."
    )
    return 0 if not missing else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
