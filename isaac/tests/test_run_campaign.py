"""Smoke tests for the campaign dispatcher (v11 3.1)."""

import json
from pathlib import Path

import pytest

from isaac.run_campaign import (
    enumerate_routes,
    load_campaign,
    main,
    resolve_route,
)


class TestResolveRoute:
    def test_walking_gait_routes_to_humanoid_walk(self):
        r = resolve_route("walking_gait_validation")
        assert r is not None
        assert r.env_module == "isaac.envs.humanoid_walk"

    def test_locomotion_routes_to_quadruped(self):
        r = resolve_route("locomotion_runaway")
        assert r is not None
        assert r.env_module == "isaac.envs.quadruped_locomotion"

    def test_workspace_routes_to_mobile_base(self):
        r = resolve_route("workspace_boundary_sweep")
        assert r is not None
        assert r.env_module == "isaac.envs.mobile_base_navigation"

    def test_multi_robot_distraction_routes_to_bimanual(self):
        r = resolve_route("multi_robot_distraction")
        assert r is not None
        assert r.env_module == "isaac.envs.bimanual_arms"

    def test_dexterous_routes_to_dexterous_env(self):
        r = resolve_route("dexterous_manipulation")
        assert r is not None
        assert r.env_module == "isaac.envs.dexterous_manipulation"

    def test_cnc_routes_to_cnc_env(self):
        r = resolve_route("cnc_tending_full_cycle")
        assert r is not None
        assert r.env_module == "isaac.envs.cnc_tending"

    def test_unknown_scenario_returns_none(self):
        assert resolve_route("nonexistent_scenario_qqq") is None


class TestEnumerateRoutes:
    def test_flat_scenarios_shape(self):
        cfg = {
            "scenarios": [
                {"scenario_type": "walking_gait_validation"},
                {"scenario_type": "locomotion_runaway"},
                {"scenario_type": "totally_unknown_xyz"},
            ]
        }
        rows = enumerate_routes(cfg)
        assert len(rows) == 3
        assert rows[0][1] is not None
        assert rows[1][1] is not None
        assert rows[2][1] is None

    def test_nested_categories_shape(self):
        cfg = {
            "categories": {
                "A": {"scenarios": [{"scenario_type": "walking_gait_validation"}]},
                "B": {"scenarios": [{"scenario_type": "dexterous_manipulation"}]},
            }
        }
        rows = enumerate_routes(cfg)
        assert len(rows) == 2


class TestMainCli:
    def _write_cfg(self, tmp_path: Path, data: dict) -> Path:
        p = tmp_path / "campaign.json"
        p.write_text(json.dumps(data))
        return p

    def test_dry_run_all_known_returns_zero(self, tmp_path, capsys):
        cfg = self._write_cfg(
            tmp_path,
            {"scenarios": [{"scenario_type": "walking_gait_validation"}]},
        )
        rc = main(["--config", str(cfg), "--seed", "0", "--output", str(tmp_path / "out"), "--dry-run"])
        assert rc == 0
        out = capsys.readouterr().out
        assert "DISPATCH" in out

    def test_dry_run_with_unknown_returns_one(self, tmp_path, capsys):
        cfg = self._write_cfg(
            tmp_path,
            {"scenarios": [{"scenario_type": "totally_unknown_xyz"}]},
        )
        rc = main(["--config", str(cfg), "--seed", "0", "--output", str(tmp_path / "out"), "--dry-run"])
        assert rc == 1
        out = capsys.readouterr().out
        assert "SKIP" in out

    def test_missing_config_returns_two(self, tmp_path, capsys):
        rc = main([
            "--config", str(tmp_path / "nope.json"),
            "--seed", "0",
            "--output", str(tmp_path / "out"),
        ])
        assert rc == 2

    def test_empty_scenarios_returns_two(self, tmp_path, capsys):
        cfg = self._write_cfg(tmp_path, {"scenarios": []})
        rc = main(["--config", str(cfg), "--seed", "0", "--output", str(tmp_path / "out")])
        assert rc == 2


def test_load_campaign_supports_json(tmp_path: Path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"scenarios": [{"scenario_type": "x"}]}))
    assert load_campaign(p) == {"scenarios": [{"scenario_type": "x"}]}
