"""Smoke tests for the mobile-base navigation env (v11 3.1)."""

import hashlib
import json

import pytest

from isaac.envs.mobile_base_navigation import (
    EPISODES_PER_PROFILE,
    EPISODES_TOTAL,
    MOBILE_PROFILES,
    STEPS_PER_EPISODE,
    generate_mobile_base_command,
    load_profile,
    run_mobile_base_episode,
    validate_command_within_limits,
)


@pytest.fixture(params=MOBILE_PROFILES)
def profile_name(request):
    return request.param


@pytest.fixture
def profile(profile_name):
    return load_profile(profile_name)


class TestCampaignConfig:
    def test_episode_count(self):
        assert EPISODES_TOTAL == 200_000

    def test_steps_per_episode(self):
        assert STEPS_PER_EPISODE == 300

    def test_episodes_per_profile(self):
        assert EPISODES_PER_PROFILE == 100_000

    def test_profile_list(self):
        assert MOBILE_PROFILES == ["hello_stretch", "pal_tiago"]


class TestProfileLoading:
    def test_load_all_profiles(self):
        for name in MOBILE_PROFILES:
            profile = load_profile(name)
            assert len(profile["joints"]) > 0
            assert "locomotion" in profile, f"{name}: missing locomotion config"
            assert "workspace" in profile, f"{name}: missing workspace config"


class TestGenerateCommand:
    def test_metadata_marks_scenario(self, profile):
        cmd = generate_mobile_base_command(profile, 10, 300, 11)
        assert cmd["metadata"]["scenario"] == "C-01_workspace_boundary_sweep"
        assert cmd["metadata"]["step"] == "10"

    def test_locomotion_state_present(self, profile):
        cmd = generate_mobile_base_command(profile, 0, 300, 1)
        ls = cmd["locomotion_state"]
        loco = profile["locomotion"]
        # Linear speed bounded by 30% of max_locomotion_velocity.
        import math
        vx, vy, _ = ls["base_linear_velocity"]
        assert math.hypot(vx, vy) <= 0.30 * loco["max_locomotion_velocity"] + 1e-9
        # Heading rate bounded by 20% of max_heading_rate.
        assert abs(ls["base_angular_velocity"][2]) <= 0.20 * loco["max_heading_rate"] + 1e-9

    def test_ee_inside_workspace(self, profile):
        cmd = generate_mobile_base_command(profile, 0, 300, 1)
        ws = profile["workspace"]
        for ee in cmd["end_effector_positions"]:
            p = ee["position"]
            for i in range(3):
                assert ws["min"][i] - 1e-9 <= p[i] <= ws["max"][i] + 1e-9


class TestHappyPathValidates:
    def test_full_10_step_episode_has_no_violations(self, profile):
        cmds = run_mobile_base_episode(profile, steps=10)
        for i, cmd in enumerate(cmds):
            ok, v = validate_command_within_limits(cmd, profile)
            assert ok, f"step {i}: {v}"


class TestDeterministicHash:
    @staticmethod
    def _hash(cmds):
        canonical = []
        for c in cmds:
            canonical.append({
                "seq": c["sequence"],
                "base_x": c["metadata"]["base_x"],
                "base_y": c["metadata"]["base_y"],
                "loco_vx": round(c["locomotion_state"]["base_linear_velocity"][0], 12),
                "loco_wz": round(c["locomotion_state"]["base_angular_velocity"][2], 12),
            })
        return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()

    def test_two_runs_produce_same_hash(self, profile):
        a = run_mobile_base_episode(profile, steps=10)
        b = run_mobile_base_episode(profile, steps=10)
        assert self._hash(a) == self._hash(b)
