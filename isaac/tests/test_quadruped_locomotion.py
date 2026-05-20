"""Smoke tests for the quadruped locomotion env (v11 3.1, Category D-02)."""

import hashlib
import json

import pytest

from isaac.envs.quadruped_locomotion import (
    EPISODES_PER_PROFILE,
    EPISODES_TOTAL,
    QUADRUPED_PROFILES,
    STEPS_PER_EPISODE,
    TROT_PAIRS,
    generate_quadruped_command,
    load_profile,
    run_quadruped_episode,
    validate_command_within_limits,
)


@pytest.fixture(params=QUADRUPED_PROFILES)
def profile_name(request):
    return request.param


@pytest.fixture
def profile(profile_name):
    return load_profile(profile_name)


class TestCampaignConfig:
    def test_episode_count(self):
        assert EPISODES_TOTAL == 300_000

    def test_steps_per_episode(self):
        assert STEPS_PER_EPISODE == 300

    def test_episodes_per_profile(self):
        assert EPISODES_PER_PROFILE == 100_000

    def test_profile_list(self):
        # quadruped_12dof excluded — no `locomotion` block in the profile.
        assert QUADRUPED_PROFILES == [
            "spot",
            "spot_with_arm",
            "anybotics_anymal",
        ]


class TestProfileLoading:
    def test_load_all_profiles(self):
        for name in QUADRUPED_PROFILES:
            profile = load_profile(name)
            assert len(profile["joints"]) > 0
            assert "locomotion" in profile, f"{name}: missing locomotion config"


class TestGenerateCommand:
    def test_metadata_marks_scenario(self, profile):
        cmd = generate_quadruped_command(
            profile, step_index=10, total_steps=300, sequence=11
        )
        assert cmd["metadata"]["scenario"] == "D-02_walking_gait_validation"
        assert cmd["metadata"]["step"] == "10"

    def test_trot_pair_alternates_by_parity(self, profile):
        even = generate_quadruped_command(profile, 0, 300, 1)
        odd = generate_quadruped_command(profile, 1, 300, 2)
        assert even["metadata"]["trot_pair"] == TROT_PAIRS[0]
        assert odd["metadata"]["trot_pair"] == TROT_PAIRS[1]

    def test_locomotion_at_40_percent(self, profile):
        cmd = generate_quadruped_command(profile, 0, 300, 1)
        loco = profile["locomotion"]
        ls = cmd["locomotion_state"]
        assert abs(ls["base_linear_velocity"][0] - 0.4 * loco["max_locomotion_velocity"]) < 1e-9
        assert abs(ls["step_length"] - 0.5 * loco["max_step_length"]) < 1e-9
        assert ls["step_height"] <= loco["max_step_height"] + 1e-9


class TestHappyPathValidates:
    def test_full_10_step_episode_has_no_violations(self, profile):
        cmds = run_quadruped_episode(profile, steps=10)
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
                "joints": [
                    (j["name"], round(j["position"], 12), round(j["velocity"], 12), round(j["effort"], 12))
                    for j in c["joint_states"]
                ],
                "loco": {
                    "vx": round(c["locomotion_state"]["base_linear_velocity"][0], 12),
                    "wz": round(c["locomotion_state"]["base_angular_velocity"][2], 12),
                    "step_len": round(c["locomotion_state"]["step_length"], 12),
                    "trot_pair": c["metadata"]["trot_pair"],
                },
            })
        return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()

    def test_two_runs_produce_same_hash(self, profile):
        a = run_quadruped_episode(profile, steps=10)
        b = run_quadruped_episode(profile, steps=10)
        assert self._hash(a) == self._hash(b)
