"""Smoke tests for the humanoid walking env (v11 3.1, Category D-02).

Asserts the generator emits a 10-step happy-path gait that stays inside
every profile's locomotion + per-joint envelope, and produces a stable
final-state hash from a fixed seed (here: the deterministic step index).
"""

import hashlib
import json

import pytest

from isaac.envs.humanoid_walk import (
    EPISODES_PER_PROFILE,
    EPISODES_TOTAL,
    HUMANOID_PROFILES,
    STEPS_PER_EPISODE,
    generate_humanoid_walk_command,
    get_margins,
    load_profile,
    run_humanoid_walk_episode,
    validate_command_within_limits,
)


@pytest.fixture(params=HUMANOID_PROFILES)
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
        assert EPISODES_PER_PROFILE == 150_000

    def test_profile_list(self):
        # humanoid_28dof intentionally excluded — it has a `stability` block
        # but no `locomotion`, so the gait validator has nothing to check.
        assert HUMANOID_PROFILES == ["unitree_h1", "bd_atlas"]


class TestProfileLoading:
    def test_load_all_profiles(self):
        for name in HUMANOID_PROFILES:
            profile = load_profile(name)
            assert len(profile["joints"]) > 0
            # Every humanoid env profile must carry a locomotion block —
            # without it the locomotion envelope checks degenerate.
            assert "locomotion" in profile, f"{name}: missing locomotion config"


class TestGenerateCommand:
    def test_produces_valid_json(self, profile):
        cmd = generate_humanoid_walk_command(
            profile, step_index=0, total_steps=300, sequence=1
        )
        json_str = json.dumps(cmd)
        parsed = json.loads(json_str)
        assert parsed["sequence"] == 1
        assert parsed["source"] == "isaac_lab_campaign"
        assert len(parsed["joint_states"]) == len(profile["joints"])

    def test_metadata_marks_scenario(self, profile):
        cmd = generate_humanoid_walk_command(
            profile, step_index=10, total_steps=300, sequence=11
        )
        assert cmd["metadata"]["scenario"] == "D-02_walking_gait_validation"
        assert cmd["metadata"]["step"] == "10"

    def test_locomotion_state_present(self, profile):
        cmd = generate_humanoid_walk_command(
            profile, step_index=0, total_steps=300, sequence=1
        )
        ls = cmd["locomotion_state"]
        loco = profile["locomotion"]
        assert abs(ls["base_linear_velocity"][0] - 0.5 * loco["max_locomotion_velocity"]) < 1e-9
        assert abs(ls["step_length"] - 0.6 * loco["max_step_length"]) < 1e-9
        assert ls["step_height"] > loco.get("min_foot_clearance", 0.0)
        assert ls["step_height"] <= loco["max_step_height"] + 1e-9

    def test_swing_foot_alternates_by_parity(self, profile):
        even = generate_humanoid_walk_command(profile, 0, 300, 1)
        odd = generate_humanoid_walk_command(profile, 1, 300, 2)
        assert even["locomotion_state"]["swing_foot"] == "left"
        assert odd["locomotion_state"]["swing_foot"] == "right"


class TestHappyPathValidates:
    def test_full_10_step_episode_has_no_violations(self, profile):
        cmds = run_humanoid_walk_episode(profile, steps=10)
        for i, cmd in enumerate(cmds):
            ok, v = validate_command_within_limits(cmd, profile)
            assert ok, f"step {i}: {v}"


class TestDeterministicHash:
    """The dry-run path must be deterministic from the seed (here: step
    index). Two runs over the same profile / step count must produce
    identical joint-position / locomotion sequences. We hash a
    canonicalized projection so wall-clock `timestamp` doesn't leak in."""

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
                    "swing_foot": c["locomotion_state"]["swing_foot"],
                },
            })
        return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()

    def test_two_runs_produce_same_hash(self, profile):
        a = run_humanoid_walk_episode(profile, steps=10)
        b = run_humanoid_walk_episode(profile, steps=10)
        assert self._hash(a) == self._hash(b)
