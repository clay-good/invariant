"""Smoke tests for the bimanual two-arm env (v11 3.1)."""

import hashlib
import json

import pytest

from isaac.envs.bimanual_arms import (
    BIMANUAL_PAIRS,
    EPISODES_PER_PAIR,
    EPISODES_TOTAL,
    STEPS_PER_EPISODE,
    generate_bimanual_command,
    load_profile,
    run_bimanual_episode,
    validate_command_within_limits,
)


@pytest.fixture(params=BIMANUAL_PAIRS, ids=lambda p: f"{p[0]}__{p[1]}")
def pair(request):
    left_name, right_name = request.param
    return load_profile(left_name), load_profile(right_name)


class TestCampaignConfig:
    def test_episode_count(self):
        assert EPISODES_TOTAL == 200_000

    def test_steps_per_episode(self):
        assert STEPS_PER_EPISODE == 300

    def test_episodes_per_pair(self):
        assert EPISODES_PER_PAIR == 100_000

    def test_pair_list(self):
        assert BIMANUAL_PAIRS == [
            ("franka_panda", "kuka_iiwa14"),
            ("ur10", "abb_gofa"),
        ]


class TestGenerateCommand:
    def test_joint_names_namespaced(self, pair):
        left, right = pair
        cmd = generate_bimanual_command(left, right, 0, 300, 1)
        names = [js["name"] for js in cmd["joint_states"]]
        assert all(n.startswith("left_") or n.startswith("right_") for n in names)
        left_count = sum(1 for n in names if n.startswith("left_"))
        right_count = sum(1 for n in names if n.startswith("right_"))
        assert left_count == len(left["joints"])
        assert right_count == len(right["joints"])

    def test_metadata_records_both_profiles(self, pair):
        left, right = pair
        cmd = generate_bimanual_command(left, right, 0, 300, 1)
        assert cmd["metadata"]["left_profile"] == left["name"]
        assert cmd["metadata"]["right_profile"] == right["name"]
        assert cmd["metadata"]["scenario"] == "J-08_multi_robot_distraction_pass"

    def test_two_end_effectors_present(self, pair):
        left, right = pair
        cmd = generate_bimanual_command(left, right, 0, 300, 1)
        names = {ee["name"] for ee in cmd["end_effector_positions"]}
        assert names == {"left_end_effector", "right_end_effector"}


class TestHappyPathValidates:
    def test_full_10_step_episode_has_no_violations(self, pair):
        left, right = pair
        cmds = run_bimanual_episode(left, right, steps=10)
        for i, cmd in enumerate(cmds):
            ok, v = validate_command_within_limits(cmd, left, right)
            assert ok, f"step {i}: {v}"


class TestDeterministicHash:
    @staticmethod
    def _hash(cmds):
        canonical = []
        for c in cmds:
            canonical.append({
                "seq": c["sequence"],
                "joints": [
                    (j["name"], round(j["position"], 12))
                    for j in c["joint_states"]
                ],
            })
        return hashlib.sha256(json.dumps(canonical, sort_keys=True).encode()).hexdigest()

    def test_two_runs_produce_same_hash(self, pair):
        left, right = pair
        a = run_bimanual_episode(left, right, steps=10)
        b = run_bimanual_episode(left, right, steps=10)
        assert self._hash(a) == self._hash(b)
