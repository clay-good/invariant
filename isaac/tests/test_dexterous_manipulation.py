"""Tests for the A-07 dexterous manipulation scenario.

Verifies that the sinusoidal command generator produces valid commands
for all three dexterous profiles (shadow_hand, kinova_gen3, franka_panda)
across a full episode, exercising P1-P4 limits without violations.
"""

import json

import pytest

from isaac.envs.dexterous_manipulation import (
    DEXTEROUS_PROFILES,
    EPISODES_PER_PROFILE,
    EPISODES_TOTAL,
    STEPS_PER_EPISODE,
    generate_dexterous_command,
    get_margins,
    load_profile,
    run_dexterous_episode,
    validate_command_within_limits,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(params=DEXTEROUS_PROFILES)
def profile_name(request):
    return request.param


@pytest.fixture
def profile(profile_name):
    return load_profile(profile_name)


# ---------------------------------------------------------------------------
# Configuration tests
# ---------------------------------------------------------------------------


class TestCampaignConfig:
    def test_episode_count(self):
        assert EPISODES_TOTAL == 300_000

    def test_steps_per_episode(self):
        assert STEPS_PER_EPISODE == 300

    def test_episodes_per_profile(self):
        assert EPISODES_PER_PROFILE == 100_000

    def test_profile_list(self):
        assert DEXTEROUS_PROFILES == [
            "shadow_hand", "kinova_gen3", "franka_panda"
        ]


# ---------------------------------------------------------------------------
# Profile loading
# ---------------------------------------------------------------------------


class TestProfileLoading:
    def test_load_all_profiles(self):
        for name in DEXTEROUS_PROFILES:
            profile = load_profile(name)
            assert profile["name"] == name
            assert len(profile["joints"]) > 0

    def test_shadow_hand_joint_count(self):
        profile = load_profile("shadow_hand")
        assert len(profile["joints"]) == 24

    def test_kinova_gen3_joint_count(self):
        profile = load_profile("kinova_gen3")
        assert len(profile["joints"]) == 7

    def test_franka_panda_joint_count(self):
        profile = load_profile("franka_panda")
        assert len(profile["joints"]) == 7


# ---------------------------------------------------------------------------
# Margins
# ---------------------------------------------------------------------------


class TestMargins:
    def test_shadow_hand_has_explicit_margins(self):
        profile = load_profile("shadow_hand")
        m = get_margins(profile)
        assert m["position_margin"] == 0.03
        assert m["velocity_margin"] == 0.10
        assert m["torque_margin"] == 0.05

    def test_franka_uses_defaults(self):
        profile = load_profile("franka_panda")
        m = get_margins(profile)
        assert m["position_margin"] == 0.05
        assert m["velocity_margin"] == 0.10
        assert m["torque_margin"] == 0.10


# ---------------------------------------------------------------------------
# Command generation
# ---------------------------------------------------------------------------


class TestGenerateCommand:
    def test_produces_valid_json(self, profile):
        cmd = generate_dexterous_command(
            profile, step_index=0, total_steps=300, sequence=1
        )
        json_str = json.dumps(cmd)
        parsed = json.loads(json_str)
        assert parsed["sequence"] == 1
        assert parsed["source"] == "isaac_lab_campaign"
        assert len(parsed["joint_states"]) == len(profile["joints"])

    def test_joint_count_matches_profile(self, profile):
        cmd = generate_dexterous_command(
            profile, step_index=50, total_steps=300, sequence=5
        )
        assert len(cmd["joint_states"]) == len(profile["joints"])

    def test_delta_time_is_half_max(self, profile):
        cmd = generate_dexterous_command(
            profile, step_index=0, total_steps=300, sequence=1
        )
        expected = 0.5 * profile.get("max_delta_time", 0.01)
        assert abs(cmd["delta_time"] - expected) < 1e-12

    def test_authority_fields_present(self, profile):
        cmd = generate_dexterous_command(
            profile, step_index=0, total_steps=300, sequence=1
        )
        assert "authority" in cmd
        assert cmd["authority"]["required_ops"] == ["actuate:*"]

    def test_metadata_contains_scenario(self, profile):
        cmd = generate_dexterous_command(
            profile, step_index=10, total_steps=300, sequence=11
        )
        assert cmd["metadata"]["scenario"] == "A-07_dexterous_manipulation"
        assert cmd["metadata"]["step"] == 10

    def test_ee_positions_present(self, profile):
        cmd = generate_dexterous_command(
            profile, step_index=0, total_steps=300, sequence=1
        )
        assert len(cmd["end_effector_positions"]) > 0
        for ee in cmd["end_effector_positions"]:
            assert "name" in ee
            assert len(ee["position"]) == 3


# ---------------------------------------------------------------------------
# Per-joint sinusoidal sweep correctness
# ---------------------------------------------------------------------------


class TestSinusoidalSweep:
    def test_distinct_frequencies(self, profile):
        """Each joint should have a distinct frequency f_j = 1.0 + j * 0.3."""
        n = len(profile["joints"])
        freqs = [1.0 + j * 0.3 for j in range(n)]
        assert len(set(freqs)) == n

    def test_position_at_step_zero(self, profile):
        """At step 0, sin(0) = 0, so position should be at midpoint."""
        cmd = generate_dexterous_command(
            profile, step_index=0, total_steps=300, sequence=1
        )
        margins = get_margins(profile)
        pos_margin = margins["position_margin"]

        for i, js in enumerate(cmd["joint_states"]):
            joint = profile["joints"][i]
            j_range = joint["max"] - joint["min"]
            eff_min = joint["min"] + j_range * pos_margin
            eff_max = joint["max"] - j_range * pos_margin
            mid = (eff_min + eff_max) / 2.0
            assert abs(js["position"] - mid) < 1e-9, (
                f"Joint {js['name']} at step 0: expected {mid}, "
                f"got {js['position']}"
            )

    def test_velocity_nonnegative(self, profile):
        """Velocity uses |cos(phi)| so should always be >= 0."""
        for step in range(0, 300, 30):
            cmd = generate_dexterous_command(
                profile, step_index=step, total_steps=300, sequence=step + 1
            )
            for js in cmd["joint_states"]:
                assert js["velocity"] >= -1e-12, (
                    f"Negative velocity at step {step}: {js['velocity']}"
                )

    def test_effort_constant(self, profile):
        """Effort is constant: max_torque * (1 - torque_margin) * 0.4."""
        margins = get_margins(profile)
        torque_margin = margins["torque_margin"]

        cmd0 = generate_dexterous_command(
            profile, step_index=0, total_steps=300, sequence=1
        )
        cmd99 = generate_dexterous_command(
            profile, step_index=99, total_steps=300, sequence=100
        )

        for i, joint in enumerate(profile["joints"]):
            expected = joint["max_torque"] * (1.0 - torque_margin) * 0.4
            assert abs(cmd0["joint_states"][i]["effort"] - expected) < 1e-9
            assert abs(cmd99["joint_states"][i]["effort"] - expected) < 1e-9


# ---------------------------------------------------------------------------
# Validation: all commands stay within limits
# ---------------------------------------------------------------------------


class TestValidation:
    def test_single_command_valid(self, profile):
        cmd = generate_dexterous_command(
            profile, step_index=150, total_steps=300, sequence=151
        )
        ok, violations = validate_command_within_limits(cmd, profile)
        assert ok, f"Violations: {violations}"

    def test_full_episode_all_valid(self, profile):
        """Every command in a 300-step episode must pass validation."""
        commands = run_dexterous_episode(profile)
        assert len(commands) == 300

        for i, cmd in enumerate(commands):
            ok, violations = validate_command_within_limits(cmd, profile)
            assert ok, (
                f"Step {i} violations for {profile['name']}: {violations}"
            )

    def test_boundary_steps_valid(self, profile):
        """First, last, and mid steps must all be valid."""
        for step in [0, 149, 299]:
            cmd = generate_dexterous_command(
                profile, step_index=step, total_steps=300, sequence=step + 1
            )
            ok, violations = validate_command_within_limits(cmd, profile)
            assert ok, (
                f"Step {step} violations for {profile['name']}: {violations}"
            )

    def test_position_stays_within_85_pct_effective_range(self, profile):
        """Position amplitude is 85% of half the effective range."""
        margins = get_margins(profile)
        pos_margin = margins["position_margin"]

        commands = run_dexterous_episode(profile)
        for i, joint in enumerate(profile["joints"]):
            j_range = joint["max"] - joint["min"]
            eff_min = joint["min"] + j_range * pos_margin
            eff_max = joint["max"] - j_range * pos_margin
            mid = (eff_min + eff_max) / 2.0
            half_range = (eff_max - eff_min) / 2.0
            max_deviation = half_range * 0.85

            for cmd in commands:
                pos = cmd["joint_states"][i]["position"]
                deviation = abs(pos - mid)
                assert deviation <= max_deviation + 1e-9, (
                    f"Joint {joint['name']}: deviation {deviation} > "
                    f"max {max_deviation}"
                )


# ---------------------------------------------------------------------------
# Episode runner
# ---------------------------------------------------------------------------


class TestRunEpisode:
    def test_episode_length(self, profile):
        commands = run_dexterous_episode(profile)
        assert len(commands) == STEPS_PER_EPISODE

    def test_sequences_monotonic(self, profile):
        commands = run_dexterous_episode(profile, sequence_offset=100)
        seqs = [cmd["sequence"] for cmd in commands]
        assert seqs == list(range(101, 101 + STEPS_PER_EPISODE))

    def test_episode_json_serializable(self, profile):
        commands = run_dexterous_episode(profile, steps=10)
        for cmd in commands:
            json.dumps(cmd)


# ---------------------------------------------------------------------------
# Shadow Hand specific: high DOF coverage
# ---------------------------------------------------------------------------


class TestShadowHandSpecifics:
    def test_24_joints_all_swept(self):
        profile = load_profile("shadow_hand")
        commands = run_dexterous_episode(profile)

        for j in range(24):
            positions = [cmd["joint_states"][j]["position"] for cmd in commands]
            pos_range = max(positions) - min(positions)
            assert pos_range > 0.01, (
                f"Joint {j} ({profile['joints'][j]['name']}) has near-zero "
                f"sweep range: {pos_range}"
            )

    def test_all_phase_relationships_covered(self):
        """With 24 joints at distinct frequencies over 300 steps, we should
        see diverse inter-joint phase combinations."""
        profile = load_profile("shadow_hand")
        cmd_first = generate_dexterous_command(
            profile, step_index=0, total_steps=300, sequence=1
        )
        cmd_mid = generate_dexterous_command(
            profile, step_index=150, total_steps=300, sequence=151
        )

        pos_first = [js["position"] for js in cmd_first["joint_states"]]
        pos_mid = [js["position"] for js in cmd_mid["joint_states"]]

        differences = [abs(a - b) for a, b in zip(pos_first, pos_mid)]
        nonzero = sum(1 for d in differences if d > 1e-6)
        assert nonzero >= 20, (
            f"Expected most joints to differ between step 0 and 150, "
            f"got {nonzero}/24"
        )
