"""Tests for the CNC tending environment.

These tests exercise the state machine logic, protocol formatting, cycle
sequencing, and Haas simulator without requiring Isaac Sim or a running
Invariant server.
"""

import json
import math

import pytest

from isaac.envs.cell_config import (
    BILLET_MASS_KG,
    CycleState,
    DEFAULT_BILLETS,
    GripperState,
    HaasState,
    HOME_JOINT_POSITIONS,
    JOINT_NAMES,
    SPINDLE_ZONE_DISABLED_STATES,
    WAYPOINTS,
)
from isaac.envs.cnc_tending import (
    CellObservation,
    CycleCoordinator,
    CncTendingEnv,
    HaasSimulator,
    build_invariant_command,
    interpolate_waypoint,
)


# ---------------------------------------------------------------------------
# HaasSimulator tests
# ---------------------------------------------------------------------------


class TestHaasSimulator:
    def test_initial_state_is_idle(self):
        haas = HaasSimulator()
        assert haas.state == HaasState.IDLE
        assert haas.is_ready
        assert not haas.is_cutting
        assert not haas.is_complete

    def test_start_cycle(self):
        haas = HaasSimulator()
        haas.start_cycle()
        assert haas.state == HaasState.CUTTING
        assert haas.is_cutting

    def test_start_cycle_requires_idle(self):
        haas = HaasSimulator()
        haas.start_cycle()
        with pytest.raises(RuntimeError, match="not IDLE"):
            haas.start_cycle()

    def test_cycle_completes_after_time(self):
        haas = HaasSimulator(cycle_time_s=1.0)
        haas.start_cycle()
        haas.step(0.5)
        assert haas.is_cutting
        haas.step(0.6)  # Total 1.1s > 1.0s
        assert haas.is_complete

    def test_acknowledge_complete(self):
        haas = HaasSimulator(cycle_time_s=0.1)
        haas.start_cycle()
        haas.step(0.2)
        assert haas.is_complete
        haas.acknowledge_complete()
        assert haas.is_ready

    def test_acknowledge_requires_complete(self):
        haas = HaasSimulator()
        with pytest.raises(RuntimeError, match="not COMPLETE"):
            haas.acknowledge_complete()

    def test_reset(self):
        haas = HaasSimulator(cycle_time_s=0.1)
        haas.start_cycle()
        haas.step(0.2)
        haas.reset()
        assert haas.state == HaasState.IDLE


# ---------------------------------------------------------------------------
# CycleCoordinator tests
# ---------------------------------------------------------------------------


class TestCycleCoordinator:
    def test_initial_state(self):
        cc = CycleCoordinator(num_billets=5)
        assert cc.state == CycleState.IDLE
        assert cc.billets_remaining == 5
        assert cc.parts_completed == 0

    def test_zone_overrides_disabled_in_loading_states(self):
        cc = CycleCoordinator()
        for state in SPINDLE_ZONE_DISABLED_STATES:
            cc.state = state
            overrides = cc.zone_overrides
            assert overrides.get("haas_spindle_zone") is False, (
                f"Expected spindle zone disabled in {state.name}"
            )

    def test_zone_overrides_empty_in_other_states(self):
        cc = CycleCoordinator()
        non_disabled = set(CycleState) - SPINDLE_ZONE_DISABLED_STATES
        for state in non_disabled:
            cc.state = state
            assert cc.zone_overrides == {}, (
                f"Expected no overrides in {state.name}"
            )

    def test_full_single_billet_cycle(self):
        cc = CycleCoordinator(num_billets=1)
        haas = HaasSimulator(cycle_time_s=0.01)

        states_visited = [cc.state]
        all_commands = []
        max_steps = 100

        for _ in range(max_steps):
            state, cmds = cc.advance(haas, GripperState.OPEN)
            states_visited.append(state)
            all_commands.extend(cmds)

            # Execute Haas commands.
            if "HAAS_CYCLE_START" in cmds:
                haas.start_cycle()
            # Fast-forward machining.
            if state == CycleState.WAIT_MACHINING:
                haas.step(1.0)

            if state == CycleState.CYCLE_COMPLETE:
                break

        assert cc.state == CycleState.CYCLE_COMPLETE
        assert cc.parts_completed == 1
        assert cc.billets_remaining == 0
        assert "GRIPPER_CLOSE" in all_commands
        assert "GRIPPER_OPEN" in all_commands
        assert "VISE_CLAMP" in all_commands
        assert "VISE_UNCLAMP" in all_commands
        assert "HAAS_CYCLE_START" in all_commands

    def test_multi_billet_cycle(self):
        cc = CycleCoordinator(num_billets=3)
        haas = HaasSimulator(cycle_time_s=0.01)

        max_steps = 500

        for _ in range(max_steps):
            state, cmds = cc.advance(haas, GripperState.OPEN)
            if "HAAS_CYCLE_START" in cmds:
                haas.start_cycle()
            if state == CycleState.WAIT_MACHINING:
                haas.step(1.0)
            if state == CycleState.CYCLE_COMPLETE:
                break

        assert cc.parts_completed == 3
        assert cc.billets_remaining == 0

    def test_target_waypoint_mapping(self):
        cc = CycleCoordinator()
        for state in CycleState:
            cc.state = state
            wp = cc.target_waypoint
            assert wp is not None, f"No waypoint mapped for {state.name}"
            assert wp in WAYPOINTS, f"Waypoint {wp} not in WAYPOINTS"

    def test_reset(self):
        cc = CycleCoordinator(num_billets=5)
        cc.state = CycleState.WAIT_MACHINING
        cc.parts_completed = 3
        cc.billets_remaining = 2
        cc.reset(num_billets=10)
        assert cc.state == CycleState.IDLE
        assert cc.billets_remaining == 10
        assert cc.parts_completed == 0


# ---------------------------------------------------------------------------
# Command builder tests
# ---------------------------------------------------------------------------


class TestBuildInvariantCommand:
    def test_produces_valid_json(self):
        cmd = build_invariant_command(
            joint_positions={n: 0.0 for n in JOINT_NAMES},
            joint_velocities={n: 0.0 for n in JOINT_NAMES},
            joint_efforts={n: 0.0 for n in JOINT_NAMES},
            ee_position=(0.0, 0.0, 1.0),
            delta_time=0.008,
            sequence=1,
            pca_chain_b64="dGVzdA==",
            required_ops=["actuate:*"],
        )
        # Must be JSON-serializable.
        json_str = json.dumps(cmd)
        parsed = json.loads(json_str)
        assert parsed["sequence"] == 1
        assert parsed["source"] == "isaac_lab"
        assert len(parsed["joint_states"]) == 6
        assert parsed["authority"]["pca_chain"] == "dGVzdA=="

    def test_includes_zone_overrides(self):
        cmd = build_invariant_command(
            joint_positions={n: 0.0 for n in JOINT_NAMES},
            joint_velocities={n: 0.0 for n in JOINT_NAMES},
            joint_efforts={n: 0.0 for n in JOINT_NAMES},
            ee_position=(0.0, 0.0, 1.0),
            delta_time=0.008,
            sequence=1,
            pca_chain_b64="dGVzdA==",
            required_ops=["actuate:*"],
            zone_overrides={"haas_spindle_zone": False},
        )
        assert cmd["zone_overrides"] == {"haas_spindle_zone": False}

    def test_excludes_zone_overrides_when_none(self):
        cmd = build_invariant_command(
            joint_positions={n: 0.0 for n in JOINT_NAMES},
            joint_velocities={n: 0.0 for n in JOINT_NAMES},
            joint_efforts={n: 0.0 for n in JOINT_NAMES},
            ee_position=(0.0, 0.0, 1.0),
            delta_time=0.008,
            sequence=1,
            pca_chain_b64="dGVzdA==",
            required_ops=["actuate:*"],
        )
        assert "zone_overrides" not in cmd

    def test_includes_payload(self):
        cmd = build_invariant_command(
            joint_positions={n: 0.0 for n in JOINT_NAMES},
            joint_velocities={n: 0.0 for n in JOINT_NAMES},
            joint_efforts={n: 0.0 for n in JOINT_NAMES},
            ee_position=(0.0, 0.0, 1.0),
            delta_time=0.008,
            sequence=1,
            pca_chain_b64="dGVzdA==",
            required_ops=["actuate:*"],
            estimated_payload_kg=1.6,
        )
        assert cmd["estimated_payload_kg"] == 1.6

    def test_joint_state_format(self):
        positions = {n: float(i) for i, n in enumerate(JOINT_NAMES)}
        cmd = build_invariant_command(
            joint_positions=positions,
            joint_velocities={n: 0.0 for n in JOINT_NAMES},
            joint_efforts={n: 0.0 for n in JOINT_NAMES},
            ee_position=(0.0, 0.0, 1.0),
            delta_time=0.008,
            sequence=42,
            pca_chain_b64="dGVzdA==",
            required_ops=["actuate:*"],
        )
        for i, js in enumerate(cmd["joint_states"]):
            assert js["name"] == JOINT_NAMES[i]
            assert js["position"] == float(i)
            assert "velocity" in js
            assert "effort" in js


# ---------------------------------------------------------------------------
# Interpolation tests
# ---------------------------------------------------------------------------


class TestInterpolateWaypoint:
    def test_reaches_target_when_close(self):
        result = interpolate_waypoint((0.0, 0.0, 0.0), (0.005, 0.0, 0.0))
        assert result == (0.005, 0.0, 0.0)

    def test_clamps_to_max_step(self):
        result = interpolate_waypoint(
            (0.0, 0.0, 0.0), (1.0, 0.0, 0.0), max_step_m=0.1
        )
        assert abs(result[0] - 0.1) < 1e-9
        assert abs(result[1]) < 1e-9
        assert abs(result[2]) < 1e-9

    def test_diagonal_movement(self):
        result = interpolate_waypoint(
            (0.0, 0.0, 0.0), (1.0, 1.0, 1.0), max_step_m=0.1
        )
        dist = math.sqrt(sum(c * c for c in result))
        assert abs(dist - 0.1) < 1e-9

    def test_already_at_target(self):
        result = interpolate_waypoint((1.0, 2.0, 3.0), (1.0, 2.0, 3.0))
        assert result == (1.0, 2.0, 3.0)


# ---------------------------------------------------------------------------
# CellObservation tests
# ---------------------------------------------------------------------------


class TestCellObservation:
    def test_to_dict_format(self):
        obs = CellObservation(
            timestamp_ns=1000000,
            joint_positions={n: 0.0 for n in JOINT_NAMES},
            joint_velocities={n: 0.0 for n in JOINT_NAMES},
            joint_efforts={n: 0.0 for n in JOINT_NAMES},
            end_effector_position=(0.0, -0.3, 1.2),
            force_torque=(0.0, 0.0, 0.0, 0.0, 0.0, 0.0),
            haas_state="IDLE",
            gripper_state="OPEN",
            billet_in_gripper=False,
            billets_remaining=15,
            cycle_state="IDLE",
        )
        d = obs.to_dict()
        assert d["type"] == "observation"
        assert d["timestamp_ns"] == 1000000
        assert len(d["joint_states"]) == 6
        assert d["haas_state"] == "IDLE"
        assert d["billets_remaining"] == 15

    def test_to_dict_is_json_serializable(self):
        obs = CellObservation(
            timestamp_ns=0,
            joint_positions={n: 0.0 for n in JOINT_NAMES},
            joint_velocities={n: 0.0 for n in JOINT_NAMES},
            joint_efforts={n: 0.0 for n in JOINT_NAMES},
            end_effector_position=(0.0, 0.0, 0.0),
            force_torque=(0.0, 0.0, 0.0, 0.0, 0.0, 0.0),
            haas_state="CUTTING",
            gripper_state="CLOSED",
            billet_in_gripper=True,
            billets_remaining=5,
            cycle_state="WAIT_MACHINING",
        )
        json_str = json.dumps(obs.to_dict())
        parsed = json.loads(json_str)
        assert parsed["billet_in_gripper"] is True


# ---------------------------------------------------------------------------
# CncTendingEnv tests (dry-run, no bridge)
# ---------------------------------------------------------------------------


class TestCncTendingEnv:
    def test_init_defaults(self):
        env = CncTendingEnv()
        assert env.num_envs == 1
        assert env.cycle.billets_remaining == DEFAULT_BILLETS
        assert env.haas.state == HaasState.IDLE
        assert env.gripper == GripperState.OPEN
        assert not env.is_done

    def test_reset(self):
        env = CncTendingEnv(num_billets=5)
        env.cycle.state = CycleState.WAIT_MACHINING
        obs = env.reset(num_billets=10)
        assert obs.cycle_state == "IDLE"
        assert obs.billets_remaining == 10
        assert obs.haas_state == "IDLE"

    def test_step_dry_run(self):
        env = CncTendingEnv(num_billets=1)
        obs, info = env.step()
        assert info["approved"] is True
        assert obs.haas_state == "IDLE"

    def test_step_with_target_ee(self):
        env = CncTendingEnv()
        obs0 = env.reset()
        target = WAYPOINTS["W1_stock_pick_approach"]
        obs, info = env.step(target_ee_position=target)
        # EE should have moved toward target (but not reached it in one step).
        assert obs.end_effector_position != obs0.end_effector_position

    def test_cycle_step_advances_state(self):
        env = CncTendingEnv(num_billets=1)
        env.reset()
        # First cycle_step should advance from IDLE to PICK_APPROACH.
        obs, info = env.cycle_step()
        assert obs.cycle_state == "PICK_APPROACH"

    def test_full_single_billet_dry_run(self):
        env = CncTendingEnv(
            num_billets=1, haas_cycle_time_s=0.01
        )
        env.reset()
        stats = env.run_single_billet_cycle(fast_forward_machining=True)
        assert env.is_done
        assert env.cycle.parts_completed == 1
        assert stats.commands_sent > 0
        assert stats.commands_approved > 0

    def test_context_manager(self):
        with CncTendingEnv() as env:
            env.reset()
            assert env.cycle.state == CycleState.IDLE

    def test_repr(self):
        env = CncTendingEnv(num_billets=5)
        r = repr(env)
        assert "CncTendingEnv" in r
        assert "billets=5" in r

    def test_sequence_increments(self):
        env = CncTendingEnv()
        env.reset()
        env.step()
        env.step()
        env.step()
        assert env._sequence == 3

    def test_heartbeat_counting(self):
        env = CncTendingEnv()
        env.reset()
        # Run enough steps to trigger at least one heartbeat.
        for _ in range(100):
            env.step()
        assert env.stats.heartbeats_sent > 0
