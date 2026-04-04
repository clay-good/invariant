"""End-to-end bridge integration tests.

Starts the Invariant serve process with --bridge, connects the Python
InvariantBridge client over Unix socket, and validates the full
command → verdict round-trip.

Requires: the `invariant` binary (built via `cargo build`).
Does NOT require Isaac Sim — uses raw JSON commands.
"""

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

# Add the bridge client to the path.
_repo_root = Path(__file__).resolve().parent.parent.parent
_bridge_client_dir = _repo_root / "crates" / "invariant-sim"
sys.path.insert(0, str(_bridge_client_dir))

from invariant_isaac_bridge import InvariantBridge  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _find_invariant_binary() -> str:
    """Locate the invariant binary in target/debug or target/release."""
    for mode in ("debug", "release"):
        candidate = _repo_root / "target" / mode / "invariant"
        if candidate.is_file() and os.access(str(candidate), os.X_OK):
            return str(candidate)
    pytest.skip(
        "invariant binary not found — run `cargo build` first"
    )


@pytest.fixture(scope="module")
def bridge_server():
    """Start an Invariant serve process with --bridge and yield connection info.

    The server runs in trust-plane mode (auto-issues PCA chains) so we
    don't need to manually construct authority chains for the tests.
    """
    binary = _find_invariant_binary()

    tmpdir = tempfile.mkdtemp(prefix="invariant_e2e_")
    keys_path = os.path.join(tmpdir, "keys.json")
    socket_path = os.path.join(tmpdir, "invariant.sock")

    # Generate keys.
    keygen_result = subprocess.run(
        [binary, "keygen", "--kid", "e2e-test", "--output", keys_path],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert keygen_result.returncode == 0, (
        f"keygen failed: {keygen_result.stderr}"
    )

    # Locate the production profile.
    profile_path = str(_repo_root / "profiles" / "ur10e_cnc_tending.json")
    assert os.path.isfile(profile_path), (
        f"Profile not found: {profile_path}"
    )

    # Start serve with bridge in background.
    server_proc = subprocess.Popen(
        [
            binary,
            "serve",
            "--profile", profile_path,
            "--key", keys_path,
            "--port", "1025",
            "--trust-plane",
            "--watchdog-timeout-ms", "0",
            "--bridge",
            "--bridge-socket", socket_path,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # Wait for the socket to appear (server startup).
    import shutil

    try:
        for _ in range(50):
            if os.path.exists(socket_path):
                break
            time.sleep(0.1)
        else:
            server_proc.kill()
            _, stderr = server_proc.communicate(timeout=5)
            pytest.fail(
                f"Bridge socket {socket_path} never appeared. "
                f"Server stderr: {stderr.decode()}"
            )

        yield {
            "socket_path": socket_path,
            "process": server_proc,
            "tmpdir": tmpdir,
        }
    finally:
        # Cleanup: always terminate the server and remove temp files.
        server_proc.send_signal(signal.SIGTERM)
        try:
            server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_proc.kill()
            server_proc.wait(timeout=5)

        shutil.rmtree(tmpdir, ignore_errors=True)


def _make_valid_command() -> dict:
    """Build a minimal valid command for the ur10e_cnc_tending profile."""
    from datetime import datetime, timezone

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "e2e_test",
        "sequence": 1,
        "joint_states": [
            {"name": "shoulder_pan_joint", "position": 0.0, "velocity": 0.0, "effort": 0.0},
            {"name": "shoulder_lift_joint", "position": -1.571, "velocity": 0.0, "effort": 0.0},
            {"name": "elbow_joint", "position": 1.571, "velocity": 0.0, "effort": 0.0},
            {"name": "wrist_1_joint", "position": -1.571, "velocity": 0.0, "effort": 0.0},
            {"name": "wrist_2_joint", "position": 0.0, "velocity": 0.0, "effort": 0.0},
            {"name": "wrist_3_joint", "position": 0.0, "velocity": 0.0, "effort": 0.0},
        ],
        "delta_time": 0.004,
        "end_effector_positions": [
            {"name": "end_effector", "position": [0.3, 0.0, 0.9]},
            {"name": "base_link", "position": [0.2, 0.0, 0.1]},
            {"name": "shoulder_link", "position": [0.2, 0.0, 0.3]},
            {"name": "forearm_link", "position": [0.3, 0.0, 0.6]},
            {"name": "wrist_3_link", "position": [0.3, 0.0, 0.9]},
        ],
        "authority": {
            "pca_chain": "",
            "required_ops": ["actuate:*"],
        },
    }


def _make_invalid_command() -> dict:
    """Build a command with joint positions way out of range."""
    cmd = _make_valid_command()
    cmd["sequence"] = 2
    cmd["joint_states"][0]["position"] = 999.0  # Way out of [-6.28, 6.28]
    return cmd


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestBridgeEndToEnd:
    """End-to-end tests that talk to a real Invariant bridge server.

    Note: The bridge does not apply trust-plane auto-authority (that's
    HTTP-only), so commands sent without a valid PCA chain will fail the
    authority check. The validator still runs ALL checks (authority +
    sensor + physics) and populates the full verdict — only ``approved``
    is false. Tests validate protocol correctness, physics check
    behavior, and verdict structure rather than full approval.
    """

    def test_command_returns_verdict(self, bridge_server):
        """A command should return a verdict response (not an error)."""
        bridge = InvariantBridge(bridge_server["socket_path"])
        try:
            cmd = _make_valid_command()
            result = bridge.validate(cmd)
            assert result["type"] == "verdict", f"Expected verdict, got: {result}"
            assert "signed_verdict" in result
            assert "approved" in result
        finally:
            bridge.close()

    def test_physics_checks_pass_for_valid_joints(self, bridge_server):
        """Valid joint positions should pass all physics checks even without authority."""
        bridge = InvariantBridge(bridge_server["socket_path"])
        try:
            cmd = _make_valid_command()
            result = bridge.validate(cmd)
            assert result["type"] == "verdict"
            verdict = result["signed_verdict"]
            # All physics checks should pass (authority fails due to empty chain).
            physics_checks = [
                c for c in verdict["checks"] if c["category"] == "physics"
            ]
            for check in physics_checks:
                assert check["passed"] is True, (
                    f"Physics check '{check['name']}' failed: {check['details']}"
                )
        finally:
            bridge.close()

    def test_invalid_joints_fail_physics(self, bridge_server):
        """A command with joints at 999.0 should fail the joint_limits check."""
        bridge = InvariantBridge(bridge_server["socket_path"])
        try:
            cmd = _make_invalid_command()
            result = bridge.validate(cmd)
            assert result["type"] == "verdict"
            assert result["approved"] is False
            verdict = result["signed_verdict"]
            joint_check = next(
                c for c in verdict["checks"] if c["name"] == "joint_limits"
            )
            assert joint_check["passed"] is False
        finally:
            bridge.close()

    def test_heartbeat_acknowledged(self, bridge_server):
        """A heartbeat message should get a heartbeat_ack response."""
        bridge = InvariantBridge(bridge_server["socket_path"])
        try:
            result = bridge.heartbeat()
            assert result["type"] == "heartbeat_ack"
        finally:
            bridge.close()

    def test_invalid_json_returns_error(self, bridge_server):
        """Malformed JSON should return an error response, not crash."""
        import socket as sock

        s = sock.socket(sock.AF_UNIX, sock.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect(bridge_server["socket_path"])
        try:
            s.sendall(b"this is not valid json\n")
            # Buffer reads until we get a full newline-delimited response.
            buf = b""
            while b"\n" not in buf:
                chunk = s.recv(65536)
                assert chunk, "server closed connection unexpectedly"
                buf += chunk
            line = buf.split(b"\n", 1)[0]
            response = json.loads(line)
            assert response["type"] == "error"
            assert "JSON parse error" in response.get("error", "")
        finally:
            s.close()

    def test_multiple_commands_on_one_connection(self, bridge_server):
        """Multiple commands on the same connection should all get verdict responses."""
        bridge = InvariantBridge(bridge_server["socket_path"])
        try:
            for i in range(5):
                cmd = _make_valid_command()
                cmd["sequence"] = i + 10
                result = bridge.validate(cmd)
                assert result["type"] == "verdict", (
                    f"Command {i} should get verdict, got: {result['type']}"
                )
        finally:
            bridge.close()

    def test_verdict_contains_all_check_categories(self, bridge_server):
        """The signed verdict should contain authority, sensor, and physics checks."""
        bridge = InvariantBridge(bridge_server["socket_path"])
        try:
            cmd = _make_valid_command()
            cmd["sequence"] = 200
            result = bridge.validate(cmd)
            assert result["type"] == "verdict"
            verdict = result["signed_verdict"]
            assert "checks" in verdict
            assert len(verdict["checks"]) > 0
            check_names = [c["name"] for c in verdict["checks"]]
            assert "authority" in check_names
            assert "joint_limits" in check_names
            assert "sensor_integrity" in check_names
            assert "workspace_bounds" in check_names
            # Profile info should be present.
            assert verdict["profile_name"] == "ur10e_cnc_tending"
        finally:
            bridge.close()
