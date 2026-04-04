"""
Invariant Isaac Lab bridge client (Section 21.1).

Thin Python wrapper that connects an Isaac Lab environment to the Invariant
safety firewall over a Unix domain socket. The Invariant server must be
running with --bridge enabled:

    invariant serve --profile profile.json --key keys.json --bridge

Usage in Isaac Lab:

    from invariant_isaac_bridge import InvariantBridge

    bridge = InvariantBridge()

    # Each step:
    verdict = bridge.validate(command_dict)
    if verdict["approved"]:
        env.apply_action(verdict["signed_actuation_command"])
    else:
        env.apply_zero_torque()

    # Periodically:
    bridge.heartbeat()

Protocol: newline-delimited JSON over Unix socket. Each message is a JSON
object followed by '\\n'. The server responds with a JSON object followed by
'\\n'. See crates/invariant-sim/src/isaac/bridge.rs for the Rust server.
"""

import json
import socket
from typing import Any, Dict, Optional


class InvariantBridge:
    """Connects an Isaac Lab environment to Invariant over Unix socket."""

    def __init__(
        self,
        socket_path: str = "/tmp/invariant.sock",
        timeout_s: float = 2.0,
    ):
        """Connect to the Invariant bridge server.

        Args:
            socket_path: Path to the Unix domain socket. Must match the
                --bridge-socket flag passed to `invariant serve`.
            timeout_s: Socket timeout in seconds. If the server does not
                respond within this window, a ``TimeoutError`` is raised
                so the caller can apply a hold-position policy instead of
                hanging. Set to ``None`` to disable (not recommended).

        Raises:
            ConnectionRefusedError: If the Invariant server is not running.
            FileNotFoundError: If the socket file does not exist.
        """
        self.socket_path = socket_path
        self.timeout_s = timeout_s
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout_s)
        self.sock.connect(socket_path)
        self._buf = b""

    def validate(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Send a command for validation and receive a signed verdict.

        Args:
            command: A dict matching Invariant's Command JSON schema. Must
                include at minimum: timestamp, source, sequence, joint_states,
                delta_time, authority (pca_chain + required_ops).

        Returns:
            A dict with:
                type: "verdict" | "error"
                approved: bool (when type == "verdict")
                signed_verdict: dict (when type == "verdict")
                error: str (when type == "error")

        Raises:
            TimeoutError: If the server does not respond within ``timeout_s``.
            ConnectionError: If the connection is lost and reconnect fails.
        """
        try:
            self._send(command)
            return self._recv()
        except (ConnectionError, BrokenPipeError):
            self._reconnect()
            self._send(command)
            return self._recv()

    def heartbeat(self) -> Dict[str, Any]:
        """Send a watchdog heartbeat.

        Returns:
            A dict with type: "heartbeat_ack".

        Raises:
            TimeoutError: If the server does not respond within ``timeout_s``.
            ConnectionError: If the connection is lost and reconnect fails.
        """
        try:
            self._send({"heartbeat": True})
            return self._recv()
        except (ConnectionError, BrokenPipeError):
            self._reconnect()
            self._send({"heartbeat": True})
            return self._recv()

    def close(self) -> None:
        """Close the connection."""
        try:
            self.sock.close()
        except OSError:
            pass

    def _reconnect(self) -> None:
        """Attempt to reconnect to the bridge server once."""
        try:
            self.sock.close()
        except OSError:
            pass
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout_s)
        self.sock.connect(self.socket_path)
        self._buf = b""

    def _send(self, msg: Any) -> None:
        """Send a newline-delimited JSON message."""
        data = json.dumps(msg, separators=(",", ":")).encode("utf-8") + b"\n"
        self.sock.sendall(data)

    def _recv(self) -> Dict[str, Any]:
        """Receive a newline-delimited JSON response.

        Uses an internal buffer to handle partial reads and messages
        that span multiple recv() calls.

        Raises:
            TimeoutError: If no complete response arrives within ``timeout_s``.
            ConnectionError: If the server closes the connection.
        """
        while b"\n" not in self._buf:
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout as exc:
                raise TimeoutError(
                    f"Invariant bridge did not respond within {self.timeout_s}s"
                ) from exc
            if not chunk:
                raise ConnectionError("Invariant bridge connection closed")
            self._buf += chunk

        line, self._buf = self._buf.split(b"\n", 1)
        return json.loads(line)

    def __enter__(self) -> "InvariantBridge":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"InvariantBridge(socket_path={self.socket_path!r})"
