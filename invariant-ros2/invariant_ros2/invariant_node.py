"""
Invariant ROS 2 bridge node (Step 56, Section 21.3).

Thin wrapper that subscribes to /invariant/command, forwards each command
to the Invariant Rust binary over a Unix domain socket, and publishes the
signed verdict on /invariant/verdict (and optional signed actuation on
/invariant/actuation).

All validation logic runs in the Rust binary. This node only handles
ROS 2 message conversion and transport. The trusted computing base is
the Rust binary — never this Python code.

Topics:
    /invariant/command    (sub)  Command from cognitive layer
    /invariant/verdict    (pub)  SignedVerdict after validation
    /invariant/actuation  (pub)  SignedActuation for motor controller (approved only)
    /invariant/heartbeat  (sub)  Watchdog heartbeat from cognitive layer
    /invariant/status     (pub)  Node health status
"""

import json
import socket
import threading
import time

import rclpy
from rclpy.node import Node
from std_msgs.msg import Empty, String

from invariant_ros2.msg import (
    AuthoritySummary,
    CheckResult,
    Command,
    CommandAuthority,
    EndEffectorPosition,
    JointState,
    SignedActuation,
    SignedVerdict,
)


def _command_msg_to_json(msg: Command) -> dict:
    """Convert a ROS 2 Command message to Invariant JSON format."""
    joint_states = []
    for js in msg.joint_states:
        joint_states.append({
            "name": js.name,
            "position": js.position,
            "velocity": js.velocity,
            "effort": js.effort,
        })

    ee_positions = []
    for ee in msg.end_effector_positions:
        ee_positions.append({
            "name": ee.name,
            "position": list(ee.position),
        })

    cmd = {
        "timestamp": _time_to_iso(msg.timestamp),
        "source": msg.source,
        "sequence": msg.sequence,
        "joint_states": joint_states,
        "delta_time": msg.delta_time,
        "end_effector_positions": ee_positions,
        "authority": {
            "pca_chain": msg.authority.pca_chain,
            "required_ops": list(msg.authority.required_ops),
        },
        "metadata": json.loads(msg.metadata_json) if msg.metadata_json else {},
    }

    if msg.has_center_of_mass:
        cmd["center_of_mass"] = list(msg.center_of_mass)

    return cmd


def _json_to_verdict_msg(data: dict) -> SignedVerdict:
    """Convert Invariant JSON verdict to a ROS 2 SignedVerdict message."""
    msg = SignedVerdict()
    msg.approved = data.get("approved", False)
    msg.command_hash = data.get("command_hash", "")
    msg.command_sequence = data.get("command_sequence", 0)
    msg.timestamp = _iso_to_time(data.get("timestamp", ""))
    msg.profile_name = data.get("profile_name", "")
    msg.profile_hash = data.get("profile_hash", "")
    msg.verdict_signature = data.get("verdict_signature", "")
    msg.signer_kid = data.get("signer_kid", "")

    for check in data.get("checks", []):
        cr = CheckResult()
        cr.name = check.get("name", "")
        cr.category = check.get("category", "")
        cr.passed = check.get("passed", False)
        cr.details = check.get("details", "")
        msg.checks.append(cr)

    auth = data.get("authority_summary", {})
    msg.authority_summary.origin_principal = auth.get("origin_principal", "")
    msg.authority_summary.hop_count = auth.get("hop_count", 0)
    msg.authority_summary.operations_granted = auth.get("operations_granted", [])
    msg.authority_summary.operations_required = auth.get("operations_required", [])

    return msg


def _json_to_actuation_msg(data: dict) -> SignedActuation:
    """Convert Invariant JSON actuation command to a ROS 2 SignedActuation message."""
    msg = SignedActuation()
    msg.command_hash = data.get("command_hash", "")
    msg.command_sequence = data.get("command_sequence", 0)
    msg.timestamp = _iso_to_time(data.get("timestamp", ""))
    msg.actuation_signature = data.get("actuation_signature", "")
    msg.signer_kid = data.get("signer_kid", "")

    for js_data in data.get("joint_states", []):
        js = JointState()
        js.name = js_data.get("name", "")
        js.position = js_data.get("position", 0.0)
        js.velocity = js_data.get("velocity", 0.0)
        js.effort = js_data.get("effort", 0.0)
        msg.joint_states.append(js)

    return msg


def _time_to_iso(stamp) -> str:
    """Convert a ROS 2 builtin_interfaces/Time to ISO 8601 string."""
    from datetime import datetime, timezone
    secs = stamp.sec
    nsecs = stamp.nanosec
    dt = datetime.fromtimestamp(secs + nsecs / 1e9, tz=timezone.utc)
    return dt.isoformat()


def _iso_to_time(iso_str: str):
    """Convert an ISO 8601 string to a ROS 2 builtin_interfaces/Time."""
    from builtin_interfaces.msg import Time
    from datetime import datetime, timezone

    msg = Time()
    if not iso_str:
        return msg
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        epoch = dt.timestamp()
        msg.sec = int(epoch)
        msg.nanosec = int((epoch - int(epoch)) * 1e9)
    except (ValueError, OSError):
        pass
    return msg


class InvariantNode(Node):
    """ROS 2 bridge node for the Invariant safety firewall."""

    def __init__(self):
        super().__init__("invariant_node")

        # Parameters.
        self.declare_parameter("socket_path", "/tmp/invariant.sock")
        self.declare_parameter("heartbeat_forward", True)

        self._socket_path = (
            self.get_parameter("socket_path").get_parameter_value().string_value
        )
        self._heartbeat_forward = (
            self.get_parameter("heartbeat_forward")
            .get_parameter_value()
            .bool_value
        )

        # Socket connection (lazy — connects on first command).
        self._sock = None
        self._sock_lock = threading.Lock()

        # Publishers.
        self._verdict_pub = self.create_publisher(
            SignedVerdict, "/invariant/verdict", 10
        )
        self._actuation_pub = self.create_publisher(
            SignedActuation, "/invariant/actuation", 10
        )
        self._status_pub = self.create_publisher(
            String, "/invariant/status", 10
        )

        # Subscribers.
        self._command_sub = self.create_subscription(
            Command, "/invariant/command", self._on_command, 10
        )
        self._heartbeat_sub = self.create_subscription(
            Empty, "/invariant/heartbeat", self._on_heartbeat, 10
        )

        # Status timer (1 Hz).
        self._status_timer = self.create_timer(1.0, self._publish_status)

        self._connected = False
        self._commands_processed = 0
        self._last_error = ""

        self.get_logger().info(
            f"Invariant ROS 2 node started (socket: {self._socket_path})"
        )

    def _ensure_connected(self) -> bool:
        """Establish socket connection if not already connected."""
        if self._sock is not None:
            return True
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            sock.connect(self._socket_path)
            self._sock = sock
            self._connected = True
            self.get_logger().info(f"Connected to Invariant at {self._socket_path}")
            return True
        except OSError as e:
            self._connected = False
            self._last_error = str(e)
            self.get_logger().error(
                f"Failed to connect to Invariant: {e}"
            )
            return False

    def _send_receive(self, payload: dict) -> dict | None:
        """Send JSON to Invariant and receive the response."""
        with self._sock_lock:
            if not self._ensure_connected():
                return None
            try:
                data = json.dumps(payload).encode() + b"\n"
                self._sock.sendall(data)
                # Read response (newline-delimited JSON).
                response = b""
                while True:
                    chunk = self._sock.recv(65536)
                    if not chunk:
                        raise ConnectionError("Socket closed by Invariant")
                    response += chunk
                    if b"\n" in response:
                        break
                return json.loads(response.decode().strip())
            except (OSError, json.JSONDecodeError, ConnectionError) as e:
                self._last_error = str(e)
                self.get_logger().error(f"Communication error: {e}")
                # Reset connection for next attempt.
                self._close_socket()
                return None

    def _close_socket(self):
        """Close and reset the socket connection."""
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            self._connected = False

    def _on_command(self, msg: Command):
        """Handle incoming command: forward to Invariant, publish result."""
        cmd_json = _command_msg_to_json(msg)
        response = self._send_receive(cmd_json)

        if response is None:
            self.get_logger().warn("No response from Invariant — command dropped")
            return

        self._commands_processed += 1

        # Extract verdict (may be nested under "verdict" key or flat).
        verdict_data = response.get("verdict", response)
        verdict_msg = _json_to_verdict_msg(verdict_data)
        self._verdict_pub.publish(verdict_msg)

        # Publish actuation command if approved.
        actuation_data = response.get("actuation_command")
        if actuation_data is not None:
            actuation_msg = _json_to_actuation_msg(actuation_data)
            self._actuation_pub.publish(actuation_msg)

    def _on_heartbeat(self, _msg: Empty):
        """Forward watchdog heartbeat to Invariant."""
        if not self._heartbeat_forward:
            return
        self._send_receive({"heartbeat": True})

    def _publish_status(self):
        """Publish node health status."""
        status = String()
        status.data = json.dumps({
            "connected": self._connected,
            "commands_processed": self._commands_processed,
            "socket_path": self._socket_path,
            "last_error": self._last_error,
        })
        self._status_pub.publish(status)

    def destroy_node(self):
        """Clean up socket on shutdown."""
        self._close_socket()
        super().destroy_node()


def main(args=None):
    rclpy.init(args=args)
    node = InvariantNode()
    try:
        rclpy.spin(node)
    except KeyboardInterrupt:
        pass
    finally:
        node.destroy_node()
        rclpy.shutdown()


if __name__ == "__main__":
    main()
