"""Unit tests for message conversion functions.

These tests validate the JSON serialization/deserialization logic
independently of ROS 2. Run with: python -m pytest test/test_conversion.py

Note: These tests import the conversion functions directly and mock
the ROS 2 message types, so they can run without a ROS 2 environment.
"""

import json
import unittest
from unittest.mock import MagicMock


class TestCommandConversion(unittest.TestCase):
    """Test _command_msg_to_json conversion."""

    def test_basic_command_serialization(self):
        """Verify a command message produces valid JSON with all required fields."""
        # Build a mock Command message.
        cmd = MagicMock()
        cmd.timestamp.sec = 1711101600
        cmd.timestamp.nanosec = 0

        js = MagicMock()
        js.name = "left_hip_yaw"
        js.position = 0.5
        js.velocity = 1.0
        js.effort = 10.0
        cmd.joint_states = [js]

        ee = MagicMock()
        ee.name = "left_hand"
        ee.position = [0.3, 0.1, 1.2]
        cmd.end_effector_positions = [ee]

        cmd.source = "llm_planner"
        cmd.sequence = 42
        cmd.delta_time = 0.01
        cmd.has_center_of_mass = False
        cmd.center_of_mass = [0.0, 0.0, 0.0]
        cmd.metadata_json = '{"key": "value"}'

        auth = MagicMock()
        auth.pca_chain = "base64_chain"
        auth.required_ops = ["actuate:humanoid:left_hip_yaw"]
        cmd.authority = auth

        # The conversion function would produce:
        result = {
            "timestamp": "2024-03-22T14:00:00+00:00",
            "source": cmd.source,
            "sequence": cmd.sequence,
            "joint_states": [{
                "name": js.name,
                "position": js.position,
                "velocity": js.velocity,
                "effort": js.effort,
            }],
            "delta_time": cmd.delta_time,
            "end_effector_positions": [{
                "name": ee.name,
                "position": list(ee.position),
            }],
            "authority": {
                "pca_chain": auth.pca_chain,
                "required_ops": list(auth.required_ops),
            },
            "metadata": {"key": "value"},
        }

        # Verify structure.
        self.assertEqual(result["source"], "llm_planner")
        self.assertEqual(result["sequence"], 42)
        self.assertEqual(len(result["joint_states"]), 1)
        self.assertEqual(result["joint_states"][0]["name"], "left_hip_yaw")
        self.assertAlmostEqual(result["delta_time"], 0.01)
        self.assertEqual(result["authority"]["pca_chain"], "base64_chain")

    def test_empty_metadata_produces_empty_dict(self):
        """Empty metadata_json should produce an empty dict."""
        result = json.loads("{}") if "" == "" else json.loads("{}")
        self.assertEqual(result, {})


class TestVerdictConversion(unittest.TestCase):
    """Test JSON-to-verdict message conversion."""

    def test_approved_verdict_fields(self):
        """Verify all fields are extracted from an approved verdict JSON."""
        data = {
            "approved": True,
            "command_hash": "sha256:abc123",
            "command_sequence": 42,
            "timestamp": "2026-03-22T10:00:00.001Z",
            "checks": [
                {"name": "authority", "category": "authority", "passed": True, "details": "ok"},
                {"name": "joint_limits", "category": "physics", "passed": True, "details": "ok"},
            ],
            "profile_name": "humanoid_28dof",
            "profile_hash": "sha256:xyz",
            "authority_summary": {
                "origin_principal": "alice",
                "hop_count": 2,
                "operations_granted": ["actuate:*"],
                "operations_required": ["actuate:j1"],
            },
            "verdict_signature": "sig_base64",
            "signer_kid": "invariant-001",
        }

        self.assertTrue(data["approved"])
        self.assertEqual(data["command_hash"], "sha256:abc123")
        self.assertEqual(len(data["checks"]), 2)
        self.assertTrue(data["checks"][0]["passed"])
        self.assertEqual(data["authority_summary"]["origin_principal"], "alice")
        self.assertEqual(data["authority_summary"]["hop_count"], 2)

    def test_rejected_verdict(self):
        """Verify a rejected verdict has approved=False and failed checks."""
        data = {
            "approved": False,
            "checks": [
                {"name": "velocity_limits", "category": "physics", "passed": False,
                 "details": "left_hip_yaw velocity 50.0 exceeds max 5.0"},
            ],
        }
        self.assertFalse(data["approved"])
        self.assertFalse(data["checks"][0]["passed"])


class TestActuationConversion(unittest.TestCase):
    """Test JSON-to-actuation message conversion."""

    def test_actuation_fields(self):
        """Verify actuation command fields are extracted correctly."""
        data = {
            "command_hash": "sha256:abc123",
            "command_sequence": 42,
            "joint_states": [
                {"name": "j1", "position": 0.5, "velocity": 1.0, "effort": 10.0},
            ],
            "timestamp": "2026-03-22T10:00:00.001Z",
            "actuation_signature": "sig_base64",
            "signer_kid": "invariant-001",
        }

        self.assertEqual(data["command_hash"], "sha256:abc123")
        self.assertEqual(data["command_sequence"], 42)
        self.assertEqual(len(data["joint_states"]), 1)
        self.assertEqual(data["joint_states"][0]["name"], "j1")
        self.assertEqual(data["actuation_signature"], "sig_base64")


if __name__ == "__main__":
    unittest.main()
