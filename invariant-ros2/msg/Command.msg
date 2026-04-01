# Robot command for Invariant validation.
# Matches invariant_core::models::command::Command (Section 3.2).
#
# Publish to /invariant/command for validation.
# The Invariant node will validate and respond on /invariant/verdict.

builtin_interfaces/Time timestamp
string source
uint64 sequence
invariant_ros2/JointState[] joint_states
float64 delta_time
invariant_ros2/EndEffectorPosition[] end_effector_positions
# Center of mass [x, y, z] for stability check (P9). Empty = skip.
float64[3] center_of_mass
bool has_center_of_mass
invariant_ros2/CommandAuthority authority
# Flat key-value metadata (serialized as JSON string for ROS compatibility).
string metadata_json
