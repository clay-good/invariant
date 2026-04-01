# Signed actuation command for the motor controller.
# Only published on /invariant/actuation when a command is APPROVED.
# The motor controller verifies actuation_signature before executing.
# Matches invariant_core::models::actuation::SignedActuationCommand (Section 3.4).

string command_hash
uint64 command_sequence
invariant_ros2/JointState[] joint_states
builtin_interfaces/Time timestamp
string actuation_signature
string signer_kid
