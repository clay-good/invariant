# Signed validation verdict from Invariant.
# Published on /invariant/verdict after each command is validated.
# Matches invariant_core::models::verdict::SignedVerdict (Section 3.3).

bool approved
string command_hash
uint64 command_sequence
builtin_interfaces/Time timestamp
invariant_ros2/CheckResult[] checks
string profile_name
string profile_hash
invariant_ros2/AuthoritySummary authority_summary
string verdict_signature
string signer_kid
