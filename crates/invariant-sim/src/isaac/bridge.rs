// Isaac Lab Unix socket IPC bridge.
//
// Production implementation connects to Isaac Lab via /tmp/invariant.sock.
// Currently uses dry-run mode for campaign execution.
//
// Protocol sketch (future implementation):
//   1. Client (invariant-sim) listens on /tmp/invariant.sock.
//   2. Isaac Lab connects and sends newline-delimited JSON `Command` messages.
//   3. invariant-sim validates each command via `ValidatorConfig::validate` and
//      writes back a newline-delimited JSON `SignedVerdict`.
//   4. If approved, the corresponding `SignedActuationCommand` is forwarded to
//      the Isaac Lab actuator interface.
//
// For local development and CI, use `run_dry_campaign` from `dry_run` module.
