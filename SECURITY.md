# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.0.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in Invariant, please report it
responsibly:

1. **Do not** open a public GitHub issue.
2. Email **security@invariant.dev** with:
   - A description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Any suggested fix (optional)
3. You will receive an acknowledgement within **48 hours**.
4. We will work with you to understand and address the issue before any
   public disclosure.

## Scope

The following are in scope:

- Bypass of physics checks (P1-P25) that could allow an unsafe command
- Authority chain forgery or privilege escalation
- Audit log tampering or integrity bypass
- Watchdog evasion
- Cryptographic weaknesses in Ed25519 signing/verification
- Sensor attestation bypass
- Any input that causes undefined behavior (there should be none --
  `#![forbid(unsafe_code)]` is enforced)

## Out of Scope

- Denial of service via large inputs (we have size limits, but resource
  exhaustion on the host is the operator's responsibility)
- Issues in third-party dependencies (report upstream, but let us know)
- Social engineering

## Recognition

We gratefully acknowledge security researchers who report vulnerabilities
responsibly. With your permission, we will credit you in the release notes.
