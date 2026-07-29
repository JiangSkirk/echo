# Local Red-Team Simulation

Status: LOCAL_SIMULATION_COMPLETE

Date: 2026-06-28

## Scope

The local simulation is represented by executable tests for:

- obvious secret blocking before model execution
- WebSocket normal and streaming path coverage
- path traversal and symlink escape denial
- metadata/private/loopback network denial
- prompt text failing to grant scopes
- journal tamper and crash-tail detection
- memory quarantine and plugin bypass denial
- sandbox timeout and output truncation

## Boundary

This is not a real external red-team report. The real red-team sign-off remains pending in `docs/security/REDTEAM_REPORT.md`.
