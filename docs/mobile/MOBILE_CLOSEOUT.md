# Mobile reserved-module closeout

This is the honest status of `js/mobile/`. It does **not** claim a
shipping mobile product, a paired iPhone, or a second runtime.

Machine-readable status: **`not_implemented`**.

## 1. Verdict

| Item | Conclusion |
|------|------------|
| Product status | **Reserved contract layer only** |
| Host cold start | Must not import `js.mobile` |
| `mobile_enabled` | Default `false` |
| Pairing / Bonjour / QR / push | **Not implemented** |
| Mobile ACP / editor protocol | **Out of scope** (parity plan §3 WP6 exclusion) |
| Real network daemon | **Not implemented** |

`js/mobile/` is 376 Python lines:

- `js/mobile/__init__.py` (27) — public names
- `js/mobile/protocol.py` (124) — DTO contracts and pairing-code helpers
- `js/mobile/gateway.py` (225) — in-memory pairing/session skeleton

The gateway docstring itself says: no real network, no Bonjour daemon,
no real iPhone. Treat that as the product claim.

## 2. What this layer is allowed to be

- In-process pairing-code format checks and fingerprint hashing
- In-memory session objects used only by `tests/test_r5_mobile.py`
- A place to hang a later design without inventing a second turn path

It is **not** a Host route, not a Gateway channel, and not an Echo
ingest surface. Enabling `mobile_enabled` only widens the isolation
posture warning (`js/security/posture.py`); it does not mount a
listener.

## 3. Explicitly not built (do not imply otherwise)

Do not write, ship, or document any of the following as present:

- Local-network pairing (Bonjour / QR / short-code over the wire)
- Push notifications or a mobile background daemon
- An iOS / Android node, canvas, or App Store build
- ACP / editor-protocol adapters for a phone
- Storage of Host API keys on a phone
- Phone-initiated shell, Python, Fleet, file, or network tools
- A FastAPI / AppShell mount of `MobileGateway`

A future implementation, if ever approved, must enter through
`run_echo_turn` with taint and a single-use lease. It must not become
a second agent runtime.

## 4. Tests that pin this closeout

- `tests/test_reserved_runtime_isolation.py` — Host / AppShell startup
  sources do not import `js.mobile`
- `tests/test_r5_mobile.py` — contract helpers stay in-memory
- `tests/test_security_policy_doc.py` — `mobile_enabled` default false
  is documented in `SECURITY.md` / `SECURITY_en.md`

## 5. Forbidden sentences

This closeout **must not** be quoted as:

- Mobile is implemented
- iPhone pairing is production-ready
- `mobile_enabled` mounts a product surface

## 6. Rollback

Keep `mobile_enabled=false`. Do not add `js.mobile` to Host cold start.
If a trial ever mounts a listener, the only exit is to unmount it and
return to this `not_implemented` declaration.
