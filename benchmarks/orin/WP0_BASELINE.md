# Orin Stage A WP0 baseline

- generated_at: `2026-08-22T16:44:50.517324+00:00`
- git: `feature/orin-stage-a` @ `e308fea185b81963bc16ba86b2361d388866fc2d`
- dirty: `True`

These are measured numbers, not targets. Do not treat them as acceptance.

## Mock task wall time (11 YAML tasks × 3 repeats)

- n = 33
- p50 = **94.021 ms**
- p99 = **215.412 ms**
- mean = 100.464 ms
- failures = 0

## LeaseAuthority issue/consume (in-memory, primary)

- issue n=10000: p50 **13.667 µs**, p99 32.335 µs, 65509.4 ops/s
- consume n=10000: p50 **12.625 µs**, p99 21.084 µs, 76667.0 ops/s

## LeaseAuthority JSONL path (separate, not the primary number)

- issue n=1000: p50 6645.771 µs, p99 13343.592 µs, 147.9 ops/s
- consume n=1000: p50 16372.958 µs, p99 26395.826 µs, 60.1 ops/s

## Cold start ×10 (new process, JSAgent construct)

- elapsed p50 **102.95 ms**, p99 109.104 ms
- RSS p50 **119.945 MiB**, p99 120.073 MiB

## pytest tests/ wall time

- elapsed **483.979 s**, returncode 1

```
tests/test_work_cli_surface.py:118: FutureWarning: js-work is a compatibility shim; use `js work`.
    work_cli.compat_main()

tests/test_work_cli_surface.py::test_compat_and_module_dispatch_through_same_canonical_hook
js_work/__main__.py:8: FutureWarning: js-work is a compatibility shim; use `js work`.
    compat_main()

tests/test_work_cli_surface.py::test_compat_web_inherits_canonical_overlap_gate
tests/test_work_cli_surface.py:148: FutureWarning: js-work is a compatibility shim; use `js work`.
    work_cli.compat_main()

tests/test_work_cli_surface.py::test_compat_web_serves_parent_appshell_instead_of_work_only_host
tests/test_work_cli_surface.py:208: FutureWarning: js-work is a compatibility shim; use `js work`.
    work_cli.compat_main()

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
=========================== short test summary info ============================
FAILED tests/test_net_guard.py::TestOriginCheck::test_no_origin_requires_api_key
FAILED tests/web/test_auth_security.py::TestSessionCookieLogin::test_login_rejects_invalid_key
2 failed, 6216 passed, 2 skipped, 113 deselected, 207 warnings in 482.49s (0:08:02)
```

## Notes

- `is_lease_authority_handle` was already on the tree; WP0 did not edit `_canonical_lease_payload` or issue/consume semantics.
- JSONL microbench is smaller (1k) and reported separately because the existing ledger replay cost is O(n²) TECH_DEBT.
