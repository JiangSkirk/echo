from __future__ import annotations

import importlib.util
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "echo_live_acceptance.py"


def _harness_module() -> ModuleType:
    spec = importlib.util.spec_from_file_location("echo_live_acceptance_for_test", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_live_acceptance_short_mode_runs_real_local_processes(tmp_path: Path) -> None:
    """The regression harness stays short while exercising the real HTTP/WS boundary."""
    output = tmp_path / "live-acceptance.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--duration-seconds",
            "1",
            "--concurrency",
            "1",
            "--output",
            str(output),
        ],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=90,
        check=False,
    )

    assert proc.returncode == 0, proc.stdout + proc.stderr
    report = json.loads(output.read_text(encoding="utf-8"))

    assert report["ok"] is True
    assert report["duration_seconds"] == 1
    assert report["concurrency"] == 1
    assert report["network"] == "local-only"
    assert isinstance(report.get("acceptance_pid"), int)
    assert not isinstance(report["acceptance_pid"], bool)
    assert report["acceptance_pid"] > 0
    assert report["source_integrity"]["ok"] is True
    assert report["source_integrity"]["drifted"] is False
    assert report["source_integrity"]["check_count"] > 0
    assert report["resources"]["ok"] is True
    assert report["storage_stability"]["ok"] is True
    assert report["cleanup"]["all_processes_stopped"] is True
    assert report["cleanup"]["graceful"] is True
    assert all(child["forced_kill"] is False for child in report["cleanup"]["children"].values())
    assert report["soak"]["success"] >= 2
    assert report["soak"]["http_5xx"] == 0
    assert report["soak"]["terminal"]["done"] >= 2
    assert report["soak"]["samples"]

    assert report["max_state_bytes"] == 512 * 1024 * 1024
    for product in ("js_agent", "js_work"):
        storage = report["storage"][product]
        assert 0 < storage["total_bytes"] <= report["max_state_bytes"]
        assert storage["file_count"] > 0
        assert storage["largest_files"]
        assert storage["max_active_session_partitions_per_owner"] <= 64
        assert storage["retention_checkpoint_errors"] == []
        assert storage["incomplete_retirements"] == []
        assert report["products"][product]["storage_within_limit"] is True
        assert report["products"][product]["session_partitions_bounded"] is True

    for product in ("js_agent", "js_work"):
        checks = report["products"][product]
        assert checks["status_primary_healthy"] is True
        assert checks["chat"] is True
        assert checks["stream"] is True
        assert checks["tool_continue"] is True
        assert checks["attachment"] is True
        assert checks["cross_owner_rejected"] is True
        assert checks["secret_rejected"] is True
        assert checks["cancel"] is True
        assert checks["provider_error_single_terminal"] is True


@pytest.mark.parametrize(
    "fault",
    [
        {"terminal_frames": ["done", "done"]},
        {"http_identity": "js_work:wrong-request"},
        {"terminal_frames": ["error"], "ws_errors": 1},
    ],
)
def test_faulty_soak_evidence_cannot_make_report_ok(fault: dict[str, object]) -> None:
    harness = _harness_module()
    identity = "js_agent:request-1"
    sample: dict[str, object] = {
        "product": "js_agent",
        "request_id": "request-1",
        "expected_identity": identity,
        "http_status": 200,
        "http_identity": identity,
        "ws_identity": identity,
        "terminal_frames": ["done"],
        "ws_errors": 0,
        "provider_identity_calls": 2,
    }
    sample.update(fault)

    soak = harness._summarize_soak([sample])
    assert soak["failures"] == 1
    assert (
        harness._overall_ok(
            {"js_agent": {"chat": True}, "js_work": {"chat": True}},
            soak,
            cleanup_ok=True,
        )
        is False
    )


def test_soak_summary_retains_late_failures_and_uses_all_latency_samples() -> None:
    harness = _harness_module()
    samples: list[dict[str, object]] = []
    for index in range(60):
        identity = f"js_agent:request-{index}"
        sample: dict[str, object] = {
            "product": "js_agent",
            "request_id": f"request-{index}",
            "expected_identity": identity,
            "http_status": 200,
            "http_identity": identity,
            "ws_identity": identity,
            "terminal_frames": ["done"],
            "ws_errors": 0,
            "provider_identity_calls": 2,
            "http_ms": float(index + 1),
            "ws_ms": float((index + 1) * 10),
        }
        samples.append(sample)
    samples[55]["exception"] = "TimeoutError: late failure"

    soak = harness._summarize_soak(samples)

    assert soak["sample_count"] == 60
    assert soak["failures"] == 1
    assert soak["failure_reasons"] == {"exception": 1}
    assert [sample["request_id"] for sample in soak["failure_samples"]] == ["request-55"]
    assert soak["latency_ms"]["http"]["count"] == 60
    assert soak["latency_ms"]["http"]["max"] == 60.0
    assert soak["latency_ms"]["ws"]["p95"] == 570.0
    assert len(soak["samples"]) <= 40


def test_terminal_error_without_identity_is_failure_not_crosstalk() -> None:
    harness = _harness_module()
    identity = "js_agent:soak:1:" + ("a" * 32)
    soak = harness._summarize_soak(
        [
            {
                "product": "js_agent",
                "request_id": "soak:1:" + ("a" * 32),
                "expected_identity": identity,
                "http_status": 200,
                "http_identity": identity,
                "ws_identity": None,
                "terminal_frames": ["error"],
                "ws_errors": 1,
                "provider_identity_calls": 1,
            }
        ]
    )

    assert soak["failures"] == 1
    assert soak["crosstalk"] == 0


def test_identity_parser_and_summary_detect_actual_crosstalk() -> None:
    harness = _harness_module()
    expected = "js_agent:soak:1:" + ("a" * 32)
    wrong = "js_work:soak:2:" + ("b" * 32)

    observed = harness._identity_in_text(f"local acceptance complete {wrong}", expected)
    soak = harness._summarize_soak(
        [
            {
                "product": "js_agent",
                "request_id": "soak:1:" + ("a" * 32),
                "expected_identity": expected,
                "http_status": 200,
                "http_identity": expected,
                "ws_identity": observed,
                "terminal_frames": ["done"],
                "ws_errors": 0,
                "provider_identity_calls": 2,
            }
        ]
    )

    assert observed == wrong
    assert soak["failures"] == 1
    assert soak["crosstalk"] == 1


def test_soak_failure_message_is_bounded_and_contains_reason_counts() -> None:
    harness = _harness_module()
    soak = {
        "failures": 17,
        "crosstalk": 0,
        "http_5xx": 0,
        "failure_reasons": {"exception": 12, "terminal_frames": 5},
        "failure_samples": [{"exception": "x" * 50_000}],
    }

    message = harness._soak_failure_message(soak)

    assert len(message) < 500
    assert "failures=17" in message
    assert "exception" in message


def test_stream_evidence_retains_bounded_error_diagnostics() -> None:
    harness = _harness_module()
    frames = [
        {"type": "status", "content": "streaming..."},
        {
            "type": "error",
            "content": "ledger temporarily unavailable " + ("x" * 2_000),
            "session_id": "private-session-id",
            "turns": 1,
        },
    ]

    evidence = harness._stream_evidence(frames, "js_agent:request-1")

    assert evidence["terminal_frames"] == ["error"]
    assert evidence["ws_errors"] == 1
    assert evidence["ws_error_frames"] == [
        {
            "type": "error",
            "content": "ledger temporarily unavailable " + ("x" * 469),
            "turns": 1,
        }
    ]
    assert "session_id" not in evidence["ws_error_frames"][0]


def test_soak_summary_bounds_failure_evidence_without_losing_counts() -> None:
    harness = _harness_module()
    samples: list[dict[str, object]] = []
    for index in range(100):
        identity = f"js_agent:request-{index}"
        samples.append(
            {
                "product": "js_agent",
                "request_id": f"request-{index}",
                "expected_identity": identity,
                "http_status": 503,
                "http_identity": identity,
                "ws_identity": identity,
                "terminal_frames": ["done"],
                "ws_errors": 0,
                "provider_identity_calls": 2,
            }
        )

    soak = harness._summarize_soak(samples)

    assert soak["sample_count"] == 100
    assert soak["failures"] == 100
    assert soak["failure_reasons"] == {"http_status": 100}
    assert len(soak["failure_samples"]) <= 40


def test_soak_reads_provider_stats_once_after_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _harness_module()
    products = [object(), object()]
    calls = 0

    def fake_soak_one(product: object, index: int, provider_port: int) -> dict[str, object]:
        del product, provider_port
        identity = f"product:request-{index}"
        return {
            "product": "product",
            "request_id": f"request-{index}",
            "expected_identity": identity,
            "http_status": 200,
            "http_identity": identity,
            "ws_identity": identity,
            "terminal_frames": ["done"],
            "ws_errors": 0,
        }

    def fake_provider_stats(provider_port: int) -> dict[str, object]:
        nonlocal calls
        assert provider_port == 1234
        calls += 1
        return {
            "chat_calls": 10,
            "interactive_calls": 8,
            "background_calls": 2,
            "identities": {
                "product:request-0": 4,
                "product:request-1": 4,
            },
            "primary_identities": {
                "product:request-0": 2,
                "product:request-1": 2,
            },
        }

    monkeypatch.setattr(harness, "_soak_one", fake_soak_one)
    monkeypatch.setattr(harness, "_provider_stats", fake_provider_stats)

    soak = harness._run_soak(
        products,
        provider_port=1234,
        duration_seconds=0,
        concurrency=1,
    )

    assert calls == 1
    assert soak["failures"] == 0
    assert soak["provider_snapshot"] == {
        "background_model_calls": 2,
        "chat_calls": 10,
        "classification_complete": True,
        "background_identity_calls": 4,
        "identity_call_distribution": {"4": 2},
        "identity_count": 2,
        "interactive_model_calls": 8,
        "primary_identity_call_distribution": {"2": 2},
        "primary_identity_count": 2,
        "scenarios": {},
    }


def test_fake_provider_identity_uses_latest_user_message_only() -> None:
    harness = _harness_module()
    messages = [
        {"role": "system", "content": "memory __live_id__=old-owner:request-1"},
        {"role": "user", "content": "current __live_id__=js_agent:request-2"},
        {"role": "assistant", "content": "working"},
        {"role": "tool", "content": "tool result"},
    ]

    assert harness._latest_user_text(messages) == ("current __live_id__=js_agent:request-2")


def test_primary_soak_classifier_excludes_background_prompts() -> None:
    harness = _harness_module()
    identity = "js_agent:soak:42:abcdef"

    def messages(user_text: str, *, system_text: str = "You are JS, a helpful assistant"):
        return [
            {"role": "system", "content": system_text},
            {"role": "user", "content": user_text},
        ]

    assert harness._is_primary_soak_call(messages(f"__live_soak__ __live_id__={identity}")) is True
    assert (
        harness._is_primary_soak_call(messages(f"__live_soak_stream__ __live_id__={identity}"))
        is True
    )
    assert (
        harness._is_primary_soak_call(
            messages(f"工作模式：普通执行。\n\n用户任务：__live_soak__ __live_id__={identity}")
        )
        is True
    )
    assert (
        harness._is_primary_soak_call(
            messages(
                f"__live_soak__ __live_id__={identity}",
                system_text="You are a memory analyst. Extract durable facts.",
            )
        )
        is False
    )
    assert (
        harness._is_interactive_acceptance_call(messages(f"__live_soak__ __live_id__={identity}"))
        is True
    )
    assert (
        harness._is_interactive_acceptance_call(
            messages(f"工作模式：普通执行。\n\n用户任务：__live_soak__ __live_id__={identity}")
        )
        is True
    )


def test_true_duplicate_primary_provider_calls_still_fail_soak() -> None:
    harness = _harness_module()
    identity = "js_agent:soak:42:abcdef"
    sample = {
        "product": "js_agent",
        "request_id": "soak:42:abcdef",
        "expected_identity": identity,
        "http_status": 200,
        "http_identity": identity,
        "ws_identity": identity,
        "terminal_frames": ["done"],
        "ws_errors": 0,
        "provider_identity_calls": 4,
    }

    soak = harness._summarize_soak([sample])

    assert soak["failures"] == 1
    assert soak["failure_reasons"] == {"provider_identity_calls": 1}
    assert (
        harness._is_interactive_acceptance_call(
            f"Extract durable facts. Conversation:\nUser: __live_soak__ __live_id__={identity}"
        )
        is False
    )


def test_resource_summary_rejects_sustained_rss_growth() -> None:
    harness = _harness_module()
    mib = 1024 * 1024
    samples = [
        {
            "elapsed_seconds": float(second),
            "rss_bytes": {"js_agent": 100 * mib + int(second / 60 * 4 * mib)},
        }
        for second in range(0, 601, 5)
    ]

    summary = harness._summarize_resource_samples(
        samples,
        duration_seconds=600,
        max_rss_bytes=512 * mib,
        max_growth_mib_per_minute=2.0,
    )

    assert summary["ok"] is False
    assert summary["stability_enforced"] is True
    assert summary["processes"]["js_agent"]["growth_mib_per_minute"] > 3.9


def test_storage_summary_rejects_sustained_partition_growth() -> None:
    harness = _harness_module()
    mib = 1024 * 1024
    samples = []
    for second in range(0, 601, 5):
        partition_bytes = 2 * mib + int(second / 60 * mib)
        samples.append(
            {
                "elapsed_seconds": float(second),
                "storage": {
                    "js_agent": {
                        "total_bytes": 100 * mib + partition_bytes,
                        "partition_storage_bytes": partition_bytes,
                        "max_active_session_partitions_per_owner": 64,
                        "retention_checkpoint_errors": [],
                        "incomplete_retirements": [],
                    }
                },
            }
        )

    summary = harness._summarize_storage_samples(
        samples,
        duration_seconds=600,
        max_state_bytes=512 * mib,
        required_products=("js_agent",),
    )

    assert summary["ok"] is False
    assert summary["stability_enforced"] is True
    assert (
        summary["products"]["js_agent"]["partition_growth_mib_per_minute"]
        > harness.DEFAULT_MAX_PARTITION_GROWTH_MIB_PER_MINUTE
    )


def test_storage_summary_accepts_bounded_partition_plateau() -> None:
    harness = _harness_module()
    mib = 1024 * 1024
    samples = []
    for second in range(0, 601, 5):
        warmup = min(second / 60, 2) * mib
        samples.append(
            {
                "elapsed_seconds": float(second),
                "storage": {
                    "js_agent": {
                        "total_bytes": 100 * mib + warmup,
                        "partition_storage_bytes": 2 * mib + warmup,
                        "max_active_session_partitions_per_owner": 64,
                        "retention_checkpoint_errors": [],
                        "incomplete_retirements": [],
                    }
                },
            }
        )

    summary = harness._summarize_storage_samples(
        samples,
        duration_seconds=600,
        max_state_bytes=512 * mib,
        required_products=("js_agent",),
    )

    assert summary["ok"] is True
    assert summary["products"]["js_agent"]["growth_within_limit"] is True


def test_storage_summary_allows_one_transient_retirement_observation() -> None:
    harness = _harness_module()
    mib = 1024 * 1024
    owner = "product_hash/owner_hash"
    samples = []
    for second in range(0, 601, 5):
        samples.append(
            {
                "elapsed_seconds": float(second),
                "storage": {
                    "js_agent": {
                        "total_bytes": 100 * mib,
                        "partition_storage_bytes": 2 * mib,
                        "max_active_session_partitions_per_owner": 64,
                        "retention_checkpoint_errors": [],
                        "incomplete_retirements": [owner] if second == 300 else [],
                    }
                },
            }
        )

    summary = harness._summarize_storage_samples(
        samples,
        duration_seconds=600,
        max_state_bytes=512 * mib,
        required_products=("js_agent",),
    )

    product = summary["products"]["js_agent"]
    assert summary["ok"] is True
    assert product["transient_retirement_observations"] == [owner]
    assert product["stale_incomplete_retirements"] == []


def test_storage_summary_distinguishes_separate_retirements_for_same_owner() -> None:
    harness = _harness_module()
    mib = 1024 * 1024
    owner = "product_hash/owner_hash"
    samples = []
    for second in range(0, 601, 5):
        incomplete = second in {300, 305}
        marker = f"{owner}|retirement-{second}"
        samples.append(
            {
                "elapsed_seconds": float(second),
                "storage": {
                    "js_agent": {
                        "total_bytes": 100 * mib,
                        "partition_storage_bytes": 2 * mib,
                        "max_active_session_partitions_per_owner": 64,
                        "retention_checkpoint_errors": [],
                        "incomplete_retirements": [owner] if incomplete else [],
                        "incomplete_retirement_markers": [marker] if incomplete else [],
                    }
                },
            }
        )

    summary = harness._summarize_storage_samples(
        samples,
        duration_seconds=600,
        max_state_bytes=512 * mib,
        required_products=("js_agent",),
    )

    product = summary["products"]["js_agent"]
    assert summary["ok"] is True
    assert product["transient_retirement_observations"] == [owner]
    assert product["stale_incomplete_retirements"] == []


@pytest.mark.parametrize("mode", ["consecutive", "final"])
def test_storage_summary_rejects_stale_incomplete_retirement(mode: str) -> None:
    harness = _harness_module()
    mib = 1024 * 1024
    owner = "product_hash/owner_hash"
    samples = []
    for second in range(0, 601, 5):
        incomplete = second in {300, 305} if mode == "consecutive" else second == 600
        samples.append(
            {
                "elapsed_seconds": float(second),
                "storage": {
                    "js_agent": {
                        "total_bytes": 100 * mib,
                        "partition_storage_bytes": 2 * mib,
                        "max_active_session_partitions_per_owner": 64,
                        "retention_checkpoint_errors": [],
                        "incomplete_retirements": [owner] if incomplete else [],
                    }
                },
            }
        )

    summary = harness._summarize_storage_samples(
        samples,
        duration_seconds=600,
        max_state_bytes=512 * mib,
        required_products=("js_agent",),
    )

    product = summary["products"]["js_agent"]
    assert summary["ok"] is False
    assert product["stale_incomplete_retirements"] == [owner]


def test_resource_sampler_counts_the_complete_process_tree(monkeypatch) -> None:
    harness = _harness_module()

    class FakeMemory:
        def __init__(self, rss: int) -> None:
            self.rss = rss

    class FakeChild:
        def memory_info(self) -> FakeMemory:
            return FakeMemory(50)

    class FakeRoot:
        def memory_info(self) -> FakeMemory:
            return FakeMemory(100)

        def children(self, *, recursive: bool) -> list[FakeChild]:
            assert recursive is True
            return [FakeChild()]

    class FakePopen:
        pid = 123

        @staticmethod
        def poll() -> None:
            return None

    monkeypatch.setattr(harness.psutil, "Process", lambda _pid: FakeRoot())

    sample = harness._sample_process_resources(
        {"js_agent": FakePopen()},
        elapsed_seconds=2.5,
    )

    assert sample["rss_bytes"] == {"js_agent": 150}
    assert sample["process_counts"] == {"js_agent": 2}


def test_resource_summary_accepts_a_bounded_plateau() -> None:
    harness = _harness_module()
    mib = 1024 * 1024
    samples = [
        {
            "elapsed_seconds": float(second),
            "rss_bytes": {
                "js_agent": (100 + min(second / 60, 5) * 8) * mib,
            },
        }
        for second in range(0, 601, 5)
    ]

    summary = harness._summarize_resource_samples(
        samples,
        duration_seconds=600,
        max_rss_bytes=512 * mib,
        max_growth_mib_per_minute=2.0,
    )

    assert summary["ok"] is True
    assert summary["processes"]["js_agent"]["peak_rss_mib"] == 140.0


def test_resource_summary_does_not_hide_window_growth_behind_a_flat_tail() -> None:
    """Tail diagnostics must not relax the full stability-window gate."""
    harness = _harness_module()
    mib = 1024 * 1024
    samples = [
        {
            "elapsed_seconds": float(second),
            "rss_bytes": {
                "js_agent": (100 * mib) + (int(3.75 * mib) if second >= 480 else 0),
            },
        }
        for second in range(0, 601, 5)
    ]

    summary = harness._summarize_resource_samples(
        samples,
        duration_seconds=600,
        max_rss_bytes=512 * mib,
        max_growth_mib_per_minute=0.5,
    )

    process = summary["processes"]["js_agent"]
    assert process["growth_mib_per_minute"] > 0.5
    assert process["tail_growth_mib_per_minute"] == 0.0
    assert summary["ok"] is False


def test_resource_summary_records_all_canonical_samples() -> None:
    harness = _harness_module()
    mib = 1024 * 1024
    sample_count = harness.MAX_RECORDED_SAMPLES + 7
    samples = [
        {
            "elapsed_seconds": float(index * 5),
            "rss_bytes": {"js_agent": 100 * mib},
        }
        for index in range(sample_count)
    ]

    summary = harness._summarize_resource_samples(
        samples,
        duration_seconds=float((sample_count - 1) * 5),
        max_rss_bytes=512 * mib,
        max_growth_mib_per_minute=0.5,
    )

    assert summary["samples_truncated"] is False
    assert summary["recorded_sample_count"] == sample_count
    assert summary["omitted_sample_count"] == 0
    assert len(summary["samples"]) == sample_count


def test_resource_summary_reports_complete_minute_medians_for_each_process() -> None:
    harness = _harness_module()
    mib = 1024 * 1024
    samples = []
    for second in range(0, 3600, 5):
        minute = second // 60
        samples.append(
            {
                "elapsed_seconds": float(second),
                "rss_bytes": {
                    "js_agent": (180 if minute == 30 else 100) * mib,
                    "js_work": 150 * mib,
                },
            }
        )

    summary = harness._summarize_resource_samples(
        samples,
        duration_seconds=3600,
        max_rss_bytes=512 * mib,
        max_growth_mib_per_minute=0.5,
        required_processes=("js_agent", "js_work"),
    )

    agent_medians = summary["processes"]["js_agent"]["minute_medians"]
    work_medians = summary["processes"]["js_work"]["minute_medians"]
    assert len(agent_medians) == 60
    assert agent_medians[0] == {"elapsed_seconds": 30.0, "rss_mib": 100.0}
    assert agent_medians[30] == {"elapsed_seconds": 1830.0, "rss_mib": 180.0}
    assert agent_medians[-1] == {"elapsed_seconds": 3570.0, "rss_mib": 100.0}
    assert len(work_medians) == 60
    assert work_medians[30] == {"elapsed_seconds": 1830.0, "rss_mib": 150.0}


@pytest.mark.parametrize(
    "samples",
    [
        [],
        [{"elapsed_seconds": 0.0, "rss_bytes": {"js_agent": 100 * 1024 * 1024}}],
    ],
)
def test_resource_summary_fails_closed_on_missing_samples(
    samples: list[dict[str, object]],
) -> None:
    harness = _harness_module()

    summary = harness._summarize_resource_samples(
        samples,
        duration_seconds=600,
        max_rss_bytes=512 * 1024 * 1024,
        max_growth_mib_per_minute=0.5,
        required_processes=("js_agent", "js_work"),
    )

    assert summary["ok"] is False
    assert set(summary["processes"]) == {"js_agent", "js_work"}
    assert all(process["sample_integrity_ok"] is False for process in summary["processes"].values())


def test_resource_summary_without_required_processes_or_samples_fails_closed() -> None:
    harness = _harness_module()

    summary = harness._summarize_resource_samples(
        [],
        duration_seconds=600,
        max_rss_bytes=512 * 1024 * 1024,
        max_growth_mib_per_minute=0.5,
    )

    assert summary["ok"] is False
    assert summary["processes"] == {}


def test_resource_summary_rejects_late_rss_step_even_when_regression_is_diluted() -> None:
    harness = _harness_module()
    mib = 1024 * 1024
    samples = []
    for second in range(0, 3601, 5):
        rss = 100 * mib
        if second >= 3540:
            rss += int((second - 3540) / 60 * 200 * mib)
        samples.append(
            {
                "elapsed_seconds": float(second),
                "rss_bytes": {"js_agent": rss},
            }
        )

    summary = harness._summarize_resource_samples(
        samples,
        duration_seconds=3600,
        max_rss_bytes=512 * mib,
        max_growth_mib_per_minute=0.5,
        required_processes=("js_agent",),
    )

    assert summary["ok"] is False
    assert summary["processes"]["js_agent"]["plateau_growth_mib"] > 16


@pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX-specific")
def test_sigterm_cleans_all_child_process_groups(tmp_path: Path) -> None:
    output = tmp_path / "signal-report.json"
    ready = tmp_path / "ready.json"
    proc = subprocess.Popen(
        [
            sys.executable,
            str(SCRIPT),
            "--duration-seconds",
            "60",
            "--concurrency",
            "1",
            "--ready-file",
            str(ready),
            "--output",
            str(output),
        ],
        cwd=REPO_ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 25
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.1)
    assert ready.exists(), proc.communicate(timeout=10)

    proc.send_signal(signal.SIGTERM)
    stdout, stderr = proc.communicate(timeout=35)
    assert proc.returncode != 0, stdout + stderr
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["ok"] is False
    assert report["cleanup"]["all_processes_stopped"] is True
    assert report["cleanup"]["graceful"] is True
    assert report["cleanup"]["signal"] == "SIGTERM"
    assert "identities" not in report["provider"]
    assert isinstance(report["provider"].get("identity_count"), int)
    for child in report["cleanup"]["children"].values():
        with pytest.raises(ProcessLookupError):
            os.killpg(child["process_group"], 0)
