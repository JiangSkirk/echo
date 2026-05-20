"""Tests for ParallelToolExecutor grouping and safety logic."""

from __future__ import annotations

from js.tools.registry import ParallelToolExecutor


class TestParallelToolExecutor:
    def test_empty_calls(self):
        ex = ParallelToolExecutor()
        assert ex.group([]) == []

    def test_single_call(self):
        ex = ParallelToolExecutor()
        calls = [{"function": {"name": "file_read", "arguments": "{}"}, "id": "1"}]
        batches = ex.group(calls)
        assert len(batches) == 1
        assert len(batches[0]) == 1

    def test_read_only_tools_parallel(self):
        ex = ParallelToolExecutor()
        calls = [
            {"function": {"name": "file_read", "arguments": '{"path": "/tmp/a"}'}, "id": "1"},
            {"function": {"name": "file_read", "arguments": '{"path": "/tmp/b"}'}, "id": "2"},
        ]
        batches = ex.group(calls)
        assert len(batches) == 1
        assert len(batches[0]) == 2

    def test_same_path_sequential(self):
        ex = ParallelToolExecutor()
        calls = [
            {"function": {"name": "file_read", "arguments": '{"path": "/tmp/same"}'}, "id": "1"},
            {"function": {"name": "file_read", "arguments": '{"path": "/tmp/same"}'}, "id": "2"},
        ]
        batches = ex.group(calls)
        assert len(batches) == 2
        assert len(batches[0]) == 1
        assert len(batches[1]) == 1

    def test_never_parallel_tools_sequential(self):
        ex = ParallelToolExecutor()
        calls = [
            {"function": {"name": "shell", "arguments": '{"command": "ls"}'}, "id": "1"},
            {"function": {"name": "file_read", "arguments": '{"path": "/tmp/a"}'}, "id": "2"},
        ]
        batches = ex.group(calls)
        assert len(batches) == 2
        for batch in batches:
            assert len(batch) == 1

    def test_max_parallel_respected(self):
        ex = ParallelToolExecutor(max_parallel=2)
        calls = [
            {"function": {"name": "file_read", "arguments": '{"path": "/tmp/1"}'}, "id": "1"},
            {"function": {"name": "file_read", "arguments": '{"path": "/tmp/2"}'}, "id": "2"},
            {"function": {"name": "file_read", "arguments": '{"path": "/tmp/3"}'}, "id": "3"},
            {"function": {"name": "file_read", "arguments": '{"path": "/tmp/4"}'}, "id": "4"},
        ]
        batches = ex.group(calls)
        # First batch should have 2 (max_parallel), second batch the rest
        assert len(batches[0]) == 2
        assert len(batches[1]) == 2

    def test_mixed_read_and_write_sequential(self):
        ex = ParallelToolExecutor()
        calls = [
            {"function": {"name": "file_read", "arguments": '{"path": "/tmp/x"}'}, "id": "1"},
            {"function": {"name": "file_write", "arguments": '{"path": "/tmp/x"}'}, "id": "2"},
        ]
        batches = ex.group(calls)
        # file_write is in NEVER_PARALLEL_TOOLS, so everything sequential
        assert len(batches) == 2
