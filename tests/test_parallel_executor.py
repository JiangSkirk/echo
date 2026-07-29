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

    def test_unknown_tools_are_serial_by_default(self):
        ex = ParallelToolExecutor()
        calls = [
            {"function": {"name": "custom_side_effect", "arguments": "{}"}, "id": "1"},
            {"function": {"name": "custom_side_effect", "arguments": "{}"}, "id": "2"},
        ]

        assert ex.group(calls) == [[calls[0]], [calls[1]]]

    def test_registry_read_only_metadata_is_required_for_custom_parallel_tools(self):
        class _Spec:
            def __init__(self, read_only: bool) -> None:
                self.read_only = read_only

        class _Registry:
            def get(self, name: str):
                return _Spec(read_only=name == "custom_read")

        ex = ParallelToolExecutor(registry=_Registry())
        reads = [
            {"function": {"name": "custom_read", "arguments": "{}"}, "id": "1"},
            {"function": {"name": "custom_read", "arguments": "{}"}, "id": "2"},
        ]
        writes = [
            {"function": {"name": "custom_write", "arguments": "{}"}, "id": "3"},
            {"function": {"name": "custom_read", "arguments": "{}"}, "id": "4"},
        ]

        assert ex.group(reads) == [reads]
        assert ex.group(writes) == [[writes[0]], [writes[1]]]

    def test_canonical_equivalent_paths_are_not_grouped_together(self, tmp_path):
        ex = ParallelToolExecutor(workspace=tmp_path)
        calls = [
            {
                "function": {
                    "name": "file_read",
                    "arguments": '{"path":"folder/../same.txt"}',
                },
                "id": "1",
            },
            {
                "function": {
                    "name": "file_read",
                    "arguments": '{"source":"same.txt"}',
                },
                "id": "2",
            },
        ]

        assert ex.group(calls) == [[calls[0]], [calls[1]]]
