"""F-10 regression tests: code.py sandbox escape families.

Each attack string is a CONFIRMED sandbox-bypass vector against
``CodeTool._scan_code``.  After the fix every one must be rejected by the
static scan before any interpreter is spawned (fail-closed).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from js.config import SecurityConfig, ToolLimits
from js.security.guard import BehaviorGuard
from js.tools.code import CodeTool


@pytest.fixture
def code_tool(tmp_path: Path) -> CodeTool:
    limits = ToolLimits()
    guard = BehaviorGuard(SecurityConfig(), tmp_path)
    return CodeTool(tmp_path, limits, guard)


class TestDunderAttributeEscapes:
    @pytest.mark.asyncio
    async def test_builtins_import_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute('__builtins__.__import__("os")')
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    async def test_class_subclasses_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("().__class__.__base__.__subclasses__()")
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    async def test_class_attribute_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("print(''.__class__)")
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    async def test_getattribute_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("x.__getattribute__('__class__')")
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    async def test_init_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("x.__init__.__globals__")
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    async def test_mro_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("int.__mro__")
        assert not result.success
        assert "Disallowed" in result.error


class TestImportEscapes:
    @pytest.mark.asyncio
    async def test_relative_import_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("from . import os")
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    async def test_relative_parent_import_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("from .. import os")
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    @pytest.mark.parametrize("module", ["io", "posix", "runpy", "shutil", "pty", "pathlib"])
    async def test_newly_disallowed_modules_rejected(
        self, code_tool: CodeTool, module: str
    ) -> None:
        result = await code_tool.execute(f"import {module}")
        assert not result.success
        assert "Disallowed import" in result.error

    @pytest.mark.asyncio
    async def test_from_pathlib_import_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute("from pathlib import Path")
        assert not result.success
        assert "Disallowed import" in result.error

    @pytest.mark.asyncio
    @pytest.mark.parametrize("module", ["pickle", "_pickle", "marshal", "shelve"])
    async def test_deserialization_modules_rejected(self, code_tool: CodeTool, module: str) -> None:
        """Round-3 finding: pickle.loads executes embedded opcodes (confirmed
        RCE inside the sandbox) without any import statement the AST scan
        would catch; the whole deserialization family is denied."""
        result = await code_tool.execute(f"import {module}")
        assert not result.success
        assert "Disallowed import" in result.error

    @pytest.mark.asyncio
    async def test_pickle_rce_payload_rejected(self, code_tool: CodeTool) -> None:
        rce = b"cos\nsystem\np0\n(S'echo PWNED'\np1\ntp2\nRp3\n."
        result = await code_tool.execute(f"import pickle\npickle.loads({rce!r})")
        assert not result.success
        assert "Disallowed import" in result.error


class TestDynamicTypeConstruction:
    @pytest.mark.asyncio
    async def test_type_three_args_rejected(self, code_tool: CodeTool) -> None:
        result = await code_tool.execute('type("X", (), {})()')
        assert not result.success
        assert "Disallowed" in result.error

    @pytest.mark.asyncio
    async def test_type_single_arg_allowed_by_scan(self, code_tool: CodeTool) -> None:
        assert code_tool._scan_code("print(type(1))") is None


class TestLegitCodeStillScansClean:
    @pytest.mark.asyncio
    async def test_math_code_allowed(self, code_tool: CodeTool) -> None:
        assert code_tool._scan_code("import math\nprint(math.sqrt(16))") is None

    def test_math_exp_not_confused_with_exec_prefix(self, code_tool: CodeTool) -> None:
        assert code_tool._scan_code("import math\nprint(math.exp(1))") is None

    def test_future_import_allowed(self, code_tool: CodeTool) -> None:
        assert code_tool._scan_code("from __future__ import annotations\nprint(1)") is None

    def test_json_import_allowed(self, code_tool: CodeTool) -> None:
        assert code_tool._scan_code("import json\nprint(json.dumps({'a': 1}))") is None

    def test_bytecode_disabled_in_child_env(self, code_tool: CodeTool) -> None:
        """F-10: the sandboxed interpreter must not write .pyc files."""
        import inspect

        source = inspect.getsource(CodeTool.execute)
        assert "PYTHONDONTWRITEBYTECODE" in source


class TestUnderscoreAndLoaderScanDenies:
    """P0-1: scan-only denies. Do not execute these snippets."""

    def test_underscore_thread_import_denied(self, code_tool: CodeTool) -> None:
        assert code_tool._scan_code("import _thread") is not None

    def test_frozen_importlib_denied(self, code_tool: CodeTool) -> None:
        assert code_tool._scan_code("import _frozen_importlib") is not None

    def test_from_imp_denied(self, code_tool: CodeTool) -> None:
        assert code_tool._scan_code("from _imp import acquire_lock") is not None

    def test_zipimport_denied(self, code_tool: CodeTool) -> None:
        assert code_tool._scan_code("import zipimport") is not None

    def test_pkgutil_denied(self, code_tool: CodeTool) -> None:
        assert code_tool._scan_code("import pkgutil") is not None

    def test_loader_attr_denied(self, code_tool: CodeTool) -> None:
        denied = code_tool._scan_code("x.__loader__")
        assert denied is not None
        assert "Disallowed" in denied

    def test_load_module_attr_denied(self, code_tool: CodeTool) -> None:
        denied = code_tool._scan_code("loader.load_module")
        assert denied is not None
        assert "Disallowed" in denied

    def test_posix_spawn_attr_denied(self, code_tool: CodeTool) -> None:
        denied = code_tool._scan_code("mod.posix_spawn")
        assert denied is not None
        assert "Disallowed" in denied

    def test_execv_attr_denied(self, code_tool: CodeTool) -> None:
        denied = code_tool._scan_code("mod.execv")
        assert denied is not None
        assert "Disallowed" in denied

    def test_spawnlp_attr_denied(self, code_tool: CodeTool) -> None:
        denied = code_tool._scan_code("mod.spawnlp")
        assert denied is not None
        assert "Disallowed" in denied


class TestImportAllowlistScanDenies:
    """String-exec stdlib family is denied by import allowlist. Scan only."""

    @pytest.mark.parametrize(
        "source",
        [
            "import timeit",
            "import pydoc",
            "import pdb",
            "import asyncio",
            "import codeop",
            "import profile",
            "import cProfile",
            "import trace",
            "import symtable",
            "import timeit\ntimeit.timeit('1+1', number=1)",
        ],
    )
    def test_string_exec_modules_denied(self, code_tool: CodeTool, source: str) -> None:
        assert code_tool._scan_code(source) is not None


class TestAllowlistModuleAttrLeaks:
    """P0-a/P0-b: scan-only. Do not execute these snippets."""

    def test_random_private_os_alias_denied(self, code_tool: CodeTool) -> None:
        denied = code_tool._scan_code("import random\nrandom._os")
        assert denied is not None
        assert "Disallowed" in denied

    def test_collections_private_sys_alias_denied(self, code_tool: CodeTool) -> None:
        denied = code_tool._scan_code("import collections\ncollections._sys")
        assert denied is not None
        assert "Disallowed" in denied

    @pytest.mark.parametrize(
        "source",
        [
            "mod.attrgetter",
            "mod.itemgetter",
            "mod.methodcaller",
            "x.format",
            "x.format_map",
        ],
    )
    def test_string_attribute_resolvers_denied(self, code_tool: CodeTool, source: str) -> None:
        denied = code_tool._scan_code(source)
        assert denied is not None
        assert "Disallowed" in denied

    def test_math_exp_still_allowed(self, code_tool: CodeTool) -> None:
        assert code_tool._scan_code("import math\nprint(math.exp(1))") is None



class TestModuleAttrAllowlistScan:
    """F1/F2/F3: scan-only. Do not execute these snippets."""

    @pytest.mark.parametrize(
        "source",
        [
            "from random import _os",
            "from random import _os as os_mod",
            "from statistics import sys",
            "from fractions import operator",
            "from fractions import sys as s",
            "from json import codecs",
            "from base64 import struct",
            "from math import *",
            "import math._private",
        ],
    )
    def test_from_import_names_denied(self, code_tool: CodeTool, source: str) -> None:
        denied = code_tool._scan_code(source)
        assert denied is not None
        assert "Disallowed" in denied

    @pytest.mark.parametrize(
        "source",
        [
            "import statistics\nstatistics.sys",
            "import statistics\nstatistics.sys.modules",
            "import fractions\nfractions.operator",
            "import json\njson.codecs",
            "import base64\nbase64.struct",
            "import calendar\ncalendar.warnings",
            "import statistics as st\nst.sys",
            "import statistics\nm = statistics\nm.sys",
            "import json\njson.decoder.JSONDecoder",
        ],
    )
    def test_module_valued_attr_hops_denied(self, code_tool: CodeTool, source: str) -> None:
        denied = code_tool._scan_code(source)
        assert denied is not None
        assert "Disallowed" in denied

    @pytest.mark.parametrize(
        "source",
        [
            "x.open",
            "x.fdopen",
            "x.vformat",
        ],
    )
    def test_alias_wash_sinks_denied(self, code_tool: CodeTool, source: str) -> None:
        denied = code_tool._scan_code(source)
        assert denied is not None
        assert "Disallowed" in denied

    @pytest.mark.parametrize(
        "source",
        [
            "import math\nprint(math.sqrt(16))",
            "import math as m\nprint(m.exp(1))",
            "import json\nprint(json.loads('{}'))",
            "from math import sqrt\nprint(sqrt(4))",
            "from datetime import datetime\nprint(datetime.now)",
            "import datetime\nprint(datetime.datetime.now)",
            "import statistics\nprint(statistics.mean([1, 2]))",
            "import re\nprint(re.search('a', 'abc'))",
            "import random\nprint(random.randint(1, 6))",
            "from collections import Counter\nprint(Counter('aab'))",
            "import statistics\nm = statistics\nprint(m.fmean([1.0, 2.0]))",
            "from __future__ import annotations\nprint(1)",
            "import zoneinfo\nprint(zoneinfo.ZoneInfo('UTC'))",
        ],
    )
    def test_public_api_still_allowed(self, code_tool: CodeTool, source: str) -> None:
        assert code_tool._scan_code(source) is None
