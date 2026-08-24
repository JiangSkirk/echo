"""Sandboxed Python code execution tool."""
# noqa: SIM102 (intentional layered security checks)

from __future__ import annotations

import ast
import os
import secrets
import stat
import sys
from pathlib import Path
from typing import Any

from js.config import ToolLimits
from js.security.guard import BehaviorGuard
from js.security.sandbox import SandboxExecutor
from js.tools.registry import ToolParam, ToolResult, ToolSpec


class CodeTool:
    """Execute Python code in a sandboxed environment."""

    DISALLOWED_BUILTINS = frozenset(
        {
            "open",
            "eval",
            "exec",
            "compile",
            "__import__",
            "input",
            "exit",
            "quit",
            "globals",  # globals()["__builtins__"] bypass
            "locals",  # locals() introspection bypass
            "vars",  # vars() introspection bypass
            "breakpoint",  # breakpoint() debugger bypass
        }
    )

    DISALLOWED_IMPORTS = frozenset(
        {
            "os",
            "subprocess",
            "sys",
            "ctypes",
            "socket",
            "urllib",
            "importlib",  # importlib.import_module("os") bypass
            "builtins",  # builtins.open bypass
            "inspect",  # inspect.currentframe() introspection
            "code",  # code.InteractiveConsole bypass
            "types",  # types.FunctionType dynamic code
            "gc",  # gc.get_objects() introspection
            "io",  # io.open raw file access bypass
            "posix",  # posix.system direct syscall module
            "runpy",  # runpy.run_module("os") execution bypass
            "shutil",  # shutil.copy/chown file manipulation
            "pty",  # pty.spawn interactive shell escape
            "pathlib",  # pathlib.Path.write_text file write bypass
            "operator",  # operator.attrgetter("__traceback__") introspection bypass
            "pickle",  # pickle.loads executes embedded opcodes (RCE, bypasses AST scan)
            "_pickle",  # C pickle implementation, same opcode-execution risk
            "marshal",  # marshal.loads loads code objects for exec-equivalent abuse
            "shelve",  # shelve unpickles stored values on read (pickle RCE vector)
            "zipimport",  # zipimport.zipimporter load_module bypass
            "pkgutil",  # pkgutil.get_loader / ModuleType loader family
        }
    )

    # String-exec family (timeit/pdb/pydoc/...) is not listed above.  Import
    # is allowlist-only: anything not in this set is denied, including numpy.
    ALLOWED_IMPORTS = frozenset(
        {
            "math",
            "json",
            "re",
            "datetime",
            "collections",
            "itertools",
            "functools",
            "string",
            "textwrap",
            "base64",
            "binascii",
            "hashlib",
            "hmac",
            "secrets",
            "random",
            "statistics",
            "fractions",
            "decimal",
            "calendar",
            "zoneinfo",
            "__future__",
        }
    )

    # Private CPython modules (`_thread`, `_frozen_importlib`, `_imp`, …) are
    # not named in DISALLOWED_IMPORTS; a leading underscore is the fail-closed
    # stand-in.  `__future__` is the one documented exception.
    _ALLOWED_UNDERSCORE_IMPORTS = frozenset({"__future__"})

    # Attribute names that spawn/exec a process without matching the exact
    # `spawn` / `exec` entries: posix_spawn, execv, spawnlp, …
    # `math.exp` must not match (`exp` is not an `exec*` prefix).
    _DANGEROUS_ATTR_PREFIXES = ("exec", "spawn", "posix_")

    DISALLOWED_ATTRS = frozenset(
        {
            "system",
            "popen",
            "spawn",
            "exec",
            "eval",
            "fork",
            "kill",
            "__loader__",  # module.__loader__.load_module
            "__spec__",
            "__path__",
            "__file__",
            "__package__",
            "load_module",
            "__subclasses__",
            "__mro__",
            "__dict__",  # object introspection
            "__bases__",  # class hierarchy traversal
            "__base__",  # ().class .__base__ hierarchy traversal
            "__globals__",  # function global scope access
            "__code__",  # function code object access
            "__builtins__",  # __builtins__.__import__ sandbox escape
            "__class__",  # ().class .__base__.__subclasses__() escape
            "__init__",  # x.__init__.__globals__ escape
            "__getattribute__",  # getattr-equivalent introspection escape
            "__traceback__",  # exc.__traceback__.tb_frame.f_globals escape
            "tb_frame",  # traceback -> frame -> f_globals escape
            "f_globals",  # frame global scope access
            "f_locals",  # frame local scope access
            "f_builtins",  # frame builtins -> __import__ escape
            "gi_frame",  # generator frame introspection
            "gi_code",  # generator code object access
            "cr_frame",  # coroutine frame introspection
            "cr_await",  # coroutine await stack introspection
            "__closure__",  # closure cell -> enclosed scope access
            "__func__",  # bound method -> function -> __globals__ escape
            "__self__",  # bound method -> instance -> class traversal
            # String-named attribute resolution (operator / str.format family).
            "attrgetter",
            "itemgetter",
            "methodcaller",
            "format",
            "format_map",
            "vformat",  # string.Formatter.vformat — same field parsing as format
            "open",  # alias wash: f = leaked_os.open evades the call-form check
            "fdopen",  # same raw-file sink under a name missing from the call check
        }
    )

    # F2: per-module public API allowlist.  An attribute access on a name bound
    # to an allowlisted module (import / import-as / plain assignment) must land
    # in this table, as must every `from X import name`.  Module-valued
    # attributes are excluded on purpose: statistics.sys / fractions.operator /
    # json.codecs … hand a live module (and via sys.modules the whole loaded
    # set) to the payload.  Generated from each module's public dir() minus
    # module-valued members.
    MODULE_ATTR_ALLOWLIST: dict[str, frozenset[str]] = {
        "math": frozenset(
            {
                "acos", "acosh", "asin", "asinh", "atan", "atan2",
                "atanh", "cbrt", "ceil", "comb", "copysign", "cos",
                "cosh", "degrees", "dist", "e", "erf", "erfc",
                "exp", "exp2", "expm1", "fabs", "factorial", "floor",
                "fmod", "frexp", "fsum", "gamma", "gcd", "hypot",
                "inf", "isclose", "isfinite", "isinf", "isnan", "isqrt",
                "lcm", "ldexp", "lgamma", "log", "log10", "log1p",
                "log2", "modf", "nan", "nextafter", "perm", "pi",
                "pow", "prod", "radians", "remainder", "sin", "sinh",
                "sqrt", "sumprod", "tan", "tanh", "tau", "trunc",
                "ulp",
            }
        ),
        "json": frozenset(
            {
                "JSONDecodeError", "JSONDecoder", "JSONEncoder", "detect_encoding", "dump", "dumps",
                "load", "loads",
            }
        ),
        "re": frozenset(
            {
                "A", "ASCII", "DEBUG", "DOTALL", "I", "IGNORECASE",
                "L", "LOCALE", "M", "MULTILINE", "Match", "NOFLAG",
                "Pattern", "RegexFlag", "S", "Scanner", "T", "TEMPLATE",
                "U", "UNICODE", "VERBOSE", "X", "compile", "error",
                "escape", "findall", "finditer", "fullmatch", "match", "purge",
                "search", "split", "sub", "subn", "template",
            }
        ),
        "datetime": frozenset(
            {
                "MAXYEAR", "MINYEAR", "UTC", "date", "datetime", "datetime_CAPI",
                "time", "timedelta", "timezone", "tzinfo",
            }
        ),
        "collections": frozenset(
            {
                "ChainMap", "Counter", "OrderedDict", "UserDict", "UserList", "UserString",
                "defaultdict", "deque", "namedtuple",
            }
        ),
        "itertools": frozenset(
            {
                "accumulate", "batched", "chain", "combinations", "combinations_with_replacement", "compress",
                "count", "cycle", "dropwhile", "filterfalse", "groupby", "islice",
                "pairwise", "permutations", "product", "repeat", "starmap", "takewhile",
                "tee", "zip_longest",
            }
        ),
        "functools": frozenset(
            {
                "GenericAlias", "RLock", "WRAPPER_ASSIGNMENTS", "WRAPPER_UPDATES", "cache", "cached_property",
                "cmp_to_key", "get_cache_token", "lru_cache", "namedtuple", "partial", "partialmethod",
                "recursive_repr", "reduce", "singledispatch", "singledispatchmethod", "total_ordering", "update_wrapper",
                "wraps",
            }
        ),
        "string": frozenset(
            {
                "Formatter", "Template", "ascii_letters", "ascii_lowercase", "ascii_uppercase", "capwords",
                "digits", "hexdigits", "octdigits", "printable", "punctuation", "whitespace",
            }
        ),
        "textwrap": frozenset(
            {
                "TextWrapper", "dedent", "fill", "indent", "shorten", "wrap",
            }
        ),
        "base64": frozenset(
            {
                "MAXBINSIZE", "MAXLINESIZE", "a85decode", "a85encode", "b16decode", "b16encode",
                "b32decode", "b32encode", "b32hexdecode", "b32hexencode", "b64decode", "b64encode",
                "b85decode", "b85encode", "bytes_types", "decode", "decodebytes", "encode",
                "encodebytes", "main", "standard_b64decode", "standard_b64encode", "urlsafe_b64decode", "urlsafe_b64encode",
            }
        ),
        "binascii": frozenset(
            {
                "Error", "Incomplete", "a2b_base64", "a2b_hex", "a2b_qp", "a2b_uu",
                "b2a_base64", "b2a_hex", "b2a_qp", "b2a_uu", "crc32", "crc_hqx",
                "hexlify", "unhexlify",
            }
        ),
        "hashlib": frozenset(
            {
                "algorithms_available", "algorithms_guaranteed", "blake2b", "blake2s", "file_digest", "md5",
                "new", "pbkdf2_hmac", "scrypt", "sha1", "sha224", "sha256",
                "sha384", "sha3_224", "sha3_256", "sha3_384", "sha3_512", "sha512",
                "shake_128", "shake_256",
            }
        ),
        "hmac": frozenset(
            {
                "HMAC", "compare_digest", "digest", "digest_size", "new", "trans_36",
                "trans_5C",
            }
        ),
        "secrets": frozenset(
            {
                "DEFAULT_ENTROPY", "SystemRandom", "choice", "compare_digest", "randbelow", "randbits",
                "token_bytes", "token_hex", "token_urlsafe",
            }
        ),
        "random": frozenset(
            {
                "BPF", "LOG4", "NV_MAGICCONST", "RECIP_BPF", "Random", "SG_MAGICCONST",
                "SystemRandom", "TWOPI", "betavariate", "binomialvariate", "choice", "choices",
                "expovariate", "gammavariate", "gauss", "getrandbits", "getstate", "lognormvariate",
                "normalvariate", "paretovariate", "randbytes", "randint", "random", "randrange",
                "sample", "seed", "setstate", "shuffle", "triangular", "uniform",
                "vonmisesvariate", "weibullvariate",
            }
        ),
        "statistics": frozenset(
            {
                "Counter", "Decimal", "Fraction", "LinearRegression", "NormalDist", "StatisticsError",
                "bisect_left", "bisect_right", "correlation", "count", "covariance", "defaultdict",
                "erf", "exp", "fabs", "fmean", "fsum", "geometric_mean",
                "groupby", "harmonic_mean", "hypot", "linear_regression", "log", "mean",
                "median", "median_grouped", "median_high", "median_low", "mode", "multimode",
                "namedtuple", "pstdev", "pvariance", "quantiles", "reduce", "repeat",
                "sqrt", "stdev", "sumprod", "tau", "variance",
            }
        ),
        "fractions": frozenset(
            {
                "Decimal", "Fraction",
            }
        ),
        "decimal": frozenset(
            {
                "BasicContext", "Clamped", "Context", "ConversionSyntax", "Decimal", "DecimalException",
                "DecimalTuple", "DefaultContext", "DivisionByZero", "DivisionImpossible", "DivisionUndefined", "ExtendedContext",
                "FloatOperation", "HAVE_CONTEXTVAR", "HAVE_THREADS", "Inexact", "InvalidContext", "InvalidOperation",
                "MAX_EMAX", "MAX_PREC", "MIN_EMIN", "MIN_ETINY", "Overflow", "ROUND_05UP",
                "ROUND_CEILING", "ROUND_DOWN", "ROUND_FLOOR", "ROUND_HALF_DOWN", "ROUND_HALF_EVEN", "ROUND_HALF_UP",
                "ROUND_UP", "Rounded", "Subnormal", "Underflow", "getcontext", "localcontext",
                "setcontext",
            }
        ),
        "calendar": frozenset(
            {
                "APRIL", "AUGUST", "Calendar", "DECEMBER", "Day", "EPOCH",
                "FEBRUARY", "FRIDAY", "HTMLCalendar", "IllegalMonthError", "IllegalWeekdayError", "IntEnum",
                "JANUARY", "JULY", "JUNE", "LocaleHTMLCalendar", "LocaleTextCalendar", "MARCH",
                "MAY", "MONDAY", "Month", "NOVEMBER", "OCTOBER", "SATURDAY",
                "SEPTEMBER", "SUNDAY", "THURSDAY", "TUESDAY", "TextCalendar", "WEDNESDAY",
                "c", "calendar", "day_abbr", "day_name", "different_locale", "error",
                "firstweekday", "formatstring", "global_enum", "isleap", "leapdays", "main",
                "mdays", "month", "month_abbr", "month_name", "monthcalendar", "monthrange",
                "prcal", "prmonth", "prweek", "repeat", "setfirstweekday", "timegm",
                "week", "weekday", "weekheader",
            }
        ),
        "zoneinfo": frozenset(
            {
                "InvalidTZPathWarning", "TZPATH", "ZoneInfo", "ZoneInfoNotFoundError", "available_timezones", "reset_tzpath",
            }
        ),
        "__future__": frozenset(
            {
                "absolute_import", "annotations", "barry_as_FLUFL", "division", "generator_stop", "generators",
                "nested_scopes", "print_function", "unicode_literals", "with_statement",
            }
        ),
    }

    def __init__(self, workspace: Path, limits: ToolLimits, guard: BehaviorGuard) -> None:
        self.workspace = workspace.resolve()
        self.limits = limits
        self.guard = guard
        self.executor = SandboxExecutor(
            workspace=workspace,
            timeout=limits.shell_timeout,
            max_output_bytes=limits.shell_max_output_bytes,
            strict_isolation=True,
            trusted_executables=[Path(sys.executable)],
        )

    def get_spec(self) -> ToolSpec:
        return ToolSpec(
            name="python",
            description=(
                "Execute Python and return stdout/stderr. Imports are limited to "
                "pure-computation stdlib modules: math, json, re, datetime, "
                "collections, itertools, functools, string, textwrap, base64, "
                "binascii, hashlib, hmac, secrets, random, statistics, fractions, "
                "decimal, calendar, zoneinfo, and __future__. Files can be read "
                "from workspace."
            ),
            parameters=[
                ToolParam("code", "string", "Python code to execute"),
                ToolParam("timeout", "integer", "Execution timeout in seconds", required=False),
            ],
            dangerous=True,
        )

    async def execute(self, code: str, timeout: int = 0) -> ToolResult:
        if len(code) > self.limits.file_write_max_chars:
            return ToolResult(success=False, error="Code exceeds the execution size limit")

        # Quick AST scan for dangerous patterns
        scan = self._scan_code(code)
        if scan:
            return ToolResult(success=False, error=f"Code security scan failed: {scan}")

        script_path: Path
        temp_dir_fd: int
        script_name: str
        try:
            script_path, temp_dir_fd, script_name = self._create_private_script(code)
        except (OSError, RuntimeError, ValueError):
            return ToolResult(
                success=False,
                error="Secure code temporary directory is unavailable",
            )

        try:
            effective_timeout = min(
                timeout or self.limits.shell_timeout, self.limits.shell_timeout
            )
            cell_backend = getattr(self, "cell_backend", None)
            if cell_backend is not None:
                return await self._execute_via_build_cell(
                    argv=[sys.executable, str(script_path)],
                    timeout_s=int(effective_timeout),
                    backend=cell_backend,
                )
            result = await self.executor.execute(
                [sys.executable, str(script_path)],
                cwd=str(self.workspace),
                # Never let the sandboxed interpreter emit .pyc bytecode into
                # __pycache__ directories (on-host artifact poisoning vector).
                env={"PYTHONDONTWRITEBYTECODE": "1"},
                # Caller-supplied timeout may only shorten the configured
                # ceiling, never extend it.
                timeout=effective_timeout,
                network_allowed=False,
                fs_restricted=True,
            )

            return ToolResult(
                success=result.returncode == 0 and not result.killed,
                output=result.stdout,
                error=result.stderr,
                metadata={
                    "returncode": result.returncode,
                    "duration_ms": result.duration_ms,
                },
            )
        finally:
            try:
                os.unlink(script_name, dir_fd=temp_dir_fd)
                os.fsync(temp_dir_fd)
            except FileNotFoundError:
                pass
            finally:
                os.close(temp_dir_fd)

    async def _execute_via_build_cell(
        self,
        *,
        argv: list[str],
        timeout_s: int,
        backend: Any,
    ) -> ToolResult:
        """WP7: run the already-scanned script inside the Build Cell."""

        from js.echo.capability import LeaseDenied

        try:
            raw = await backend(
                {
                    "kind": "shell",
                    "command": list(argv),
                    "cwd": str(self.workspace),
                    "timeout_ms": int(timeout_s * 1000),
                    "tool": "code",
                }
            )
        except LeaseDenied as exc:
            return ToolResult(
                success=False,
                error=(
                    "Safety degradation: Build Cell unavailable — "
                    f"build effects are paused ({type(exc).__name__}). "
                    "Other tools are unaffected."
                ),
            )
        success = raw.get("status") == "COMMITTED"
        output = str(raw.get("output") or "")
        return ToolResult(
            success=success,
            output=output,
            error="" if success else output[-2000:],
            metadata={
                "returncode": int(raw.get("returncode", -1)),
                "duration_ms": raw.get("duration_ms"),
                "killed": bool(raw.get("killed")),
                "cell": "build",
            },
        )

    def _create_private_script(self, code: str) -> tuple[Path, int, str]:
        """Create an execution script without following workspace symlinks."""
        required_dir_fd = (os.open, os.mkdir, os.unlink)
        if (
            not hasattr(os, "O_DIRECTORY")
            or not hasattr(os, "O_NOFOLLOW")
            or not hasattr(os, "O_CLOEXEC")
            or any(function not in os.supports_dir_fd for function in required_dir_fd)
        ):
            raise RuntimeError("Secure temporary-file primitives are unavailable")

        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        workspace_fd = os.open(self.workspace, directory_flags)
        temp_dir_fd = -1
        try:
            try:
                os.mkdir(".js-code", 0o700, dir_fd=workspace_fd)
                os.fsync(workspace_fd)
            except FileExistsError:
                pass
            temp_dir_fd = os.open(".js-code", directory_flags, dir_fd=workspace_fd)
            metadata = os.fstat(temp_dir_fd)
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("Code temporary path is not a directory")
            if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                raise ValueError("Code temporary directory has an unexpected owner")
            os.fchmod(temp_dir_fd, 0o700)
        except BaseException:
            if temp_dir_fd >= 0:
                os.close(temp_dir_fd)
            raise
        finally:
            os.close(workspace_fd)

        script_name = f"script-{secrets.token_hex(16)}.py"
        script_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
        try:
            script_fd = os.open(script_name, script_flags, 0o600, dir_fd=temp_dir_fd)
            try:
                payload = code.encode("utf-8")
                view = memoryview(payload)
                while view:
                    written = os.write(script_fd, view)
                    if written <= 0:
                        raise OSError("Code script write stalled")
                    view = view[written:]
                os.fsync(script_fd)
            finally:
                os.close(script_fd)
            os.fsync(temp_dir_fd)
        except BaseException:
            try:
                os.unlink(script_name, dir_fd=temp_dir_fd)
            except FileNotFoundError:
                pass
            os.close(temp_dir_fd)
            raise

        return self.workspace / ".js-code" / script_name, temp_dir_fd, script_name

    def _scan_code(self, code: str) -> str | None:
        """Quick static analysis for dangerous patterns."""
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            return f"Syntax error: {e}"

        # Local names bound to allowlisted module objects, mapped to the module
        # root.  `ast.walk` is breadth-first, so every top-level binding is
        # recorded before any attribute node that could use it is visited.
        module_bindings: dict[str, str] = {}

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    segments = alias.name.split(".")
                    root = segments[0]
                    if self._import_root_denied(root):
                        return f"Disallowed import: {alias.name}"
                    if any(segment.startswith("_") for segment in segments[1:]):
                        return f"Disallowed private submodule import: {alias.name}"
                    # `import json.decoder` still binds the root name `json`;
                    # both forms are checked against the root module's table.
                    module_bindings[alias.asname or root] = root
            elif isinstance(node, ast.ImportFrom):
                # Relative imports (from . import os) resolve against the
                # caller's package context and escape the module allowlist.
                if node.level and node.level > 0:
                    return "Disallowed relative import — sandbox bypass"
                if node.module:
                    segments = node.module.split(".")
                    root = segments[0]
                    if self._import_root_denied(root):
                        return f"Disallowed import: {node.module}"
                    if any(segment.startswith("_") for segment in segments[1:]):
                        return f"Disallowed private submodule import: {node.module}"
                    # F1/F2: the imported symbol names were never inspected,
                    # so `from random import _os` / `from statistics import sys`
                    # rebound dangerous modules without any attribute access.
                    table = self.MODULE_ATTR_ALLOWLIST.get(root)
                    for alias in node.names:
                        if alias.name == "*":
                            # Star imports bind whatever public names exist —
                            # including module-valued members the table hides.
                            return f"Disallowed star import from {root} — sandbox bypass"
                        if self._is_disallowed_attr(alias.name):
                            return f"Disallowed imported name: {node.module}.{alias.name}"
                        if table is not None and alias.name not in table:
                            return (
                                f"Disallowed imported name: {node.module}.{alias.name} "
                                "— outside the module's public API"
                            )
            elif isinstance(node, ast.Assign):
                # `m = math` alias propagation for the module attribute table.
                if isinstance(node.value, ast.Name) and node.value.id in module_bindings:
                    source = module_bindings[node.value.id]
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            module_bindings[target.id] = source
            elif isinstance(node, ast.AnnAssign):
                if (
                    isinstance(node.value, ast.Name)
                    and node.value.id in module_bindings
                    and isinstance(node.target, ast.Name)
                ):
                    module_bindings[node.target.id] = module_bindings[node.value.id]
            elif isinstance(node, ast.Call):
                # Check for disallowed builtins
                if isinstance(node.func, ast.Name) and node.func.id in self.DISALLOWED_BUILTINS:
                    return f"Disallowed builtin: {node.func.id}"
                # Same sinks in attribute-call form: x.open(...), x.__import__(...),
                # obj.eval(...), etc. (exec/eval also sit in DISALLOWED_ATTRS, which
                # blocks even non-call attribute access below).
                if (
                    isinstance(node.func, ast.Attribute)
                    and node.func.attr in self.DISALLOWED_BUILTINS
                ):
                    return f"Disallowed builtin attribute call: {node.func.attr}"
                # type("X", (), {}) dynamic class construction — bootstrap for
                # metaclass/__subclasses__ escapes.
                if (
                    isinstance(node.func, ast.Name)
                    and node.func.id == "type"
                    and len(node.args) == 3
                ):
                    return "Disallowed type() with 3 arguments — dynamic class construction"
                # Check for subprocess
                if isinstance(node.func, ast.Attribute) and node.func.attr in (
                    "popen",
                    "call",
                    "run",
                ):
                    return f"Disallowed subprocess call: {node.func.attr}"
                # Check for getattr(__builtins__, ...) bypass
                if isinstance(node.func, ast.Name) and node.func.id == "getattr":
                    return "Disallowed getattr() call — potential sandbox bypass"
                # Check for builtins.open / builtins.eval (import builtins; builtins.open(...))
                if (
                    isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "builtins"
                ):
                    return f"Disallowed builtins.{node.func.attr} call — sandbox bypass"
                # Check for all reflective class introspection attrs
                if isinstance(node.func, ast.Attribute) and self._is_disallowed_attr(
                    node.func.attr
                ):
                    return f"Disallowed reflective attribute: {node.func.attr}"
            elif isinstance(node, ast.Attribute):
                if self._is_disallowed_attr(node.attr):
                    return f"Disallowed reflective attribute access: {node.attr}"
                # F2: attributes on module-bound names must be public API.
                # Blocks statistics.sys / json.codecs / fractions.operator —
                # public names that leak live modules — at the first hop.
                if isinstance(node.value, ast.Name) and node.value.id in module_bindings:
                    bound_root = module_bindings[node.value.id]
                    table = self.MODULE_ATTR_ALLOWLIST.get(bound_root)
                    if table is not None and node.attr not in table:
                        return (
                            f"Disallowed module attribute: {bound_root}.{node.attr} "
                            "— outside the module's public API"
                        )
            # Bare __builtins__ name access (e.g. __builtins__.__import__)
            elif isinstance(node, ast.Name) and node.id == "__builtins__":
                return "Disallowed __builtins__ access — sandbox bypass"
            # Check for __builtins__["eval"] / globals()["__builtins__"] subscript bypass
            elif (
                isinstance(node, ast.Subscript)
                and isinstance(node.value, ast.Name)
                and node.value.id == "__builtins__"
            ):
                return "Disallowed __builtins__ subscript access — sandbox bypass"

        return None

    def _import_root_denied(self, root: str) -> bool:
        if root.startswith("_") and root not in self._ALLOWED_UNDERSCORE_IMPORTS:
            return True
        if root in self.DISALLOWED_IMPORTS:
            return True
        return root not in self.ALLOWED_IMPORTS

    def _is_disallowed_attr(self, attr: str) -> bool:
        # Allowlisted modules expose private aliases like random._os / collections._sys.
        # Public computation APIs never need a leading underscore.
        if attr.startswith("_"):
            return True
        if attr in self.DISALLOWED_ATTRS:
            return True
        if attr.startswith(self._DANGEROUS_ATTR_PREFIXES):
            return True
        return attr.endswith("spawn")

    def register(self, registry: Any) -> None:
        registry.register(self.get_spec(), self.execute)
