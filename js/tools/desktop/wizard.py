"""Desktop control first-use setup wizard.

Detects and guides installation of dependencies and macOS permissions.
Designed to be called from both the web API and CLI context.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("js.tools.desktop.wizard")


@dataclass
class WizardStep:
    name: str
    title: str
    # "ok" | "missing" (not installed/not authorized) |
    # "unavailable" (tool missing and cannot auto-install) |
    # "error" (detection failed)
    status: str
    detail: str = ""
    action_label: str = ""
    action_type: str = ""  # "install" | "open_accessibility" | "open_screen_recording" | "none"


@dataclass
class WizardState:
    steps: list[WizardStep] = field(default_factory=list)
    ready: bool = False
    deps_ready: bool = False
    perms_ready: bool = False
    overall_status: str = "checking"
    can_install_cliclick: bool = False  # True if brew is available and cliclick is missing
    install_summary: str = ""  # Last install attempt result, if any


# ── Dependency checks ──

def _has_brew() -> bool:
    return shutil.which("brew") is not None


def _has_cliclick() -> bool:
    return shutil.which("cliclick") is not None


def _has_screencapture() -> bool:
    return shutil.which("screencapture") is not None


# Store last install attempt for display
_last_install_result: dict[str, Any] = {}


def install_cliclick() -> tuple[bool, str]:
    """Attempt to install cliclick via brew. Returns (success, message)."""
    global _last_install_result

    if _has_cliclick():
        _last_install_result = {"success": True, "summary": "cliclick already installed", "error": "", "stderr": ""}
        return True, "cliclick already installed"

    if not _has_brew():
        _last_install_result = {"success": False, "summary": "Homebrew not found",
                                "error": "Homebrew 未安装", "stderr": "",
                                "help": "Visit https://brew.sh to install Homebrew first"}
        return False, "Homebrew 未安装。请先访问 https://brew.sh 安装 Homebrew，然后运行: brew install cliclick"

    try:
        result = subprocess.run(
            ["brew", "install", "cliclick"],
            capture_output=True, text=True, timeout=60,
        )
        stderr_tail = result.stderr.strip()[-500:] if result.stderr else ""
        if result.returncode == 0:
            _last_install_result = {"success": True, "summary": "Installed successfully",
                                    "error": "", "stderr": stderr_tail}
            return True, "cliclick 安装成功"
        err_msg = stderr_tail[:300]
        _last_install_result = {"success": False, "summary": "Installation failed",
                                "error": err_msg, "stderr": stderr_tail,
                                "help": "Try: brew update && brew install cliclick"}
        return False, err_msg
    except FileNotFoundError:
        _last_install_result = {"success": False, "summary": "brew command not found",
                                "error": "brew 命令不可用", "stderr": ""}
        return False, "brew 命令不可用"
    except subprocess.TimeoutExpired:
        _last_install_result = {"success": False, "summary": "Install timed out (60s)",
                                "error": "安装超时", "stderr": ""}
        return False, "安装超时（60秒），请手动运行: brew install cliclick"
    except Exception as e:
        _last_install_result = {"success": False, "summary": str(e)[:200],
                                "error": str(e), "stderr": ""}
        return False, f"安装出错: {e}"


def get_install_summary() -> dict[str, Any]:
    """Return the last install result for display in UI."""
    return dict(_last_install_result)


# ── Permission checks with granular status ──

def _check_permission_with_fallback(check_fn: Callable[[], bool], fallback_cmd: list[str]) -> dict[str, str]:
    """Check a permission. Returns {"status": "ok"|"missing"|"unavailable"|"error", "detail": str}."""
    try:
        if check_fn():
            return {"status": "ok", "detail": "已授权"}
        return {"status": "missing", "detail": "未授权"}
    except Exception:
        # Try fallback check
        try:
            result = subprocess.run(fallback_cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return {"status": "ok", "detail": "已授权（通过 fallback 检测）"}
            return {"status": "missing", "detail": "未授权"}
        except FileNotFoundError:
            return {"status": "unavailable", "detail": "检测命令不可用"}
        except Exception as e:
            return {"status": "error", "detail": f"检测失败: {e}"}


def check_accessibility_detailed() -> dict[str, str]:
    """Detailed accessibility check with fallback."""
    try:
        from .permissions import PermissionChecker
        return _check_permission_with_fallback(
            PermissionChecker.check_accessibility,
            ["cliclick", "p:"],
        )
    except Exception as e:
        return {"status": "error", "detail": f"检测失败: {e}"}


def check_screen_recording_detailed() -> dict[str, str]:
    """Detailed screen recording check with fallback."""
    try:
        from .permissions import PermissionChecker
        return _check_permission_with_fallback(
            PermissionChecker.check_screen_recording,
            ["screencapture", "-R0,0,1,1", "-x", "-c"],
        )
    except Exception as e:
        return {"status": "error", "detail": f"检测失败: {e}"}


# ── Settings openers ──

def open_accessibility_settings() -> bool:
    try:
        subprocess.run(
            ["open", "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"],
            capture_output=True, timeout=5,
        )
        return True
    except Exception:
        return False


def open_screen_recording_settings() -> bool:
    try:
        subprocess.run(
            ["open", "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture"],
            capture_output=True, timeout=5,
        )
        return True
    except Exception:
        return False


# ── Wizard logic ──

def run_wizard() -> WizardState:
    """Run the full first-use wizard, returning current state.

    Call this repeatedly — it checks current conditions each time
    so the frontend can poll until everything is ready.
    """
    steps: list[WizardStep] = []
    install_summary = ""

    # Step 1: Platform
    import platform
    is_macos = platform.system() == "Darwin"
    steps.append(WizardStep(
        name="platform",
        title="平台检测",
        status="ok" if is_macos else "unavailable",
        detail="macOS 平台" if is_macos else f"当前平台 {platform.system()} 不支持桌面控制",
    ))
    if not is_macos:
        return WizardState(steps=steps, ready=False, overall_status="unsupported")

    # Step 2: Mouse/keyboard backend (Quartz CGEvent preferred, cliclick optional)
    _has_quartz = False
    try:
        from . import controller_native
        controller_native._init_quartz()
        _has_quartz = controller_native._QUARTZ_AVAILABLE
    except Exception:
        pass

    if _has_quartz:
        steps.append(WizardStep(
            name="mouse_backend", title="鼠标键盘后端",
            status="ok", detail="PyObjC Quartz CGEvent（macOS 原生）",
        ))
    elif _has_cliclick():
        steps.append(WizardStep(
            name="mouse_backend", title="鼠标键盘后端",
            status="ok", detail="cliclick（fallback）",
        ))
    elif _has_brew():
        steps.append(WizardStep(
            name="mouse_backend", title="鼠标键盘后端",
            status="missing",
            detail="需要 PyObjC (pip install pyobjc-framework-Quartz) 或 cliclick (brew install cliclick)。推荐 PyObjC，无需额外依赖。",
            action_label="安装 cliclick (brew)", action_type="install",
        ))
    else:
        steps.append(WizardStep(
            name="mouse_backend", title="鼠标键盘后端",
            status="missing",
            detail="需要 PyObjC 或 cliclick。推荐: pip install pyobjc-framework-Quartz（无需 Homebrew）",
        ))

    # Step 3: screencapture
    has_sc = _has_screencapture()
    steps.append(WizardStep(
        name="screencapture", title="screencapture（截图）",
        status="ok" if has_sc else "missing",
        detail="macOS 内置截图工具，已可用" if has_sc else "screencapture 不可用，请检查系统",
    ))

    # Step 4: Accessibility (detailed)
    acc = check_accessibility_detailed()
    acc_action = ""
    acc_action_type = "none"
    if acc["status"] == "missing":
        acc_action = "打开辅助功能设置"
        acc_action_type = "open_accessibility"
    steps.append(WizardStep(
        name="accessibility", title="辅助功能权限",
        status=acc["status"],
        detail=acc["detail"] + " — 需要此权限才能控制鼠标和键盘",
        action_label=acc_action, action_type=acc_action_type,
    ))

    # Step 5: Screen Recording (detailed)
    sr = check_screen_recording_detailed()
    sr_action = ""
    sr_action_type = "none"
    if sr["status"] == "missing":
        sr_action = "打开屏幕录制设置"
        sr_action_type = "open_screen_recording"
    steps.append(WizardStep(
        name="screen_recording", title="屏幕录制权限",
        status=sr["status"],
        detail=sr["detail"] + " — 需要此权限才能截图",
        action_label=sr_action, action_type=sr_action_type,
    ))

    # Determine readiness: need ANY mouse backend + screencapture + perms
    has_mouse_backend = _has_quartz or _has_cliclick()
    deps_ok = has_mouse_backend and _has_screencapture()
    perms_ok = acc["status"] == "ok" and sr["status"] == "ok"
    ready = is_macos and deps_ok and perms_ok

    if ready:
        overall = "ready"
    elif not deps_ok:
        overall = "missing_deps"
    elif not perms_ok:
        overall = "missing_perms"
    else:
        overall = "checking"

    return WizardState(
        steps=steps, ready=ready,
        deps_ready=deps_ok, perms_ready=perms_ok,
        overall_status=overall,
        can_install_cliclick=not has_mouse_backend and _has_brew(),
        install_summary=install_summary,
    )


def execute_action(action_type: str) -> dict[str, Any]:
    """Execute a wizard action. Returns result dict with error details."""
    actions = {
        "install": lambda: install_cliclick(),
        "open_accessibility": lambda: (open_accessibility_settings(), "已打开辅助功能设置面板。请在列表中勾选终端或 VS Code，然后返回此页面。"),
        "open_screen_recording": lambda: (open_screen_recording_settings(), "已打开屏幕录制设置面板。请在列表中勾选终端或 VS Code，然后返回此页面。"),
    }
    handler = actions.get(action_type)
    if handler is None:
        return {"success": False, "error": f"Unknown action: {action_type}"}

    try:
        result = handler()  # type: ignore[no-untyped-call]
        if isinstance(result, tuple):
            ok, msg = result
            resp = {"success": ok, "message": msg}
        else:
            ok, msg = result
            resp = {"success": ok, "message": msg}

        # Attach install debug info if applicable
        if action_type == "install":
            resp["install_summary"] = get_install_summary()

        return resp
    except Exception as e:
        return {"success": False, "error": str(e)}
