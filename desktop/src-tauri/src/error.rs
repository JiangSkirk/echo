//! Closed-set desktop / sidecar failure codes and safe display helpers.
//!
//! Raw stderr, bootstrap tokens, HOME paths, and credential-shaped strings must
//! never appear in Display output or evidence. URLs that may carry a bootstrap
//! fragment must be stripped before logging.

use std::fmt;
use url::Url;

/// Primary closed-set error codes shown to operators and recovery UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopErrorCode {
    SpawnFailed,
    ReadyTimeout,
    SentinelInvalid,
    DigestMismatch,
    PgidEscape,
    /// Child exited before ready; takes priority over stream-level symptoms.
    SidecarExit,
    /// Child terminated by signal before ready; highest exit-class priority.
    SidecarSignal,
    Cancelled,
    TrayFailed,
    WindowFailed,
    BootstrapFailed,
    /// Stdout closed before sentinel when no exit status could be reaped yet.
    StdoutEof,
}

impl DesktopErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SpawnFailed => "spawn_failed",
            Self::ReadyTimeout => "ready_timeout",
            Self::SentinelInvalid => "sentinel_invalid",
            Self::DigestMismatch => "digest_mismatch",
            Self::PgidEscape => "pgid_escape",
            Self::SidecarExit => "sidecar_exit",
            Self::SidecarSignal => "sidecar_signal",
            Self::Cancelled => "cancelled",
            Self::TrayFailed => "tray_failed",
            Self::WindowFailed => "window_failed",
            Self::BootstrapFailed => "bootstrap_failed",
            Self::StdoutEof => "stdout_eof",
        }
    }
}

impl fmt::Display for DesktopErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Secondary detail — never replaces primary code when the child has exited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorDetail {
    StdoutEof,
    SentinelInvalid,
    DigestMismatch,
    PgidEscape,
    ReadyTimeout,
    SpawnFailed,
}

impl ErrorDetail {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::StdoutEof => "stdout_eof",
            Self::SentinelInvalid => "sentinel_invalid",
            Self::DigestMismatch => "digest_mismatch",
            Self::PgidEscape => "pgid_escape",
            Self::ReadyTimeout => "ready_timeout",
            Self::SpawnFailed => "spawn_failed",
        }
    }
}

/// Symptom observed while waiting for the ready sentinel (before priority fold).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadyFailureKind {
    StdoutEof,
    ReadyTimeout,
    SentinelInvalid,
    DigestMismatch,
    PgidEscape,
    SpawnFailed,
    Cancelled,
    Other,
}

impl ReadyFailureKind {
    fn to_detail(self) -> Option<ErrorDetail> {
        match self {
            Self::StdoutEof => Some(ErrorDetail::StdoutEof),
            Self::ReadyTimeout => Some(ErrorDetail::ReadyTimeout),
            Self::SentinelInvalid => Some(ErrorDetail::SentinelInvalid),
            Self::DigestMismatch => Some(ErrorDetail::DigestMismatch),
            Self::PgidEscape => Some(ErrorDetail::PgidEscape),
            Self::SpawnFailed => Some(ErrorDetail::SpawnFailed),
            Self::Cancelled | Self::Other => None,
        }
    }

    fn to_primary_without_exit(self) -> DesktopErrorCode {
        match self {
            Self::StdoutEof => DesktopErrorCode::StdoutEof,
            Self::ReadyTimeout => DesktopErrorCode::ReadyTimeout,
            Self::SentinelInvalid => DesktopErrorCode::SentinelInvalid,
            Self::DigestMismatch => DesktopErrorCode::DigestMismatch,
            Self::PgidEscape => DesktopErrorCode::PgidEscape,
            Self::SpawnFailed => DesktopErrorCode::SpawnFailed,
            Self::Cancelled => DesktopErrorCode::Cancelled,
            Self::Other => DesktopErrorCode::SpawnFailed,
        }
    }
}

/// Structured, safe-to-display failure for shell UI and supervisor errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopFailure {
    pub code: DesktopErrorCode,
    pub detail: Option<ErrorDetail>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    /// Attribute only — never a substitute for the primary code.
    pub stderr_truncated: bool,
}

impl DesktopFailure {
    /// Fold exit status and stream symptoms into a single primary code.
    ///
    /// Priority when the child has exited:
    /// 1. `sidecar_signal` if terminated by signal
    /// 2. `sidecar_exit` if an exit code is available
    /// 3. otherwise kind-specific primary
    ///
    /// `stdout_eof` becomes `detail` when an exit/signal is present.
    /// `stderr_truncated` is always only a boolean attribute.
    pub fn classify(
        exit_code: Option<i32>,
        signal: Option<i32>,
        kind: ReadyFailureKind,
        stderr_truncated: bool,
    ) -> Self {
        if let Some(sig) = signal {
            return Self {
                code: DesktopErrorCode::SidecarSignal,
                detail: kind.to_detail(),
                exit_code: None,
                signal: Some(sig),
                stderr_truncated,
            };
        }
        if let Some(code) = exit_code {
            return Self {
                code: DesktopErrorCode::SidecarExit,
                detail: kind.to_detail(),
                exit_code: Some(code),
                signal: None,
                stderr_truncated,
            };
        }
        Self {
            code: kind.to_primary_without_exit(),
            detail: None,
            exit_code: None,
            signal: None,
            stderr_truncated,
        }
    }

    pub fn tray_failed() -> Self {
        Self {
            code: DesktopErrorCode::TrayFailed,
            detail: None,
            exit_code: None,
            signal: None,
            stderr_truncated: false,
        }
    }

    pub fn window_failed() -> Self {
        Self {
            code: DesktopErrorCode::WindowFailed,
            detail: None,
            exit_code: None,
            signal: None,
            stderr_truncated: false,
        }
    }

    pub fn bootstrap_failed() -> Self {
        Self {
            code: DesktopErrorCode::BootstrapFailed,
            detail: None,
            exit_code: None,
            signal: None,
            stderr_truncated: false,
        }
    }

    pub fn cancelled() -> Self {
        Self {
            code: DesktopErrorCode::Cancelled,
            detail: None,
            exit_code: None,
            signal: None,
            stderr_truncated: false,
        }
    }
}

impl fmt::Display for DesktopFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code.as_str())?;
        if let Some(detail) = self.detail {
            write!(f, " detail={}", detail.as_str())?;
        }
        if let Some(code) = self.exit_code {
            write!(f, " exit={code}")?;
        }
        if let Some(sig) = self.signal {
            write!(f, " signal={sig}")?;
        }
        if self.stderr_truncated {
            write!(f, " stderr_truncated=true")?;
        }
        Ok(())
    }
}

/// Strip fragments (bootstrap tokens) before any error or log path.
pub fn url_for_log(url: &Url) -> String {
    let mut safe = url.clone();
    safe.set_fragment(None);
    safe.to_string()
}

/// Strip fragments from a candidate navigation string without panicking.
pub fn navigation_target_for_log(candidate: &str) -> String {
    match Url::parse(candidate) {
        Ok(url) => url_for_log(&url),
        Err(_) => {
            if let Some(idx) = candidate.find('#') {
                candidate[..idx].to_string()
            } else {
                candidate.to_string()
            }
        }
    }
}

/// Map free-form historical ready-wait strings into a failure kind (no secrets).
pub fn ready_failure_kind_from_message(message: &str) -> ReadyFailureKind {
    let lower = message.to_ascii_lowercase();
    if lower.contains("cancelled") {
        ReadyFailureKind::Cancelled
    } else if lower.contains("deadline exceeded") || lower.contains("timeout") {
        ReadyFailureKind::ReadyTimeout
    } else if lower.contains("eof") {
        ReadyFailureKind::StdoutEof
    } else if lower.contains("digest") {
        ReadyFailureKind::DigestMismatch
    } else if lower.contains("escaped") || lower.contains("process group") {
        ReadyFailureKind::PgidEscape
    } else if lower.contains("sentinel") || lower.contains("canonical") {
        ReadyFailureKind::SentinelInvalid
    } else if lower.contains("spawn") {
        ReadyFailureKind::SpawnFailed
    } else {
        ReadyFailureKind::Other
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_exit_makes_sidecar_exit_primary_and_eof_detail() {
        let failure = DesktopFailure::classify(Some(64), None, ReadyFailureKind::StdoutEof, true);
        assert_eq!(failure.code, DesktopErrorCode::SidecarExit);
        assert_eq!(failure.detail, Some(ErrorDetail::StdoutEof));
        assert_eq!(failure.exit_code, Some(64));
        assert!(failure.stderr_truncated);
        let text = failure.to_string();
        assert!(text.contains("sidecar_exit"));
        assert!(text.contains("exit=64"));
        assert!(text.contains("stderr_truncated=true"));
        assert!(!text.contains("token"));
    }

    #[test]
    fn child_signal_outranks_exit_and_eof() {
        let failure =
            DesktopFailure::classify(Some(1), Some(9), ReadyFailureKind::StdoutEof, false);
        assert_eq!(failure.code, DesktopErrorCode::SidecarSignal);
        assert_eq!(failure.signal, Some(9));
        assert_eq!(failure.detail, Some(ErrorDetail::StdoutEof));
    }

    #[test]
    fn without_exit_stdout_eof_is_primary() {
        let failure = DesktopFailure::classify(None, None, ReadyFailureKind::StdoutEof, false);
        assert_eq!(failure.code, DesktopErrorCode::StdoutEof);
        assert!(failure.detail.is_none());
    }

    #[test]
    fn url_for_log_strips_bootstrap_fragment() {
        let url = Url::parse("http://127.0.0.1:43127/#bootstrap=deadbeef").expect("url");
        let safe = url_for_log(&url);
        assert_eq!(safe, "http://127.0.0.1:43127/");
        assert!(!safe.contains("bootstrap"));
        assert!(!safe.contains("deadbeef"));
    }

    #[test]
    fn display_never_embeds_path_like_or_token_payloads() {
        let failure = DesktopFailure::classify(Some(1), None, ReadyFailureKind::SpawnFailed, false);
        let text = failure.to_string();
        assert!(!text.contains('/'));
        assert!(!text.contains("HOME"));
        assert!(!text.contains("bootstrap"));
    }
}
