mod error;
mod shell;

pub use error::{
    DesktopErrorCode, DesktopFailure, ErrorDetail, ReadyFailureKind, navigation_target_for_log,
    ready_failure_kind_from_message, url_for_log,
};
pub use shell::{
    ReadyPublicationError, RecoveryAction, RecoveryState, SetupBoundaryReport, SetupOutcome,
    ShellController, ShellPhase, finalize_setup_boundary, is_recovery_navigation,
    publish_ready_child, recovery_action_for_url, recovery_url_for_state,
};

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::time::{Duration, Instant};
use url::Url;

/// Fixed upper bound for redacted stderr classification buffer (bytes).
/// The drain thread always continues reading so the pipe cannot block.
const STDERR_CAPTURE_CAP: usize = 8 * 1024;

/// Keep AppKit from presenting a crash-state restoration modal before Tauri's
/// setup callback can start the sidecar. The override lives only in this
/// process's volatile argument domain and preserves any existing launch
/// arguments; it never writes the user's persistent defaults.
#[cfg(target_os = "macos")]
pub fn configure_process_local_appkit_state_restoration() {
    use objc2_foundation::{NSMutableDictionary, NSNumber, NSUserDefaults, ns_string};

    let defaults = NSUserDefaults::standardUserDefaults();
    let argument_domain = ns_string!("NSArgumentDomain");
    let existing = defaults.volatileDomainForName(argument_domain);
    let merged = NSMutableDictionary::dictionaryWithDictionary(&existing);
    let enabled = NSNumber::numberWithBool(true);
    merged.insert(ns_string!("ApplePersistenceIgnoreState"), &enabled);
    // SAFETY: `merged` was obtained from NSUserDefaults as an
    // NSDictionary<NSString, AnyObject> and only receives a valid NSNumber.
    unsafe { defaults.setVolatileDomain_forName(&merged, argument_domain) };
}

#[cfg(not(target_os = "macos"))]
pub fn configure_process_local_appkit_state_restoration() {}

pub const READY_SCHEMA: &str = "JSAgentHostReadyV1";
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
pub const RESTART_WINDOW: Duration = Duration::from_secs(300);
pub const READY_DEADLINE: Duration = Duration::from_secs(90);
const FORCE_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug)]
pub struct SidecarTimeouts {
    ready: Duration,
    graceful: Duration,
    forced: Duration,
}

impl SidecarTimeouts {
    pub const fn new(ready: Duration, graceful: Duration, forced: Duration) -> Self {
        Self {
            ready,
            graceful,
            forced,
        }
    }

    const fn production() -> Self {
        Self::new(READY_DEADLINE, SHUTDOWN_TIMEOUT, FORCE_SHUTDOWN_TIMEOUT)
    }

    const fn shutdown_only(graceful: Duration, forced: Duration) -> Self {
        Self::new(Duration::ZERO, graceful, forced)
    }
}

#[derive(Debug)]
pub struct SupervisorError {
    message: String,
    fatal: bool,
    failure: Option<DesktopFailure>,
}

impl SupervisorError {
    fn restartable(message: impl Into<String>) -> Self {
        let message = message.into();
        let kind = ready_failure_kind_from_message(&message);
        let failure = DesktopFailure::classify(None, None, kind, false);
        Self {
            message: failure.to_string(),
            fatal: false,
            failure: Some(failure),
        }
    }

    fn fatal(message: impl Into<String>) -> Self {
        let message = message.into();
        let kind = ready_failure_kind_from_message(&message);
        let failure = DesktopFailure::classify(None, None, kind, false);
        Self {
            message: failure.to_string(),
            fatal: true,
            failure: Some(failure),
        }
    }

    fn from_failure(failure: DesktopFailure, fatal: bool) -> Self {
        Self {
            message: failure.to_string(),
            fatal,
            failure: Some(failure),
        }
    }

    pub fn is_fatal(&self) -> bool {
        self.fatal
    }

    pub fn failure(&self) -> Option<&DesktopFailure> {
        self.failure.as_ref()
    }

    fn with_note(self, _note: impl Into<String>) -> Self {
        // Notes may contain OS paths; never merge them into Display.
        self
    }
}

impl std::fmt::Display for SupervisorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SupervisorError {}

impl From<String> for SupervisorError {
    fn from(message: String) -> Self {
        Self::restartable(message)
    }
}

#[derive(Debug, Default)]
struct StderrSummary {
    truncated: bool,
}

fn spawn_stderr_drain(stderr: std::process::ChildStderr) -> std::thread::JoinHandle<StderrSummary> {
    std::thread::spawn(move || {
        let mut reader = stderr;
        let mut buf = [0_u8; 512];
        let mut kept = 0_usize;
        let mut truncated = false;
        // Rolling redacted buffer used only for in-process classification.
        // Never returned, logged, hashed, or stored on DesktopFailure.
        let mut redacted = vec![0_u8; STDERR_CAPTURE_CAP];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    for &byte in &buf[..n] {
                        // Drop path separators and high-entropy runs from the
                        // classification window; keep draining regardless.
                        let sanitized = if byte == b'/' || byte == b'\\' {
                            b'_'
                        } else {
                            byte
                        };
                        if kept < STDERR_CAPTURE_CAP {
                            redacted[kept] = sanitized;
                            kept += 1;
                        } else {
                            truncated = true;
                        }
                    }
                }
                Err(_) => break,
            }
        }
        redacted.fill(0);
        StderrSummary { truncated }
    })
}

pub fn compiled_source_digest() -> Result<&'static str, String> {
    let digest = option_env!("JS_AGENT_DESKTOP_SOURCE_DIGEST")
        .ok_or_else(|| "JS_AGENT_DESKTOP_SOURCE_DIGEST was not set at build time".to_string())?;
    validate_lower_hex_256(digest, "compiled source digest")?;
    Ok(digest)
}

fn validate_lower_hex_256(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!("{label} must be 256-bit lower-hex"));
    }
    Ok(())
}

pub fn generate_bootstrap_token() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| format!("OS entropy unavailable: {error}"))?;
    let mut token = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut token, "{byte:02x}").map_err(|error| error.to_string())?;
    }
    Ok(token)
}

pub struct SidecarLaunchSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub stdin_payload: Vec<u8>,
}

impl SidecarLaunchSpec {
    pub fn new(program: PathBuf, source_digest: &str, token: String) -> Result<Self, String> {
        validate_lower_hex_256(source_digest, "source digest")?;
        validate_lower_hex_256(&token, "bootstrap token")?;
        Ok(Self {
            program,
            args: vec!["--source-digest".to_string(), source_digest.to_string()],
            env: Vec::new(),
            stdin_payload: format!("{token}\n").into_bytes(),
        })
    }

    /// Set the supervisor PID env var so the sidecar can watchdog its parent.
    pub fn with_supervisor_pid(mut self) -> Self {
        let supervisor_pid = std::process::id().to_string();
        self.env
            .push(("JS_AGENT_SUPERVISOR_PID".to_string(), supervisor_pid));
        self
    }

    pub fn spawn(self) -> Result<ManagedSidecar, SupervisorError> {
        self.spawn_with_timeouts(SidecarTimeouts::production())
    }

    pub fn spawn_cancelable(
        self,
        cancelled: &AtomicBool,
    ) -> Result<Option<ManagedSidecar>, SupervisorError> {
        self.spawn_with_timeouts_and_resolver_cancel(
            SidecarTimeouts::production(),
            &OsReadyPgidResolver,
            Some(cancelled),
        )
    }

    pub fn spawn_with_timeouts(
        self,
        timeouts: SidecarTimeouts,
    ) -> Result<ManagedSidecar, SupervisorError> {
        self.spawn_with_timeouts_and_resolver(timeouts, &OsReadyPgidResolver)
    }

    fn spawn_with_timeouts_and_resolver<R: ReadyPgidResolver>(
        self,
        timeouts: SidecarTimeouts,
        ready_pgid_resolver: &R,
    ) -> Result<ManagedSidecar, SupervisorError> {
        self.spawn_with_timeouts_and_resolver_cancel(timeouts, ready_pgid_resolver, None)?
            .ok_or_else(|| SupervisorError::restartable("sidecar startup was cancelled"))
    }

    fn spawn_with_timeouts_and_resolver_cancel<R: ReadyPgidResolver>(
        mut self,
        timeouts: SidecarTimeouts,
        ready_pgid_resolver: &R,
        cancelled: Option<&AtomicBool>,
    ) -> Result<Option<ManagedSidecar>, SupervisorError> {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        for (key, value) in &self.env {
            command.env(key, value);
        }
        let child = command.spawn().map_err(|_error| {
            SupervisorError::from_failure(
                DesktopFailure::classify(None, None, ReadyFailureKind::SpawnFailed, false),
                false,
            )
        })?;
        let mut process = ProcessGroupGuard::new(child).map_err(|error| {
            SupervisorError::from_failure(
                DesktopFailure::classify(None, None, ReadyFailureKind::SpawnFailed, false),
                true,
            )
            .with_note(error)
        })?;
        let stderr_handle = process.child.stderr.take().map(spawn_stderr_drain);
        let write_result = process
            .child
            .stdin
            .take()
            .ok_or_else(|| "sidecar stdin pipe unavailable".to_string())
            .and_then(|mut stdin| {
                stdin
                    .write_all(&self.stdin_payload)
                    .map_err(|error| format!("failed to write sidecar bootstrap: {error}"))
            });
        self.stdin_payload.fill(0);
        if let Err(error) = write_result {
            return Err(process.fail_before_ready_kind(
                ReadyFailureKind::SpawnFailed,
                timeouts,
                stderr_handle,
                error,
            ));
        }

        let Some(stdout) = process.child.stdout.take() else {
            return Err(process.fail_before_ready_kind(
                ReadyFailureKind::SpawnFailed,
                timeouts,
                stderr_handle,
                "sidecar stdout pipe unavailable",
            ));
        };
        let line = match read_sentinel_with_deadline(stdout, timeouts.ready, cancelled) {
            Ok(Some(line)) => line,
            Ok(None) => {
                // Shut down before joining the stderr drain so the pipe reaches
                // EOF promptly; never block on a live child's open stderr.
                let shutdown = process.shutdown_with(timeouts);
                let _ = take_stderr_summary(stderr_handle);
                shutdown.map_err(|error| {
                    SupervisorError::from_failure(DesktopFailure::cancelled(), true)
                        .with_note(error)
                })?;
                return Ok(None);
            }
            Err(error) => {
                let kind = ready_failure_kind_from_message(&error);
                return Err(process.fail_before_ready_kind(kind, timeouts, stderr_handle, error));
            }
        };
        let Some(expected_digest) = self.args.get(1) else {
            return Err(process.fail_before_ready_kind(
                ReadyFailureKind::DigestMismatch,
                timeouts,
                stderr_handle,
                "source digest argument missing",
            ));
        };
        let ready = match parse_ready_sentinel(line.trim_end_matches('\n'), expected_digest) {
            Ok(ready) => ready,
            Err(error) => {
                let kind = ready_failure_kind_from_message(&error);
                return Err(process.fail_before_ready_kind(kind, timeouts, stderr_handle, error));
            }
        };
        let ready_group = match ready_pgid_resolver.resolve(ready.pid) {
            Ok(group) => group,
            Err(error) => {
                return Err(process.fail_before_ready_kind(
                    ReadyFailureKind::PgidEscape,
                    timeouts,
                    stderr_handle,
                    error,
                ));
            }
        };
        if !ready_pid_matches_group(process.pgid, ready.pid, ready_group) {
            return Err(process.fail_before_ready_kind(
                ReadyFailureKind::PgidEscape,
                timeouts,
                stderr_handle,
                "sidecar sentinel PID escaped the externalBin process group",
            ));
        }
        // Ready path: detach the drain thread (do not join). Joining would
        // block until the live sidecar closes stderr. Dropping JoinHandle
        // leaves the thread running so the pipe stays drained.
        drop(stderr_handle);
        Ok(Some(ManagedSidecar {
            process,
            ready,
            timeouts,
        }))
    }
}

fn take_stderr_summary(handle: Option<std::thread::JoinHandle<StderrSummary>>) -> StderrSummary {
    let Some(handle) = handle else {
        return StderrSummary::default();
    };
    // Never block the supervisor path on a live child's open stderr pipe.
    // If the drain cannot finish quickly after shutdown, return a safe
    // truncated summary and let the drain thread exit when the pipe closes.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(handle.join().unwrap_or_default());
    });
    rx.recv_timeout(Duration::from_millis(400))
        .unwrap_or(StderrSummary { truncated: true })
}

trait ReadyPgidResolver {
    fn resolve(&self, pid: u32) -> Result<u32, String>;
}

struct OsReadyPgidResolver;

impl ReadyPgidResolver for OsReadyPgidResolver {
    fn resolve(&self, pid: u32) -> Result<u32, String> {
        process_group_id(pid)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostReady {
    pub pid: u32,
    pub port: u16,
    pub schema: String,
    pub source_digest: String,
}

pub fn parse_ready_sentinel(line: &str, expected_digest: &str) -> Result<HostReady, String> {
    if line.len() > 512 || line.contains('\n') || line.contains('\r') {
        return Err("sidecar sentinel is not a single bounded line".to_string());
    }
    let ready: HostReady =
        serde_json::from_str(line).map_err(|error| format!("invalid sidecar sentinel: {error}"))?;
    let canonical = serde_json::to_string(&ready)
        .map_err(|error| format!("failed to canonicalize sidecar sentinel: {error}"))?;
    if canonical != line {
        return Err("sidecar sentinel is not canonical JSON".to_string());
    }
    if ready.schema != READY_SCHEMA {
        return Err("sidecar sentinel schema mismatch".to_string());
    }
    if ready.pid == 0 || ready.port == 0 || ready.port == 8765 {
        return Err("sidecar sentinel PID or port is invalid".to_string());
    }
    validate_lower_hex_256(&ready.source_digest, "sentinel source digest")?;
    if !constant_time_equal(ready.source_digest.as_bytes(), expected_digest.as_bytes()) {
        return Err("sidecar source digest mismatch".to_string());
    }
    Ok(ready)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}

#[derive(Debug)]
pub struct ManagedSidecar {
    process: ProcessGroupGuard,
    pub ready: HostReady,
    timeouts: SidecarTimeouts,
}

#[derive(Debug)]
pub enum SidecarPoll {
    Running,
    ExitedAndGroupCleaned(ExitStatus),
}

impl ManagedSidecar {
    pub fn pid(&self) -> u32 {
        self.process.child.id()
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, String> {
        self.process.try_wait()
    }

    pub fn poll(&mut self) -> Result<SidecarPoll, SupervisorError> {
        match self.process.try_wait() {
            Ok(Some(status)) => {
                self.process.shutdown_with(self.timeouts).map_err(|error| {
                    SupervisorError::fatal(format!(
                        "sidecar exited but its process group was not cleaned: {error}"
                    ))
                })?;
                Ok(SidecarPoll::ExitedAndGroupCleaned(status))
            }
            Ok(None) => Ok(SidecarPoll::Running),
            Err(error) => {
                let cleanup = self.process.shutdown_with(self.timeouts);
                Err(SupervisorError::fatal(match cleanup {
                    Ok(()) => error,
                    Err(cleanup_error) => format!("{error}; {cleanup_error}"),
                }))
            }
        }
    }

    pub fn shutdown(&mut self, timeout: Duration) -> Result<(), String> {
        self.process.shutdown_with(SidecarTimeouts::shutdown_only(
            timeout,
            self.timeouts.forced,
        ))
    }
}

#[derive(Debug)]
struct ProcessGroupGuard {
    child: Child,
    pgid: u32,
    target: i32,
}

impl ProcessGroupGuard {
    fn new(child: Child) -> Result<Self, String> {
        let pgid = child.id();
        let target = process_group_target(pgid)?;
        Ok(Self {
            child,
            pgid,
            target,
        })
    }

    fn try_wait(&mut self) -> Result<Option<ExitStatus>, String> {
        self.child
            .try_wait()
            .map_err(|error| format!("failed to poll sidecar: {error}"))
    }

    fn fail_before_ready_kind(
        &mut self,
        kind: ReadyFailureKind,
        timeouts: SidecarTimeouts,
        stderr_handle: Option<std::thread::JoinHandle<StderrSummary>>,
        _internal_message: impl Into<String>,
    ) -> SupervisorError {
        self.fail_before_ready_with_probe(kind, timeouts, stderr_handle, &OsGroupPresenceProbe)
    }

    fn fail_before_ready_with_probe<P: GroupPresenceProbe>(
        &mut self,
        kind: ReadyFailureKind,
        timeouts: SidecarTimeouts,
        stderr_handle: Option<std::thread::JoinHandle<StderrSummary>>,
        presence_probe: &P,
    ) -> SupervisorError {
        // Capture a best-effort exit snapshot, then force group cleanup so the
        // stderr drain can observe EOF. Join the drain only after shutdown.
        let (exit_code, signal) = self.reap_exit_status_bits();
        let cleanup = self.shutdown_with_probe(timeouts, presence_probe);
        let (exit_code, signal) = match self.reap_exit_status_bits() {
            (None, None) => (exit_code, signal),
            bits => bits,
        };
        let stderr = take_stderr_summary(stderr_handle);
        let failure = DesktopFailure::classify(exit_code, signal, kind, stderr.truncated);
        match cleanup {
            Ok(()) => SupervisorError::from_failure(failure, false),
            Err(_cleanup_error) => SupervisorError::from_failure(failure, true),
        }
    }

    fn reap_exit_status_bits(&mut self) -> (Option<i32>, Option<i32>) {
        match self.try_wait() {
            Ok(Some(status)) => exit_status_bits(status),
            _ => (None, None),
        }
    }

    fn shutdown_with(&mut self, timeouts: SidecarTimeouts) -> Result<(), String> {
        self.shutdown_with_probe(timeouts, &OsGroupPresenceProbe)
    }

    fn shutdown_with_probe<P: GroupPresenceProbe>(
        &mut self,
        timeouts: SidecarTimeouts,
        presence_probe: &P,
    ) -> Result<(), String> {
        let _ = self.try_wait()?;
        let graceful_deadline = Instant::now() + timeouts.graceful;
        if matches!(
            self.wait_for_initial_presence(timeouts.graceful, presence_probe)?,
            GroupPresence::Absent
        ) {
            return self.prove_leader_reaped();
        }

        signal_process_group(self.target, 15)?;
        let graceful_remaining = graceful_deadline.saturating_duration_since(Instant::now());
        let graceful_probe_error =
            match self.wait_for_group_absence(graceful_remaining, presence_probe) {
                Ok(true) => return self.prove_leader_reaped(),
                Ok(false) => None,
                Err(error) => Some(error),
            };

        if let Err(error) = signal_process_group(self.target, 9) {
            return Err(match graceful_probe_error {
                Some(probe_error) => format!(
                    "failed to force-kill sidecar group: {error}; graceful absence probe failed: {probe_error}"
                ),
                None => format!("failed to force-kill sidecar group: {error}"),
            });
        }
        match self.wait_for_group_absence(timeouts.forced, presence_probe) {
            Ok(true) => self.prove_leader_reaped(),
            Ok(false) => {
                Err("sidecar process group survived the bounded force-kill proof".to_string())
            }
            Err(error) => Err(format!(
                "sidecar process-group absence remained uncertain after force-kill: {error}"
            )),
        }
    }

    fn wait_for_initial_presence<P: GroupPresenceProbe>(
        &mut self,
        timeout: Duration,
        presence_probe: &P,
    ) -> Result<GroupPresence, String> {
        let deadline = Instant::now() + timeout;
        loop {
            let _ = self.try_wait()?;
            let error = match presence_probe.query(self.target) {
                Ok(presence) => return Ok(presence),
                Err(error) => error,
            };
            if timeout.is_zero() || Instant::now() >= deadline {
                return Err(format!(
                    "initial sidecar process-group presence remained uncertain: {error}"
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait_for_group_absence<P: GroupPresenceProbe>(
        &mut self,
        timeout: Duration,
        presence_probe: &P,
    ) -> Result<bool, String> {
        if timeout.is_zero() {
            return Ok(false);
        }
        let deadline = Instant::now() + timeout;
        loop {
            let _ = self.try_wait()?;
            let probe_error = match presence_probe.query(self.target) {
                Ok(GroupPresence::Absent) => return Ok(true),
                Ok(GroupPresence::Present) => None,
                Err(error) => Some(error),
            };
            if Instant::now() >= deadline {
                return match probe_error {
                    Some(error) => Err(error),
                    None => Ok(false),
                };
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn prove_leader_reaped(&mut self) -> Result<(), String> {
        match self.try_wait()? {
            Some(_) => Ok(()),
            None => Err("sidecar leader survived after its saved process group disappeared".into()),
        }
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        let _ = self.shutdown_with(SidecarTimeouts::production());
        match self.child.try_wait() {
            Ok(Some(_)) => {
                let _ = self.child.wait();
            }
            _ => {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }
}

#[derive(Clone, Copy)]
enum GroupPresence {
    Present,
    Absent,
}

trait GroupPresenceProbe {
    fn query(&self, target: i32) -> Result<GroupPresence, String>;
}

struct OsGroupPresenceProbe;

impl GroupPresenceProbe for OsGroupPresenceProbe {
    fn query(&self, target: i32) -> Result<GroupPresence, String> {
        process_group_presence(target)
    }
}

#[cfg(unix)]
fn signal_process_group(target: i32, signal: i32) -> Result<(), String> {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    let result = unsafe { kill(target, signal) };
    let error = std::io::Error::last_os_error();
    if result == 0 || error.raw_os_error() == Some(3) {
        Ok(())
    } else {
        Err(format!("failed to signal sidecar: {error}"))
    }
}

#[cfg(unix)]
fn process_group_presence(target: i32) -> Result<GroupPresence, String> {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    let result = unsafe { kill(target, 0) };
    if result == 0 {
        return Ok(GroupPresence::Present);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(3) {
        Ok(GroupPresence::Absent)
    } else {
        Err(format!(
            "failed to prove sidecar process-group absence: {error}"
        ))
    }
}

#[cfg(not(unix))]
fn signal_process_group(_target: i32, _signal: i32) -> Result<(), String> {
    Err("graceful sidecar signals are unsupported on this platform".to_string())
}

#[cfg(not(unix))]
fn process_group_presence(_target: i32) -> Result<GroupPresence, String> {
    Err("process-group absence cannot be proven on this platform".to_string())
}

fn read_sentinel_with_deadline(
    stdout: std::process::ChildStdout,
    deadline: Duration,
    cancelled: Option<&AtomicBool>,
) -> Result<Option<String>, String> {
    use std::io::Read;
    use std::sync::mpsc;

    let (tx, rx) = mpsc::channel::<Result<String, String>>();
    let mut reader = BufReader::new(stdout);

    std::thread::spawn(move || {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match reader.read(&mut byte) {
                Ok(0) => {
                    let _ = tx.send(Err("sidecar stdout EOF before sentinel".to_string()));
                    return;
                }
                Ok(_) => {
                    line.push(byte[0]);
                    if byte[0] == b'\n' || line.len() > 512 {
                        let decoded = String::from_utf8(line)
                            .map_err(|error| format!("failed to read sidecar sentinel: {error}"));
                        let _ = tx.send(decoded);
                        return;
                    }
                }
                Err(error) => {
                    let _ = tx.send(Err(format!("failed to read sidecar sentinel: {error}")));
                    return;
                }
            }
        }
    });

    let started = Instant::now();
    loop {
        if cancelled.is_some_and(|flag| flag.load(AtomicOrdering::Acquire)) {
            return Ok(None);
        }
        let remaining = deadline.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err("sidecar ready sentinel deadline exceeded".to_string());
        }
        match rx.recv_timeout(remaining.min(Duration::from_millis(50))) {
            Ok(result) => return result.map(Some),
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err("sidecar sentinel reader disconnected".to_string());
            }
        }
    }
}

pub fn process_group_target(pid: u32) -> Result<i32, String> {
    let pid = i32::try_from(pid).map_err(|_| "sidecar PID is out of range".to_string())?;
    if pid <= 0 {
        return Err("sidecar PID is invalid".to_string());
    }
    Ok(-pid)
}

pub fn ready_pid_matches_group(launch_pid: u32, ready_pid: u32, ready_pgid: u32) -> bool {
    launch_pid > 0 && ready_pid == launch_pid && ready_pgid == launch_pid
}

#[cfg(unix)]
fn process_group_id(pid: u32) -> Result<u32, String> {
    unsafe extern "C" {
        fn getpgid(pid: i32) -> i32;
    }
    let pid = i32::try_from(pid).map_err(|_| "sidecar runtime PID is out of range".to_string())?;
    let pgid = unsafe { getpgid(pid) };
    if pgid <= 0 {
        Err(format!(
            "failed to resolve sidecar runtime process group: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        Ok(pgid as u32)
    }
}

#[cfg(not(unix))]
fn process_group_id(pid: u32) -> Result<u32, String> {
    Ok(pid)
}

pub struct RestartBudget {
    window: Duration,
    restarts: VecDeque<Instant>,
}

impl RestartBudget {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            restarts: VecDeque::new(),
        }
    }

    pub fn record_restart(&mut self, now: Instant) -> Option<Duration> {
        while self
            .restarts
            .front()
            .is_some_and(|oldest| now.saturating_duration_since(*oldest) >= self.window)
        {
            self.restarts.pop_front();
        }
        if self.restarts.len() >= 3 {
            return None;
        }
        let delay = Duration::from_secs(1_u64 << self.restarts.len());
        self.restarts.push_back(now);
        Some(delay)
    }
}

pub enum MonitorEvent {
    Running,
    ExitedAndGroupCleaned,
    Missing,
    Fatal(SupervisorError),
}

#[derive(Debug, PartialEq, Eq)]
pub enum MonitorDecision {
    Continue,
    QuarantineThenRestartAfter(Duration),
    QuarantineThenFatal,
}

pub fn monitor_decision(
    event: MonitorEvent,
    restart_budget: &mut RestartBudget,
    now: Instant,
) -> MonitorDecision {
    match event {
        MonitorEvent::Running => MonitorDecision::Continue,
        MonitorEvent::ExitedAndGroupCleaned | MonitorEvent::Missing => {
            restart_budget.record_restart(now).map_or(
                MonitorDecision::QuarantineThenFatal,
                MonitorDecision::QuarantineThenRestartAfter,
            )
        }
        MonitorEvent::Fatal(_) => MonitorDecision::QuarantineThenFatal,
    }
}

pub struct NavigationPolicy {
    /// When set, exact loopback host+port for the active generation is allowed.
    loopback_port: Option<u16>,
    /// Packaged recovery page is always allowed so the shell can fail closed.
    allow_recovery: bool,
}

impl NavigationPolicy {
    pub fn new(port: u16) -> Result<Self, String> {
        if port == 0 || port == 8765 {
            return Err("invalid Host port".to_string());
        }
        Ok(Self {
            loopback_port: Some(port),
            allow_recovery: true,
        })
    }

    pub fn recovery_only() -> Self {
        Self {
            loopback_port: None,
            allow_recovery: true,
        }
    }

    pub fn allows(&self, candidate: &str) -> bool {
        let Ok(url) = Url::parse(candidate) else {
            return false;
        };
        self.allows_url(&url)
    }

    pub fn allows_url(&self, url: &Url) -> bool {
        if self.allow_recovery && shell::is_recovery_url(url) {
            return true;
        }
        let Some(port) = self.loopback_port else {
            return false;
        };
        url.scheme() == "http"
            && url.host_str() == Some("127.0.0.1")
            && url.port() == Some(port)
            && url.username().is_empty()
            && url.password().is_none()
    }
}

fn exit_status_bits(status: ExitStatus) -> (Option<i32>, Option<i32>) {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return (None, Some(signal));
        }
    }
    (status.code(), None)
}

pub fn bootstrap_url(port: u16, token: &str) -> Result<Url, String> {
    NavigationPolicy::new(port)?;
    validate_lower_hex_256(token, "bootstrap token")?;
    Url::parse(&format!("http://127.0.0.1:{port}/#bootstrap={token}"))
        .map_err(|error| format!("invalid bootstrap URL: {error}"))
}

pub fn keep_awake_command(pid: u32) -> Result<(PathBuf, Vec<String>), String> {
    if pid == 0 {
        return Err("application PID is invalid".to_string());
    }
    Ok((
        PathBuf::from("/usr/bin/caffeinate"),
        vec!["-d".to_string(), "-w".to_string(), pid.to_string()],
    ))
}

pub fn launch_agent_contents(executable: &std::path::Path) -> Result<String, String> {
    if !executable.is_absolute() {
        return Err("autostart executable must be absolute".to_string());
    }
    let raw = executable
        .to_str()
        .ok_or_else(|| "autostart executable is not UTF-8".to_string())?;
    if raw.contains(['\0', '\n', '\r']) {
        return Err("autostart executable contains unsafe characters".to_string());
    }
    let escaped = raw
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;");
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \
\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
<plist version=\"1.0\">\n<dict>\n\
  <key>Label</key>\n  <string>com.titan.js-agent</string>\n\
  <key>ProgramArguments</key>\n  <array>\n    <string>{escaped}</string>\n  </array>\n\
  <key>RunAtLoad</key>\n  <true/>\n\
  <key>KeepAlive</key>\n  <false/>\n\
</dict>\n</plist>\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use std::fs;
    use std::os::unix::process::CommandExt as _;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const DIGEST: &str = "abababababababababababababababababababababababababababababababab";

    #[cfg(target_os = "macos")]
    static USER_DEFAULTS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(target_os = "macos")]
    #[test]
    fn appkit_state_restoration_override_is_volatile_and_preserves_argument_domain() {
        use objc2_foundation::{NSMutableDictionary, NSNumber, NSUserDefaults, ns_string};
        use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

        let _guard = USER_DEFAULTS_TEST_LOCK
            .lock()
            .expect("NSUserDefaults test lock");
        let defaults = NSUserDefaults::standardUserDefaults();
        let argument_domain = ns_string!("NSArgumentDomain");
        let original = defaults.volatileDomainForName(argument_domain);
        let seeded = NSMutableDictionary::dictionaryWithDictionary(&original);
        let disabled = NSNumber::numberWithBool(false);
        let sentinel = NSNumber::numberWithBool(true);
        seeded.insert(ns_string!("ApplePersistenceIgnoreState"), &disabled);
        seeded.insert(ns_string!("JSAgentArgumentDomainSentinel"), &sentinel);
        // SAFETY: both inserted values are property-list-compatible NSNumbers.
        unsafe { defaults.setVolatileDomain_forName(&seeded, argument_domain) };

        let outcome = catch_unwind(AssertUnwindSafe(|| {
            configure_process_local_appkit_state_restoration();
            assert!(defaults.boolForKey(ns_string!("ApplePersistenceIgnoreState")));
            assert!(defaults.boolForKey(ns_string!("JSAgentArgumentDomainSentinel")));
        }));

        // Restore the exact process-local domain observed before the test.
        // SAFETY: `original` came directly from this NSUserDefaults instance.
        unsafe { defaults.setVolatileDomain_forName(&original, argument_domain) };
        if let Err(payload) = outcome {
            resume_unwind(payload);
        }
    }

    #[test]
    fn bootstrap_token_is_256_bit_lower_hex_and_unique() {
        let first = generate_bootstrap_token().expect("OS entropy");
        let second = generate_bootstrap_token().expect("OS entropy");
        assert_eq!(first.len(), 64);
        assert!(
            first
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
        assert_ne!(first, second);
    }

    #[test]
    fn sidecar_spec_places_token_only_on_stdin() {
        let token = "23".repeat(32);
        let spec =
            SidecarLaunchSpec::new(PathBuf::from("/tmp/js-agent-host"), DIGEST, token.clone())
                .expect("valid launch spec");
        assert!(spec.args.iter().all(|arg| !arg.contains(&token)));
        assert!(
            spec.env
                .iter()
                .all(|(key, value)| !key.contains(&token) && !value.contains(&token))
        );
        assert_eq!(spec.stdin_payload, format!("{token}\n").into_bytes());
    }

    #[test]
    fn cancelled_pre_ready_spawn_cleans_process_group_promptly() {
        let cancelled = std::sync::Arc::new(AtomicBool::new(false));
        let setter = std::sync::Arc::clone(&cancelled);
        let cancel_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            setter.store(true, AtomicOrdering::Release);
        });
        let spec = SidecarLaunchSpec {
            program: PathBuf::from("/bin/sh"),
            args: vec!["-c".to_string(), "exec /bin/sleep 60".to_string()],
            env: Vec::new(),
            stdin_payload: Vec::new(),
        };
        let started = Instant::now();
        let result = spec
            .spawn_cancelable(&cancelled)
            .expect("cancelled startup cleanup");
        cancel_thread.join().expect("cancel setter");
        assert!(result.is_none());
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn ready_parser_accepts_only_canonical_loopback_sentinel() {
        let line = format!(
            "{{\"pid\":42,\"port\":43127,\"schema\":\"JSAgentHostReadyV1\",\"source_digest\":\"{DIGEST}\"}}"
        );
        let ready = parse_ready_sentinel(&line, DIGEST).expect("valid sentinel");
        assert_eq!(ready.pid, 42);
        assert_eq!(ready.port, 43127);

        for invalid in [
            format!(
                "{{\"pid\":42,\"port\":8765,\"schema\":\"JSAgentHostReadyV1\",\"source_digest\":\"{DIGEST}\"}}"
            ),
            format!(
                "{{\"pid\":42,\"port\":43127,\"schema\":\"JSAgentHostReadyV1\",\"source_digest\":\"{DIGEST}\",\"token\":\"secret\"}}"
            ),
            format!(
                "{{\"pid\":42,\"port\":43127,\"schema\":\"wrong\",\"source_digest\":\"{DIGEST}\"}}"
            ),
            format!(
                "{{\"pid\":42,\"port\":43127,\"schema\":\"JSAgentHostReadyV1\",\"source_digest\":\"{}\"}}",
                "cd".repeat(32)
            ),
        ] {
            assert!(
                parse_ready_sentinel(&invalid, DIGEST).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn restart_budget_is_three_in_five_minutes_with_one_two_four_backoff() {
        let start = Instant::now();
        let mut budget = RestartBudget::new(Duration::from_secs(300));
        assert_eq!(budget.record_restart(start), Some(Duration::from_secs(1)));
        assert_eq!(
            budget.record_restart(start + Duration::from_secs(2)),
            Some(Duration::from_secs(2))
        );
        assert_eq!(
            budget.record_restart(start + Duration::from_secs(4)),
            Some(Duration::from_secs(4))
        );
        assert_eq!(budget.record_restart(start + Duration::from_secs(8)), None);
        assert_eq!(
            budget.record_restart(start + Duration::from_secs(305)),
            Some(Duration::from_secs(1))
        );
    }

    #[test]
    fn shutdown_signals_the_sidecar_process_group_not_only_the_leader() {
        assert_eq!(process_group_target(4321).expect("valid PID"), -4321);
        assert!(process_group_target(0).is_err());
    }

    #[test]
    fn onefile_runtime_pid_must_stay_in_the_external_bin_process_group() {
        assert!(ready_pid_matches_group(4200, 4200, 4200));
        assert!(!ready_pid_matches_group(4200, 4201, 4200));
        assert!(!ready_pid_matches_group(4200, 4200, 4201));
        assert!(!ready_pid_matches_group(4200, 9999, 9999));
        assert!(!ready_pid_matches_group(0, 1, 1));
    }

    struct MismatchedReadyPgid;

    impl ReadyPgidResolver for MismatchedReadyPgid {
        fn resolve(&self, pid: u32) -> Result<u32, String> {
            Ok(pid + 1)
        }
    }

    #[test]
    fn injected_ready_pgid_mismatch_rejects_spawn_and_cleans_launch_group() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "js-agent-ready-pgid-mismatch-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("test directory");
        let evidence_path = directory.join("evidence.json");
        let trace_path = directory.join("trace.log");
        let fixture = directory.join("probe.sh");
        let script = format!(
            r#"#!/bin/sh
exec 2>"{trace}"
set -x
/bin/sleep 60 &
member=$!
printf '{{"leader_pid":%s,"member_pid":%s,"pgid":%s}}' "$$" "$member" "$$" > "{evidence}"
printf '{{"pid":%s,"port":43127,"schema":"JSAgentHostReadyV1","source_digest":"{DIGEST}"}}\n' "$$"
wait
"#,
            trace = trace_path.display(),
            evidence = evidence_path.display(),
        );
        fs::write(&fixture, script).expect("write shell fixture");
        let spec = SidecarLaunchSpec {
            program: PathBuf::from("/bin/sh"),
            args: vec![fixture.display().to_string(), DIGEST.to_string()],
            env: Vec::new(),
            stdin_payload: format!("{}\n", "23".repeat(32)).into_bytes(),
        };
        let result = spec.spawn_with_timeouts_and_resolver(
            SidecarTimeouts::new(
                Duration::from_secs(1),
                Duration::from_millis(250),
                Duration::from_secs(1),
            ),
            &MismatchedReadyPgid,
        );
        let deadline = Instant::now() + Duration::from_secs(2);
        while !evidence_path.is_file() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let raw = fs::read_to_string(&evidence_path).unwrap_or_else(|error| {
            let trace = fs::read_to_string(&trace_path).unwrap_or_else(|_| "missing trace".into());
            panic!("process evidence: {error}; launch result: {result:?}; trace: {trace}")
        });
        let value: Value = serde_json::from_str(&raw).expect("valid process evidence");
        let pgid = value["pgid"].as_i64().expect("PGID") as i32;
        let leader = value["leader_pid"].as_u64().expect("leader PID") as u32;
        let member = value["member_pid"].as_u64().expect("member PID") as u32;
        let _ = fs::remove_dir_all(&directory);
        let error = result.expect_err("mismatched ready PGID must be rejected");
        assert!(
            error.to_string().contains("pgid_escape"),
            "expected closed-set pgid_escape code, got {error}"
        );
        assert!(matches!(
            process_group_presence(-pgid).expect("group presence"),
            GroupPresence::Absent
        ));
        assert!(process_group_id(leader).is_err());
        assert!(process_group_id(member).is_err());
    }

    struct FailingPresenceProbe {
        message: &'static str,
        queries: AtomicUsize,
    }

    impl FailingPresenceProbe {
        fn new(message: &'static str) -> Self {
            Self {
                message,
                queries: AtomicUsize::new(0),
            }
        }
    }

    impl GroupPresenceProbe for FailingPresenceProbe {
        fn query(&self, _target: i32) -> Result<GroupPresence, String> {
            self.queries.fetch_add(1, Ordering::Relaxed);
            Err(self.message.to_string())
        }
    }

    #[test]
    fn uncertain_and_eperm_presence_results_are_fatal() {
        for message in [
            "process-group presence is uncertain",
            "Operation not permitted (os error 1)",
        ] {
            let probe = FailingPresenceProbe::new(message);
            let mut command = Command::new("/bin/sleep");
            command.arg("60").process_group(0);
            let child = command.spawn().expect("sleep fixture");
            let mut process = ProcessGroupGuard::new(child).expect("process guard");
            let started = Instant::now();
            let error = process.fail_before_ready_with_probe(
                ReadyFailureKind::Other,
                SidecarTimeouts::new(
                    Duration::ZERO,
                    Duration::from_millis(40),
                    Duration::from_millis(40),
                ),
                None,
                &probe,
            );
            let elapsed = started.elapsed();
            assert!(error.is_fatal(), "probe error was restartable: {error}");
            // Display is closed-set codes only; never embed OS probe strings.
            assert!(
                !error.to_string().contains(message),
                "supervisor error must not leak probe OS text: {error}"
            );
            assert!(
                elapsed >= Duration::from_millis(30),
                "initial uncertainty returned without bounded retry: {elapsed:?}"
            );
            assert!(elapsed < Duration::from_secs(1), "used production timeout");
            assert!(
                probe.queries.load(Ordering::Relaxed) >= 2,
                "initial uncertainty was queried only once"
            );
            assert!(
                matches!(process.try_wait(), Ok(None)),
                "unproven process group was signaled"
            );
        }
    }

    #[test]
    fn monitor_fatal_decision_does_not_restart_or_consume_budget() {
        let now = Instant::now();
        let mut budget = RestartBudget::new(RESTART_WINDOW);
        let decision = monitor_decision(
            MonitorEvent::Fatal(SupervisorError::fatal("cleanup uncertain")),
            &mut budget,
            now,
        );
        assert_eq!(decision, MonitorDecision::QuarantineThenFatal);
        assert_eq!(budget.record_restart(now), Some(Duration::from_secs(1)));
    }

    #[test]
    fn monitor_clean_exit_uses_one_two_four_backoff() {
        let now = Instant::now();
        let mut budget = RestartBudget::new(RESTART_WINDOW);
        assert_eq!(
            monitor_decision(MonitorEvent::ExitedAndGroupCleaned, &mut budget, now),
            MonitorDecision::QuarantineThenRestartAfter(Duration::from_secs(1))
        );
        assert_eq!(
            monitor_decision(
                MonitorEvent::ExitedAndGroupCleaned,
                &mut budget,
                now + Duration::from_secs(2),
            ),
            MonitorDecision::QuarantineThenRestartAfter(Duration::from_secs(2))
        );
        assert_eq!(
            monitor_decision(
                MonitorEvent::ExitedAndGroupCleaned,
                &mut budget,
                now + Duration::from_secs(4),
            ),
            MonitorDecision::QuarantineThenRestartAfter(Duration::from_secs(4))
        );
    }

    #[test]
    fn monitor_clean_exit_requires_webview_quarantine_before_backoff() {
        let now = Instant::now();
        let mut budget = RestartBudget::new(RESTART_WINDOW);

        let decision = monitor_decision(MonitorEvent::ExitedAndGroupCleaned, &mut budget, now);

        assert_eq!(
            decision,
            MonitorDecision::QuarantineThenRestartAfter(Duration::from_secs(1)),
        );
    }

    #[test]
    fn navigation_policy_allows_only_the_exact_recovery_document_and_closed_fragment() {
        let policy = NavigationPolicy::recovery_only();

        for candidate in [
            "tauri://localhost/recovery.html",
            "tauri://localhost/recovery.html#",
            "tauri://localhost/recovery.html#state=starting",
            "tauri://localhost/recovery.html#state=retryable_failure&error=spawn_failed",
            "tauri://localhost/recovery.html#state=retryable_failure&error=ready_timeout",
            "tauri://localhost/recovery.html#state=retryable_failure&error=sentinel_invalid",
            "tauri://localhost/recovery.html#state=retryable_failure&error=digest_mismatch",
            "tauri://localhost/recovery.html#state=fatal_failure&error=pgid_escape",
            "tauri://localhost/recovery.html#state=automatic_recovery&error=sidecar_exit",
            "tauri://localhost/recovery.html#state=fatal_failure&error=sidecar_signal",
            "tauri://localhost/recovery.html#state=retryable_failure&error=cancelled",
            "tauri://localhost/recovery.html#state=fatal_failure&error=tray_failed",
            "tauri://localhost/recovery.html#state=fatal_failure&error=window_failed",
            "tauri://localhost/recovery.html#state=retryable_failure&error=bootstrap_failed",
            "tauri://localhost/recovery.html#state=retryable_failure&error=stdout_eof",
        ] {
            assert!(policy.allows(candidate), "must allow {candidate}");
        }

        for candidate in [
            "recovery.html",
            "/recovery.html",
            "http://tauri.localhost/recovery.html",
            "http://localhost/recovery.html",
            "tauri://127.0.0.1/recovery.html",
            "tauri://localhost/other/recovery.html",
            "tauri://localhost/recovery.html/extra",
            "tauri://user@localhost/recovery.html",
            "tauri://user:password@localhost/recovery.html",
            "tauri://localhost:443/recovery.html",
            "tauri://localhost/recovery.html?error=sidecar_exit",
            "tauri://localhost/recovery.html?x=1#state=retryable_failure&error=sidecar_exit",
            "tauri://localhost/recovery.html#state=retryable_failure&error=unknown",
            "tauri://localhost/recovery.html#state=retryable_failure&error=sidecar_exit&next=host",
            "tauri://localhost/recovery.html#next=host",
            "tauri://localhost/__recovery_action__/retry",
            "tauri://localhost/__recovery_action__/quit",
        ] {
            assert!(!policy.allows(candidate), "must reject {candidate}");
        }
    }

    #[test]
    fn navigation_policy_allows_only_the_bound_loopback_origin() {
        let policy = NavigationPolicy::new(43127).expect("valid policy");
        assert!(policy.allows("http://127.0.0.1:43127/"));
        assert!(policy.allows("http://127.0.0.1:43127/api/status?view=full#section"));
        assert!(
            policy.allows(
                "tauri://localhost/recovery.html#state=retryable_failure&error=sidecar_exit"
            )
        );
        assert!(!policy.allows("http://localhost:43127/"));
        assert!(!policy.allows("http://[::1]:43127/"));
        assert!(!policy.allows("http://127.0.0.1:43128/"));
        assert!(!policy.allows("https://127.0.0.1:43127/"));
        assert!(!policy.allows("http://user@127.0.0.1:43127/"));
        assert!(!policy.allows("http://user:pass@127.0.0.1:43127/"));
        assert!(!policy.allows("https://example.com/"));
        assert!(!policy.allows("data:text/html,hello"));
        assert!(!policy.allows("javascript:alert(1)"));
    }

    #[test]
    fn navigation_policy_tracks_only_the_current_ready_generation_port() {
        fn allows(controller: &ShellController, candidate: &str) -> bool {
            let port = controller.allowed_port();
            if port == 0 {
                return NavigationPolicy::recovery_only().allows(candidate);
            }
            NavigationPolicy::new(port).is_ok_and(|policy| policy.allows(candidate))
        }

        let controller = ShellController::new();
        let first = controller.begin_start().expect("first generation");
        assert!(controller.mark_ready(first, 43127));
        assert!(allows(&controller, "http://127.0.0.1:43127/"));

        let second = controller.begin_start().expect("second generation");
        assert!(!allows(&controller, "http://127.0.0.1:43127/"));
        assert!(!controller.mark_ready(first, 43127));
        assert!(!allows(&controller, "http://127.0.0.1:43127/"));

        assert!(controller.mark_ready(second, 43128));
        assert!(!allows(&controller, "http://127.0.0.1:43127/"));
        assert!(allows(&controller, "http://127.0.0.1:43128/"));
    }

    #[test]
    fn pre_ready_exit_reports_sidecar_exit_code_not_only_eof() {
        let directory = std::env::temp_dir().join(format!(
            "js-agent-pre-ready-exit-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&directory).expect("temp dir");
        let fixture = directory.join("exit64.sh");
        fs::write(
            &fixture,
            "#!/bin/sh\nprintf 'noise-on-stderr\\n' 1>&2\nexit 64\n",
        )
        .expect("fixture");
        let mut payload = format!("{}\n", "ab".repeat(32)).into_bytes();
        let spec = SidecarLaunchSpec {
            program: PathBuf::from("/bin/sh"),
            args: vec![fixture.display().to_string(), DIGEST.to_string()],
            env: Vec::new(),
            stdin_payload: payload.clone(),
        };
        payload.fill(0);
        let error = spec
            .spawn_with_timeouts(SidecarTimeouts::new(
                Duration::from_secs(2),
                Duration::from_millis(200),
                Duration::from_millis(200),
            ))
            .expect_err("exiting child must fail ready wait");
        let _ = fs::remove_dir_all(&directory);
        let text = error.to_string();
        assert!(
            text.contains("sidecar_exit"),
            "primary code must be sidecar_exit when child exits: {text}"
        );
        assert!(
            text.contains("exit=64"),
            "exit code must be surfaced: {text}"
        );
        assert!(
            !text.contains("noise-on-stderr"),
            "raw stderr must not appear: {text}"
        );
        assert!(!text.contains("/bin/sh"), "paths must not appear: {text}");
        let failure = error.failure().expect("structured failure");
        assert_eq!(failure.code, DesktopErrorCode::SidecarExit);
        assert_eq!(failure.exit_code, Some(64));
        assert_eq!(failure.detail, Some(ErrorDetail::StdoutEof));
    }

    #[test]
    fn stderr_flood_before_ready_is_bounded_and_non_blocking() {
        let directory = std::env::temp_dir().join(format!(
            "js-agent-stderr-flood-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        fs::create_dir_all(&directory).expect("temp dir");
        let fixture = directory.join("flood.sh");
        // Flood > 8 KiB on stderr, then exit — drain must not deadlock.
        fs::write(
            &fixture,
            "#!/bin/sh\n\
i=0\n\
while [ \"$i\" -lt 400 ]; do\n\
  printf 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\\n' 1>&2\n\
  i=$((i+1))\n\
done\n\
exit 7\n",
        )
        .expect("fixture");
        let spec = SidecarLaunchSpec {
            program: PathBuf::from("/bin/sh"),
            args: vec![fixture.display().to_string(), DIGEST.to_string()],
            env: Vec::new(),
            stdin_payload: format!("{}\n", "cd".repeat(32)).into_bytes(),
        };
        let started = Instant::now();
        let error = spec
            .spawn_with_timeouts(SidecarTimeouts::new(
                Duration::from_secs(3),
                Duration::from_millis(250),
                Duration::from_millis(250),
            ))
            .expect_err("flooding child must fail ready");
        let elapsed = started.elapsed();
        let _ = fs::remove_dir_all(&directory);
        assert!(
            elapsed < Duration::from_secs(3),
            "stderr flood deadlocked ready wait: {elapsed:?}"
        );
        let failure = error.failure().expect("structured failure");
        assert_eq!(failure.code, DesktopErrorCode::SidecarExit);
        assert_eq!(failure.exit_code, Some(7));
        assert!(
            failure.stderr_truncated,
            "expected stderr_truncated attribute after >8KiB flood"
        );
        assert!(!error.to_string().contains("xxxxxxxx"));
    }

    #[test]
    fn bootstrap_url_uses_fragment_not_query_or_path() {
        let token = "45".repeat(32);
        let url = bootstrap_url(43127, &token).expect("valid URL");
        assert_eq!(
            url.as_str(),
            format!("http://127.0.0.1:43127/#bootstrap={token}")
        );
        assert!(url.query().is_none());
    }

    #[test]
    fn native_keep_awake_and_autostart_are_opt_in_with_fixed_commands() {
        let (program, args) = keep_awake_command(4321).expect("valid PID");
        assert_eq!(program, PathBuf::from("/usr/bin/caffeinate"));
        assert_eq!(args, ["-d", "-w", "4321"]);

        let executable = PathBuf::from("/Applications/JS & Agent.app/Contents/MacOS/js-agent");
        let plist = launch_agent_contents(&executable).expect("valid executable");
        assert!(plist.contains("/Applications/JS &amp; Agent.app/Contents/MacOS/js-agent"));
        assert!(plist.contains("<key>RunAtLoad</key>\n  <true/>"));
        assert!(plist.contains("<key>KeepAlive</key>\n  <false/>"));
        assert!(!plist.contains("bootstrap"));
    }
}
