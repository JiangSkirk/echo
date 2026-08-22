//! Desktop shell phase machine and setup-boundary contracts.
//!
//! Application-layer recoverable failures must never escape Tauri `.setup` as
//! `Err` (that panics inside AppKit `did_finish_launching`). Tests inject
//! failing sidecar / tray / window dependencies — they do not string-search
//! source for `?`.

use crate::error::{DesktopErrorCode, DesktopFailure};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Lifecycle phase of the native shell surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellPhase {
    Starting,
    Ready,
    Failed,
}

/// Operator-facing recovery state encoded in the bundled page fragment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryState {
    Starting,
    AutomaticRecovery,
    RetryableFailure,
    FatalFailure,
}

impl RecoveryState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::AutomaticRecovery => "automatic_recovery",
            Self::RetryableFailure => "retryable_failure",
            Self::FatalFailure => "fatal_failure",
        }
    }
}

/// Closed-set actions emitted only by the bundled recovery page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    Retry,
    Quit,
}

#[derive(Debug)]
struct ShellStatus {
    phase: ShellPhase,
    failure: Option<DesktopFailure>,
    manual_retry_available: bool,
}

/// Result of the Tauri setup boundary for application-layer work.
///
/// Always `Continue` for recoverable app-layer failures so setup returns `Ok`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupOutcome {
    Continue,
}

/// Report produced by folding injected setup dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupBoundaryReport {
    pub outcome: SetupOutcome,
    pub phase: ShellPhase,
    pub failure: Option<DesktopFailure>,
    pub recovery_surface_active: bool,
    pub tray_installed: bool,
}

/// Single-flight, generation-bound shell controller (process-local).
#[derive(Debug)]
pub struct ShellController {
    generation: AtomicU64,
    /// Phase, failure, and the one-shot manual-retry capability must move as a
    /// single locked state. Keeping the capability inside this mutex prevents
    /// two tray/page clicks from both starting a generation.
    status: Mutex<ShellStatus>,
    in_flight: AtomicBool,
    in_flight_generation: AtomicU64,
    /// Generations whose sidecars must be terminated (not merely ignored).
    terminate_generations: Mutex<Vec<u64>>,
    allowed_port: AtomicU64,
    stopping: AtomicBool,
}

impl Default for ShellController {
    fn default() -> Self {
        Self::new()
    }
}

impl ShellController {
    pub fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            status: Mutex::new(ShellStatus {
                phase: ShellPhase::Starting,
                failure: None,
                manual_retry_available: false,
            }),
            in_flight: AtomicBool::new(false),
            in_flight_generation: AtomicU64::new(0),
            terminate_generations: Mutex::new(Vec::new()),
            allowed_port: AtomicU64::new(0),
            stopping: AtomicBool::new(false),
        }
    }

    pub fn phase(&self) -> ShellPhase {
        self.status.lock().unwrap_or_else(|e| e.into_inner()).phase
    }

    pub fn failure(&self) -> Option<DesktopFailure> {
        self.status
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .failure
            .clone()
    }

    pub fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    pub fn request_stop(&self) {
        self.stopping.store(true, Ordering::Release);
    }

    /// Authorize a recovery-page Quit action exactly once. A healthy Ready
    /// Host must not be able to terminate the desktop shell by navigating to
    /// the otherwise valid recovery action URL.
    pub fn authorize_recovery_quit(&self) -> bool {
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        if status.phase == ShellPhase::Ready
            || self
                .stopping
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
        {
            return false;
        }
        status.manual_retry_available = false;
        true
    }

    pub fn allowed_port(&self) -> u16 {
        u16::try_from(self.allowed_port.load(Ordering::Acquire)).unwrap_or(0)
    }

    pub fn set_allowed_port(&self, port: u16) {
        self.allowed_port.store(u64::from(port), Ordering::Release);
    }

    /// Begin a start/retry attempt. Supersedes any in-flight generation by
    /// queueing it for **termination** (callbacks must not only drop work).
    pub fn begin_start(&self) -> Option<u64> {
        if self.stopping.load(Ordering::Acquire) {
            return None;
        }
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        if self.stopping.load(Ordering::Acquire) {
            return None;
        }
        Some(self.begin_start_locked(&mut status))
    }

    /// Consume the one-shot manual retry capability and start a new
    /// generation. Only a retryable `Failed` state can own this capability.
    pub fn begin_manual_retry(&self) -> Option<u64> {
        if self.stopping.load(Ordering::Acquire) {
            return None;
        }
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        if self.stopping.load(Ordering::Acquire)
            || status.phase != ShellPhase::Failed
            || !status.manual_retry_available
        {
            return None;
        }
        status.manual_retry_available = false;
        Some(self.begin_start_locked(&mut status))
    }

    fn begin_start_locked(&self, status: &mut ShellStatus) -> u64 {
        let next_generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        if self.in_flight.swap(true, Ordering::AcqRel) {
            let prev = self.in_flight_generation.load(Ordering::Acquire);
            if prev != 0 {
                if let Ok(mut q) = self.terminate_generations.lock() {
                    q.push(prev);
                }
            }
        }
        self.in_flight_generation
            .store(next_generation, Ordering::Release);
        status.phase = ShellPhase::Starting;
        status.failure = None;
        status.manual_retry_available = false;
        self.allowed_port.store(0, Ordering::Release);
        next_generation
    }

    /// Drain generations that must have their sidecar process groups killed.
    pub fn take_terminate_generations(&self) -> Vec<u64> {
        self.terminate_generations
            .lock()
            .map(|mut q| std::mem::take(&mut *q))
            .unwrap_or_default()
    }

    pub fn is_active_generation(&self, generation: u64) -> bool {
        !self.stopping.load(Ordering::Acquire)
            && self.in_flight_generation.load(Ordering::Acquire) == generation
    }

    pub fn mark_ready(&self, generation: u64, port: u16) -> bool {
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        if !self.is_active_generation(generation) {
            if let Ok(mut q) = self.terminate_generations.lock() {
                q.push(generation);
            }
            return false;
        }
        self.in_flight.store(false, Ordering::Release);
        self.set_allowed_port(port);
        status.phase = ShellPhase::Ready;
        status.failure = None;
        status.manual_retry_available = false;
        true
    }

    pub fn mark_failed_with_retry(
        &self,
        generation: u64,
        failure: DesktopFailure,
        manual_retry_available: bool,
    ) -> bool {
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        if !self.is_active_generation(generation) {
            if let Ok(mut q) = self.terminate_generations.lock() {
                q.push(generation);
            }
            return false;
        }
        self.in_flight.store(false, Ordering::Release);
        self.allowed_port.store(0, Ordering::Release);
        status.phase = ShellPhase::Failed;
        status.failure = Some(failure);
        status.manual_retry_available = manual_retry_available;
        true
    }

    pub fn cancel_in_flight(&self) {
        if self.in_flight.swap(false, Ordering::AcqRel) {
            let prev = self.in_flight_generation.load(Ordering::Acquire);
            if prev != 0 {
                if let Ok(mut q) = self.terminate_generations.lock() {
                    q.push(prev);
                }
            }
        }
    }

    /// Invalidate every generation and clear the ready port (app exit path).
    pub fn invalidate_all(&self) {
        self.stopping.store(true, Ordering::Release);
        self.cancel_in_flight();
        self.in_flight_generation.store(0, Ordering::Release);
        self.allowed_port.store(0, Ordering::Release);
        let mut status = self.status.lock().unwrap_or_else(|e| e.into_inner());
        status.phase = ShellPhase::Failed;
        status.manual_retry_available = false;
    }
}

/// A ready publication failed without leaving an owned child in the shared
/// slot. Callers must shut down every child returned by `into_children`.
#[derive(Debug)]
pub enum ReadyPublicationError<T> {
    Stale(T),
    Occupied { existing: T, candidate: T },
}

impl<T> ReadyPublicationError<T> {
    pub fn is_occupied(&self) -> bool {
        matches!(self, Self::Occupied { .. })
    }

    pub fn into_children(self) -> Vec<T> {
        match self {
            Self::Stale(child) => vec![child],
            Self::Occupied {
                existing,
                candidate,
            } => vec![existing, candidate],
        }
    }
}

/// Publish a supervised child before making `Ready` and its port observable.
/// The slot lock is held across the phase transition, so a monitor that sees
/// `Ready` can no longer observe an empty child slot.
pub fn publish_ready_child<T>(
    controller: &ShellController,
    slot: &Mutex<Option<(u64, T)>>,
    generation: u64,
    child: T,
    port: u16,
) -> Result<(), ReadyPublicationError<T>> {
    publish_ready_child_with_hook(controller, slot, generation, child, port, || {})
}

fn publish_ready_child_with_hook<T, F>(
    controller: &ShellController,
    slot: &Mutex<Option<(u64, T)>>,
    generation: u64,
    child: T,
    port: u16,
    before_ready: F,
) -> Result<(), ReadyPublicationError<T>>
where
    F: FnOnce(),
{
    let mut guard = slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((_existing_generation, existing)) = guard.take() {
        return Err(ReadyPublicationError::Occupied {
            existing,
            candidate: child,
        });
    }
    *guard = Some((generation, child));
    before_ready();
    if controller.mark_ready(generation, port) {
        return Ok(());
    }
    let (_generation, child) = guard
        .take()
        .expect("ready publication owns the inserted child");
    Err(ReadyPublicationError::Stale(child))
}

/// Fold application-layer setup dependency results into a panic-safe boundary.
///
/// Window/recovery surface is assumed pre-declared (or ensured before this
/// fold). Sidecar and tray failures move phase to `Failed` but **never** produce
/// an outcome other than `Continue`.
pub fn finalize_setup_boundary(
    recovery_surface_active: bool,
    sidecar_result: Result<(), DesktopFailure>,
    tray_result: Result<(), DesktopFailure>,
) -> SetupBoundaryReport {
    let tray_installed = tray_result.is_ok();
    let mut failure = None;
    let mut phase = ShellPhase::Starting;

    if let Err(err) = tray_result {
        failure = Some(err);
        phase = ShellPhase::Failed;
    }
    match sidecar_result {
        Ok(()) => {
            if failure.is_none() {
                phase = ShellPhase::Ready;
            }
        }
        Err(err) => {
            // Sidecar failure is the operator-facing primary when present.
            failure = Some(err);
            phase = ShellPhase::Failed;
        }
    }

    // Recovery surface must remain active whenever we are not fully ready, and
    // also when ready was not achieved because dependencies failed.
    let recovery_surface_active =
        recovery_surface_active && !matches!(phase, ShellPhase::Ready) || failure.is_some();

    SetupBoundaryReport {
        outcome: SetupOutcome::Continue,
        phase,
        failure,
        recovery_surface_active,
        tray_installed,
    }
}

fn is_closed_error_code(code: &str) -> bool {
    matches!(
        code,
        "spawn_failed"
            | "ready_timeout"
            | "sentinel_invalid"
            | "digest_mismatch"
            | "pgid_escape"
            | "sidecar_exit"
            | "sidecar_signal"
            | "cancelled"
            | "tray_failed"
            | "window_failed"
            | "bootstrap_failed"
            | "stdout_eof"
    )
}

fn is_exact_tauri_origin(url: &url::Url) -> bool {
    url.scheme() == "tauri"
        && url.host_str() == Some("localhost")
        && url.username().is_empty()
        && url.password().is_none()
        && url.port().is_none()
}

fn is_closed_recovery_fragment(fragment: Option<&str>) -> bool {
    let Some(fragment) = fragment else {
        // tauri.conf.json initially opens the bundled page before native code
        // has assigned an explicit state.
        return true;
    };
    if fragment.is_empty() || fragment == "state=starting" {
        return true;
    }
    for prefix in [
        "state=automatic_recovery&error=",
        "state=retryable_failure&error=",
        "state=fatal_failure&error=",
    ] {
        if let Some(code) = fragment.strip_prefix(prefix) {
            return is_closed_error_code(code);
        }
    }
    false
}

/// Whether a parsed navigation target is the exact packaged recovery page.
pub(crate) fn is_recovery_url(url: &url::Url) -> bool {
    is_exact_tauri_origin(url)
        && url.path() == "/recovery.html"
        && url.query().is_none()
        && is_closed_recovery_fragment(url.fragment())
}

/// Whether a navigation candidate is the exact packaged recovery page.
pub fn is_recovery_navigation(candidate: &str) -> bool {
    url::Url::parse(candidate).is_ok_and(|url| is_recovery_url(&url))
}

/// Parse exact local page actions. They are intercepted by native navigation
/// handling and must never be loaded as documents.
pub fn recovery_action_for_url(url: &url::Url) -> Option<RecoveryAction> {
    if !is_exact_tauri_origin(url) || url.query().is_some() || url.fragment().is_some() {
        return None;
    }
    match url.path() {
        "/__recovery_action__/retry" => Some(RecoveryAction::Retry),
        "/__recovery_action__/quit" => Some(RecoveryAction::Quit),
        _ => None,
    }
}

/// Build a recovery App URL with a closed-set state and error-code pair.
pub fn recovery_url_for_state(
    state: RecoveryState,
    code: Option<DesktopErrorCode>,
) -> Option<String> {
    match (state, code) {
        (RecoveryState::Starting, None) => Some("recovery.html#state=starting".to_string()),
        (RecoveryState::Starting, Some(_)) | (_, None) => None,
        (state, Some(code)) => Some(format!(
            "recovery.html#state={}&error={}",
            state.as_str(),
            code.as_str()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{DesktopErrorCode, ReadyFailureKind};
    use std::sync::{Arc, Barrier, TryLockError};

    fn recoverable_failure() -> DesktopFailure {
        DesktopFailure::classify(None, None, ReadyFailureKind::SpawnFailed, false)
    }

    #[test]
    fn setup_boundary_survives_sidecar_and_tray_failures_without_err_outcome() {
        let report = finalize_setup_boundary(
            true,
            Err(DesktopFailure::classify(
                Some(64),
                None,
                ReadyFailureKind::StdoutEof,
                false,
            )),
            Err(DesktopFailure::tray_failed()),
        );
        assert_eq!(report.outcome, SetupOutcome::Continue);
        assert_eq!(report.phase, ShellPhase::Failed);
        assert!(report.recovery_surface_active);
        assert!(!report.tray_installed);
        let failure = report.failure.expect("failure");
        assert_eq!(failure.code, DesktopErrorCode::SidecarExit);
        assert_eq!(failure.exit_code, Some(64));
    }

    #[test]
    fn setup_boundary_sidecar_ok_tray_fail_stays_failed_but_continue() {
        let report = finalize_setup_boundary(true, Ok(()), Err(DesktopFailure::tray_failed()));
        assert_eq!(report.outcome, SetupOutcome::Continue);
        assert_eq!(report.phase, ShellPhase::Failed);
        assert!(report.recovery_surface_active);
        assert_eq!(
            report.failure.map(|f| f.code),
            Some(DesktopErrorCode::TrayFailed)
        );
    }

    #[test]
    fn setup_boundary_all_ok_is_ready_with_continue() {
        let report = finalize_setup_boundary(true, Ok(()), Ok(()));
        assert_eq!(report.outcome, SetupOutcome::Continue);
        assert_eq!(report.phase, ShellPhase::Ready);
        assert!(!report.recovery_surface_active);
        assert!(report.tray_installed);
        assert!(report.failure.is_none());
    }

    #[test]
    fn superseding_generation_queues_previous_for_termination() {
        let ctl = ShellController::new();
        let g1 = ctl.begin_start().expect("g1");
        let g2 = ctl.begin_start().expect("g2");
        assert_ne!(g1, g2);
        let terminate = ctl.take_terminate_generations();
        assert!(
            terminate.contains(&g1),
            "previous in-flight generation must be terminated, not only ignored: {terminate:?}"
        );
        assert!(ctl.is_active_generation(g2));
        assert!(!ctl.is_active_generation(g1));
    }

    #[test]
    fn stale_ready_callback_queues_generation_for_termination() {
        let ctl = ShellController::new();
        let g1 = ctl.begin_start().expect("g1");
        let g2 = ctl.begin_start().expect("g2");
        let _ = ctl.take_terminate_generations();
        assert!(!ctl.mark_ready(g1, 41234));
        let terminate = ctl.take_terminate_generations();
        assert!(terminate.contains(&g1));
        assert!(ctl.mark_ready(g2, 41234));
        assert_eq!(ctl.phase(), ShellPhase::Ready);
        assert_eq!(ctl.allowed_port(), 41234);
    }

    #[test]
    fn cancel_in_flight_queues_termination() {
        let ctl = ShellController::new();
        let g1 = ctl.begin_start().expect("g1");
        ctl.cancel_in_flight();
        let terminate = ctl.take_terminate_generations();
        assert!(terminate.contains(&g1));
    }

    #[test]
    fn manual_retry_is_single_flight_and_only_starts_from_retryable_failed_state() {
        let ctl = ShellController::new();
        assert!(
            ctl.begin_manual_retry().is_none(),
            "starting must reject retry"
        );

        let first = ctl.begin_start().expect("initial generation");
        assert!(ctl.mark_failed_with_retry(first, recoverable_failure(), true));

        let retry = ctl
            .begin_manual_retry()
            .expect("retryable failed state must permit one retry");
        assert!(retry > first);
        assert_eq!(ctl.phase(), ShellPhase::Starting);
        assert!(
            ctl.begin_manual_retry().is_none(),
            "a second click must not start another generation"
        );
    }

    #[test]
    fn manual_retry_rejects_ready_fatal_auto_recovery_and_stopping_states() {
        let ready = ShellController::new();
        let generation = ready.begin_start().expect("ready generation");
        assert!(ready.mark_ready(generation, 43127));
        assert!(ready.begin_manual_retry().is_none());

        let fatal = ShellController::new();
        let generation = fatal.begin_start().expect("fatal generation");
        assert!(fatal.mark_failed_with_retry(generation, recoverable_failure(), false));
        assert!(fatal.begin_manual_retry().is_none());

        let automatic = ShellController::new();
        let generation = automatic.begin_start().expect("automatic generation");
        assert!(automatic.mark_failed_with_retry(generation, recoverable_failure(), false));
        assert!(automatic.begin_manual_retry().is_none());

        let stopping = ShellController::new();
        let generation = stopping.begin_start().expect("stopping generation");
        assert!(stopping.mark_failed_with_retry(generation, recoverable_failure(), true));
        stopping.request_stop();
        assert!(stopping.begin_manual_retry().is_none());
    }

    #[test]
    fn recovery_quit_is_authorized_only_from_starting_or_failed_and_is_one_shot() {
        let starting = ShellController::new();
        assert!(starting.authorize_recovery_quit());
        assert!(starting.is_stopping());
        assert!(
            !starting.authorize_recovery_quit(),
            "a second recovery quit must have no side effect"
        );

        let failed = ShellController::new();
        let generation = failed.begin_start().expect("failed generation");
        assert!(failed.mark_failed_with_retry(generation, recoverable_failure(), true));
        assert!(failed.authorize_recovery_quit());
        assert!(failed.is_stopping());

        let ready = ShellController::new();
        let generation = ready.begin_start().expect("ready generation");
        assert!(ready.mark_ready(generation, 43127));
        assert!(
            !ready.authorize_recovery_quit(),
            "a ready Host page must not be able to quit through a recovery action"
        );
        assert!(!ready.is_stopping());

        let stopping = ShellController::new();
        stopping.request_stop();
        assert!(!stopping.authorize_recovery_quit());
    }

    #[test]
    fn child_is_published_under_lock_before_ready_becomes_observable() {
        let controller = Arc::new(ShellController::new());
        let slot = Arc::new(Mutex::new(None));
        let generation = controller.begin_start().expect("generation");
        let child_published = Arc::new(Barrier::new(2));
        let allow_ready = Arc::new(Barrier::new(2));

        let worker_controller = Arc::clone(&controller);
        let worker_slot = Arc::clone(&slot);
        let worker_published = Arc::clone(&child_published);
        let worker_allow_ready = Arc::clone(&allow_ready);
        let worker = std::thread::spawn(move || {
            publish_ready_child_with_hook(
                &worker_controller,
                &worker_slot,
                generation,
                "child",
                43127,
                || {
                    worker_published.wait();
                    worker_allow_ready.wait();
                },
            )
        });

        child_published.wait();
        assert_eq!(controller.phase(), ShellPhase::Starting);
        assert!(matches!(slot.try_lock(), Err(TryLockError::WouldBlock)));

        allow_ready.wait();
        assert!(worker.join().expect("publisher thread").is_ok());
        assert_eq!(controller.phase(), ShellPhase::Ready);
        assert_eq!(controller.allowed_port(), 43127);
        assert_eq!(
            slot.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .as_ref(),
            Some(&(generation, "child"))
        );
    }

    #[test]
    fn failed_ready_publication_returns_every_child_and_leaves_slot_empty() {
        let controller = ShellController::new();
        let slot = Mutex::new(None);
        let stale = controller.begin_start().expect("stale generation");
        let active = controller.begin_start().expect("active generation");

        let error = publish_ready_child(&controller, &slot, stale, "stale-child", 43127)
            .expect_err("stale publication must fail");
        assert_eq!(error.into_children(), vec!["stale-child"]);
        assert!(
            slot.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_none()
        );
        assert_eq!(controller.phase(), ShellPhase::Starting);
        assert!(controller.is_active_generation(active));

        *slot.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) =
            Some((active, "existing-child"));
        let error = publish_ready_child(&controller, &slot, active, "candidate-child", 43128)
            .expect_err("occupied slot must fail closed");
        assert_eq!(
            error.into_children(),
            vec!["existing-child", "candidate-child"]
        );
        assert!(
            slot.lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .is_none()
        );
    }

    #[test]
    fn recovery_navigation_actions_are_exact_and_never_load_as_documents() {
        let retry =
            url::Url::parse("tauri://localhost/__recovery_action__/retry").expect("retry URL");
        let quit = url::Url::parse("tauri://localhost/__recovery_action__/quit").expect("quit URL");

        assert_eq!(recovery_action_for_url(&retry), Some(RecoveryAction::Retry));
        assert_eq!(recovery_action_for_url(&quit), Some(RecoveryAction::Quit));
        assert!(!NavigationPolicyForTest::recovery_allows(&retry));
        assert!(!NavigationPolicyForTest::recovery_allows(&quit));

        for candidate in [
            "tauri://localhost/__recovery_action__/retry/extra",
            "tauri://localhost/__recovery_action__/retry?next=host",
            "tauri://localhost/__recovery_action__/retry#again",
            "tauri://127.0.0.1/__recovery_action__/retry",
            "http://tauri.localhost/__recovery_action__/retry",
            "javascript:location='tauri://localhost/__recovery_action__/retry'",
        ] {
            let parsed = url::Url::parse(candidate).expect("candidate URL");
            assert_eq!(
                recovery_action_for_url(&parsed),
                None,
                "must reject {candidate}"
            );
        }
    }

    struct NavigationPolicyForTest;

    impl NavigationPolicyForTest {
        fn recovery_allows(candidate: &url::Url) -> bool {
            is_recovery_url(candidate)
        }
    }

    #[test]
    fn recovery_urls_encode_a_closed_state_and_error_pair() {
        assert_eq!(
            recovery_url_for_state(RecoveryState::Starting, None).expect("starting URL"),
            "recovery.html#state=starting"
        );
        assert_eq!(
            recovery_url_for_state(
                RecoveryState::AutomaticRecovery,
                Some(DesktopErrorCode::SidecarExit),
            )
            .expect("automatic recovery URL"),
            "recovery.html#state=automatic_recovery&error=sidecar_exit"
        );
        assert_eq!(
            recovery_url_for_state(
                RecoveryState::RetryableFailure,
                Some(DesktopErrorCode::SpawnFailed),
            )
            .expect("retryable failure URL"),
            "recovery.html#state=retryable_failure&error=spawn_failed"
        );
        assert_eq!(
            recovery_url_for_state(
                RecoveryState::FatalFailure,
                Some(DesktopErrorCode::PgidEscape),
            )
            .expect("fatal failure URL"),
            "recovery.html#state=fatal_failure&error=pgid_escape"
        );

        for candidate in [
            "tauri://localhost/recovery.html#state=starting",
            "tauri://localhost/recovery.html#state=automatic_recovery&error=sidecar_exit",
            "tauri://localhost/recovery.html#state=retryable_failure&error=spawn_failed",
            "tauri://localhost/recovery.html#state=fatal_failure&error=pgid_escape",
        ] {
            assert!(is_recovery_navigation(candidate), "must allow {candidate}");
        }
        for candidate in [
            "tauri://localhost/recovery.html#error=spawn_failed",
            "tauri://localhost/recovery.html#state=retryable_failure",
            "tauri://localhost/recovery.html#state=unknown&error=spawn_failed",
            "tauri://localhost/recovery.html#state=retryable_failure&error=unknown",
            "tauri://localhost/recovery.html#state=retryable_failure&error=spawn_failed&next=host",
        ] {
            assert!(
                !is_recovery_navigation(candidate),
                "must reject {candidate}"
            );
        }
    }

    #[test]
    fn navigation_policy_recovery_helper_accepts_only_packaged_origin() {
        assert!(is_recovery_navigation(
            "tauri://localhost/recovery.html#state=retryable_failure&error=sidecar_exit"
        ));
        assert!(!is_recovery_navigation("recovery.html"));
        assert!(!is_recovery_navigation(
            "http://tauri.localhost/recovery.html#state=retryable_failure&error=sidecar_exit"
        ));
        assert!(!is_recovery_navigation(
            "tauri://localhost/nested/recovery.html#state=retryable_failure&error=sidecar_exit"
        ));
        assert!(!is_recovery_navigation(
            "tauri://localhost/recovery.html#state=retryable_failure&error=not_closed_set"
        ));
        assert!(!is_recovery_navigation("http://127.0.0.1:9/"));
        assert!(!is_recovery_navigation("data:text/html,hi"));
    }
}
