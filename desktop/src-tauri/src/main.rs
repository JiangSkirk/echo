use js_agent_desktop::{
    DesktopErrorCode, DesktopFailure, ManagedSidecar, MonitorDecision, MonitorEvent,
    NavigationPolicy, RESTART_WINDOW, ReadyFailureKind, RecoveryAction, RecoveryState,
    RestartBudget, SHUTDOWN_TIMEOUT, SetupOutcome, ShellController, ShellPhase, SidecarLaunchSpec,
    SidecarPoll, SupervisorError, bootstrap_url, compiled_source_digest,
    configure_process_local_appkit_state_restoration, finalize_setup_boundary,
    generate_bootstrap_token, keep_awake_command, launch_agent_contents, monitor_decision,
    publish_ready_child, recovery_action_for_url, recovery_url_for_state,
};
use signal_hook::consts::signal::{SIGINT, SIGTERM};
use signal_hook::iterator::Signals;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tauri::menu::{CheckMenuItem, Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::webview::NewWindowResponse;
use tauri::{AppHandle, Manager, RunEvent, WebviewWindowBuilder, WindowEvent};
use zeroize::Zeroize;

const MAIN_WINDOW: &str = "main";
const LAUNCH_AGENT_NAME: &str = "com.titan.js-agent.plist";

struct SidecarSupervisor {
    child: Mutex<Option<(u64, ManagedSidecar)>>,
    /// Serializes spawn_host against shutdown so SIGTERM cannot exit the
    /// process while a spawn thread still owns an untracked sidecar.
    spawn_lock: Mutex<()>,
    restart_budget: Mutex<RestartBudget>,
    shell: Arc<ShellController>,
    stopping: AtomicBool,
    sidecar_path: PathBuf,
    source_digest: &'static str,
}

impl SidecarSupervisor {
    fn new(
        sidecar_path: PathBuf,
        source_digest: &'static str,
        shell: Arc<ShellController>,
    ) -> Self {
        Self {
            child: Mutex::new(None),
            spawn_lock: Mutex::new(()),
            restart_budget: Mutex::new(RestartBudget::new(RESTART_WINDOW)),
            shell,
            stopping: AtomicBool::new(false),
            sidecar_path,
            source_digest,
        }
    }

    fn spawn_host(&self) -> Result<Option<(ManagedSidecar, url::Url)>, SupervisorError> {
        let _spawn_guard = self
            .spawn_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if self.stopping.load(Ordering::Acquire) {
            return Ok(None);
        }
        let mut token = match generate_bootstrap_token() {
            Ok(token) => token,
            Err(_) => {
                return Err(SupervisorError::from(
                    DesktopFailure::bootstrap_failed().to_string(),
                ));
            }
        };
        let launch = match SidecarLaunchSpec::new(
            self.sidecar_path.clone(),
            self.source_digest,
            token.clone(),
        ) {
            Ok(spec) => spec.with_supervisor_pid(),
            Err(_) => {
                token.zeroize();
                return Err(SupervisorError::from(
                    DesktopFailure::bootstrap_failed().to_string(),
                ));
            }
        };
        let spawned = match launch.spawn_cancelable(&self.stopping) {
            Ok(value) => value,
            Err(error) => {
                token.zeroize();
                return Err(error);
            }
        };
        let Some(mut sidecar) = spawned else {
            token.zeroize();
            return Ok(None);
        };
        if self.stopping.load(Ordering::Acquire) {
            token.zeroize();
            let _ = sidecar.shutdown(SHUTDOWN_TIMEOUT);
            return Ok(None);
        }
        let url = match bootstrap_url(sidecar.ready.port, &token) {
            Ok(url) => url,
            Err(_) => {
                token.zeroize();
                let _ = sidecar.shutdown(SHUTDOWN_TIMEOUT);
                return Err(SupervisorError::from(
                    DesktopFailure::bootstrap_failed().to_string(),
                ));
            }
        };
        token.zeroize();
        if self.stopping.load(Ordering::Acquire) {
            let _ = sidecar.shutdown(SHUTDOWN_TIMEOUT);
            return Ok(None);
        }
        Ok(Some((sidecar, url)))
    }

    fn apply_terminate_queue(&self) {
        for generation in self.shell.take_terminate_generations() {
            if let Ok(mut guard) = self.child.lock()
                && let Some((owned_generation, mut sidecar)) = guard.take()
            {
                if owned_generation == generation {
                    let _ = sidecar.shutdown(SHUTDOWN_TIMEOUT);
                } else {
                    *guard = Some((owned_generation, sidecar));
                }
            }
        }
    }

    fn start_generation(self: &Arc<Self>, app: AppHandle, generation: u64) {
        let supervisor = Arc::clone(self);
        thread::spawn(move || {
            supervisor.apply_terminate_queue();
            if !supervisor.shell.is_active_generation(generation)
                || supervisor.stopping.load(Ordering::Acquire)
            {
                return;
            }
            let result = supervisor.spawn_host();
            // Re-check after the blocking spawn: SIGTERM may have arrived while
            // we waited for the ready sentinel. Always tear down a returned
            // sidecar when stopping or when this generation is stale.
            if supervisor.stopping.load(Ordering::Acquire)
                || !supervisor.shell.is_active_generation(generation)
            {
                if let Ok(Some((mut sidecar, _url))) = result {
                    let _ = sidecar.shutdown(SHUTDOWN_TIMEOUT);
                }
                return;
            }
            match result {
                Ok(Some((mut sidecar, url))) => {
                    let port = sidecar.ready.port;
                    // Hold spawn_lock while publishing the child so shutdown
                    // cannot observe an empty slot between spawn return and store.
                    let _spawn_guard = supervisor
                        .spawn_lock
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if supervisor.stopping.load(Ordering::Acquire)
                        || !supervisor.shell.is_active_generation(generation)
                    {
                        drop(_spawn_guard);
                        let _ = sidecar.shutdown(SHUTDOWN_TIMEOUT);
                        return;
                    }
                    let publication = publish_ready_child(
                        &supervisor.shell,
                        &supervisor.child,
                        generation,
                        sidecar,
                        port,
                    );
                    match publication {
                        Ok(()) => {}
                        Err(error) => {
                            drop(_spawn_guard);
                            let occupied = error.is_occupied();
                            for mut child in error.into_children() {
                                let _ = child.shutdown(SHUTDOWN_TIMEOUT);
                            }
                            if occupied && supervisor.shell.is_active_generation(generation) {
                                let failure = DesktopFailure::classify(
                                    None,
                                    None,
                                    ReadyFailureKind::Other,
                                    false,
                                );
                                let code = failure.code;
                                let _ = supervisor
                                    .shell
                                    .mark_failed_with_retry(generation, failure, false);
                                show_recovery(&app, RecoveryState::FatalFailure, Some(code));
                            }
                            return;
                        }
                    }
                    if supervisor.stopping.load(Ordering::Acquire) {
                        drop(_spawn_guard);
                        return;
                    }
                    navigate_to_host(&app, &url);
                    drop(_spawn_guard);
                }
                Ok(None) => {
                    if supervisor.stopping.load(Ordering::Acquire) {
                        return;
                    }
                    let _ = supervisor.shell.mark_failed_with_retry(
                        generation,
                        DesktopFailure::cancelled(),
                        false,
                    );
                    show_recovery(
                        &app,
                        RecoveryState::FatalFailure,
                        Some(DesktopErrorCode::Cancelled),
                    );
                }
                Err(error) => {
                    if supervisor.stopping.load(Ordering::Acquire) {
                        return;
                    }
                    let failure = error.failure().cloned().unwrap_or_else(|| {
                        DesktopFailure::classify(None, None, ReadyFailureKind::Other, false)
                    });
                    let code = failure.code;
                    let retryable = !error.is_fatal();
                    let _ = supervisor
                        .shell
                        .mark_failed_with_retry(generation, failure, retryable);
                    show_recovery(
                        &app,
                        if retryable {
                            RecoveryState::RetryableFailure
                        } else {
                            RecoveryState::FatalFailure
                        },
                        Some(code),
                    );
                }
            }
        });
    }

    fn request_start(self: &Arc<Self>, app: AppHandle) {
        if self.stopping.load(Ordering::Acquire) {
            return;
        }
        self.apply_terminate_queue();
        // Clear any live child before an initial or automatic restart.
        if let Ok(mut guard) = self.child.lock()
            && let Some((_gen, mut sidecar)) = guard.take()
        {
            let _ = sidecar.shutdown(SHUTDOWN_TIMEOUT);
        }
        let Some(generation) = self.shell.begin_start() else {
            return;
        };
        show_recovery(&app, RecoveryState::Starting, None);
        self.apply_terminate_queue();
        self.start_generation(app, generation);
    }

    fn request_manual_retry(self: &Arc<Self>, app: AppHandle) -> bool {
        if self.stopping.load(Ordering::Acquire) {
            return false;
        }
        let Some(generation) = self.shell.begin_manual_retry() else {
            return false;
        };
        let retry_supervisor = Arc::clone(self);
        thread::spawn(move || {
            if retry_supervisor.stopping.load(Ordering::Acquire)
                || retry_supervisor.shell.is_stopping()
            {
                return;
            }
            retry_supervisor.apply_terminate_queue();
            if let Ok(mut guard) = retry_supervisor.child.lock()
                && let Some((_gen, mut sidecar)) = guard.take()
            {
                let _ = sidecar.shutdown(SHUTDOWN_TIMEOUT);
            }
            show_recovery(&app, RecoveryState::Starting, None);
            retry_supervisor.start_generation(app, generation);
        });
        true
    }

    fn request_recovery_quit(self: &Arc<Self>, app: AppHandle) -> bool {
        if !self.shell.authorize_recovery_quit() {
            return false;
        }
        let quit_supervisor = Arc::clone(self);
        thread::spawn(move || {
            quit_supervisor.shutdown();
            app.exit(0);
        });
        true
    }

    fn start_monitor(self: &Arc<Self>, app: AppHandle) {
        let supervisor = Arc::clone(self);
        thread::spawn(move || {
            loop {
                if supervisor.stopping.load(Ordering::Acquire) {
                    break;
                }
                thread::sleep(Duration::from_millis(200));
                supervisor.apply_terminate_queue();
                let event = {
                    // A publisher holds this lock until the child is stored,
                    // Ready is visible, and the WebView navigation is issued.
                    // The monitor therefore cannot consume a half-published
                    // generation or race recovery ahead of its first navigate.
                    let _spawn_guard = supervisor
                        .spawn_lock
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    if !matches!(supervisor.shell.phase(), ShellPhase::Ready) {
                        continue;
                    }
                    let Ok(mut child) = supervisor.child.lock() else {
                        break;
                    };
                    match child.as_mut() {
                        Some((_gen, process)) => match process.poll() {
                            Ok(SidecarPoll::ExitedAndGroupCleaned(_)) => {
                                child.take();
                                supervisor.shell.set_allowed_port(0);
                                MonitorEvent::ExitedAndGroupCleaned
                            }
                            Ok(SidecarPoll::Running) => MonitorEvent::Running,
                            Err(error) => {
                                child.take();
                                supervisor.shell.set_allowed_port(0);
                                MonitorEvent::Fatal(error)
                            }
                        },
                        None => MonitorEvent::Missing,
                    }
                };
                let decision = {
                    let (cleanup_is_fatal, recovery_code) = match &event {
                        MonitorEvent::Fatal(error) => (
                            true,
                            error
                                .failure()
                                .map(|failure| failure.code)
                                .unwrap_or(DesktopErrorCode::SidecarExit),
                        ),
                        _ => (false, DesktopErrorCode::SidecarExit),
                    };
                    let Ok(mut budget) = supervisor.restart_budget.lock() else {
                        break;
                    };
                    (
                        monitor_decision(event, &mut budget, Instant::now()),
                        cleanup_is_fatal,
                        recovery_code,
                    )
                };
                match decision {
                    (MonitorDecision::Continue, _, _) => continue,
                    (MonitorDecision::QuarantineThenRestartAfter(delay), _, recovery_code) => {
                        enter_post_ready_recovery(
                            &supervisor,
                            &app,
                            recovery_code,
                            RecoveryState::AutomaticRecovery,
                            false,
                        );
                        let deadline = Instant::now() + delay;
                        while Instant::now() < deadline {
                            if supervisor.stopping.load(Ordering::Acquire) {
                                return;
                            }
                            thread::sleep(Duration::from_millis(50));
                        }
                        supervisor.request_start(app.clone());
                    }
                    (MonitorDecision::QuarantineThenFatal, cleanup_is_fatal, recovery_code) => {
                        enter_post_ready_recovery(
                            &supervisor,
                            &app,
                            recovery_code,
                            if cleanup_is_fatal {
                                RecoveryState::FatalFailure
                            } else {
                                RecoveryState::RetryableFailure
                            },
                            !cleanup_is_fatal,
                        );
                    }
                }
            }
        });
    }

    fn allows_navigation(&self, candidate: &url::Url) -> bool {
        let port = self.shell.allowed_port();
        if port == 0 {
            return NavigationPolicy::recovery_only().allows_url(candidate);
        }
        NavigationPolicy::new(port).is_ok_and(|policy| policy.allows_url(candidate))
    }

    fn shutdown(&self) {
        self.stopping.store(true, Ordering::Release);
        self.shell.invalidate_all();
        // Wait for any in-flight spawn_host to observe `stopping`, finish, and
        // release its guard before we reap the supervised child.
        let _spawn_guard = self
            .spawn_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.apply_terminate_queue();
        if let Ok(mut guard) = self.child.lock()
            && let Some((_gen, mut child)) = guard.take()
        {
            let _ = child.shutdown(SHUTDOWN_TIMEOUT);
        }
    }
}

fn enter_post_ready_recovery(
    supervisor: &SidecarSupervisor,
    app: &AppHandle,
    code: DesktopErrorCode,
    state: RecoveryState,
    retryable: bool,
) {
    supervisor.shell.set_allowed_port(0);
    if let Some(generation) = supervisor.shell.begin_start() {
        // Immediately mark failed for this generation so phase is Failed and
        // any in-flight start is queued for termination.
        let _ = supervisor.shell.mark_failed_with_retry(
            generation,
            DesktopFailure {
                code,
                detail: None,
                exit_code: None,
                signal: None,
                stderr_truncated: false,
            },
            retryable,
        );
    }
    show_recovery(app, state, Some(code));
}

struct NativeControls {
    keep_awake: Mutex<Option<Child>>,
}

impl NativeControls {
    fn new() -> Self {
        Self {
            keep_awake: Mutex::new(None),
        }
    }

    fn set_keep_awake(&self, enabled: bool) -> Result<(), String> {
        let mut guard = self
            .keep_awake
            .lock()
            .map_err(|_| "keep-awake lock poisoned".to_string())?;
        if enabled {
            if guard.is_some() {
                return Ok(());
            }
            let (program, args) = keep_awake_command(std::process::id())?;
            let child = Command::new(program)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|error| format!("failed to enable keep-awake: {error}"))?;
            *guard = Some(child);
        } else if let Some(mut child) = guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        Ok(())
    }

    fn shutdown(&self) {
        let _ = self.set_keep_awake(false);
    }
}

struct AppState {
    supervisor: Arc<SidecarSupervisor>,
    native: Arc<NativeControls>,
}

fn reveal_main_window(app: &AppHandle) -> bool {
    let Some(window) = app.get_webview_window(MAIN_WINDOW) else {
        return false;
    };
    let _ = window.unminimize();
    let _ = window.show();
    let _ = window.set_focus();
    true
}

fn show_recovery(app: &AppHandle, state: RecoveryState, code: Option<DesktopErrorCode>) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let title = match state {
            RecoveryState::Starting => "JS Agent — 正在启动",
            RecoveryState::AutomaticRecovery => "JS Agent — 正在自动恢复",
            RecoveryState::RetryableFailure => "JS Agent — 需要重新连接",
            RecoveryState::FatalFailure => "JS Agent — 无法自动恢复",
        };
        let _ = window.set_title(title);
        if let Ok(url) = app_recovery_url(state, code) {
            let _ = window.navigate(url);
        }
        let _ = reveal_main_window(app);
    }
}

fn app_recovery_url(state: RecoveryState, code: Option<DesktopErrorCode>) -> Result<url::Url, ()> {
    // Packaged macOS App URLs use the tauri://localhost origin.
    let target = recovery_url_for_state(state, code).ok_or(())?;
    url::Url::parse(&format!("tauri://localhost/{target}")).map_err(|_| ())
}

fn navigate_to_host(app: &AppHandle, url: &url::Url) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let _ = window.navigate(url.clone());
        let _ = window.set_title("JS Agent");
        let _ = reveal_main_window(app);
    }
}

fn ensure_recovery_window_handlers(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(MAIN_WINDOW) {
        let close_window = window.clone();
        window.on_window_event(move |event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = close_window.hide();
            }
        });
    }
}

fn create_main_window(
    app: &mut tauri::App,
    supervisor: Arc<SidecarSupervisor>,
) -> Result<(), DesktopFailure> {
    let Some(config) = app
        .config()
        .app
        .windows
        .iter()
        .find(|config| config.label == MAIN_WINDOW)
        .cloned()
    else {
        return Err(DesktopFailure::window_failed());
    };
    let navigation_supervisor = Arc::clone(&supervisor);
    let navigation_app = app.handle().clone();
    let builder = WebviewWindowBuilder::from_config(app.handle(), &config)
        .map_err(|_| DesktopFailure::window_failed())?;
    builder
        .on_navigation(move |candidate| {
            if let Some(action) = recovery_action_for_url(candidate) {
                match action {
                    RecoveryAction::Retry => {
                        let _ = navigation_supervisor.request_manual_retry(navigation_app.clone());
                    }
                    RecoveryAction::Quit => {
                        let _ = navigation_supervisor.request_recovery_quit(navigation_app.clone());
                    }
                }
                return false;
            }
            navigation_supervisor.allows_navigation(candidate)
        })
        .on_new_window(|_url, _features| NewWindowResponse::Deny)
        .build()
        .map(|_| ())
        .map_err(|_| DesktopFailure::window_failed())
}

fn bundled_sidecar_path() -> Result<PathBuf, String> {
    let current = std::env::current_exe()
        .map_err(|error| format!("cannot locate desktop executable: {error}"))?;
    let directory = current
        .parent()
        .ok_or_else(|| "desktop executable has no parent directory".to_string())?;
    let bundled = directory.join("js-agent-host");
    if bundled.is_file() {
        return Ok(bundled);
    }
    let development = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("binaries/js-agent-host-aarch64-apple-darwin");
    if development.is_file() {
        return Ok(development);
    }
    Err("bundled AppShell sidecar is missing".to_string())
}

fn launch_agent_path(app: &AppHandle) -> Result<PathBuf, String> {
    let home = app
        .path()
        .home_dir()
        .map_err(|error| format!("cannot locate home directory: {error}"))?;
    Ok(home.join("Library/LaunchAgents").join(LAUNCH_AGENT_NAME))
}

fn write_launch_agent(path: &Path) -> Result<(), String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("cannot locate autostart executable: {error}"))?;
    let contents = launch_agent_contents(&executable)?;
    let parent = path
        .parent()
        .ok_or_else(|| "LaunchAgent path has no parent".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create LaunchAgents directory: {error}"))?;
    let temporary = parent.join(format!(".{LAUNCH_AGENT_NAME}.{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|error| format!("cannot create temporary LaunchAgent: {error}"))?;
    let result = (|| -> Result<(), String> {
        file.write_all(contents.as_bytes())
            .map_err(|error| format!("cannot write LaunchAgent: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("cannot sync LaunchAgent: {error}"))?;
        drop(file);
        fs::rename(&temporary, path)
            .map_err(|error| format!("cannot install LaunchAgent: {error}"))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("cannot restrict LaunchAgent: {error}"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn configure_tray(
    app: &mut tauri::App,
    native: Arc<NativeControls>,
    supervisor: Arc<SidecarSupervisor>,
) -> Result<(), DesktopFailure> {
    let show = MenuItem::with_id(app, "show", "显示 JS Agent", true, None::<&str>)
        .map_err(|_| DesktopFailure::tray_failed())?;
    let retry = MenuItem::with_id(app, "retry", "重新连接", true, None::<&str>)
        .map_err(|_| DesktopFailure::tray_failed())?;
    let keep_awake =
        CheckMenuItem::with_id(app, "keep_awake", "保持唤醒", true, false, None::<&str>)
            .map_err(|_| DesktopFailure::tray_failed())?;
    let autostart_path = launch_agent_path(app.handle()).unwrap_or_default();
    let autostart = CheckMenuItem::with_id(
        app,
        "autostart",
        "登录时启动",
        true,
        autostart_path.is_file(),
        None::<&str>,
    )
    .map_err(|_| DesktopFailure::tray_failed())?;
    let quit = MenuItem::with_id(app, "quit", "退出", true, None::<&str>)
        .map_err(|_| DesktopFailure::tray_failed())?;
    let menu = Menu::with_items(app, &[&show, &retry, &keep_awake, &autostart, &quit])
        .map_err(|_| DesktopFailure::tray_failed())?;

    let keep_awake_item = keep_awake.clone();
    let autostart_item = autostart.clone();
    let tray_supervisor = Arc::clone(&supervisor);
    TrayIconBuilder::new()
        .menu(&menu)
        .tooltip("JS Agent")
        .icon_as_template(true)
        .on_menu_event(move |app, event| match event.id().as_ref() {
            "show" => {
                let _ = reveal_main_window(app);
            }
            "retry" => {
                let _ = tray_supervisor.request_manual_retry(app.clone());
            }
            "keep_awake" => {
                let checked = keep_awake_item.is_checked().unwrap_or(false);
                if native.set_keep_awake(checked).is_err() {
                    let _ = keep_awake_item.set_checked(!checked);
                }
            }
            "autostart" => {
                let checked = autostart_item.is_checked().unwrap_or(false);
                let result = if checked {
                    write_launch_agent(&autostart_path)
                } else {
                    match fs::remove_file(&autostart_path) {
                        Ok(()) => Ok(()),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
                        Err(error) => Err(format!("cannot disable autostart: {error}")),
                    }
                };
                if result.is_err() {
                    let _ = autostart_item.set_checked(!checked);
                }
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .build(app)
        .map_err(|_| DesktopFailure::tray_failed())?;
    Ok(())
}

fn install_signal_exit(
    app: AppHandle,
    supervisor: Arc<SidecarSupervisor>,
    native: Arc<NativeControls>,
) {
    let Ok(mut signals) = Signals::new([SIGTERM, SIGINT]) else {
        return;
    };
    thread::spawn(move || {
        if signals.forever().next().is_some() {
            supervisor.shutdown();
            native.shutdown();
            app.exit(0);
        }
    });
}

fn run() -> Result<(), String> {
    // Packaging / build-time failures may exit before the event loop (outside
    // did_finish_launching). Application-layer work inside setup must not
    // return Err.
    let source_digest = compiled_source_digest()?;
    let sidecar_path = bundled_sidecar_path()?;
    let shell = Arc::new(ShellController::new());
    let supervisor = Arc::new(SidecarSupervisor::new(
        sidecar_path,
        source_digest,
        Arc::clone(&shell),
    ));
    let native = Arc::new(NativeControls::new());

    let setup_supervisor = Arc::clone(&supervisor);
    let setup_native = Arc::clone(&native);
    let app = tauri::Builder::default()
        .setup(move |app| {
            if let Err(failure) = create_main_window(app, Arc::clone(&setup_supervisor)) {
                eprintln!("JS Agent desktop setup failed: {}", failure.code);
                app.handle().exit(70);
                return Ok(());
            }

            install_signal_exit(
                app.handle().clone(),
                Arc::clone(&setup_supervisor),
                Arc::clone(&setup_native),
            );

            let recovery_present = app.get_webview_window(MAIN_WINDOW).is_some();
            ensure_recovery_window_handlers(app.handle());

            let tray_result = configure_tray(
                app,
                Arc::clone(&setup_native),
                Arc::clone(&setup_supervisor),
            );

            // Sidecar starts asynchronously after setup returns Ok.
            let report = finalize_setup_boundary(recovery_present, Ok(()), tray_result);
            debug_assert_eq!(report.outcome, SetupOutcome::Continue);
            if let Some(failure) = report.failure.as_ref() {
                if let Some(generation) = setup_supervisor.shell.begin_start() {
                    let _ = setup_supervisor.shell.mark_failed_with_retry(
                        generation,
                        failure.clone(),
                        false,
                    );
                }
                show_recovery(
                    app.handle(),
                    RecoveryState::FatalFailure,
                    Some(failure.code),
                );
            }

            if report.failure.is_none() {
                setup_supervisor.request_start(app.handle().clone());
                setup_supervisor.start_monitor(app.handle().clone());
            }

            app.manage(AppState {
                supervisor: Arc::clone(&setup_supervisor),
                native: Arc::clone(&setup_native),
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .map_err(|error| format!("failed to build desktop shell: {error}"))?;

    if supervisor.stopping.load(Ordering::Acquire) {
        supervisor.shutdown();
        native.shutdown();
        return Ok(());
    }

    app.run(|handle, event| {
        #[cfg(target_os = "macos")]
        if matches!(event, RunEvent::Reopen { .. }) {
            let _ = reveal_main_window(handle);
        }
        if matches!(event, RunEvent::ExitRequested { .. } | RunEvent::Exit)
            && let Some(state) = handle.try_state::<AppState>()
        {
            state.supervisor.shutdown();
            state.native.shutdown();
        }
    });
    Ok(())
}

fn main() {
    configure_process_local_appkit_state_restoration();
    if let Err(error) = run() {
        eprintln!("JS Agent desktop failed: {error}");
        std::process::exit(70);
    }
}
