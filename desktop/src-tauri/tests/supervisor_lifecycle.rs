use js_agent_desktop::{
    MonitorDecision, MonitorEvent, RestartBudget, SidecarLaunchSpec, SidecarPoll, SidecarTimeouts,
    SupervisorError, monitor_decision,
};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const DIGEST: &str = "abababababababababababababababababababababababababababababababab";
const TOKEN: &str = "2323232323232323232323232323232323232323232323232323232323232323";
static NEXT_TEST_DIR: AtomicU64 = AtomicU64::new(0);
static PROCESS_TEST_LOCK: Mutex<()> = Mutex::new(());

#[derive(Debug)]
struct Evidence {
    leader_pid: u32,
    member_pid: u32,
    pgid: u32,
    leader_current_pgid: u32,
    setpgid_errno: Option<i32>,
    escaped_pid: Option<u32>,
}

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let suffix = NEXT_TEST_DIR.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "js-agent-supervisor-{}-{nanos}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test directory");
        Self(path)
    }

    fn evidence_path(&self) -> PathBuf {
        self.0.join("evidence.json")
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("desktop root")
        .join("tests/fixtures/process_group_probe.py")
}

fn process_test_guard() -> MutexGuard<'static, ()> {
    PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn short_timeouts() -> SidecarTimeouts {
    SidecarTimeouts::new(
        Duration::from_secs(1),
        Duration::from_millis(250),
        Duration::from_secs(1),
    )
}

fn launch_spec(mode: &str, evidence_path: &Path) -> SidecarLaunchSpec {
    let mut spec =
        SidecarLaunchSpec::new(fixture_path(), DIGEST, TOKEN.to_string()).expect("launch spec");
    spec.env.extend([
        ("JS_AGENT_PROCESS_GROUP_MODE".to_string(), mode.to_string()),
        (
            "JS_AGENT_PROCESS_GROUP_EVIDENCE".to_string(),
            evidence_path.display().to_string(),
        ),
    ]);
    spec
}

fn read_evidence(path: &Path) -> Evidence {
    let deadline = Instant::now() + Duration::from_secs(2);
    while !path.is_file() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let raw = fs::read_to_string(path).expect("process evidence");
    let value: Value = serde_json::from_str(&raw).expect("valid process evidence");
    Evidence {
        leader_pid: value["leader_pid"].as_u64().expect("leader PID") as u32,
        member_pid: value["member_pid"].as_u64().expect("member PID") as u32,
        pgid: value["pgid"].as_u64().expect("PGID") as u32,
        leader_current_pgid: value["leader_current_pgid"]
            .as_u64()
            .expect("leader current PGID") as u32,
        setpgid_errno: value["setpgid_errno"].as_i64().map(|errno| errno as i32),
        escaped_pid: value["escaped_pid"].as_u64().map(|pid| pid as u32),
    }
}

#[cfg(unix)]
fn signal(target: i32, signal: i32) -> i32 {
    unsafe extern "C" {
        fn kill(pid: i32, signal: i32) -> i32;
    }
    unsafe { kill(target, signal) }
}

fn group_exists(pgid: u32) -> bool {
    signal(-(pgid as i32), 0) == 0
}

fn pid_exists(pid: u32) -> bool {
    signal(pid as i32, 0) == 0
}

fn wait_for_group_absence(pgid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !group_exists(pgid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    !group_exists(pgid)
}

fn wait_for_pid_absence(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !pid_exists(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    !pid_exists(pid)
}

fn emergency_cleanup(evidence: &Evidence) {
    let _ = signal(-(evidence.pgid as i32), 9);
    if let Some(pid) = evidence.escaped_pid {
        let _ = signal(-(pid as i32), 9);
        let _ = signal(pid as i32, 9);
        let _ = wait_for_group_absence(pid, Duration::from_secs(2));
    }
    let _ = wait_for_group_absence(evidence.pgid, Duration::from_secs(2));
}

fn assert_failed_launch_cleans(mode: &str) -> SupervisorError {
    let directory = TestDir::new();
    let evidence_path = directory.evidence_path();
    let result = launch_spec(mode, &evidence_path).spawn_with_timeouts(short_timeouts());
    let evidence = read_evidence(&evidence_path);
    let group_absent = wait_for_group_absence(evidence.pgid, Duration::from_secs(2));
    let leader_absent = !pid_exists(evidence.leader_pid);
    let member_absent = !pid_exists(evidence.member_pid);
    emergency_cleanup(&evidence);
    let error = result.expect_err("fixture must fail before readiness");
    assert!(
        group_absent && leader_absent && member_absent,
        "{mode} returned before PGID {} disappeared: {evidence:?}",
        evidence.pgid
    );
    error
}

#[test]
fn pre_ready_eof_cleans_entire_process_group() {
    let _guard = process_test_guard();
    let error = assert_failed_launch_cleans("eof");
    // Closed-set codes: child exit outranks stream symptoms when reaped.
    let text = error.to_string();
    assert!(
        text.contains("stdout_eof")
            || text.contains("sidecar_exit")
            || text.contains("sidecar_signal"),
        "expected closed-set pre-ready failure, got {text}"
    );
}

#[test]
fn stdout_read_error_cleans_entire_process_group() {
    let _guard = process_test_guard();
    let error = assert_failed_launch_cleans("read_error");
    let text = error.to_string();
    assert!(
        text.contains("spawn_failed")
            || text.contains("stdout_eof")
            || text.contains("sidecar_exit")
            || text.contains("sidecar_signal"),
        "expected closed-set read failure, got {text}"
    );
}

#[test]
fn invalid_sentinel_cleans_entire_process_group() {
    let _guard = process_test_guard();
    for mode in [
        "malformed",
        "noncanonical",
        "unknown_field",
        "wrong_schema",
        "wrong_digest",
        "invalid_pid",
        "escaped_pid",
    ] {
        let _ = assert_failed_launch_cleans(mode);
    }
}

#[test]
fn launch_leader_moved_to_another_group_is_rejected_and_cleaned() {
    let _guard = process_test_guard();
    let directory = TestDir::new();
    let evidence_path = directory.evidence_path();
    let result = launch_spec("leader_group_escape_attempt", &evidence_path)
        .spawn_with_timeouts(short_timeouts());
    let evidence = read_evidence(&evidence_path);
    assert_eq!(evidence.leader_pid, evidence.pgid);
    assert_ne!(evidence.leader_current_pgid, evidence.pgid);
    assert_eq!(evidence.setpgid_errno, None, "macOS allowed the group move");
    let error = result.err();
    let group_absent = wait_for_group_absence(evidence.pgid, Duration::from_secs(2));
    let leader_absent = wait_for_pid_absence(evidence.leader_pid, Duration::from_secs(2));
    let member_absent = wait_for_pid_absence(evidence.member_pid, Duration::from_secs(2));
    let anchor_pgid = evidence.escaped_pid.expect("controlled foreign group");
    assert!(
        group_exists(anchor_pgid),
        "production cleanup crossed the immutable saved-PGID boundary"
    );
    emergency_cleanup(&evidence);
    let moved_group_absent =
        wait_for_group_absence(evidence.leader_current_pgid, Duration::from_secs(2));
    let error = error.expect("moved launch leader must be rejected");
    assert!(
        error.to_string().contains("pgid_escape"),
        "expected closed-set pgid_escape, got {error}"
    );
    assert!(
        group_absent && leader_absent && member_absent && moved_group_absent,
        "moved leader failure left owned processes: {evidence:?}"
    );
}

#[test]
fn term_resistant_pre_ready_failure_escalates_to_kill_and_proves_absence() {
    let _guard = process_test_guard();
    let directory = TestDir::new();
    let evidence_path = directory.evidence_path();
    let mut spec = launch_spec("eof", &evidence_path);
    spec.env.push((
        "JS_AGENT_PROCESS_GROUP_IGNORE_TERM".to_string(),
        "1".to_string(),
    ));
    let result = spec.spawn_with_timeouts(SidecarTimeouts::new(
        Duration::from_secs(1),
        Duration::from_millis(100),
        Duration::from_secs(1),
    ));
    let evidence = read_evidence(&evidence_path);
    let group_absent = wait_for_group_absence(evidence.pgid, Duration::from_secs(2));
    let leader_absent = !pid_exists(evidence.leader_pid);
    let member_absent = !pid_exists(evidence.member_pid);
    emergency_cleanup(&evidence);
    let error = result.expect_err("EOF must fail before readiness");
    assert!(
        !error.is_fatal(),
        "KILL cleanup should prove absence: {error}"
    );
    assert!(
        group_absent && leader_absent && member_absent,
        "TERM-resistant group survived KILL proof: {evidence:?}"
    );
}

#[test]
fn stdin_failure_cleans_entire_process_group() {
    let _guard = process_test_guard();
    let directory = TestDir::new();
    let evidence_path = directory.evidence_path();
    let mut spec = launch_spec("stdin_failure", &evidence_path);
    spec.stdin_payload = vec![b'x'; 4 * 1024 * 1024];
    let result = spec.spawn_with_timeouts(short_timeouts());
    let evidence = read_evidence(&evidence_path);
    let group_absent = wait_for_group_absence(evidence.pgid, Duration::from_secs(2));
    let leader_absent = !pid_exists(evidence.leader_pid);
    let member_absent = !pid_exists(evidence.member_pid);
    emergency_cleanup(&evidence);
    let error = result.expect_err("closed stdin must reject bootstrap write");
    assert!(
        error.to_string().contains("spawn_failed")
            || error.to_string().contains("sidecar_exit")
            || error.to_string().contains("sidecar_signal"),
        "expected closed-set spawn/exit code, got {error}"
    );
    assert!(
        group_absent && leader_absent && member_absent,
        "stdin error left owned processes: {evidence:?}"
    );
}

#[test]
fn ready_deadline_cleans_and_reaps_entire_group() {
    let _guard = process_test_guard();
    let directory = TestDir::new();
    let evidence_path = directory.evidence_path();
    let timeout = SidecarTimeouts::new(
        Duration::from_millis(100),
        Duration::from_millis(250),
        Duration::from_secs(1),
    );
    let result = launch_spec("timeout", &evidence_path).spawn_with_timeouts(timeout);
    let evidence = read_evidence(&evidence_path);
    let group_absent = wait_for_group_absence(evidence.pgid, Duration::from_secs(2));
    let leader_absent = !pid_exists(evidence.leader_pid);
    let member_absent = !pid_exists(evidence.member_pid);
    emergency_cleanup(&evidence);
    let error = result.expect_err("missing sentinel must reach the test deadline");
    assert!(
        group_absent && leader_absent && member_absent,
        "ready timeout left owned processes: {evidence:?}"
    );
    assert!(
        error.to_string().contains("ready_timeout")
            || error.to_string().contains("sidecar_exit")
            || error.to_string().contains("sidecar_signal"),
        "expected closed-set ready_timeout/exit, got {error}"
    );
}

#[test]
fn leader_exit_with_live_grandchild_is_cleaned_before_restart() {
    let _guard = process_test_guard();
    let directory = TestDir::new();
    let evidence_path = directory.evidence_path();
    let mut sidecar = launch_spec("ready_then_exit", &evidence_path)
        .spawn_with_timeouts(short_timeouts())
        .expect("valid ready sentinel");
    let evidence = read_evidence(&evidence_path);
    assert!(
        pid_exists(evidence.member_pid),
        "fixture grandchild must be live"
    );

    let deadline = Instant::now() + Duration::from_secs(2);
    let poll = loop {
        match sidecar.poll() {
            Ok(SidecarPoll::Running) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(10));
            }
            result => break result,
        }
    };
    let group_absent = wait_for_group_absence(evidence.pgid, Duration::from_secs(1));
    emergency_cleanup(&evidence);
    assert!(
        matches!(poll, Ok(SidecarPoll::ExitedAndGroupCleaned(_))),
        "monitor did not close the exited leader's group: {poll:?}"
    );
    assert!(group_absent, "poll allowed restart with old PGID live");
}

#[test]
fn drop_after_leader_exit_still_cleans_the_saved_process_group() {
    let _guard = process_test_guard();
    let directory = TestDir::new();
    let evidence_path = directory.evidence_path();
    let sidecar = launch_spec("ready_then_exit", &evidence_path)
        .spawn_with_timeouts(short_timeouts())
        .expect("valid ready sentinel");
    let evidence = read_evidence(&evidence_path);
    let deadline = Instant::now() + Duration::from_secs(2);
    while pid_exists(evidence.leader_pid) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }

    drop(sidecar);
    let group_absent = wait_for_group_absence(evidence.pgid, Duration::from_secs(1));
    emergency_cleanup(&evidence);
    assert!(group_absent, "Drop ignored a live descendant: {evidence:?}");
}

#[test]
fn uncertain_group_cleanup_is_fatal_not_restartable() {
    let _guard = process_test_guard();
    let directory = TestDir::new();
    let evidence_path = directory.evidence_path();
    let no_proof_time =
        SidecarTimeouts::new(Duration::from_millis(100), Duration::ZERO, Duration::ZERO);
    let error = launch_spec("timeout", &evidence_path)
        .spawn_with_timeouts(no_proof_time)
        .expect_err("zero proof deadline must fail closed");
    let evidence = read_evidence(&evidence_path);
    emergency_cleanup(&evidence);
    assert!(
        error.is_fatal(),
        "uncertain cleanup was restartable: {error}"
    );

    let now = Instant::now();
    let mut budget = RestartBudget::new(Duration::from_secs(300));
    assert_eq!(
        monitor_decision(MonitorEvent::Fatal(error), &mut budget, now),
        MonitorDecision::QuarantineThenFatal
    );
    assert_eq!(budget.record_restart(now), Some(Duration::from_secs(1)));
}
