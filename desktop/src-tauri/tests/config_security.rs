use serde_json::Value;
use std::fs;
use std::path::PathBuf;

fn desktop_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("desktop root")
        .to_path_buf()
}

fn config() -> Value {
    let raw = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tauri.conf.json"))
        .expect("tauri.conf.json");
    serde_json::from_str(&raw).expect("valid JSON")
}

#[test]
fn bundle_is_app_only_with_one_target_triple_sidecar() {
    let config = config();
    assert_eq!(config.pointer("/bundle/active"), Some(&Value::Bool(true)));
    assert_eq!(
        config.pointer("/bundle/targets"),
        Some(&serde_json::json!(["app"]))
    );
    assert_eq!(
        config.pointer("/bundle/externalBin"),
        Some(&serde_json::json!(["binaries/js-agent-host"]))
    );
    assert_eq!(
        config.pointer("/bundle/createUpdaterArtifacts"),
        Some(&Value::Bool(false))
    );
}

#[test]
fn webview_has_no_remote_urls_or_general_ipc_capabilities() {
    let config = config();
    // The main window is pre-declared so a fallible sidecar cannot leave the
    // process without a recovery surface. It must load only the packaged
    // recovery page — never a remote URL.
    let windows = config
        .pointer("/app/windows")
        .and_then(|value| value.as_array())
        .expect("windows array");
    assert_eq!(windows.len(), 1);
    assert_eq!(windows[0].get("label"), Some(&serde_json::json!("main")));
    assert_eq!(
        windows[0].get("url"),
        Some(&serde_json::json!("recovery.html"))
    );
    let url = windows[0]
        .get("url")
        .and_then(|value| value.as_str())
        .expect("window url");
    assert!(!url.starts_with("http://") && !url.starts_with("https://"));
    assert!(!url.starts_with("data:"));

    let serialized = serde_json::to_string(&config).expect("serialize");
    assert!(!serialized.contains("remote.urls"));
    assert!(!serialized.contains("http://127.0.0.1"));
    // Schema metadata may use https://; window content must not.
    assert!(!serialized.contains("\"url\":\"http"));
    assert!(!serialized.contains("\"url\":\"https"));

    let capability_path = desktop_root().join("src-tauri/capabilities/main.json");
    let capability: Value =
        serde_json::from_str(&fs::read_to_string(capability_path).expect("capability manifest"))
            .expect("valid capability JSON");
    assert_eq!(
        capability.pointer("/permissions"),
        Some(&serde_json::json!([]))
    );
    assert!(capability.get("remote").is_none());
}

#[test]
fn csp_is_self_only_and_forbids_cdn_or_remote_connect() {
    let config = config();
    let csp = config
        .pointer("/app/security/csp")
        .and_then(|v| v.as_str())
        .expect("csp must exist");
    assert!(csp.contains("default-src 'self'"));
    assert!(csp.contains("object-src 'none'"));
    assert!(csp.contains("base-uri 'none'"));
    assert!(csp.contains("frame-ancestors 'none'"));
    // The initial Tauri shell CSP must not include wildcard WebSocket.
    // The Host middleware injects a precise port-specific CSP at runtime.
    assert!(!csp.contains("ws://127.0.0.1:*"));
    assert!(!csp.contains("cdn"));
    assert!(!csp.contains("https://"));
}

#[test]
fn appkit_state_restoration_is_disabled_before_tauri_run() {
    let main_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let source = fs::read_to_string(main_path).expect("desktop main source");
    let main_body = source
        .split_once("fn main() {")
        .map(|(_, body)| body)
        .expect("main function");
    let override_position = main_body
        .find("configure_process_local_appkit_state_restoration();")
        .expect("AppKit restoration override");
    let run_position = main_body.find("run()").expect("Tauri run call");
    assert!(override_position < run_position);
}

#[test]
fn dock_reopen_uses_the_same_reveal_helper_as_the_tray() {
    let main_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let source = fs::read_to_string(main_path).expect("desktop main source");

    assert!(source.contains("fn reveal_main_window("));
    assert!(source.contains("RunEvent::Reopen"));
    assert!(
        source.matches("reveal_main_window(").count() >= 3,
        "definition, tray show, and Dock reopen must share one helper"
    );

    let reveal_body = source
        .split_once("fn reveal_main_window(")
        .and_then(|(_, rest)| rest.split_once("fn show_recovery("))
        .map(|(body, _)| body)
        .expect("reveal helper body");
    let unminimize = reveal_body.find("window.unminimize()").expect("unminimize");
    let show = reveal_body.find("window.show()").expect("show");
    let focus = reveal_body.find("window.set_focus()").expect("focus");
    assert!(unminimize < show && show < focus);
    assert!(!reveal_body.contains("navigate("));
}

#[test]
fn recovery_page_is_chinese_dynamic_and_uses_only_exact_internal_actions() {
    let recovery_path = desktop_root().join("src/recovery.html");
    let source = fs::read_to_string(recovery_path).expect("recovery page");

    assert!(source.contains("<html lang=\"zh-CN\">"));
    assert!(source.contains("hashchange"));
    assert!(source.contains("正在启动"));
    assert!(source.contains("正在自动恢复"));
    assert!(source.contains("重新连接"));
    assert!(source.contains("无法自动恢复"));
    assert!(source.contains("tauri://localhost/__recovery_action__/retry"));
    assert!(source.contains("tauri://localhost/__recovery_action__/quit"));
    assert!(!source.contains("__TAURI__"));
    assert!(!source.contains("invoke("));
}

#[test]
fn native_recovery_actions_are_intercepted_and_quit_is_state_authorized() {
    let main_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/main.rs");
    let source = fs::read_to_string(main_path).expect("desktop main source");

    let navigation = source
        .split_once(".on_navigation(move |candidate|")
        .and_then(|(_, rest)| rest.split_once(".on_new_window"))
        .map(|(body, _)| body)
        .expect("navigation handler");
    assert!(navigation.contains("recovery_action_for_url(candidate)"));
    assert!(navigation.contains("request_recovery_quit"));
    assert!(navigation.contains("return false;"));
    assert!(!navigation.contains("thread::spawn"));
    assert!(!navigation.contains("navigation_app.exit(0)"));
}
