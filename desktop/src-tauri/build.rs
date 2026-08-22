fn main() {
    println!("cargo:rerun-if-env-changed=JS_AGENT_DESKTOP_SOURCE_DIGEST");
    tauri_build::build()
}
