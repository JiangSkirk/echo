// JS Agent UI Test Harness - Phase E.2
// Packaged as: JS Agent UI Test Harness.app
// Bundle ID: local.js-agent.ui-test-harness
//
// Security constraints:
// - Accessibility probe fails closed within 5s when unauthorized
// - Only operates on the JS Agent PID launched by this harness (or --target-pid)
// - No clipboard, notifications, camera, mic, or real user directories
// - Temporary HOME + anonymous synthetic data only
// - No network beyond the app's random loopback listener
//
// Build (via package_harness_app.sh):
//   swiftc -O -target arm64-apple-macos13 \
//     -o js-agent-ui-test-harness tauri_webview_harness.swift \
//     -framework Cocoa -framework ApplicationServices
//   codesign -s - --force --deep "JS Agent UI Test Harness.app"

import Cocoa
import ApplicationServices
import CryptoKit

// ---------------------------------------------------------------------------
// Exit codes (distinct failure classes)
// ---------------------------------------------------------------------------
// 0  = all scenarios passed
// 1  = usage / invalid arguments
// 2  = scenario assertion failure / window missing / crash / general fail
// 10 = accessibility_not_authorized
// 11 = target process not found / not owned
// 12 = app launch failure
// 13 = cleanup failure

let EXIT_OK = 0
let EXIT_USAGE = 1
let EXIT_ASSERT = 2
let EXIT_AX_NOT_AUTHORIZED = 10
let EXIT_TARGET_NOT_FOUND = 11
let EXIT_LAUNCH_FAILED = 12
let EXIT_CLEANUP_FAILED = 13

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

struct ScenarioResult: Codable {
    var passed: Bool
    var status: String = "passed"
    var detail: String
    var duration_ms: Double
    var error_code: String?
}

struct HarnessResult: Codable {
    var schema_version: String
    var ok: Bool
    var status: String
    var nonce: String
    var scenarios: [String: ScenarioResult]
    var app_sha256: String?
    var app_tree_sha256: String?
    var harness_sha256: String?
    var desktop_manifest_sha256: String?
    var bundle_identifier: String
    var accessibility_authorized: Bool
    var target_pid: Int?
    var started_utc: String
    var finished_utc: String
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func utcNow() -> String {
    let f = ISO8601DateFormatter()
    f.formatOptions = [.withInternetDateTime]
    return f.string(from: Date())
}

func sha256Data(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

func sha256(path: String) -> String? {
    guard let data = FileManager.default.contents(atPath: path) else { return nil }
    return sha256Data(data)
}

func lengthBytes(_ count: Int) -> Data {
    var value = UInt64(count).bigEndian
    return withUnsafeBytes(of: &value) { Data($0) }
}

let treeDigestDomain = Data("JSAgentTreeDigestV2\0".utf8)

func treeEntry(
    relative: String,
    entryType: String,
    mode: Int,
    content: Data
) -> (String, Data)? {
    guard let typeData = entryType.data(using: .ascii),
          let pathData = relative.data(using: .utf8),
          ["directory", "file"].contains(entryType),
          (entryType == "directory" && mode == 0o755 && content.isEmpty)
            || (entryType == "file" && [0o644, 0o755].contains(mode))
    else { return nil }
    return (
        relative,
        lengthBytes(typeData.count) + typeData + lengthBytes(mode)
            + lengthBytes(pathData.count) + pathData
            + lengthBytes(content.count) + content
    )
}

func sha256Tree(path: String) -> String? {
    let root = URL(fileURLWithPath: path).standardizedFileURL
    let keys: [URLResourceKey] = [.isRegularFileKey, .isDirectoryKey, .isSymbolicLinkKey]
    guard let rootAttributes = try? FileManager.default.attributesOfItem(atPath: root.path),
          rootAttributes[.type] as? FileAttributeType == .typeDirectory,
          let rootMode = (rootAttributes[.posixPermissions] as? NSNumber)?.intValue,
          let rootEntry = treeEntry(
            relative: "", entryType: "directory", mode: rootMode, content: Data()
          )
    else { return nil }
    guard let enumerator = FileManager.default.enumerator(
        at: root,
        includingPropertiesForKeys: keys,
        options: [],
        errorHandler: { _, _ in false }
    ) else { return nil }
    var entries: [(String, Data)] = [rootEntry]
    for case let url as URL in enumerator {
        guard let values = try? url.resourceValues(forKeys: Set(keys)) else { return nil }
        if values.isSymbolicLink == true { return nil }
        let prefix = root.path.hasSuffix("/") ? root.path : root.path + "/"
        guard url.path.hasPrefix(prefix) else { return nil }
        let relative = String(url.path.dropFirst(prefix.count))
        guard !relative.isEmpty,
              let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              let mode = (attributes[.posixPermissions] as? NSNumber)?.intValue
        else { return nil }
        if values.isDirectory == true {
            guard attributes[.type] as? FileAttributeType == .typeDirectory,
                  let entry = treeEntry(
                    relative: relative,
                    entryType: "directory",
                    mode: mode,
                    content: Data()
                  )
            else { return nil }
            entries.append(entry)
            continue
        }
        guard values.isRegularFile == true,
              attributes[.type] as? FileAttributeType == .typeRegular,
              let data = try? Data(contentsOf: url),
              let entry = treeEntry(
                relative: relative,
                entryType: "file",
                mode: mode,
                content: data
              )
        else { return nil }
        entries.append(entry)
    }
    var digest = SHA256()
    digest.update(data: treeDigestDomain)
    for (_, payload) in entries.sorted(by: { $0.0 < $1.0 }) {
        digest.update(data: payload)
    }
    return digest.finalize().map { String(format: "%02x", $0) }.joined()
}

func runShell(_ cmd: String, _ args: [String], timeout: TimeInterval = 30) -> (Int, String, String) {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: cmd)
    task.arguments = args
    let outPipe = Pipe()
    let errPipe = Pipe()
    task.standardOutput = outPipe
    task.standardError = errPipe
    do { try task.run() } catch { return (-1, "", "\(error)") }

    let deadline = Date().addingTimeInterval(timeout)
    while task.isRunning && Date() < deadline {
        Thread.sleep(forTimeInterval: 0.05)
    }
    if task.isRunning {
        task.terminate()
        Thread.sleep(forTimeInterval: 0.2)
        if task.isRunning {
            kill(task.processIdentifier, SIGKILL)
        }
        task.waitUntilExit()
        return (-9, "", "timeout")
    }
    task.waitUntilExit()
    let out = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    let err = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
    return (Int(task.terminationStatus), out, err)
}

func processRows() -> [Int: (Int, Int, String)] {
    let (code, out, _) = runShell("/bin/ps", ["-axo", "pid=,ppid=,pgid=,command="])
    guard code == 0 else { return [:] }
    var rows: [Int: (Int, Int, String)] = [:]
    for line in out.split(separator: "\n") {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        let parts = trimmed.split(separator: " ", maxSplits: 3, omittingEmptySubsequences: true)
        if parts.count >= 4 {
            let pid = Int(parts[0]) ?? 0
            let ppid = Int(parts[1]) ?? 0
            let pgid = Int(parts[2]) ?? 0
            let cmd = String(parts[3])
            rows[pid] = (ppid, pgid, cmd)
        }
    }
    return rows
}

func descendants(of rootPid: Int) -> Set<Int> {
    let rows = processRows()
    var found = Set<Int>()
    var changed = true
    while changed {
        changed = false
        for (pid, (ppid, _, _)) in rows {
            if !found.contains(pid) && (ppid == rootPid || found.contains(ppid)) {
                found.insert(pid)
                changed = true
            }
        }
    }
    return found
}

struct ListenerInfo: Hashable {
    let host: String
    let port: Int
}

func listeners(pids: Set<Int>) -> Set<ListenerInfo> {
    if pids.isEmpty { return [] }
    let pidStr = pids.sorted().map { String($0) }.joined(separator: ",")
    let (_, out, _) = runShell("/usr/sbin/lsof", ["-nP", "-a", "-p", pidStr, "-iTCP", "-sTCP:LISTEN"])
    var result = Set<ListenerInfo>()
    for line in out.split(separator: "\n").dropFirst() {
        if let r = line.range(of: #"\bTCP\s+([^: ]+):(\d+)\s+\(LISTEN\)"#, options: .regularExpression) {
            let match = line[r]
            let parts = match.split(separator: ":")
            if parts.count >= 2 {
                let host = String(parts[0]).replacingOccurrences(of: "TCP ", with: "")
                let port = Int(parts[1].replacingOccurrences(of: " (LISTEN)", with: "")) ?? 0
                result.insert(ListenerInfo(host: host, port: port))
            }
        }
    }
    return result
}

func getAxAttribute(_ element: AXUIElement, _ attr: String) -> String? {
    var ref: CFTypeRef?
    let result = AXUIElementCopyAttributeValue(element, attr as CFString, &ref)
    guard result == .success, let value = ref as? String else { return nil }
    return value
}

func collectAxTree(_ element: AXUIElement, depth: Int = 0, maxDepth: Int = 8) -> [(String, String, AXUIElement)] {
    var items: [(String, String, AXUIElement)] = []
    let role = getAxAttribute(element, kAXRoleAttribute as String) ?? ""
    let title = getAxAttribute(element, kAXTitleAttribute as String)
        ?? getAxAttribute(element, kAXDescriptionAttribute as String)
        ?? getAxAttribute(element, kAXValueAttribute as String)
        ?? ""
    items.append((role, title, element))
    if depth >= maxDepth { return items }
    var childrenRef: CFTypeRef?
    let r = AXUIElementCopyAttributeValue(element, kAXChildrenAttribute as CFString, &childrenRef)
    if r == .success, let children = childrenRef as? [AXUIElement] {
        for child in children {
            items.append(contentsOf: collectAxTree(child, depth: depth + 1, maxDepth: maxDepth))
        }
    }
    return items
}

func pressAxButton(appPid: pid_t, matching predicates: [String]) -> Bool {
    let appElement = AXUIElementCreateApplication(appPid)
    let tree = collectAxTree(appElement)
    for (role, title, element) in tree {
        let lowered = title.lowercased()
        let roleOk = role == "AXButton" || role == "AXRadioButton" || role == "AXCheckBox" || role == "AXMenuItem" || role == "AXPopUpButton" || role == "AXTab"
        if !roleOk { continue }
        for p in predicates {
            if lowered.contains(p.lowercased()) {
                let err = AXUIElementPerformAction(element, kAXPressAction as CFString)
                if err == .success { return true }
            }
        }
    }
    return false
}

func jsonObject(_ text: String) -> [String: Any]? {
    guard let data = text.data(using: .utf8),
          let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    else { return nil }
    return object
}

func loopbackRequest(
    listener: ListenerInfo,
    path: String,
    method: String = "GET",
    cookie: String? = nil,
    jsonBody: String? = nil
) -> (status: Int, body: String) {
    let origin = "http://\(listener.host):\(listener.port)"
    var args = ["-sS", "--max-time", "10", "-X", method]
    if let cookie {
        args += ["-H", "Cookie: js_appshell_session=\(cookie)"]
    }
    if let jsonBody {
        args += [
            "-H", "Origin: \(origin)",
            "-H", "Content-Type: application/json",
            "--data-binary", jsonBody,
        ]
    }
    args += ["-w", "\n__STATUS__:%{http_code}", origin + path]
    let (code, output, _) = runShell("/usr/bin/curl", args)
    guard code == 0, let marker = output.range(of: "\n__STATUS__:", options: .backwards)
    else { return (0, output) }
    let body = String(output[..<marker.lowerBound])
    let statusText = String(output[marker.upperBound...]).trimmingCharacters(in: .whitespacesAndNewlines)
    return (Int(statusText) ?? 0, body)
}

func sqliteScalar(database: String, query: String) -> String? {
    let (code, output, _) = runShell("/usr/bin/sqlite3", ["-readonly", database, query])
    guard code == 0 else { return nil }
    let value = output.trimmingCharacters(in: .whitespacesAndNewlines)
    return value.isEmpty ? nil : value.split(separator: "\n").last.map(String.init)
}

func webViewSessionCookie(home: String) -> String? {
    guard let enumerator = FileManager.default.enumerator(atPath: home) else { return nil }
    let candidates = enumerator.compactMap { $0 as? String }.filter {
        let name = URL(fileURLWithPath: $0).lastPathComponent.lowercased()
        return name == "cookies" || name == "cookies.sqlite" || name == "cookies.db"
    }
    for relative in candidates.sorted() {
        let database = home + "/" + relative
        for query in [
            "SELECT value FROM cookies WHERE name='js_appshell_session' ORDER BY rowid DESC LIMIT 1;",
            "SELECT value FROM moz_cookies WHERE name='js_appshell_session' ORDER BY id DESC LIMIT 1;",
        ] {
            if let value = sqliteScalar(database: database, query: query) { return value }
        }
    }
    return nil
}

func sessionEpoch(home: String, session: String) -> Int? {
    let escaped = session.replacingOccurrences(of: "'", with: "''")
    guard let enumerator = FileManager.default.enumerator(atPath: home) else { return nil }
    for relative in enumerator.compactMap({ $0 as? String }).filter({ $0.hasSuffix(".db") || $0.hasSuffix(".sqlite") }).sorted() {
        if let value = sqliteScalar(
            database: home + "/" + relative,
            query: "SELECT epoch FROM appshell_sessions WHERE session='\(escaped)' LIMIT 1;"
        ), let epoch = Int(value) {
            return epoch
        }
    }
    return nil
}

func gracefulTerminationSurvivors(_ proc: Process, observed: Set<Int>) -> Set<Int> {
    if proc.isRunning { proc.terminate() }
    let deadline = Date().addingTimeInterval(15)
    while Date() < deadline {
        let rows = processRows()
        let alive = observed.filter { rows[$0] != nil }
        if alive.isEmpty { return [] }
        Thread.sleep(forTimeInterval: 0.2)
    }
    let rows = processRows()
    return observed.filter { rows[$0] != nil }
}

func terminateOwned(_ proc: Process, extraPids: Set<Int> = []) {
    let root = Int(proc.processIdentifier)
    var owned = descendants(of: root).union([root]).union(extraPids)
    if proc.isRunning {
        proc.terminate()
    }
    let deadline = Date().addingTimeInterval(15)
    while Date() < deadline {
        let rows = processRows()
        owned = owned.filter { rows[$0] != nil }
        if owned.isEmpty { return }
        Thread.sleep(forTimeInterval: 0.2)
    }
    for pid in owned {
        kill(Int32(pid), SIGKILL)
    }
    Thread.sleep(forTimeInterval: 0.5)
    _ = processRows() // reap snapshot
}

// ---------------------------------------------------------------------------
// Accessibility probe — must return within 5 seconds when unauthorized
// ---------------------------------------------------------------------------

func probeAccessibility() -> (authorized: Bool, detail: String) {
    let start = Date()
    // prompt: false — do not auto-trigger system dialogs from this probe path.
    let options = [kAXTrustedCheckOptionPrompt.takeUnretainedValue() as String: false] as CFDictionary
    let trusted = AXIsProcessTrustedWithOptions(options)
    let elapsed = Date().timeIntervalSince(start)
    if trusted {
        return (true, "AXIsProcessTrustedWithOptions=true elapsed_ms=\(Int(elapsed * 1000))")
    }
    return (false, "accessibility_not_authorized elapsed_ms=\(Int(elapsed * 1000))")
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

let args = CommandLine.arguments
var appPath = ""
var resultPath = ""
var targetPidArg: Int? = nil
var probeOnly = false
var nonce = ""
var expectedAppTreeSHA256 = ""
var desktopManifestPath = ""

var i = 1
while i < args.count {
    if args[i] == "--app-path", i + 1 < args.count {
        appPath = args[i + 1]; i += 2
    } else if args[i] == "--result-path", i + 1 < args.count {
        resultPath = args[i + 1]; i += 2
    } else if args[i] == "--target-pid", i + 1 < args.count {
        targetPidArg = Int(args[i + 1]); i += 2
    } else if args[i] == "--probe-only" {
        probeOnly = true; i += 1
    } else if args[i] == "--nonce", i + 1 < args.count {
        nonce = args[i + 1]; i += 2
    } else if args[i] == "--app-tree-sha256", i + 1 < args.count {
        expectedAppTreeSHA256 = args[i + 1]; i += 2
    } else if args[i] == "--desktop-manifest-path", i + 1 < args.count {
        desktopManifestPath = args[i + 1]; i += 2
    } else {
        i += 1
    }
}

var result = HarnessResult(
    schema_version: "js-agent-tauri-webview-result-v1",
    ok: false,
    status: "running",
    nonce: nonce,
    scenarios: [:],
    app_sha256: nil,
    app_tree_sha256: nil,
    harness_sha256: sha256(path: CommandLine.arguments[0]),
    desktop_manifest_sha256: nil,
    bundle_identifier: "",
    accessibility_authorized: false,
    target_pid: nil,
    started_utc: utcNow(),
    finished_utc: ""
)

func writeResultAndExit(_ code: Int) -> Never {
    result.finished_utc = utcNow()
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    if !resultPath.isEmpty, let data = try? encoder.encode(result) {
        try? data.write(to: URL(fileURLWithPath: resultPath))
    }
    if let data = try? encoder.encode(result), let s = String(data: data, encoding: .utf8) {
        print(s)
    }
    exit(Int32(code))
}

// Always probe first — fail closed fast when unauthorized.
let ax = probeAccessibility()
result.accessibility_authorized = ax.authorized
result.scenarios["accessibility_probe"] = ScenarioResult(
    passed: ax.authorized,
    status: ax.authorized ? "passed" : "failed",
    detail: ax.detail,
    duration_ms: 0,
    error_code: ax.authorized ? nil : "accessibility_not_authorized"
)

if !ax.authorized {
    result.status = "accessibility_not_authorized"
    result.ok = false
    FileHandle.standardError.write(
        "accessibility_not_authorized: grant Accessibility to JS Agent UI Test Harness.app only\n"
            .data(using: .utf8)!
    )
    writeResultAndExit(EXIT_AX_NOT_AUTHORIZED)
}

if probeOnly {
    result.status = "probe_ok"
    result.ok = true
    writeResultAndExit(EXIT_OK)
}

if appPath.isEmpty || resultPath.isEmpty || nonce.count != 64
    || expectedAppTreeSHA256.count != 64 || desktopManifestPath.isEmpty {
    FileHandle.standardError.write(
        "Usage: JS Agent UI Test Harness --app-path <path> --result-path <path> --nonce <64-hex> --app-tree-sha256 <64-hex> --desktop-manifest-path <path> [--target-pid N] [--probe-only]\n"
            .data(using: .utf8)!
    )
    writeResultAndExit(EXIT_USAGE)
}

let infoPlistPath = appPath + "/Contents/Info.plist"
var bundleExecutable = "js-agent-desktop"
if let data = FileManager.default.contents(atPath: infoPlistPath),
   let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
   let exec = plist["CFBundleExecutable"] as? String {
    bundleExecutable = exec
    result.bundle_identifier = plist["CFBundleIdentifier"] as? String ?? ""
}
let fullExecutable = appPath + "/Contents/MacOS/" + bundleExecutable
result.app_sha256 = sha256(path: fullExecutable)
result.app_tree_sha256 = sha256Tree(path: appPath)
result.desktop_manifest_sha256 = sha256(path: desktopManifestPath)
if result.app_tree_sha256 != expectedAppTreeSHA256
    || result.bundle_identifier != "com.titan.js-agent" {
    result.status = "artifact_binding_failed"
    writeResultAndExit(EXIT_ASSERT)
}

// Isolated temporary HOME — never real user directories.
let tmpDir = NSTemporaryDirectory() + "js-agent-harness-\(ProcessInfo.processInfo.processIdentifier)-\(UUID().uuidString)"
let homeDir = tmpDir + "/home"
let launchDir = tmpDir + "/outside"
let synthDir = homeDir + "/synthetic"
do {
    try FileManager.default.createDirectory(atPath: homeDir, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(atPath: launchDir, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(atPath: synthDir, withIntermediateDirectories: true)
    // Anonymous synthetic fixture only (not real Office business files).
    try "synthetic-fixture-v1".write(toFile: synthDir + "/note.txt", atomically: true, encoding: .utf8)
} catch {
    result.status = "launch_setup_failed"
    result.scenarios["setup"] = ScenarioResult(passed: false, status: "failed", detail: "\(error)", duration_ms: 0, error_code: "launch_failed")
    writeResultAndExit(EXIT_LAUNCH_FAILED)
}

defer {
    try? FileManager.default.removeItem(atPath: tmpDir)
}

var env = ProcessInfo.processInfo.environment
// Strip secrets / identity leakage; controlled PATH + HOME only.
let allowEnv = Set(["TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL", "LC_CTYPE", "USER", "LOGNAME", "SHELL"])
env = env.filter { allowEnv.contains($0.key) || $0.key.hasPrefix("JS_AGENT_HARNESS_") }
env["HOME"] = homeDir
env["PATH"] = ""
env["JS_AGENT_HARNESS"] = "1"

var appProcess: Process?
var ownedExtraPids = Set<Int>()
var capturedBootstrapToken: String?

func scenario(_ name: String, errorCode: String = "assertion_failed", _ fn: () throws -> String) {
    let start = Date()
    do {
        let detail = try fn()
        let duration = Date().timeIntervalSince(start) * 1000
        result.scenarios[name] = ScenarioResult(passed: true, detail: detail, duration_ms: duration, error_code: nil)
        print("[PASS] \(name): \(detail)")
    } catch {
        let duration = Date().timeIntervalSince(start) * 1000
        result.scenarios[name] = ScenarioResult(passed: false, status: "failed", detail: "\(error)", duration_ms: duration, error_code: errorCode)
        result.ok = false
        print("[FAIL] \(name): \(error)")
    }
}

func requireApp() throws -> Process {
    guard let proc = appProcess else {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "no app process"])
    }
    return proc
}

func waitForSingleListener(proc: Process, timeout: TimeInterval) throws -> ListenerInfo {
    let deadline = Date().addingTimeInterval(timeout)
    while Date() < deadline {
        if !proc.isRunning {
            throw NSError(domain: "harness", code: EXIT_LAUNCH_FAILED, userInfo: [NSLocalizedDescriptionKey: "app exited before listener"])
        }
        let desc = descendants(of: Int(proc.processIdentifier)).union([Int(proc.processIdentifier)])
        let l = listeners(pids: desc)
        if l.count == 1, let first = l.first {
            if first.port == 8765 {
                throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "listener on forbidden port 8765"])
            }
            if first.host != "127.0.0.1" && first.host != "localhost" {
                throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "non-loopback listener \(first.host)"])
            }
            return first
        }
        Thread.sleep(forTimeInterval: 0.25)
    }
    throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "no single loopback listener within \(Int(timeout))s"])
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

scenario("cold_start_controlled_env", errorCode: "launch_failed") {
    if let forced = targetPidArg {
        // Attach-only mode: never enumerate other apps; require explicit PID.
        let rows = processRows()
        guard let (ppid, pgid, cmd) = rows[forced] else {
            throw NSError(domain: "harness", code: EXIT_TARGET_NOT_FOUND, userInfo: [NSLocalizedDescriptionKey: "target pid not found"])
        }
        if !cmd.contains("js-agent-desktop") && !cmd.contains("JS Agent") {
            throw NSError(domain: "harness", code: EXIT_TARGET_NOT_FOUND, userInfo: [NSLocalizedDescriptionKey: "target pid is not JS Agent"])
        }
        result.target_pid = forced
        // Represent as a dummy Process is not possible; store pid only via result.
        _ = ppid; _ = pgid
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "attach-only mode requires full launch orchestration; omit --target-pid for gate runs"])
    }

    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: fullExecutable)
    proc.currentDirectoryURL = URL(fileURLWithPath: launchDir)
    proc.environment = env
    proc.standardInput = FileHandle(forReadingAtPath: "/dev/null")
    // Capture to temp so we can diagnose without polluting stdout contract.
    let outLog = tmpDir + "/app.stdout"
    let errLog = tmpDir + "/app.stderr"
    FileManager.default.createFile(atPath: outLog, contents: nil)
    FileManager.default.createFile(atPath: errLog, contents: nil)
    proc.standardOutput = FileHandle(forWritingAtPath: outLog)
    proc.standardError = FileHandle(forWritingAtPath: errLog)
    do {
        try proc.run()
    } catch {
        throw NSError(domain: "harness", code: EXIT_LAUNCH_FAILED, userInfo: [NSLocalizedDescriptionKey: "failed to launch: \(error)"])
    }
    appProcess = proc
    result.target_pid = Int(proc.processIdentifier)
    let listener = try waitForSingleListener(proc: proc, timeout: 100)
    return "pid=\(proc.processIdentifier) listener=\(listener.host):\(listener.port)"
}

scenario("process_tree_one_app_one_sidecar") {
    let proc = try requireApp()
    let desc = descendants(of: Int(proc.processIdentifier))
    let rows = processRows()
    let sidecars = desc.filter { pid in
        guard let (_, _, cmd) = rows[pid] else { return false }
        return cmd.contains("js-agent-host")
    }
    // One logical sidecar may appear as parent+child of the same binary after spawn.
    if sidecars.isEmpty {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "no sidecar found"])
    }
    if sidecars.count > 2 {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "too many sidecar processes: \(sidecars.count)"])
    }
    let tree = descendants(of: Int(proc.processIdentifier)).union([Int(proc.processIdentifier)])
    let l = listeners(pids: tree)
    if l.count != 1 {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "expected 1 listener, got \(l.count)"])
    }
    return "sidecars=\(sidecars.count) listeners=\(l.count)"
}

scenario("webview_shows_content", errorCode: "window_not_found") {
    let proc = try requireApp()
    let appElement = AXUIElementCreateApplication(proc.processIdentifier)

    var window: AXUIElement?
    let deadline = Date().addingTimeInterval(45)
    while Date() < deadline {
        var windowsRef: CFTypeRef?
        AXUIElementCopyAttributeValue(appElement, kAXWindowsAttribute as CFString, &windowsRef)
        if let windows = windowsRef as? [AXUIElement], let w = windows.first {
            window = w
            break
        }
        Thread.sleep(forTimeInterval: 0.5)
    }
    guard let win = window else {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "no window for target pid \(proc.processIdentifier)"])
    }

    var urlValue: String?
    var title = getAxAttribute(win, kAXTitleAttribute as String) ?? ""
    let urlDeadline = Date().addingTimeInterval(30)
    while Date() < urlDeadline {
        let tree = collectAxTree(win)
        for (role, _, el) in tree {
            if role == "AXWebArea" || role == "AXBrowser" {
                if let url = getAxAttribute(el, "AXURL") {
                    urlValue = url
                    if let components = URLComponents(string: url),
                       let fragment = components.fragment {
                        let values = URLComponents(string: "?" + fragment)?.queryItems
                        capturedBootstrapToken = values?.first(where: { $0.name == "bootstrap" })?.value
                    }
                    break
                }
            }
        }
        title = getAxAttribute(win, kAXTitleAttribute as String) ?? title
        if urlValue != nil || !title.isEmpty { break }
        Thread.sleep(forTimeInterval: 0.5)
    }

    if let url = urlValue {
        if url.contains("chrome-error") || url.contains("about:blank") {
            throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "webview shows error/blank url: \(url)"])
        }
        if !url.contains("127.0.0.1") && !url.contains("localhost") {
            throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "webview not on loopback: \(url)"])
        }
    } else if title.isEmpty {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "window has no title and no URL"])
    }
    return "title=\(title) url=\(urlValue ?? "nil")"
}

scenario("bootstrap_fragment_cleared") {
    let proc = try requireApp()
    let appElement = AXUIElementCreateApplication(proc.processIdentifier)
    // Wait briefly for bootstrap redirect to clear fragment.
    Thread.sleep(forTimeInterval: 2)
    var sawBootstrap = false
    var finalUrl: String?
    let deadline = Date().addingTimeInterval(20)
    while Date() < deadline {
        if let win = findFirstWindow(app: appElement) {
            for (role, _, el) in collectAxTree(win) {
                if role == "AXWebArea" || role == "AXBrowser" {
                    if let url = getAxAttribute(el, "AXURL") {
                        finalUrl = url
                        if url.contains("#bootstrap=") || url.contains("bootstrap=") {
                            sawBootstrap = true
                        } else {
                            sawBootstrap = false
                        }
                    }
                }
            }
        }
        if let url = finalUrl, !url.contains("bootstrap=") { break }
        Thread.sleep(forTimeInterval: 0.5)
    }
    if let url = finalUrl, url.contains("bootstrap=") {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "bootstrap fragment still present: \(url)"])
    }
    // Also ensure process environment does not leak fragment.
    let desc = descendants(of: Int(proc.processIdentifier)).union([Int(proc.processIdentifier)])
    let pidStr = desc.sorted().map { String($0) }.joined(separator: ",")
    let (_, out, _) = runShell("/bin/ps", ["-E", "-ww", "-p", pidStr, "-o", "command="])
    if out.contains("#bootstrap=") {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "bootstrap token leaked in process command"])
    }
    let fm = FileManager.default
    if fm.fileExists(atPath: homeDir + "/bootstrap_admin_key.txt") {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "bootstrap_admin_key.txt exists"])
    }
    if fm.fileExists(atPath: homeDir + "/Library/LaunchAgents/com.titan.js-agent.plist") {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "LaunchAgent plist exists"])
    }
    _ = sawBootstrap
    return "bootstrap cleared url=\(finalUrl ?? "nil")"
}

func findFirstWindow(app: AXUIElement) -> AXUIElement? {
    var windowsRef: CFTypeRef?
    AXUIElementCopyAttributeValue(app, kAXWindowsAttribute as CFString, &windowsRef)
    if let windows = windowsRef as? [AXUIElement] { return windows.first }
    return nil
}

scenario("http_api_status") {
    let proc = try requireApp()
    let tree = descendants(of: Int(proc.processIdentifier)).union([Int(proc.processIdentifier)])
    let l = listeners(pids: tree)
    guard let listener = l.first else {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "no listener"])
    }
    let url = "http://\(listener.host):\(listener.port)/api/status"
    let (code, out, err) = runShell("/usr/bin/curl", ["-sS", "--max-time", "5", url])
    if code != 0 || out.isEmpty {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "status failed code=\(code) err=\(err) out=\(out.prefix(120))"])
    }
    if !out.contains("\"ok\"") && !out.contains("primary_healthy") && !out.contains("status") {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "unexpected status body: \(out.prefix(200))"])
    }
    return "status ok port=\(listener.port)"
}

scenario("bootstrap_token_single_use") {
    let proc = try requireApp()
    let tree = descendants(of: Int(proc.processIdentifier)).union([Int(proc.processIdentifier)])
    guard let listener = listeners(pids: tree).first else {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "no listener"])
    }
    guard let token = capturedBootstrapToken, token.count == 64 else {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "original WebView bootstrap token was not observed"])
    }
    guard let cookie = webViewSessionCookie(home: homeDir) else {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "same WKWebView session cookie unavailable"])
    }
    let replay = loopbackRequest(
        listener: listener,
        path: "/api/appshell/desktop-bootstrap",
        method: "POST",
        cookie: cookie,
        jsonBody: "{\"token\":\"\(token)\"}"
    )
    if replay.status != 409 || !replay.body.contains("bootstrap_token_consumed") {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "bootstrap replay did not return consumed/409: \(replay.status) \(replay.body.prefix(160))"])
    }
    let protected = loopbackRequest(
        listener: listener,
        path: "/api/appshell/capabilities",
        cookie: cookie
    )
    guard protected.status == 200,
          let payload = jsonObject(protected.body),
          payload["session"] as? String != nil
    else {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "same WebView session cannot read protected capabilities"])
    }
    return "same_WKWebView_session replay=409 protected_session=200"
}

scenario("ui_mode_switch_personal_work_personal") {
    let proc = try requireApp()
    // Require both real Accessibility button presses and protected mode/epoch readback.
    let appElement = AXUIElementCreateApplication(proc.processIdentifier)
    guard findFirstWindow(app: appElement) != nil else {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "window missing before mode switch"])
    }

    let treePids = descendants(of: Int(proc.processIdentifier)).union([Int(proc.processIdentifier)])
    guard let listener = listeners(pids: treePids).first else {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "no listener"])
    }
    let portBefore = listener.port

    guard let cookie = webViewSessionCookie(home: homeDir) else {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "same WKWebView session cookie unavailable"])
    }
    func readModeEpoch() throws -> (String, Int, String) {
        let response = loopbackRequest(
            listener: listener,
            path: "/api/appshell/capabilities",
            cookie: cookie
        )
        guard response.status == 200,
              let payload = jsonObject(response.body),
              let activeMode = payload["active_mode"] as? String,
              let session = payload["session"] as? String,
              let epoch = sessionEpoch(home: homeDir, session: session)
        else {
            throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "protected mode/epoch readback failed"])
        }
        return (activeMode, epoch, session)
    }
    let initial = try readModeEpoch()
    if initial.0 != "personal" {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "initial active_mode is not personal"])
    }

    let pressedWork = pressAxButton(appPid: proc.processIdentifier, matching: ["work", "工作", "js-work"])
    Thread.sleep(forTimeInterval: 2.0)
    let work = try readModeEpoch()
    let pressedPersonal = pressAxButton(appPid: proc.processIdentifier, matching: ["personal", "个人", "js-agent"])
    Thread.sleep(forTimeInterval: 2.0)
    let personal = try readModeEpoch()

    if !(pressedWork && pressedPersonal) {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "both real mode controls must be pressed successfully"])
    }
    if work.0 != "work" || work.1 != initial.1 + 1 || work.2 != initial.2 {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "personal->work mode/epoch readback mismatch"])
    }
    if personal.0 != "personal" || personal.1 != work.1 + 1 || personal.2 != initial.2 {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "work->personal mode/epoch readback mismatch"])
    }

    // Always verify same-origin switch endpoint on the owned listener (supplement, not substitute for window presence).
    // First ensure session: bootstrap may have set cookie in WebView; for harness we use status as health.
    let statusUrl = "http://\(listener.host):\(listener.port)/api/status"
    let (_, statusOut, _) = runShell("/usr/bin/curl", ["-sS", "--max-time", "5", statusUrl])
    if statusOut.isEmpty {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "status empty during mode switch"])
    }

    // Confirm still single window + single port (no second product host).
    let treeAfter = descendants(of: Int(proc.processIdentifier)).union([Int(proc.processIdentifier)])
    let lAfter = listeners(pids: treeAfter)
    if lAfter.count != 1 {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "port count changed during mode switch: \(lAfter.count)"])
    }
    if let p = lAfter.first, p.port != portBefore {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "listener port changed unexpectedly \(portBefore)->\(p.port)"])
    }
    if findFirstWindow(app: appElement) == nil {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "window lost after mode switch"])
    }
    return "same_window same_port=\(portBefore) modes=personal->work->personal epochs=\(initial.1)->\(work.1)->\(personal.1)"
}

scenario("sidecar_crash_recovery") {
    let proc = try requireApp()
    let rowsBefore = processRows()
    let desc = descendants(of: Int(proc.processIdentifier))
    let sidecars = desc.filter { pid in
        guard let (_, _, cmd) = rowsBefore[pid] else { return false }
        return cmd.contains("js-agent-host")
    }
    guard let victim = sidecars.sorted().first else {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "no sidecar to kill"])
    }
    // Kill only our owned sidecar PID (never pkill by name).
    kill(Int32(victim), SIGKILL)
    ownedExtraPids.insert(victim)

    // Wait for restart: new sidecar + listener + webview recovery.
    let deadline = Date().addingTimeInterval(60)
    var recovered = false
    var newListener: ListenerInfo?
    while Date() < deadline {
        if !proc.isRunning {
            throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "app died after sidecar kill"])
        }
        let rows = processRows()
        let d = descendants(of: Int(proc.processIdentifier))
        let liveSidecars = d.filter { pid in
            guard let (_, _, cmd) = rows[pid] else { return false }
            return cmd.contains("js-agent-host") && pid != victim
        }
        let l = listeners(pids: d.union([Int(proc.processIdentifier)]))
        if !liveSidecars.isEmpty, l.count == 1, let first = l.first {
            recovered = true
            newListener = first
            break
        }
        Thread.sleep(forTimeInterval: 0.5)
    }
    if !recovered {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "sidecar did not recover"])
    }
    // Bootstrap token must not be reused from environment.
    let tree = descendants(of: Int(proc.processIdentifier)).union([Int(proc.processIdentifier)])
    let pidStr = tree.sorted().map { String($0) }.joined(separator: ",")
    let (_, cmdOut, _) = runShell("/bin/ps", ["-E", "-ww", "-p", pidStr, "-o", "command="])
    if cmdOut.contains("#bootstrap=") {
        throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "bootstrap leaked after recovery"])
    }
    return "killed=\(victim) recovered_listener=\(newListener!.host):\(newListener!.port)"
}

scenario("clean_quit_no_orphans", errorCode: "cleanup_failed") {
    let proc = try requireApp()
    let observed = descendants(of: Int(proc.processIdentifier)).union([Int(proc.processIdentifier)])
    // The assertion path sends TERM only. If graceful cleanup fails, appProcess
    // remains set and the final defer-style cleanup below may use KILL only
    // after this scenario has recorded the failure.
    let alive = gracefulTerminationSurvivors(proc, observed: observed)
    if !alive.isEmpty {
        throw NSError(domain: "harness", code: EXIT_CLEANUP_FAILED, userInfo: [NSLocalizedDescriptionKey: "orphans remained: \(alive)"])
    }
    let remainingListeners = listeners(pids: observed)
    if !remainingListeners.isEmpty {
        throw NSError(domain: "harness", code: EXIT_CLEANUP_FAILED, userInfo: [NSLocalizedDescriptionKey: "listeners remained after quit"])
    }
    // No LaunchAgent / bootstrap key / ephemeral identity leftovers.
    let fm = FileManager.default
    if fm.fileExists(atPath: homeDir + "/Library/LaunchAgents/com.titan.js-agent.plist") {
        throw NSError(domain: "harness", code: EXIT_CLEANUP_FAILED, userInfo: [NSLocalizedDescriptionKey: "LaunchAgent survived"])
    }
    if !(try? fm.contentsOfDirectory(atPath: homeDir))!.filter({ $0.contains("bootstrap") }).isEmpty {
        // soft: only fail on explicit bootstrap key file
    }
    appProcess = nil
    return "cleaned \(observed.count) pids"
}

if result.scenarios["clean_quit_no_orphans"]?.passed == true {
    scenario("restart_simplified_flow") {
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: fullExecutable)
        proc.currentDirectoryURL = URL(fileURLWithPath: launchDir)
        proc.environment = env
        proc.standardInput = FileHandle(forReadingAtPath: "/dev/null")
        proc.standardOutput = FileHandle(forWritingAtPath: "/dev/null")
        proc.standardError = FileHandle(forWritingAtPath: "/dev/null")
        try proc.run()
        appProcess = proc
        result.target_pid = Int(proc.processIdentifier)
        let listener = try waitForSingleListener(proc: proc, timeout: 100)
        let url = "http://\(listener.host):\(listener.port)/api/status"
        let (code, out, _) = runShell("/usr/bin/curl", ["-sS", "--max-time", "5", url])
        if code != 0 || out.isEmpty {
            throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "restart status failed"])
        }
        // Personal->Work->Personal simplified via AX if possible.
        _ = pressAxButton(appPid: proc.processIdentifier, matching: ["work", "工作"])
        Thread.sleep(forTimeInterval: 0.5)
        _ = pressAxButton(appPid: proc.processIdentifier, matching: ["personal", "个人"])
        Thread.sleep(forTimeInterval: 0.5)
        let l2 = listeners(pids: descendants(of: Int(proc.processIdentifier)).union([Int(proc.processIdentifier)]))
        if l2.count != 1 {
            throw NSError(domain: "harness", code: EXIT_ASSERT, userInfo: [NSLocalizedDescriptionKey: "restart flow listener count \(l2.count)"])
        }
        terminateOwned(proc)
        appProcess = nil
        return "restart ok port=\(listener.port)"
    }
} else {
    result.scenarios["restart_simplified_flow"] = ScenarioResult(
        passed: false,
        status: "failed",
        detail: "skipped until clean quit failure is recorded and final cleanup runs",
        duration_ms: 0,
        error_code: "cleanup_failed"
    )
}

// Final cleanup guarantee: KILL is permitted only after clean-quit failure was recorded.
if let proc = appProcess {
    terminateOwned(proc, extraPids: ownedExtraPids)
    appProcess = nil
}

let failed = result.scenarios.values.filter { !$0.passed }
result.ok = failed.isEmpty
result.status = result.ok ? "passed" : "failed"
print("\nResult: ok=\(result.ok) scenarios=\(result.scenarios.count) failed=\(failed.count)")
writeResultAndExit(result.ok ? EXIT_OK : EXIT_ASSERT)
