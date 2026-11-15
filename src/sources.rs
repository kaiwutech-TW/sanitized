//! Where the antivirus rules come from, so every detection can name its source:
//! - Apple XProtect: the YARA rules macOS itself ships and updates (read from this Mac).
//! - MalwareBazaar (abuse.ch): public SHA-256 hashes of Mac malware samples (free key needed).
//! - Objective-See: the public Mac malware collection; family names plus known install
//!   locations from published analyses.
//! - Built-in rules and the person's own signatures.txt.

use crate::util;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Hash, Default)]
pub enum Source {
    #[default]
    Builtin,
    XProtect,
    MalwareBazaar,
    ObjectiveSee,
    User,
}

impl Source {
    pub fn label(self) -> &'static str {
        match self {
            Source::Builtin => "內建規則",
            Source::XProtect => "Apple XProtect",
            Source::MalwareBazaar => "MalwareBazaar（abuse.ch）",
            Source::ObjectiveSee => "Objective-See",
            Source::User => "自訂病毒碼",
        }
    }
    pub fn url(self) -> &'static str {
        match self {
            Source::XProtect => "https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8/web",
            Source::MalwareBazaar => "https://bazaar.abuse.ch/",
            Source::ObjectiveSee => "https://github.com/Objective-see/Malware",
            _ => "",
        }
    }
}

// ---------------------------------------------------------------- Apple XProtect

const XPROTECT_BUNDLES: &[&str] = &[
    "/private/var/protected/xprotect/XProtect.bundle",
    "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
];

pub struct XProtect {
    pub rules: yara_x::Rules,
    pub version: String,
    pub bundle: PathBuf,
    pub updated: u64,
    pub loaded: usize,
    pub skipped: usize,
}

fn bundle_version(b: &Path) -> Option<u64> {
    let v = plist::Value::from_file(b.join("Contents/Info.plist")).ok()?;
    v.as_dictionary()?.get("CFBundleShortVersionString")?.as_string()?.parse().ok()
}

/// The newest XProtect bundle on this Mac (macOS keeps one in two places).
pub fn xprotect_bundle() -> Option<(PathBuf, u64)> {
    XPROTECT_BUNDLES.iter().filter_map(|b| bundle_version(Path::new(b)).map(|v| (PathBuf::from(b), v))).max_by_key(|(_, v)| *v)
}

/// Split a YARA file into its rules so one rule the engine can't read doesn't stop the rest.
fn split_rules(text: &str) -> (String, Vec<String>) {
    let mut header = String::new();
    let mut blocks: Vec<String> = Vec::new();
    for line in text.lines() {
        let t = line.trim_start();
        let starts = (t.starts_with("rule ") || t.starts_with("private rule ") || t.starts_with("global rule ")) && line.len() - t.len() == 0;
        if starts {
            blocks.push(String::new());
        }
        match blocks.last_mut() {
            Some(b) => {
                b.push_str(line);
                b.push('\n');
            }
            None if t.starts_with("import ") => {
                header.push_str(line);
                header.push('\n');
            }
            None => {}
        }
    }
    (header, blocks)
}

/// Compile Apple's malware rules (XProtect.yara) and script rules (XPScripts.yr).
pub fn load_xprotect() -> Option<XProtect> {
    let (bundle, version) = xprotect_bundle()?;
    let res = bundle.join("Contents/Resources");
    let mut compiler = yara_x::Compiler::new();
    let mut loaded = 0;
    let mut skipped = 0;
    let mut updated = 0;
    for name in ["XProtect.yara", "XPScripts.yr"] {
        let path = res.join(name);
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        if let Ok(m) = std::fs::metadata(&path).and_then(|m| m.modified()) {
            let s = m.duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            updated = updated.max(s);
        }
        // Each file gets its own namespace: both define helper rules with the same names.
        compiler.new_namespace(if name.ends_with(".yara") { "xprotect" } else { "xpscripts" });
        let (header, blocks) = split_rules(&text);
        for b in blocks {
            let src = format!("{}{}", header, b);
            match compiler.add_source(src.as_str()) {
                Ok(_) => {
                    if !b.trim_start().starts_with("private") {
                        loaded += 1;
                    }
                }
                Err(_) => skipped += 1,
            }
        }
    }
    Some(XProtect { rules: compiler.build(), version: version.to_string(), bundle, updated, loaded, skipped })
}

/// "MACOS.ADLOAD.B" style name of a matching XProtect rule.
pub fn xprotect_name(rule: &yara_x::Rule) -> String {
    for (k, v) in rule.metadata() {
        if k == "description" {
            if let yara_x::MetaValue::String(s) = v {
                return s.to_string();
            }
        }
    }
    rule.identifier().trim_start_matches("XProtect_").to_string()
}

// ---------------------------------------------------------------- MalwareBazaar

pub const MB_API: &str = "https://mb-api.abuse.ch/api/v1/";
/// Mac file types requested, 1000 newest samples each (the API's maximum per query).
pub const MB_FILE_TYPES: &[&str] = &["macho", "dmg", "pkg"];
pub const MB_LIMIT: u32 = 1000;
/// Automatic refresh interval (estimated: the database adds samples every day).
pub const MB_REFRESH_SECS: u64 = 86_400;
const KEYCHAIN_SERVICE: &str = "MacCareGuard.abuse.ch";

pub fn mb_file() -> PathBuf {
    util::data_dir().join("malwarebazaar.txt")
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct MbMeta {
    pub updated: u64,
    pub count: usize,
}

pub fn mb_meta() -> MbMeta {
    std::fs::read_to_string(util::data_dir().join("malwarebazaar.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

/// The free abuse.ch key, kept in the macOS Keychain.
pub fn mb_key() -> Option<String> {
    let out = std::process::Command::new("security").args(["find-generic-password", "-a", "MacCareGuard", "-s", KEYCHAIN_SERVICE, "-w"]).output().ok()?;
    let k = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if out.status.success() && !k.is_empty() { Some(k) } else { None }
}

pub fn set_mb_key(key: &str) -> Result<(), String> {
    let key = key.trim();
    if key.is_empty() {
        let _ = std::process::Command::new("security").args(["delete-generic-password", "-a", "MacCareGuard", "-s", KEYCHAIN_SERVICE]).output();
        return Ok(());
    }
    let out = std::process::Command::new("security")
        .args(["add-generic-password", "-U", "-a", "MacCareGuard", "-s", KEYCHAIN_SERVICE, "-w", key])
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&out.stderr).trim().to_string()) }
}

fn mb_query(key: &str, file_type: &str) -> Result<serde_json::Value, String> {
    // The key goes to curl through stdin, so it never appears in the process list.
    let mut child = std::process::Command::new("curl")
        .args(["-sS", "--max-time", "60", "-K", "-", "-X", "POST", "--data", &format!("query=get_file_type&file_type={}&limit={}", file_type, MB_LIMIT), MB_API])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    child.stdin.take().ok_or("stdin")?.write_all(format!("header = \"Auth-Key: {}\"\n", key.replace('"', "")).as_bytes()).map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!("無法連線到 MalwareBazaar：{}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    let j: serde_json::Value = serde_json::from_slice(&out.stdout).map_err(|_| "MalwareBazaar 回應無法解讀".to_string())?;
    if j.get("error").is_some() {
        return Err("MalwareBazaar 拒絕了金鑰，請確認金鑰是否正確".into());
    }
    match j.get("query_status").and_then(|s| s.as_str()) {
        Some("ok") | Some("no_results") => Ok(j),
        Some("unknown_auth_key") | Some("illegal_auth_key") => Err("MalwareBazaar 金鑰無效，請重新確認".into()),
        Some(s) => Err(format!("MalwareBazaar 回覆：{}", s)),
        None => Err("MalwareBazaar 回應格式不符".into()),
    }
}

/// Download the newest Mac malware hashes. Returns how many hash+size rules were saved.
pub fn update_malwarebazaar(key: &str) -> Result<usize, String> {
    let mut lines: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for ft in MB_FILE_TYPES {
        let j = mb_query(key, ft)?;
        for e in j.get("data").and_then(|d| d.as_array()).into_iter().flatten() {
            let (Some(sha), Some(size)) = (e.get("sha256_hash").and_then(|v| v.as_str()), e.get("file_size").and_then(|v| v.as_u64())) else { continue };
            if !seen.insert(sha.to_string()) {
                continue;
            }
            let family = e.get("signature").and_then(|v| v.as_str()).filter(|s| !s.is_empty()).unwrap_or(ft);
            lines.push(format!("{} {} {}", sha.to_lowercase(), size, family.replace(['\n', '\r'], " ")));
        }
    }
    let n = lines.len();
    std::fs::write(mb_file(), lines.join("\n")).map_err(|e| e.to_string())?;
    let meta = MbMeta { updated: util::now_secs(), count: n };
    let _ = std::fs::write(util::data_dir().join("malwarebazaar.json"), serde_json::to_string(&meta).unwrap_or_default());
    Ok(n)
}

pub fn mb_due() -> bool {
    util::now_secs().saturating_sub(mb_meta().updated) > MB_REFRESH_SECS
}

// ---------------------------------------------------------------- Objective-See

/// The 230 family names in Objective-See's public Mac malware collection (names only).
pub const OBJECTIVE_SEE_FAMILIES: &str = include_str!("../data/objective_see_families.txt");

pub fn objective_see_families() -> Vec<&'static str> {
    OBJECTIVE_SEE_FAMILIES.lines().filter(|l| !l.starts_with('#') && !l.trim().is_empty()).collect()
}

/// Install locations of Objective-See families, from published analyses. Family names
/// alone are not used as rules: several are common words ("Dummy", "Snake", "Leap").
pub const OBJECTIVE_SEE_ARTIFACTS: &[(&str, &str, bool)] = &[
    // (path pattern, family, malware (true) or adware (false))
    (r"/Library/AppQuest/com\.apple\.questd|/Launch(Agents|Daemons)/com\.apple\.questd\.plist$", "EvilQuest", true),
    (r"/Library/(kernel_service|\.kernel_pid|\.kernel_time|\.kernel_complete)$", "KeRanger", true),
    (r"/LaunchAgents/com\.Eltima\.UpdaterAgent\.plist$|/Library/\.rand/", "Proton", true),
    (r"/LaunchAgents/com\.client\.client\.plist$|^/Users/[^/]+/\.client$", "FruitFly", true),
    (r"/LaunchAgents/com\.apple\.rig2\.plist$|/LaunchAgents/com\.proxy\.initialize\.plist$", "CookieMiner", true),
    (r"/LaunchDaemons/com\.apple\.audio\.driver\.plist$|com\.apple\.audio\.driver\.app", "ColdRoot", true),
    (r"/\.calisto/", "Calisto", true),
    (r"/LaunchDaemons/org\.jmttrading\.plist$|/Library/JMTTrader/", "AppleJeus", true),
    (r"/LaunchDaemons/com\.unioncrypto\.pricecheck\.plist$", "AppleJeus", true),
    (r"/Library/\._insu$|/agent_updater/agent\.sh$|/LaunchAgents/init_verx\.plist$", "SilverSparrow", true),
    (r"/Library/MacOsServices/updateMacOs", "SysJoker", true),
    (r"^/usr/local/machook|/LaunchDaemons/com\.apple\.machook_damon\.plist$|/LaunchDaemons/com\.apple\.globalupdate\.plist$", "WireLurker", true),
    (r"/Application Support/JavaW|/LaunchDaemons/com\.JavaW\.plist$", "iWorm", true),
    (r"/Genieo\.app|/LaunchAgents/com\.genieoinnovation\.", "Genieo", false),
    (r"/Library/App Store/storeuserd", "Mokes", true),
    (r"/LaunchAgents/com\.apple\.Safari\.(proxy|pac)\.plist$|^/Users/Shared/AppStore\.app", "Dok", true),
    (r"/Library/WebServer/share/httpd/manual/WindowServer|/LaunchDaemons/\.com\.apple\.WindowServer\.plist$", "CloudMensis", true),
    (r"/LaunchAgents/com\.apple\.FY9\.plist$", "OSAMiner", true),
    (r"/LaunchAgents/com\.apple\.softwareupdate\.plist$|/\.local/softwareupdate$", "DazzleSpy", true),
    (r"^/(private/)?tmp/g\.py$|^/(private/)?tmp/GoogleUpdate$", "ZuRu", true),
    (r"/com\.apple\.iCloud\.sync\.daemon/icloudsyncd|/LaunchAgents/com\.apple\.iCloud\.sync\.daemon\.plist$", "Keydnap", true),
    (r"^/Users/Shared/\.local/kextd$|/LaunchAgents/com\.apple\.updates\.plist$", "Komplex", true),
    (r"^/Users/Shared/sh\.py$", "JokerSpy", true),
    (r"^/Users/Shared/\.pd$", "RustBucket", true),
    (r"^/Users/Shared/\.sld$", "KandyKorn", true),
];
