//! Antivirus engine: rule sets, scanning, quarantine, the safe list and the real-time monitor.

use crate::sources::{self, Source};
use crate::util::{self, collapse, expand, file_name};
use regex::bytes::Regex as BRegex;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub const MB: u64 = 1_000_000;
/// Launch agent plists bigger than this are not parsed (1 MB).
pub const LAUNCH_AGENT_SIZE_LIMIT: u64 = MB;
/// Path-rule content checks read at most this much (5 MB).
pub const PATH_RULE_CONTENT_LIMIT: u64 = 5 * MB;
/// Pattern (YARA-like) checks only read files up to this size (estimated).
pub const CONTENT_SCAN_LIMIT: u64 = 20 * MB;
/// Archives bigger than this are not opened (estimated).
pub const ARCHIVE_SIZE_LIMIT: u64 = 100 * MB;
/// Real-time monitor polling interval in seconds (estimated).
pub const MONITOR_INTERVAL_SECS: u64 = 5;

// ---------------------------------------------------------------- scan settings

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum ScanMode {
    Quick,
    Balanced,
    Deep,
}

impl ScanMode {
    pub fn title(self) -> &'static str {
        match self {
            ScanMode::Quick => "快速掃描",
            ScanMode::Balanced => "平衡掃描",
            ScanMode::Deep => "深度掃描",
        }
    }
    pub fn speed(self) -> &'static str {
        match self {
            ScanMode::Quick => "最快",
            ScanMode::Balanced => "中等",
            ScanMode::Deep => "最慢",
        }
    }
    pub fn depth(self) -> &'static str {
        match self {
            ScanMode::Quick => "最易受攻擊的位置",
            ScanMode::Balanced => "中等",
            ScanMode::Deep => "全面",
        }
    }
    pub fn purpose(self) -> &'static str {
        match self {
            ScanMode::Quick => "檢查系統中最容易被攻擊的區域，找出眼前的威脅。適合日常檢查或時間不多時使用。",
            ScanMode::Balanced => "除了易受攻擊的區域，也檢查個人資料夾與已安裝的應用程式。",
            ScanMode::Deep => "深入每一個檔案與資料夾，完整檢查整個系統。懷疑中毒或需要最高安全性時使用。",
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ScanOptions {
    pub mode: ScanMode,
    pub archives: bool,
    pub dmg: bool,
    pub usb: bool,
    pub exclude_icloud: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions { mode: ScanMode::Quick, archives: true, dmg: true, usb: false, exclude_icloud: true }
    }
}

/// Folders checked by each mode. Quick = common persistence locations (launch agents,
/// plug-ins, helpers, cron); Balanced adds the home folders; Deep also walks system roots.
pub fn scan_roots(o: &ScanOptions) -> Vec<(PathBuf, usize)> {
    let quick_user = [
        "Library/LaunchAgents",
        "Library/Application Support",
        "Library/Preferences",
        "Library/Services",
        "Library/Internet Plug-Ins",
        "Library/PreferencePanes",
        "Library/Application Scripts",
        "Library/ColorPickers",
        "Library/QuickLook",
        "Library/Screen Savers",
        "Library/Spotlight",
        "Downloads",
        "Applications",
    ];
    let quick_system = [
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/Library/Application Support",
        "/Library/Extensions",
        "/Library/PrivilegedHelperTools",
        "/Library/Internet Plug-Ins",
        "/Library/Services",
        "/Library/StartupItems",
        "/Library/Security/SecurityAgentPlugins",
        "/Library/Audio/Plug-Ins",
        "/Library/DirectoryServices/PlugIns",
        "/Library/ColorPickers",
        "/Library/QuickLook",
        "/Library/Screen Savers",
        "/Library/Spotlight",
        "/usr/lib/cron/tabs",
        "/Users/Shared",
        "/private/tmp",
    ];
    let h = util::home();
    let mut v: Vec<(PathBuf, usize)> = Vec::new();
    match o.mode {
        ScanMode::Quick => {
            for p in quick_user {
                v.push((h.join(p), 3));
            }
            for p in quick_system {
                v.push((PathBuf::from(p), 3));
            }
        }
        ScanMode::Balanced => {
            for p in ["Library", "Downloads", "Desktop", "Documents", "Applications"] {
                v.push((h.join(p), 8));
            }
            for p in quick_system {
                v.push((PathBuf::from(p), 6));
            }
            for p in ["/Applications", "/usr/local", "/opt/homebrew"] {
                v.push((PathBuf::from(p), 6));
            }
        }
        ScanMode::Deep => {
            v.push((h.clone(), 64));
            for p in ["/Applications", "/Library", "/Users/Shared", "/private/tmp", "/private/etc", "/usr/local", "/opt", "/usr/lib/cron"] {
                v.push((PathBuf::from(p), 64));
            }
        }
    }
    if o.usb {
        for vol in util::children(Path::new("/Volumes")) {
            if fs::symlink_metadata(&vol).map(|m| m.file_type().is_symlink()).unwrap_or(true) {
                continue; // the startup disk appears as a link
            }
            v.push((vol, if o.mode == ScanMode::Deep { 64 } else { 6 }));
        }
    }
    v
}

// ---------------------------------------------------------------- threats

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Hash)]
pub enum ThreatKind {
    Malware,
    Adware,
    Suspicious,
    TestFile,
}

impl ThreatKind {
    pub fn label(self) -> &'static str {
        match self {
            ThreatKind::Malware => "惡意軟體",
            ThreatKind::Adware => "廣告軟體",
            ThreatKind::Suspicious => "可疑項目",
            ThreatKind::TestFile => "測試檔案",
        }
    }
    pub fn rank(self) -> u8 {
        match self {
            ThreatKind::Malware => 3,
            ThreatKind::Adware => 2,
            ThreatKind::Suspicious => 1,
            ThreatKind::TestFile => 0,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub enum Engine {
    HashSize,
    PathRule,
    LaunchAgent,
    Pattern,
    Archive,
    Heuristic,
    Yara,
}

impl Engine {
    pub fn label(self) -> &'static str {
        match self {
            Engine::HashSize => "病毒碼 (SHA-256)",
            Engine::PathRule => "已知路徑規則",
            Engine::LaunchAgent => "啟動項目檢查",
            Engine::Pattern => "特徵碼比對",
            Engine::Archive => "壓縮檔內容",
            Engine::Heuristic => "行為推測",
            Engine::Yara => "Apple 惡意軟體規則 (YARA)",
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct Threat {
    pub path: PathBuf,
    pub name: String,
    pub kind: ThreatKind,
    pub engine: Engine,
    pub detail: String,
    pub size: u64,
    /// Which rule source caught it.
    #[serde(default)]
    pub source: Source,
    #[serde(skip)]
    pub selected: bool,
}

// ---------------------------------------------------------------- rules

pub struct HashRule {
    pub sha256: String,
    pub name: String,
    pub kind: ThreatKind,
    pub source: Source,
}

pub struct NameRule {
    pub re: Regex,
    pub name: String,
    pub kind: ThreatKind,
    pub source: Source,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum FileClass {
    Script,
    Plist,
    MachO,
    Other,
}

pub struct PatternRule {
    pub re: BRegex,
    pub name: String,
    pub kind: ThreatKind,
    pub classes: &'static [FileClass],
    pub source: Source,
}

pub struct RuleSet {
    /// Hash+size rules keyed by file size: size is compared first, the SHA-256 only for
    /// files whose size matches.
    pub hash: HashMap<u64, Vec<HashRule>>,
    pub names: Vec<NameRule>,
    pub agents: Vec<NameRule>,
    pub patterns: Vec<PatternRule>,
    pub ext_ids: HashMap<String, String>,
    pub eicar: Vec<u8>,
    pub version: String,
    pub count: usize,
    /// Apple's own malware rules, compiled from this Mac's XProtect bundle.
    pub xprotect: Option<sources::XProtect>,
    /// Rules per source, for the sources page.
    pub per_source: HashMap<Source, usize>,
}

fn eicar_bytes() -> Vec<u8> {
    // Assembled at run time so this program never holds the test string in one piece.
    let a = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR";
    let b = "-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    format!("{a}{b}").into_bytes()
}

pub fn signatures_file() -> PathBuf {
    util::data_dir().join("signatures.txt")
}

impl RuleSet {
    /// Every source, including compiling Apple's XProtect rules (takes a moment).
    pub fn load() -> RuleSet {
        Self::load_with(true)
    }

    /// Everything except XProtect, for a fast start; the full set replaces it when ready.
    pub fn load_basic() -> RuleSet {
        Self::load_with(false)
    }

    fn load_with(with_xprotect: bool) -> RuleSet {
        let mut r = RuleSet {
            hash: HashMap::new(),
            names: Vec::new(),
            agents: Vec::new(),
            patterns: Vec::new(),
            ext_ids: HashMap::new(),
            eicar: eicar_bytes(),
            version: String::new(),
            count: 0,
            xprotect: None,
            per_source: HashMap::new(),
        };
        // The standard antivirus test file (68 bytes).
        r.add_hash(68, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "EICAR 測試檔案", ThreatKind::TestFile, Source::Builtin);

        // Known adware / malware family artefacts by path (a small built-in sample set).
        let fams: &[(&str, &str, ThreatKind)] = &[
            (r"(?i)/(\.)?mshelper(/|$)", "MShelper 挖礦程式", ThreatKind::Malware),
            (r"(?i)pirrit", "Pirrit 廣告軟體", ThreatKind::Adware),
            (r"(?i)genieo", "Genieo 廣告軟體", ThreatKind::Adware),
            (r"(?i)vsearch", "VSearch 廣告軟體", ThreatKind::Adware),
            (r"(?i)bundlore", "Bundlore 廣告軟體", ThreatKind::Adware),
            (r"(?i)shlayer", "Shlayer 木馬", ThreatKind::Malware),
            (r"(?i)adload", "Adload 廣告軟體", ThreatKind::Adware),
            (r"(?i)searchmine", "SearchMine 瀏覽器綁架", ThreatKind::Adware),
            (r"(?i)searchbaron", "SearchBaron 瀏覽器綁架", ThreatKind::Adware),
            (r"(?i)safefinder", "SafeFinder 瀏覽器綁架", ThreatKind::Adware),
            (r"(?i)crossrider", "Crossrider 廣告軟體", ThreatKind::Adware),
            (r"(?i)installcore", "InstallCore 綑綁安裝程式", ThreatKind::Adware),
            (r"(?i)mughthesec", "Mughthesec 廣告軟體", ThreatKind::Adware),
            (r"(?i)chumsearch", "ChumSearch 瀏覽器綁架", ThreatKind::Adware),
            (r"(?i)operatorpro", "OperatorPro 廣告軟體", ThreatKind::Adware),
        ];
        for (re, name, kind) in fams {
            if let Ok(re) = Regex::new(re) {
                r.names.push(NameRule { re: re.clone(), name: name.to_string(), kind: *kind, source: Source::Builtin });
                r.agents.push(NameRule { re, name: name.to_string(), kind: *kind, source: Source::Builtin });
            }
        }

        // Pattern rules (our own).
        let pats: &[(&str, &str, ThreatKind, &'static [FileClass])] = &[
            (r"(?i)(curl|wget)[^\n|;]{0,240}\|\s*(sudo\s+)?(ba|z)?sh\b", "下載後直接執行的腳本", ThreatKind::Suspicious, &[FileClass::Script, FileClass::Plist]),
            (r"(?i)base64\s+(-d|-D|--decode)[^\n]{0,160}\|\s*(ba|z)?sh\b", "經過混淆的腳本", ThreatKind::Suspicious, &[FileClass::Script, FileClass::Plist]),
            (r"eval\s*\(\s*(atob|base64_decode|unescape|gzinflate)\s*\(", "經過混淆的程式碼", ThreatKind::Suspicious, &[FileClass::Script]),
            (r"(?i)display dialog[^\n]{0,200}with hidden answer", "假冒密碼視窗（竊密程式特徵）", ThreatKind::Malware, &[FileClass::Script, FileClass::MachO]),
            (r"(?i)(dump-keychain|find-generic-password[^\n]{0,80}-w)", "讀取鑰匙圈密碼", ThreatKind::Malware, &[FileClass::Script]),
            (r"stratum\+(tcp|ssl)://", "加密貨幣挖礦程式", ThreatKind::Malware, &[FileClass::Script, FileClass::MachO, FileClass::Plist]),
            (r"(?i)(ba)?sh\s+-i\s*>&\s*/dev/tcp/", "反向連線後門", ThreatKind::Malware, &[FileClass::Script, FileClass::Plist]),
            (r"(?i)xattr\s+-[a-z]*[dc][a-z]*\s+[^\n]{0,40}com\.apple\.quarantine", "移除系統隔離標記", ThreatKind::Suspicious, &[FileClass::Script]),
        ];
        for (re, name, kind, classes) in pats {
            if let Ok(re) = BRegex::new(re) {
                r.patterns.push(PatternRule { re, name: name.to_string(), kind: *kind, classes, source: Source::Builtin });
            }
        }

        // Extra signatures the person (or an update) placed in signatures.txt:
        //   <sha256> <size> <name>        hash+size rule
        //   path <regex> <name>           path rule
        //   ext <extension-id> <name>     blocked browser extension
        let mut extra = 0;
        if let Ok(text) = fs::read_to_string(signatures_file()) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                let parts: Vec<&str> = line.splitn(3, char::is_whitespace).collect();
                if parts.len() < 3 {
                    continue;
                }
                match parts[0] {
                    "path" => {
                        if let Ok(re) = Regex::new(parts[1]) {
                            r.names.push(NameRule { re, name: parts[2].to_string(), kind: ThreatKind::Malware, source: Source::User });
                            extra += 1;
                        }
                    }
                    "ext" => {
                        r.ext_ids.insert(parts[1].to_string(), parts[2].to_string());
                        extra += 1;
                    }
                    h if h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit()) => {
                        if let Ok(size) = parts[1].parse::<u64>() {
                            r.add_hash(size, h, parts[2], ThreatKind::Malware, Source::User);
                            extra += 1;
                        }
                    }
                    _ => {}
                }
            }
        }
        // Objective-See: install locations of documented Mac malware families.
        for (re, fam, malware) in sources::OBJECTIVE_SEE_ARTIFACTS {
            if let Ok(re) = Regex::new(re) {
                let kind = if *malware { ThreatKind::Malware } else { ThreatKind::Adware };
                r.names.push(NameRule { re, name: format!("{} 惡意軟體", fam), kind, source: Source::ObjectiveSee });
            }
        }
        // MalwareBazaar: hashes downloaded with the person's free abuse.ch key.
        if let Ok(text) = fs::read_to_string(sources::mb_file()) {
            for line in text.lines() {
                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                if parts.len() == 3 && parts[0].len() == 64 {
                    if let Ok(size) = parts[1].parse::<u64>() {
                        r.add_hash(size, parts[0], &format!("{}（MalwareBazaar 樣本）", parts[2]), ThreatKind::Malware, Source::MalwareBazaar);
                    }
                }
            }
        }
        if with_xprotect {
            r.xprotect = sources::load_xprotect();
        }
        let mut per: HashMap<Source, usize> = HashMap::new();
        for h in r.hash.values().flatten() {
            *per.entry(h.source).or_default() += 1;
        }
        for n in &r.names {
            *per.entry(n.source).or_default() += 1;
        }
        *per.entry(Source::Builtin).or_default() += r.patterns.len();
        *per.entry(Source::User).or_default() += r.ext_ids.len();
        if let Some(x) = &r.xprotect {
            *per.entry(Source::XProtect).or_default() += x.loaded;
        }
        r.count = per.values().sum();
        r.per_source = per;
        let xp = r.xprotect.as_ref().map(|x| format!("Apple XProtect {} 版", x.version)).unwrap_or_else(|| "Apple XProtect 載入中或無法使用".into());
        r.version = format!("{} · 內建與 Objective-See 規則 · {} 條自訂病毒碼", xp, extra);
        r
    }

    fn add_hash(&mut self, size: u64, sha: &str, name: &str, kind: ThreatKind, source: Source) {
        self.hash.entry(size).or_default().push(HashRule { sha256: sha.to_lowercase(), name: name.to_string(), kind, source });
    }
}

// ---------------------------------------------------------------- checking one file

pub fn sha256_file(p: &Path) -> Option<String> {
    let mut f = fs::File::open(p).ok()?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 16];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(hex(&h.finalize()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn read_head(p: &Path, n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    match fs::File::open(p).and_then(|mut f| f.read(&mut v)) {
        Ok(k) => {
            v.truncate(k);
            v
        }
        Err(_) => Vec::new(),
    }
}

fn classify(p: &Path, head: &[u8]) -> FileClass {
    let ext = p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
    if matches!(ext.as_str(), "sh" | "command" | "zsh" | "bash" | "py" | "js" | "applescript" | "php" | "pl" | "rb" | "tool") || head.starts_with(b"#!") {
        return FileClass::Script;
    }
    if ext == "plist" || head.starts_with(b"bplist") || head.starts_with(b"<?xml") {
        return FileClass::Plist;
    }
    if head.len() >= 4 {
        let m = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        if matches!(m, 0xfeedfacf | 0xcffaedfe | 0xfeedface | 0xcefaedfe | 0xcafebabe) {
            return FileClass::MachO;
        }
    }
    FileClass::Other
}

fn in_hidden_folder(p: &Path) -> bool {
    p.parent()
        .map(|par| par.components().any(|c| c.as_os_str().to_string_lossy().starts_with('.') && c.as_os_str() != "." && c.as_os_str() != ".."))
        .unwrap_or(false)
}

fn persistence_area(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.contains("/Library/Application Support/") || s.starts_with("/Users/Shared") || s.starts_with("/private/tmp") || s.starts_with("/tmp")
}

pub struct Checker<'a> {
    pub rules: &'a RuleSet,
    pub opts: &'a ScanOptions,
    /// One YARA scanner for Apple's rules, reused for every file of a scan.
    xp: Option<std::cell::RefCell<yara_x::Scanner<'a>>>,
}

impl<'a> Checker<'a> {
    pub fn new(rules: &'a RuleSet, opts: &'a ScanOptions) -> Checker<'a> {
        let xp = rules.xprotect.as_ref().map(|x| {
            let mut sc = yara_x::Scanner::new(&x.rules);
            sc.set_timeout(std::time::Duration::from_secs(5));
            std::cell::RefCell::new(sc)
        });
        Checker { rules, opts, xp }
    }

    /// Apple XProtect (YARA) on file contents already read.
    fn check_xprotect(&self, data: &[u8]) -> Option<String> {
        let cell = self.xp.as_ref()?;
        let mut sc = cell.borrow_mut();
        let res = sc.scan(data).ok()?;
        let name = res.matching_rules().find(|r| !r.identifier().is_empty()).map(|r| sources::xprotect_name(&r));
        name
    }

    pub fn check_file(&self, p: &Path, size: u64) -> Option<Threat> {
        let path_s = p.to_string_lossy();
        let mk = |name: String, kind, engine, detail: String, source: Source| Threat { path: p.to_path_buf(), name, kind, engine, detail, size, source, selected: true };

        // 1. hash + size
        if let Some(cands) = self.rules.hash.get(&size) {
            if let Some(h) = sha256_file(p) {
                if let Some(r) = cands.iter().find(|r| r.sha256 == h) {
                    return Some(mk(r.name.clone(), r.kind, Engine::HashSize, format!("SHA-256 {}…", &h[..16]), r.source));
                }
            }
        }
        // EICAR test string anywhere at the start of a small file.
        if (68..=128).contains(&size) {
            let head = read_head(p, 128);
            if head.starts_with(&self.rules.eicar) {
                return Some(mk("EICAR 測試檔案".into(), ThreatKind::TestFile, Engine::Pattern, "防毒測試用的標準檔案，無害".into(), Source::Builtin));
            }
        }
        // 2. path rules
        for r in &self.rules.names {
            if r.re.is_match(&path_s) {
                return Some(mk(r.name.clone(), r.kind, Engine::PathRule, "符合已知威脅的檔案位置".into(), r.source));
            }
        }
        // 3. patterns (only small files)
        if size <= CONTENT_SCAN_LIMIT && size > 0 {
            let head = read_head(p, 16);
            let class = classify(p, &head);
            if class != FileClass::Other {
                let limit = if class == FileClass::Plist { PATH_RULE_CONTENT_LIMIT } else { CONTENT_SCAN_LIMIT };
                if size <= limit {
                    if let Ok(data) = fs::read(p) {
                        for r in &self.rules.patterns {
                            if r.classes.contains(&class) && r.re.is_match(&data) {
                                return Some(mk(r.name.clone(), r.kind, Engine::Pattern, "檔案內容符合惡意特徵".into(), r.source));
                            }
                        }
                        // Apple XProtect rules (Mach-O programs and scripts).
                        if class != FileClass::Plist {
                            if let Some(n) = self.check_xprotect(&data) {
                                return Some(mk(format!("XProtect：{}", n), ThreatKind::Malware, Engine::Yara, "符合 Apple 內建的惡意軟體特徵".into(), Source::XProtect));
                            }
                        }
                    }
                }
                // 4. heuristic: a program hidden in a dot-folder where malware likes to live
                if class == FileClass::MachO && in_hidden_folder(p) && persistence_area(p) {
                    return Some(mk("隱藏位置中的執行檔".into(), ThreatKind::Suspicious, Engine::Heuristic, "程式藏在隱藏資料夾中，常見於惡意軟體".into(), Source::Builtin));
                }
            }
        }
        // 5. archives
        if self.opts.archives && size <= ARCHIVE_SIZE_LIMIT {
            let ext = p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
            if ext == "zip" {
                if let Some(t) = self.check_zip(p, size) {
                    return Some(t);
                }
            }
        }
        None
    }

    fn check_zip(&self, p: &Path, size: u64) -> Option<Threat> {
        let f = fs::File::open(p).ok()?;
        let mut z = zip::ZipArchive::new(f).ok()?;
        for i in 0..z.len().min(5000) {
            let Ok(mut e) = z.by_index(i) else { continue };
            let name = e.name().to_string();
            let esize = e.size();
            for r in &self.rules.names {
                if r.re.is_match(&name) {
                    return Some(Threat { path: p.to_path_buf(), name: r.name.clone(), kind: r.kind, engine: Engine::Archive, detail: format!("壓縮檔內：{}", name), size, source: r.source, selected: true });
                }
            }
            let hashed = self.rules.hash.contains_key(&esize);
            if (hashed || esize <= 64 * 1024) && esize <= CONTENT_SCAN_LIMIT {
                let mut data = Vec::new();
                if e.read_to_end(&mut data).is_err() {
                    continue;
                }
                if hashed {
                    let h = hex(&Sha256::digest(&data));
                    if let Some(r) = self.rules.hash[&esize].iter().find(|r| r.sha256 == h) {
                        return Some(Threat { path: p.to_path_buf(), name: r.name.clone(), kind: r.kind, engine: Engine::Archive, detail: format!("壓縮檔內：{}", name), size, source: r.source, selected: true });
                    }
                }
                if data.starts_with(&self.rules.eicar) {
                    return Some(Threat { path: p.to_path_buf(), name: "EICAR 測試檔案".into(), kind: ThreatKind::TestFile, engine: Engine::Archive, detail: format!("壓縮檔內：{}", name), size, source: Source::Builtin, selected: true });
                }
                if data.starts_with(b"#!") {
                    for r in &self.rules.patterns {
                        if r.classes.contains(&FileClass::Script) && r.re.is_match(&data) {
                            return Some(Threat { path: p.to_path_buf(), name: r.name.clone(), kind: r.kind, engine: Engine::Archive, detail: format!("壓縮檔內：{}", name), size, source: r.source, selected: true });
                        }
                    }
                }
            }
        }
        None
    }

    /// Launch agent / daemon plist (≤ 1 MB): name rules, then what it starts.
    pub fn check_launch_item(&self, p: &Path, size: u64) -> Option<Threat> {
        if size > LAUNCH_AGENT_SIZE_LIMIT {
            return None;
        }
        let v = plist::Value::from_file(p).ok()?;
        let d = v.as_dictionary()?;
        let label = d.get("Label").and_then(|x| x.as_string()).unwrap_or("").to_string();
        let mut cmd: Vec<String> = Vec::new();
        if let Some(prog) = d.get("Program").and_then(|x| x.as_string()) {
            cmd.push(prog.to_string());
        }
        if let Some(args) = d.get("ProgramArguments").and_then(|x| x.as_array()) {
            for a in args {
                if let Some(s) = a.as_string() {
                    cmd.push(s.to_string());
                }
            }
        }
        let joined = format!("{} {}", label, cmd.join(" "));
        let mk = |name: &str, kind, detail: String, source: Source| Threat { path: p.to_path_buf(), name: name.to_string(), kind, engine: Engine::LaunchAgent, detail, size, source, selected: true };
        for r in &self.rules.agents {
            if r.re.is_match(&joined) {
                return Some(mk(&r.name, r.kind, format!("啟動項目：{}", label), r.source));
            }
        }
        let cmd_text = cmd.join(" ");
        for r in &self.rules.patterns {
            if r.classes.contains(&FileClass::Plist) && r.re.is_match(cmd_text.as_bytes()) {
                return Some(mk(&r.name, r.kind, format!("啟動項目會執行：{}", short(&cmd_text)), r.source));
            }
        }
        if let Some(exe) = cmd.first() {
            let ep = Path::new(exe);
            if ep.is_absolute() && (in_hidden_folder(ep) || exe.starts_with("/tmp") || exe.starts_with("/private/tmp") || exe.starts_with("/Users/Shared")) {
                return Some(mk("從隱藏或暫存位置自動啟動的程式", ThreatKind::Suspicious, format!("會在開機時執行 {}", collapse(ep)), Source::Builtin));
            }
            if ep.is_absolute() && ep.exists() {
                if let Ok(md) = fs::metadata(ep) {
                    if md.is_file() {
                        if let Some(t) = self.check_file(ep, md.len()) {
                            return Some(mk(&t.name, t.kind, format!("會自動啟動已知威脅 {}", collapse(ep)), t.source));
                        }
                    }
                }
            }
        }
        None
    }
}

fn short(s: &str) -> String {
    if s.chars().count() > 80 {
        format!("{}…", s.chars().take(80).collect::<String>())
    } else {
        s.to_string()
    }
}

fn is_launch_dir(p: &Path) -> bool {
    let s = p.to_string_lossy();
    s.ends_with("/LaunchAgents") || s.ends_with("/LaunchDaemons")
}

// ---------------------------------------------------------------- scanning

#[derive(Default)]
pub struct Progress {
    pub scanned: u64,
    pub current: String,
    pub threats: Vec<Threat>,
    pub done: bool,
    pub started: u64,
    pub finished: u64,
    pub skipped: u64,
}

#[derive(Clone)]
pub struct ScanHandle {
    pub progress: Arc<Mutex<Progress>>,
    pub cancel: Arc<AtomicBool>,
}

impl ScanHandle {
    pub fn stop(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

/// Start a scan in the background. `custom` replaces the mode's folders (for a dropped file
/// or folder).
pub fn start_scan(opts: ScanOptions, rules: Arc<RuleSet>, safe: Vec<PathBuf>, custom: Option<Vec<PathBuf>>) -> ScanHandle {
    let h = ScanHandle { progress: Arc::new(Mutex::new(Progress { started: util::now_secs(), ..Default::default() })), cancel: Arc::new(AtomicBool::new(false)) };
    let hh = h.clone();
    std::thread::spawn(move || {
        let roots: Vec<(PathBuf, usize)> = match custom {
            Some(v) => v.into_iter().map(|p| (p, 64)).collect(),
            None => scan_roots(&opts),
        };
        let checker = Checker::new(&rules, &opts);
        let quarantine = util::data_dir();
        let icloud = util::home().join("Library/Mobile Documents");
        let mut visited: HashSet<PathBuf> = HashSet::new();
        let mut found: HashSet<PathBuf> = HashSet::new();
        let mut local_count = 0u64;
        for (root, depth) in roots {
            let mut stack = vec![(root, 0usize)];
            while let Some((p, d)) = stack.pop() {
                if hh.cancel.load(Ordering::Relaxed) {
                    break;
                }
                if !visited.insert(p.clone()) {
                    continue;
                }
                if p.starts_with(&quarantine) || safe.iter().any(|s| p.starts_with(s)) || p.starts_with("/System") || p.starts_with("/dev") || p.starts_with("/Volumes") && !opts.usb && !p.starts_with("/Volumes/") {
                    continue;
                }
                if opts.exclude_icloud && p.starts_with(&icloud) {
                    continue;
                }
                let Ok(md) = fs::symlink_metadata(&p) else {
                    hh.progress.lock().unwrap().skipped += 1;
                    continue;
                };
                if md.file_type().is_symlink() {
                    continue;
                }
                if md.is_dir() {
                    // Name rules also apply to folders (adware often installs whole folders).
                    if let Some(r) = checker.rules.names.iter().find(|r| r.re.is_match(&p.to_string_lossy())) {
                        if found.insert(p.clone()) {
                            let size = util::tree_size(&p, 20_000);
                            hh.progress.lock().unwrap().threats.push(Threat { path: p.clone(), name: r.name.clone(), kind: r.kind, engine: Engine::PathRule, detail: "符合已知威脅的資料夾".into(), size, source: r.source, selected: true });
                        }
                        continue;
                    }
                    if d < depth {
                        for c in util::children(&p) {
                            stack.push((c, d + 1));
                        }
                    }
                    continue;
                }
                if !md.is_file() {
                    continue;
                }
                local_count += 1;
                let ext = p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
                if ext == "dmg" && !opts.dmg {
                    continue;
                }
                let parent_is_launch = p.parent().map(is_launch_dir).unwrap_or(false);
                let t = if parent_is_launch && ext == "plist" {
                    checker.check_launch_item(&p, md.len()).or_else(|| checker.check_file(&p, md.len()))
                } else {
                    checker.check_file(&p, md.len())
                };
                let mut pr = hh.progress.lock().unwrap();
                pr.scanned += 1;
                if local_count % 37 == 0 {
                    pr.current = collapse(&p);
                }
                if let Some(mut t) = t {
                    if found.insert(t.path.clone()) {
                        t.size = util::alloc_size(&md);
                        pr.threats.push(t);
                    }
                }
            }
        }
        let mut pr = hh.progress.lock().unwrap();
        pr.threats.sort_by(|a, b| b.kind.rank().cmp(&a.kind.rank()));
        pr.done = true;
        pr.finished = util::now_secs();
        pr.current.clear();
    });
    h
}

// ---------------------------------------------------------------- browser extensions

#[derive(Clone, Debug)]
pub struct Extension {
    pub browser: String,
    pub id: String,
    pub name: String,
    pub path: PathBuf,
    pub permissions: Vec<String>,
    pub risk: u8, // 0 low, 1 medium, 2 high
    pub blocked: Option<String>,
}

pub fn list_extensions(rules: &RuleSet) -> Vec<Extension> {
    let h = util::home();
    let browsers = [
        ("Google Chrome", "Library/Application Support/Google/Chrome"),
        ("Chromium", "Library/Application Support/Chromium"),
        ("Brave", "Library/Application Support/BraveSoftware/Brave-Browser"),
        ("Microsoft Edge", "Library/Application Support/Microsoft Edge"),
    ];
    let mut out = Vec::new();
    for (bname, rel) in browsers {
        for prof in util::children(&h.join(rel)) {
            let ext_dir = prof.join("Extensions");
            for ext in util::children(&ext_dir) {
                let id = file_name(&ext);
                if id.starts_with('.') || id == "Temp" {
                    continue;
                }
                let Some(ver) = util::children(&ext).into_iter().find(|v| v.join("manifest.json").exists()) else { continue };
                let Ok(text) = fs::read_to_string(ver.join("manifest.json")) else { continue };
                let Ok(j) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
                let mut name = j.get("name").and_then(|v| v.as_str()).unwrap_or(&id).to_string();
                if name.starts_with("__MSG_") {
                    name = localized_name(&ver, &name).unwrap_or(id.clone());
                }
                let mut perms: Vec<String> = Vec::new();
                for key in ["permissions", "host_permissions", "optional_permissions"] {
                    if let Some(a) = j.get(key).and_then(|v| v.as_array()) {
                        perms.extend(a.iter().filter_map(|x| x.as_str().map(String::from)));
                    }
                }
                let all_sites = perms.iter().any(|p| p == "<all_urls>" || p.starts_with("*://*/") || p.starts_with("http://*/") || p.starts_with("https://*/"));
                let strong = perms.iter().any(|p| matches!(p.as_str(), "webRequest" | "webRequestBlocking" | "proxy" | "nativeMessaging" | "debugger" | "cookies" | "management"));
                let risk = if all_sites && strong { 2 } else if all_sites || strong { 1 } else { 0 };
                let blocked = rules.ext_ids.get(&id).cloned();
                out.push(Extension { browser: format!("{} · {}", bname, file_name(&prof)), id, name, path: ext, permissions: perms, risk, blocked });
            }
        }
    }
    out.sort_by(|a, b| b.blocked.is_some().cmp(&a.blocked.is_some()).then(b.risk.cmp(&a.risk)));
    out
}

fn localized_name(ver: &Path, msg: &str) -> Option<String> {
    let key = msg.trim_start_matches("__MSG_").trim_end_matches("__");
    for loc in ["zh_TW", "en", "en_US"] {
        if let Ok(t) = fs::read_to_string(ver.join("_locales").join(loc).join("messages.json")) {
            if let Ok(j) = serde_json::from_str::<serde_json::Value>(&t) {
                if let Some(obj) = j.as_object() {
                    for (k, v) in obj {
                        if k.eq_ignore_ascii_case(key) {
                            return v.get("message").and_then(|m| m.as_str()).map(String::from);
                        }
                    }
                }
            }
        }
    }
    None
}

/// Configuration profiles installed on this Mac, and whether it is enrolled in device
/// management, as macOS itself reports them (`profiles`). Folders under
/// /Library/Managed Preferences are not used: macOS keeps entries there for system accounts
/// such as `_mbsetupuser` even when no profile is installed.
pub fn managed_profiles() -> Vec<String> {
    let mut out = Vec::new();
    let status = util::run("profiles", &["status", "-type", "enrollment"]);
    if status.lines().any(|l| l.contains("MDM enrollment: Yes")) {
        out.push("裝置管理 (MDM)".to_string());
    }
    for l in util::run("profiles", &["list"]).lines() {
        if let Some(id) = l.split("profileIdentifier:").nth(1) {
            let id = id.trim().to_string();
            if !id.is_empty() && !out.contains(&id) {
                out.push(id);
            }
        }
    }
    out
}

// ---------------------------------------------------------------- quarantine

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct QItem {
    pub id: u64,
    pub original: PathBuf,
    pub stored: PathBuf,
    pub name: String,
    pub kind: ThreatKind,
    pub when: u64,
    pub size: u64,
}

pub fn quarantine_dir() -> PathBuf {
    let d = util::data_dir().join("Quarantine");
    let _ = fs::create_dir_all(&d);
    d
}

pub fn load_quarantine() -> Vec<QItem> {
    fs::read_to_string(quarantine_dir().join("index.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

pub fn save_quarantine(v: &[QItem]) {
    if let Ok(t) = serde_json::to_string_pretty(v) {
        let _ = fs::write(quarantine_dir().join("index.json"), t);
    }
}

fn move_path(from: &Path, to: &Path) -> Result<(), String> {
    if fs::rename(from, to).is_ok() {
        return Ok(());
    }
    // Another disk: copy, then remove the original.
    let md = fs::symlink_metadata(from).map_err(|e| e.to_string())?;
    if md.is_file() {
        fs::copy(from, to).map_err(|e| e.to_string())?;
        fs::remove_file(from).map_err(|e| e.to_string())
    } else {
        Err("無法搬移資料夾到隔離區（位於其他磁碟）".into())
    }
}

/// Put a threat in quarantine: launch items are unloaded first, files lose their execute bit.
pub fn quarantine(t: &Threat, list: &mut Vec<QItem>) -> Result<(), String> {
    if !t.path.exists() {
        return Err("檔案已不存在".into());
    }
    if t.engine == Engine::LaunchAgent {
        let _ = std::process::Command::new("launchctl").arg("unload").arg(&t.path).output();
    }
    let id = util::now_secs() * 1000 + list.len() as u64 % 1000 + (std::process::id() as u64 % 7);
    let id = if list.iter().any(|q| q.id == id) { id + 1 } else { id };
    let dir = quarantine_dir().join(id.to_string());
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let stored = dir.join(file_name(&t.path));
    move_path(&t.path, &stored).map_err(|e| format!("{}（可能需要管理員權限）", e))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if stored.is_file() {
            let _ = fs::set_permissions(&stored, fs::Permissions::from_mode(0o600));
        }
    }
    list.push(QItem { id, original: t.path.clone(), stored, name: t.name.clone(), kind: t.kind, when: util::now_secs(), size: t.size });
    save_quarantine(list);
    Ok(())
}

pub fn restore(q: &QItem) -> Result<(), String> {
    if q.original.exists() {
        return Err("原位置已有同名檔案".into());
    }
    if let Some(par) = q.original.parent() {
        let _ = fs::create_dir_all(par);
    }
    move_path(&q.stored, &q.original)?;
    if let Some(d) = q.stored.parent() {
        let _ = fs::remove_dir_all(d);
    }
    Ok(())
}

pub fn delete_quarantined(q: &QItem) -> Result<(), String> {
    match q.stored.parent() {
        Some(d) => fs::remove_dir_all(d).map_err(|e| e.to_string()),
        None => Err("找不到隔離檔案".into()),
    }
}

// ---------------------------------------------------------------- safe list (ignore list)

pub fn load_safe_list() -> Vec<PathBuf> {
    fs::read_to_string(util::data_dir().join("safe_list.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

pub fn save_safe_list(v: &[PathBuf]) {
    if let Ok(t) = serde_json::to_string_pretty(v) {
        let _ = fs::write(util::data_dir().join("safe_list.json"), t);
    }
}

// ---------------------------------------------------------------- real-time monitor

#[derive(Clone, Debug)]
pub struct MonitorEvent {
    pub when: u64,
    pub text: String,
    pub threat: Option<Threat>,
}

pub struct Monitor {
    pub running: Arc<AtomicBool>,
    pub auto_quarantine: Arc<AtomicBool>,
    pub events: Arc<Mutex<Vec<MonitorEvent>>>,
    pub checks: Arc<Mutex<u64>>,
    /// The last file the monitor checked (shown on the status page).
    pub last: Arc<Mutex<String>>,
}

/// Folders the real-time monitor watches (launch agents and daemons,
/// Applications, Downloads, Chrome extensions) with how deep to look.
pub fn watched_folders() -> Vec<(PathBuf, usize)> {
    let h = util::home();
    vec![
        (h.join("Library/LaunchAgents"), 1),
        (PathBuf::from("/Library/LaunchAgents"), 1),
        (PathBuf::from("/Library/LaunchDaemons"), 1),
        (h.join("Applications"), 1),
        (PathBuf::from("/Applications"), 1),
        (h.join("Downloads"), 2),
        (h.join("Library/Application Support/Google/Chrome/Default/Extensions"), 2),
    ]
}

fn snapshot(folders: &[(PathBuf, usize)]) -> HashMap<PathBuf, (u64, std::time::SystemTime)> {
    let mut m = HashMap::new();
    for (root, depth) in folders {
        let mut stack = vec![(root.clone(), 0usize)];
        while let Some((p, d)) = stack.pop() {
            let Ok(md) = fs::symlink_metadata(&p) else { continue };
            if md.is_dir() {
                if d < *depth && !p.extension().map(|e| e == "app").unwrap_or(false) {
                    for c in util::children(&p) {
                        stack.push((c, d + 1));
                    }
                }
            } else if md.is_file() {
                m.insert(p, (md.len(), md.modified().unwrap_or(std::time::UNIX_EPOCH)));
            }
        }
    }
    m
}

impl Monitor {
    pub fn new() -> Monitor {
        Monitor { running: Arc::new(AtomicBool::new(false)), auto_quarantine: Arc::new(AtomicBool::new(true)), events: Arc::new(Mutex::new(Vec::new())), checks: Arc::new(Mutex::new(0)), last: Arc::new(Mutex::new(String::new())) }
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn start(&self, rules: Arc<RuleSet>, safe: Arc<Mutex<Vec<PathBuf>>>, quarantine_list: Arc<Mutex<Vec<QItem>>>) {
        if self.running.swap(true, Ordering::Relaxed) {
            return;
        }
        let running = self.running.clone();
        let auto_q = self.auto_quarantine.clone();
        let events = self.events.clone();
        let checks = self.checks.clone();
        let last = self.last.clone();
        events.lock().unwrap().push(MonitorEvent { when: util::now_secs(), text: "即時防護已啟動".into(), threat: None });
        std::thread::spawn(move || {
            let folders = watched_folders();
            let mut prev = snapshot(&folders);
            let opts = ScanOptions { archives: true, ..Default::default() };
            while running.load(Ordering::Relaxed) {
                for _ in 0..(MONITOR_INTERVAL_SECS * 10) {
                    if !running.load(Ordering::Relaxed) {
                        return;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                let now = snapshot(&folders);
                let checker = Checker::new(&rules, &opts);
                for (p, (size, mt)) in &now {
                    let changed = prev.get(p).map(|(s, m)| s != size || m != mt).unwrap_or(true);
                    if !changed || safe.lock().unwrap().iter().any(|s| p.starts_with(s)) {
                        continue;
                    }
                    *checks.lock().unwrap() += 1;
                    *last.lock().unwrap() = collapse(p);
                    let launch = p.parent().map(is_launch_dir).unwrap_or(false);
                    let t = if launch { checker.check_launch_item(p, *size).or_else(|| checker.check_file(p, *size)) } else { checker.check_file(p, *size) };
                    let mut ev = events.lock().unwrap();
                    match t {
                        Some(t) => {
                            let mut text = format!("發現{}：{}（{}，來源：{}）", t.kind.label(), t.name, collapse(&t.path), t.source.label());
                            if auto_q.load(Ordering::Relaxed) {
                                let mut ql = quarantine_list.lock().unwrap();
                                match quarantine(&t, &mut ql) {
                                    Ok(()) => text.push_str("，已自動隔離"),
                                    Err(e) => text.push_str(&format!("，隔離失敗：{}", e)),
                                }
                            }
                            notify("偵測到威脅", &text);
                            ev.push(MonitorEvent { when: util::now_secs(), text, threat: Some(t) });
                        }
                        None => {
                            if launch {
                                ev.push(MonitorEvent { when: util::now_secs(), text: format!("新的啟動項目已檢查，安全：{}", collapse(p)), threat: None });
                            }
                        }
                    }
                    let n = ev.len();
                    if n > 300 {
                        ev.drain(0..n - 300);
                    }
                }
                prev = now;
            }
        });
    }

    pub fn stop(&self) {
        if self.running.swap(false, Ordering::Relaxed) {
            self.events.lock().unwrap().push(MonitorEvent { when: util::now_secs(), text: "即時防護已關閉".into(), threat: None });
        }
    }
}

pub fn notify(title: &str, body: &str) {
    let script = format!("display notification \"{}\" with title \"Sanitized\" subtitle \"{}\"", body.replace('"', "'"), title.replace('"', "'"));
    let _ = std::process::Command::new("osascript").args(["-e", &script]).spawn();
}

// ---------------------------------------------------------------- history

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct ScanRecord {
    pub when: u64,
    pub mode: String,
    pub scanned: u64,
    pub threats: usize,
    pub seconds: u64,
}

pub fn load_history() -> Vec<ScanRecord> {
    fs::read_to_string(util::data_dir().join("history.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

pub fn save_history(v: &[ScanRecord]) {
    if let Ok(t) = serde_json::to_string_pretty(v) {
        let _ = fs::write(util::data_dir().join("history.json"), t);
    }
}

/// Write the harmless standard test file into Downloads so the person can see detection work.
pub fn write_test_file() -> Result<PathBuf, String> {
    let p = expand("~/Downloads/eicar-test.com");
    fs::write(&p, eicar_bytes()).map_err(|e| e.to_string())?;
    Ok(p)
}
