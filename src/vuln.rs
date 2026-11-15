//! Project vulnerability check: read the dependency lists of software projects, then look up
//! each package version in the public vulnerability database (OSV.dev, which links every entry
//! to its CVE number) and report what needs updating.

use crate::util::{self, collapse};
use regex::Regex;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub const OSV_BATCH: &str = "https://api.osv.dev/v1/querybatch";
pub const OSV_VULN: &str = "https://api.osv.dev/v1/vulns/";
/// Packages per batch request (OSV allows up to 1000).
pub const BATCH_SIZE: usize = 500;
/// Folder depth searched for dependency files.
pub const PROJECT_DEPTH: usize = 6;
/// Most vulnerability records fetched in detail per check.
pub const MAX_DETAILS: usize = 400;

const SKIP_DIRS: &[&str] = &["node_modules", ".git", "target", "vendor", "dist", "build", ".venv", "venv", "__pycache__", ".next", "Pods", ".gradle", ".idea", "DerivedData"];

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Package {
    pub ecosystem: &'static str,
    pub name: String,
    pub version: String,
}

#[derive(Clone, Debug)]
pub struct Manifest {
    pub path: PathBuf,
    pub kind: &'static str,
    pub packages: Vec<Package>,
    pub exact: bool,
}

#[derive(Clone, Debug)]
pub struct Vuln {
    pub id: String,
    pub cves: Vec<String>,
    pub summary: String,
    pub severity: Severity,
    pub fixed: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Unknown,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Critical => t!("嚴重"),
            Severity::High => t!("高"),
            Severity::Medium => t!("中"),
            Severity::Low => t!("低"),
            Severity::Unknown => t!("未評級"),
        }
    }
    fn parse(s: &str) -> Severity {
        match s.to_ascii_uppercase().as_str() {
            "CRITICAL" => Severity::Critical,
            "HIGH" => Severity::High,
            "MODERATE" | "MEDIUM" => Severity::Medium,
            "LOW" => Severity::Low,
            _ => Severity::Unknown,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub package: Package,
    pub files: Vec<PathBuf>,
    pub vulns: Vec<Vuln>,
    pub upgrade_to: Option<String>,
    pub selected: bool,
}

impl Finding {
    pub fn worst(&self) -> Severity {
        self.vulns.iter().map(|v| v.severity).max().unwrap_or(Severity::Unknown)
    }
}

#[derive(Default)]
pub struct CheckProgress {
    pub stage: String,
    pub manifests: Vec<Manifest>,
    pub packages: usize,
    pub findings: Vec<Finding>,
    pub done: bool,
    pub error: Option<String>,
    pub fraction: f32,
}

#[derive(Clone)]
pub struct CheckHandle {
    pub progress: Arc<Mutex<CheckProgress>>,
    pub cancel: Arc<AtomicBool>,
}

// ---------------------------------------------------------------- reading dependency files

fn clean_ver(v: &str) -> String {
    v.trim().trim_start_matches(['^', '~', '=', 'v', '>', '<', ' ']).split([',', ' ', '|']).next().unwrap_or("").to_string()
}

fn npm_lock(text: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let Ok(j) = serde_json::from_str::<serde_json::Value>(text) else { return out };
    if let Some(pk) = j.get("packages").and_then(|p| p.as_object()) {
        for (k, v) in pk {
            if k.is_empty() {
                continue;
            }
            let name = k.rsplit("node_modules/").next().unwrap_or(k);
            if let Some(ver) = v.get("version").and_then(|x| x.as_str()) {
                if v.get("link").and_then(|l| l.as_bool()) != Some(true) {
                    out.push(Package { ecosystem: "npm", name: name.to_string(), version: ver.to_string() });
                }
            }
        }
    } else if let Some(deps) = j.get("dependencies").and_then(|d| d.as_object()) {
        fn walk(d: &serde_json::Map<String, serde_json::Value>, out: &mut Vec<Package>) {
            for (k, v) in d {
                if let Some(ver) = v.get("version").and_then(|x| x.as_str()) {
                    out.push(Package { ecosystem: "npm", name: k.clone(), version: ver.to_string() });
                }
                if let Some(sub) = v.get("dependencies").and_then(|x| x.as_object()) {
                    walk(sub, out);
                }
            }
        }
        walk(deps, &mut out);
    }
    out
}

fn npm_manifest(text: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let Ok(j) = serde_json::from_str::<serde_json::Value>(text) else { return out };
    for key in ["dependencies", "devDependencies"] {
        if let Some(d) = j.get(key).and_then(|d| d.as_object()) {
            for (k, v) in d {
                if let Some(s) = v.as_str() {
                    let ver = clean_ver(s);
                    if ver.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                        out.push(Package { ecosystem: "npm", name: k.clone(), version: ver });
                    }
                }
            }
        }
    }
    out
}

fn yarn_lock(text: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let mut cur: Option<String> = None;
    for line in text.lines() {
        if !line.starts_with(' ') && line.ends_with(':') && !line.starts_with('#') {
            let first = line.trim_end_matches(':').split(',').next().unwrap_or("").trim().trim_matches('"');
            let name = match first.strip_prefix('@') {
                Some(rest) => format!("@{}", rest.split('@').next().unwrap_or("")),
                None => first.split('@').next().unwrap_or("").to_string(),
            };
            cur = if name.is_empty() { None } else { Some(name) };
        } else if let Some(name) = &cur {
            let t = line.trim();
            if let Some(v) = t.strip_prefix("version ").or_else(|| t.strip_prefix("version: ")) {
                out.push(Package { ecosystem: "npm", name: name.clone(), version: v.trim_matches('"').to_string() });
                cur = None;
            }
        }
    }
    out
}

fn toml_packages(text: &str, eco: &'static str) -> Vec<Package> {
    // Cargo.lock and poetry.lock: [[package]] blocks with name = "…" and version = "…".
    let mut out = Vec::new();
    let mut name = None;
    for line in text.lines() {
        let t = line.trim();
        if t == "[[package]]" {
            name = None;
        } else if let Some(v) = t.strip_prefix("name = ") {
            name = Some(v.trim_matches('"').to_string());
        } else if let Some(v) = t.strip_prefix("version = ") {
            if let Some(n) = name.take() {
                out.push(Package { ecosystem: eco, name: n, version: v.trim_matches('"').to_string() });
            }
        }
    }
    out
}

fn requirements(text: &str) -> Vec<Package> {
    let re = Regex::new(r"^\s*([A-Za-z0-9_.\-\[\]]+)\s*==\s*([A-Za-z0-9_.\-+]+)").unwrap();
    text.lines()
        .filter_map(|l| re.captures(l))
        .map(|c| Package { ecosystem: "PyPI", name: c[1].split('[').next().unwrap_or(&c[1]).to_string(), version: c[2].to_string() })
        .collect()
}

fn pipfile_lock(text: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let Ok(j) = serde_json::from_str::<serde_json::Value>(text) else { return out };
    for key in ["default", "develop"] {
        if let Some(d) = j.get(key).and_then(|d| d.as_object()) {
            for (k, v) in d {
                if let Some(s) = v.get("version").and_then(|x| x.as_str()) {
                    out.push(Package { ecosystem: "PyPI", name: k.clone(), version: clean_ver(s) });
                }
            }
        }
    }
    out
}

fn go_mod(text: &str) -> Vec<Package> {
    let re = Regex::new(r"^\s*(?:require\s+)?([a-zA-Z0-9.\-_/]+\.[a-z]+/[^\s]+)\s+(v[0-9][^\s]*)").unwrap();
    text.lines()
        .filter(|l| !l.trim_start().starts_with("module") && !l.contains("// indirect-skip"))
        .filter_map(|l| re.captures(l))
        .map(|c| Package { ecosystem: "Go", name: c[1].to_string(), version: c[2].to_string() })
        .collect()
}

fn gemfile_lock(text: &str) -> Vec<Package> {
    let re = Regex::new(r"^    ([A-Za-z0-9_.\-]+) \(([0-9][^)\s]*)\)").unwrap();
    text.lines().filter_map(|l| re.captures(l)).map(|c| Package { ecosystem: "RubyGems", name: c[1].to_string(), version: c[2].to_string() }).collect()
}

fn composer_lock(text: &str) -> Vec<Package> {
    let mut out = Vec::new();
    let Ok(j) = serde_json::from_str::<serde_json::Value>(text) else { return out };
    for key in ["packages", "packages-dev"] {
        if let Some(a) = j.get(key).and_then(|d| d.as_array()) {
            for p in a {
                if let (Some(n), Some(v)) = (p.get("name").and_then(|x| x.as_str()), p.get("version").and_then(|x| x.as_str())) {
                    out.push(Package { ecosystem: "Packagist", name: n.to_string(), version: clean_ver(v) });
                }
            }
        }
    }
    out
}

fn pom_xml(text: &str) -> Vec<Package> {
    let re = Regex::new(r"(?s)<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*<version>([0-9][^<$]*)</version>").unwrap();
    re.captures_iter(text).map(|c| Package { ecosystem: "Maven", name: format!("{}:{}", c[1].trim(), c[2].trim()), version: c[3].trim().to_string() }).collect()
}

fn csproj(text: &str) -> Vec<Package> {
    let re = Regex::new(r#"<PackageReference\s+Include="([^"]+)"\s+Version="([0-9][^"]*)""#).unwrap();
    re.captures_iter(text).map(|c| Package { ecosystem: "NuGet", name: c[1].to_string(), version: c[2].to_string() }).collect()
}

/// Recognise a dependency file by name and read its packages.
pub fn read_manifest(p: &Path) -> Option<Manifest> {
    let name = util::file_name(p);
    let (kind, exact, parser): (&'static str, bool, fn(&str) -> Vec<Package>) = match name.as_str() {
        "package-lock.json" | "npm-shrinkwrap.json" => (n!("npm 鎖定檔"), true, npm_lock),
        "yarn.lock" => (n!("Yarn 鎖定檔"), true, yarn_lock),
        "package.json" => (n!("npm 套件清單"), false, npm_manifest),
        "Cargo.lock" => ("Rust Cargo.lock", true, |t| toml_packages(t, "crates.io")),
        "poetry.lock" => ("Python Poetry", true, |t| toml_packages(t, "PyPI")),
        "Pipfile.lock" => ("Python Pipenv", true, pipfile_lock),
        "go.mod" => (n!("Go 模組"), true, go_mod),
        "Gemfile.lock" => ("Ruby Bundler", true, gemfile_lock),
        "composer.lock" => ("PHP Composer", true, composer_lock),
        "pom.xml" => ("Java Maven", true, pom_xml),
        n if n.ends_with(".csproj") => (n!(".NET 專案"), true, csproj),
        n if n.starts_with("requirements") && n.ends_with(".txt") => ("Python requirements", true, requirements),
        _ => return None,
    };
    let md = fs::metadata(p).ok()?;
    if md.len() > 30_000_000 {
        return None;
    }
    let text = fs::read_to_string(p).ok()?;
    let mut packages = parser(&text);
    packages.sort();
    packages.dedup();
    Some(Manifest { path: p.to_path_buf(), kind, packages, exact })
}

pub fn find_manifests(root: &Path, cancel: &AtomicBool) -> Vec<Manifest> {
    let mut out = Vec::new();
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    while let Some((p, d)) = stack.pop() {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let Ok(md) = fs::symlink_metadata(&p) else { continue };
        if md.is_dir() {
            let n = util::file_name(&p);
            if d > 0 && SKIP_DIRS.contains(&n.as_str()) {
                continue;
            }
            if d < PROJECT_DEPTH {
                for c in util::children(&p) {
                    stack.push((c, d + 1));
                }
            }
        } else if md.is_file() {
            if let Some(m) = read_manifest(&p) {
                out.push(m);
            }
        }
    }
    // A lock file makes the plain package.json beside it unnecessary.
    let locked: HashSet<PathBuf> = out.iter().filter(|m| m.exact && m.packages.first().map(|p| p.ecosystem == "npm").unwrap_or(false)).filter_map(|m| m.path.parent().map(Path::to_path_buf)).collect();
    out.retain(|m| !(m.kind == n!("npm 套件清單") && m.path.parent().map(|p| locked.contains(p)).unwrap_or(false)));
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

// ---------------------------------------------------------------- the CVE lookup

fn post_json(url: &str, body: &str) -> Result<serde_json::Value, String> {
    let mut child = std::process::Command::new("curl")
        .args(["-sS", "--max-time", "60", "-H", "Content-Type: application/json", "--data-binary", "@-", url])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    child.stdin.take().ok_or("stdin")?.write_all(body.as_bytes()).map_err(|e| e.to_string())?;
    let out = child.wait_with_output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(tf!("無法連線到漏洞資料庫：{}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    serde_json::from_slice(&out.stdout).map_err(|e| tf!("資料庫回應無法解讀：{}", e))
}

fn get_json(url: &str) -> Result<serde_json::Value, String> {
    let out = std::process::Command::new("curl").args(["-sS", "--max-time", "30", url]).output().map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    serde_json::from_slice(&out.stdout).map_err(|e| e.to_string())
}

fn parse_vuln(j: &serde_json::Value, pkg: &Package) -> Vuln {
    let id = j.get("id").and_then(|x| x.as_str()).unwrap_or("").to_string();
    let mut cves: Vec<String> = j.get("aliases").and_then(|a| a.as_array()).map(|a| a.iter().filter_map(|x| x.as_str()).filter(|s| s.starts_with("CVE-")).map(String::from).collect()).unwrap_or_default();
    if id.starts_with("CVE-") && !cves.contains(&id) {
        cves.insert(0, id.clone());
    }
    let summary = j.get("summary").and_then(|x| x.as_str()).or_else(|| j.get("details").and_then(|x| x.as_str())).unwrap_or("").lines().next().unwrap_or("").to_string();
    let mut severity = j.pointer("/database_specific/severity").and_then(|x| x.as_str()).map(Severity::parse).unwrap_or(Severity::Unknown);
    if severity == Severity::Unknown {
        if let Some(a) = j.get("affected").and_then(|a| a.as_array()) {
            for af in a {
                if let Some(s) = af.pointer("/ecosystem_specific/severity").and_then(|x| x.as_str()) {
                    severity = Severity::parse(s);
                }
            }
        }
    }
    if severity == Severity::Unknown {
        if let Some(v) = j.get("severity").and_then(|s| s.as_array()).and_then(|a| a.first()).and_then(|s| s.get("score")).and_then(|s| s.as_str()) {
            severity = cvss_rough(v);
        }
    }
    let mut fixed = Vec::new();
    if let Some(a) = j.get("affected").and_then(|a| a.as_array()) {
        for af in a {
            let same = af.pointer("/package/name").and_then(|x| x.as_str()).map(|n| n.eq_ignore_ascii_case(&pkg.name)).unwrap_or(true);
            if !same {
                continue;
            }
            if let Some(ranges) = af.get("ranges").and_then(|r| r.as_array()) {
                for r in ranges {
                    if let Some(ev) = r.get("events").and_then(|e| e.as_array()) {
                        for e in ev {
                            if let Some(f) = e.get("fixed").and_then(|x| x.as_str()) {
                                if !fixed.contains(&f.to_string()) {
                                    fixed.push(f.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Vuln { id, cves, summary, severity, fixed }
}

/// Rough severity from a CVSS v3 vector when no rating is given (network + no privileges +
/// high impact counts as high). Estimated; real scores come from the CVE record.
fn cvss_rough(v: &str) -> Severity {
    if !v.starts_with("CVSS:3") {
        return Severity::Unknown;
    }
    let high_impact = ["C:H", "I:H", "A:H"].iter().filter(|m| v.contains(*m)).count();
    let net = v.contains("AV:N");
    let nopriv = v.contains("PR:N");
    match (high_impact, net && nopriv) {
        (3, true) => Severity::Critical,
        (n, true) if n >= 1 => Severity::High,
        (n, _) if n >= 1 => Severity::Medium,
        _ => Severity::Low,
    }
}

/// Compare dotted versions numerically ("1.10.0" > "1.9.3").
pub fn cmp_ver(a: &str, b: &str) -> std::cmp::Ordering {
    let parts = |s: &str| -> Vec<u64> { s.trim_start_matches('v').split(|c: char| !c.is_ascii_digit()).filter(|x| !x.is_empty()).map(|x| x.parse().unwrap_or(0)).collect() };
    let (pa, pb) = (parts(a), parts(b));
    for i in 0..pa.len().max(pb.len()) {
        let (x, y) = (pa.get(i).copied().unwrap_or(0), pb.get(i).copied().unwrap_or(0));
        if x != y {
            return x.cmp(&y);
        }
    }
    std::cmp::Ordering::Equal
}

pub fn start_check(root: PathBuf) -> CheckHandle {
    let h = CheckHandle { progress: Arc::new(Mutex::new(CheckProgress { stage: t!("正在尋找專案的相依套件清單…").into(), ..Default::default() })), cancel: Arc::new(AtomicBool::new(false)) };
    let hh = h.clone();
    std::thread::spawn(move || {
        let set_stage = |s: String, f: f32| {
            let mut p = hh.progress.lock().unwrap();
            p.stage = s;
            p.fraction = f;
        };
        let manifests = find_manifests(&root, &hh.cancel);
        let mut files_of: BTreeMap<Package, Vec<PathBuf>> = BTreeMap::new();
        for m in &manifests {
            for p in &m.packages {
                files_of.entry(p.clone()).or_default().push(m.path.clone());
            }
        }
        {
            let mut p = hh.progress.lock().unwrap();
            p.manifests = manifests;
            p.packages = files_of.len();
        }
        if files_of.is_empty() {
            let mut p = hh.progress.lock().unwrap();
            p.done = true;
            p.fraction = 1.0;
            p.stage = t!("這個資料夾裡沒有找到可檢查的相依套件清單。").into();
            return;
        }
        let pkgs: Vec<Package> = files_of.keys().cloned().collect();
        let mut hits: Vec<(Package, Vec<String>)> = Vec::new();
        let batches = pkgs.chunks(BATCH_SIZE).count().max(1);
        for (bi, chunk) in pkgs.chunks(BATCH_SIZE).enumerate() {
            if hh.cancel.load(Ordering::Relaxed) {
                break;
            }
            set_stage(tf!("正在查詢漏洞資料庫（{} 個套件）…", pkgs.len()), 0.1 + 0.4 * bi as f32 / batches as f32);
            let queries: Vec<serde_json::Value> = chunk.iter().map(|p| serde_json::json!({"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version})).collect();
            let body = serde_json::json!({ "queries": queries }).to_string();
            match post_json(OSV_BATCH, &body) {
                Ok(j) => {
                    if let Some(res) = j.get("results").and_then(|r| r.as_array()) {
                        for (i, r) in res.iter().enumerate() {
                            let ids: Vec<String> = r.get("vulns").and_then(|v| v.as_array()).map(|a| a.iter().filter_map(|x| x.get("id").and_then(|i| i.as_str()).map(String::from)).collect()).unwrap_or_default();
                            if !ids.is_empty() {
                                if let Some(p) = chunk.get(i) {
                                    hits.push((p.clone(), ids));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    let mut p = hh.progress.lock().unwrap();
                    p.error = Some(e);
                    p.done = true;
                    return;
                }
            }
        }
        let total: usize = hits.iter().map(|(_, ids)| ids.len()).sum::<usize>().min(MAX_DETAILS).max(1);
        let mut cache: HashMap<String, serde_json::Value> = HashMap::new();
        let mut fetched = 0usize;
        let mut findings = Vec::new();
        for (pkg, ids) in hits {
            if hh.cancel.load(Ordering::Relaxed) {
                break;
            }
            let mut vulns = Vec::new();
            for id in ids {
                let j = if let Some(j) = cache.get(&id) {
                    Some(j.clone())
                } else if fetched < MAX_DETAILS {
                    fetched += 1;
                    set_stage(tf!("正在讀取漏洞詳情 {}（{}）…", id, pkg.name), 0.5 + 0.5 * fetched as f32 / total as f32);
                    get_json(&format!("{}{}", OSV_VULN, id)).ok().inspect(|j| {
                        cache.insert(id.clone(), j.clone());
                    })
                } else {
                    None
                };
                match j {
                    Some(j) => vulns.push(parse_vuln(&j, &pkg)),
                    None => vulns.push(Vuln { id: id.clone(), cves: vec![], summary: String::new(), severity: Severity::Unknown, fixed: vec![] }),
                }
            }
            vulns.sort_by(|a, b| b.severity.cmp(&a.severity));
            // The smallest fixed version above the current one that fixes every listed issue.
            let mut upgrade: Option<String> = None;
            for v in &vulns {
                if let Some(f) = v.fixed.iter().filter(|f| cmp_ver(f, &pkg.version).is_gt()).min_by(|a, b| cmp_ver(a, b)) {
                    if upgrade.as_ref().map(|u| cmp_ver(f, u).is_gt()).unwrap_or(true) {
                        upgrade = Some(f.clone());
                    }
                }
            }
            let files = files_of.get(&pkg).cloned().unwrap_or_default();
            findings.push(Finding { package: pkg, files, vulns, upgrade_to: upgrade, selected: false });
        }
        findings.sort_by(|a, b| b.worst().cmp(&a.worst()).then(b.vulns.len().cmp(&a.vulns.len())));
        let mut p = hh.progress.lock().unwrap();
        p.findings = findings;
        p.done = true;
        p.fraction = 1.0;
        p.stage = String::new();
    });
    h
}

/// The command a developer runs to update one package.
pub fn update_hint(f: &Finding) -> String {
    let to = f.upgrade_to.clone().unwrap_or_else(|| t!("最新版").into());
    let n = &f.package.name;
    match f.package.ecosystem {
        "npm" => format!("npm install {}@{}", n, to),
        "PyPI" => format!("pip install \"{}>={}\"", n, to),
        "crates.io" => format!("cargo update -p {} --precise {}", n, to),
        "Go" => format!("go get {}@{}", n, to),
        "RubyGems" => format!("bundle update {}", n),
        "Packagist" => format!("composer require {}:^{}", n, to),
        "Maven" => tf!("把 pom.xml 中 {} 的版本改為 {}", n, to),
        "NuGet" => format!("dotnet add package {} --version {}", n, to),
        _ => tf!("更新 {} 到 {}", n, to),
    }
}

pub fn report_text(root: &Path, findings: &[Finding]) -> String {
    let mut s = tf!("專案漏洞檢查報告\n資料夾：{}\n\n", collapse(root));
    for f in findings {
        s.push_str(&format!("[{}] {} {} ({})\n", f.worst().label(), f.package.name, f.package.version, f.package.ecosystem));
        for v in &f.vulns {
            let ids = if v.cves.is_empty() { v.id.clone() } else { v.cves.join(", ") };
            s.push_str(&format!("  - {} {}\n", ids, v.summary));
        }
        s.push_str(&tf!("  建議：{}\n\n", update_hint(f)));
    }
    s
}
