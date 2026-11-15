//! Docker cleanup, following the person's rules:
//! - never touch Docker.raw or the Data folder; every removal goes through the `docker` command,
//!   each name/ID a separate argument (no shell), exact IDs/names only, one kind at a time,
//!   stop at the first failure, write a log;
//! - level 1 (rebuilt automatically): build cache and dangling images, one click;
//! - level 2 (pick from a list): unused images, stopped containers, unused networks;
//! - level 3 (one by one, explicit confirmation): volumes and running containers;
//! - report what was really freed by measuring Docker.raw's allocated size before and after.

use crate::util;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

const DOCKER_PATHS: &[&str] = &["/usr/local/bin/docker", "/opt/homebrew/bin/docker", "/Applications/Docker.app/Contents/Resources/bin/docker"];
/// Labels that name the project an item belongs to, in order of preference.
const PROJECT_LABELS: &[&str] = &["com.docker.compose.project", "com.supabase.cli.project"];
/// Networks Docker itself owns; never offered for removal.
const BUILTIN_NETWORKS: &[&str] = &["bridge", "host", "none"];

pub fn docker_bin() -> Option<PathBuf> {
    DOCKER_PATHS.iter().map(PathBuf::from).find(|p| p.exists())
}

pub fn data_dir() -> PathBuf {
    util::home().join("Library/Containers/com.docker.docker/Data")
}

pub fn raw_file() -> PathBuf {
    data_dir().join("vms/0/data/Docker.raw")
}

/// Real disk usage of Docker's disk image (allocated blocks, not its nominal size).
pub fn raw_used() -> Option<u64> {
    let p = raw_file();
    if p.exists() { Some(util::file_size_on_disk(&p)) } else { None }
}

/// Run docker with separate arguments (no shell). Ok(stdout) or Err(stderr).
fn docker(args: &[&str]) -> Result<String, String> {
    let bin = docker_bin().ok_or(t!("找不到 docker 指令"))?;
    let out = std::process::Command::new(bin).args(args).output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

/// "10.26GB", "79.2MB (99%)", "4.1kB", "0B" → bytes (Docker uses powers of 1000).
pub fn parse_size(s: &str) -> u64 {
    let t = s.split_whitespace().next().unwrap_or("").trim();
    let idx = t.find(|c: char| c.is_ascii_alphabetic()).unwrap_or(t.len());
    let (num, unit) = t.split_at(idx);
    let v: f64 = num.parse().unwrap_or(0.0);
    let m = match unit.to_ascii_lowercase().as_str() {
        "kb" => 1e3,
        "mb" => 1e6,
        "gb" => 1e9,
        "tb" => 1e12,
        _ => 1.0,
    };
    (v * m) as u64
}

fn labels_of(v: &Value) -> HashMap<String, String> {
    v.as_object().map(|o| o.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string()))).collect()).unwrap_or_default()
}

fn project_of(labels: &HashMap<String, String>, fallback: &str) -> String {
    PROJECT_LABELS.iter().find_map(|k| labels.get(*k).filter(|v| !v.is_empty()).cloned()).unwrap_or_else(|| fallback.to_string())
}

#[derive(Clone, Debug, Default)]
pub struct Summary {
    pub kind: String,
    pub total: String,
    pub active: String,
    pub size: u64,
    pub reclaimable: u64,
}

#[derive(Clone, Debug)]
pub struct Image {
    pub id: String,
    pub name: String,
    pub project: String,
    pub size: u64,
    pub unique: u64,
    pub created: String,
    pub dangling: bool,
    pub local_build: bool,
    pub used_by: Vec<String>,
    pub selected: bool,
}

#[derive(Clone, Debug)]
pub struct Container {
    pub id: String,
    pub name: String,
    pub project: String,
    pub image: String,
    pub running: bool,
    pub status: String,
    pub started: String,
    pub volumes: Vec<String>,
    pub networks: Vec<String>,
    pub size: u64,
    pub selected: bool,
}

#[derive(Clone, Debug)]
pub struct Volume {
    pub name: String,
    pub project: String,
    pub size: u64,
    pub created: String,
    /// Containers that mount it, with whether each is running.
    pub used_by: Vec<(String, bool)>,
}

#[derive(Clone, Debug)]
pub struct Network {
    pub id: String,
    pub name: String,
    pub project: String,
    pub selected: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Info {
    pub running: bool,
    pub version: String,
    pub raw_used: Option<u64>,
    pub data_used: u64,
    pub summary: Vec<Summary>,
    pub build_cache: u64,
    pub build_cache_reclaimable: u64,
    pub images: Vec<Image>,
    pub containers: Vec<Container>,
    pub volumes: Vec<Volume>,
    pub networks: Vec<Network>,
}

impl Info {
    pub fn dangling(&self) -> Vec<&Image> {
        self.images.iter().filter(|i| i.dangling && i.used_by.is_empty()).collect()
    }
    /// Images no container uses (stopped containers count as users); dangling ones are level 1.
    pub fn unused_images(&self) -> Vec<&Image> {
        self.images.iter().filter(|i| !i.dangling && i.used_by.is_empty()).collect()
    }
    pub fn stopped(&self) -> Vec<&Container> {
        self.containers.iter().filter(|c| !c.running).collect()
    }
    pub fn running(&self) -> Vec<&Container> {
        self.containers.iter().filter(|c| c.running).collect()
    }
}

/// Everything about Docker's disk use, read-only.
pub fn load() -> Info {
    let mut info = Info { raw_used: raw_used(), ..Default::default() };
    info.data_used = util::tree_size(&data_dir(), 0);
    let Ok(ver) = docker(&["info", "--format", "{{.ServerVersion}}"]) else { return info };
    info.running = true;
    info.version = ver.trim().to_string();

    for line in docker(&["system", "df", "--format", "{{json .}}"]).unwrap_or_default().lines() {
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            let g = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            let s = Summary { kind: g("Type"), total: g("TotalCount"), active: g("Active"), size: parse_size(&g("Size")), reclaimable: parse_size(&g("Reclaimable")) };
            if s.kind == "Build Cache" {
                info.build_cache = s.size;
                info.build_cache_reclaimable = s.reclaimable;
            }
            info.summary.push(s);
        }
    }
    // Per-item sizes from `docker system df -v`.
    let dfv: Value = docker(&["system", "df", "-v", "--format", "{{json .}}"]).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
    let mut img_size: HashMap<String, (u64, u64)> = HashMap::new();
    for i in dfv.get("Images").and_then(|v| v.as_array()).into_iter().flatten() {
        let id = i.get("ID").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let g = |k: &str| parse_size(i.get(k).and_then(|v| v.as_str()).unwrap_or("0B"));
        img_size.insert(id, (g("Size"), g("UniqueSize")));
    }
    let mut ctr_size: HashMap<String, u64> = HashMap::new();
    for c in dfv.get("Containers").and_then(|v| v.as_array()).into_iter().flatten() {
        let id = c.get("ID").and_then(|v| v.as_str()).unwrap_or("").to_string();
        ctr_size.insert(id, parse_size(c.get("Size").and_then(|v| v.as_str()).unwrap_or("0B")));
    }
    let mut vol_size: HashMap<String, u64> = HashMap::new();
    for v in dfv.get("Volumes").and_then(|v| v.as_array()).into_iter().flatten() {
        let n = v.get("Name").and_then(|x| x.as_str()).unwrap_or("").to_string();
        vol_size.insert(n, parse_size(v.get("Size").and_then(|x| x.as_str()).unwrap_or("0B")));
    }

    // Containers (all, stopped included).
    let ids: Vec<String> = docker(&["ps", "-aq", "--no-trunc"]).unwrap_or_default().lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if !ids.is_empty() {
        let mut args = vec!["container", "inspect"];
        args.extend(ids.iter().map(|s| s.as_str()));
        let arr: Value = docker(&args).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
        for c in arr.as_array().into_iter().flatten() {
            let id = c.get("Id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let name = c.get("Name").and_then(|v| v.as_str()).unwrap_or("").trim_start_matches('/').to_string();
            let labels = labels_of(c.pointer("/Config/Labels").unwrap_or(&Value::Null));
            let st = c.get("State").cloned().unwrap_or(Value::Null);
            let running = st.get("Running").and_then(|v| v.as_bool()).unwrap_or(false);
            let status = st.get("Status").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let started = st.get("StartedAt").and_then(|v| v.as_str()).unwrap_or("").chars().take(19).collect::<String>().replace('T', " ");
            let volumes = c.get("Mounts").and_then(|v| v.as_array()).into_iter().flatten().filter(|m| m.get("Type").and_then(|t| t.as_str()) == Some("volume")).filter_map(|m| m.get("Name").and_then(|n| n.as_str()).map(String::from)).collect();
            let networks = c.pointer("/NetworkSettings/Networks").and_then(|v| v.as_object()).map(|o| o.keys().cloned().collect()).unwrap_or_default();
            let image = c.get("Image").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let size = ctr_size.iter().find(|(k, _)| id.starts_with(k.as_str()) || k.starts_with(&id)).map(|(_, v)| *v).unwrap_or(0);
            info.containers.push(Container { project: project_of(&labels, &name), id, name, image, running, status, started, volumes, networks, size, selected: false });
        }
    }

    // Images.
    // Top-level images only (not intermediate layers); dangling = Docker's own definition.
    let dangling_ids: HashSet<String> = docker(&["image", "ls", "-q", "--no-trunc", "--filter", "dangling=true"]).unwrap_or_default().lines().map(|s| s.trim().to_string()).collect();
    let iids: Vec<String> = docker(&["image", "ls", "-q", "--no-trunc"]).unwrap_or_default().lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).chain(dangling_ids.iter().cloned()).filter(|s| !s.is_empty()).collect::<HashSet<_>>().into_iter().collect();
    if !iids.is_empty() {
        let mut args = vec!["image", "inspect"];
        args.extend(iids.iter().map(|s| s.as_str()));
        let arr: Value = docker(&args).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
        for i in arr.as_array().into_iter().flatten() {
            let id = i.get("Id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let tags: Vec<String> = i.get("RepoTags").and_then(|v| v.as_array()).into_iter().flatten().filter_map(|t| t.as_str().map(String::from)).collect();
            let digests = i.get("RepoDigests").and_then(|v| v.as_array()).map(|a| a.len()).unwrap_or(0);
            let labels = labels_of(i.pointer("/Config/Labels").unwrap_or(&Value::Null));
            let name = tags.first().cloned().unwrap_or_else(|| tf!("<無名稱> {}", &id.trim_start_matches("sha256:")[..12.min(id.len())]));
            let (size, unique) = img_size.get(&id).copied().unwrap_or((i.get("Size").and_then(|v| v.as_u64()).unwrap_or(0), 0));
            let used_by: Vec<String> = info.containers.iter().filter(|c| c.image == id).map(|c| c.name.clone()).collect();
            let repo = tags.first().map(|t| t.rsplit_once(':').map(|(r, _)| r.to_string()).unwrap_or(t.clone())).unwrap_or_else(|| name.clone());
            info.images.push(Image {
                project: project_of(&labels, &repo),
                created: i.get("Created").and_then(|v| v.as_str()).unwrap_or("").chars().take(10).collect(),
                dangling: dangling_ids.contains(&id),
                local_build: digests == 0,
                id,
                name,
                size,
                unique,
                used_by,
                selected: false,
            });
        }
        info.images.sort_by(|a, b| b.unique.cmp(&a.unique));
    }

    // Volumes.
    let vnames: Vec<String> = docker(&["volume", "ls", "-q"]).unwrap_or_default().lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if !vnames.is_empty() {
        let mut args = vec!["volume", "inspect"];
        args.extend(vnames.iter().map(|s| s.as_str()));
        let arr: Value = docker(&args).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null);
        for v in arr.as_array().into_iter().flatten() {
            let name = v.get("Name").and_then(|x| x.as_str()).unwrap_or("").to_string();
            let labels = labels_of(v.get("Labels").unwrap_or(&Value::Null));
            let used_by = info.containers.iter().filter(|c| c.volumes.iter().any(|n| n == &name)).map(|c| (c.name.clone(), c.running)).collect();
            info.volumes.push(Volume { project: project_of(&labels, &name), size: vol_size.get(&name).copied().unwrap_or(0), created: v.get("CreatedAt").and_then(|x| x.as_str()).unwrap_or("").chars().take(10).collect(), name, used_by });
        }
    }

    // Networks no container (running or stopped) is attached to.
    let used_nets: HashSet<String> = info.containers.iter().flat_map(|c| c.networks.iter().cloned()).collect();
    for line in docker(&["network", "ls", "--no-trunc", "--format", "{{json .}}"]).unwrap_or_default().lines() {
        if let Ok(v) = serde_json::from_str::<Value>(line) {
            let name = v.get("Name").and_then(|x| x.as_str()).unwrap_or("").to_string();
            if BUILTIN_NETWORKS.contains(&name.as_str()) || used_nets.contains(&name) {
                continue;
            }
            let labels: HashMap<String, String> = v.get("Labels").and_then(|x| x.as_str()).unwrap_or("").split(',').filter_map(|kv| kv.split_once('=').map(|(k, v)| (k.to_string(), v.to_string()))).collect();
            let id = v.get("ID").and_then(|x| x.as_str()).unwrap_or("").to_string();
            info.networks.push(Network { project: project_of(&labels, &name), id, name, selected: false });
        }
    }
    info
}

/// Group anything by project name, exactly (no prefix matching: "demo" ≠ "demo-test").
pub fn by_project<'a, T>(items: &'a [T], project: impl Fn(&T) -> &str) -> BTreeMap<String, Vec<&'a T>> {
    let mut m: BTreeMap<String, Vec<&T>> = BTreeMap::new();
    for it in items {
        m.entry(project(it).to_string()).or_default().push(it);
    }
    m
}

/// Items of exactly one project.
pub fn of_project<'a, T>(items: &'a [T], project: impl Fn(&T) -> &str, name: &str) -> Vec<&'a T> {
    items.iter().filter(|t| project(t) == name).collect()
}

// ---------------------------------------------------------------- running a cleanup

#[derive(Clone, Debug)]
pub struct Step {
    /// Shown to the person before running.
    pub title: String,
    /// The docker arguments, each one separate.
    pub args: Vec<String>,
    /// The exact items it removes (for the list and the log).
    pub items: Vec<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Report {
    pub lines: Vec<String>,
    pub failed: bool,
    pub before: Option<u64>,
    pub after: Option<u64>,
    pub stopped_unexpectedly: Vec<String>,
}

pub fn level1_steps(info: &Info) -> Vec<Step> {
    let mut v = Vec::new();
    if info.build_cache_reclaimable > 0 {
        v.push(Step { title: t!("清除建置快取（下次建置會比較慢）").into(), args: vec!["builder".into(), "prune".into(), "--force".into()], items: vec![tf!("建置快取，可釋放約 {}", util::fmt_bytes(info.build_cache_reclaimable))] });
    }
    let d = info.dangling();
    if !d.is_empty() {
        v.push(Step { title: t!("清除沒有名稱的殘留映像檔").into(), args: vec!["image".into(), "prune".into(), "--force".into()], items: d.iter().map(|i| i.name.clone()).collect() });
    }
    v
}

/// Level 2: what the person ticked, one kind per step, by full ID.
pub fn level2_steps(info: &Info) -> Vec<Step> {
    let mut v = Vec::new();
    let c: Vec<&Container> = info.containers.iter().filter(|c| c.selected && !c.running).collect();
    if !c.is_empty() {
        let mut args = vec!["container".to_string(), "rm".to_string()];
        args.extend(c.iter().map(|c| c.id.clone()));
        v.push(Step { title: t!("刪除已停止的容器").into(), args, items: c.iter().map(|c| c.name.clone()).collect() });
    }
    let i: Vec<&Image> = info.images.iter().filter(|i| i.selected && i.used_by.is_empty()).collect();
    if !i.is_empty() {
        let mut args = vec!["image".to_string(), "rm".to_string()];
        args.extend(i.iter().map(|i| i.id.clone()));
        v.push(Step { title: t!("刪除沒有容器使用的映像檔").into(), args, items: i.iter().map(|i| i.name.clone()).collect() });
    }
    let n: Vec<&Network> = info.networks.iter().filter(|n| n.selected).collect();
    if !n.is_empty() {
        let mut args = vec!["network".to_string(), "rm".to_string()];
        args.extend(n.iter().map(|n| n.id.clone()));
        v.push(Step { title: t!("刪除沒在用的網路").into(), args, items: n.iter().map(|n| n.name.clone()).collect() });
    }
    v
}

/// Level 3: one volume (exact name) — never `volume prune` or `system prune --volumes`.
pub fn volume_step(name: &str) -> Step {
    Step { title: tf!("刪除 volume「{}」（無法復原）", name), args: vec!["volume".into(), "rm".into(), name.to_string()], items: vec![name.to_string()] }
}

/// Level 3: stop then remove one running container (full ID).
pub fn running_container_steps(c: &Container) -> Vec<Step> {
    vec![
        Step { title: tf!("停止容器「{}」", c.name), args: vec!["container".into(), "stop".into(), c.id.clone()], items: vec![c.name.clone()] },
        Step { title: tf!("刪除容器「{}」", c.name), args: vec!["container".into(), "rm".into(), c.id.clone()], items: vec![c.name.clone()] },
    ]
}

fn log(line: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(util::data_dir().join("docker_cleanup.log")) {
        use std::io::Write;
        let _ = writeln!(f, "{} {}", util::now_secs(), line);
    }
}

/// Run steps in order; stop at the first failure. Measures Docker.raw before and after and
/// checks that containers that were running still are.
pub fn run(steps: &[Step]) -> Report {
    let mut r = Report { before: raw_used(), ..Default::default() };
    let running_before: Vec<String> = docker(&["ps", "--format", "{{.Names}}"]).unwrap_or_default().lines().map(String::from).collect();
    let deleting: HashSet<String> = steps.iter().filter(|s| s.args.get(1).map(|a| a == "stop").unwrap_or(false)).flat_map(|s| s.items.clone()).collect();
    for s in steps {
        let args: Vec<&str> = s.args.iter().map(|a| a.as_str()).collect();
        log(&format!("RUN docker {} | 項目：{}", s.args.join(" "), s.items.join("、"))); // i18n-ignore
        match docker(&args) {
            Ok(_) => {
                r.lines.push(format!("✓ {}", tf!("{}（{} 項）", s.title, s.items.len())));
                log("OK");
            }
            Err(e) => {
                r.lines.push(tf!("失敗：{}：{}。後面的步驟已停止。", s.title, e));
                log(&format!("FAIL {}", e));
                r.failed = true;
                break;
            }
        }
    }
    let running_after: HashSet<String> = docker(&["ps", "--format", "{{.Names}}"]).unwrap_or_default().lines().map(String::from).collect();
    r.stopped_unexpectedly = running_before.into_iter().filter(|n| !running_after.contains(n) && !deleting.contains(n)).collect();
    r.after = raw_used();
    log(&format!("Docker.raw 實際佔用 前 {:?} 後 {:?}", r.before, r.after)); // i18n-ignore
    r
}
