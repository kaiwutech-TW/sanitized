//! Live system status (menu-bar panel; health score and memory diagnosis follow
//! the open-source Mole project's `mo status` / `mo optimize`). Read-only: nothing here changes
//! the system except `quit_app`, which asks one app to quit.

use crate::util;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Seconds between samples.
pub const SAMPLE_SECS: u64 = 2;

// Health score weights and thresholds (Mole cmd/status/metrics_health.go).
const CPU_WEIGHT: f32 = 30.0;
const MEM_WEIGHT: f32 = 25.0;
const DISK_WEIGHT: f32 = 20.0;
const CPU_NORMAL: f32 = 50.0;
const CPU_HIGH: f32 = 85.0;
const MEM_NORMAL: f32 = 70.0;
const MEM_HIGH: f32 = 88.0;
const PRESSURE_WARN_PENALTY: f32 = 5.0;
const PRESSURE_CRIT_PENALTY: f32 = 15.0;
const DISK_WARN: f32 = 80.0;
const DISK_CRIT: f32 = 93.0;
const UPTIME_WARN_DAYS: u64 = 7;
const UPTIME_DANGER_DAYS: u64 = 14;
// Memory diagnosis thresholds (Mole lib/optimize/diagnostics.sh).
pub const SWAP_WARN_PCT: f32 = 50.0;
pub const FREE_WARN_PCT: f32 = 15.0;

#[derive(Clone, Debug, Default)]
pub struct Proc {
    pub pid: u32,
    pub name: String,
    pub app_name: Option<String>,
    pub rss: u64,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub ready: bool,
    pub model: String,
    pub cpu_pct: f32,
    pub cores: u32,
    pub load: [f32; 3],
    pub mem_total: u64,
    pub mem_used: u64,
    pub mem_used_pct: f32,
    pub mem_free_pct: f32,
    pub pressure: String, // normal / warn / critical
    pub swap_used: u64,
    pub swap_total: u64,
    pub disk_total: u64,
    pub disk_free: u64,
    pub net_iface: String,
    pub net_up: f64,
    pub net_down: f64,
    pub battery: Option<(u32, String)>,
    pub devices: Vec<String>,
    pub uptime_secs: u64,
    pub top_mem: Vec<Proc>,
    pub vm_rss: u64,
    pub health: u32,
    pub issues: Vec<String>,
}

impl Snapshot {
    pub fn health_label(&self) -> &'static str {
        match self.health {
            85.. => "極佳",
            65..=84 => "良好",
            45..=64 => "普通",
            _ => "需要注意",
        }
    }
    pub fn pressure_label(&self) -> &'static str {
        match self.pressure.as_str() {
            "warn" => "偏高",
            "critical" => "嚴重",
            "normal" => "正常",
            _ => "未知",
        }
    }
    pub fn disk_used_pct(&self) -> f32 {
        if self.disk_total == 0 { 0.0 } else { 100.0 * (self.disk_total - self.disk_free) as f32 / self.disk_total as f32 }
    }
    pub fn swap_pct(&self) -> f32 {
        if self.swap_total == 0 { 0.0 } else { 100.0 * self.swap_used as f32 / self.swap_total as f32 }
    }
    /// Mole's rule: memory needs attention when swap is half used or under 15 % is free.
    pub fn memory_tight(&self) -> bool {
        self.swap_pct() >= SWAP_WARN_PCT || self.mem_free_pct < FREE_WARN_PCT || self.pressure == "warn" || self.pressure == "critical"
    }
}

fn sysctl(key: &str) -> String {
    util::run("/usr/sbin/sysctl", &["-n", key]).trim().to_string()
}

fn parse_mb(s: &str) -> u64 {
    // "1024.00M"
    let v: f64 = s.trim_end_matches(['M', 'm']).parse().unwrap_or(0.0);
    (v * 1024.0 * 1024.0) as u64
}

fn cpu_pct() -> f32 {
    // Two samples one second apart; the second line is the live one.
    let out = util::run("/usr/bin/top", &["-l", "2", "-n", "0", "-s", "1"]);
    let line = out.lines().filter(|l| l.starts_with("CPU usage")).last().unwrap_or("");
    // "CPU usage: 6.25% user, 4.16% sys, 89.58% idle"
    let idle = line.split(',').find(|p| p.contains("idle")).and_then(|p| p.trim().split('%').next()).and_then(|v| v.trim().parse::<f32>().ok());
    idle.map(|i| (100.0 - i).clamp(0.0, 100.0)).unwrap_or(0.0)
}

fn memory(s: &mut Snapshot) {
    s.mem_total = sysctl("hw.memsize").parse().unwrap_or(0);
    let vm = util::run("/usr/bin/vm_stat", &[]);
    let page: u64 = vm.lines().next().and_then(|l| l.split("page size of ").nth(1)).and_then(|r| r.split(' ').next()).and_then(|v| v.parse().ok()).unwrap_or(16384);
    let get = |k: &str| -> u64 { vm.lines().find(|l| l.starts_with(k)).and_then(|l| l.split(':').nth(1)).map(|v| v.trim().trim_end_matches('.').parse().unwrap_or(0)).unwrap_or(0) };
    // App memory + wired + compressed, the way Activity Monitor counts "Memory Used".
    let app = get("Anonymous pages").saturating_sub(get("Pages purgeable"));
    let used = (app + get("Pages wired down") + get("Pages occupied by compressor")) * page;
    s.mem_used = used.min(s.mem_total);
    s.mem_used_pct = if s.mem_total > 0 { 100.0 * s.mem_used as f32 / s.mem_total as f32 } else { 0.0 };
    s.pressure = match sysctl("kern.memorystatus_vm_pressure_level").as_str() {
        "1" => "normal",
        "2" => "warn",
        "4" => "critical",
        _ => "",
    }
    .to_string();
    let mp = util::run("/usr/bin/memory_pressure", &["-Q"]);
    s.mem_free_pct = mp.lines().find(|l| l.contains("free percentage")).and_then(|l| l.split(':').nth(1)).and_then(|v| v.trim().trim_end_matches('%').parse().ok()).unwrap_or(100.0 - s.mem_used_pct);
    // "total = 2048.00M  used = 1024.00M  free = 1024.00M  (encrypted)"
    let sw = sysctl("vm.swapusage");
    let field = |k: &str| sw.split(k).nth(1).and_then(|r| r.split_whitespace().next()).map(parse_mb).unwrap_or(0);
    s.swap_total = field("total = ");
    s.swap_used = field("used = ");
}

fn processes(s: &mut Snapshot) {
    let out = util::run("/bin/ps", &["-Axo", "pid=,rss=,comm="]);
    let mut v: Vec<Proc> = Vec::new();
    let mut vm = 0u64;
    for l in out.lines() {
        let mut it = l.split_whitespace();
        let (Some(pid), Some(rss)) = (it.next().and_then(|x| x.parse().ok()), it.next().and_then(|x| x.parse::<u64>().ok())) else { continue };
        let comm: String = it.collect::<Vec<_>>().join(" ");
        if comm.contains("CoreSimulator") {
            continue;
        }
        if comm.contains("Virtualization") || comm.contains("VirtualMachine") || comm.contains("qemu") {
            vm += rss * 1024;
        }
        let app_name = comm.split(".app/").next().filter(|_| comm.contains(".app/Contents/MacOS/")).and_then(|p| p.rsplit('/').next()).map(String::from);
        let name = app_name.clone().unwrap_or_else(|| comm.rsplit('/').next().unwrap_or(&comm).to_string());
        v.push(Proc { pid, name, app_name, rss: rss * 1024 });
    }
    // Group helper processes under their app so "Google Chrome" counts its renderers too.
    let mut by_name: std::collections::HashMap<String, Proc> = std::collections::HashMap::new();
    for p in v {
        let e = by_name.entry(p.name.clone()).or_insert(Proc { pid: p.pid, name: p.name.clone(), app_name: p.app_name.clone(), rss: 0 });
        e.rss += p.rss;
        if e.app_name.is_none() {
            e.app_name = p.app_name;
        }
    }
    let mut all: Vec<Proc> = by_name.into_values().collect();
    all.sort_by(|a, b| b.rss.cmp(&a.rss));
    all.truncate(8);
    s.top_mem = all;
    s.vm_rss = vm;
}

struct NetPrev {
    at: Instant,
    rx: u64,
    tx: u64,
}

fn network(s: &mut Snapshot, prev: &mut Option<NetPrev>) {
    let route = util::run("/sbin/route", &["-n", "get", "default"]);
    let iface = route.lines().find(|l| l.trim().starts_with("interface:")).and_then(|l| l.split(':').nth(1)).map(|v| v.trim().to_string()).unwrap_or_else(|| "en0".into());
    let out = util::run("/usr/sbin/netstat", &["-ib", "-I", &iface]);
    // Columns: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
    let mut rx: u64 = 0;
    let mut tx: u64 = 0;
    for l in out.lines().skip(1) {
        let c: Vec<&str> = l.split_whitespace().collect();
        if c.len() >= 10 && c[2].starts_with("<Link") {
            rx = c[c.len() - 5].parse().unwrap_or(0);
            tx = c[c.len() - 2].parse().unwrap_or(0);
        }
    }
    let now = Instant::now();
    if let Some(p) = prev.as_ref() {
        let dt = now.duration_since(p.at).as_secs_f64().max(0.1);
        s.net_down = rx.saturating_sub(p.rx) as f64 / dt;
        s.net_up = tx.saturating_sub(p.tx) as f64 / dt;
    }
    s.net_iface = iface;
    *prev = Some(NetPrev { at: now, rx, tx });
}

fn battery() -> Option<(u32, String)> {
    let out = util::run("/usr/bin/pmset", &["-g", "batt"]);
    let line = out.lines().find(|l| l.contains('%'))?;
    let pct = line.split('%').next()?.rsplit(|c: char| !c.is_ascii_digit()).next()?.parse().ok()?;
    let state = if line.contains("discharging") { "使用電池" } else if line.contains("charged") { "已充飽" } else if line.contains("charging") { "充電中" } else { "接上電源" };
    Some((pct, state.to_string()))
}

fn devices() -> Vec<String> {
    let mut v: Vec<String> = util::children(std::path::Path::new("/Volumes"))
        .into_iter()
        .filter(|p| std::fs::symlink_metadata(p).map(|m| !m.file_type().is_symlink()).unwrap_or(false))
        .map(|p| format!("磁碟：{}", util::file_name(&p)))
        .collect();
    // Bluetooth devices listed under "Connected:".
    let bt = util::run("/usr/sbin/system_profiler", &["SPBluetoothDataType"]);
    let mut in_connected = false;
    let mut indent = 0usize;
    for l in bt.lines() {
        let t = l.trim_start();
        let ind = l.len() - t.len();
        if t.starts_with("Connected:") {
            in_connected = true;
            indent = ind;
            continue;
        }
        if in_connected {
            if ind <= indent && !t.is_empty() {
                in_connected = false;
                continue;
            }
            if ind == indent + 4 && t.ends_with(':') {
                v.push(format!("藍牙：{}", t.trim_end_matches(':')));
            }
        }
    }
    v
}

fn penalty(v: f32, normal: f32, high: f32, weight: f32) -> f32 {
    if v <= normal {
        0.0
    } else if v > high {
        weight * (v - normal) / (100.0 - normal)
    } else {
        (weight / 2.0) * (v - normal) / (high - normal)
    }
}

/// Mole's health score without the parts we can't read here (temperature, disk I/O, SMART).
pub fn health(s: &Snapshot) -> (u32, Vec<String>) {
    let mut score = 100.0f32;
    let mut issues = Vec::new();
    score -= penalty(s.cpu_pct, CPU_NORMAL, CPU_HIGH, CPU_WEIGHT);
    if s.cpu_pct > CPU_HIGH {
        issues.push("處理器負載很高".to_string());
    }
    score -= penalty(s.mem_used_pct, MEM_NORMAL, MEM_HIGH, MEM_WEIGHT);
    if s.mem_used_pct > MEM_HIGH {
        issues.push("記憶體用量很高".to_string());
    }
    match s.pressure.as_str() {
        "warn" => {
            score -= PRESSURE_WARN_PENALTY;
            issues.push("記憶體壓力偏高".to_string());
        }
        "critical" => {
            score -= PRESSURE_CRIT_PENALTY;
            issues.push("記憶體壓力嚴重".to_string());
        }
        _ => {}
    }
    let du = s.disk_used_pct();
    score -= penalty(du, DISK_WARN, DISK_CRIT, DISK_WEIGHT);
    if du > 90.0 || (s.disk_total > 0 && s.disk_free < 30_000_000_000) {
        issues.push("磁碟空間快滿了".to_string());
    }
    let days = s.uptime_secs / 86400;
    if days > UPTIME_DANGER_DAYS {
        score -= 3.0;
        issues.push(format!("已 {} 天沒有重新開機", days));
    } else if days > UPTIME_WARN_DAYS {
        score -= 1.0;
    }
    (score.clamp(0.0, 100.0).round() as u32, issues)
}

pub struct Sampler {
    pub snap: Arc<Mutex<Snapshot>>,
    pub running: Arc<AtomicBool>,
}

impl Sampler {
    pub fn start() -> Sampler {
        let snap = Arc::new(Mutex::new(Snapshot::default()));
        let running = Arc::new(AtomicBool::new(true));
        let (s2, r2) = (snap.clone(), running.clone());
        std::thread::spawn(move || {
            let model = util::run("/usr/sbin/sysctl", &["-n", "hw.model"]).trim().to_string();
            let cores: u32 = sysctl("hw.ncpu").parse().unwrap_or(1);
            let boot: u64 = sysctl("kern.boottime").split("sec = ").nth(1).and_then(|r| r.split(',').next()).and_then(|v| v.trim().parse().ok()).unwrap_or(0);
            let mut prev = None;
            let mut devs = Vec::new();
            let mut tick = 0u64;
            let mut last_cpu = 0.0f32;
            while r2.load(Ordering::Relaxed) {
                let mut s = Snapshot { model: model.clone(), cores, ..Default::default() };
                s.cpu_pct = last_cpu;
                let la = sysctl("vm.loadavg");
                let nums: Vec<f32> = la.trim_matches(['{', '}', ' ']).split_whitespace().filter_map(|v| v.parse().ok()).collect();
                for (i, n) in nums.iter().take(3).enumerate() {
                    s.load[i] = *n;
                }
                memory(&mut s);
                processes(&mut s);
                let (t, f) = crate::clean::disk_usage();
                s.disk_total = t;
                s.disk_free = f;
                network(&mut s, &mut prev);
                s.battery = battery();
                s.devices = devs.clone();
                s.uptime_secs = util::now_secs().saturating_sub(boot);
                let (h, issues) = health(&s);
                s.health = h;
                s.issues = issues;
                s.ready = true;
                *s2.lock().unwrap() = s;
                // The processor sample takes about a second, so it is taken after the reading
                // above is shown and used from the next round on.
                last_cpu = cpu_pct();
                {
                    let mut g = s2.lock().unwrap();
                    g.cpu_pct = last_cpu;
                    let (h, issues) = health(&g);
                    g.health = h;
                    g.issues = issues;
                }
                // The Bluetooth lookup is slow, so it runs after the first reading is shown.
                if tick % 15 == 0 {
                    devs = devices();
                    s2.lock().unwrap().devices = devs.clone();
                }
                tick += 1;
                std::thread::sleep(Duration::from_secs(SAMPLE_SECS.saturating_sub(1)));
            }
        });
        Sampler { snap, running }
    }

    pub fn get(&self) -> Snapshot {
        self.snap.lock().unwrap().clone()
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Ask an app to quit normally (it can still ask to save documents).
pub fn quit_app(name: &str) -> Result<(), String> {
    let script = format!("tell application \"{}\" to quit", name.replace('"', ""));
    let out = std::process::Command::new("osascript").args(["-e", &script]).output().map_err(|e| e.to_string())?;
    if out.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&out.stderr).trim().to_string()) }
}

pub fn fmt_rate(bps: f64) -> String {
    format!("{}/s", util::fmt_bytes(bps as u64))
}
