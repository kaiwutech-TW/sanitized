//! Cleanup modules: junk cleanup, privacy, performance (maintenance, launch items),
//! applications (uninstaller, leftovers, updates), large and duplicate files, the disk map
//! and local cloud folders.

use crate::util::{self, collapse, file_name, fmt_bytes};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// Files at least this big count as "large" in the large-file list (estimated).
pub const LARGE_FILE_BYTES: u64 = 50_000_000;
/// Duplicates are only searched among files of at least this size (estimated).
pub const DUPLICATE_MIN_BYTES: u64 = 1_000_000;

#[derive(Clone, Debug)]
pub struct Item {
    pub path: PathBuf,
    pub label: String,
    pub size: u64,
    pub selected: bool,
    pub note: String,
}

#[derive(Clone, Debug)]
pub struct Group {
    pub title: String,
    pub desc: String,
    pub items: Vec<Item>,
    pub open: bool,
    /// Items here are deleted for good instead of moved to the Trash (emptying the Trash).
    pub permanent: bool,
}

impl Group {
    pub fn size(&self) -> u64 {
        self.items.iter().map(|i| i.size).sum()
    }
    pub fn selected_size(&self) -> u64 {
        self.items.iter().filter(|i| i.selected).map(|i| i.size).sum()
    }
}

pub fn total_selected(groups: &[Group]) -> u64 {
    groups.iter().map(|g| g.selected_size()).sum()
}

fn kids_as_items(dir: &Path, selected: bool, min: u64) -> Vec<Item> {
    let mut v: Vec<Item> = util::children(dir)
        .into_iter()
        .filter(|p| !file_name(p).starts_with(".DS_Store"))
        .map(|p| {
            let size = util::tree_size(&p, 50_000);
            Item { label: file_name(&p), path: p, size, selected, note: String::new() }
        })
        .filter(|i| i.size >= min)
        .collect();
    v.sort_by(|a, b| b.size.cmp(&a.size));
    v
}

fn group(title: &str, desc: &str, items: Vec<Item>) -> Group {
    Group { title: title.into(), desc: desc.into(), items, open: false, permanent: false }
}

/// Our own background job wrapper: a worker fills `T`, the UI polls it.
pub struct Job<T> {
    pub result: Arc<Mutex<Option<T>>>,
    pub status: Arc<Mutex<String>>,
}

impl<T: Send + 'static> Job<T> {
    pub fn spawn(f: impl FnOnce(&Mutex<String>) -> T + Send + 'static) -> Job<T> {
        let result = Arc::new(Mutex::new(None));
        let status = Arc::new(Mutex::new(String::new()));
        let (r, s) = (result.clone(), status.clone());
        std::thread::spawn(move || {
            let v = f(&s);
            *r.lock().unwrap() = Some(v);
        });
        Job { result, status }
    }
    pub fn take(&self) -> Option<T> {
        self.result.lock().unwrap().take()
    }
    pub fn status(&self) -> String {
        self.status.lock().unwrap().clone()
    }
}

// ---------------------------------------------------------------- junk cleanup

fn broken_prefs() -> Vec<Item> {
    util::children(&util::home().join("Library/Preferences"))
        .into_iter()
        .filter(|p| p.extension().map(|e| e == "plist").unwrap_or(false))
        .filter(|p| fs::metadata(p).map(|m| m.len() > 0).unwrap_or(false) && plist::Value::from_file(p).is_err())
        .map(|p| {
            let size = util::file_size_on_disk(&p);
            Item { label: file_name(&p), path: p, size, selected: true, note: t!("無法讀取的偏好設定檔").into() }
        })
        .collect()
}

pub fn scan_junk(status: &Mutex<String>) -> Vec<Group> {
    let h = util::home();
    let say = |s: &str| *status.lock().unwrap() = s.to_string();
    let mut g = Vec::new();
    say(t!("正在查找使用者快取檔案…"));
    g.push(group(t!("使用者快取檔案"), t!("應用程式為了加快速度而暫存的資料，刪除後會在需要時重新產生。"), kids_as_items(&h.join("Library/Caches"), true, 1)));
    say(t!("正在查找記錄檔…"));
    g.push(group(t!("使用者記錄檔"), t!("應用程式與系統服務的活動記錄，通常只在排除問題時用到。"), kids_as_items(&h.join("Library/Logs"), true, 1)));
    say(t!("正在查找損壞的偏好設定…"));
    g.push(group(t!("損壞的偏好設定檔"), t!("格式已損壞、應用程式無法再讀取的設定檔。"), broken_prefs()));
    say(t!("正在查找 Xcode 垃圾…"));
    let mut x = kids_as_items(&h.join("Library/Developer/Xcode/DerivedData"), true, 1);
    x.extend(kids_as_items(&h.join("Library/Developer/Xcode/iOS DeviceSupport"), false, 1));
    x.extend(kids_as_items(&h.join("Library/Developer/CoreSimulator/Caches"), true, 1));
    g.push(group(t!("Xcode 垃圾"), t!("編譯產生的衍生資料、舊的裝置支援檔與模擬器快取。"), x));
    say(t!("正在查找 iOS 裝置備份…"));
    g.push(group(t!("iOS 裝置備份"), t!("iPhone 或 iPad 的舊備份。刪除前請確認不再需要。"), kids_as_items(&h.join("Library/Application Support/MobileSync/Backup"), false, 1)));
    say(t!("正在查找郵件附件…"));
    let mut mail = kids_as_items(&h.join("Library/Containers/com.apple.mail/Data/Library/Mail Downloads"), true, 1);
    mail.extend(kids_as_items(&h.join("Library/Mail Downloads"), true, 1));
    g.push(group(t!("郵件附件"), t!("在「郵件」中開啟過的附件副本，原始郵件不受影響。"), mail));
    say(t!("正在查找 AI 雜亂檔案…"));
    let mut ai = Vec::new();
    for p in [".cache/huggingface", ".ollama/models", ".cache/lm-studio", ".lmstudio/models", ".cache/torch", "Library/Caches/pip"] {
        let full = h.join(p);
        if full.exists() {
            let size = util::tree_size(&full, 200_000);
            if size > 0 {
                ai.push(Item { label: p.to_string(), path: full, size, selected: false, note: t!("本機 AI 模型或快取").into() });
            }
        }
    }
    g.push(group(t!("AI 雜亂檔案"), t!("本機 AI 工具下載的模型與快取。刪除本機模型可能影響您的專案。"), ai));
    say(t!("正在查找開發工具快取…"));
    // Package-manager download caches outside ~/Library/Caches (after Mole lib/clean/dev.sh).
    // They are re-downloaded when needed; installed projects keep working.
    let mut dev = Vec::new();
    for (p, label) in [
        (".npm/_cacache", t!("npm 下載快取")),
        ("Library/pnpm/store", t!("pnpm 套件庫")),
        (".bun/install/cache", t!("Bun 下載快取")),
        (".cache/yarn", t!("Yarn 下載快取")),
        (".cargo/registry/cache", t!("Rust Cargo 下載快取")),
        (".cargo/git/checkouts", t!("Rust Cargo Git 快取")),
        (".gradle/caches", t!("Gradle 快取")),
        (".cache/pre-commit", t!("pre-commit 快取")),
        (".cache/node-gyp", t!("node-gyp 快取")),
    ] {
        let full = h.join(p);
        if full.exists() {
            let size = util::tree_size(&full, 300_000);
            if size > 0 {
                dev.push(Item { label: label.to_string(), path: full, size, selected: true, note: tf!("~/{}，需要時會重新下載", p) });
            }
        }
    }
    dev.sort_by(|a, b| b.size.cmp(&a.size));
    g.push(group(t!("開發工具快取"), t!("npm、pnpm、Cargo、Gradle 等套件管理工具的下載快取，刪除後需要時會自動重新下載。"), dev));
    say(t!("正在查找廢紙簍…"));
    let mut t = group(t!("廢紙簍"), t!("廢紙簍裡的項目會被永久刪除。"), kids_as_items(&h.join(".Trash"), true, 1));
    t.permanent = true;
    g.push(t);
    g.retain(|g| !g.items.is_empty());
    g
}

/// Remove the selected items. Returns (bytes freed, failure messages).
pub fn clean_groups(groups: &mut Vec<Group>) -> (u64, Vec<String>) {
    let mut freed = 0;
    let mut errs = Vec::new();
    for g in groups.iter_mut() {
        let mut keep = Vec::new();
        for it in g.items.drain(..) {
            if !it.selected {
                keep.push(it);
                continue;
            }
            if let Some(why) = util::protected_reason(&it.path) {
                errs.push(tf!("{}：{}", it.label, why));
                keep.push(it);
                continue;
            }
            let r = if g.permanent {
                if it.path.is_dir() { fs::remove_dir_all(&it.path) } else { fs::remove_file(&it.path) }.map_err(|e| e.to_string())
            } else {
                util::move_to_trash(&it.path)
            };
            match r {
                Ok(()) => freed += it.size,
                Err(e) => {
                    errs.push(tf!("{}：{}", it.label, e));
                    keep.push(it);
                }
            }
        }
        g.items = keep;
    }
    groups.retain(|g| !g.items.is_empty());
    (freed, errs)
}

// ---------------------------------------------------------------- privacy

pub fn browser_running(name: &str) -> bool {
    !util::run("pgrep", &["-x", name]).trim().is_empty()
}

pub fn scan_privacy(_s: &Mutex<String>) -> Vec<Group> {
    let h = util::home();
    let mut out = Vec::new();
    let file_item = |p: PathBuf, label: &str, selected: bool| -> Option<Item> {
        let md = fs::metadata(&p).ok()?;
        let size = if md.is_dir() { util::tree_size(&p, 20_000) } else { util::alloc_size(&md) };
        Some(Item { path: p, label: label.into(), size, selected, note: String::new() })
    };
    // Chromium-family browsers.
    for (bname, rel, proc_name) in [
        ("Google Chrome", "Library/Application Support/Google/Chrome", "Google Chrome"),
        ("Brave", "Library/Application Support/BraveSoftware/Brave-Browser", "Brave Browser"),
        ("Microsoft Edge", "Library/Application Support/Microsoft Edge", "Microsoft Edge"),
    ] {
        let mut items = Vec::new();
        for prof in util::children(&h.join(rel)) {
            if !prof.join("History").exists() {
                continue;
            }
            let pn = file_name(&prof);
            for (f, label, sel) in [
                ("History", t!("瀏覽歷史記錄與下載記錄"), true),
                ("Cookies", "Cookie", true),
                ("Web Data", t!("自動填寫的值"), true),
                ("Sessions", t!("上次工作階段的分頁"), true),
                ("Top Sites", t!("常用網站"), true),
                ("Login Data", t!("已儲存的密碼"), false),
            ] {
                if let Some(mut it) = file_item(prof.join(f), &tf!("{}（{}）", label, pn), sel) {
                    if f == "Login Data" {
                        it.note = t!("刪除後需重新登入各網站").into();
                    }
                    items.push(it);
                }
            }
        }
        if !items.is_empty() {
            let mut g = group(bname, &tf!("移除使用 {} 後留在本機的瀏覽資料。", bname), items);
            if browser_running(proc_name) {
                g.desc.push_str(t!("（請先結束瀏覽器再移除）"));
            }
            out.push(g);
        }
    }
    // Safari (protected: needs Full Disk Access to read).
    let mut safari = Vec::new();
    for (f, label) in [("Library/Safari/History.db", t!("瀏覽歷史記錄")), ("Library/Safari/Downloads.plist", t!("下載記錄")), ("Library/Safari/LastSession.plist", t!("上次工作階段的分頁")), ("Library/Safari/Form Values", t!("自動填寫的值"))] {
        if let Some(it) = file_item(h.join(f), label, true) {
            safari.push(it);
        }
    }
    if let Some(it) = file_item(h.join("Library/Containers/com.apple.Safari/Data/Library/Caches"), t!("HTML5 本機儲存與快取"), true) {
        safari.push(it);
    }
    if !safari.is_empty() {
        out.push(group("Safari", t!("移除使用 Safari 後留在本機的瀏覽資料。部分項目需要「完整磁碟取用權限」。"), safari));
    }
    // Firefox.
    let mut ff = Vec::new();
    for prof in util::children(&h.join("Library/Application Support/Firefox/Profiles")) {
        for (f, label) in [("places.sqlite", t!("瀏覽與下載記錄")), ("cookies.sqlite", "Cookie"), ("formhistory.sqlite", t!("自動填寫的值")), ("sessionstore.jsonlz4", t!("上次工作階段的分頁"))] {
            if let Some(it) = file_item(prof.join(f), &tf!("{}（{}）", label, file_name(&prof)), true) {
                ff.push(it);
            }
        }
    }
    if !ff.is_empty() {
        out.push(group("Firefox", t!("移除使用 Firefox 後留在本機的瀏覽資料。"), ff));
    }
    // Recent items lists.
    let recent: Vec<Item> = util::children(&h.join("Library/Application Support/com.apple.sharedfilelist"))
        .into_iter()
        .filter(|p| file_name(p).contains("Recent"))
        .filter_map(|p| {
            let n = file_name(&p);
            let label = if n.contains("Application") { t!("最近使用的應用程式") } else if n.contains("Document") { t!("最近開啟的文件") } else if n.contains("Server") { t!("最近連接的伺服器") } else { t!("最近項目") };
            file_item(p, label, true)
        })
        .collect();
    if !recent.is_empty() {
        out.push(group(t!("最近項目列表"), t!("Apple 選單「最近使用的項目」中的應用程式、文件與伺服器。"), recent));
    }
    out
}

pub fn wifi_networks() -> (String, Vec<String>) {
    let ports = util::run("networksetup", &["-listallhardwareports"]);
    let mut dev = "en0".to_string();
    let mut lines = ports.lines();
    while let Some(l) = lines.next() {
        if l.contains("Wi-Fi") || l.contains("AirPort") {
            if let Some(d) = lines.next().and_then(|d| d.strip_prefix("Device: ")) {
                dev = d.trim().to_string();
            }
        }
    }
    let out = util::run("networksetup", &["-listpreferredwirelessnetworks", &dev]);
    let nets = out.lines().skip(1).map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
    (dev, nets)
}

pub fn remove_wifi(dev: &str, names: &[String]) -> Result<(), String> {
    let cmd: Vec<String> = names.iter().map(|n| format!("networksetup -removepreferredwirelessnetwork {} '{}'", dev, n.replace('\'', "'\\''"))).collect();
    util::run_admin(&cmd.join("; "))
}

/// Privacy & Security panes listed under app permissions.
pub const PERMISSIONS: &[(&str, &str, &str)] = &[
    (n!("完整磁碟取用權限"), n!("允許應用程式讀寫 Mac 磁碟的任何位置。"), "Privacy_AllFiles"),
    (n!("輔助使用"), n!("允許應用程式控制電腦，可用來模擬點擊與按鍵。"), "Privacy_Accessibility"),
    (n!("螢幕錄製"), n!("允許應用程式錄下您的螢幕畫面。"), "Privacy_ScreenCapture"),
    (n!("輸入監控"), n!("允許應用程式記錄您的鍵盤與滑鼠輸入。"), "Privacy_ListenEvent"),
    (n!("相機"), n!("允許應用程式使用 Mac 的相機。"), "Privacy_Camera"),
    (n!("麥克風"), n!("允許應用程式使用 Mac 的麥克風。"), "Privacy_Microphone"),
    (n!("自動化"), n!("允許應用程式控制其他應用程式。"), "Privacy_Automation"),
    (n!("通訊錄"), n!("允許應用程式讀取您的聯絡人。"), "Privacy_Contacts"),
    (n!("照片"), n!("允許應用程式讀取您的照片圖庫。"), "Privacy_Photos"),
    (n!("行事曆"), n!("允許應用程式讀取您的行事曆。"), "Privacy_Calendars"),
];

pub fn open_privacy_pane(anchor: &str) {
    util::open_url(&format!("x-apple.systempreferences:com.apple.preference.security?{}", anchor));
}

// ---------------------------------------------------------------- performance

pub struct Task {
    pub title: &'static str,
    pub desc: &'static str,
    pub cmd: &'static str,
    pub admin: bool,
    /// Checked when the page opens.
    pub default_on: bool,
}

/// Maintenance tasks. "Free up RAM" (`purge`) was dropped: it only empties the file cache,
/// which macOS refills within seconds, and the Mole project removed its memory operations as
/// unsafe; the memory diagnosis on the Performance page replaces it. The Finder cache,
/// saved-state, quarantine-history, network-stack and database tasks follow Mole's
/// `mo optimize` catalogue (lib/optimize/catalog.sh).
pub const TASKS: &[Task] = &[
    Task { title: n!("刷新 DNS 快取"), desc: n!("清除網址對應的暫存，解決部分網站無法開啟的問題。"), cmd: "dscacheutil -flushcache; killall -HUP mDNSResponder", admin: true, default_on: true },
    Task { title: n!("重新整理 Finder 快取"), desc: n!("重建「快速查看」縮圖快取，修正顯示錯誤或過期的預覽圖。"), cmd: "qlmanage -r cache >/dev/null 2>&1; qlmanage -r >/dev/null 2>&1; true", admin: false, default_on: true },
    Task { title: n!("清除舊的應用程式狀態"), desc: n!("移除 30 天以上沒用過的視窗還原資料（應用程式會自動重新建立）。"), cmd: "find ~/Library/'Saved Application State' -maxdepth 1 -name '*.savedState' -mtime +30 -exec rm -rf {} + 2>/dev/null; true", admin: false, default_on: true },
    Task { title: n!("清除下載追蹤記錄"), desc: n!("清空系統記錄的「從哪裡下載了哪些檔案」歷史，保護隱私。"), cmd: "f=~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2; [ -f \"$f\" ] && sqlite3 \"$f\" 'DELETE FROM LSQuarantineEvent; VACUUM;'; true", admin: false, default_on: true },
    Task { title: n!("資料庫最佳化"), desc: n!("壓縮「郵件」、Safari 與「訊息」的資料庫，讓搜尋與捲動更流暢（正在使用的應用程式會略過）。"), cmd: "pgrep -x Mail >/dev/null || for f in ~/Library/Mail/V*/MailData/Envelope\\ Index; do [ -f \"$f\" ] && sqlite3 \"$f\" vacuum; done; pgrep -x Safari >/dev/null || { [ -f ~/Library/Safari/History.db ] && sqlite3 ~/Library/Safari/History.db vacuum; }; pgrep -x Messages >/dev/null || { [ -f ~/Library/Messages/chat.db ] && sqlite3 ~/Library/Messages/chat.db vacuum; }", admin: false, default_on: true },
    Task { title: n!("精簡「時間機器」快照"), desc: n!("移除本機的時間機器快照，釋放可清除的空間。"), cmd: "tmutil thinlocalsnapshots / 999999999999 4", admin: true, default_on: true },
    Task { title: n!("執行定期維護腳本"), desc: n!("執行系統每日、每週與每月的維護腳本。"), cmd: "periodic daily weekly monthly", admin: true, default_on: true },
    Task { title: n!("重新整理網路連線"), desc: n!("清除路由表與 ARP 快取，解決網路卡住或連不上的問題（網路會短暫中斷）。"), cmd: "route -n flush >/dev/null; arp -a -d >/dev/null", admin: true, default_on: false },
    Task { title: n!("重新索引「聚焦」"), desc: n!("重建搜尋索引，搜尋變慢或找不到檔案時使用（需要一段時間）。"), cmd: "mdutil -E /", admin: true, default_on: false },
    Task { title: n!("修復磁碟權限"), desc: n!("重設您個人資料夾中檔案的擁有權與權限。"), cmd: "diskutil resetUserPermissions / $(stat -f %u /dev/console)", admin: true, default_on: false },
];

/// Run the chosen maintenance tasks; admin tasks share one password prompt.
pub fn run_tasks(sel: &[bool]) -> Vec<String> {
    let mut msgs = Vec::new();
    let admin: Vec<&Task> = TASKS.iter().zip(sel).filter(|(t, s)| **s && t.admin).map(|(t, _)| t).collect();
    if !admin.is_empty() {
        let cmd = admin.iter().map(|t| t.cmd).collect::<Vec<_>>().join("; ");
        match util::run_admin(&cmd) {
            Ok(()) => msgs.extend(admin.iter().map(|t| format!("✓ {}", crate::i18n::tr(t.title)))),
            Err(e) => msgs.push(tf!("未完成：系統任務未執行：{}", e)),
        }
    }
    for (t, s) in TASKS.iter().zip(sel) {
        if *s && !t.admin {
            let out = std::process::Command::new("sh").args(["-c", t.cmd]).output();
            match out {
                Ok(o) if o.status.success() => msgs.push(format!("✓ {}", crate::i18n::tr(t.title))),
                _ => msgs.push(tf!("未完成：{}：部分資料需要給本程式「完整磁碟取用權限」，或請先結束相關應用程式", t.title)),
            }
        }
    }
    msgs
}

#[derive(Clone, Debug)]
pub struct LaunchItem {
    pub path: PathBuf,
    pub label: String,
    pub program: String,
    pub broken: bool,
    pub system: bool,
    pub selected: bool,
}

pub fn launch_items() -> Vec<LaunchItem> {
    let h = util::home();
    let mut out = Vec::new();
    for (dir, system) in [(h.join("Library/LaunchAgents"), false), (PathBuf::from("/Library/LaunchAgents"), true), (PathBuf::from("/Library/LaunchDaemons"), true)] {
        for p in util::children(&dir) {
            if p.extension().map(|e| e != "plist").unwrap_or(true) {
                continue;
            }
            let v = plist::Value::from_file(&p).ok();
            let d = v.as_ref().and_then(|v| v.as_dictionary());
            let label = d.and_then(|d| d.get("Label")).and_then(|x| x.as_string()).map(String::from).unwrap_or_else(|| file_name(&p));
            let program = d
                .and_then(|d| d.get("Program").and_then(|x| x.as_string()).map(String::from).or_else(|| d.get("ProgramArguments").and_then(|a| a.as_array()).and_then(|a| a.first()).and_then(|x| x.as_string()).map(String::from)))
                .unwrap_or_default();
            let broken = v.is_none() || (program.starts_with('/') && !Path::new(&program).exists());
            out.push(LaunchItem { path: p, label, program, broken, system, selected: broken });
        }
    }
    out.sort_by(|a, b| b.broken.cmp(&a.broken).then(a.label.cmp(&b.label)));
    out
}

pub fn remove_launch_items(items: &[LaunchItem]) -> Vec<String> {
    let mut msgs = Vec::new();
    let mut sys = Vec::new();
    for it in items.iter().filter(|i| i.selected) {
        if it.system {
            sys.push(it);
            continue;
        }
        let _ = std::process::Command::new("launchctl").arg("unload").arg(&it.path).output();
        match util::move_to_trash(&it.path) {
            Ok(()) => msgs.push(format!("✓ {}", tf!("已移除 {}", it.label))),
            Err(e) => msgs.push(tf!("未完成：{}：{}", it.label, e)),
        }
    }
    if !sys.is_empty() {
        let trash = util::home().join(".Trash");
        let cmd: Vec<String> = sys.iter().map(|i| format!("launchctl unload '{0}'; mv '{0}' '{1}/'", i.path.display(), trash.display())).collect();
        match util::run_admin(&cmd.join("; ")) {
            Ok(()) => msgs.extend(sys.iter().map(|i| format!("✓ {}", tf!("已移除 {}", i.label)))),
            Err(e) => msgs.push(tf!("未完成：系統背景項目未移除：{}", e)),
        }
    }
    msgs
}

// ---------------------------------------------------------------- applications

#[derive(Clone, Debug)]
pub struct App {
    pub path: PathBuf,
    pub name: String,
    pub bundle_id: String,
    pub version: String,
    pub size: u64,
    pub feed: Option<String>,
    pub latest: Option<String>,
    pub last_used_days: Option<u64>,
    pub selected: bool,
}

pub fn list_apps(status: &Mutex<String>) -> Vec<App> {
    let mut out = Vec::new();
    for dir in [PathBuf::from("/Applications"), util::home().join("Applications"), PathBuf::from("/Applications/Utilities")] {
        for p in util::children(&dir) {
            if p.extension().map(|e| e != "app").unwrap_or(true) {
                continue;
            }
            *status.lock().unwrap() = tf!("正在讀取 {}…", file_name(&p));
            let info = plist::Value::from_file(p.join("Contents/Info.plist")).ok();
            let d = info.as_ref().and_then(|v| v.as_dictionary());
            let get = |k: &str| d.and_then(|d| d.get(k)).and_then(|x| x.as_string()).map(String::from);
            let size = util::tree_size(&p, 300_000);
            let used = fs::metadata(&p).ok().and_then(|m| m.accessed().ok()).and_then(|t| t.elapsed().ok()).map(|d| d.as_secs() / 86400);
            out.push(App {
                name: file_name(&p).trim_end_matches(".app").to_string(),
                bundle_id: get("CFBundleIdentifier").unwrap_or_default(),
                version: get("CFBundleShortVersionString").or_else(|| get("CFBundleVersion")).unwrap_or_default(),
                feed: get("SUFeedURL"),
                latest: None,
                size,
                path: p,
                last_used_days: used,
                selected: false,
            });
        }
    }
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    out
}

pub fn app_leftovers(app: &App) -> Vec<Item> {
    let h = util::home();
    let lib = h.join("Library");
    let mut cands = vec![lib.join("Application Support").join(&app.name), lib.join("Logs").join(&app.name), lib.join("Caches").join(&app.name)];
    if !app.bundle_id.is_empty() {
        let b = &app.bundle_id;
        for p in ["Application Support", "Caches", "Containers", "HTTPStorages", "WebKit", "Logs"] {
            cands.push(lib.join(p).join(b));
        }
        cands.push(lib.join("Preferences").join(format!("{}.plist", b)));
        cands.push(lib.join("Saved Application State").join(format!("{}.savedState", b)));
        cands.push(lib.join("Cookies").join(format!("{}.binarycookies", b)));
    }
    let mut seen = HashSet::new();
    cands
        .into_iter()
        .filter(|p| p.exists() && seen.insert(p.clone()))
        .map(|p| {
            let size = util::tree_size(&p, 50_000);
            Item { label: collapse(&p), path: p, size, selected: true, note: String::new() }
        })
        .collect()
}

/// Remove an app and its support files (all to the Trash).
pub fn uninstall(app: &App) -> Vec<String> {
    let mut msgs = Vec::new();
    let _ = std::process::Command::new("osascript").args(["-e", &format!("tell application id \"{}\" to quit", app.bundle_id)]).output();
    for it in app_leftovers(app) {
        if let Err(e) = util::move_to_trash(&it.path) {
            msgs.push(tf!("未完成：{}：{}", it.label, e));
        }
    }
    match util::move_to_trash(&app.path) {
        Ok(()) => msgs.push(format!("✓ {}", tf!("已解除安裝 {}", app.name))),
        Err(e) => msgs.push(tf!("未完成：{}：{}（系統應用程式或需要管理員權限）", app.name, e)),
    }
    msgs
}

/// Support files whose reverse-DNS name matches no installed app (or vendor).
pub fn orphan_leftovers(apps: &[App]) -> Vec<Item> {
    let vendor = |b: &str| b.split('.').take(2).collect::<Vec<_>>().join(".").to_lowercase();
    let ids: HashSet<String> = apps.iter().map(|a| a.bundle_id.to_lowercase()).collect();
    let vendors: HashSet<String> = apps.iter().filter(|a| !a.bundle_id.is_empty()).map(|a| vendor(&a.bundle_id)).collect();
    let lib = util::home().join("Library");
    let mut out = Vec::new();
    for dir in ["Containers", "Saved Application State", "Caches", "Preferences", "HTTPStorages"] {
        for p in util::children(&lib.join(dir)) {
            let n = file_name(&p);
            let id = n.trim_end_matches(".plist").trim_end_matches(".savedState").to_lowercase();
            if id.split('.').count() < 3 || id.starts_with("com.apple.") || id.starts_with("group.") || id.starts_with("org.mozilla") {
                continue;
            }
            if ids.contains(&id) || ids.iter().any(|b| id.starts_with(b.as_str())) || vendors.contains(&vendor(&id)) {
                continue;
            }
            let size = util::tree_size(&p, 20_000);
            out.push(Item { label: tf!("{}（{}）", n, dir), path: p, size, selected: false, note: t!("找不到對應的應用程式").into() });
        }
    }
    out.sort_by(|a, b| b.size.cmp(&a.size));
    out
}

/// Ask each app's update feed (Sparkle appcast) for its newest version.
pub fn check_updates(apps: &mut [App], status: &Mutex<String>) {
    let re = regex::Regex::new(r#"sparkle:shortVersionString(?:="|>)([0-9][^"<]*)"#).unwrap();
    let re2 = regex::Regex::new(r#"sparkle:version(?:="|>)([0-9][^"<]*)"#).unwrap();
    for a in apps.iter_mut() {
        let Some(feed) = a.feed.clone() else { continue };
        if !feed.starts_with("https://") {
            continue;
        }
        *status.lock().unwrap() = tf!("正在檢查 {} 的更新…", a.name);
        let xml = util::run("curl", &["-sSL", "--max-time", "15", &feed]);
        let mut best: Option<String> = None;
        for c in re.captures_iter(&xml).chain(re2.captures_iter(&xml)) {
            let v = c[1].trim().to_string();
            if best.as_ref().map(|b| crate::vuln::cmp_ver(&v, b).is_gt()).unwrap_or(true) {
                best = Some(v);
            }
        }
        if let Some(b) = best {
            if crate::vuln::cmp_ver(&b, &a.version).is_gt() && b.contains('.') {
                a.latest = Some(b);
            }
        }
    }
}

pub fn unused_installers() -> Vec<Item> {
    let mut v: Vec<Item> = util::children(&util::home().join("Downloads"))
        .into_iter()
        .filter(|p| p.extension().map(|e| e == "dmg" || e == "pkg").unwrap_or(false))
        .filter_map(|p| {
            let md = fs::metadata(&p).ok()?;
            Some(Item { label: file_name(&p), size: util::alloc_size(&md), note: tf!("{} 天前下載", util::age_days(&md)), path: p, selected: true })
        })
        .collect();
    v.sort_by(|a, b| b.size.cmp(&a.size));
    v
}

// ---------------------------------------------------------------- large & duplicate files

fn walk_files(roots: &[PathBuf], depth: usize, mut f: impl FnMut(&Path, &fs::Metadata)) {
    for r in roots {
        let mut stack = vec![(r.clone(), 0usize)];
        while let Some((p, d)) = stack.pop() {
            let Ok(md) = fs::symlink_metadata(&p) else { continue };
            if md.is_dir() {
                let n = file_name(&p);
                if n.starts_with('.') || n.ends_with(".photoslibrary") || n.ends_with(".app") || n == "node_modules" || n.ends_with(".musiclibrary") {
                    continue;
                }
                if d < depth {
                    for c in util::children(&p) {
                        stack.push((c, d + 1));
                    }
                }
            } else if md.is_file() {
                f(&p, &md);
            }
        }
    }
}

fn clutter_roots() -> Vec<PathBuf> {
    let h = util::home();
    ["Downloads", "Documents", "Desktop", "Movies", "Music", "Pictures"].iter().map(|p| h.join(p)).collect()
}

pub fn large_files(status: &Mutex<String>) -> Vec<Item> {
    *status.lock().unwrap() = t!("正在查找大型檔案…").into();
    let mut v = Vec::new();
    walk_files(&clutter_roots(), 10, |p, md| {
        // Real disk usage, so a sparse file that only claims a big size isn't listed.
        let used = util::alloc_size(md);
        if used >= LARGE_FILE_BYTES {
            v.push(Item { path: p.to_path_buf(), label: file_name(p), size: used, selected: false, note: tf!("{} · {} 天未修改", collapse(p.parent().unwrap_or(p)), util::age_days(md)) });
        }
    });
    v.sort_by(|a, b| b.size.cmp(&a.size));
    v
}

/// Duplicate groups: same size, then same SHA-256. The newest copy stays unselected.
pub fn duplicates(status: &Mutex<String>) -> Vec<Group> {
    *status.lock().unwrap() = t!("正在比對重複檔案…").into();
    let mut by_size: HashMap<u64, Vec<(PathBuf, std::time::SystemTime)>> = HashMap::new();
    walk_files(&clutter_roots(), 10, |p, md| {
        // Grouped by exact length (copies have equal length); the size shown is disk usage.
        if util::alloc_size(md) >= DUPLICATE_MIN_BYTES {
            by_size.entry(md.len()).or_default().push((p.to_path_buf(), md.modified().unwrap_or(std::time::UNIX_EPOCH)));
        }
    });
    let mut groups = Vec::new();
    for (_len, files) in by_size.into_iter().filter(|(_, v)| v.len() > 1) {
        let mut by_hash: HashMap<String, Vec<(PathBuf, std::time::SystemTime)>> = HashMap::new();
        // Hard links of one file are not copies: keep one path per (device, inode).
        let mut inodes = HashSet::new();
        for (p, t) in files {
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if let Ok(m) = fs::metadata(&p) {
                    if !inodes.insert((m.dev(), m.ino())) {
                        continue;
                    }
                }
            }
            if let Ok(data) = fs::read(&p) {
                by_hash.entry(format!("{:x}", Sha256::digest(&data))).or_default().push((p, t));
            }
        }
        for (_, mut same) in by_hash.into_iter().filter(|(_, v)| v.len() > 1) {
            same.sort_by(|a, b| b.1.cmp(&a.1));
            let title = file_name(&same[0].0);
            let items = same.into_iter().enumerate().map(|(i, (p, _))| Item { label: collapse(&p), size: util::file_size_on_disk(&p), path: p, selected: i > 0, note: if i == 0 { t!("保留最新的副本").into() } else { String::new() } }).collect();
            groups.push(Group { title, desc: String::new(), items, open: false, permanent: false });
        }
    }
    for g in groups.iter_mut() {
        g.desc = tf!("{} 個相同的檔案，每個 {}", g.items.len(), fmt_bytes(g.items[0].size));
    }
    groups.sort_by(|a, b| b.size().cmp(&a.size()));
    groups
}

// ---------------------------------------------------------------- disk map

#[derive(Clone, Debug)]
pub struct Node {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
}

// ---- Disk map scan with progress and an estimated time remaining

/// Folders measured at the same time.
pub const LENS_WORKERS: usize = 6;
/// Random descents per folder when guessing how many items it holds.
pub const LENS_PROBES: usize = 160;
/// A running folder that has passed its guess is expected to hold this much more again.
pub const LENS_OVERRUN: f64 = 1.5;
/// Lowest share of the average speed used for the recent speed.
pub const LENS_RATE_FLOOR: f64 = 0.3;

#[derive(Default)]
pub struct LensProgress {
    pub total_children: usize,
    pub done_children: usize,
    /// Expected number of items in the whole folder (refined as folders finish).
    pub estimate: f64,
    /// Folders finished so far, biggest first.
    pub nodes: Vec<Node>,
    pub current: Vec<String>,
    pub finished: bool,
    pub cancelled: bool,
    pub estimating: bool,
    /// The scan stopped because of an internal error.
    pub failed: bool,
    /// Per item: first guess (or last scan's count), and 0 waiting / 1 running / 2 done.
    pub guesses: Vec<f64>,
    pub state: Vec<u8>,
    /// Live item counts per folder.
    pub counts: Arc<Vec<std::sync::atomic::AtomicU64>>,
    /// When each folder started, and whether its guess came from the last scan (exact).
    pub started_at: Vec<Option<std::time::Instant>>,
    pub from_cache: Vec<bool>,
}

pub struct LensScan {
    pub dir: PathBuf,
    pub progress: Arc<Mutex<LensProgress>>,
    pub cancel: Arc<std::sync::atomic::AtomicBool>,
    pub entries: Arc<std::sync::atomic::AtomicU64>,
    pub started: std::time::Instant,
    /// (seconds since start, items checked) samples for the recent speed.
    samples: Mutex<std::collections::VecDeque<(f64, f64)>>,
    /// Last shown estimate (time, seconds left), for smoothing.
    shown: Mutex<Option<(f64, f64)>>,
    /// Per running folder: (seconds since start, its items) samples.
    folder_samples: Mutex<HashMap<usize, std::collections::VecDeque<(f64, f64)>>>,
}

fn lens_cache_file() -> PathBuf {
    util::data_dir().join("lens_cache.json")
}

fn load_lens_cache() -> HashMap<String, u64> {
    fs::read_to_string(lens_cache_file()).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default()
}

/// Total time the estimating step may take before scanning starts (all folders together).
pub const LENS_ESTIMATE_BUDGET_MS: u64 = 2500;

/// Knuth's random-probe estimate of how many items a folder tree holds: walk random paths
/// from the top and multiply the number of choices met on the way; the average over many
/// walks is an unbiased guess. Listings are remembered between walks and the work stops at
/// `budget`, so even huge folders take a fraction of a second.
fn estimate_items(root: &Path, seed: &mut u64, budget: std::time::Duration) -> f64 {
    let t0 = std::time::Instant::now();
    #[cfg(unix)]
    let root_dev = {
        use std::os::unix::fs::MetadataExt;
        fs::symlink_metadata(root).map(|m| m.dev()).unwrap_or(0)
    };
    let mut memo: HashMap<PathBuf, std::rc::Rc<Vec<(PathBuf, bool)>>> = HashMap::new();
    let mut list = |p: &Path, memo: &mut HashMap<PathBuf, std::rc::Rc<Vec<(PathBuf, bool)>>>| -> std::rc::Rc<Vec<(PathBuf, bool)>> {
        if let Some(v) = memo.get(p) {
            return v.clone();
        }
        let v: Vec<(PathBuf, bool)> = fs::read_dir(p)
            .map(|rd| rd.flatten().map(|e| { let d = e.file_type().map(|t| t.is_dir()).unwrap_or(false); (e.path(), d) }).collect())
            .unwrap_or_default();
        let v = std::rc::Rc::new(v);
        if memo.len() < 4096 {
            memo.insert(p.to_path_buf(), v.clone());
        }
        v
    };
    let mut total = 0.0;
    let mut probes = 0usize;
    while probes < LENS_PROBES && (probes < 8 || t0.elapsed() < budget) {
        let mut node = root.to_path_buf();
        let mut mult = 1.0f64;
        let mut est = 1.0f64;
        for _depth in 0..64 {
            let kids = list(&node, &mut memo);
            if kids.is_empty() {
                break;
            }
            mult *= kids.len() as f64;
            est += mult;
            *seed ^= *seed << 13;
            *seed ^= *seed >> 7;
            *seed ^= *seed << 17;
            let (next, is_dir) = &kids[(*seed % kids.len() as u64) as usize];
            if !*is_dir {
                break;
            }
            // other file systems (e.g. DeviceFS) are not measured, so don't probe them
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if fs::symlink_metadata(next).map(|m| m.dev()).unwrap_or(0) != root_dev {
                    break;
                }
            }
            node = next.clone();
        }
        total += est;
        probes += 1;
    }
    total / probes.max(1) as f64
}

/// Disk usage and item count of a folder tree (shared size function), counting into the
/// scan-wide and per-folder progress counters; stops when cancelled.
fn measure(p: &Path, entries: &std::sync::atomic::AtomicU64, mine: &std::sync::atomic::AtomicU64, cancel: &std::sync::atomic::AtomicBool, links: &Mutex<HashSet<(u64, u64)>>) -> (u64, u64) {
    use std::sync::atomic::Ordering;
    let tick = || {
        entries.fetch_add(1, Ordering::Relaxed);
        mine.fetch_add(1, Ordering::Relaxed);
    };
    let (size, count, _) = util::walk_size(p, &util::WalkOpts { limit: 0, cancel: Some(cancel), on_entry: Some(&tick), links: Some(links) });
    (util::checked_size(p, size), count)
}

pub fn start_lens(dir: PathBuf) -> LensScan {
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    let scan = LensScan {
        dir: dir.clone(),
        progress: Arc::new(Mutex::new(LensProgress { estimating: true, ..Default::default() })),
        cancel: Arc::new(AtomicBool::new(false)),
        entries: Arc::new(AtomicU64::new(0)),
        started: std::time::Instant::now(),
        samples: Mutex::new(std::collections::VecDeque::new()),
        shown: Mutex::new(None),
        folder_samples: Mutex::new(HashMap::new()),
    };
    let (prog, cancel, entries) = (scan.progress.clone(), scan.cancel.clone(), scan.entries.clone());
    let guard = scan.progress.clone();
    std::thread::spawn(move || {
      // If anything inside fails, end the scan instead of leaving the page waiting forever.
      let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let kids: Vec<(PathBuf, bool)> = util::children(&dir)
            .into_iter()
            .filter_map(|p| fs::symlink_metadata(&p).ok().filter(|m| !m.file_type().is_symlink()).map(|m| (p, m.is_dir())))
            .collect();
        // Expected items per folder: the last scan's count when we have one, else a probe estimate.
        let cache = load_lens_cache();
        let est: Vec<f64> = {
            let slots: Vec<Mutex<f64>> = kids.iter().map(|_| Mutex::new(1.0)).collect();
            let next = AtomicUsize::new(0);
            let unknown = kids.iter().filter(|(p, d)| *d && !cache.contains_key(&p.to_string_lossy().to_string())).count().max(1);
            let budget = std::time::Duration::from_millis((LENS_ESTIMATE_BUDGET_MS * LENS_WORKERS as u64 / unknown as u64).clamp(30, 600));
            std::thread::scope(|sc| {
                for w in 0..LENS_WORKERS {
                    let (slots, next, kids, cache) = (&slots, &next, &kids, &cache);
                    sc.spawn(move || {
                        let mut seed = (util::now_secs() ^ (w as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15)) | 1;
                        loop {
                            let i = next.fetch_add(1, Ordering::Relaxed);
                            if i >= kids.len() {
                                break;
                            }
                            let (p, is_dir) = &kids[i];
                            let v = match (is_dir, cache.get(&p.to_string_lossy().to_string())) {
                                (false, _) => 1.0,
                                (true, Some(c)) => *c as f64,
                                (true, None) => estimate_items(p, &mut seed, budget),
                            };
                            *slots[i].lock().unwrap() = v;
                        }
                    });
                }
            });
            slots.into_iter().map(|m| m.into_inner().unwrap()).collect()
        };
        let live: Arc<Vec<AtomicU64>> = Arc::new(kids.iter().map(|_| AtomicU64::new(0)).collect());
        {
            let mut g = prog.lock().unwrap();
            g.total_children = kids.len();
            g.estimate = est.iter().sum::<f64>().max(1.0);
            g.guesses = est.clone();
            g.from_cache = kids.iter().map(|(p, d)| !*d || cache.contains_key(&p.to_string_lossy().to_string())).collect();
            g.started_at = vec![None; kids.len()];
            g.state = vec![0; kids.len()];
            g.counts = live.clone();
            g.estimating = false;
        }
        let est = Arc::new(Mutex::new(est));
        let counts: Arc<Mutex<HashMap<String, u64>>> = Arc::new(Mutex::new(HashMap::new()));
        let links: Mutex<HashSet<(u64, u64)>> = Mutex::new(HashSet::new());
        let next = AtomicUsize::new(0);
        // Biggest guesses first, so the long folders start early.
        let mut order: Vec<usize> = (0..kids.len()).collect();
        {
            let e = est.lock().unwrap();
            order.sort_by(|a, b| e[*b].partial_cmp(&e[*a]).unwrap_or(std::cmp::Ordering::Equal));
        }
        std::thread::scope(|sc| {
            for _ in 0..LENS_WORKERS.min(kids.len().max(1)) {
                sc.spawn(|| loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= order.len() || cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let (p, is_dir) = &kids[order[i]];
                    let name = file_name(p);
                    {
                        let mut g = prog.lock().unwrap();
                        g.current.push(name.clone());
                        g.state[order[i]] = 1;
                        g.started_at[order[i]] = Some(std::time::Instant::now());
                    }
                    let (size, count) = if *is_dir {
                        measure(p, &entries, &live[order[i]], &cancel, &links)
                    } else {
                        entries.fetch_add(1, Ordering::Relaxed);
                        (util::file_size_on_disk(p), 1)
                    };
                    let cancelled = cancel.load(Ordering::Relaxed);
                    let mut g = prog.lock().unwrap();
                    g.current.retain(|n| n != &name);
                    if cancelled {
                        break;
                    }
                    // Replace the guess with the real count so the estimate keeps improving.
                    {
                        let mut e = est.lock().unwrap();
                        e[order[i]] = count as f64;
                        g.estimate = e.iter().sum::<f64>().max(1.0);
                    }
                    if *is_dir {
                        counts.lock().unwrap().insert(p.to_string_lossy().to_string(), count);
                    }
                    g.state[order[i]] = 2;
                    g.done_children += 1;
                    g.nodes.push(Node { path: p.clone(), name, size, is_dir: *is_dir });
                    g.nodes.sort_by(|a, b| b.size.cmp(&a.size));
                });
            }
        });
        let mut cache = load_lens_cache();
        cache.extend(counts.lock().unwrap().drain());
        if let Ok(t) = serde_json::to_string(&cache) {
            let _ = fs::write(lens_cache_file(), t);
        }
        let mut g = prog.lock().unwrap();
        g.cancelled = cancel.load(Ordering::Relaxed);
        g.finished = true;
      }));
      if outcome.is_err() {
          let mut g = guard.lock().unwrap_or_else(|e| e.into_inner());
          g.estimating = false;
          g.cancelled = true;
          g.failed = true;
          g.finished = true;
      }
    });
    scan
}

impl LensScan {
    pub fn stop(&self) {
        self.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    /// Share done (0..1) and seconds left, from items checked against the expected total.
    pub fn eta(&self) -> (f32, Option<f64>) {
        let g = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        if g.estimating {
            return (0.0, None);
        }
        let done = self.entries.load(std::sync::atomic::Ordering::Relaxed) as f64;
        let el = self.started.elapsed().as_secs_f64();
        // Expected items per folder: exact when known from the last scan; a running folder that
        // has passed its guess is expected to grow by half again; waiting ones keep their guess.
        // Recent speed (last 15 s): reading slows down inside big folders, so the average since
        // the start would be too optimistic.
        let rate = {
            let mut sm = self.samples.lock().unwrap();
            sm.push_back((el, done));
            while sm.len() > 2 && el - sm[0].0 > 15.0 {
                sm.pop_front();
            }
            let (t0, d0) = sm[0];
            let avg = done / el.max(0.1);
            let recent = if el - t0 >= 3.0 { (done - d0).max(0.0) / (el - t0) } else { avg };
            // Kept between 30 % and 100 % of the overall average, so a pause inside one slow
            // folder can't make the estimate jump to hours.
            recent.clamp(avg * LENS_RATE_FLOOR, avg)
        };
        let running_n = g.state.iter().filter(|s| **s == 1).count().max(1) as f64;
        let mut total = 0.0;
        let mut running_left = 0.0f64;
        let mut pending = 0.0;
        for (i, st) in g.state.iter().enumerate() {
            let c = g.counts.get(i).map(|a| a.load(std::sync::atomic::Ordering::Relaxed) as f64).unwrap_or(0.0);
            let exact = g.from_cache.get(i).copied().unwrap_or(false);
            let expect = if exact { g.guesses[i].max(c) } else { g.guesses[i].max(c * LENS_OVERRUN) };
            match st {
                2 => total += c,
                1 => {
                    total += expect;
                    // Each running folder at its own recent speed (some folders, like Library, are
                    // much slower per file than others); the slowest one decides the end.
                    let t = g.started_at[i].map(|s| s.elapsed().as_secs_f64()).unwrap_or(0.0);
                    let own_avg = if t > 0.0 { c / t } else { 0.0 };
                    let own = {
                        let mut fs = self.folder_samples.lock().unwrap();
                        let q = fs.entry(i).or_default();
                        q.push_back((el, c));
                        while q.len() > 2 && el - q[0].0 > 15.0 {
                            q.pop_front();
                        }
                        let (t0, c0) = q[0];
                        let recent = if el - t0 >= 3.0 { (c - c0).max(0.0) / (el - t0) } else { own_avg };
                        recent.clamp(own_avg * LENS_RATE_FLOOR, own_avg.max(1.0))
                    };
                    let speed = if t > 3.0 && own > 0.0 { own } else { rate / running_n };
                    if t > 1.0 && speed > 0.0 {
                        running_left = running_left.max((expect - c).max(0.0) / speed);
                    }
                }
                _ => {
                    total += g.guesses[i];
                    pending += g.guesses[i];
                }
            }
        }
        let total = total.max(done + 1.0);
        let frac = (done / total).clamp(0.0, 0.99);
        if el < 2.0 || done < 500.0 {
            return (frac as f32, None);
        }
        // Waiting folders share the workers at the speed seen so far.
        let pending_left = if pending > 0.0 && rate > 0.0 { pending / rate } else { 0.0 };
        let raw = running_left.max(pending_left).max(if g.done_children < g.total_children { 1.0 } else { 0.0 });
        // Smooth: move a third of the way from the previous estimate (counted down) to the new one.
        let mut sh = self.shown.lock().unwrap();
        let left = match *sh {
            Some((t, prev)) => {
                let counted = (prev - (el - t)).max(0.0);
                counted + (raw - counted) / 3.0
            }
            None => raw,
        };
        *sh = Some((el, left));
        (frac as f32, Some(left))
    }

    /// True when every folder's size is known from an earlier scan, so the estimate is reliable.
    pub fn exact(&self) -> bool {
        let g = self.progress.lock().unwrap_or_else(|e| e.into_inner());
        !g.from_cache.is_empty() && g.from_cache.iter().all(|x| *x)
    }
}

pub fn fmt_duration(secs: f64) -> String {
    let s = secs.round() as u64;
    if s < 60 {
        tf!("{} 秒", s.max(1))
    } else if s < 3600 {
        tf!("{} 分 {} 秒", s / 60, s % 60)
    } else {
        tf!("{} 小時 {} 分", s / 3600, (s / 60) % 60)
    }
}

pub fn disk_usage() -> (u64, u64) {
    // (total, free) of the startup disk, from `df -k /`.
    let out = util::run("df", &["-k", "/System/Volumes/Data"]);
    let line = out.lines().nth(1).unwrap_or("");
    let cols: Vec<&str> = line.split_whitespace().collect();
    let total = cols.get(1).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0) * 1024;
    let avail = cols.get(3).and_then(|x| x.parse::<u64>().ok()).unwrap_or(0) * 1024;
    (total, avail)
}

// ---------------------------------------------------------------- cloud folders (local)

pub fn cloud_folders(status: &Mutex<String>) -> Vec<Group> {
    let h = util::home();
    let mut out = Vec::new();
    let mut roots: Vec<(String, PathBuf)> = util::children(&h.join("Library/CloudStorage")).into_iter().map(|p| (file_name(&p), p)).collect();
    let icloud = h.join("Library/Mobile Documents/com~apple~CloudDocs");
    if icloud.exists() {
        roots.push((t!("iCloud 雲碟").into(), icloud));
    }
    for (name, root) in roots {
        *status.lock().unwrap() = tf!("正在查看 {}…", name);
        let mut items = Vec::new();
        walk_files(&[root.clone()], 8, |p, md| {
            // Only files actually stored on this Mac take space (blocks > 0).
            #[cfg(unix)]
            let local = {
                use std::os::unix::fs::MetadataExt;
                md.blocks() > 0
            };
            #[cfg(not(unix))]
            let local = true;
            if local && util::alloc_size(md) >= 10_000_000 {
                items.push(Item { path: p.to_path_buf(), label: file_name(p), size: util::alloc_size(md), selected: false, note: collapse(p.parent().unwrap_or(p)) });
            }
        });
        items.sort_by(|a, b| b.size.cmp(&a.size));
        out.push(group(&name, t!("已下載到這台 Mac 的大型雲端檔案。「移除下載」只刪本機副本，雲端上的檔案保留。"), items));
    }
    out
}

/// Free the local copy of cloud files (they stay in the cloud).
pub fn evict(items: &[Item]) -> Vec<String> {
    let mut msgs = Vec::new();
    for it in items.iter().filter(|i| i.selected) {
        let s = it.path.to_string_lossy();
        let ok = if s.contains("Mobile Documents") {
            std::process::Command::new("brctl").arg("evict").arg(&it.path).status().map(|s| s.success()).unwrap_or(false)
        } else {
            std::process::Command::new("fileproviderctl").arg("evict").arg(&it.path).status().map(|s| s.success()).unwrap_or(false)
        };
        msgs.push(if ok {
            format!("✓ {}", tf!("已移除本機副本：{}", it.label))
        } else {
            tf!("未完成：無法移除本機副本：{}", it.label)
        });
    }
    msgs
}
