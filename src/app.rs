//! The window: sidebar of modules, and each module's intro → scanning → results → done flow.
//! Page bodies live in `app/pages.rs` and `app/protect.rs`.

mod docker_page;
mod pages;
mod protect;
mod settings_page;
mod sources_page;
pub(crate) mod status_page;
#[cfg(target_os = "macos")]
mod tray;

use crate::av::{self, Extension, QItem, RuleSet, ScanHandle, ScanOptions, ScanRecord, Threat, ThreatKind};
use crate::clean::{self, App, Group, Item, Job, LaunchItem, Node};
use crate::theme::{self, alpha, Glyph, Palette, BAD, FAINT, GOOD, SUBTLE, TEXT, WARN};
use crate::util::{self, collapse, fmt_bytes};
use crate::vuln::{CheckHandle, Finding, Severity};
use egui::{Align, Color32, FontFamily, FontId, Layout, Pos2, Rect, RichText, Vec2};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------- style & fonts

pub fn setup_style(ctx: &egui::Context) {
    let lang = crate::prefs::Prefs::load().effective_lang();
    crate::i18n::set(lang);
    apply_fonts(ctx, lang);
    style_rest(ctx);
}

/// Vertical nudge for the Japanese font, as a share of the font size.
const JA_Y_OFFSET: f32 = 0.15;

/// Fonts for the interface language: SF Pro / SF Mono, then a CJK font (a Japanese one for
/// Japanese, so kanji use Japanese glyph shapes).
pub fn apply_fonts(ctx: &egui::Context, lang: crate::i18n::Lang) {
    let mut fonts = egui::FontDefinitions::default();
    // Design fonts: a clean sans for text and a monospace for labels and numbers (SF Pro /
    // SF Mono stand in for the design's Plus Jakarta Sans / JetBrains Mono), then a CJK font.
    for (key, path, fam) in [
        ("sans", "/System/Library/Fonts/SFNS.ttf", FontFamily::Proportional),
        ("mono", "/System/Library/Fonts/SFNSMono.ttf", FontFamily::Monospace),
    ] {
        if let Ok(bytes) = std::fs::read(path) {
            fonts.font_data.insert(key.into(), egui::FontData::from_owned(bytes));
            fonts.families.entry(fam).or_default().insert(0, key.into());
        }
    }
    for path in [
        "/System/Library/Fonts/STHeiti Medium.ttc",
        "/System/Library/Fonts/Hiragino Sans GB.ttc",
        "/Library/Fonts/Arial Unicode.ttf",
        "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
        "C:/Windows/Fonts/msjh.ttc",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    ] {
        if let Ok(bytes) = std::fs::read(path) {
            fonts.font_data.insert("cjk".into(), egui::FontData::from_owned(bytes));
            for fam in [FontFamily::Proportional, FontFamily::Monospace] {
                let list = fonts.families.entry(fam).or_default();
                let at = list.len().min(2);
                list.insert(at, "cjk".into());
            }
            break;
        }
    }
    // Second CJK fallback for characters the first font lacks (e.g. some kana and symbols).
    if let Ok(bytes) = std::fs::read("/System/Library/Fonts/Hiragino Sans GB.ttc") {
        if !fonts.font_data.contains_key("cjk2") {
            fonts.font_data.insert("cjk2".into(), egui::FontData::from_owned(bytes));
            for fam in [FontFamily::Proportional, FontFamily::Monospace] {
                fonts.families.entry(fam).or_default().push("cjk2".into());
            }
        }
    }
    if lang == crate::i18n::Lang::Ja {
        for path in ["/System/Library/Fonts/ヒラギノ角ゴシック W3.ttc", "/System/Library/Fonts/Hiragino Sans W3.ttc", "/System/Library/Fonts/Hiragino Sans GB.ttc"] { // i18n-ignore (font file names; GB has kanji and kana in one font)
            if let Ok(bytes) = std::fs::read(path) {
                // Hiragino's glyphs sit higher than SF Pro's; nudge them down to share a baseline.
                let tweak = egui::FontTweak { y_offset_factor: JA_Y_OFFSET, ..Default::default() };
                fonts.font_data.insert("ja".into(), egui::FontData::from_owned(bytes).tweak(tweak));
                for fam in [FontFamily::Proportional, FontFamily::Monospace] {
                    let list = fonts.families.entry(fam).or_default();
                    let at = list.iter().position(|f| f == "cjk").unwrap_or(list.len().min(2));
                    list.insert(at, "ja".into());
                }
                break;
            }
        }
    }
    ctx.set_fonts(fonts);
}

fn style_rest(ctx: &egui::Context) {
    let mut st = (*ctx.style()).clone();
    st.visuals = egui::Visuals::dark();
    st.visuals.override_text_color = Some(TEXT);
    st.visuals.panel_fill = theme::BG;
    st.visuals.window_fill = theme::SURFACE;
    st.visuals.window_stroke = egui::Stroke::new(1.0_f32, theme::OUTLINE);
    st.visuals.extreme_bg_color = theme::SIDEBAR_BG;
    st.visuals.faint_bg_color = theme::SURFACE;
    st.visuals.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0_f32, theme::OUTLINE);
    st.visuals.widgets.inactive.weak_bg_fill = theme::SURFACE_HI;
    st.visuals.widgets.inactive.bg_fill = theme::SURFACE_HI;
    st.visuals.widgets.hovered.weak_bg_fill = theme::SURFACE_TOP;
    st.visuals.widgets.hovered.bg_fill = theme::SURFACE_TOP;
    st.visuals.widgets.active.weak_bg_fill = theme::SURFACE_TOP;
    st.visuals.widgets.active.bg_fill = theme::PRIMARY_BTN;
    st.visuals.selection.bg_fill = alpha(theme::PRIMARY_BTN, 110);
    st.visuals.selection.stroke = egui::Stroke::new(1.0_f32, theme::PRIMARY);
    st.visuals.hyperlink_color = theme::PRIMARY;
    for w in [&mut st.visuals.widgets.inactive, &mut st.visuals.widgets.hovered, &mut st.visuals.widgets.active] {
        w.rounding = egui::Rounding::same(6.0);
        w.fg_stroke = egui::Stroke::new(1.6_f32, TEXT);
        w.bg_stroke = egui::Stroke::new(1.0_f32, theme::OUTLINE);
    }
    st.visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, theme::FAINT);
    st.spacing.item_spacing = Vec2::new(8.0, 7.0);
    st.spacing.button_padding = Vec2::new(12.0, 5.0);
    st.spacing.scroll = egui::style::ScrollStyle::thin();
    st.text_styles.insert(egui::TextStyle::Body, FontId::proportional(14.0));
    st.text_styles.insert(egui::TextStyle::Button, FontId::proportional(13.5));
    st.text_styles.insert(egui::TextStyle::Small, FontId::proportional(12.0));
    st.text_styles.insert(egui::TextStyle::Monospace, FontId::monospace(12.5));
    st.text_styles.insert(egui::TextStyle::Heading, FontId::proportional(24.0));
    ctx.set_style(st);
}

// ---------------------------------------------------------------- pages

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Page {
    Status,
    QuickCheck,
    Cleanup,
    Protection,
    Performance,
    Applications,
    Clutter,
    DiskMap,
    Cloud,
    Vulnerability,
    Docker,
    Settings,
}

impl Page {
    fn title(self) -> &'static str {
        match self {
            Page::Status => t!("Mac 狀態"),
            Page::QuickCheck => t!("一鍵健檢"),
            Page::Cleanup => t!("垃圾清理"),
            Page::Protection => t!("安全防護"),
            Page::Performance => t!("效能最佳化"),
            Page::Applications => t!("應用程式"),
            Page::Clutter => t!("整理雜亂"),
            Page::DiskMap => t!("空間地圖"),
            Page::Cloud => t!("雲端檔案"),
            Page::Vulnerability => t!("漏洞檢查"),
            Page::Docker => t!("Docker 清理"),
            Page::Settings => t!("設定"),
        }
    }
    fn palette(self) -> Palette {
        use theme::pal;
        match self {
            Page::Status => pal([24, 30, 80], [58, 36, 120], [80, 110, 240], [140, 180, 255]),
            Page::QuickCheck => pal([34, 30, 84], [86, 38, 112], [104, 84, 230], [150, 120, 255]),
            Page::Cleanup => pal([10, 58, 52], [24, 104, 82], [32, 170, 120], [96, 230, 170]),
            Page::Protection => pal([66, 14, 60], [128, 26, 96], [196, 40, 140], [250, 120, 200]),
            Page::Performance => pal([78, 30, 14], [150, 64, 22], [236, 110, 40], [255, 180, 90]),
            Page::Applications => pal([14, 36, 92], [26, 80, 160], [40, 120, 240], [120, 190, 255]),
            Page::Clutter => pal([12, 64, 78], [20, 110, 120], [24, 168, 180], [110, 230, 230]),
            Page::DiskMap => pal([40, 22, 90], [92, 46, 156], [140, 80, 240], [200, 150, 255]),
            Page::Cloud => pal([14, 52, 92], [30, 104, 160], [50, 150, 230], [140, 210, 255]),
            Page::Docker => pal([14, 36, 92], [26, 80, 160], [40, 120, 240], [120, 190, 255]),
            Page::Vulnerability => pal([46, 14, 52], [118, 28, 58], [220, 60, 80], [255, 150, 120]),
            Page::Settings => pal([30, 32, 44], [52, 56, 74], [110, 118, 150], [180, 188, 214]),
        }
    }
    fn eyebrow(self) -> &'static str {
        match self {
            Page::Status => "CORE TELEMETRY REPORT",
            Page::QuickCheck => "QUICK CHECKUP",
            Page::Cleanup => "SYSTEM JUNK · PURGE",
            Page::Protection => "MALWARE PROTECTION",
            Page::Performance => "PERFORMANCE · MAINTENANCE",
            Page::Applications => "APPLICATIONS",
            Page::Clutter => "LARGE & DUPLICATE FILES",
            Page::DiskMap => "DISK MAP",
            Page::Cloud => "CLOUD STORAGE",
            Page::Vulnerability => "CVE SCANNER · OSV.DEV",
            Page::Docker => "DOCKER · DISK USAGE",
            Page::Settings => "SETTINGS · PREFERENCES",
        }
    }
    fn glyph(self) -> Glyph {
        match self {
            Page::Status => Glyph::Pulse,
            Page::QuickCheck => Glyph::Sparkle,
            Page::Cleanup => Glyph::Bubbles,
            Page::Protection => Glyph::Shield,
            Page::Performance => Glyph::Bolt,
            Page::Applications => Glyph::Grid,
            Page::Clutter => Glyph::Folders,
            Page::DiskMap => Glyph::Rings,
            Page::Cloud => Glyph::Cloud,
            Page::Vulnerability => Glyph::Bug,
            Page::Docker => Glyph::Grid,
            Page::Settings => Glyph::Gear,
        }
    }
}

const SIDEBAR: &[(&str, &[Page])] = &[
    ("", &[Page::Status, Page::QuickCheck]),
    (n!("模組"), &[Page::Cleanup, Page::Protection, Page::Performance, Page::Applications, Page::Clutter]),
    (n!("工具"), &[Page::DiskMap, Page::Cloud, Page::Docker, Page::Vulnerability]),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProtTab {
    Scan,
    Realtime,
    Quarantine,
    Extensions,
    Privacy,
    Permissions,
    SafeList,
    Settings,
    Sources,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PerfTab {
    Tasks,
    Launch,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AppTab {
    Uninstaller,
    Updater,
    Leftovers,
    Installers,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ClutterTab {
    Large,
    Duplicates,
}

struct SmartResult {
    junk: Vec<Group>,
    large: Vec<Item>,
    launch: Vec<LaunchItem>,
}

pub struct MacApp {
    page: Page,
    t: f32,
    toast: Option<(String, f64)>,
    log: Vec<String>,
    shooting: bool,

    // antivirus
    rules: Arc<RuleSet>,
    /// Full rule set (with Apple XProtect) being compiled in the background.
    rules_job: Option<Job<RuleSet>>,
    /// MalwareBazaar download in the background.
    mb_job: Option<Job<Result<usize, String>>>,
    mb_key_input: String,
    mb_status: Option<String>,
    mb_has_key: bool,
    opts: ScanOptions,
    safe: Arc<Mutex<Vec<PathBuf>>>,
    quarantine: Arc<Mutex<Vec<QItem>>>,
    monitor: av::Monitor,
    history: Vec<ScanRecord>,
    scan: Option<ScanHandle>,
    scan_custom: bool,
    threats: Option<Vec<Threat>>,
    scan_summary: Option<(u64, u64)>,
    removed_summary: Option<(usize, Vec<String>)>,
    prot_tab: ProtTab,
    exts: Option<Vec<Extension>>,
    profiles: Vec<String>,
    privacy_job: Option<Job<Vec<Group>>>,
    privacy: Option<Vec<Group>>,
    wifi: Option<(String, Vec<(String, bool)>)>,
    safe_input: String,

    // cleanup
    junk_job: Option<Job<Vec<Group>>>,
    junk: Option<Vec<Group>>,
    junk_done: Option<(u64, Vec<String>)>,

    // performance
    perf_tab: PerfTab,
    task_sel: Vec<bool>,
    task_job: Option<Job<Vec<String>>>,
    task_msgs: Vec<String>,
    launch: Option<Vec<LaunchItem>>,

    // applications
    app_tab: AppTab,
    apps_job: Option<Job<Vec<App>>>,
    apps: Option<Vec<App>>,
    app_filter: String,
    app_selected: Option<usize>,
    update_job: Option<Job<Vec<App>>>,
    updates_checked: bool,
    leftovers: Option<Vec<Item>>,
    installers: Option<Vec<Item>>,

    // clutter
    clutter_tab: ClutterTab,
    clutter_job: Option<Job<(Vec<Item>, Vec<Group>)>>,
    large: Option<Vec<Item>>,
    dups: Option<Vec<Group>>,

    // disk map
    lens_stack: Vec<PathBuf>,
    lens_scan: Option<clean::LensScan>,
    lens_note: Option<String>,
    logo: Option<egui::TextureHandle>,
    docker_job: Option<Job<crate::docker::Info>>,
    docker: Option<crate::docker::Info>,
    docker_pending: Option<docker_page::Pending>,
    docker_typed: String,
    docker_ack: bool,
    docker_run: Option<Job<crate::docker::Report>>,
    docker_report: Option<crate::docker::Report>,
    lens: Option<Vec<Node>>,
    disk: (u64, u64),

    // cloud
    cloud_job: Option<Job<Vec<Group>>>,
    cloud: Option<Vec<Group>>,

    // vulnerability
    vuln_path: String,
    vuln: Option<CheckHandle>,
    vuln_root: PathBuf,
    vuln_findings: Option<Vec<Finding>>,
    vuln_manifests: Vec<(String, String, usize)>,
    vuln_packages: usize,
    vuln_error: Option<String>,

    // quick checkup
    smart_job: Option<Job<SmartResult>>,
    smart_scan: Option<ScanHandle>,
    smart: Option<SmartResult>,
    smart_threats: Option<Vec<Threat>>,
    smart_done: Option<String>,

    // live status (menu-bar panel)
    sampler: crate::status::Sampler,
    #[cfg(target_os = "macos")]
    tray: Option<tray::Tray>,
    tray_updated: f64,

    // settings: language and new-version check
    prefs: crate::prefs::Prefs,
    ver_job: Option<Job<Result<String, String>>>,
    /// Result of the last check (newest version, or the error), shown in Settings.
    ver_msg: Option<Result<String, String>>,
}

impl MacApp {
    pub fn new(shooting: bool) -> MacApp {
        // Start fast without Apple's rules; the full set is compiled in the background.
        let rules = Arc::new(RuleSet::load_basic());
        let mb_has_key = crate::sources::mb_key().is_some();
        let mb_job: Option<Job<Result<usize, String>>> = if mb_has_key && crate::sources::mb_due() && !shooting {
            Some(Job::spawn(|_| match crate::sources::mb_key() {
                Some(k) => crate::sources::update_malwarebazaar(&k),
                None => Err(t!("沒有金鑰").into()),
            }))
        } else {
            None
        };
        let settings: ScanOptions = std::fs::read_to_string(util::data_dir().join("settings.json")).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
        let monitor = av::Monitor::new();
        let safe = Arc::new(Mutex::new(av::load_safe_list()));
        let quarantine = Arc::new(Mutex::new(av::load_quarantine()));
        let monitor_on = std::fs::read_to_string(util::data_dir().join("monitor.txt")).map(|s| s.trim() != "off").unwrap_or(true);
        if monitor_on && !shooting {
            monitor.start(rules.clone(), safe.clone(), quarantine.clone());
        }
        let prefs = crate::prefs::Prefs::load();
        crate::i18n::set(prefs.effective_lang());
        let ver_due = util::now_secs().saturating_sub(prefs.last_update_check) >= crate::update::CHECK_EVERY_SECS;
        let ver_job = if prefs.check_updates && ver_due && !shooting { Some(Job::spawn(|_| crate::update::fetch_latest())) } else { None };
        let default_proj = ["Projects", "Developer", "Documents/GitHub", "code", "src"].iter().map(|p| util::home().join(p)).find(|p| p.exists()).unwrap_or_else(util::home);
        // Developer switch for checking one page: MCG_PAGE=status|performance.
        let start = match std::env::var("MCG_PAGE").unwrap_or_default().as_str() {
            "status" => Page::Status,
            "performance" => Page::Performance,
            "sources" => Page::Protection,
            "vuln" => Page::Vulnerability,
            "lens" => Page::DiskMap,
            "docker" => Page::Docker,
            "settings" => Page::Settings,
            _ => Page::QuickCheck,
        };
        MacApp {
            page: start,
            t: 0.0,
            toast: None,
            log: Vec::new(),
            shooting,
            rules,
            rules_job: Some(Job::spawn(|_| RuleSet::load())),
            mb_job,
            mb_key_input: String::new(),
            mb_status: None,
            mb_has_key,
            opts: settings,
            safe,
            quarantine,
            monitor,
            history: av::load_history(),
            scan: None,
            scan_custom: false,
            threats: None,
            scan_summary: None,
            removed_summary: None,
            prot_tab: if std::env::var("MCG_PAGE").as_deref() == Ok("sources") { ProtTab::Sources } else { ProtTab::Scan },
            exts: None,
            profiles: Vec::new(),
            privacy_job: None,
            privacy: None,
            wifi: None,
            safe_input: String::new(),
            junk_job: None,
            junk: None,
            junk_done: None,
            perf_tab: PerfTab::Tasks,
            task_sel: clean::TASKS.iter().map(|t| t.default_on).collect(),
            task_job: None,
            task_msgs: Vec::new(),
            launch: None,
            app_tab: AppTab::Uninstaller,
            apps_job: None,
            apps: None,
            app_filter: String::new(),
            app_selected: None,
            update_job: None,
            updates_checked: false,
            leftovers: None,
            installers: None,
            clutter_tab: ClutterTab::Large,
            clutter_job: None,
            large: None,
            dups: None,
            lens_stack: vec![util::home()],
            lens_scan: None,
            lens_note: None,
            logo: None,
            docker_job: None,
            docker: None,
            docker_pending: None,
            docker_typed: String::new(),
            docker_ack: false,
            docker_run: None,
            docker_report: None,
            lens: None,
            disk: clean::disk_usage(),
            cloud_job: None,
            cloud: None,
            vuln_path: collapse(&default_proj),
            vuln: None,
            vuln_root: default_proj,
            vuln_findings: None,
            vuln_manifests: Vec::new(),
            vuln_packages: 0,
            vuln_error: None,
            smart_job: None,
            smart_scan: None,
            smart: None,
            smart_threats: None,
            smart_done: None,
            sampler: crate::status::Sampler::start(),
            #[cfg(target_os = "macos")]
            tray: if shooting { None } else { tray::Tray::new() },
            tray_updated: -10.0,
            prefs,
            ver_job,
            ver_msg: None,
        }
    }

    /// Developer switch: MCG_VULN=<folder> starts a vulnerability check at launch.
    pub fn dev_autostart(&mut self) {
        if let Ok(p) = std::env::var("MCG_LENS") {
            self.lens_stack = vec![util::expand(&p)];
            self.lens_scan = Some(clean::start_lens(util::expand(&p)));
        }
        if let Ok(p) = std::env::var("MCG_VULN") {
            self.vuln_path = p;
            self.start_vuln();
        }
    }

    pub fn on_exit(&mut self) {
        self.monitor.stop();
        self.save_settings();
    }

    fn save_settings(&self) {
        if let Ok(t) = serde_json::to_string_pretty(&self.opts) {
            let _ = std::fs::write(util::data_dir().join("settings.json"), t);
        }
    }

    fn say(&mut self, ctx: &egui::Context, s: impl Into<String>) {
        let s = s.into();
        self.log.push(s.clone());
        self.toast = Some((s, ctx.input(|i| i.time) + 4.0));
    }

    pub fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.t = ctx.input(|i| i.time) as f32;
        self.poll(ctx);
        self.handle_drops(ctx);
        #[cfg(target_os = "macos")]
        self.tray_tick(ctx);
        let busy = self.scan.is_some() || self.junk_job.is_some() || self.smart_job.is_some() || self.vuln.is_some() || self.apps_job.is_some() || self.clutter_job.is_some() || self.lens_scan.is_some() || self.docker_job.is_some() || self.docker_run.is_some() || self.task_job.is_some() || self.update_job.is_some() || self.cloud_job.is_some() || self.privacy_job.is_some() || self.smart_scan.is_some();
        if busy || self.shooting {
            ctx.request_repaint();
        } else {
            ctx.request_repaint_after(std::time::Duration::from_millis(50));
        }

        egui::SidePanel::left("side").exact_width(232.0).resizable(false).frame(egui::Frame::none()).show(ctx, |ui| self.sidebar(ui));
        egui::TopBottomPanel::top("top").exact_height(52.0).frame(egui::Frame::none()).show(ctx, |ui| self.topbar(ui));
        egui::CentralPanel::default().frame(egui::Frame::none().fill(theme::BG)).show(ctx, |ui| {
            let rect = ui.max_rect();
            let inner = rect.shrink2(Vec2::new(34.0, 20.0));
            #[allow(deprecated)]
            ui.allocate_ui_at_rect(inner, |ui| match self.page {
                Page::Status => self.page_status(ui),
                Page::QuickCheck => self.page_smart(ui),
                Page::Cleanup => self.page_cleanup(ui),
                Page::Protection => self.page_protection(ui),
                Page::Performance => self.page_performance(ui),
                Page::Applications => self.page_apps(ui),
                Page::Clutter => self.page_clutter(ui),
                Page::DiskMap => self.page_lens(ui),
                Page::Cloud => self.page_cloud(ui),
                Page::Vulnerability => self.page_vuln(ui),
                Page::Docker => self.page_docker(ui),
                Page::Settings => self.page_settings(ui),
            });
            self.draw_toast(ui, rect);
        });
    }

    // ------------------------------------------------------------ polling background work

    fn poll(&mut self, ctx: &egui::Context) {
        if let Some(v) = self.rules_job.as_ref().and_then(|j| j.take()) {
            self.rules = Arc::new(v);
            self.rules_job = None;
            self.exts = None;
            if self.monitor.is_running() {
                self.monitor.stop();
                self.monitor.start(self.rules.clone(), self.safe.clone(), self.quarantine.clone());
            }
        }
        if let Some(r) = self.mb_job.as_ref().and_then(|j| j.take()) {
            self.mb_job = None;
            self.mb_status = Some(match r {
                Ok(n) => {
                    if self.rules_job.is_none() {
                        self.rules_job = Some(Job::spawn(|_| RuleSet::load()));
                    }
                    format!("✓ {}", tf!("已從 MalwareBazaar 下載 {} 筆 Mac 惡意軟體指紋", n))
                }
                Err(e) => e,
            });
        }
        if let Some(h) = &self.scan {
            let done = h.progress.lock().unwrap().done;
            if done {
                let pr = h.progress.lock().unwrap();
                let secs = pr.finished.saturating_sub(pr.started);
                self.threats = Some(pr.threats.clone());
                self.scan_summary = Some((pr.scanned, secs));
                let rec = ScanRecord { when: util::now_secs(), mode: if self.scan_custom { n!("自訂掃描").into() } else { self.opts.mode.title_source().into() }, scanned: pr.scanned, threats: pr.threats.len(), seconds: secs };
                drop(pr);
                self.history.insert(0, rec);
                self.history.truncate(50);
                av::save_history(&self.history);
                self.scan = None;
            }
        }
        if let Some(v) = self.junk_job.as_ref().and_then(|j| j.take()) {
            self.junk = Some(v);
            self.junk_job = None;
        }
        if let Some(v) = self.privacy_job.as_ref().and_then(|j| j.take()) {
            self.privacy = Some(v);
            self.privacy_job = None;
        }
        if let Some(v) = self.task_job.as_ref().and_then(|j| j.take()) {
            self.task_msgs = v;
            self.task_job = None;
        }
        if let Some(v) = self.apps_job.as_ref().and_then(|j| j.take()) {
            self.leftovers = Some(clean::orphan_leftovers(&v));
            self.apps = Some(v);
            self.apps_job = None;
        }
        if let Some(v) = self.update_job.as_ref().and_then(|j| j.take()) {
            self.apps = Some(v);
            self.update_job = None;
            self.updates_checked = true;
        }
        if let Some((l, d)) = self.clutter_job.as_ref().and_then(|j| j.take()) {
            self.large = Some(l);
            self.dups = Some(d);
            self.clutter_job = None;
        }
        if let Some(v) = self.docker_job.as_ref().and_then(|j| j.take()) {
            self.docker = Some(v);
            self.docker_job = None;
        }
        if let Some(r) = self.docker_run.as_ref().and_then(|j| j.take()) {
            self.docker_report = Some(r);
            self.docker_run = None;
            self.docker_job = Some(Job::spawn(|_| crate::docker::load()));
        }
        let lens_done = self.lens_scan.as_ref().map(|l| l.progress.lock().unwrap_or_else(|e| e.into_inner()).finished).unwrap_or(false);
        if lens_done {
            if let Some(l) = self.lens_scan.take() {
                let g = l.progress.lock().unwrap_or_else(|e| e.into_inner());
                self.lens = Some(g.nodes.clone());
                self.lens_note = if g.failed {
                    Some(t!("掃描時發生錯誤而中止，以下為已算完的部分結果。").to_string())
                } else if g.cancelled {
                    Some(tf!("已停止：只算完 {} / {} 個項目，以下為部分結果。", g.done_children, g.total_children))
                } else {
                    None
                };
            }
        }
        if let Some(v) = self.cloud_job.as_ref().and_then(|j| j.take()) {
            self.cloud = Some(v);
            self.cloud_job = None;
        }
        if let Some(h) = &self.vuln {
            let mut p = h.progress.lock().unwrap();
            if p.done {
                self.vuln_findings = Some(std::mem::take(&mut p.findings));
                self.vuln_error = p.error.take();
                self.vuln_packages = p.packages;
                self.vuln_manifests = p.manifests.iter().map(|m| (collapse(&m.path), m.kind.to_string(), m.packages.len())).collect();
                if p.packages == 0 && self.vuln_error.is_none() {
                    self.vuln_error = Some(p.stage.clone());
                }
                if self.vuln_error.is_some() && p.packages == 0 {
                    self.vuln_findings = None;
                }
                drop(p);
                self.vuln = None;
            }
        }
        if let Some(v) = self.smart_job.as_ref().and_then(|j| j.take()) {
            self.smart = Some(v);
            self.smart_job = None;
        }
        if let Some(h) = &self.smart_scan {
            let pr = h.progress.lock().unwrap();
            if pr.done {
                self.smart_threats = Some(pr.threats.clone());
                drop(pr);
                self.smart_scan = None;
            }
        }
        if let Some(r) = self.ver_job.as_ref().and_then(|j| j.take()) {
            self.ver_job = None;
            match r {
                Ok(v) => {
                    self.prefs.last_update_check = util::now_secs();
                    self.prefs.latest_version = Some(v.clone());
                    self.prefs.save();
                    self.ver_msg = Some(Ok(v));
                }
                Err(e) => self.ver_msg = Some(Err(e)),
            }
        }
        if let Some((_, until)) = &self.toast {
            if ctx.input(|i| i.time) > *until {
                self.toast = None;
            }
        }
    }

    fn handle_drops(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect());
        if dropped.is_empty() {
            return;
        }
        match self.page {
            Page::Vulnerability => {
                if let Some(p) = dropped.into_iter().find(|p| p.is_dir()) {
                    self.vuln_path = collapse(&p);
                    self.start_vuln();
                }
            }
            _ => {
                self.page = Page::Protection;
                self.prot_tab = ProtTab::Scan;
                self.start_scan(Some(dropped));
            }
        }
    }

    fn draw_toast(&self, ui: &mut egui::Ui, rect: Rect) {
        if let Some((s, _)) = &self.toast {
            let galley = ui.painter().layout(s.clone(), FontId::proportional(13.0), TEXT, rect.width() - 120.0);
            let size = galley.size() + Vec2::new(28.0, 16.0);
            let r = Rect::from_center_size(Pos2::new(rect.center().x, rect.top() + 26.0), size);
            ui.painter().rect_filled(r, 8.0, theme::SURFACE_HI);
            ui.painter().rect_stroke(r, 8.0, egui::Stroke::new(1.0_f32, theme::OUTLINE));
            ui.painter().galley(r.min + Vec2::new(14.0, 8.0), galley, TEXT);
        }
    }

    // ------------------------------------------------------------ top bar

    fn topbar(&mut self, ui: &mut egui::Ui) {
        let rect = ui.max_rect();
        ui.painter().rect_filled(rect, 0.0, theme::BG);
        ui.painter().line_segment([rect.left_bottom(), rect.right_bottom()], egui::Stroke::new(1.0_f32, theme::OUTLINE));
        ui.horizontal_centered(|ui| {
            ui.add_space(24.0);
            ui.label(RichText::new("Sanitized").monospace().color(SUBTLE));
            ui.label(RichText::new("/").monospace().color(FAINT));
            ui.label(RichText::new(self.page.title()).monospace().color(theme::PRIMARY));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(20.0);
                let btn = egui::Button::new(RichText::new(t!("快速清理")).color(Color32::WHITE).size(13.5)).fill(theme::PRIMARY_BTN).stroke(egui::Stroke::NONE).rounding(6.0).min_size(Vec2::new(96.0, 30.0));
                if ui.add(btn).on_hover_text(t!("執行一鍵健檢")).clicked() {
                    self.page = Page::QuickCheck;
                }
                ui.add_space(6.0);
                // Settings (gear)
                let (gr, gresp) = ui.allocate_exact_size(Vec2::splat(30.0), egui::Sense::click());
                let on_settings = self.page == Page::Settings;
                if gresp.hovered() || on_settings {
                    ui.painter().rect_filled(gr, 6.0, theme::SURFACE_HI);
                }
                theme::icon(ui.painter(), gr.center(), 16.0, Glyph::Gear, if on_settings { theme::PRIMARY } else { SUBTLE });
                if gresp.on_hover_text(t!("設定")).clicked() {
                    self.page = Page::Settings;
                }
                ui.add_space(8.0);
                // New version available (only when checking is on)
                let newer = self.prefs.latest_version.clone().filter(|v| self.prefs.check_updates && crate::update::is_newer(v));
                if let Some(v) = newer {
                    let txt = tf!("新版本 v{} →", v);
                    let resp = ui.add(egui::Button::new(RichText::new(txt).monospace().size(11.5).color(GOOD)).fill(alpha(GOOD, 22)).stroke(egui::Stroke::new(1.0_f32, alpha(GOOD, 120))).rounding(5.0));
                    if resp.on_hover_text(t!("在 GitHub 查看並下載新版本")).clicked() {
                        util::open_url(crate::update::RELEASES_PAGE);
                    }
                    ui.add_space(8.0);
                }
                let on = self.monitor.is_running() || self.shooting;
                let xp = self.rules.xprotect.as_ref().map(|x| format!("XProtect v{}", x.version)).unwrap_or_else(|| t!("XProtect 載入中").into());
                let (dot, txt) = if on { (GOOD, tf!("{} · 即時防護開啟", xp)) } else { (WARN, tf!("{} · 即時防護關閉", xp)) };
                ui.label(RichText::new(txt).monospace().size(11.5).color(SUBTLE));
                let (r, _) = ui.allocate_exact_size(Vec2::splat(10.0), egui::Sense::hover());
                ui.painter().circle_filled(r.center(), 3.5, dot);
            });
        });
    }

    // ------------------------------------------------------------ sidebar

    fn sidebar(&mut self, ui: &mut egui::Ui) {
        let rect = ui.max_rect();
        ui.painter().rect_filled(rect, 0.0, theme::SIDEBAR_BG);
        ui.painter().line_segment([rect.right_top(), rect.right_bottom()], egui::Stroke::new(1.0_f32, theme::OUTLINE));
        let snap = self.sampler.get();
        ui.add_space(18.0);
        ui.horizontal(|ui| {
            ui.add_space(18.0);
            let (r, _) = ui.allocate_exact_size(Vec2::splat(34.0), egui::Sense::hover());
            if self.logo.is_none() {
                if let Some((px, w, h)) = util::png_rgba(include_bytes!("../assets/logo_96.png")) {
                    let img = egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], &px);
                    self.logo = Some(ui.ctx().load_texture("logo", img, egui::TextureOptions::LINEAR));
                }
            }
            match &self.logo {
                Some(t) => {
                    ui.painter().image(t.id(), r.expand(4.0), Rect::from_min_max(Pos2::ZERO, Pos2::new(1.0, 1.0)), Color32::WHITE);
                }
                None => {
                    ui.painter().rect_filled(r, 7.0, theme::PRIMARY_BTN);
                    theme::icon(ui.painter(), r.center(), 18.0, Glyph::Shield, Color32::WHITE);
                }
            }
            ui.vertical(|ui| {
                ui.spacing_mut().item_spacing.y = 1.0;
                ui.label(RichText::new("Sanitized").size(15.0).strong());
                ui.label(RichText::new(macos_version()).monospace().size(10.5).color(SUBTLE));
            });
        });
        ui.add_space(12.0);
        // Quick sweep (outlined), like the design's sidebar button.
        let qs = Rect::from_min_size(Pos2::new(rect.left() + 14.0, ui.cursor().top()), Vec2::new(rect.width() - 28.0, 34.0));
        let resp = ui.allocate_rect(qs, egui::Sense::click());
        ui.painter().rect_filled(qs, 7.0, if resp.hovered() { theme::SURFACE_HI } else { theme::SURFACE });
        ui.painter().rect_stroke(qs, 7.0, egui::Stroke::new(1.0_f32, theme::OUTLINE));
        theme::icon(ui.painter(), Pos2::new(qs.center().x - 44.0, qs.center().y), 15.0, Glyph::Bolt, theme::PRIMARY);
        ui.painter().text(Pos2::new(qs.center().x + 8.0, qs.center().y), egui::Align2::CENTER_CENTER, "Quick Sweep", FontId::proportional(13.5), TEXT);
        if resp.clicked() {
            self.page = Page::QuickCheck;
        }
        ui.add_space(8.0);
        let threats_now = self.monitor.events.lock().unwrap().iter().filter(|e| e.threat.is_some()).count();
        for (head, pages) in SIDEBAR {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.add_space(24.0);
                let h = if head.is_empty() { t!("系統總覽") } else { crate::i18n::tr(head) };
                ui.label(RichText::new(h).size(11.0).color(FAINT));
            });
            for pg in *pages {
                let selected = self.page == *pg;
                let (r, resp) = ui.allocate_exact_size(Vec2::new(rect.width(), 32.0), egui::Sense::click());
                let row = Rect::from_min_max(Pos2::new(r.left() + 12.0, r.top() + 1.0), Pos2::new(r.right() - 12.0, r.bottom() - 1.0));
                if selected {
                    ui.painter().rect_filled(row, 7.0, theme::SURFACE_HI);
                    ui.painter().rect_stroke(row, 7.0, egui::Stroke::new(1.0_f32, theme::OUTLINE));
                } else if resp.hovered() {
                    ui.painter().rect_filled(row, 7.0, theme::SURFACE);
                }
                let col = if selected { theme::PRIMARY } else { SUBTLE };
                theme::icon(ui.painter(), Pos2::new(row.left() + 18.0, row.center().y), 15.0, pg.glyph(), col);
                ui.painter().text(Pos2::new(row.left() + 36.0, row.center().y), egui::Align2::LEFT_CENTER, pg.title(), FontId::proportional(13.5), if selected { theme::PRIMARY } else { TEXT });
                let metric: Option<(String, Color32)> = match pg {
                    Page::Status if snap.ready => Some((format!("{}%", snap.health), FAINT)),
                    Page::Protection if threats_now > 0 => Some((threats_now.to_string(), BAD)),
                    Page::Protection => Some(("0".into(), GOOD)),
                    Page::DiskMap if snap.ready => Some((format!("{}G", snap.disk_free / 1_000_000_000), FAINT)),
                    Page::Applications => self.apps.as_ref().map(|a| (a.len().to_string(), FAINT)),
                    Page::Vulnerability => Some((t!("新").into(), WARN)),
                    _ => None,
                };
                if let Some((m, c)) = metric {
                    ui.painter().text(Pos2::new(row.right() - 10.0, row.center().y), egui::Align2::RIGHT_CENTER, m, FontId::monospace(11.0), c);
                }
                if resp.clicked() {
                    self.page = *pg;
                }
                if resp.hovered() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
            }
        }
        // footer: engine, uptime, protection (mono rows like the design)
        let top = rect.bottom() - 92.0;
        ui.painter().line_segment([Pos2::new(rect.left() + 14.0, top), Pos2::new(rect.right() - 14.0, top)], egui::Stroke::new(1.0_f32, theme::OUTLINE));
        let on = self.monitor.is_running() || self.shooting;
        let xp = self.rules.xprotect.as_ref().map(|x| format!("v{}", x.version)).unwrap_or_else(|| t!("載入中").into());
        let up = snap.uptime_secs;
        let rows = [
            ("XPROTECT ENGINE", xp, SUBTLE),
            ("UPTIME", if snap.ready { format!("{}d {}h {}m", up / 86400, (up / 3600) % 24, (up / 60) % 60) } else { "–".into() }, SUBTLE),
            ("REAL-TIME", if on { "ON".to_string() } else { "OFF".to_string() }, if on { GOOD } else { WARN }),
        ];
        for (i, (k, v, c)) in rows.iter().enumerate() {
            let y = top + 18.0 + i as f32 * 22.0;
            ui.painter().text(Pos2::new(rect.left() + 20.0, y), egui::Align2::LEFT_CENTER, *k, FontId::monospace(10.5), FAINT);
            ui.painter().text(Pos2::new(rect.right() - 20.0, y), egui::Align2::RIGHT_CENTER, v, FontId::monospace(10.5), *c);
        }
    }

    // ------------------------------------------------------------ shared layouts

    fn intro(&mut self, ui: &mut egui::Ui, title: &str, subtitle: &str, bullets: &[(&str, &str)]) {
        let r = ui.max_rect();
        let p = self.page.palette();
        let art_c = Pos2::new(r.left() + r.width() * 0.76, r.top() + r.height() * 0.36);
        // still while idle: the moving dot only appears during scans
        theme::illustration(ui.painter(), art_c, (r.height() * 0.42).min(250.0), p, self.page.glyph(), -1.0);
        let text_rect = Rect::from_min_max(Pos2::new(r.left() + 4.0, r.top() + r.height() * 0.08), Pos2::new(r.left() + r.width() * 0.56, r.bottom() - 170.0));
        let eyebrow = self.page.eyebrow();
        #[allow(deprecated)]
        ui.allocate_ui_at_rect(text_rect, |ui| {
            theme::eyebrow(ui, eyebrow);
            ui.label(RichText::new(title).size(30.0).strong());
            ui.add_space(2.0);
            ui.label(RichText::new(subtitle).size(14.5).color(SUBTLE));
            ui.add_space(18.0);
            card(ui, |ui| {
                for (i, (h, d)) in bullets.iter().enumerate() {
                    if i > 0 {
                        ui.separator();
                    }
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(format!("{:02}", i + 1)).monospace().color(theme::PRIMARY));
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            ui.label(RichText::new(*h).size(14.5).strong());
                            ui.label(RichText::new(*d).size(12.5).color(SUBTLE));
                        });
                    });
                }
            });
        });
    }

    fn bottom_center(&self, ui: &egui::Ui) -> Pos2 {
        let r = ui.max_rect();
        Pos2::new(r.center().x, r.bottom() - 46.0)
    }

    fn header(&self, ui: &mut egui::Ui, title: &str, right: &str) {
        theme::eyebrow(ui, self.page.eyebrow());
        ui.horizontal(|ui| {
            ui.label(RichText::new(title).size(22.0).strong());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(RichText::new(right).size(13.0).color(SUBTLE));
            });
        });
        ui.add_space(6.0);
    }

    fn header_inline(&self, ui: &mut egui::Ui, l: &str, r: &str) {
        ui.horizontal(|ui| {
            ui.label(RichText::new(l).size(18.0).strong());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| ui.label(RichText::new(r).monospace().color(SUBTLE)));
        });
    }

    fn progress_view(&self, ui: &mut egui::Ui, title: &str, detail: &str) {
        let r = ui.max_rect();
        let p = self.page.palette();
        let c = Pos2::new(r.center().x, r.top() + r.height() * 0.38);
        theme::illustration(ui.painter(), c, (r.height() * 0.3).min(190.0), p, self.page.glyph(), self.t * 3.0);
        ui.painter().text(Pos2::new(r.center().x, r.top() + r.height() * 0.62), egui::Align2::CENTER_CENTER, self.page.eyebrow(), FontId::monospace(11.0), SUBTLE);
        ui.painter().text(Pos2::new(r.center().x, r.top() + r.height() * 0.62 + 26.0), egui::Align2::CENTER_CENTER, title, FontId::proportional(22.0), TEXT);
        ui.painter().text(Pos2::new(r.center().x, r.top() + r.height() * 0.62 + 54.0), egui::Align2::CENTER_CENTER, short(detail, 90), FontId::monospace(12.0), SUBTLE);
    }

    fn progress_done(&self, ui: &mut egui::Ui, title: &str, detail: &str) {
        let r = ui.max_rect();
        let p = self.page.palette();
        theme::illustration(ui.painter(), Pos2::new(r.center().x, r.top() + r.height() * 0.36), (r.height() * 0.28).min(180.0), p, self.page.glyph(), -1.0);
        ui.painter().text(Pos2::new(r.center().x, r.top() + r.height() * 0.6), egui::Align2::CENTER_CENTER, title, FontId::proportional(24.0), TEXT);
        let g = ui.painter().layout(detail.to_string(), FontId::proportional(14.0), SUBTLE, r.width() * 0.7);
        let pos = Pos2::new(r.center().x - g.size().x / 2.0, r.top() + r.height() * 0.6 + 24.0);
        ui.painter().galley(pos, g, SUBTLE);
    }
}

fn macos_version() -> &'static str {
    static V: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    V.get_or_init(|| {
        let v = util::run("sw_vers", &["-productVersion"]).trim().to_string();
        if v.is_empty() { "macOS".into() } else { format!("macOS {}", v) }
    })
}

// ---------------------------------------------------------------- small widgets

fn short(s: &str, n: usize) -> String {
    let n = n.max(4);
    if s.chars().count() > n {
        format!("{}…", s.chars().take(n - 1).collect::<String>())
    } else {
        s.to_string()
    }
}

fn card(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::none()
        .fill(theme::SURFACE)
        .stroke(egui::Stroke::new(1.0_f32, theme::OUTLINE))
        .rounding(10.0)
        .inner_margin(egui::Margin::symmetric(16.0, 12.0))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        });
    ui.add_space(6.0);
}

/// Status tag: mono text, tinted border, dark fill ("● HIGH RISK" style).
fn pill(ui: &mut egui::Ui, text: &str, col: Color32) {
    egui::Frame::none().fill(alpha(col, 22)).stroke(egui::Stroke::new(1.0_f32, alpha(col, 120))).rounding(5.0).inner_margin(egui::Margin::symmetric(7.0, 2.0)).show(ui, |ui| {
        ui.label(RichText::new(text).monospace().size(11.0).color(col));
    });
}

fn kind_color(k: ThreatKind) -> Color32 {
    match k {
        ThreatKind::Malware => BAD,
        ThreatKind::Adware => WARN,
        ThreatKind::Suspicious => Color32::from_rgb(230, 210, 140),
        ThreatKind::TestFile => Color32::from_rgb(150, 200, 255),
    }
}

fn sev_color(s: Severity) -> Color32 {
    match s {
        Severity::Critical => Color32::from_rgb(255, 80, 100),
        Severity::High => Color32::from_rgb(255, 140, 90),
        Severity::Medium => WARN,
        Severity::Low => Color32::from_rgb(150, 220, 170),
        Severity::Unknown => FAINT,
    }
}

fn items_ui(ui: &mut egui::Ui, items: &mut [Item]) {
    if items.is_empty() {
        ui.label(RichText::new(t!("沒有找到項目。")).color(FAINT));
    }
    for it in items.iter_mut() {
        item_row(ui, it);
    }
}

fn item_row(ui: &mut egui::Ui, it: &mut Item) {
    ui.horizontal(|ui| {
        match util::protected_reason(&it.path) {
            Some(why) => {
                it.selected = false;
                ui.label(RichText::new(t!("受保護")).monospace().size(11.0).color(WARN)).on_hover_text(crate::i18n::tr(&why));
            }
            None => {
                ui.checkbox(&mut it.selected, "");
            }
        }
        ui.vertical(|ui| {
            ui.label(RichText::new(short(crate::i18n::tr(&it.label), 70)).size(13.5));
            if !it.note.is_empty() {
                ui.label(RichText::new(short(crate::i18n::tr(&it.note), 90)).size(11.5).color(FAINT));
            }
        });
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            if ui.small_button(t!("顯示")).clicked() {
                util::reveal(&it.path);
            }
            ui.label(RichText::new(fmt_bytes(it.size)).color(SUBTLE));
        });
    });
}

fn groups_ui(ui: &mut egui::Ui, groups: &mut [Group], salt: &str) {
    for (gi, g) in groups.iter_mut().enumerate() {
        card(ui, |ui| {
            ui.horizontal(|ui| {
                let mut a = g.items.iter().all(|i| i.selected);
                if ui.checkbox(&mut a, "").changed() {
                    for i in g.items.iter_mut() {
                        i.selected = a;
                    }
                }
                let arrow = if g.open { "▼" } else { "▶" };
                if ui.add(egui::Label::new(RichText::new(format!("{} {}", arrow, crate::i18n::tr(&g.title))).size(15.0).strong()).sense(egui::Sense::click())).clicked() {
                    g.open = !g.open;
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new(format!("{} / {}", fmt_bytes(g.selected_size()), fmt_bytes(g.size()))).color(SUBTLE));
                    ui.label(RichText::new(tf!("{} 個項目", g.items.len())).size(12.0).color(FAINT));
                });
            });
            ui.label(RichText::new(crate::i18n::tr(&g.desc)).size(12.0).color(SUBTLE));
            if g.open {
                ui.push_id((salt, gi), |ui| {
                    for it in g.items.iter_mut().take(300) {
                        item_row(ui, it);
                    }
                    if g.items.len() > 300 {
                        ui.label(RichText::new(tf!("還有 {} 個項目…", g.items.len() - 300)).color(FAINT));
                    }
                });
            }
        });
    }
}
