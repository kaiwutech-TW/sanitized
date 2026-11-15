//! Quick checkup, cleanup, performance, applications, large files, disk map and cloud pages.

use super::{card, groups_ui, items_ui, pill, short, AppTab, ClutterTab, MacApp, Page, PerfTab, ProtTab, SmartResult};
use crate::av::{self, ScanMode, ScanOptions};
use crate::clean::{self, App, Group, Item, Job};
use crate::theme::{self, alpha, big_button, FAINT, GOOD, SUBTLE, TEXT, WARN};
use crate::util::{self, collapse, fmt_bytes};
use egui::{Align, Color32, FontId, Layout, Pos2, Rect, RichText, Vec2};
use std::path::PathBuf;

fn fmt_count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// Bars for Disk map items; `interactive` adds open / show / trash actions.
fn lens_list(ui: &mut egui::Ui, nodes: &[clean::Node], interactive: bool, nav: &mut Option<PathBuf>, trash: &mut Option<PathBuf>) {
    let max = nodes.first().map(|n| n.size).unwrap_or(1).max(1) as f32;
    for n in nodes {
        ui.horizontal(|ui| {
            let w = ui.available_width() - if interactive { 250.0 } else { 120.0 };
            let (r, resp) = ui.allocate_exact_size(Vec2::new(w.max(100.0), 26.0), egui::Sense::click());
            ui.painter().rect_filled(r, 5.0, theme::SURFACE);
            let fill = Rect::from_min_size(r.min, Vec2::new(r.width() * (n.size as f32 / max).clamp(0.01, 1.0), r.height()));
            ui.painter().rect_filled(fill, 5.0, alpha(theme::PRIMARY_BTN, 110));
            let label = if n.is_dir && interactive { format!("{} ›", n.name) } else { n.name.clone() };
            ui.painter().text(r.left_center() + Vec2::new(10.0, 0.0), egui::Align2::LEFT_CENTER, label, FontId::proportional(13.0), TEXT);
            if interactive && resp.clicked() && n.is_dir {
                *nav = Some(n.path.clone());
            }
            if interactive && resp.hovered() && n.is_dir {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
            ui.label(RichText::new(fmt_bytes(n.size)).monospace().color(SUBTLE));
            if interactive {
                if ui.small_button(t!("顯示")).clicked() {
                    util::reveal(&n.path);
                }
                match util::protected_reason(&n.path) {
                    // Docker data / virtual disks: no delete button, only the explanation.
                    Some(why) => {
                        ui.label(RichText::new(t!("受保護 · 不可直接刪除")).size(12.0).color(WARN)).on_hover_text(crate::i18n::tr(why));
                    }
                    None => {
                        if ui.small_button(t!("移到廢紙簍")).clicked() {
                            *trash = Some(n.path.clone());
                        }
                    }
                }
            }
        });
    }
}

fn one_group(items: Vec<Item>) -> Vec<Group> {
    vec![Group { title: String::new(), desc: String::new(), items, open: true, permanent: false }]
}

impl MacApp {
    // ------------------------------------------------------------ quick checkup

    pub(super) fn page_smart(&mut self, ui: &mut egui::Ui) {
        let bc = self.bottom_center(ui);
        let p = self.page.palette();
        if self.smart_job.is_some() || self.smart_scan.is_some() {
            let st = self.smart_job.as_ref().map(|j| j.status()).unwrap_or_else(|| t!("正在完成安全檢查…").into());
            let scanned = self.smart_scan.as_ref().map(|h| h.progress.lock().unwrap().scanned).unwrap_or(0);
            self.progress_view(ui, t!("正在全面檢查您的 Mac…"), &tf!("{}　已檢查 {} 個檔案的安全性", crate::i18n::tr(&st), scanned));
            if big_button(ui, bc, t!("停止"), p, self.t, Some(0.0)).clicked() {
                if let Some(h) = &self.smart_scan {
                    h.stop();
                }
            }
            return;
        }
        if let Some(msg) = self.smart_done.clone() {
            self.progress_done(ui, t!("做得好！您的 Mac 狀態良好！"), &msg);
            if big_button(ui, bc, t!("重新開始"), p, self.t, None).clicked() {
                self.smart_done = None;
                self.smart = None;
                self.smart_threats = None;
            }
            return;
        }
        if self.smart.is_some() {
            self.smart_results(ui);
            return;
        }
        self.intro(ui, t!("歡迎使用 Sanitized"), t!("先為您的 Mac 進行一次快速而全面的掃描。"), &[
            (t!("清理"), t!("移除系統垃圾與不需要的檔案")),
            (t!("安全防護"), t!("找出惡意軟體與可疑的自動啟動項目")),
            (t!("效能"), t!("檢查損壞的背景項目與維護工作")),
            (t!("整理雜亂"), t!("找出佔用空間的大型檔案")),
        ]);
        if big_button(ui, bc, t!("掃描"), p, self.t, None).clicked() {
            self.smart_job = Some(Job::spawn(|s| {
                let junk = clean::scan_junk(s);
                let large = clean::large_files(s);
                *s.lock().unwrap() = n!("正在檢查背景項目…").into();
                let launch = clean::launch_items();
                SmartResult { junk, large, launch }
            }));
            let o = ScanOptions { mode: ScanMode::Quick, ..self.opts.clone() };
            self.smart_scan = Some(av::start_scan(o, self.rules.clone(), self.safe.lock().unwrap().clone(), None));
        }
    }

    fn smart_results(&mut self, ui: &mut egui::Ui) {
        let bc = self.bottom_center(ui);
        let p = self.page.palette();
        let Some(sr) = &self.smart else { return };
        let junk = clean::total_selected(&sr.junk);
        let threats = self.smart_threats.as_ref().map(|v| v.len()).unwrap_or(0);
        let broken = sr.launch.iter().filter(|l| l.broken).count();
        let large: u64 = sr.large.iter().map(|i| i.size).sum();
        let nlarge = sr.large.len();
        ui.add_space(10.0);
        ui.label(RichText::new(t!("執行任務已準備就緒。看看我們發現了什麼：")).size(24.0).strong());
        ui.add_space(18.0);
        let cards: Vec<(Page, &str, String, String, bool)> = vec![
            (Page::Cleanup, t!("清理"), if junk > 0 { fmt_bytes(junk) } else { t!("無").into() }, if junk > 0 { t!("待清理的垃圾").into() } else { t!("您的 Mac 很乾淨").into() }, junk > 0),
            (Page::Protection, t!("安全防護"), if threats > 0 { tf!("{} 個", threats) } else { t!("無威脅").into() }, if threats > 0 { t!("待移除的威脅").into() } else { t!("您的 Mac 是安全的").into() }, threats > 0),
            (Page::Performance, t!("效能"), if broken > 0 { tf!("{} 個", broken) } else { t!("正常").into() }, if broken > 0 { t!("損壞的背景項目").into() } else { t!("沒有需要處理的項目").into() }, broken > 0),
            (Page::Clutter, t!("整理雜亂"), fmt_bytes(large), tf!("{} 個大型檔案待檢視", nlarge), false),
        ];
        let w = (ui.available_width() - 3.0 * 14.0) / 4.0;
        let mut goto = None;
        ui.horizontal(|ui| {
            for (pg, title, big, sub, act) in &cards {
                let (r, resp) = ui.allocate_exact_size(Vec2::new(w, 250.0), egui::Sense::click());
                let pal = pg.palette();
                theme::gradient_rect(ui.painter(), r, alpha(pal.accent, 110), alpha(pal.accent2, 70), alpha(pal.top, 170), alpha(pal.bottom, 170));
                ui.painter().rect_stroke(r, 16.0, egui::Stroke::new(1.0_f32, alpha(Color32::WHITE, if resp.hovered() { 90 } else { 40 })));
                theme::illustration(ui.painter(), Pos2::new(r.center().x, r.top() + 78.0), 70.0, pal, pg.glyph(), self.t);
                ui.painter().text(Pos2::new(r.left() + 16.0, r.top() + 150.0), egui::Align2::LEFT_CENTER, *title, FontId::proportional(15.0), SUBTLE);
                ui.painter().text(Pos2::new(r.left() + 16.0, r.top() + 182.0), egui::Align2::LEFT_CENTER, big, FontId::proportional(26.0), if *act { TEXT } else { SUBTLE });
                ui.painter().text(Pos2::new(r.left() + 16.0, r.top() + 216.0), egui::Align2::LEFT_CENTER, short(sub, 22), FontId::proportional(12.5), SUBTLE);
                if resp.clicked() {
                    goto = Some(*pg);
                }
                if resp.hovered() {
                    ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
                }
                ui.add_space(14.0);
            }
        });
        ui.add_space(8.0);
        ui.label(RichText::new(t!("點一下卡片可查看詳細內容。按「執行」會清理垃圾檔案並隔離發現的威脅（都可以復原）。")).color(SUBTLE));
        if let Some(pg) = goto {
            match pg {
                Page::Cleanup => self.junk = self.smart.as_ref().map(|s| s.junk.clone()),
                Page::Protection => {
                    self.threats = self.smart_threats.clone();
                    self.scan_summary = Some((0, 0));
                    self.prot_tab = ProtTab::Scan;
                }
                Page::Performance => {
                    self.launch = self.smart.as_ref().map(|s| s.launch.clone());
                    self.perf_tab = PerfTab::Launch;
                }
                Page::Clutter => {
                    self.large = self.smart.as_ref().map(|s| s.large.clone());
                    self.clutter_tab = ClutterTab::Large;
                }
                _ => {}
            }
            self.page = pg;
        }
        if big_button(ui, bc, t!("執行"), p, self.t, None).clicked() {
            let mut junk = self.smart.take().map(|s| s.junk).unwrap_or_default();
            let (freed, errs) = clean::clean_groups(&mut junk);
            let mut moved = 0;
            if let Some(ts) = self.smart_threats.take() {
                let mut ql = self.quarantine.lock().unwrap();
                for t in ts.iter() {
                    if av::quarantine(t, &mut ql).is_ok() {
                        moved += 1;
                    }
                }
            }
            let mut msg = tf!("已清理 {} 的垃圾，隔離 {} 個威脅。", fmt_bytes(freed), moved);
            if !errs.is_empty() {
                msg.push_str(&tf!(" {} 個項目無法移除（可能正在使用中）。", errs.len()));
            }
            self.disk = clean::disk_usage();
            self.smart_done = Some(msg);
        }
    }

    // ------------------------------------------------------------ cleanup

    pub(super) fn page_cleanup(&mut self, ui: &mut egui::Ui) {
        let bc = self.bottom_center(ui);
        let p = self.page.palette();
        if let Some(j) = &self.junk_job {
            let st = j.status();
            self.progress_view(ui, t!("正在查找垃圾檔案…"), crate::i18n::tr(&st));
            big_button(ui, bc, t!("請稍候"), p, self.t, Some(0.0));
            return;
        }
        if let Some((freed, errs)) = self.junk_done.clone() {
            let mut d = tf!("共釋放 {} 空間。項目已移到廢紙簍，需要時可以還原。", fmt_bytes(freed));
            if !errs.is_empty() {
                d.push_str(&tf!("\n有 {} 個項目無法清理（可能正在使用中或需要權限）。", errs.len()));
            }
            self.progress_done(ui, t!("清理完畢"), &d);
            if big_button(ui, bc, t!("重新開始"), p, self.t, None).clicked() {
                self.junk_done = None;
            }
            return;
        }
        if let Some(groups) = &mut self.junk {
            let total: u64 = groups.iter().map(|g| g.size()).sum();
            let sel = clean::total_selected(groups);
            let hdr = if total == 0 { t!("您的 Mac 很乾淨！").to_string() } else { tf!("您的 Mac 上有 {} 的垃圾檔案。", fmt_bytes(total)) };
            let body_h = ui.available_height() - 150.0;
            ui.horizontal(|ui| {
                ui.label(RichText::new(hdr).size(24.0).strong());
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new(tf!("已選取 {}", fmt_bytes(sel))).color(SUBTLE));
                });
            });
            egui::ScrollArea::vertical().max_height(body_h).auto_shrink([false; 2]).show(ui, |ui| groups_ui(ui, groups, "junk"));
            if big_button(ui, bc, t!("清理"), p, self.t, None).clicked() && sel > 0 {
                let mut g = self.junk.take().unwrap_or_default();
                let (freed, errs) = clean::clean_groups(&mut g);
                self.disk = clean::disk_usage();
                self.junk_done = Some((freed, errs));
            }
            return;
        }
        self.intro(ui, t!("垃圾清理"), t!("移除系統垃圾、快取與不需要的檔案，釋放儲存空間。"), &[
            (t!("系統垃圾"), t!("快取、記錄檔與損壞的偏好設定")),
            (t!("Xcode 與 AI 雜亂檔案"), t!("開發與 AI 工具留下的大型暫存")),
            (t!("郵件附件"), t!("郵件下載的附件副本")),
            (t!("廢紙簍"), t!("清空所有廢紙簍")),
        ]);
        if big_button(ui, bc, t!("掃描"), p, self.t, None).clicked() {
            self.junk_job = Some(Job::spawn(clean::scan_junk));
        }
    }

    // ------------------------------------------------------------ performance

    pub(super) fn page_performance(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.selectable_label(self.perf_tab == PerfTab::Tasks, t!("維護任務")).clicked() {
                self.perf_tab = PerfTab::Tasks;
            }
            if ui.selectable_label(self.perf_tab == PerfTab::Launch, t!("登入與背景項目")).clicked() {
                self.perf_tab = PerfTab::Launch;
                if self.launch.is_none() {
                    self.launch = Some(clean::launch_items());
                }
            }
        });
        ui.add_space(6.0);
        let bc = self.bottom_center(ui);
        let p = self.page.palette();
        match self.perf_tab {
            PerfTab::Tasks => {
                if self.task_job.is_some() {
                    self.progress_view(ui, t!("正在執行效能維護任務…"), t!("macOS 可能會要求輸入管理員密碼"));
                    big_button(ui, bc, t!("請稍候"), p, self.t, Some(0.0));
                    return;
                }
                self.header(ui, t!("效能維護任務"), t!("每週為您推薦的一組維護任務"));
                let body_h = ui.available_height() - 150.0;
                egui::ScrollArea::vertical().max_height(body_h).auto_shrink([false; 2]).show(ui, |ui| {
                    self.memory_card(ui);
                    for m in &self.task_msgs {
                        ui.label(RichText::new(crate::i18n::tr(m)).color(if m.starts_with('✓') { GOOD } else { WARN }));
                    }
                    for (i, t) in clean::TASKS.iter().enumerate() {
                        card(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut self.task_sel[i], "");
                                ui.vertical(|ui| {
                                    ui.label(RichText::new(crate::i18n::tr(t.title)).strong());
                                    ui.label(RichText::new(crate::i18n::tr(t.desc)).size(12.0).color(SUBTLE));
                                });
                                if t.admin {
                                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| egui::Frame::none().fill(Color32::from_rgba_unmultiplied(0, 0, 0, 90)).rounding(10.0).inner_margin(egui::Margin::symmetric(8.0, 2.0)).show(ui, |ui| ui.label(RichText::new(t!("需要管理員密碼")).size(11.5).color(TEXT))));
                                }
                            });
                        });
                    }
                });
                if big_button(ui, bc, t!("執行"), p, self.t, None).clicked() && self.task_sel.iter().any(|s| *s) {
                    let sel = self.task_sel.clone();
                    self.task_job = Some(Job::spawn(move |_| clean::run_tasks(&sel)));
                }
            }
            PerfTab::Launch => {
                self.header(ui, t!("登入與背景項目"), t!("開機時自動執行的程式"));
                let mut refresh = false;
                ui.horizontal(|ui| {
                    if ui.button(t!("重新整理")).clicked() {
                        refresh = true;
                    }
                    if ui.button(t!("打開系統的「登入項目」設定")).clicked() {
                        util::open_url("x-apple.systempreferences:com.apple.LoginItems-Settings.extension");
                    }
                });
                if refresh {
                    self.launch = Some(clean::launch_items());
                }
                let body_h = ui.available_height() - 150.0;
                let Some(items) = &mut self.launch else { return };
                egui::ScrollArea::vertical().max_height(body_h).auto_shrink([false; 2]).show(ui, |ui| {
                    for it in items.iter_mut() {
                        card(ui, |ui| {
                            ui.horizontal(|ui| {
                                ui.checkbox(&mut it.selected, "");
                                if it.broken {
                                    pill(ui, t!("已損壞"), WARN);
                                }
                                ui.vertical(|ui| {
                                    ui.label(RichText::new(crate::i18n::tr(&it.label)).strong());
                                    ui.label(RichText::new(format!("{} · {}", if it.system { t!("系統背景項目") } else { t!("使用者啟動代理") }, short(&it.program, 70))).size(12.0).color(SUBTLE));
                                });
                                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                    if ui.small_button(t!("顯示")).clicked() {
                                        util::reveal(&it.path);
                                    }
                                });
                            });
                        });
                    }
                    if items.is_empty() {
                        ui.label(RichText::new(t!("沒有找到啟動項目。")).color(FAINT));
                    }
                });
                if big_button(ui, bc, t!("移除"), p, self.t, None).clicked() {
                    let msgs = clean::remove_launch_items(items);
                    self.launch = Some(clean::launch_items());
                    let m = msgs.iter().map(|m| crate::i18n::tr(m)).collect::<Vec<_>>().join(t!("；"));
                    self.say(ui.ctx(), if m.is_empty() { t!("請先勾選要移除的項目").to_string() } else { m });
                }
            }
        }
    }

    // ------------------------------------------------------------ applications

    pub(super) fn page_apps(&mut self, ui: &mut egui::Ui) {
        let bc = self.bottom_center(ui);
        let p = self.page.palette();
        if let Some(j) = &self.apps_job {
            let st = j.status();
            self.progress_view(ui, t!("正在查找應用程式…"), crate::i18n::tr(&st));
            big_button(ui, bc, t!("請稍候"), p, self.t, Some(0.0));
            return;
        }
        if self.apps.is_none() {
            self.intro(ui, t!("應用程式"), t!("完整解除安裝、檢查更新，並清除應用程式殘留檔案。"), &[
                (t!("解除安裝程式"), t!("連同支援檔案一起移除應用程式")),
                (t!("更新程式"), t!("找出有新版本的應用程式")),
                (t!("應用程式殘留"), t!("清除已刪除應用程式留下的檔案")),
                (t!("未使用的安裝檔"), t!("下載資料夾中的 DMG 與 PKG")),
            ]);
            if big_button(ui, bc, t!("掃描"), p, self.t, None).clicked() {
                self.apps_job = Some(Job::spawn(clean::list_apps));
                self.installers = Some(clean::unused_installers());
            }
            return;
        }
        let mut rescan = false;
        ui.horizontal(|ui| {
            for (t, n) in [(AppTab::Uninstaller, t!("解除安裝程式")), (AppTab::Updater, t!("更新程式")), (AppTab::Leftovers, t!("應用程式殘留")), (AppTab::Installers, t!("未使用的安裝檔"))] {
                if ui.selectable_label(self.app_tab == t, n).clicked() {
                    self.app_tab = t;
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button(t!("重新掃描")).clicked() {
                    rescan = true;
                }
            });
        });
        if rescan {
            self.apps = None;
            self.updates_checked = false;
            self.apps_job = Some(Job::spawn(clean::list_apps));
            self.installers = Some(clean::unused_installers());
            return;
        }
        ui.add_space(6.0);
        match self.app_tab {
            AppTab::Uninstaller => self.apps_uninstaller(ui),
            AppTab::Updater => self.apps_updater(ui),
            AppTab::Leftovers => {
                self.header(ui, t!("應用程式殘留"), t!("找不到對應應用程式的支援檔案"));
                ui.label(RichText::new(t!("這些檔案的名稱不屬於任何已安裝的應用程式。請確認後再勾選，移除的項目會放到廢紙簍。")).color(SUBTLE));
                let body_h = ui.available_height() - 150.0;
                let mut go = false;
                if let Some(items) = &mut self.leftovers {
                    egui::ScrollArea::vertical().max_height(body_h).auto_shrink([false; 2]).show(ui, |ui| items_ui(ui, items));
                    let sel: u64 = items.iter().filter(|i| i.selected).map(|i| i.size).sum();
                    go = big_button(ui, bc, t!("移除"), p, self.t, None).clicked() && sel > 0;
                }
                if go {
                    let mut g = one_group(self.leftovers.take().unwrap_or_default());
                    let (freed, _) = clean::clean_groups(&mut g);
                    self.leftovers = Some(g.pop().map(|g| g.items).unwrap_or_default());
                    self.say(ui.ctx(), tf!("已清除 {} 的應用程式殘留", fmt_bytes(freed)));
                }
            }
            AppTab::Installers => {
                self.header(ui, t!("未使用的安裝檔"), t!("下載資料夾中的 DMG 與 PKG"));
                let body_h = ui.available_height() - 150.0;
                let mut go = false;
                if let Some(items) = &mut self.installers {
                    egui::ScrollArea::vertical().max_height(body_h).auto_shrink([false; 2]).show(ui, |ui| items_ui(ui, items));
                    let sel: u64 = items.iter().filter(|i| i.selected).map(|i| i.size).sum();
                    go = big_button(ui, bc, t!("移除"), p, self.t, None).clicked() && sel > 0;
                }
                if go {
                    let mut g = one_group(self.installers.take().unwrap_or_default());
                    let (freed, _) = clean::clean_groups(&mut g);
                    self.installers = Some(g.pop().map(|g| g.items).unwrap_or_default());
                    self.say(ui.ctx(), tf!("已移除 {} 的安裝檔", fmt_bytes(freed)));
                }
            }
        }
    }

    fn apps_uninstaller(&mut self, ui: &mut egui::Ui) {
        let Some(apps) = &self.apps else { return };
        let total: u64 = apps.iter().map(|a| a.size).sum();
        ui.horizontal(|ui| {
            ui.label(RichText::new(tf!("{} 個應用程式 · {}", apps.len(), fmt_bytes(total))).size(20.0).strong());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add(egui::TextEdit::singleline(&mut self.app_filter).hint_text(t!("搜尋")).desired_width(200.0));
            });
        });
        let filter = self.app_filter.to_lowercase();
        let mut pick = None;
        let mut uninstall: Option<App> = None;
        let selected = self.app_selected;
        ui.columns(2, |cols| {
            egui::ScrollArea::vertical().id_salt("applist").auto_shrink([false; 2]).show(&mut cols[0], |ui| {
                for (i, a) in apps.iter().enumerate() {
                    if !filter.is_empty() && !a.name.to_lowercase().contains(&filter) {
                        continue;
                    }
                    let txt = format!("{}    {}", a.name, fmt_bytes(a.size));
                    if ui.selectable_label(selected == Some(i), txt).clicked() {
                        pick = Some(i);
                    }
                }
            });
            let ui = &mut cols[1];
            if let Some(a) = selected.and_then(|i| apps.get(i)) {
                card(ui, |ui| {
                    ui.label(RichText::new(&a.name).size(20.0).strong());
                    ui.label(RichText::new(tf!("版本 {} · {}", a.version, a.bundle_id)).color(SUBTLE));
                    let used = a.last_used_days.map(|d| tf!(" · {} 天前使用", d)).unwrap_or_default();
                    ui.label(RichText::new(tf!("大小 {}{}", fmt_bytes(a.size), used)).color(SUBTLE));
                    ui.add_space(6.0);
                    ui.label(RichText::new(t!("會一併移除的支援檔案：")).strong());
                    let left = clean::app_leftovers(a);
                    if left.is_empty() {
                        ui.label(RichText::new(t!("沒有找到支援檔案")).color(FAINT));
                    }
                    for l in &left {
                        ui.label(RichText::new(format!("{}  {}", short(&l.label, 60), fmt_bytes(l.size))).size(12.0).color(SUBTLE));
                    }
                    ui.add_space(8.0);
                    if ui.button(RichText::new(t!("解除安裝")).size(15.0)).clicked() {
                        uninstall = Some(a.clone());
                    }
                });
            } else {
                ui.label(RichText::new(t!("從左邊選一個應用程式以查看詳細資料。")).color(SUBTLE));
            }
        });
        if let Some(i) = pick {
            self.app_selected = Some(i);
        }
        if let Some(a) = uninstall {
            let msgs = clean::uninstall(&a);
            if msgs.iter().any(|m| m.starts_with('✓')) {
                if let Some(v) = &mut self.apps {
                    v.retain(|x| x.path != a.path);
                }
                self.app_selected = None;
            }
            self.say(ui.ctx(), msgs.iter().map(|m| crate::i18n::tr(m)).collect::<Vec<_>>().join(t!("；")));
        }
    }

    fn apps_updater(&mut self, ui: &mut egui::Ui) {
        let bc = self.bottom_center(ui);
        let p = self.page.palette();
        if let Some(j) = &self.update_job {
            let st = j.status();
            self.progress_view(ui, t!("正在檢查應用程式更新…"), crate::i18n::tr(&st));
            big_button(ui, bc, t!("請稍候"), p, self.t, Some(0.0));
            return;
        }
        self.header(ui, t!("更新程式"), t!("過時的應用程式可能有安全漏洞"));
        ui.horizontal(|ui| {
            if ui.button(t!("打開 macOS 軟體更新")).clicked() {
                util::open_url("x-apple.systempreferences:com.apple.Software-Update-Settings.extension");
            }
            if ui.button(t!("打開 App Store 更新")).clicked() {
                util::open_url("macappstore://showUpdatesPage");
            }
        });
        let Some(apps) = &self.apps else { return };
        if !self.updates_checked {
            let with_feed = apps.iter().filter(|a| a.feed.is_some()).count();
            ui.label(RichText::new(tf!("有 {} 個應用程式提供線上更新資訊，按「檢查」向它們的官方更新來源查詢最新版本。", with_feed)).color(SUBTLE));
            let list = apps.clone();
            if big_button(ui, bc, t!("檢查"), p, self.t, None).clicked() {
                self.update_job = Some(Job::spawn(move |s| {
                    let mut l = list;
                    clean::check_updates(&mut l, s);
                    l
                }));
            }
            return;
        }
        let outdated: Vec<&App> = apps.iter().filter(|a| a.latest.is_some()).collect();
        if outdated.is_empty() {
            ui.label(RichText::new(t!("一切都是最新的！")).size(18.0).color(GOOD));
        }
        let mut open: Option<PathBuf> = None;
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            for a in outdated {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new(&a.name).strong());
                            ui.label(RichText::new(tf!("目前 {} → 最新 {}", a.version, a.latest.clone().unwrap_or_default())).color(SUBTLE));
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.button(t!("打開以更新")).clicked() {
                                open = Some(a.path.clone());
                            }
                        });
                    });
                });
            }
        });
        if let Some(pth) = open {
            util::open_url(&pth.to_string_lossy());
        }
    }

    // ------------------------------------------------------------ clutter

    pub(super) fn page_clutter(&mut self, ui: &mut egui::Ui) {
        let bc = self.bottom_center(ui);
        let p = self.page.palette();
        if let Some(j) = &self.clutter_job {
            let st = j.status();
            self.progress_view(ui, t!("正在整理雜亂檔案…"), crate::i18n::tr(&st));
            big_button(ui, bc, t!("請稍候"), p, self.t, Some(0.0));
            return;
        }
        if self.large.is_none() {
            let big = tf!("{} 以上的檔案", fmt_bytes(clean::LARGE_FILE_BYTES));
            self.intro(ui, t!("整理雜亂"), t!("找出佔用大量空間的檔案與重複的副本。"), &[(t!("大型檔案"), &big), (t!("重複檔案"), t!("內容完全相同的副本")), (t!("安全移除"), t!("所有項目都先移到廢紙簍"))]);
            if big_button(ui, bc, t!("掃描"), p, self.t, None).clicked() {
                self.clutter_job = Some(Job::spawn(|s| (clean::large_files(s), clean::duplicates(s))));
            }
            return;
        }
        if self.dups.is_none() {
            self.dups = Some(Vec::new());
        }
        let mut rescan = false;
        ui.horizontal(|ui| {
            if ui.selectable_label(self.clutter_tab == ClutterTab::Large, t!("大型檔案")).clicked() {
                self.clutter_tab = ClutterTab::Large;
            }
            if ui.selectable_label(self.clutter_tab == ClutterTab::Duplicates, t!("重複檔案")).clicked() {
                self.clutter_tab = ClutterTab::Duplicates;
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button(t!("重新掃描")).clicked() {
                    rescan = true;
                }
            });
        });
        if rescan {
            self.clutter_job = Some(Job::spawn(|s| (clean::large_files(s), clean::duplicates(s))));
            return;
        }
        let body_h = ui.available_height() - 190.0;
        let mut go = false;
        match self.clutter_tab {
            ClutterTab::Large => {
                let (n, sel) = {
                    let items = self.large.as_ref().unwrap();
                    (items.len(), items.iter().filter(|i| i.selected).map(|i| i.size).sum::<u64>())
                };
                self.header_inline(ui, &tf!("{} 個大型檔案", n), &tf!("已選取 {}", fmt_bytes(sel)));
                let items = self.large.as_mut().unwrap();
                egui::ScrollArea::vertical().max_height(body_h).auto_shrink([false; 2]).show(ui, |ui| items_ui(ui, items));
                go = big_button(ui, bc, t!("移除"), p, self.t, None).clicked() && sel > 0;
            }
            ClutterTab::Duplicates => {
                let (n, sel) = {
                    let g = self.dups.as_ref().unwrap();
                    (g.len(), clean::total_selected(g))
                };
                self.header_inline(ui, &tf!("{} 組重複檔案", n), &tf!("已選取 {}", fmt_bytes(sel)));
                let groups = self.dups.as_mut().unwrap();
                egui::ScrollArea::vertical().max_height(body_h).auto_shrink([false; 2]).show(ui, |ui| {
                    if groups.is_empty() {
                        ui.label(RichText::new(t!("沒有找到重複的檔案。")).color(FAINT));
                    }
                    groups_ui(ui, groups, "dups")
                });
                go = big_button(ui, bc, t!("移除"), p, self.t, None).clicked() && sel > 0;
            }
        }
        if go {
            let freed = match self.clutter_tab {
                ClutterTab::Large => {
                    let mut g = one_group(self.large.take().unwrap_or_default());
                    let (f, _) = clean::clean_groups(&mut g);
                    self.large = Some(g.pop().map(|g| g.items).unwrap_or_default());
                    f
                }
                ClutterTab::Duplicates => {
                    let mut g = self.dups.take().unwrap_or_default();
                    let (f, _) = clean::clean_groups(&mut g);
                    g.retain(|g| g.items.len() > 1);
                    self.dups = Some(g);
                    f
                }
            };
            self.disk = clean::disk_usage();
            self.say(ui.ctx(), tf!("已移除 {}，項目在廢紙簍中", fmt_bytes(freed)));
        }
    }

    // ---------------------------------------------------------------- disk map

    pub(super) fn page_lens(&mut self, ui: &mut egui::Ui) {
        let bc = self.bottom_center(ui);
        let p = self.page.palette();
        let cur = self.lens_stack.last().cloned().unwrap_or_else(util::home);
        // ---- scanning: progress, time estimate, folders as they finish, stop
        if let Some(scan) = &self.lens_scan {
            let (frac, eta) = scan.eta();
            let (done, total, estimating, current, nodes) = {
                let g = scan.progress.lock().unwrap_or_else(|e| e.into_inner());
                (g.done_children, g.total_children, g.estimating, g.current.clone(), g.nodes.clone())
            };
            let checked = scan.entries.load(std::sync::atomic::Ordering::Relaxed);
            let elapsed = scan.started.elapsed().as_secs_f64();
            theme::eyebrow(ui, "DISK MAP · SCANNING");
            ui.label(RichText::new(tf!("正在建立 {} 的儲存空間地圖…", collapse(&cur))).size(20.0).strong());
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    let eta_txt = if estimating {
                        t!("正在估算時間…").to_string()
                    } else {
                        match eta {
                            Some(s) => tf!("預估剩餘 約 {}", clean::fmt_duration(s)),
                            None => t!("正在計算速度…").to_string(),
                        }
                    };
                    ui.label(RichText::new(eta_txt).size(17.0).color(theme::PRIMARY));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(RichText::new(format!("{:.0}%", frac * 100.0)).monospace().size(15.0));
                    });
                });
                let (r, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 6.0), egui::Sense::hover());
                ui.painter().rect_filled(r, 3.0, theme::SURFACE_HI);
                let mut f = r;
                f.set_width(r.width() * frac.max(0.01));
                ui.painter().rect_filled(f, 3.0, theme::PRIMARY_BTN);
                ui.label(
                    RichText::new(tf!("已完成 {} / {} 個項目 · 已檢查 {} 個檔案 · 已用 {}", done, total, fmt_count(checked), clean::fmt_duration(elapsed)))
                        .monospace()
                        .size(12.0)
                        .color(SUBTLE),
                );
                if !current.is_empty() {
                    ui.label(RichText::new(tf!("正在計算：{}", short(&current.join(t!("、")), 90))).size(12.0).color(FAINT));
                }
                ui.label(RichText::new(t!("預估時間依上次掃描結果或抽樣估計，會隨進度越來越準。")).size(11.5).color(FAINT));
            });
            let mut dummy_nav = None;
            let mut dummy_trash = None;
            let h = ui.available_height() - 110.0;
            egui::ScrollArea::vertical().max_height(h.max(80.0)).auto_shrink([false; 2]).show(ui, |ui| lens_list(ui, &nodes, false, &mut dummy_nav, &mut dummy_trash));
            if big_button(ui, bc, t!("停止"), p, self.t, Some(frac)).clicked() {
                scan.stop();
            }
            return;
        }
        let Some(nodes) = self.lens.clone() else {
            self.intro(ui, t!("空間地圖"), t!("以視覺化的方式查看哪些資料夾佔用了最多空間。"), &[(t!("資料夾大小一覽"), t!("依大小排列，一眼找出空間殺手")), (t!("逐層深入"), t!("點選資料夾進入下一層")), (t!("預估時間"), t!("掃描時顯示進度與預估剩餘時間，可隨時停止"))]);
            let (t, f) = self.disk;
            let r = ui.max_rect();
            ui.painter().text(Pos2::new(r.left() + 12.0, r.bottom() - 120.0), egui::Align2::LEFT_CENTER, tf!("啟動磁碟：已使用 {} / {}", fmt_bytes(t.saturating_sub(f)), fmt_bytes(t)), FontId::monospace(12.5), SUBTLE);
            if big_button(ui, bc, t!("掃描"), p, self.t, None).clicked() {
                self.lens_note = None;
                self.lens_scan = Some(clean::start_lens(cur));
            }
            return;
        };
        let mut nav: Option<PathBuf> = None;
        let mut up = false;
        let mut trash: Option<PathBuf> = None;
        let mut rescan = false;
        theme::eyebrow(ui, "DISK MAP · USER HOME SPACE");
        ui.horizontal(|ui| {
            if self.lens_stack.len() > 1 && ui.button(t!("← 上一層")).clicked() {
                up = true;
            }
            ui.label(RichText::new(collapse(&cur)).monospace().size(18.0).strong());
            let total: u64 = nodes.iter().map(|n| n.size).sum();
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button(t!("重新掃描")).clicked() {
                    rescan = true;
                }
                ui.label(RichText::new(fmt_bytes(total)).monospace().color(SUBTLE));
            });
        });
        if let Some(n) = &self.lens_note {
            ui.label(RichText::new(crate::i18n::tr(n)).size(12.5).color(WARN));
        }
        // treemap-style tiles of the biggest items
        let total: u64 = nodes.iter().map(|n| n.size).sum::<u64>().max(1);
        let (strip, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 150.0), egui::Sense::hover());
        let top: Vec<&clean::Node> = nodes.iter().take(6).collect();
        let top_sum: f32 = top.iter().map(|n| n.size as f32).sum::<f32>().max(1.0);
        let mut x = strip.left();
        let cols = [theme::PRIMARY, theme::PURPLE, theme::GOOD, theme::WARN, Color32::from_rgb(0x60, 0xa5, 0xfa), theme::BAD];
        for (i, n) in top.iter().enumerate() {
            let w = (strip.width() * n.size as f32 / top_sum).max(60.0).min(strip.right() - x);
            if w < 40.0 {
                break;
            }
            let r = Rect::from_min_size(Pos2::new(x, strip.top()), Vec2::new(w - 6.0, strip.height()));
            let resp = ui.interact(r, ui.id().with(("tile", i)), egui::Sense::click());
            ui.painter().rect_filled(r, 8.0, if resp.hovered() { theme::SURFACE_HI } else { theme::SURFACE });
            ui.painter().rect_stroke(r, 8.0, egui::Stroke::new(1.0_f32, alpha(cols[i % cols.len()], 120)));
            ui.painter().text(r.left_top() + Vec2::new(12.0, 16.0), egui::Align2::LEFT_CENTER, short(&n.name, ((w / 8.5) as usize).max(4)), FontId::monospace(12.5), TEXT);
            ui.painter().text(r.left_top() + Vec2::new(12.0, 36.0), egui::Align2::LEFT_CENTER, format!("{:.1}%", 100.0 * n.size as f32 / total as f32), FontId::monospace(11.0), cols[i % cols.len()]);
            ui.painter().text(r.left_bottom() + Vec2::new(12.0, -18.0), egui::Align2::LEFT_CENTER, fmt_bytes(n.size), FontId::monospace(15.0), TEXT);
            if resp.clicked() && n.is_dir {
                nav = Some(n.path.clone());
            }
            if resp.hovered() && n.is_dir {
                ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
            }
            x += w;
        }
        ui.add_space(6.0);
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| lens_list(ui, &nodes, true, &mut nav, &mut trash));
        if up {
            self.lens_stack.pop();
            if let Some(d) = self.lens_stack.last().cloned() {
                self.lens_note = None;
                self.lens_scan = Some(clean::start_lens(d));
            }
        }
        if rescan {
            self.lens_note = None;
            self.lens_scan = Some(clean::start_lens(cur.clone()));
        }
        if let Some(d) = nav {
            self.lens_stack.push(d.clone());
            self.lens_note = None;
            self.lens_scan = Some(clean::start_lens(d));
        }
        if let Some(t) = trash {
            let m = match util::move_to_trash(&t) {
                Ok(()) => tf!("已將 {} 移到廢紙簍", collapse(&t)),
                Err(e) => tf!("無法移除：{}", e),
            };
            if let Some(v) = &mut self.lens {
                v.retain(|n| n.path != t);
            }
            self.say(ui.ctx(), m);
        }
    }

    // ------------------------------------------------------------ cloud

    pub(super) fn page_cloud(&mut self, ui: &mut egui::Ui) {
        let bc = self.bottom_center(ui);
        let p = self.page.palette();
        if let Some(j) = &self.cloud_job {
            let st = j.status();
            self.progress_view(ui, t!("正在查看雲端資料夾…"), crate::i18n::tr(&st));
            big_button(ui, bc, t!("請稍候"), p, self.t, Some(0.0));
            return;
        }
        if self.cloud.is_none() {
            self.intro(ui, t!("雲端檔案"), t!("找出已下載到這台 Mac 的大型雲端檔案，釋放本機空間。"), &[
                (t!("iCloud 雲碟"), t!("移除本機副本，檔案仍保留在 iCloud")),
                (t!("Dropbox、Google 雲端硬碟、OneDrive"), t!("透過 macOS 的雲端資料夾管理")),
                (t!("不需登入"), t!("只處理這台 Mac 上的同步資料夾")),
            ]);
            if big_button(ui, bc, t!("掃描"), p, self.t, None).clicked() {
                self.cloud_job = Some(Job::spawn(clean::cloud_folders));
            }
            return;
        }
        let groups = self.cloud.as_mut().unwrap();
        let sel = clean::total_selected(groups);
        let body_h = ui.available_height() - 190.0;
        ui.horizontal(|ui| {
            ui.label(RichText::new(t!("雲端資料夾")).size(24.0).strong());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| ui.label(RichText::new(tf!("已選取 {}", fmt_bytes(sel))).color(SUBTLE)));
        });
        egui::ScrollArea::vertical().max_height(body_h).auto_shrink([false; 2]).show(ui, |ui| {
            if groups.is_empty() {
                ui.label(RichText::new(t!("沒有找到雲端同步資料夾。")).color(SUBTLE));
            }
            groups_ui(ui, groups, "cloud");
        });
        if big_button(ui, bc, t!("移除下載"), p, self.t, None).clicked() && sel > 0 {
            let items: Vec<Item> = groups.iter().flat_map(|g| g.items.iter().cloned()).collect();
            let msgs = clean::evict(&items);
            let ok = msgs.iter().filter(|m| m.starts_with('✓')).count();
            self.cloud_job = Some(Job::spawn(clean::cloud_folders));
            self.say(ui.ctx(), tf!("已移除 {} 個檔案的本機副本（雲端上仍保留）", ok));
        }
    }
}
