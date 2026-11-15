//! Protection module (malware scan, real-time monitor, quarantine, extensions, privacy,
//! permissions, safe list, settings) and the project vulnerability (CVE) check.

use super::{card, groups_ui, kind_color, pill, sev_color, short, MacApp, Page, ProtTab};
use crate::av::{self, MonitorEvent, QItem, RuleSet, ScanMode};
use crate::clean::{self, Job};
use crate::theme::{big_button, FAINT, GOOD, SUBTLE, WARN};
use crate::util::{self, collapse, fmt_bytes};
use crate::vuln::{self, Finding, Severity};
use egui::{Align, Color32, FontId, Layout, Pos2, Rect, RichText};
use std::path::PathBuf;
use std::sync::Arc;

impl MacApp {
    pub(super) fn page_protection(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            let qn = self.quarantine.lock().unwrap().len();
            for (tab, name) in [
                (ProtTab::Scan, "惡意軟體掃描".to_string()),
                (ProtTab::Realtime, "即時防護".to_string()),
                (ProtTab::Quarantine, format!("隔離區（{}）", qn)),
                (ProtTab::Sources, "病毒碼來源".to_string()),
                (ProtTab::Extensions, "瀏覽器擴充功能".to_string()),
                (ProtTab::Privacy, "隱私".to_string()),
                (ProtTab::Permissions, "應用程式權限".to_string()),
                (ProtTab::SafeList, "安全清單".to_string()),
                (ProtTab::Settings, "掃描設定".to_string()),
            ] {
                if ui.selectable_label(self.prot_tab == tab, RichText::new(name).size(13.5)).clicked() {
                    self.prot_tab = tab;
                    if tab == ProtTab::Extensions && self.exts.is_none() {
                        self.exts = Some(av::list_extensions(&self.rules));
                        self.profiles = av::managed_profiles();
                    }
                }
            }
        });
        ui.add_space(8.0);
        match self.prot_tab {
            ProtTab::Scan => self.prot_scan(ui),
            ProtTab::Realtime => self.prot_realtime(ui),
            ProtTab::Quarantine => self.prot_quarantine(ui),
            ProtTab::Extensions => self.prot_extensions(ui),
            ProtTab::Privacy => self.prot_privacy(ui),
            ProtTab::Permissions => self.prot_permissions(ui),
            ProtTab::SafeList => self.prot_safelist(ui),
            ProtTab::Settings => self.prot_settings(ui),
            ProtTab::Sources => self.prot_sources(ui),
        }
    }

    pub(super) fn start_scan(&mut self, custom: Option<Vec<PathBuf>>) {
        if self.scan.is_some() {
            return;
        }
        self.scan_custom = custom.is_some();
        self.threats = None;
        self.removed_summary = None;
        self.scan = Some(av::start_scan(self.opts.clone(), self.rules.clone(), self.safe.lock().unwrap().clone(), custom));
    }

    fn prot_scan(&mut self, ui: &mut egui::Ui) {
        let bc = self.bottom_center(ui);
        let p = self.page.palette();
        if let Some(h) = self.scan.clone() {
            let (scanned, cur, n) = {
                let pr = h.progress.lock().unwrap();
                (pr.scanned, pr.current.clone(), pr.threats.len())
            };
            let title = if n > 0 { format!("正在查找潛在威脅…（已發現 {} 個）", n) } else { "正在查找潛在威脅…".to_string() };
            self.progress_view(ui, &title, &format!("已檢查 {} 個檔案　{}", scanned, cur));
            if big_button(ui, bc, "停止", p, self.t, Some(0.0)).clicked() {
                h.stop();
            }
            return;
        }
        if let Some((n, msgs)) = self.removed_summary.clone() {
            let mut d = format!("{} 個項目已移入隔離區，可在「隔離區」中還原或永久刪除。", n);
            for m in msgs.iter().take(4) {
                d.push('\n');
                d.push_str(m);
            }
            self.progress_done(ui, "完成移除！", &d);
            if big_button(ui, bc, "重新開始", p, self.t, None).clicked() {
                self.removed_summary = None;
                self.threats = None;
            }
            return;
        }
        if self.threats.is_some() {
            self.prot_results(ui);
            return;
        }
        // intro
        let mode = self.opts.mode;
        self.intro(ui, "安全防護", "檢查您的 Mac 是否有惡意軟體、廣告軟體與可疑的自動啟動項目。", &[
            ("惡意軟體清除", "以病毒碼、已知路徑與特徵碼找出威脅"),
            ("啟動項目檢查", "揪出開機時偷偷執行的程式"),
            ("隔離與還原", "移除的項目先隔離，誤判可隨時還原"),
            ("即時防護", "監控下載、應用程式與啟動項目的變動"),
        ]);
        let r = ui.max_rect();
        let row = Rect::from_min_max(Pos2::new(r.left() + 10.0, r.bottom() - 160.0), Pos2::new(r.left() + r.width() * 0.6, r.bottom() - 124.0));
        let mut hint = false;
        #[allow(deprecated)]
        ui.allocate_ui_at_rect(row, |ui| {
            ui.horizontal(|ui| {
                for m in [ScanMode::Quick, ScanMode::Balanced, ScanMode::Deep] {
                    if ui.selectable_label(mode == m, m.title()).on_hover_text(m.purpose()).clicked() {
                        self.opts.mode = m;
                        self.save_settings();
                    }
                }
                if ui.button("檢查指定檔案…").on_hover_text("也可以直接把檔案或資料夾拖進視窗").clicked() {
                    hint = true;
                }
            });
        });
        if hint {
            self.say(ui.ctx(), "把要檢查的檔案或資料夾拖進這個視窗即可開始掃描。");
        }
        let mode = self.opts.mode;
        ui.painter().text(Pos2::new(r.left() + 12.0, r.bottom() - 110.0), egui::Align2::LEFT_CENTER, format!("速度：{}　深度：{}", mode.speed(), mode.depth()), FontId::proportional(12.5), SUBTLE);
        if let Some(last) = self.history.first() {
            ui.painter().text(Pos2::new(r.left() + 12.0, r.bottom() - 90.0), egui::Align2::LEFT_CENTER, format!("上次掃描：{}，檢查 {} 個檔案，發現 {} 個威脅", last.mode, last.scanned, last.threats), FontId::proportional(12.0), FAINT);
        }
        if big_button(ui, bc, "掃描", p, self.t, None).clicked() {
            self.start_scan(None);
        }
    }

    fn prot_results(&mut self, ui: &mut egui::Ui) {
        let bc = self.bottom_center(ui);
        let p = self.page.palette();
        let (scanned, secs) = self.scan_summary.unwrap_or((0, 0));
        let empty = self.threats.as_ref().map(|t| t.is_empty()).unwrap_or(true);
        if empty {
            self.progress_done(ui, "未發現潛在威脅", &format!("您的 Mac 是安全的。已檢查 {} 個檔案，用時 {} 秒。", scanned, secs));
            if big_button(ui, bc, "完成", p, self.t, None).clicked() {
                self.threats = None;
            }
            return;
        }
        let body_h = ui.available_height() - 160.0;
        let threats = self.threats.as_mut().unwrap();
        ui.horizontal(|ui| {
            ui.label(RichText::new(format!("發現 {} 個潛在威脅", threats.len())).size(24.0).strong());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(RichText::new(format!("已檢查 {} 個檔案 · {} 秒", scanned, secs)).color(SUBTLE));
            });
        });
        ui.label(RichText::new("盡早移除它們，以保護您的 Mac。移除的項目會先放進隔離區。").color(SUBTLE));
        let mut add_safe: Option<PathBuf> = None;
        egui::ScrollArea::vertical().max_height(body_h).auto_shrink([false; 2]).show(ui, |ui| {
            for t in threats.iter_mut() {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.checkbox(&mut t.selected, "");
                        pill(ui, t.kind.label(), kind_color(t.kind));
                        ui.vertical(|ui| {
                            ui.label(RichText::new(&t.name).size(15.0).strong());
                            ui.label(RichText::new(short(&collapse(&t.path), 80)).size(12.0).color(SUBTLE));
                            ui.label(RichText::new(format!("{} · {}", t.engine.label(), t.detail)).size(12.0).color(FAINT));
                            ui.label(RichText::new(format!("來源：{}", t.source.label())).size(12.0).color(Color32::from_rgb(170, 200, 255)));
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.small_button("加入安全清單").on_hover_text("以後的掃描不再檢查這個位置").clicked() {
                                add_safe = Some(t.path.clone());
                            }
                            if ui.small_button("顯示").clicked() {
                                util::reveal(&t.path);
                            }
                            ui.label(RichText::new(fmt_bytes(t.size)).color(SUBTLE));
                        });
                    });
                });
            }
        });
        if let Some(pth) = add_safe {
            threats.retain(|t| t.path != pth);
            let mut s = self.safe.lock().unwrap();
            s.push(pth);
            av::save_safe_list(&s);
        }
        let any = self.threats.as_ref().map(|t| t.iter().any(|t| t.selected)).unwrap_or(false);
        if big_button(ui, bc, "移除", p, self.t, None).clicked() && any {
            let ts = self.threats.take().unwrap_or_default();
            let mut ql = self.quarantine.lock().unwrap();
            let mut n = 0;
            let mut msgs = Vec::new();
            for t in ts.iter().filter(|t| t.selected) {
                match av::quarantine(t, &mut ql) {
                    Ok(()) => n += 1,
                    Err(e) => msgs.push(format!("無法隔離 {}：{}", t.name, e)),
                }
            }
            drop(ql);
            self.removed_summary = Some((n, msgs));
        }
    }

    fn prot_realtime(&mut self, ui: &mut egui::Ui) {
        let on = self.monitor.is_running();
        let mut toggle = false;
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(RichText::new("即時惡意軟體監控").size(18.0).strong());
                    ui.label(RichText::new("即使您沒有執行掃描，也會持續檢查新下載的檔案、新安裝的應用程式、新的啟動項目與瀏覽器擴充功能。").color(SUBTLE));
                });
            });
            ui.horizontal(|ui| {
                pill(ui, if on { "運作中" } else { "已關閉" }, if on { GOOD } else { WARN });
                if ui.button(if on { "關閉即時防護" } else { "開啟即時防護" }).clicked() {
                    toggle = true;
                }
                let mut aq = self.monitor.auto_quarantine.load(std::sync::atomic::Ordering::Relaxed);
                if ui.checkbox(&mut aq, "發現威脅時自動移入隔離區").changed() {
                    self.monitor.auto_quarantine.store(aq, std::sync::atomic::Ordering::Relaxed);
                }
            });
            ui.label(RichText::new(format!("每 {} 秒檢查一次 · 目前已檢查 {} 個變動的檔案", av::MONITOR_INTERVAL_SECS, *self.monitor.checks.lock().unwrap())).size(12.0).color(FAINT));
        });
        if toggle {
            if on {
                self.monitor.stop();
                let _ = std::fs::write(util::data_dir().join("monitor.txt"), "off");
            } else {
                self.monitor.start(self.rules.clone(), self.safe.clone(), self.quarantine.clone());
                let _ = std::fs::write(util::data_dir().join("monitor.txt"), "on");
            }
        }
        ui.label(RichText::new("監控的位置").strong());
        for (p, _) in av::watched_folders() {
            ui.label(RichText::new(format!("•  {}", collapse(&p))).size(12.5).color(SUBTLE));
        }
        ui.add_space(8.0);
        ui.label(RichText::new("防護記錄").strong());
        let events: Vec<MonitorEvent> = self.monitor.events.lock().unwrap().iter().rev().cloned().collect();
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            if events.is_empty() {
                ui.label(RichText::new("目前沒有事件。").color(FAINT));
            }
            for e in events {
                ui.horizontal(|ui| {
                    ui.label(RichText::new(util::clock(e.when)).monospace().size(12.0).color(FAINT));
                    let col = if e.threat.is_some() { super::BAD } else { SUBTLE };
                    ui.label(RichText::new(e.text).size(13.0).color(col));
                });
            }
        });
    }

    fn prot_quarantine(&mut self, ui: &mut egui::Ui) {
        self.header(ui, "隔離區", "隔離的檔案無法執行，可以還原或永久刪除");
        let items: Vec<QItem> = self.quarantine.lock().unwrap().clone();
        if items.is_empty() {
            ui.add_space(40.0);
            ui.vertical_centered(|ui| ui.label(RichText::new("隔離區是空的。").size(16.0).color(SUBTLE)));
            return;
        }
        let mut restore: Option<u64> = None;
        let mut delete: Option<u64> = None;
        let mut delete_all = false;
        ui.horizontal(|ui| {
            if ui.button("全部永久刪除").clicked() {
                delete_all = true;
            }
            if ui.button("打開隔離區資料夾").clicked() {
                util::open_url(&av::quarantine_dir().to_string_lossy());
            }
        });
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            for q in items.iter().rev() {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        pill(ui, q.kind.label(), kind_color(q.kind));
                        ui.vertical(|ui| {
                            ui.label(RichText::new(&q.name).strong());
                            ui.label(RichText::new(format!("原位置：{}", short(&collapse(&q.original), 70))).size(12.0).color(SUBTLE));
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.small_button("永久刪除").clicked() {
                                delete = Some(q.id);
                            }
                            if ui.small_button("還原").clicked() {
                                restore = Some(q.id);
                            }
                            ui.label(RichText::new(fmt_bytes(q.size)).color(SUBTLE));
                        });
                    });
                });
            }
        });
        let mut msg = None;
        {
            let mut ql = self.quarantine.lock().unwrap();
            if let Some(id) = restore {
                if let Some(i) = ql.iter().position(|q| q.id == id) {
                    match av::restore(&ql[i]) {
                        Ok(()) => {
                            msg = Some(format!("已還原 {}", collapse(&ql[i].original)));
                            ql.remove(i);
                        }
                        Err(e) => msg = Some(format!("無法還原：{}", e)),
                    }
                }
            }
            if let Some(id) = delete {
                if let Some(i) = ql.iter().position(|q| q.id == id) {
                    let _ = av::delete_quarantined(&ql[i]);
                    ql.remove(i);
                    msg = Some("已永久刪除".into());
                }
            }
            if delete_all {
                for q in ql.iter() {
                    let _ = av::delete_quarantined(q);
                }
                ql.clear();
                msg = Some("隔離區已清空".into());
            }
            if restore.is_some() || delete.is_some() || delete_all {
                av::save_quarantine(&ql);
            }
        }
        if let Some(m) = msg {
            self.say(ui.ctx(), m);
        }
    }

    fn prot_extensions(&mut self, ui: &mut egui::Ui) {
        self.header(ui, "瀏覽器擴充功能", "Chrome、Brave、Edge 與 Chromium");
        ui.label(RichText::new("擴充功能若能讀取所有網站並攔截網路請求，就可能竊取資料或插入廣告。請移除不認得的項目。").color(SUBTLE));
        if !self.profiles.is_empty() {
            ui.label(RichText::new(format!("這台 Mac 受描述檔管理：{}（若不是公司或學校安裝，請到「系統設定 > 一般 > 裝置管理」檢查）", self.profiles.join("、"))).color(WARN));
        }
        if ui.button("重新整理").clicked() {
            self.exts = Some(av::list_extensions(&self.rules));
            self.profiles = av::managed_profiles();
        }
        let mut remove: Option<PathBuf> = None;
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            let Some(exts) = &self.exts else { return };
            if exts.is_empty() {
                ui.label(RichText::new("沒有找到 Chromium 系瀏覽器的擴充功能。").color(SUBTLE));
            }
            for e in exts {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        let (txt, col) = match (&e.blocked, e.risk) {
                            (Some(_), _) => ("已知惡意", super::BAD),
                            (None, 2) => ("高權限", WARN),
                            (None, 1) => ("中等權限", Color32::from_rgb(230, 210, 140)),
                            _ => ("低權限", GOOD),
                        };
                        pill(ui, txt, col);
                        ui.vertical(|ui| {
                            ui.label(RichText::new(&e.name).strong());
                            ui.label(RichText::new(format!("{} · {}", e.browser, e.id)).size(11.5).color(FAINT));
                            if !e.permissions.is_empty() {
                                ui.label(RichText::new(short(&e.permissions.join(", "), 110)).size(11.5).color(SUBTLE));
                            }
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.small_button("移除").on_hover_text("移到廢紙簍；請先結束瀏覽器").clicked() {
                                remove = Some(e.path.clone());
                            }
                        });
                    });
                });
            }
        });
        if let Some(pth) = remove {
            let m = match util::move_to_trash(&pth) {
                Ok(()) => "擴充功能已移到廢紙簍，重新開啟瀏覽器後生效。".to_string(),
                Err(e) => format!("無法移除：{}", e),
            };
            self.exts = Some(av::list_extensions(&self.rules));
            self.say(ui.ctx(), m);
        }
    }

    fn prot_privacy(&mut self, ui: &mut egui::Ui) {
        self.header(ui, "隱私", "清除瀏覽記錄與使用痕跡");
        if let Some(j) = &self.privacy_job {
            ui.label(j.status());
            ui.spinner();
            return;
        }
        if self.privacy.is_none() {
            ui.label(RichText::new("找出瀏覽器的歷史記錄、Cookie、自動填寫資料，以及「最近使用的項目」與已儲存的 Wi-Fi 網路。").color(SUBTLE));
            ui.add_space(10.0);
            if ui.button(RichText::new("掃描隱私痕跡").size(15.0)).clicked() {
                self.privacy_job = Some(Job::spawn(clean::scan_privacy));
                let (dev, nets) = clean::wifi_networks();
                self.wifi = Some((dev, nets.into_iter().map(|n| (n, false)).collect()));
            }
            return;
        }
        let sel = clean::total_selected(self.privacy.as_ref().unwrap());
        let mut do_remove = false;
        let mut rescan = false;
        ui.horizontal(|ui| {
            if ui.button(format!("移除選取的項目（{}）", fmt_bytes(sel))).clicked() {
                do_remove = true;
            }
            if ui.button("重新掃描").clicked() {
                rescan = true;
            }
        });
        let mut wifi_remove = None;
        let groups = self.privacy.as_mut().unwrap();
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            groups_ui(ui, groups, "privacy");
            if let Some((dev, nets)) = &mut self.wifi {
                card(ui, |ui| {
                    ui.label(RichText::new("Wi-Fi 網路").strong());
                    ui.label(RichText::new("Mac 會自動連線到以前用過的網路，包括開放的公共熱點。可以移除不再使用的網路。").size(12.0).color(SUBTLE));
                    for (n, s) in nets.iter_mut() {
                        ui.checkbox(s, n.as_str());
                    }
                    if nets.iter().any(|(_, s)| *s) && ui.button("移除選取的網路（需要管理員密碼）").clicked() {
                        wifi_remove = Some((dev.clone(), nets.iter().filter(|(_, s)| *s).map(|(n, _)| n.clone()).collect::<Vec<_>>()));
                    }
                });
            }
        });
        if rescan {
            self.privacy = None;
            self.privacy_job = Some(Job::spawn(clean::scan_privacy));
        }
        if do_remove {
            let mut g = self.privacy.take().unwrap_or_default();
            let (freed, errs) = clean::clean_groups(&mut g);
            self.privacy = Some(g);
            let extra = if errs.is_empty() { String::new() } else { format!("，{} 個項目無法移除（請先結束瀏覽器或授予完整磁碟取用權限）", errs.len()) };
            self.say(ui.ctx(), format!("已移除 {} 的隱私項目{}", fmt_bytes(freed), extra));
        }
        if let Some((dev, names)) = wifi_remove {
            let m = match clean::remove_wifi(&dev, &names) {
                Ok(()) => "已移除選取的 Wi-Fi 網路".to_string(),
                Err(e) => format!("未移除：{}", e),
            };
            let (dev, nets) = clean::wifi_networks();
            self.wifi = Some((dev, nets.into_iter().map(|n| (n, false)).collect()));
            self.say(ui.ctx(), m);
        }
    }

    fn prot_permissions(&mut self, ui: &mut egui::Ui) {
        self.header(ui, "應用程式權限", "掌控哪些應用程式能使用敏感功能");
        ui.label(RichText::new("在目前的 macOS 中，這些權限由系統統一管理。點「檢查」會開啟對應的「隱私權與安全性」設定頁，您可以在那裡撤銷權限。").color(SUBTLE));
        ui.add_space(6.0);
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            for (title, desc, anchor) in clean::PERMISSIONS {
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.vertical(|ui| {
                            ui.label(RichText::new(*title).strong());
                            ui.label(RichText::new(*desc).size(12.0).color(SUBTLE));
                        });
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            if ui.button("檢查").clicked() {
                                clean::open_privacy_pane(anchor);
                            }
                        });
                    });
                });
            }
        });
    }

    fn prot_safelist(&mut self, ui: &mut egui::Ui) {
        self.header(ui, "安全清單", "這些位置不會被掃描");
        ui.label(RichText::new("加入您信任的檔案或資料夾，避免誤判。也可以在掃描結果中按「加入安全清單」。").color(SUBTLE));
        let mut add = None;
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.safe_input).hint_text("~/Projects/my-tool").desired_width(360.0));
            if ui.button("加入").clicked() && !self.safe_input.trim().is_empty() {
                add = Some(util::expand(self.safe_input.trim()));
            }
        });
        if add.is_some() {
            self.safe_input.clear();
        }
        let mut s = self.safe.lock().unwrap();
        if let Some(a) = add {
            s.push(a);
            av::save_safe_list(&s);
        }
        let mut remove = None;
        for (i, p) in s.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(collapse(p));
                if ui.small_button("移除").clicked() {
                    remove = Some(i);
                }
            });
        }
        if let Some(i) = remove {
            s.remove(i);
            av::save_safe_list(&s);
        }
        if s.is_empty() {
            ui.label(RichText::new("安全清單是空的。").color(FAINT));
        }
    }

    fn prot_settings(&mut self, ui: &mut egui::Ui) {
        self.header(ui, "掃描設定", "");
        let mut changed = false;
        let mut reload = false;
        let mut msg = None;
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            card(ui, |ui| {
                ui.label(RichText::new("掃描模式").strong());
                for m in [ScanMode::Quick, ScanMode::Balanced, ScanMode::Deep] {
                    ui.horizontal(|ui| {
                        changed |= ui.radio_value(&mut self.opts.mode, m, m.title()).changed();
                        ui.label(RichText::new(format!("速度：{}　{}", m.speed(), m.purpose())).size(12.0).color(SUBTLE));
                    });
                }
            });
            card(ui, |ui| {
                ui.label(RichText::new("掃描選項").strong());
                changed |= ui.checkbox(&mut self.opts.archives, "掃描壓縮檔（ZIP）").changed();
                changed |= ui.checkbox(&mut self.opts.dmg, "掃描 DMG 磁碟映像檔").changed();
                changed |= ui.checkbox(&mut self.opts.usb, "掃描 USB 外接磁碟").changed();
                changed |= ui.checkbox(&mut self.opts.exclude_icloud, "排除已下載的 iCloud 檔案（通常是安全的，可節省時間）").changed();
            });
            card(ui, |ui| {
                ui.label(RichText::new("病毒碼").strong());
                ui.label(RichText::new(format!("{} · 共 {} 條規則", self.rules.version, self.rules.count)).color(SUBTLE));
                ui.label(RichText::new("可在 signatures.txt 加入病毒碼：每行「SHA-256 大小 名稱」、「path 規則 名稱」或「ext 擴充功能ID 名稱」。").size(12.0).color(FAINT));
                ui.horizontal(|ui| {
                    if ui.button("重新載入病毒碼").clicked() {
                        reload = true;
                    }
                    if ui.button("打開病毒碼檔案").clicked() {
                        let f = av::signatures_file();
                        if !f.exists() {
                            let _ = std::fs::write(&f, "# 每行一條：<sha256> <大小> <名稱> | path <規則> <名稱> | ext <擴充功能ID> <名稱>\n");
                        }
                        let _ = std::process::Command::new("open").arg("-t").arg(&f).spawn();
                    }
                    if ui.button("建立防毒測試檔").on_hover_text("在「下載項目」放一個無害的標準測試檔 (EICAR)，用來確認掃描有效").clicked() {
                        msg = Some(match av::write_test_file() {
                            Ok(p) => format!("已建立 {}，執行掃描或等即時防護偵測。", collapse(&p)),
                            Err(e) => format!("無法建立：{}", e),
                        });
                    }
                });
            });
            card(ui, |ui| {
                ui.label(RichText::new("掃描記錄").strong());
                if self.history.is_empty() {
                    ui.label(RichText::new("還沒有掃描記錄。").color(FAINT));
                }
                for h in self.history.iter().take(12) {
                    ui.label(RichText::new(format!("{}  {}：檢查 {} 個檔案，發現 {} 個威脅，{} 秒", util::clock(h.when), h.mode, h.scanned, h.threats, h.seconds)).size(12.5).color(SUBTLE));
                }
            });
        });
        if changed {
            self.save_settings();
        }
        if reload {
            self.rules_job = Some(Job::spawn(|_| RuleSet::load()));
            self.say(ui.ctx(), "正在重新載入所有病毒碼來源…");
        }
        if let Some(m) = msg {
            self.say(ui.ctx(), m);
        }
    }

    // ------------------------------------------------------------ vulnerability (CVE)

    pub(super) fn start_vuln(&mut self) {
        let root = util::expand(self.vuln_path.trim());
        if !root.is_dir() {
            self.vuln_error = Some("找不到這個資料夾".into());
            return;
        }
        self.vuln_findings = None;
        self.vuln_error = None;
        self.vuln_root = root.clone();
        self.vuln = Some(vuln::start_check(root));
    }

    pub(super) fn page_vuln(&mut self, ui: &mut egui::Ui) {
        let bc = self.bottom_center(ui);
        let p = self.page.palette();
        if let Some(h) = self.vuln.clone() {
            let (stage, frac, pk) = {
                let pr = h.progress.lock().unwrap();
                (pr.stage.clone(), pr.fraction, pr.packages)
            };
            let extra = if pk > 0 { format!("　共 {} 個套件", pk) } else { String::new() };
            self.progress_view(ui, "正在檢查專案的已知漏洞…", &format!("{}{}", stage, extra));
            if big_button(ui, bc, "停止", p, self.t, Some(frac)).clicked() {
                h.cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            return;
        }
        if self.vuln_findings.is_some() {
            self.vuln_results(ui);
            return;
        }
        self.intro(ui, "專案漏洞檢查", "找出專案中尚未更新、含有已知 CVE 漏洞的套件。", &[
            ("讀取相依清單", "npm、Python、Rust、Go、Ruby、PHP、Java、.NET"),
            ("比對 CVE 資料", "向公開漏洞資料庫 OSV.dev 查詢每個套件版本"),
            ("嚴重程度與修正版本", "列出 CVE 編號、風險等級與建議升級的版本"),
            ("匯出報告", "一鍵複製更新指令或存成文字報告"),
        ]);
        let r = ui.max_rect();
        let row = Rect::from_min_max(Pos2::new(r.left() + 10.0, r.bottom() - 168.0), Pos2::new(r.left() + r.width() * 0.62, r.bottom() - 104.0));
        let mut go = false;
        #[allow(deprecated)]
        ui.allocate_ui_at_rect(row, |ui| {
            ui.horizontal(|ui| {
                ui.label("專案資料夾：");
                let resp = ui.add(egui::TextEdit::singleline(&mut self.vuln_path).desired_width(300.0));
                if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    go = true;
                }
            });
            ui.horizontal(|ui| {
                for d in ["Projects", "Developer", "Documents", "Desktop"] {
                    let pth = util::home().join(d);
                    if pth.exists() && ui.small_button(format!("~/{}", d)).clicked() {
                        self.vuln_path = collapse(&pth);
                    }
                }
                ui.label(RichText::new("或把資料夾拖進視窗").size(12.0).color(FAINT));
            });
        });
        let note = self.vuln_error.clone().unwrap_or_else(|| "只會把套件名稱與版本（不含程式碼）送到 OSV.dev 查詢。".into());
        ui.painter().text(Pos2::new(r.left() + 12.0, r.bottom() - 92.0), egui::Align2::LEFT_CENTER, note, FontId::proportional(12.0), if self.vuln_error.is_some() { WARN } else { FAINT });
        if big_button(ui, bc, "檢查", p, self.t, None).clicked() || go {
            self.start_vuln();
        }
    }

    fn vuln_results(&mut self, ui: &mut egui::Ui) {
        use crate::theme::{OUTLINE, PRIMARY, PRIMARY_BTN, SURFACE_HI, TEXT};
        let root = self.vuln_root.clone();
        let findings = self.vuln_findings.clone().unwrap_or_default();
        let mut copy: Option<String> = None;
        let mut export = false;
        let mut again = false;
        let mut rescan = false;
        let filter_id = egui::Id::new("vuln_high_only");
        let mut high_only = ui.data(|d| d.get_temp::<bool>(filter_id).unwrap_or(false));
        // header (design: "LIVE CVE DATABASE · OSV.dev API Linked")
        ui.horizontal(|ui| {
            ui.label(RichText::new("● LIVE CVE DATABASE").monospace().size(11.0).color(PRIMARY));
            ui.label(RichText::new("· OSV.dev API").monospace().size(11.0).color(SUBTLE));
        });
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new("專案漏洞檢查（CVE Scanner）").size(22.0).strong());
                ui.label(RichText::new("掃描專案的相依套件，向 OSV.dev 公開資料庫比對 CVE 弱點與修正版本。").size(12.5).color(SUBTLE));
            });
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let b = egui::Button::new(RichText::new("重新掃描專案").color(Color32::WHITE)).fill(PRIMARY_BTN).stroke(egui::Stroke::NONE).rounding(6.0).min_size(egui::vec2(110.0, 32.0));
                if ui.add(b).clicked() {
                    rescan = true;
                }
                if ui.add(egui::Button::new("檢查其他資料夾").min_size(egui::vec2(0.0, 32.0))).clicked() {
                    again = true;
                }
            });
        });
        ui.add_space(4.0);
        // repository row
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("REPOSITORY").monospace().size(10.5).color(FAINT));
                ui.label(RichText::new(collapse(&root)).monospace().size(13.0).color(PRIMARY));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(RichText::new(format!("{} 個相依清單", self.vuln_manifests.len())).monospace().size(11.5).color(SUBTLE));
                });
            });
        });
        // stats strip
        let n_of = |s: Severity| findings.iter().filter(|f| f.worst() == s).count();
        card(ui, |ui| {
            ui.columns(5, |c| {
                let cell = |ui: &mut egui::Ui, k: &str, v: String, sub: &str, col: Color32| {
                    ui.label(RichText::new(k).monospace().size(10.5).color(col));
                    ui.label(RichText::new(v).font(egui::FontId::monospace(20.0)).color(col));
                    ui.label(RichText::new(sub).size(11.5).color(SUBTLE));
                };
                cell(&mut c[0], "已檢測套件", format!("{}", self.vuln_packages), &format!("{} 個清單解析完成", self.vuln_manifests.len()), TEXT);
                cell(&mut c[1], "CRITICAL（嚴重）", n_of(Severity::Critical).to_string(), "須立即處理", sev_color(Severity::Critical));
                cell(&mut c[2], "HIGH（高危）", n_of(Severity::High).to_string(), "儘快更新", sev_color(Severity::High));
                cell(&mut c[3], "MEDIUM（中度）", n_of(Severity::Medium).to_string(), "可套用官方修補", sev_color(Severity::Medium));
                cell(&mut c[4], "LOW / 未評級", (n_of(Severity::Low) + n_of(Severity::Unknown)).to_string(), "風險較低", SUBTLE);
            });
        });
        // table
        let shown: Vec<&Finding> = findings.iter().filter(|f| !high_only || f.worst() >= Severity::High).collect();
        egui::Frame::none().fill(crate::theme::SURFACE).stroke(egui::Stroke::new(1.0_f32, OUTLINE)).rounding(10.0).inner_margin(egui::Margin::symmetric(16.0, 12.0)).show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal(|ui| {
                ui.label(RichText::new("弱點詳細清單").strong());
                ui.label(RichText::new(format!("/ {} 個待處理項目", findings.len())).color(sev_color(Severity::High)));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if ui.selectable_label(high_only, format!("僅高危（{}）", n_of(Severity::Critical) + n_of(Severity::High))).clicked() {
                        high_only = true;
                    }
                    if ui.selectable_label(!high_only, format!("全部（{}）", findings.len())).clicked() {
                        high_only = false;
                    }
                    ui.label(RichText::new("FILTER:").monospace().size(10.5).color(FAINT));
                });
            });
            ui.separator();
            let body_h = (ui.available_height() - 60.0).max(160.0);
            egui::ScrollArea::vertical().max_height(body_h).auto_shrink([false, true]).show(ui, |ui| {
                if shown.is_empty() {
                    ui.add_space(8.0);
                    ui.label(RichText::new("根據公開的 CVE 資料，這些套件版本目前沒有已知的安全漏洞。").color(GOOD));
                }
                egui::Grid::new("vuln_grid").num_columns(6).spacing(egui::vec2(22.0, 12.0)).min_col_width(60.0).show(ui, |ui| {
                    ui.style_mut().wrap_mode = Some(egui::TextWrapMode::Extend);
                    if !shown.is_empty() {
                        for h in ["套件名稱 (PACKAGE)", "當前版本", "嚴重程度", "CVE 編號", "建議升級版本", "快速修復指令 (QUICK FIX)"] {
                            ui.label(RichText::new(h).monospace().size(10.5).color(FAINT));
                        }
                        ui.end_row();
                    }
                    for f in &shown {
                        ui.horizontal(|ui| {
                            let eco = match f.package.ecosystem { "crates.io" => "cargo", "PyPI" => "pypi", e => e };
                            egui::Frame::none().fill(SURFACE_HI).rounding(4.0).inner_margin(egui::Margin::symmetric(5.0, 1.0)).show(ui, |ui| {
                                ui.label(RichText::new(eco.to_lowercase()).monospace().size(10.5).color(SUBTLE));
                            });
                            ui.label(RichText::new(short(&f.package.name, 26)).monospace().strong());
                        });
                        ui.label(RichText::new(&f.package.version).monospace().color(SUBTLE));
                        ui.vertical(|ui| pill(ui, &format!("● {}", f.worst().label()), sev_color(f.worst())));
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            for v in f.vulns.iter().take(1) {
                                let (id, url) = match v.cves.first() {
                                    Some(c) => (c.clone(), format!("https://www.cve.org/CVERecord?id={}", c)),
                                    None => (v.id.clone(), format!("https://osv.dev/vulnerability/{}", v.id)),
                                };
                                ui.hyperlink_to(RichText::new(format!("{} ↗", id)).monospace().size(12.0).color(PRIMARY), url).on_hover_text(&v.summary);
                            }
                            if f.vulns.len() > 1 {
                                ui.label(RichText::new(format!("另有 {} 個漏洞", f.vulns.len() - 1)).size(11.0).color(FAINT)).on_hover_text(f.vulns.iter().skip(1).take(12).map(|v| v.cves.first().cloned().unwrap_or_else(|| v.id.clone())).collect::<Vec<_>>().join("\n"));
                            }
                        });
                        ui.vertical(|ui| {
                            ui.spacing_mut().item_spacing.y = 2.0;
                            match &f.upgrade_to {
                                Some(u) => {
                                    ui.label(RichText::new(format!(">= {}", u)).monospace().color(GOOD));
                                    ui.label(RichText::new(format!("Fixed in {}", u)).monospace().size(11.0).color(FAINT));
                                }
                                None => {
                                    ui.label(RichText::new("尚無修正版本").size(12.5).color(WARN));
                                }
                            }
                        });
                        let hint = vuln::update_hint(f);
                        let b = egui::Button::new(RichText::new(format!("$ {}", short(&hint, 34))).monospace().size(11.5)).fill(crate::theme::SIDEBAR_BG);
                        if ui.add(b).on_hover_text(format!("複製：{}", hint)).clicked() {
                            copy = Some(hint);
                        }
                        ui.end_row();
                    }
                });
                if !self.vuln_manifests.is_empty() {
                    ui.add_space(10.0);
                    egui::CollapsingHeader::new(RichText::new("已讀取的相依清單").size(12.5)).id_salt("vuln_manifests").show(ui, |ui| {
                        for (path, kind, n) in &self.vuln_manifests {
                            ui.label(RichText::new(format!("{}（{}，{} 個套件）", path, kind, n)).monospace().size(11.5).color(SUBTLE));
                        }
                    });
                }
            });
        });
        // footer
        ui.horizontal(|ui| {
            crate::theme::icon(ui.painter(), ui.cursor().min + egui::vec2(8.0, 9.0), 14.0, crate::theme::Glyph::Shield, GOOD);
            ui.add_space(18.0);
            ui.label(RichText::new("本機隱私保護：").strong().size(12.5));
            ui.label(RichText::new("只向 OSV.dev 查詢套件名稱與版本，不傳送專案程式碼。").size(12.5).color(SUBTLE));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if !findings.is_empty() && ui.button("匯出檢查報告到桌面").clicked() {
                    export = true;
                }
            });
        });
        ui.data_mut(|d| d.insert_temp(filter_id, high_only));
        if let Some(c) = copy {
            ui.ctx().copy_text(c);
            self.say(ui.ctx(), "已複製更新指令");
        }
        if export {
            let text = vuln::report_text(&root, &findings);
            let out = util::home().join("Desktop").join("專案漏洞報告.txt");
            let m = match std::fs::write(&out, text) {
                Ok(()) => format!("已儲存 {}", collapse(&out)),
                Err(e) => format!("無法儲存：{}", e),
            };
            self.say(ui.ctx(), m);
        }
        if again {
            self.vuln_findings = None;
        }
        if rescan {
            self.vuln_path = collapse(&root);
            self.start_vuln();
        }
        let _ = Page::Vulnerability;
    }
}
