//! "Mac 狀態": the live health dashboard (figures after Mole's `mo status`), and the memory diagnosis used on the
//! Performance page.

use super::{card, pill, short, MacApp, Page, PerfTab};
use crate::status::{self, Snapshot};
use crate::theme::{self, alpha, BAD, FAINT, GOOD, OUTLINE, PRIMARY, PURPLE, SUBTLE, SURFACE_HI, TEXT, WARN};
use crate::util::fmt_bytes;
use egui::{Align, Color32, FontId, Layout, Pos2, Rect, RichText, Stroke, Vec2};
use std::cell::RefCell;

thread_local! {
    /// Recent CPU % and download/upload rates for the small graphs (UI thread only).
    static HIST: RefCell<(f64, Vec<f32>, Vec<f32>)> = RefCell::new((0.0, Vec::new(), Vec::new()));
}

fn level_color(pct: f32, warn: f32, bad: f32) -> Color32 {
    if pct >= bad {
        BAD
    } else if pct >= warn {
        WARN
    } else {
        GOOD
    }
}

/// Thin bar with coloured segments (fractions of the whole).
fn seg_bar(ui: &mut egui::Ui, segs: &[(f32, Color32)]) {
    let (r, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 6.0), egui::Sense::hover());
    ui.painter().rect_filled(r, 3.0, SURFACE_HI);
    let mut x = r.left();
    for (f, c) in segs {
        let w = r.width() * f.clamp(0.0, 1.0);
        if w > 0.5 {
            ui.painter().rect_filled(Rect::from_min_size(Pos2::new(x, r.top()), Vec2::new((w - 2.0).max(1.0), r.height())), 3.0, *c);
        }
        x += w;
    }
}

/// Label above a mono value (the design's small stat blocks).
fn stat(ui: &mut egui::Ui, label: &str, value: &str, col: Color32) {
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 2.0;
        ui.label(RichText::new(label).monospace().size(10.5).color(FAINT));
        ui.label(RichText::new(value).monospace().size(13.0).color(col));
    });
}

fn big_number(ui: &mut egui::Ui, value: &str, unit: &str, col: Color32) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = 6.0;
        ui.label(RichText::new(value).font(FontId::monospace(40.0)).color(col));
        ui.label(RichText::new(unit).size(17.0).color(SUBTLE));
    });
}

fn sparkline(ui: &mut egui::Ui, data: &[f32], h: f32, col: Color32) {
    let (r, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), h), egui::Sense::hover());
    if data.len() < 2 {
        ui.painter().line_segment([r.left_center(), r.right_center()], Stroke::new(1.0_f32, OUTLINE));
        return;
    }
    let max = data.iter().cloned().fold(1e-6f32, f32::max);
    let n = data.len();
    let pts: Vec<Pos2> = data.iter().enumerate().map(|(i, v)| Pos2::new(r.left() + r.width() * i as f32 / (n - 1) as f32, r.bottom() - r.height() * (v / max).clamp(0.0, 1.0) * 0.9)).collect();
    ui.painter().add(egui::Shape::line(pts, Stroke::new(1.5_f32, col)));
}

/// Column bars for CPU history (the design's core grid).
fn bars(ui: &mut egui::Ui, data: &[f32], h: f32) {
    let (r, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), h), egui::Sense::hover());
    let n = 18usize;
    let w = r.width() / n as f32;
    let start = data.len().saturating_sub(n);
    for i in 0..n {
        let cell = Rect::from_min_size(Pos2::new(r.left() + i as f32 * w + 2.0, r.top()), Vec2::new(w - 4.0, h));
        ui.painter().rect_filled(cell, 3.0, SURFACE_HI);
        if let Some(v) = data.get(start + i) {
            let fh = (h * v / 100.0).clamp(2.0, h);
            let fill = Rect::from_min_max(Pos2::new(cell.left(), cell.bottom() - fh), cell.max);
            ui.painter().rect_filled(fill, 3.0, if *v > 85.0 { BAD } else if *v > 50.0 { WARN } else { Color32::from_rgb(0x4f, 0x86, 0xf7) });
        }
    }
}

fn panel(ui: &mut egui::Ui, eyebrow: &str, right: Option<(&str, Color32)>, add: impl FnOnce(&mut egui::Ui)) {
    card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(RichText::new(eyebrow).monospace().size(10.5).color(SUBTLE).extra_letter_spacing(1.2));
            if let Some((t, c)) = right {
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| ui.label(RichText::new(t).monospace().size(11.5).color(c)));
            }
        });
        ui.add_space(4.0);
        add(ui);
    });
}

impl MacApp {
    pub(super) fn page_status(&mut self, ui: &mut egui::Ui) {
        let s = self.sampler.get();
        let mut goto: Option<(Page, Option<PerfTab>)> = None;
        if !s.ready {
            self.progress_view(ui, "正在讀取系統狀態…", "第一次讀取需要幾秒鐘");
            return;
        }
        let now = ui.input(|i| i.time);
        let (cpu_hist, net_hist) = HIST.with(|h| {
            let mut g = h.borrow_mut();
            let (t, cpu, net) = &mut *g;
            if now - *t >= status::SAMPLE_SECS as f64 {
                *t = now;
                cpu.push(s.cpu_pct);
                net.push((s.net_down + s.net_up) as f32);
                for v in [cpu, net] {
                    if v.len() > 60 {
                        v.remove(0);
                    }
                }
            }
            (g.1.clone(), g.2.clone())
        });
        let hcol = match s.health {
            85.. => PRIMARY,
            65..=84 => GOOD,
            45..=64 => WARN,
            _ => BAD,
        };
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            // ---- score
            ui.horizontal(|ui| {
                ui.label(RichText::new("CORE TELEMETRY REPORT").monospace().size(11.0).color(SUBTLE).extra_letter_spacing(1.5));
                let (msg, c) = if s.issues.is_empty() { ("● 系統各項指標均處於良好狀態", GOOD) } else { ("● 有需要留意的項目", WARN) };
                ui.label(RichText::new(msg).size(12.0).color(c));
            });
            ui.columns(2, |c| {
                let ui = &mut c[0];
                ui.horizontal(|ui| {
                    ui.label(RichText::new(s.health.to_string()).font(FontId::proportional(72.0)).color(TEXT));
                    ui.label(RichText::new("/100").font(FontId::proportional(34.0)).color(FAINT));
                });
                ui.horizontal(|ui| {
                    ui.label(RichText::new("健康狀態：").size(18.0));
                    ui.label(RichText::new(s.health_label()).size(18.0).color(hcol));
                });
                let days = s.uptime_secs / 86400;
                ui.label(RichText::new(format!("{} · {} 核心 · 已開機 {} 天 · 分數計算參考 Mole", s.model, s.cores, days)).size(12.0).color(SUBTLE));
                if !s.issues.is_empty() {
                    ui.horizontal_wrapped(|ui| {
                        for i in &s.issues {
                            pill(ui, i, WARN);
                        }
                    });
                }
                let ui = &mut c[1];
                ui.add_space(26.0);
                card(ui, |ui| {
                    ui.horizontal(|ui| {
                        stat(ui, "可用空間", &fmt_bytes(s.disk_free), PRIMARY);
                        ui.add_space(24.0);
                        stat(ui, "記憶體壓力", &format!("{:.0}%", (100.0 - s.mem_free_pct).clamp(0.0, 100.0)), PRIMARY);
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                            let btn = egui::Button::new(RichText::new("立即深度清理").color(Color32::WHITE)).fill(theme::PRIMARY_BTN).stroke(Stroke::NONE).rounding(6.0).min_size(Vec2::new(120.0, 34.0));
                            if ui.add(btn).clicked() {
                                goto = Some((Page::QuickCheck, None));
                            }
                        });
                    });
                });
            });
            ui.add_space(6.0);
            // ---- summary strip
            let on = self.monitor.is_running();
            let qn = self.quarantine.lock().unwrap().len();
            let xp = self.rules.xprotect.as_ref().map(|x| format!("v{}", x.version)).unwrap_or_else(|| "載入中".into());
            card(ui, |ui| {
                ui.columns(3, |c| {
                    let row = |ui: &mut egui::Ui, k: &str, v: String, col: Color32| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(k).size(12.5).color(SUBTLE));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| ui.label(RichText::new(v).monospace().color(col)));
                        });
                    };
                    row(&mut c[0], "即時防護", if on { "已啟用".into() } else { "已關閉".into() }, if on { GOOD } else { WARN });
                    row(&mut c[1], "隔離區", format!("{} 個項目", qn), if qn > 0 { WARN } else { GOOD });
                    row(&mut c[2], "XProtect 引擎", xp, PRIMARY);
                });
            });
            // ---- storage & memory
            ui.columns(2, |c| {
                let du = s.disk_used_pct();
                panel(&mut c[0], "STORAGE ALLOCATION · APFS", Some(("釋放空間 →", PRIMARY)), |ui| {
                    ui.label(RichText::new("Macintosh HD 磁碟空間").size(15.0).strong());
                    big_number(ui, &format!("{:.1}", s.disk_free as f64 / 1e9), "GB 可用", TEXT);
                    seg_bar(ui, &[(du / 100.0, level_color(du, 80.0, 93.0)), (1.0 - du / 100.0, Color32::TRANSPARENT)]);
                    ui.horizontal(|ui| {
                        stat(ui, "總量", &fmt_bytes(s.disk_total), TEXT);
                        ui.add_space(18.0);
                        stat(ui, "已使用", &format!("{:.1}%", du), level_color(du, 80.0, 93.0));
                        ui.add_space(18.0);
                        stat(ui, "可用", &fmt_bytes(s.disk_free), TEXT);
                    });
                    ui.horizontal(|ui| {
                        if ui.small_button("前往垃圾清理").clicked() {
                            goto = Some((Page::Cleanup, None));
                        }
                    });
                });
                let pressure = (100.0 - s.mem_free_pct).clamp(0.0, 100.0);
                let pcol = match s.pressure.as_str() {
                    "critical" => BAD,
                    "warn" => WARN,
                    _ => GOOD,
                };
                panel(&mut c[1], &format!("UNIFIED MEMORY · {} TOTAL", fmt_bytes(s.mem_total)), Some(("活動監視器 →", PRIMARY)), |ui| {
                    ui.label(RichText::new("記憶體負載與分佈").size(15.0).strong());
                    big_number(ui, &format!("{:.1}", s.mem_used as f64 / 1e9), "GB 已使用", TEXT);
                    ui.label(RichText::new(format!("● 壓力{} {:.0}%", s.pressure_label(), pressure)).monospace().size(12.0).color(pcol));
                    let used = s.mem_used_pct / 100.0;
                    let swap = if s.mem_total > 0 { s.swap_used as f32 / s.mem_total as f32 } else { 0.0 };
                    seg_bar(ui, &[(used, GOOD), (swap, PURPLE)]);
                    ui.horizontal(|ui| {
                        stat(ui, "已使用", &format!("{:.0}%", s.mem_used_pct), TEXT);
                        ui.add_space(18.0);
                        stat(ui, "可用", &format!("{:.0}%", s.mem_free_pct), TEXT);
                        ui.add_space(18.0);
                        stat(ui, "SWAP 虛擬記憶體", &fmt_bytes(s.swap_used), TEXT);
                    });
                    ui.horizontal(|ui| {
                        if ui.small_button("記憶體診斷").clicked() {
                            goto = Some((Page::Performance, Some(PerfTab::Tasks)));
                        }
                    });
                });
            });
            // ---- cpu, network, security
            ui.columns(3, |c| {
                panel(&mut c[0], &format!("CPU · {} CORES", s.cores), Some((&format!("{:.0}% 負載", s.cpu_pct), level_color(s.cpu_pct, 50.0, 85.0))), |ui| {
                    ui.label(RichText::new(format!("平均負載：{:.2} · {:.2} · {:.2}", s.load[0], s.load[1], s.load[2])).monospace().size(12.0).color(SUBTLE));
                    ui.add_space(4.0);
                    bars(ui, &cpu_hist, 46.0);
                    let top = s.top_mem.first().map(|p| p.name.clone()).unwrap_or_default();
                    ui.label(RichText::new(format!("最佔記憶體：{}", short(&top, 26))).monospace().size(11.0).color(FAINT));
                });
                panel(&mut c[1], "NETWORK THROUGHPUT", Some((&s.net_iface, SUBTLE)), |ui| {
                    ui.horizontal(|ui| {
                        stat(ui, "上傳 (TX)", &status::fmt_rate(s.net_up), TEXT);
                        ui.add_space(20.0);
                        stat(ui, "下載 (RX)", &status::fmt_rate(s.net_down), TEXT);
                    });
                    ui.add_space(4.0);
                    sparkline(ui, &net_hist, 44.0, GOOD);
                });
                panel(&mut c[2], "SECURITY SUBSYSTEM", Some((if on { "已保護" } else { "未保護" }, if on { GOOD } else { WARN })), |ui| {
                    let last = self.monitor.last.lock().unwrap().clone();
                    for (k, v) in [
                        ("XProtect 引擎", self.rules.xprotect.as_ref().map(|x| format!("{} 條規則", x.loaded)).unwrap_or_else(|| "載入中".into())),
                        ("隔離區威脅項目", format!("{} 個項目", qn)),
                        ("即時監控", if on { "運作中".into() } else { "已關閉".into() }),
                        ("最後檢查", if last.is_empty() { "—".into() } else { short(&last, 18) }),
                    ] {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(k).size(12.5).color(SUBTLE));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| ui.label(RichText::new(v).size(12.5)));
                        });
                    }
                    ui.horizontal(|ui| {
                        if ui.small_button("開啟安全防護").clicked() {
                            goto = Some((Page::Protection, None));
                        }
                    });
                });
            });
            // ---- devices
            panel(ui, "ATTACHED HARDWARE & DEVICES", None, |ui| {
                ui.label(RichText::new("已連接周邊裝置").size(15.0).strong());
                let mut rows: Vec<(String, String)> = s.devices.iter().map(|d| {
                    let (k, n) = d.split_once('：').unwrap_or(("裝置", d.as_str()));
                    (n.to_string(), k.to_string())
                }).collect();
                if let Some((pct, st)) = &s.battery {
                    rows.push(("內建電池".into(), format!("電量 {}% · {}", pct, st)));
                }
                if rows.is_empty() {
                    ui.label(RichText::new("沒有連接裝置").color(SUBTLE));
                }
                for (i, (name, kind)) in rows.iter().enumerate() {
                    if i > 0 {
                        ui.separator();
                    }
                    ui.horizontal(|ui| {
                        let g = if kind.contains("藍牙") { theme::Glyph::Pulse } else { theme::Glyph::Folders };
                        let (r, _) = ui.allocate_exact_size(Vec2::splat(20.0), egui::Sense::hover());
                        theme::icon(ui.painter(), r.center(), 16.0, g, PRIMARY);
                        ui.label(RichText::new(name).size(13.5));
                        ui.with_layout(Layout::right_to_left(Align::Center), |ui| ui.label(RichText::new(kind).monospace().size(11.5).color(SUBTLE)));
                    });
                }
            });
            self.memory_card(ui);
        });
        if let Some((pg, tab)) = goto {
            self.page = pg;
            if let Some(t) = tab {
                self.perf_tab = t;
            }
        }
    }

    /// Memory diagnosis (Mole lib/optimize/diagnostics.sh): pressure, swap and the biggest
    /// memory users, with a button to quit an app. Replaces the old "free up RAM" task.
    pub(super) fn memory_card(&mut self, ui: &mut egui::Ui) {
        let s: Snapshot = self.sampler.get();
        let mut quit: Option<String> = None;
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("MEMORY DIAGNOSIS").monospace().size(10.5).color(SUBTLE).extra_letter_spacing(1.2));
                ui.label(RichText::new("記憶體診斷").size(15.0).strong());
                if s.ready {
                    let (t, c) = if s.memory_tight() { ("記憶體吃緊", WARN) } else { ("狀況良好", GOOD) };
                    pill(ui, t, c);
                }
            });
            if !s.ready {
                ui.label(RichText::new("正在讀取…").color(SUBTLE));
                return;
            }
            ui.label(RichText::new(format!(
                "壓力 {} · 可用 {:.0}% · SWAP {} / {}（{:.0}%）",
                s.pressure_label(),
                s.mem_free_pct,
                fmt_bytes(s.swap_used),
                fmt_bytes(s.swap_total),
                s.swap_pct()
            )).monospace().size(12.5));
            ui.label(RichText::new("macOS 會把閒置的記憶體拿來當快取，強制「釋放記憶體」只會清掉這些快取、幾秒後又被填滿，所以不提供這個按鈕。有效的做法是結束佔用最多記憶體的應用程式：").size(12.0).color(SUBTLE));
            if s.vm_rss > 2_000_000_000 {
                ui.label(RichText::new(format!("虛擬機器（例如 Docker Desktop、UTM）佔用了 {}，即使閒置也會保留，不用時結束它就能釋放。", fmt_bytes(s.vm_rss))).size(12.5).color(WARN));
            }
            ui.add_space(2.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("程式名稱").monospace().size(10.5).color(FAINT));
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.add_space(58.0);
                    ui.label(RichText::new("實體 RAM 佔用").monospace().size(10.5).color(FAINT));
                });
            });
            for p in s.top_mem.iter().take(6) {
                ui.separator();
                ui.horizontal(|ui| {
                    let frac = if s.mem_total > 0 { p.rss as f32 / s.mem_total as f32 } else { 0.0 };
                    ui.label(RichText::new(short(&p.name, 34)).size(13.5));
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        match &p.app_name {
                            Some(app) => {
                                let b = egui::Button::new(RichText::new("結束").size(12.0).color(BAD)).fill(alpha(BAD, 20)).stroke(Stroke::new(1.0_f32, alpha(BAD, 120)));
                                if ui.add(b).on_hover_text("請這個應用程式正常結束（會提示儲存文件）").clicked() {
                                    quit = Some(app.clone());
                                }
                            }
                            None => {
                                ui.add_space(46.0);
                            }
                        }
                        let (r, _) = ui.allocate_exact_size(Vec2::new(60.0, 4.0), egui::Sense::hover());
                        ui.painter().rect_filled(r, 2.0, SURFACE_HI);
                        let mut f = r;
                        f.set_width(r.width() * (frac * 4.0).clamp(0.02, 1.0));
                        ui.painter().rect_filled(f, 2.0, if frac > 0.1 { BAD } else { PRIMARY });
                        ui.label(RichText::new(format!("{}（{:.1}%）", fmt_bytes(p.rss), frac * 100.0)).monospace().size(12.5));
                    });
                });
            }
        });
        if let Some(a) = quit {
            let m = match status::quit_app(&a) {
                Ok(()) => format!("已要求 {} 結束", a),
                Err(e) => format!("無法結束 {}：{}", a, e),
            };
            self.say(ui.ctx(), m);
        }
    }
}
