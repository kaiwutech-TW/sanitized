//! "Docker 清理" page. Shows Docker's real disk use and lets the person clean it through the
//! docker command only, in three risk levels (see docker.rs for the rules).

use super::{card, pill, short, MacApp};
use crate::clean::Job;
use crate::docker::{self, Step};
use crate::theme::{self, BAD, FAINT, GOOD, PRIMARY, PRIMARY_BTN, SUBTLE, TEXT, WARN};
use crate::util::fmt_bytes;
use egui::{Align, Color32, Layout, RichText, Vec2};

pub struct Pending {
    pub steps: Vec<Step>,
    pub level: u8,
    /// Level 3: the exact name the person must type.
    pub confirm_name: Option<String>,
}

fn level_head(ui: &mut egui::Ui, n: u8, title: &str, sub: &str, col: Color32) {
    ui.horizontal(|ui| {
        pill(ui, &format!("第 {} 級", n), col);
        ui.label(RichText::new(title).size(15.0).strong());
    });
    ui.label(RichText::new(sub).size(12.0).color(SUBTLE));
}

impl MacApp {
    pub(super) fn page_docker(&mut self, ui: &mut egui::Ui) {
        if self.docker.is_none() && self.docker_job.is_none() {
            self.docker_job = Some(Job::spawn(|_| docker::load()));
        }
        theme::eyebrow(ui, "DOCKER · DISK USAGE");
        let mut reload = false;
        ui.horizontal(|ui| {
            ui.label(RichText::new("Docker 磁碟清理").size(22.0).strong());
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                if ui.button("重新讀取").clicked() {
                    reload = true;
                }
            });
        });
        ui.label(RichText::new("只透過 docker 指令清理，讓 Docker 自己處理；不會直接刪除或搬動 Docker 的檔案。").size(12.5).color(SUBTLE));
        if reload && self.docker_job.is_none() && self.docker_run.is_none() {
            self.docker_job = Some(Job::spawn(|_| docker::load()));
        }
        if self.docker_job.is_some() {
            ui.add_space(30.0);
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("正在讀取 Docker 的磁碟用量…");
            });
            return;
        }
        if let Some(_) = &self.docker_run {
            ui.add_space(30.0);
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("正在執行，請稍候（一次只處理一類，失敗會立即停止）…");
            });
            return;
        }
        let Some(info) = self.docker.as_mut() else { return };
        let mut pending: Option<Pending> = None;

        egui::ScrollArea::vertical().id_salt("docker_scroll").auto_shrink([false; 2]).show(ui, |ui| {
            // ---- real usage
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(RichText::new("DOCKER 實際佔用").monospace().size(10.5).color(FAINT));
                        let used = info.raw_used.unwrap_or(info.data_used);
                        ui.label(RichText::new(fmt_bytes(used)).font(egui::FontId::monospace(30.0)).color(TEXT));
                        ui.label(RichText::new(format!("Docker.raw 是稀疏檔：名義大小等於整顆硬碟，但只佔用實際寫入的部分。整個 Data 資料夾實際佔用 {}。", fmt_bytes(info.data_used))).size(12.0).color(SUBTLE));
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if info.running {
                            pill(ui, &format!("Docker {} 執行中", info.version), GOOD);
                        } else {
                            pill(ui, "Docker 未開啟", WARN);
                        }
                    });
                });
            });
            if let Some(r) = &self.docker_report {
                card(ui, |ui| {
                    ui.label(RichText::new("上次清理結果").size(15.0).strong());
                    for l in &r.lines {
                        ui.label(RichText::new(l).color(if l.starts_with("完成") { GOOD } else { BAD }));
                    }
                    match (r.before, r.after) {
                        (Some(b), Some(a)) if a < b => {
                            ui.label(RichText::new(format!("實際釋放 {}（Docker.raw 實際佔用 {} → {}）", fmt_bytes(b - a), fmt_bytes(b), fmt_bytes(a))).color(GOOD));
                        }
                        (Some(_), Some(a)) => {
                            ui.label(RichText::new(format!("Docker.raw 目前還沒有縮小（Docker 可能稍後才會歸還空間），現在實際佔用 {}。", fmt_bytes(a))).color(WARN));
                        }
                        _ => {}
                    }
                    if !r.stopped_unexpectedly.is_empty() {
                        ui.label(RichText::new(format!("注意：這些原本在執行的容器現在沒有在執行：{}", r.stopped_unexpectedly.join("、"))).color(BAD));
                    }
                });
            }
            if !info.running {
                card(ui, |ui| {
                    ui.label(RichText::new("開啟 Docker 才能看明細").size(15.0).strong());
                    ui.label(RichText::new("Docker 沒開時，這裡只顯示實際佔用大小，不提供任何刪除動作。").color(SUBTLE));
                    if ui.button("開啟 Docker").clicked() {
                        let _ = std::process::Command::new("open").args(["-a", "Docker"]).spawn();
                    }
                });
                return;
            }
            // ---- summary
            card(ui, |ui| {
                ui.label(RichText::new("DOCKER 回報的用量（docker system df）").monospace().size(10.5).color(FAINT));
                egui::Grid::new("dk_sum").num_columns(4).spacing(Vec2::new(28.0, 6.0)).show(ui, |ui| {
                    for h in ["類別", "數量（使用中）", "大小", "可釋放"] {
                        ui.label(RichText::new(h).size(11.5).color(FAINT));
                    }
                    ui.end_row();
                    for s in &info.summary {
                        let k = match s.kind.as_str() {
                            "Images" => "映像檔",
                            "Containers" => "容器",
                            "Local Volumes" => "Volume",
                            "Build Cache" => "建置快取",
                            o => o,
                        };
                        ui.label(k);
                        ui.label(RichText::new(format!("{}（{}）", s.total, s.active)).monospace());
                        ui.label(RichText::new(fmt_bytes(s.size)).monospace());
                        ui.label(RichText::new(fmt_bytes(s.reclaimable)).monospace().color(PRIMARY));
                        ui.end_row();
                    }
                });
                ui.label(RichText::new("映像檔之間會共用層，把每個映像檔的大小相加會高估；可釋放空間以 Docker 回報的數字為準。").size(11.5).color(FAINT));
            });

            // ---- level 1
            card(ui, |ui| {
                level_head(ui, 1, "可以一鍵清", "刪了會自動重建，只是下次建置或下載比較慢。", GOOD);
                let d = info.dangling();
                ui.label(format!("建置快取：{}（Docker 回報可釋放 {}）", fmt_bytes(info.build_cache), fmt_bytes(info.build_cache_reclaimable)));
                ui.label(format!("沒有名稱、沒有容器使用的殘留映像檔（dangling）：{} 個，約 {}", d.len(), fmt_bytes(d.iter().map(|i| i.unique).sum())));
                let steps = docker::level1_steps(info);
                ui.add_enabled_ui(!steps.is_empty(), |ui| {
                    if ui.add(egui::Button::new(RichText::new("一鍵清理第 1 級").color(Color32::WHITE)).fill(PRIMARY_BTN)).clicked() {
                        pending = Some(Pending { steps, level: 1, confirm_name: None });
                    }
                });
            });

            // ---- level 2
            card(ui, |ui| {
                level_head(ui, 2, "勾選後才清", "沒有任何容器使用的映像檔（停止中的容器也算使用）、已停止的容器、沒在用的網路。", WARN);
                ui.label(RichText::new("已停止的容器：容器內沒有掛 volume 的資料會一起消失。本機建置的映像檔刪了要重新建置，不是重新下載。").size(12.0).color(WARN));
                let projects: std::collections::BTreeSet<String> = info.unused_images().iter().map(|i| i.project.clone()).chain(info.stopped().iter().map(|c| c.project.clone())).chain(info.networks.iter().map(|n| n.project.clone())).collect();
                if projects.is_empty() {
                    ui.label(RichText::new("沒有可以清理的項目。").color(SUBTLE));
                }
                for proj in projects {
                    ui.add_space(4.0);
                    ui.label(RichText::new(format!("專案：{}", proj)).strong().color(PRIMARY));
                    for img in info.images.iter_mut().filter(|i| i.project == proj && !i.dangling && i.used_by.is_empty()) {
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut img.selected, "");
                            ui.label(RichText::new("映像檔").size(11.0).color(FAINT));
                            ui.label(RichText::new(short(&img.name, 48)).monospace());
                            if img.local_build {
                                pill(ui, "本機建置", WARN);
                            }
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(RichText::new(format!("獨占 {} · 建立 {}", fmt_bytes(img.unique), img.created)).monospace().size(11.5).color(SUBTLE));
                            });
                        });
                    }
                    for c in info.containers.iter_mut().filter(|c| c.project == proj && !c.running) {
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut c.selected, "");
                            ui.label(RichText::new("容器").size(11.0).color(FAINT));
                            ui.label(RichText::new(&c.name).monospace());
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                let vols = if c.volumes.is_empty() { "沒有掛 volume".to_string() } else { format!("掛載 {}", c.volumes.join("、")) };
                                ui.label(RichText::new(format!("{} · {} · {}", c.status, vols, fmt_bytes(c.size))).size(11.5).color(SUBTLE));
                            });
                        });
                    }
                    for n in info.networks.iter_mut().filter(|n| n.project == proj) {
                        ui.horizontal(|ui| {
                            ui.checkbox(&mut n.selected, "");
                            ui.label(RichText::new("網路").size(11.0).color(FAINT));
                            ui.label(RichText::new(&n.name).monospace());
                        });
                    }
                }
                let steps = docker::level2_steps(info);
                ui.add_enabled_ui(!steps.is_empty(), |ui| {
                    if ui.button(format!("刪除勾選的項目（{} 類）…", steps.len())).clicked() {
                        pending = Some(Pending { steps, level: 2, confirm_name: None });
                    }
                });
            });

            // ---- level 3
            card(ui, |ui| {
                level_head(ui, 3, "預設不清，只能逐項確認", "Volume 裡通常是資料庫，刪了救不回來；正在執行的容器可能還在用。是否還在用請您自己判斷，這裡只提供證據。", BAD);
                let vols = docker::by_project(&info.volumes, |v| v.project.as_str());
                for (proj, list) in vols {
                    ui.add_space(4.0);
                    ui.label(RichText::new(format!("專案：{}", proj)).strong().color(PRIMARY));
                    for v in list {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("Volume").size(11.0).color(FAINT));
                            ui.label(RichText::new(&v.name).monospace());
                            ui.label(RichText::new("刪除後無法復原").size(11.5).color(BAD));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.button("刪除…").clicked() {
                                    pending = Some(Pending { steps: vec![docker::volume_step(&v.name)], level: 3, confirm_name: Some(v.name.clone()) });
                                }
                                let users = if v.used_by.is_empty() { "沒有容器掛載".to_string() } else { v.used_by.iter().map(|(n, r)| format!("{}（{}）", n, if *r { "執行中" } else { "已停止" })).collect::<Vec<_>>().join("、") };
                                ui.label(RichText::new(format!("{} · 建立 {} · 掛載：{}", fmt_bytes(v.size), v.created, short(&users, 60))).size(11.5).color(SUBTLE));
                            });
                        });
                    }
                }
                ui.label(RichText::new("最後寫入時間：Docker Desktop 的 volume 在虛擬機內，無法從外面讀取，因此不顯示。").size(11.5).color(FAINT));
                let running: Vec<docker::Container> = info.running().into_iter().cloned().collect();
                let groups = docker::by_project(&running, |c| c.project.as_str());
                for (proj, list) in groups {
                    ui.add_space(4.0);
                    ui.label(RichText::new(format!("執行中 · 專案：{}", proj)).strong().color(PRIMARY));
                    for c in list {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new("容器").size(11.0).color(FAINT));
                            ui.label(RichText::new(&c.name).monospace());
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.button("停止並刪除…").clicked() {
                                    pending = Some(Pending { steps: docker::running_container_steps(c), level: 3, confirm_name: Some(c.name.clone()) });
                                }
                                ui.label(RichText::new(format!("執行中 · 啟動於 {} UTC", c.started)).size(11.5).color(SUBTLE));
                            });
                        });
                    }
                }
            });
        });
        if let Some(p) = pending {
            self.docker_typed.clear();
            self.docker_ack = false;
            self.docker_pending = Some(p);
        }
        self.docker_confirm_window(ui.ctx());
    }

    fn docker_confirm_window(&mut self, ctx: &egui::Context) {
        let Some(p) = &self.docker_pending else { return };
        let mut close = false;
        let mut go = false;
        egui::Window::new("確認刪除")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, Vec2::ZERO)
            .min_width(520.0)
            .show(ctx, |ui| {
                ui.label(RichText::new("以下是會執行的指令與完整清單，確認後才會執行：").color(SUBTLE));
                for s in &p.steps {
                    card(ui, |ui| {
                        ui.label(RichText::new(&s.title).strong());
                        ui.label(RichText::new(format!("docker {}", short(&s.args.join(" "), 120))).monospace().size(11.5).color(SUBTLE));
                        for it in s.items.iter().take(30) {
                            ui.label(RichText::new(format!("• {}", it)).monospace().size(12.0));
                        }
                        if s.items.len() > 30 {
                            ui.label(format!("……共 {} 項", s.items.len()));
                        }
                    });
                }
                ui.label(RichText::new("一次處理一類，任何一步失敗就停止。執行後會記錄在 docker_cleanup.log。").size(11.5).color(FAINT));
                let mut ok = true;
                if let Some(name) = &p.confirm_name {
                    ui.label(RichText::new("刪除後無法復原。").color(BAD).strong());
                    ui.checkbox(&mut self.docker_ack, "我了解刪除後無法復原");
                    ui.label(format!("請輸入完整名稱「{}」確認：", name));
                    ui.add(egui::TextEdit::singleline(&mut self.docker_typed).desired_width(360.0));
                    // exact match only: "demo" never confirms "demo-test"
                    ok = self.docker_ack && self.docker_typed.trim() == name;
                }
                ui.horizontal(|ui| {
                    if ui.button("取消").clicked() {
                        close = true;
                    }
                    ui.add_enabled_ui(ok, |ui| {
                        let b = egui::Button::new(RichText::new("確認執行").color(Color32::WHITE)).fill(if p.level == 3 { BAD } else { PRIMARY_BTN });
                        if ui.add(b).clicked() {
                            go = true;
                        }
                    });
                });
            });
        if go {
            let steps = self.docker_pending.take().map(|p| p.steps).unwrap_or_default();
            self.docker_run = Some(Job::spawn(move |_| docker::run(&steps)));
        } else if close {
            self.docker_pending = None;
        }
    }
}
