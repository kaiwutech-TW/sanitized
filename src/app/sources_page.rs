//! "病毒碼來源": what each antivirus rule source is, how current it is, and links to it,
//! so the person knows where the data comes from.

use super::{card, pill, MacApp};
use crate::av::RuleSet;
use crate::clean::Job;
use crate::sources::{self, Source};
use crate::theme::{FAINT, GOOD, SUBTLE, WARN};
use crate::util;
use egui::{Align, Color32, Layout, RichText};

const LINK: Color32 = Color32::from_rgb(160, 210, 255);

impl MacApp {
    pub(super) fn prot_sources(&mut self, ui: &mut egui::Ui) {
        let count = |s: Source| self.rules.per_source.get(&s).copied().unwrap_or(0);
        self.header(ui, "病毒碼來源", &format!("共 {} 條規則", self.rules.count));
        ui.label(RichText::new("掃描時會同時使用以下來源。每個掃描結果都會註明是哪一個來源抓到的。").color(SUBTLE));
        ui.add_space(4.0);
        let mut save_key = false;
        let mut update_now = false;
        let mut clear_key = false;
        let mut open_sig = false;
        egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
            // ---- Apple XProtect
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Apple XProtect").size(17.0).strong());
                    match (&self.rules.xprotect, self.rules_job.is_some()) {
                        (Some(_), _) => pill(ui, "已啟用", GOOD),
                        (None, true) => pill(ui, "載入中…", WARN),
                        (None, false) => pill(ui, "這台 Mac 找不到", WARN),
                    }
                });
                ui.label(RichText::new("macOS 內建、由 Apple 自動更新的惡意軟體特徵規則（YARA 格式）。本程式直接讀取這台 Mac 上的規則，用來檢查已經在電腦裡的程式與腳本。").size(12.5).color(SUBTLE));
                match &self.rules.xprotect {
                    Some(x) => {
                        let mut t = format!("版本 {} · 已載入 {} 條規則 · 規則檔更新於 {}", x.version, x.loaded, util::date(x.updated));
                        if x.skipped > 0 {
                            t.push_str(&format!(" · {} 條無法使用", x.skipped));
                        }
                        ui.label(RichText::new(t).size(12.5));
                        ui.label(RichText::new(format!("位置：{}", x.bundle.display())).size(11.5).color(FAINT));
                    }
                    None if self.rules_job.is_some() => {
                        ui.label(RichText::new("正在編譯規則，約需幾秒鐘…").size(12.5));
                    }
                    None => {}
                }
                ui.hyperlink_to(RichText::new("Apple 說明：防範惡意軟體").size(12.5).color(LINK), Source::XProtect.url());
            });

            // ---- MalwareBazaar
            card(ui, |ui| {
                let meta = sources::mb_meta();
                ui.horizontal(|ui| {
                    ui.label(RichText::new("MalwareBazaar（abuse.ch）").size(17.0).strong());
                    if self.mb_job.is_some() {
                        pill(ui, "更新中…", WARN);
                    } else if count(Source::MalwareBazaar) > 0 {
                        pill(ui, "已啟用", GOOD);
                    } else if self.mb_has_key {
                        pill(ui, "尚未下載", WARN);
                    } else {
                        pill(ui, "需要免費金鑰", WARN);
                    }
                });
                ui.label(RichText::new(format!(
                    "瑞士非營利組織 abuse.ch 的公開惡意軟體樣本資料庫（CC0 公眾領域授權）。本程式會下載最新的 Mac 惡意軟體檔案指紋（Mach-O 程式、DMG、PKG 各最多 {} 筆），並每天自動更新一次。",
                    sources::MB_LIMIT
                )).size(12.5).color(SUBTLE));
                ui.label(RichText::new("限制：檔案指紋只抓得到一模一樣的檔案，惡意軟體稍微修改過就抓不到。").size(12.0).color(FAINT));
                if count(Source::MalwareBazaar) > 0 {
                    ui.label(RichText::new(format!("目前有 {} 筆指紋 · 更新於 {}", count(Source::MalwareBazaar), util::date(meta.updated))).size(12.5));
                }
                if let Some(s) = &self.mb_status {
                    ui.label(RichText::new(s).size(12.5).color(if s.starts_with("已從") { GOOD } else { WARN }));
                }
                ui.horizontal(|ui| {
                    ui.label("Auth-Key：");
                    let hint = if self.mb_has_key { "已儲存在鑰匙圈（輸入新的可取代）" } else { "貼上您的免費金鑰" };
                    ui.add(egui::TextEdit::singleline(&mut self.mb_key_input).password(true).hint_text(hint).desired_width(300.0));
                    if ui.button("儲存並更新").clicked() {
                        save_key = true;
                    }
                });
                ui.horizontal(|ui| {
                    if self.mb_has_key && self.mb_job.is_none() && ui.button("立即更新").clicked() {
                        update_now = true;
                    }
                    if self.mb_has_key && ui.button("清除金鑰").clicked() {
                        clear_key = true;
                    }
                    ui.hyperlink_to(RichText::new("取得免費金鑰").size(12.5).color(LINK), "https://auth.abuse.ch/");
                    ui.hyperlink_to(RichText::new("MalwareBazaar 網站").size(12.5).color(LINK), Source::MalwareBazaar.url());
                });
                ui.label(RichText::new("金鑰只存在這台 Mac 的鑰匙圈，只會傳給 abuse.ch。").size(11.5).color(FAINT));
            });

            // ---- Objective-See
            card(ui, |ui| {
                let fams = sources::objective_see_families();
                let with_rules: Vec<&str> = {
                    let mut v: Vec<&str> = sources::OBJECTIVE_SEE_ARTIFACTS.iter().map(|(_, f, _)| *f).collect();
                    v.dedup();
                    v
                };
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Objective-See").size(17.0).strong());
                    pill(ui, "已啟用", GOOD);
                });
                ui.label(RichText::new(format!(
                    "專門研究 Mac 惡意軟體的非營利組織，公開收錄了 {} 個 Mac 惡意軟體家族。本程式依公開的分析報告，整理其中 {} 個家族會安裝的檔案位置，作為 {} 條規則。",
                    fams.len(),
                    with_rules.len(),
                    count(Source::ObjectiveSee)
                )).size(12.5).color(SUBTLE));
                ui.label(RichText::new("家族名稱本身不直接當作規則，因為有些是常見單字（例如 Dummy、Snake），會造成誤判。這份清單由人工整理，需要隨新版本手動更新。").size(12.0).color(FAINT));
                ui.label(RichText::new("已有規則的家族").size(12.5).strong());
                ui.label(RichText::new(with_rules.join("、")).size(12.5));
                egui::CollapsingHeader::new(RichText::new(format!("收錄的 {} 個家族名稱", fams.len())).size(12.5)).id_salt("os_fams").show(ui, |ui| {
                    ui.label(RichText::new(fams.join("、")).size(12.0).color(SUBTLE));
                });
                ui.hyperlink_to(RichText::new("Objective-See 惡意軟體清單").size(12.5).color(LINK), Source::ObjectiveSee.url());
            });

            // ---- built-in and own rules
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("內建規則").size(17.0).strong());
                    pill(ui, "已啟用", GOOD);
                });
                ui.label(RichText::new(format!(
                    "{} 條：EICAR 防毒測試檔指紋（EICAR 組織公布的標準測試檔）、資安研究公開報導的 Mac 廣告軟體家族名稱，以及本程式自己寫的可疑行為特徵（例如下載後直接執行的腳本、假冒密碼視窗）。",
                    count(Source::Builtin)
                )).size(12.5).color(SUBTLE));
            });
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("自訂病毒碼").size(17.0).strong());
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui.button("打開病毒碼檔案").clicked() {
                            open_sig = true;
                        }
                    });
                });
                ui.label(RichText::new(format!("{} 條。您自己加入的規則，每行一條：「SHA-256 大小 名稱」、「path 規則 名稱」或「ext 擴充功能ID 名稱」。", count(Source::User))).size(12.5).color(SUBTLE));
            });
        });

        if save_key {
            let key = self.mb_key_input.trim().to_string();
            if key.is_empty() {
                self.say(ui.ctx(), "請先貼上金鑰");
            } else {
                match sources::set_mb_key(&key) {
                    Ok(()) => {
                        self.mb_has_key = true;
                        self.mb_key_input.clear();
                        update_now = true;
                    }
                    Err(e) => self.say(ui.ctx(), format!("無法儲存金鑰：{}", e)),
                }
            }
        }
        if update_now && self.mb_job.is_none() {
            self.mb_status = Some("正在從 MalwareBazaar 下載…".into());
            self.mb_job = Some(Job::spawn(|_| match sources::mb_key() {
                Some(k) => sources::update_malwarebazaar(&k),
                None => Err("沒有金鑰".into()),
            }));
        }
        if clear_key {
            let _ = sources::set_mb_key("");
            let _ = std::fs::remove_file(sources::mb_file());
            self.mb_has_key = false;
            self.mb_status = Some("已清除金鑰與下載的指紋".into());
            self.rules_job = Some(Job::spawn(|_| RuleSet::load()));
        }
        if open_sig {
            let f = crate::av::signatures_file();
            if !f.exists() {
                let _ = std::fs::write(&f, "# 每行一條：<sha256> <大小> <名稱> | path <規則> <名稱> | ext <擴充功能ID> <名稱>\n");
            }
            let _ = std::process::Command::new("open").arg("-t").arg(&f).spawn();
        }
    }
}
