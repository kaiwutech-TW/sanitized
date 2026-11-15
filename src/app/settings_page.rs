//! Settings: interface language and the new-version check.

use super::{card, MacApp};
use crate::clean::Job;
use crate::i18n::{self, Lang};
use crate::theme::{self, FAINT, GOOD, SUBTLE, WARN};
use crate::{update, util};
use egui::RichText;

impl MacApp {
    pub(super) fn page_settings(&mut self, ui: &mut egui::Ui) {
        theme::eyebrow(ui, self.page.eyebrow());
        ui.label(RichText::new(t!("設定")).size(22.0).strong());
        ui.add_space(10.0);
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            self.language_card(ui);
            ui.add_space(4.0);
            self.update_card(ui);
        });
    }

    fn language_card(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            ui.label(RichText::new(t!("語言")).size(16.0).strong());
            ui.label(RichText::new(t!("介面使用的語言。預設跟著這台 Mac 的系統語言。")).size(12.5).color(SUBTLE));
            ui.add_space(8.0);
            let mut choice = self.prefs.lang;
            ui.radio_value(&mut choice, None, tf!("跟隨系統（{}）", i18n::system().native_name()));
            for l in Lang::ALL {
                ui.radio_value(&mut choice, Some(l), l.native_name());
            }
            if choice != self.prefs.lang {
                self.prefs.lang = choice;
                self.prefs.save();
                let lang = self.prefs.effective_lang();
                i18n::set(lang);
                super::apply_fonts(ui.ctx(), lang);
            }
        });
    }

    fn update_card(&mut self, ui: &mut egui::Ui) {
        card(ui, |ui| {
            ui.label(RichText::new(t!("新版本")).size(16.0).strong());
            ui.label(RichText::new(tf!("目前版本：v{}", update::current_version())).monospace().size(12.5).color(SUBTLE));
            ui.add_space(8.0);
            let mut on = self.prefs.check_updates;
            if ui.checkbox(&mut on, t!("每天自動檢查一次新版本")).changed() {
                self.prefs.check_updates = on;
                self.prefs.save();
                let due = util::now_secs().saturating_sub(self.prefs.last_update_check) >= update::CHECK_EVERY_SECS;
                if on && due && self.ver_job.is_none() {
                    self.ver_job = Some(Job::spawn(|_| update::fetch_latest()));
                }
            }
            ui.label(RichText::new(t!("只會向 GitHub 查詢最新的版本號，不會傳送任何關於這台 Mac 或你的資料，也不會自動下載或安裝。")).size(12.0).color(FAINT));
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let busy = self.ver_job.is_some();
                if ui.add_enabled(!busy, egui::Button::new(t!("立即檢查"))).clicked() {
                    self.ver_msg = None;
                    self.ver_job = Some(Job::spawn(|_| update::fetch_latest()));
                }
                if busy {
                    ui.spinner();
                    ui.label(RichText::new(t!("正在檢查…")).color(SUBTLE));
                } else {
                    match &self.ver_msg {
                        Some(Ok(v)) if update::is_newer(v) => {
                            ui.label(RichText::new(tf!("有新版本 v{}。", v)).color(GOOD));
                            if ui.button(t!("前往下載")).clicked() {
                                util::open_url(update::RELEASES_PAGE);
                            }
                        }
                        Some(Ok(_)) => {
                            ui.label(RichText::new(t!("已是最新版本。")).color(GOOD));
                        }
                        Some(Err(e)) => {
                            ui.label(RichText::new(tf!("無法檢查新版本：{}", e)).color(WARN));
                        }
                        None => {}
                    }
                }
            });
            if self.prefs.last_update_check > 0 {
                ui.add_space(4.0);
                ui.label(RichText::new(tf!("上次檢查：{}", util::date(self.prefs.last_update_check))).size(11.5).color(FAINT));
            }
        });
    }
}
