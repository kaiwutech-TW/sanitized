//! Menu-bar item: shows memory pressure next
//! to a shield icon, and a menu with health, CPU, memory, disk and protection status.

use super::{MacApp, Page};
use crate::util::fmt_bytes;
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};

pub struct Tray {
    icon: TrayIcon,
    health: MenuItem,
    cpu_mem: MenuItem,
    disk: MenuItem,
    protect: MenuItem,
    open: MenuItem,
    status: MenuItem,
    smart: MenuItem,
    quit: MenuItem,
}

/// A small shield drawn in black (a template image, so macOS tints it for light/dark bars).
fn shield_icon() -> Icon {
    let n = 36u32;
    let mut px = vec![0u8; (n * n * 4) as usize];
    for y in 0..n {
        for x in 0..n {
            let fx = (x as f32 + 0.5) / n as f32 - 0.5;
            let fy = (y as f32 + 0.5) / n as f32;
            // top part a rectangle-ish band, bottom tapering to a point
            let half = if fy < 0.55 { 0.38 } else { 0.38 * (1.0 - (fy - 0.55) / 0.42) };
            let inside = fy > 0.06 && fy < 0.97 && fx.abs() < half;
            // hollow centre stripe makes it read as a shield outline with a check
            let inner = fy > 0.18 && fy < 0.85 && fx.abs() < half - 0.12;
            let check = {
                let (cx, cy) = (fx, fy);
                let d1 = (cy - (0.52 + (cx + 0.12))).abs() < 0.06 && cx > -0.16 && cx < -0.02;
                let d2 = (cy - (0.62 - (cx + 0.02) * 1.3)).abs() < 0.06 && cx >= -0.04 && cx < 0.16;
                d1 || d2
            };
            if inside && (!inner || check) {
                let i = ((y * n + x) * 4) as usize;
                px[i + 3] = 255;
            }
        }
    }
    Icon::from_rgba(px, n, n).expect("icon")
}

/// The app logo for the menu bar (falls back to the plain shield).
fn logo_icon() -> Option<Icon> {
    let (px, w, h) = crate::util::png_rgba(include_bytes!("../../assets/logo_44.png"))?;
    Icon::from_rgba(px, w, h).ok()
}

impl Tray {
    pub fn new() -> Option<Tray> {
        let health = MenuItem::new("Mac 健康度：讀取中…", false, None);
        let cpu_mem = MenuItem::new("處理器 –　記憶體 –", false, None);
        let disk = MenuItem::new("磁碟可用 –", false, None);
        let protect = MenuItem::new("即時防護 –", false, None);
        let open = MenuItem::new("打開 Sanitized", true, None);
        let status = MenuItem::new("查看 Mac 狀態", true, None);
        let smart = MenuItem::new("一鍵健檢…", true, None);
        let quit = MenuItem::new("結束", true, None);
        let menu = Menu::new();
        menu.append_items(&[&health, &cpu_mem, &disk, &protect, &PredefinedMenuItem::separator(), &status, &smart, &open, &PredefinedMenuItem::separator(), &quit]).ok()?;
        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_icon(logo_icon().unwrap_or_else(shield_icon))
            .with_tooltip("Sanitized")
            .build()
            .ok()?;
        Some(Tray { icon, health, cpu_mem, disk, protect, open, status, smart, quit })
    }
}

impl MacApp {
    pub(super) fn tray_tick(&mut self, ctx: &egui::Context) {
        let Some(tray) = &self.tray else { return };
        let now = ctx.input(|i| i.time);
        if now - self.tray_updated > 2.0 {
            self.tray_updated = now;
            let s = self.sampler.get();
            if s.ready {
                let pressure = (100.0 - s.mem_free_pct).clamp(0.0, 100.0);
                tray.health.set_text(format!("Mac 健康度：{}（{} 分）", s.health_label(), s.health));
                tray.cpu_mem.set_text(format!("處理器 {:.0}%　記憶體壓力 {:.0}%", s.cpu_pct, pressure));
                tray.disk.set_text(format!("磁碟可用 {}", fmt_bytes(s.disk_free)));
                tray.icon.set_title(Some(format!("{:.0}%", pressure)));
            }
            tray.protect.set_text(if self.monitor.is_running() { "即時防護：開啟" } else { "即時防護：關閉" });
        }
        let mut show: Option<Page> = None;
        let mut quit = false;
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if ev.id == *tray.open.id() {
                show = Some(self.page);
            } else if ev.id == *tray.status.id() {
                show = Some(Page::Status);
            } else if ev.id == *tray.smart.id() {
                show = Some(Page::QuickCheck);
            } else if ev.id == *tray.quit.id() {
                quit = true;
            }
        }
        if let Some(p) = show {
            self.page = p;
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }
        if quit {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}
