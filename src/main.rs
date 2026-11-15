mod app;
mod av;
mod clean;
mod docker;
mod theme;
mod sources;
mod status;
mod util;
mod vuln;
#[cfg(test)]
mod tests;

use std::path::PathBuf;

/// Wraps the app to support `--screenshot <file.png>`: draw ~120 frames, save, exit.
struct Runner {
    app: app::MacApp,
    shot: Option<PathBuf>,
    frames: u32,
    requested: bool,
}

impl eframe::App for Runner {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.app.update(ctx, frame);
        if let Some(path) = self.shot.clone() {
            self.frames += 1;
            ctx.request_repaint();
            if self.frames >= std::env::var("MCG_FRAMES").ok().and_then(|v| v.parse().ok()).unwrap_or(120) && !self.requested {
                self.requested = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot);
            }
            let shots: Vec<std::sync::Arc<egui::ColorImage>> = ctx.input(|i| {
                i.raw.events.iter().filter_map(|e| if let egui::Event::Screenshot { image, .. } = e { Some(image.clone()) } else { None }).collect()
            });
            if let Some(img) = shots.into_iter().next() {
                let [w, h] = img.size;
                let mut buf = Vec::with_capacity(w * h * 4);
                for p in &img.pixels {
                    buf.extend_from_slice(&[p.r(), p.g(), p.b(), 255]);
                }
                if let Some(dir) = path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                match image::save_buffer(&path, &buf, w as u32, h as u32, image::ExtendedColorType::Rgba8) {
                    Ok(()) => eprintln!("saved screenshot to {}", path.display()),
                    Err(e) => eprintln!("could not save screenshot: {e}"),
                }
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.app.on_exit();
    }
}

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let shot = args.iter().position(|a| a == "--screenshot").and_then(|i| args.get(i + 1)).map(PathBuf::from);
    let shooting = shot.is_some();

    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Sanitized")
        .with_inner_size([1160.0, 740.0])
        .with_min_inner_size([960.0, 640.0]);
    if let Some((px, w, h)) = util::png_rgba(include_bytes!("../assets/logo_512.png")) {
        viewport = viewport.with_icon(egui::IconData { rgba: px, width: w, height: h });
    }
    if shooting {
        viewport = viewport.with_active(false);
        #[cfg(target_os = "windows")]
        {
            viewport = viewport.with_window_level(egui::WindowLevel::AlwaysOnBottom);
        }
    }
    let mut options = eframe::NativeOptions { viewport, ..Default::default() };
    #[cfg(target_os = "macos")]
    if shooting {
        options.event_loop_builder = Some(Box::new(|b| {
            use winit::platform::macos::EventLoopBuilderExtMacOS;
            b.with_activate_ignoring_other_apps(false);
        }));
    }
    #[cfg(not(target_os = "macos"))]
    let _ = &mut options;

    eframe::run_native(
        "Sanitized",
        options,
        Box::new(move |cc| {
            app::setup_style(&cc.egui_ctx);
            Ok(Box::new(Runner { app: { let mut a = app::MacApp::new(shooting); a.dev_autostart(); a }, shot, frames: 0, requested: false }))
        }),
    )
}
