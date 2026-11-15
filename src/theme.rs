//! Look of the app: flat near-black
//! surfaces, thin outlines, one blue accent, green/red status colours, monospaced labels and
//! numbers, and outline icons instead of illustrations.

use egui::epaint::{Mesh, Vertex, WHITE_UV};
use egui::{Color32, FontId, Pos2, Rect, Shape, Stroke, Vec2};

// Design tokens.
pub const BG: Color32 = Color32::from_rgb(0x0c, 0x0c, 0x0e);
pub const SIDEBAR_BG: Color32 = Color32::from_rgb(0x0a, 0x0a, 0x0b);
pub const SURFACE: Color32 = Color32::from_rgb(0x13, 0x13, 0x16);
pub const SURFACE_HI: Color32 = Color32::from_rgb(0x1f, 0x20, 0x25);
pub const SURFACE_TOP: Color32 = Color32::from_rgb(0x28, 0x29, 0x30);
pub const OUTLINE: Color32 = Color32::from_rgb(0x2b, 0x2e, 0x38);
pub const TEXT: Color32 = Color32::from_rgb(0xed, 0xed, 0xf0);
pub const SUBTLE: Color32 = Color32::from_rgb(0x9b, 0xa0, 0xad);
pub const FAINT: Color32 = Color32::from_rgb(0x5a, 0x5e, 0x6b);
pub const PRIMARY: Color32 = Color32::from_rgb(0x8e, 0xb2, 0xff);
pub const PRIMARY_BTN: Color32 = Color32::from_rgb(0x25, 0x63, 0xeb);
pub const GOOD: Color32 = Color32::from_rgb(0x34, 0xd3, 0x99);
pub const WARN: Color32 = Color32::from_rgb(0xfb, 0xbf, 0x24);
pub const BAD: Color32 = Color32::from_rgb(0xf8, 0x71, 0x71);
pub const PURPLE: Color32 = Color32::from_rgb(0xa7, 0x8b, 0xfa);

#[derive(Clone, Copy)]
pub struct Palette {
    pub top: Color32,
    pub bottom: Color32,
    pub accent: Color32,
    pub accent2: Color32,
}

/// Module colours now only tint small icons; every page shares the same flat surfaces.
pub const fn pal(_t: [u8; 3], _b: [u8; 3], a: [u8; 3], a2: [u8; 3]) -> Palette {
    Palette { top: BG, bottom: BG, accent: Color32::from_rgb(a[0], a[1], a[2]), accent2: Color32::from_rgb(a2[0], a2[1], a2[2]) }
}

pub fn lerp(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let f = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t).round() as u8;
    Color32::from_rgba_unmultiplied(f(a.r(), b.r()), f(a.g(), b.g()), f(a.b(), b.b()), f(a.a(), b.a()))
}

pub fn alpha(c: Color32, a: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), a)
}

/// Four-corner gradient (kept for thin bars; pages are flat now).
pub fn gradient_rect(painter: &egui::Painter, r: Rect, tl: Color32, tr: Color32, bl: Color32, br: Color32) {
    let mut m = Mesh::default();
    for (p, c) in [(r.left_top(), tl), (r.right_top(), tr), (r.left_bottom(), bl), (r.right_bottom(), br)] {
        m.vertices.push(Vertex { pos: p, uv: WHITE_UV, color: c });
    }
    m.add_triangle(0, 1, 2);
    m.add_triangle(1, 3, 2);
    painter.add(Shape::mesh(m));
}

pub fn radial_poly(painter: &egui::Painter, pts: &[Pos2], center: Pos2, inner: Color32, outer: Color32) {
    let mut m = Mesh::default();
    m.vertices.push(Vertex { pos: center, uv: WHITE_UV, color: inner });
    for p in pts {
        m.vertices.push(Vertex { pos: *p, uv: WHITE_UV, color: outer });
    }
    let n = pts.len() as u32;
    for i in 0..n {
        m.add_triangle(0, 1 + i, 1 + (i + 1) % n);
    }
    painter.add(Shape::mesh(m));
}

pub fn circle_pts(c: Pos2, r: f32, n: usize, rot: f32) -> Vec<Pos2> {
    (0..n)
        .map(|i| {
            let a = rot + i as f32 / n as f32 * std::f32::consts::TAU;
            c + Vec2::new(a.cos(), a.sin()) * r
        })
        .collect()
}

#[derive(Clone, Copy, PartialEq)]
pub enum Glyph {
    Sparkle,
    Bubbles,
    Shield,
    Bolt,
    Grid,
    Folders,
    Rings,
    Cloud,
    Bug,
    Pulse,
    Gear,
}

/// Outline icon (Material-Symbols-like, 1.5 px strokes) centred at `c`, `s` = icon size.
pub fn icon(painter: &egui::Painter, c: Pos2, s: f32, glyph: Glyph, col: Color32) {
    let w = (s * 0.09).max(1.4);
    let st = Stroke::new(w, col);
    let p = |x: f32, y: f32| c + Vec2::new(x, y) * s;
    match glyph {
        Glyph::Shield | Glyph::Bug => {
            let pts = vec![p(0.0, -0.45), p(0.38, -0.3), p(0.36, 0.08), p(0.0, 0.46), p(-0.36, 0.08), p(-0.38, -0.3)];
            painter.add(Shape::closed_line(pts, st));
            if glyph == Glyph::Shield {
                painter.add(Shape::line(vec![p(-0.15, 0.0), p(-0.03, 0.12), p(0.17, -0.1)], st));
            } else {
                painter.line_segment([p(0.0, -0.2), p(0.0, 0.07)], st);
                painter.circle_filled(p(0.0, 0.2), w * 0.7, col);
            }
        }
        Glyph::Gear => {
            // Ring with eight teeth around a small hole.
            painter.circle_stroke(c, s * 0.24, st);
            painter.circle_stroke(c, s * 0.09, st);
            for i in 0..8 {
                let a = i as f32 / 8.0 * std::f32::consts::TAU;
                let d = Vec2::new(a.cos(), a.sin());
                painter.line_segment([c + d * s * 0.27, c + d * s * 0.42], Stroke::new(w * 1.6, col));
            }
        }
        Glyph::Pulse => {
            painter.add(Shape::line(vec![p(-0.45, 0.02), p(-0.2, 0.02), p(-0.1, -0.25), p(0.05, 0.3), p(0.17, -0.3), p(0.26, 0.02), p(0.45, 0.02)], st));
        }
        Glyph::Sparkle => {
            let star = |cx: f32, cy: f32, r: f32| {
                let pts: Vec<Pos2> = (0..8)
                    .map(|i| {
                        let a = i as f32 / 8.0 * std::f32::consts::TAU - std::f32::consts::FRAC_PI_2;
                        let rr = if i % 2 == 0 { r } else { r * 0.3 };
                        p(cx + a.cos() * rr, cy + a.sin() * rr)
                    })
                    .collect();
                painter.add(Shape::closed_line(pts, st));
            };
            star(-0.05, 0.05, 0.38);
            star(0.3, -0.3, 0.14);
        }
        Glyph::Bubbles => {
            painter.circle_stroke(p(-0.08, 0.08), 0.28 * s, st);
            painter.circle_stroke(p(0.28, -0.24), 0.13 * s, st);
        }
        Glyph::Bolt => {
            painter.add(Shape::closed_line(vec![p(0.08, -0.45), p(-0.25, 0.06), p(-0.02, 0.06), p(-0.1, 0.45), p(0.25, -0.08), p(0.02, -0.08)], st));
        }
        Glyph::Grid => {
            for (dx, dy) in [(-1.0, -1.0), (1.0, -1.0), (-1.0, 1.0), (1.0, 1.0)] {
                painter.rect_stroke(Rect::from_center_size(p(dx * 0.2, dy * 0.2), Vec2::splat(0.26 * s)), 2.0, st);
            }
        }
        Glyph::Folders => {
            painter.rect_stroke(Rect::from_min_max(p(-0.42, -0.24), p(0.42, 0.34)), 3.0, st);
            painter.add(Shape::line(vec![p(-0.42, -0.24), p(-0.42, -0.36), p(-0.1, -0.36), p(0.0, -0.24)], st));
        }
        Glyph::Rings => {
            painter.circle_stroke(c, 0.42 * s, st);
            painter.line_segment([c, p(0.0, -0.42)], st);
            painter.line_segment([c, p(0.36, 0.2)], st);
        }
        Glyph::Cloud => {
            painter.add(Shape::line(
                vec![p(-0.3, 0.25), p(-0.42, 0.12), p(-0.36, -0.04), p(-0.2, -0.08), p(-0.1, -0.28), p(0.12, -0.3), p(0.26, -0.12), p(0.42, -0.02), p(0.42, 0.16), p(0.3, 0.25), p(-0.3, 0.25)],
                st,
            ));
        }
    }
}

/// The page's icon in a bordered tile (replaces the glossy illustrations; the design has none).
/// `t` animates a slow ring while a scan runs (pass a growing time) or stays still.
pub fn illustration(painter: &egui::Painter, c: Pos2, size: f32, p: Palette, glyph: Glyph, t: f32) {
    let side = (size * 0.55).clamp(56.0, 120.0);
    let r = Rect::from_center_size(c, Vec2::splat(side));
    painter.rect_filled(r, 14.0, SURFACE);
    painter.rect_stroke(r, 14.0, Stroke::new(1.0_f32, OUTLINE));
    icon(painter, c, side * 0.5, glyph, lerp(p.accent2, TEXT, 0.3));
    // a thin orbit; its marker only moves during work (t < 0 means idle: no marker)
    let orbit = side * 0.78;
    painter.circle_stroke(c, orbit, Stroke::new(1.0_f32, alpha(OUTLINE, 160)));
    if t >= 0.0 {
        let a = t * 0.8;
        painter.circle_filled(c + Vec2::new(a.cos(), a.sin()) * orbit, 2.5, alpha(PRIMARY, 200));
    }
}

/// Kept for callers that used the old glow; draws nothing now (flat design).
pub fn glow(_painter: &egui::Painter, _c: Pos2, _r: f32, _col: Color32) {}

/// Small uppercase monospaced section label, e.g. "CORE TELEMETRY REPORT".
pub fn eyebrow(ui: &mut egui::Ui, text: &str) {
    ui.label(egui::RichText::new(text).font(FontId::monospace(11.0)).color(SUBTLE).extra_letter_spacing(1.5));
}

/// The main action button of a page (the design's solid blue button). Same call as before:
/// centred on `center`; `busy` shows a progress bar inside (negative/zero = indeterminate).
pub fn big_button(ui: &mut egui::Ui, center: Pos2, label: &str, _p: Palette, t: f32, busy: Option<f32>) -> egui::Response {
    let font = FontId::proportional(15.0);
    let galley = ui.painter().layout_no_wrap(label.to_string(), font.clone(), Color32::WHITE);
    let size = Vec2::new((galley.size().x + 64.0).max(180.0), 44.0);
    let rect = Rect::from_center_size(center, size);
    let resp = ui.interact(rect, ui.id().with(("big", label)), egui::Sense::click());
    let painter = ui.painter();
    let hover = resp.hovered();
    let (fill, stroke) = match busy {
        Some(_) => (SURFACE_HI, OUTLINE),
        None if hover => (lerp(PRIMARY_BTN, Color32::WHITE, 0.12), PRIMARY_BTN),
        None => (PRIMARY_BTN, PRIMARY_BTN),
    };
    painter.rect_filled(rect, 8.0, fill);
    painter.rect_stroke(rect, 8.0, Stroke::new(1.0_f32, stroke));
    if let Some(frac) = busy {
        let track = Rect::from_min_max(Pos2::new(rect.left() + 12.0, rect.bottom() - 6.0), Pos2::new(rect.right() - 12.0, rect.bottom() - 4.0));
        painter.rect_filled(track, 1.0, OUTLINE);
        let (x0, x1) = if frac > 0.0 {
            (0.0, frac.clamp(0.0, 1.0))
        } else {
            let k = (t * 0.6).fract();
            ((k - 0.25).max(0.0), (k + 0.15).min(1.0))
        };
        let bar = Rect::from_min_max(Pos2::new(track.left() + track.width() * x0, track.top()), Pos2::new(track.left() + track.width() * x1, track.bottom()));
        painter.rect_filled(bar, 1.0, PRIMARY);
    }
    let text_col = if busy.is_some() { TEXT } else { Color32::WHITE };
    painter.text(center - Vec2::new(0.0, if busy.is_some() { 2.0 } else { 0.0 }), egui::Align2::CENTER_CENTER, label, font, text_col);
    if hover {
        ui.ctx().set_cursor_icon(egui::CursorIcon::PointingHand);
    }
    resp
}
