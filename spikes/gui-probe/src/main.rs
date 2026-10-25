//! Stage 18p throw-away probe. No printing: everything is shown in the window.
//! `--render-check` renders 3 frames and exits 0 (1 if no renderer starts).

use eframe::egui;
use eframe::egui::{Color32, FontId, RichText, Role, Sense, WidgetInfo};

const QR_TEXT: &str = "CHERVO1-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const SAS: &str = "1234 5678";

struct Probe {
    render_check: bool,
    frames: u32,
    text: String,
    adapter: String,
    picked: String,
    qr: Vec<bool>,
    qr_width: usize,
}

impl Probe {
    fn new(render_check: bool) -> Self {
        let code = qrcode::QrCode::new(QR_TEXT.as_bytes()).ok();
        let (qr, qr_width) = match code {
            Some(c) => {
                let w = c.width();
                (
                    c.to_colors().into_iter().map(|x| x == qrcode::Color::Dark).collect(),
                    w,
                )
            }
            None => (Vec::new(), 0),
        };
        Self {
            render_check,
            frames: 0,
            text: String::new(),
            adapter: String::from("(unknown)"),
            picked: String::new(),
            qr,
            qr_width,
        }
    }
}

impl eframe::App for Probe {
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        self.frames += 1;
        let ctx = ui.ctx().clone();
        if let Some(rs) = frame.wgpu_render_state() {
            let info = rs.adapter.get_info();
            self.adapter = format!("wgpu: {} ({:?})", info.name, info.backend);
        } else {
            self.adapter = String::from("glow (OpenGL)");
        }
        for f in ctx.input(|i| i.raw.dropped_files.clone()) {
            self.picked = format!("drop: {}", f.path().display());
        }
        egui::CentralPanel::default().show(ui, |ui| {
            ui.label(format!("Адаптер: {}", self.adapter));
            ui.label("Привет, мир! Отправка файлов между друзьями.");
            ui.text_edit_singleline(&mut self.text);
            if ui.button("Выбрать файл").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_file() {
                    self.picked = format!("file: {}", p.display());
                }
            }
            if ui.button("Выбрать папку").clicked() {
                if let Some(p) = rfd::FileDialog::new().pick_folder() {
                    self.picked = format!("dir: {}", p.display());
                }
            }
            ui.label(&self.picked);
            let r = ui.label(RichText::new(SAS).font(FontId::monospace(48.0)));
            let r = r.interact(Sense::focusable_noninteractive());
            r.widget_info(|| WidgetInfo::labeled(Role::Label, true, "1 2 3 4 5 6 7 8"));
            let cell = 3.0_f32;
            let side = (self.qr_width as f32 + 8.0) * cell;
            let (rect, _) = ui.allocate_exact_size(egui::vec2(side, side), Sense::hover());
            let painter = ui.painter_at(rect);
            painter.rect_filled(rect, 0.0, Color32::WHITE);
            for y in 0..self.qr_width {
                for x in 0..self.qr_width {
                    if self.qr[y * self.qr_width + x] {
                        let p = rect.min + egui::vec2((x as f32 + 4.0) * cell, (y as f32 + 4.0) * cell);
                        painter.rect_filled(egui::Rect::from_min_size(p, egui::vec2(cell, cell)), 0.0, Color32::BLACK);
                    }
                }
            }
        });
        if self.render_check {
            if self.frames >= 3 {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint();
        }
    }
}

fn run(renderer: eframe::Renderer, render_check: bool) -> bool {
    let options = eframe::NativeOptions {
        renderer,
        viewport: egui::ViewportBuilder::default().with_inner_size([640.0, 720.0]),
        ..Default::default()
    };
    eframe::run_native(
        "gui-probe",
        options,
        Box::new(move |_cc| Ok(Box::new(Probe::new(render_check)))),
    )
    .is_ok()
}

fn main() {
    let render_check = std::env::args().any(|a| a == "--render-check");
    let want_glow = std::env::var_os("GUI_PROBE_RENDERER").is_some_and(|v| v == "glow");
    let want_wgpu = std::env::var_os("GUI_PROBE_RENDERER").is_some_and(|v| v == "wgpu");
    let ok = if want_wgpu {
        run(eframe::Renderer::Wgpu, render_check)
    } else if want_glow {
        run(eframe::Renderer::Glow, render_check)
    } else {
        run(eframe::Renderer::Wgpu, render_check) || run(eframe::Renderer::Glow, render_check)
    };
    std::process::exit(if ok { 0 } else { 1 });
}
