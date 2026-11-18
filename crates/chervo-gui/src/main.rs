//! Червоточина: оболочка с окном поверх `chervo_core::Node` (этап 18б). Печати и журнала нет
//! совсем: всё, что нужно пользователю, показывается в окне.
#![windows_subsystem = "windows"]

mod access_model;
mod app;
mod fixtures;
mod main_model;
mod model;
mod picker;
mod qr;
mod redact;
mod rows;
mod safe_text;
mod screens;
mod settings_model;
mod texts;
mod update_model;
mod update_worker;
mod worker;
mod worker_ops;

use std::cell::{Cell, RefCell};
use std::process::ExitCode;
use std::rc::Rc;

use chervo_core::HardenReport;
use eframe::egui;

use crate::app::App;
use crate::model::Model;
use crate::worker::Worker;

fn main() -> ExitCode {
    // Первая строка (этап 17, C07): запрет дампов памяти до чтения аргументов и любых ключей.
    let _hardening = chervo_core::harden_process();
    let render_check = std::env::args_os().skip(1).any(|a| a == "--render-check");
    // Рендер: wgpu, при ошибке запуска glow (DECISION 2.9). Второй попытки нет, если приложение
    // уже было создано: его фоновый поток держит замок профиля, и новый узел получил бы
    // `AlreadyRunning` от нашего же замка.
    let session = Rc::new(Session::default());
    // Паника в потоке окна (профиль без `panic = "abort"`, проверено: в корневом Cargo.toml такого
    // нет) не должна обходить остановку узла: ловим её, затем всё равно доходим до `finish`.
    let mut panicked = false;
    let mut ok = guarded(&mut panicked, || {
        run(eframe::Renderer::Wgpu, render_check, _hardening, &session)
    });
    if !ok && !panicked && !session.created.get() {
        ok = guarded(&mut panicked, || {
            run(eframe::Renderer::Glow, render_check, _hardening, &session)
        });
    }
    // На любом пути выхода узел останавливается по порядку (снятие проброса порта), а поток
    // ждётся не дольше `JOIN_BOUND`.
    let worker = session.worker.borrow_mut().take();
    let joined = worker.is_none_or(|w| w.finish());
    // `--render-check` успешен, только если нарисованы все состояния
    let complete =
        !render_check || app::RENDER_CHECK_DONE.load(std::sync::atomic::Ordering::SeqCst);
    if ok && complete && joined && !panicked {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Выполняет запуск окна, превращая панику в `false` (и отметку `panicked`).
fn guarded(panicked: &mut bool, f: impl FnOnce() -> bool) -> bool {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(v) => v,
        Err(_) => {
            *panicked = true;
            false
        }
    }
}

/// Идентификатор приложения: `app_id` окна (Wayland) и имя `.desktop` на Linux (этап 19е, `StartupWMClass`).
const APP_ID: &str = "io.github.rekc2004.chervotochina";

/// Значок окна: сырые RGBA 64x64 из `assets/icon-64.rgba` (генератор `packaging/icons/make-icons.py`).
/// Ресурс в самом `.exe` не вшивается: `build.rs` в этом крейте запрещён (тест `manifest_only_core`).
const ICON_SIDE: u32 = 64;
const ICON_RGBA: &[u8] = include_bytes!("../assets/icon-64.rgba");

fn window_icon() -> egui::IconData {
    egui::IconData {
        rgba: ICON_RGBA.to_vec(),
        width: ICON_SIDE,
        height: ICON_SIDE,
    }
}

/// Что `main` узнаёт о запуске окна: создано ли приложение и фоновый поток (его `main` ждёт).
#[derive(Default)]
struct Session {
    created: Cell<bool>,
    worker: RefCell<Option<Rc<Worker>>>,
}

fn run(
    renderer: eframe::Renderer,
    render_check: bool,
    hardening: HardenReport,
    session: &Rc<Session>,
) -> bool {
    let options = eframe::NativeOptions {
        renderer,
        viewport: egui::ViewportBuilder::default()
            .with_title(texts::WINDOW_TITLE)
            .with_app_id(APP_ID)
            .with_icon(window_icon())
            .with_inner_size([760.0, 560.0]),
        ..Default::default()
    };
    let session = session.clone();
    eframe::run_native(
        texts::WINDOW_TITLE,
        options,
        Box::new(move |cc| {
            let app = if render_check {
                // проверка отрисовки: без узла, ключей и файлов
                App::render_check(fixtures::all())
            } else {
                let (model, commands) = Model::start();
                let ctx = cc.egui_ctx.clone();
                let worker = Rc::new(
                    Worker::spawn(hardening, move || ctx.request_repaint())
                        .ok_or_else(|| std::io::Error::other("worker thread"))?,
                );
                for c in commands {
                    worker.send(c);
                }
                *session.worker.borrow_mut() = Some(worker.clone());
                App::new(model, Some(worker), false)
            };
            session.created.set(true);
            Ok(Box::new(app))
        }),
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_icon_is_64x64_rgba_with_opaque_pixels() {
        let icon = window_icon();
        assert_eq!(ICON_RGBA.len(), 16384);
        assert_eq!((icon.width, icon.height), (64, 64));
        assert_eq!(icon.rgba.len(), (icon.width * icon.height * 4) as usize);
        assert!(icon.rgba.iter().skip(3).step_by(4).any(|&a| a == 255));
        // углы прозрачны: значок круглый
        assert_eq!(icon.rgba[3], 0);
    }

    #[test]
    fn app_id_matches_desktop_entry_and_bundle_id() {
        assert_eq!(APP_ID, "io.github.rekc2004.chervotochina");
    }
}
