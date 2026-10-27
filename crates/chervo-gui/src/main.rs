//! Червоточина: оболочка с окном поверх `chervo_core::Node` (этап 18б). Печати и журнала нет
//! совсем: всё, что нужно пользователю, показывается в окне.
#![windows_subsystem = "windows"]

mod app;
mod main_model;
mod model;
mod picker;
mod qr;
mod rows;
mod screens;
mod texts;
mod worker;
mod worker_ops;

use std::process::ExitCode;

use chervo_core::HardenReport;
use eframe::egui;

use crate::app::App;
use crate::model::Model;
use crate::worker::Worker;

fn main() -> ExitCode {
    // Первая строка (этап 17, C07): запрет дампов памяти до чтения аргументов и любых ключей.
    let _hardening = chervo_core::harden_process();
    let render_check = std::env::args_os().skip(1).any(|a| a == "--render-check");
    // Рендер: wgpu, при ошибке запуска glow (DECISION 2.9).
    let ok = run(eframe::Renderer::Wgpu, render_check, _hardening)
        || run(eframe::Renderer::Glow, render_check, _hardening);
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn run(renderer: eframe::Renderer, render_check: bool, hardening: HardenReport) -> bool {
    let options = eframe::NativeOptions {
        renderer,
        viewport: egui::ViewportBuilder::default()
            .with_title(texts::WINDOW_TITLE)
            .with_inner_size([760.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native(
        texts::WINDOW_TITLE,
        options,
        Box::new(move |cc| {
            let app = if render_check {
                // проверка отрисовки: без узла, ключей и файлов
                App::new(Model::preview(), None, true)
            } else {
                let (model, commands) = Model::start();
                let ctx = cc.egui_ctx.clone();
                let worker = Worker::spawn(hardening, move || ctx.request_repaint())
                    .ok_or_else(|| std::io::Error::other("worker thread"))?;
                for c in commands {
                    worker.send(c);
                }
                App::new(model, Some(worker), false)
            };
            Ok(Box::new(app))
        }),
    )
    .is_ok()
}
