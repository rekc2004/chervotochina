//! Оболочка eframe: рисует экраны по состоянию модели, превращает намерения в команды
//! фоновому потоку и забирает его ответы. Узла здесь нет: он живёт только в фоновом потоке.

use eframe::egui;

use crate::main_model::MainIntent;
use crate::model::{Close, Intent, Model};
use crate::worker::Worker;
use crate::{picker, screens};

/// Сколько кадров рисует `--render-check` перед выходом.
const RENDER_CHECK_FRAMES: u32 = 3;

pub struct App {
    model: Model,
    worker: Option<Worker>,
    render_check: bool,
    frames: u32,
}

impl App {
    pub fn new(model: Model, worker: Option<Worker>, render_check: bool) -> Self {
        Self {
            model,
            worker,
            render_check,
            frames: 0,
        }
    }

    fn dispatch(&mut self, intents: Vec<Intent>) {
        for intent in intents {
            for cmd in self.model.update(intent) {
                if let Some(w) = &self.worker {
                    w.send(cmd);
                }
            }
        }
    }

    fn drain_worker(&mut self) {
        let mut commands = Vec::new();
        if let Some(w) = &self.worker {
            while let Some(outcome) = w.try_recv() {
                commands.extend(self.model.on_outcome(outcome));
            }
            for cmd in commands {
                w.send(cmd);
            }
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.frames += 1;
        self.drain_worker();

        // закрытие окна: сначала вопрос и упорядоченная остановка узла
        if !self.render_check
            && ctx.input(|i| i.viewport().close_requested())
            && !self.model.may_close_window()
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.dispatch(vec![Intent::CloseRequested]);
        }

        // файлы, брошенные в окно: добавляются к выбору для отправки (только описание путей, без
        // чтения содержимого и записи)
        let dropped: Vec<_> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .filter(|p| !p.as_os_str().is_empty())
                .collect()
        });
        if self.model.node_open && self.model.close == Close::None && !dropped.is_empty() {
            let picked: Vec<_> = dropped.into_iter().filter_map(picker::describe).collect();
            if !picked.is_empty() {
                self.dispatch(vec![Intent::Main(MainIntent::PathsAdded(picked))]);
            }
        }
        // новое предложение или проверочный код: мигнуть окном в панели задач, больше ничего
        if self.model.take_attention() {
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                egui::UserAttentionType::Informational,
            ));
        }

        let mut intents = Vec::new();
        egui::CentralPanel::default().show(ui, |ui| {
            intents = screens::show(ui, &self.model);
        });
        self.dispatch(intents);

        if self.model.may_close_window() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if self.render_check {
            if self.frames >= RENDER_CHECK_FRAMES {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint();
        }
    }
}
