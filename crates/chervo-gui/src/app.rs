//! Оболочка eframe: рисует экраны по состоянию модели, превращает намерения в команды
//! фоновому потоку и забирает его ответы. Узла здесь нет: он живёт только в фоновом потоке.

use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};

use eframe::egui;

use crate::main_model::MainIntent;
use crate::model::{Close, Intent, Model};
use crate::worker::Worker;
use crate::{picker, screens};

/// Сколько кадров рисуется на каждое состояние в `--render-check` (второй кадр нужен, чтобы
/// раскладка установилась).
const FRAMES_PER_FIXTURE: u32 = 2;

/// `--render-check` дошёл до конца списка состояний (иначе окно закрыли раньше: это провал).
pub static RENDER_CHECK_DONE: AtomicBool = AtomicBool::new(false);

pub struct App {
    model: Model,
    worker: Option<Rc<Worker>>,
    render_check: bool,
    /// Состояния для `--render-check`.
    fixtures: Vec<Model>,
    frames: u32,
}

impl App {
    pub fn new(model: Model, worker: Option<Rc<Worker>>, render_check: bool) -> Self {
        Self {
            model,
            worker,
            render_check,
            fixtures: Vec::new(),
            frames: 0,
        }
    }

    /// Проверка отрисовки: без узла, ключей и файлов, по готовым состояниям всех экранов.
    pub fn render_check(fixtures: Vec<Model>) -> Self {
        let mut app = Self::new(Model::preview(), None, true);
        app.fixtures = fixtures;
        app
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
        if self.render_check {
            let idx = ((self.frames - 1) / FRAMES_PER_FIXTURE) as usize;
            if let Some(m) = self.fixtures.get(idx) {
                egui::CentralPanel::default().show(ui, |ui| {
                    // намерения в этом режиме никому не нужны
                    let _ = screens::show(ui, m);
                });
                ctx.request_repaint();
            } else {
                RENDER_CHECK_DONE.store(true, Ordering::SeqCst);
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            return;
        }
        self.drain_worker();

        // закрытие окна: сначала вопрос и упорядоченная остановка узла
        if ctx.input(|i| i.viewport().close_requested()) && !self.model.may_close_window() {
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
    }
}
