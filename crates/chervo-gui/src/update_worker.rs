//! Поток обновлений (этап 19г-2, Р19г-7): сеть (до 30 с) и чтение файлов выпуска не должны
//! задерживать ни окно, ни команды узла, поэтому идут в отдельном потоке по одному заданию.
//! Поток не держит узел. Закрытие его не ждёт: канал заданий закрывается вместе с потоком узла,
//! а незаконченная проверка прерывается выходом процесса.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender, channel};

use chervo_core::update::{self, UpdateCheckPermit, Version};

use crate::model::Outcome;

/// Задание потоку обновлений. Создаёт только поток узла (`worker_ops`), экраны и окно нет.
pub enum UpdateJob {
    /// Один сетевой запрос; разрешение выдал узел при записанном согласии.
    Check {
        permit: UpdateCheckPermit,
        running: Version,
        manual: bool,
    },
    /// Офлайн-сверка скачанных файлов с подписанным списком.
    Verify {
        manifest: PathBuf,
        minisig: PathBuf,
        files: Vec<PathBuf>,
        allow_downgrade: bool,
    },
}

/// Отправитель заданий. Поток живёт, пока жив отправитель.
pub struct UpdateWorker {
    jobs: Sender<UpdateJob>,
}

impl UpdateWorker {
    /// `out`: те же итоги, что у потока узла; `wake` будит окно после каждого итога.
    pub fn spawn(out: Sender<Outcome>, wake: Arc<dyn Fn() + Send + Sync>) -> Option<Self> {
        let (jobs, rx) = channel::<UpdateJob>();
        std::thread::Builder::new()
            .name("chervo-gui-updates".to_owned())
            .spawn(move || run(rx, out, wake))
            .ok()?;
        Some(Self { jobs })
    }

    /// `false`, если потока уже нет.
    pub fn send(&self, job: UpdateJob) -> bool {
        self.jobs.send(job).is_ok()
    }
}

fn run(rx: Receiver<UpdateJob>, out: Sender<Outcome>, wake: Arc<dyn Fn() + Send + Sync>) {
    // задания идут по одному, по порядку
    while let Ok(job) = rx.recv() {
        let outcome = match job {
            UpdateJob::Check {
                permit,
                running,
                manual,
            } => {
                let result = update::check_latest(permit, running);
                Outcome::UpdateChecked { manual, result }
            }
            UpdateJob::Verify {
                manifest,
                minisig,
                files,
                allow_downgrade,
            } => {
                let result =
                    update::verify_release_files(&manifest, &minisig, &files, allow_downgrade);
                Outcome::ReleaseVerified(result)
            }
        };
        let _ = out.send(outcome);
        wake();
    }
}
