#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Два процесса `chervo` по петле (этап 18в): приглашение, проверочный код, дружба, отправка
//! папки, приём, сравнение содержимого, выход. Ввод скриптуется из теста построчно.
//!
//! Хранилище ключей ОС в тесте не используется, а продукт не имеет ни обхода, ни флага: каждый
//! «процесс» это этот же исполняемый файл теста, запущенный заново с одним тестом `host_child`.
//! Он открывает узел через `open_with_store_for_tests` (точка входа ядра за свойством
//! `test-store`, которое включено только в dev-зависимостях) и отдаёт его настоящему циклу
//! `chervo_cli::repl::run` со стандартным вводом. Продуктовый бинарный файл `chervo` этой
//! точки входа не содержит (страж `test_store_guard.rs`).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chervo_core::chervo_identity::{EpochStore, IdentityError, ListKeyStore, PairId, SecretStore};
use chervo_core::{KeyBackend, Node, NodeConfig, ReceiveLimits, harden_process};
use zeroize::Zeroizing;

const ENV_DATA: &str = "CHERVO_SCRIPTED_DATA";
const ENV_PORT: &str = "CHERVO_SCRIPTED_PORT";
const WAIT: Duration = Duration::from_secs(60);

// ---------- хранилище ключей в памяти (только тест) ----------

#[derive(Default)]
struct MemStore {
    map: Mutex<HashMap<PairId, Zeroizing<Vec<u8>>>>,
    list: Mutex<Option<Zeroizing<Vec<u8>>>>,
    epoch: Mutex<Option<u64>>,
}

impl SecretStore for MemStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        let m = self.map.lock().unwrap();
        Ok(m.get(pair).map(|v| Zeroizing::new(v.to_vec())))
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        self.map
            .lock()
            .unwrap()
            .insert(*pair, Zeroizing::new(blob.to_vec()));
        Ok(())
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        self.map.lock().unwrap().remove(pair);
        Ok(())
    }
}

impl ListKeyStore for MemStore {
    fn read_list_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        let l = self.list.lock().unwrap();
        Ok(l.as_ref().map(|v| Zeroizing::new(v.to_vec())))
    }

    fn write_list_key(&self, key: &[u8]) -> Result<(), IdentityError> {
        *self.list.lock().unwrap() = Some(Zeroizing::new(key.to_vec()));
        Ok(())
    }

    fn delete_list_key(&self) -> Result<(), IdentityError> {
        *self.list.lock().unwrap() = None;
        Ok(())
    }
}

impl EpochStore for MemStore {
    fn read_epoch(&self) -> Result<Option<u64>, IdentityError> {
        Ok(*self.epoch.lock().unwrap())
    }

    fn write_epoch(&self, epoch: u64) -> Result<(), IdentityError> {
        *self.epoch.lock().unwrap() = Some(epoch);
        Ok(())
    }
}

// ---------- дочерний процесс ----------

/// Без переменных окружения это пустой тест. С ними: узел с подставным хранилищем и настоящий
/// цикл команд на стандартном вводе; по выходу процесс завершается.
#[test]
fn host_child() {
    let (Ok(data), Ok(port)) = (std::env::var(ENV_DATA), std::env::var(ENV_PORT)) else {
        return;
    };
    let h = harden_process();
    let cfg = NodeConfig {
        data_dir: Some(PathBuf::from(data)),
        receive_limits: ReceiveLimits::default(),
        port_override: Some(port.parse().unwrap()),
    };
    let backend: Arc<dyn KeyBackend> = Arc::new(MemStore::default());
    let (node, events) = Node::open_with_store_for_tests(cfg, &h, backend).unwrap();
    chervo_cli::repl::run(node, events, chervo_cli::input::stdin_lines());
    std::process::exit(0);
}

// ---------- сторона теста ----------

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let p = std::env::temp_dir().join(format!(
            "chervo-cli-scripted-{}-{nanos:x}",
            std::process::id()
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Proc {
    child: Child,
    stdin: Option<ChildStdin>,
    rx: Receiver<String>,
    log: Vec<String>,
    tag: &'static str,
}

fn pump(r: impl std::io::Read + Send + 'static, tx: std::sync::mpsc::Sender<String>) {
    std::thread::spawn(move || {
        for l in BufReader::new(r).lines() {
            let Ok(l) = l else { break };
            if tx.send(l).is_err() {
                break;
            }
        }
    });
}

impl Proc {
    fn start(tag: &'static str, data: &Path, port: u16) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "host_child", "--nocapture", "--test-threads=1"])
            .env(ENV_DATA, data)
            .env(ENV_PORT, port.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let (tx, rx) = channel();
        pump(child.stdout.take().unwrap(), tx.clone());
        pump(child.stderr.take().unwrap(), tx);
        let stdin = child.stdin.take();
        Self {
            child,
            stdin,
            rx,
            log: Vec::new(),
            tag,
        }
    }

    fn send(&mut self, line: &str) {
        let s = self.stdin.as_mut().expect("stdin открыт");
        writeln!(s, "{line}").unwrap();
        s.flush().unwrap();
    }

    fn drain(&mut self, wait: Duration) -> bool {
        match self.rx.recv_timeout(wait) {
            Ok(l) => {
                self.log.push(l);
                true
            }
            Err(RecvTimeoutError::Timeout) => false,
            Err(RecvTimeoutError::Disconnected) => false,
        }
    }

    /// Номер первой строки журнала, содержащей `needle` (журнал ищется с начала: порядок
    /// вывода двух сторон не фиксирован).
    fn wait_idx(&mut self, needle: &str) -> usize {
        let end = Instant::now() + WAIT;
        let mut from = 0;
        loop {
            while from < self.log.len() {
                if self.log[from].contains(needle) {
                    return from;
                }
                from += 1;
            }
            if Instant::now() >= end {
                panic!(
                    "{}: не дождались `{needle}`; вывод:\n{}",
                    self.tag,
                    self.log.join("\n")
                );
            }
            self.drain(Duration::from_millis(100));
        }
    }

    fn wait(&mut self, needle: &str) -> String {
        let i = self.wait_idx(needle);
        self.log[i].clone()
    }

    /// Строка, следующая за найденной.
    fn wait_next(&mut self, needle: &str) -> String {
        let i = self.wait_idx(needle);
        let end = Instant::now() + WAIT;
        while self.log.len() <= i + 1 {
            assert!(
                Instant::now() < end,
                "{}: нет строки после `{needle}`",
                self.tag
            );
            self.drain(Duration::from_millis(100));
        }
        self.log[i + 1].clone()
    }

    fn has(&self, needle: &str) -> bool {
        self.log.iter().any(|l| l.contains(needle))
    }

    fn finish(&mut self) {
        self.send("quit");
        self.wait("Узел остановлен.");
        drop(self.stdin.take());
        let end = Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(st) = self.child.try_wait().unwrap() {
                assert!(st.success(), "{}: код выхода {st:?}", self.tag);
                return;
            }
            assert!(Instant::now() < end, "{}: не вышел за 30 с", self.tag);
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn two_free_ports() -> (u16, u16) {
    let a = UdpSocket::bind("127.0.0.1:0").unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").unwrap();
    (
        a.local_addr().unwrap().port(),
        b.local_addr().unwrap().port(),
    )
}

/// Настройки узла готовы (как после `chervo init`), запас места 0 %: тест не зависит от
/// заполненности диска.
fn prepare(root: &Path, port: u16) -> (PathBuf, PathBuf) {
    let data = root.join("data");
    let recv = root.join("recv");
    std::fs::create_dir_all(&recv).unwrap();
    let cfg = NodeConfig {
        data_dir: Some(data.clone()),
        receive_limits: ReceiveLimits::default(),
        port_override: Some(port),
    };
    Node::first_run_setup(&cfg, &harden_process(), &recv, false).unwrap();
    let file = data.join("settings.v1");
    let text = std::fs::read_to_string(&file).unwrap();
    let edited = text.replace("min_free_percent=10", "min_free_percent=0");
    assert_ne!(text, edited);
    std::fs::write(&file, edited).unwrap();
    (data, recv)
}

fn pseudo(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (x >> 24) as u8
        })
        .collect()
}

fn find_file(dir: &Path, name: &str) -> Option<PathBuf> {
    for e in std::fs::read_dir(dir).ok()? {
        let p = e.ok()?.path();
        if p.is_dir() {
            if let Some(f) = find_file(&p, name) {
                return Some(f);
            }
        } else if p.file_name().is_some_and(|n| n == name) {
            return Some(p);
        }
    }
    None
}

fn digits_of(line: &str) -> String {
    line.split_once(": ")
        .map(|(_, d)| d.trim().to_owned())
        .unwrap()
}

#[test]
fn repl_two_nodes_scripted() {
    if std::env::var(ENV_DATA).is_ok() {
        return; // это дочерний процесс: работает host_child
    }
    let dir = TestDir::new();
    let (pa, pb) = two_free_ports();
    let (data_a, _recv_a) = prepare(&dir.0.join("a"), pa);
    let (data_b, recv_b) = prepare(&dir.0.join("b"), pb);
    let mut a = Proc::start("A", &data_a, pa);
    let mut b = Proc::start("B", &data_b, pb);
    a.wait("Узел запущен.");
    b.wait("Узел запущен.");

    // приглашение с ручным адресом по петле
    a.send(&format!("invite --addr 127.0.0.1:{pa}"));
    let token = a.wait_next("Отправьте этот текст целиком:");
    assert!(token.len() > 20 && !token.contains(' '), "токен: {token}");
    assert!(
        a.wait("Внимание: в этом тексте ваш IP-адрес")
            .contains("IP")
    );
    b.send("accept-invite");
    b.wait("Вставьте текст приглашения одной строкой:");
    b.send(&token);

    // проверочный код на обеих сторонах: 8 цифр группами 4+4, одинаковый
    let sas_a = digits_of(&a.wait("Проверочный код:"));
    let sas_b = digits_of(&b.wait("Проверочный код:"));
    assert_eq!(sas_a, sas_b, "коды не совпали");
    let ok = sas_a.len() == 9
        && sas_a
            .char_indices()
            .all(|(i, c)| if i == 4 { c == ' ' } else { c.is_ascii_digit() });
    assert!(ok, "формат кода: {sas_a}");
    a.send("sas yes Боб");
    b.send("sas yes Алиса");
    a.wait("Друг добавлен.");
    b.wait("Друг добавлен.");
    a.wait("Боб на связи");
    b.wait("Алиса на связи");
    a.send("friends");
    a.wait("1. Боб — активен");

    // папка из трёх файлов, один вложенный
    let src = dir.0.join("src").join("pack");
    let files: [(&str, Vec<u8>); 3] = [
        ("one.txt", pseudo(5_000, 1)),
        ("two.bin", pseudo(300_000, 2)),
        ("three.dat", pseudo(70_000, 3)),
    ];
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("one.txt"), &files[0].1).unwrap();
    std::fs::write(src.join("sub").join("two.bin"), &files[1].1).unwrap();
    std::fs::write(src.join("three.dat"), &files[2].1).unwrap();

    a.send(&format!("send Боб \"{}\"", src.display()));
    a.wait("создана: ждём ответа друга.");
    b.wait("Входящее предложение от Алиса");
    b.send("offers");
    b.wait("Предложение 1 от Алиса: файлов 3");
    b.wait("two.bin");
    b.send("accept 1");
    // неизвестные типы файлов требуют вопроса о доверии
    let end = Instant::now() + WAIT;
    while !b.has("Приём начат.") {
        if b.has("Принять? Введите") && !b.has("[ответ дан]") {
            b.log.push("[ответ дан]".to_owned());
            b.send("да");
        }
        assert!(
            Instant::now() < end,
            "приём не начался:\n{}",
            b.log.join("\n")
        );
        b.drain(Duration::from_millis(100));
    }
    a.wait("Передача завершена.");
    b.wait("Передача завершена.");

    for (name, bytes) in &files {
        let got = find_file(&recv_b, name).unwrap_or_else(|| panic!("нет файла {name}"));
        assert_eq!(&std::fs::read(got).unwrap(), bytes, "{name}: содержимое");
    }

    // удаление друга оставляет текст отзыва; забыть его можно только после слова ДА
    a.send("remove Боб");
    a.wait("Друг удалён. Чтобы он узнал");
    a.send("forget-retired Боб");
    a.wait("Для подтверждения введите ДА:");
    a.send("нет");
    a.wait("Отменено: текст отзыва сохранён.");
    a.send("revoke-text");
    a.wait("Отзыв для друга Боб.");
    a.send("forget-retired Боб");
    a.send("ДА");
    a.wait("Текст отзыва забыт.");
    a.send("revoke-text");
    a.wait("Текстов отзыва для передачи нет.");

    a.finish();
    b.finish();
}

/// Ctrl+C и SIGTERM идут одним путём с `quit`. Проверка сигналом только на unix (на Windows
/// Ctrl+C в процесс без консоли из теста не послать).
#[cfg(unix)]
#[test]
fn sigterm_shuts_the_node_down_in_order() {
    let dir = TestDir::new();
    let (p, _) = two_free_ports();
    let (data, _recv) = prepare(&dir.0.join("a"), p);
    let mut a = Proc::start("A", &data, p);
    a.wait("Узел запущен.");
    // подписка на сигнал оформляется на фоновой среде узла
    std::thread::sleep(Duration::from_millis(500));
    let st = Command::new("kill")
        .args(["-TERM", &a.child.id().to_string()])
        .status()
        .unwrap();
    assert!(st.success());
    a.wait("Получен сигнал прерывания");
    a.wait("Узел остановлен.");
    drop(a.stdin.take());
    let end = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(st) = a.child.try_wait().unwrap() {
            assert!(st.success(), "код выхода {st:?}");
            break;
        }
        assert!(Instant::now() < end, "не вышел за 30 с");
        std::thread::sleep(Duration::from_millis(50));
    }
}
