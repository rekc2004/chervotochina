#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Общий набор интеграционных тестов узла (этап 18а): хранилище ключей в памяти со счётчиком
//! записей и переключателями отказов, временный каталог, свободный порт, запуск узла и ожидание
//! событий. Подключается из тестов через `#[path = "support/harness.rs"] mod harness;`.

use std::collections::HashMap;
use std::net::UdpSocket;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chervo_core::chervo_friends::{FriendBook, NewFriend, PendingRole};
use chervo_core::chervo_identity::{
    EpochStore, IdentityError, KxPublicKey, ListKeyStore, PairId, PairKey, PublicKey, SecretStore,
    create,
};
use chervo_core::{
    HardenReport, KeyBackend, Node, NodeConfig, NodeError, NodeEvent, NodeEvents, ReceiveLimits,
    harden_process,
};
use zeroize::Zeroizing;

/// Хранилище в памяти. `writes` считает все удавшиеся записи (пары, ключ списка, якорь).
#[derive(Default)]
pub struct MemStore {
    map: Mutex<HashMap<PairId, Zeroizing<Vec<u8>>>>,
    list: Mutex<Option<Zeroizing<Vec<u8>>>>,
    epoch: Mutex<Option<u64>>,
    pub writes: AtomicUsize,
    /// Запись якоря падает (сбой после сохранения файла, S1 L3).
    pub fail_epoch_write: AtomicBool,
    /// Любая операция даёт `StorageLocked`.
    pub locked: AtomicBool,
}

impl MemStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn backend(self: &Arc<Self>) -> Arc<dyn KeyBackend> {
        self.clone()
    }

    pub fn epoch_value(&self) -> Option<u64> {
        *self.epoch.lock().unwrap()
    }

    pub fn set_epoch(&self, e: Option<u64>) {
        *self.epoch.lock().unwrap() = e;
    }

    pub fn drop_list_key(&self) {
        *self.list.lock().unwrap() = None;
    }

    pub fn has_list_key(&self) -> bool {
        self.list.lock().unwrap().is_some()
    }

    pub fn pair_count(&self) -> usize {
        self.map.lock().unwrap().len()
    }

    pub fn write_count(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }

    fn gate(&self) -> Result<(), IdentityError> {
        if self.locked.load(Ordering::SeqCst) {
            Err(IdentityError::StorageLocked)
        } else {
            Ok(())
        }
    }

    fn wrote(&self) {
        self.writes.fetch_add(1, Ordering::SeqCst);
    }
}

impl SecretStore for MemStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        self.gate()?;
        Ok(self
            .map
            .lock()
            .unwrap()
            .get(pair)
            .map(|v| Zeroizing::new(v.to_vec())))
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        self.gate()?;
        self.map
            .lock()
            .unwrap()
            .insert(*pair, Zeroizing::new(blob.to_vec()));
        self.wrote();
        Ok(())
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        self.gate()?;
        self.map.lock().unwrap().remove(pair);
        Ok(())
    }
}

impl ListKeyStore for MemStore {
    fn read_list_key(&self) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        self.gate()?;
        Ok(self
            .list
            .lock()
            .unwrap()
            .as_ref()
            .map(|v| Zeroizing::new(v.to_vec())))
    }

    fn write_list_key(&self, key: &[u8]) -> Result<(), IdentityError> {
        self.gate()?;
        *self.list.lock().unwrap() = Some(Zeroizing::new(key.to_vec()));
        self.wrote();
        Ok(())
    }

    fn delete_list_key(&self) -> Result<(), IdentityError> {
        self.gate()?;
        *self.list.lock().unwrap() = None;
        Ok(())
    }
}

impl EpochStore for MemStore {
    fn read_epoch(&self) -> Result<Option<u64>, IdentityError> {
        self.gate()?;
        Ok(*self.epoch.lock().unwrap())
    }

    fn write_epoch(&self, epoch: u64) -> Result<(), IdentityError> {
        self.gate()?;
        if self.fail_epoch_write.load(Ordering::SeqCst) {
            return Err(IdentityError::StorageUnavailable);
        }
        *self.epoch.lock().unwrap() = Some(epoch);
        self.wrote();
        Ok(())
    }
}

/// Временный каталог, удаляется при уничтожении.
pub struct TestDir(pub PathBuf);

static COUNTER: AtomicUsize = AtomicUsize::new(0);

impl TestDir {
    pub fn new(tag: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let rnd = u128::from_be_bytes(*PairId::generate().unwrap().as_bytes());
        let p = std::env::temp_dir().join(format!(
            "chervo-core-{tag}-{}-{n}-{:08x}",
            std::process::id(),
            rnd as u32
        ));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, p: &str) -> PathBuf {
        self.0.join(p)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Свободный UDP-порт (на момент вызова).
pub fn free_port() -> u16 {
    let s = UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap().port()
}

pub fn hardened() -> HardenReport {
    harden_process()
}

pub fn cfg_in(data: &Path, port: Option<u16>) -> NodeConfig {
    NodeConfig {
        data_dir: Some(data.to_path_buf()),
        receive_limits: ReceiveLimits::default(),
        port_override: port,
    }
}

/// Узел для теста: каталог данных, папка приёма, хранилище, порт.
pub struct Rig {
    pub dir: TestDir,
    pub data: PathBuf,
    pub recv: PathBuf,
    pub store: Arc<MemStore>,
    pub port: u16,
}

impl Rig {
    pub fn new(tag: &str) -> Self {
        let dir = TestDir::new(tag);
        let data = dir.join("data");
        let recv = dir.join("recv");
        std::fs::create_dir_all(&recv).unwrap();
        Self {
            data,
            recv,
            dir,
            store: MemStore::new(),
            port: free_port(),
        }
    }

    pub fn cfg(&self) -> NodeConfig {
        cfg_in(&self.data, Some(self.port))
    }

    pub fn setup(&self) {
        Node::first_run_setup(&self.cfg(), &hardened(), &self.recv, false).unwrap();
    }

    pub fn open(&self) -> Result<(Node, NodeEvents), NodeError> {
        Node::open_with_store_for_tests(self.cfg(), &hardened(), self.store.backend())
    }

    /// Настройки готовы, узел открыт.
    pub fn start(&self) -> (Node, NodeEvents) {
        self.setup();
        self.open().unwrap()
    }

    /// Первый запуск с заданным запасом свободного места: тест не должен зависеть от того,
    /// насколько заполнен диск машины.
    pub fn start_with_min_free(&self, percent: u8) -> (Node, NodeEvents) {
        self.setup();
        let file = self.data.join("settings.v1");
        let text = std::fs::read_to_string(&file).unwrap();
        let edited = text.replace(
            "min_free_percent=10",
            &format!("min_free_percent={percent}"),
        );
        assert_ne!(text, edited);
        std::fs::write(&file, edited).unwrap();
        self.open().unwrap()
    }
}

/// Ждёт событие, подходящее под `pick`; остальные пропускаются. `None`: срок вышел.
pub fn wait_event<T>(
    ev: &NodeEvents,
    timeout: Duration,
    mut pick: impl FnMut(&NodeEvent) -> Option<T>,
) -> Option<T> {
    let end = Instant::now() + timeout;
    loop {
        let left = end.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return None;
        }
        match ev.recv_timeout(left.min(Duration::from_millis(200))) {
            Ok(e) => {
                if let Some(v) = pick(&e) {
                    return Some(v);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
}

/// Сколько-то событий подряд для проверок «ничего не пришло».
pub fn drain(ev: &NodeEvents) -> Vec<NodeEvent> {
    let mut out = Vec::new();
    while let Ok(e) = ev.try_recv() {
        out.push(e);
    }
    out
}

/// Ключи «друга» (чужая сторона пары) для заготовки списка без сети.
pub struct Remote {
    pub ed: PublicKey,
    pub x: KxPublicKey,
    pub key: PairKey,
}

pub fn remote() -> Remote {
    let scratch = MemStore::default();
    let key = create(&scratch, &PairId::generate().unwrap()).unwrap();
    Remote {
        ed: key.public_key(),
        x: key.kx_public(),
        key,
    }
}

/// Заготовка: в каталоге данных уже лежит файл списка с одним другом (изменение безопасности:
/// счётчик 1, якорь 1), как после дружбы. Узел при этом не запускается.
pub fn seed_one_friend(rig: &Rig, name: &str) -> PairId {
    let path = rig.data.join("friends.chfl");
    std::fs::create_dir_all(&rig.data).unwrap();
    let anchor: Arc<dyn EpochStore> = rig.store.clone();
    let mut book = FriendBook::open_anchored(&path, &*rig.store, anchor).unwrap();
    let (pair, key) = book
        .begin_pair(&*rig.store, PendingRole::Inviter, u64::MAX)
        .unwrap();
    let (our_ed, our_x) = (key.public_key(), key.kx_public());
    drop(key);
    let r = remote();
    book.finish_pair(
        &*rig.store,
        &pair,
        NewFriend {
            name: name.to_owned(),
            friend_ed: r.ed,
            friend_x: r.x,
            our_ed,
            our_x,
            addrs: Vec::new(),
            now_unix: 1234,
        },
    )
    .unwrap();
    assert_eq!(rig.store.epoch_value(), Some(1));
    pair
}

/// События узла с памятью: `wait` ищет сначала среди уже полученных, потом ждёт новых.
/// Найденное событие убирается из памяти; остальные остаются для следующих ожиданий.
pub struct Watch {
    pub ev: NodeEvents,
    seen: Vec<NodeEvent>,
}

impl Watch {
    pub fn new(ev: NodeEvents) -> Self {
        Self {
            ev,
            seen: Vec::new(),
        }
    }

    pub fn wait<T>(
        &mut self,
        timeout: Duration,
        mut pick: impl FnMut(&NodeEvent) -> Option<T>,
    ) -> Option<T> {
        let end = Instant::now() + timeout;
        loop {
            if let Some(i) = self.seen.iter().position(|e| pick(e).is_some()) {
                let e = self.seen.remove(i);
                return pick(&e);
            }
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            match self.ev.recv_timeout(left.min(Duration::from_millis(200))) {
                Ok(e) => self.seen.push(e),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    // что пришло до отключения, ещё можно найти
                    if self.seen.iter().any(|e| pick(e).is_some()) {
                        continue;
                    }
                    return None;
                }
            }
        }
    }

    /// Забыть всё накопленное (перед действием, после которого ждём новые события).
    pub fn clear(&mut self) {
        while let Ok(e) = self.ev.try_recv() {
            self.seen.push(e);
        }
        self.seen.clear();
    }

    /// Всё, что есть сейчас (в памяти и в очереди).
    pub fn all(&mut self) -> Vec<NodeEvent> {
        while let Ok(e) = self.ev.try_recv() {
            self.seen.push(e);
        }
        self.seen.clone()
    }
}

/// SHA-256 (FIPS 180-4) для сверки файлов в тестах; проверен на известных векторах в
/// `node_net.rs`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for chunk in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(chunk[4 * i..4 * i + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 32];
    for (i, x) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn sha256_hex_of_file(p: &Path) -> String {
    hex(&sha256(&std::fs::read(p).unwrap()))
}
