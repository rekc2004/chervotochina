#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stderr
)]
//! Сетевые тесты передачи файлов (X4): два настоящих движка с `QuinnTransport` на 127.0.0.1,
//! поверх них `Transfers`. Образцы медиа создаются в самом тесте (скачанных файлов нет).
//! Каждый тест сверяет принятые файлы побайтно и по SHA-256 с исходными.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chervo_addr::{AddrSource, KnownAddr, RouteSources};
use chervo_connect::{AllowSet, Clock, ConnectConfig, Engine, RouteProbe, SystemClock};
use chervo_friends::{FriendBook, NewFriend, PendingRole};
use chervo_identity::{IdentityError, ListKeyStore, PairId, PairKey, SecretStore};
use chervo_transfer::{
    AskAlways, GeneratedNames, PauseReason, SourceFile, TransferConfig, TransferEvent,
    TransferEvents, TransferKey, Transfers, block_len, file_root, layout, leaf_hash,
    state_dir_name,
};
use chervo_transport::{Connection, PeerFilter, Transport};
use chervo_transport_quinn::{QuinnConfig, QuinnTransport};
use zeroize::Zeroizing;

// ------------------------------------------------------------------- помощники

#[derive(Default)]
struct MemStore {
    map: Mutex<HashMap<PairId, Zeroizing<Vec<u8>>>>,
    list: Mutex<Option<Zeroizing<Vec<u8>>>>,
}

impl SecretStore for MemStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(self
            .map
            .lock()
            .unwrap()
            .get(pair)
            .map(|v| Zeroizing::new(v.to_vec())))
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
        Ok(self
            .list
            .lock()
            .unwrap()
            .as_ref()
            .map(|v| Zeroizing::new(v.to_vec())))
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

static DIR_SEQ: AtomicUsize = AtomicUsize::new(0);

/// Каталог в temp; удаляется целиком при уничтожении.
struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Arc<Self> {
        let n = DIR_SEQ.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("chervo-xfer-net-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Arc::new(Self(p))
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn file(&self) -> PathBuf {
        self.0.join("friends.chfl")
    }

    fn list(&self) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(&self.0)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        v.sort();
        v
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Probe;

impl RouteProbe for Probe {
    fn probe(&self) -> RouteSources {
        RouteSources {
            v4: Some(Ipv4Addr::LOCALHOST),
            ..RouteSources::default()
        }
    }

    fn source_for(&self, _target: SocketAddr) -> Option<std::net::IpAddr> {
        None
    }
}

fn quinn_cfg() -> QuinnConfig {
    QuinnConfig {
        auth_deadline: Duration::from_secs(5),
        per_ip_max: 1000,
        ..QuinnConfig::default()
    }
}

fn engine_cfg() -> ConnectConfig {
    ConnectConfig {
        tick: Duration::from_millis(100),
        probe_interval: Duration::from_millis(200),
        fast_period: Duration::from_millis(300),
        per_ip_dials: 1000,
        addr_info_out_interval: Duration::from_secs(1),
        ..ConnectConfig::default()
    }
}

struct Bound {
    t: Arc<QuinnTransport>,
    allow: Arc<AllowSet>,
    addr: SocketAddr,
}

fn bind(port: u16) -> Bound {
    let allow = AllowSet::new();
    let filter: Arc<dyn PeerFilter> = allow.clone();
    let t = Arc::new(
        QuinnTransport::bind(
            SocketAddr::from(([127, 0, 0, 1], port)),
            quinn_cfg(),
            filter,
        )
        .unwrap(),
    );
    let addr = SocketAddr::from(([127, 0, 0, 1], t.local_addrs()[0].port()));
    Bound { t, allow, addr }
}

type Eng = Engine<QuinnTransport, MemStore>;

/// Один участник: движок, транспорт, передачи, каталоги.
struct Side {
    engine: Arc<Eng>,
    t: Arc<QuinnTransport>,
    store: Arc<MemStore>,
    bookdir: Arc<TestDir>,
    partial: Arc<TestDir>,
    dest: Arc<TestDir>,
    tr: Transfers<Eng>,
    ev: TransferEvents,
    addr: SocketAddr,
    cfg: TransferConfig,
}

fn start_side(
    b: Bound,
    store: Arc<MemStore>,
    bookdir: Arc<TestDir>,
    book: Option<FriendBook>,
    partial: Arc<TestDir>,
    dest: Arc<TestDir>,
    cfg: TransferConfig,
) -> Side {
    let book = book.unwrap_or_else(|| FriendBook::open(&bookdir.file(), &*store).unwrap());
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::new());
    let probe: Arc<dyn RouteProbe> = Arc::new(Probe);
    let (engine, _events) = Engine::start(
        b.t.clone(),
        b.allow,
        book,
        store.clone(),
        clock,
        probe,
        engine_cfg(),
    )
    .unwrap();
    let engine = Arc::new(engine);
    let inbox = engine
        .stream_inbox(&[
            chervo_transfer::STREAM_TRANSFER_CTL,
            chervo_transfer::STREAM_TRANSFER_DATA,
        ])
        .unwrap();
    let (tr, ev) = Transfers::start(
        engine.clone(),
        inbox,
        Arc::new(AskAlways),
        Arc::new(GeneratedNames {
            dest_dir: dest.path().to_path_buf(),
        }),
        cfg.clone(),
    )
    .unwrap();
    Side {
        engine,
        t: b.t,
        store,
        bookdir,
        partial,
        dest,
        tr,
        ev,
        addr: b.addr,
        cfg,
    }
}

fn known(addr: SocketAddr) -> KnownAddr {
    KnownAddr {
        addr,
        source: AddrSource::Invite,
        last_seen_unix: SystemClock::new().now_unix(),
        short_lived: false,
        hint: false,
    }
}

/// По умолчанию набирает только получатель `y` (адрес `y` отправителю `x` неизвестен): так нет
/// встречного набора двух соединений. `CHERVO_NET_BOTH_DIAL=1` возвращает набор с обеих сторон
/// (в нём тесты нестабильны: см. отчёт X4).
fn both_dial() -> bool {
    std::env::var("CHERVO_NET_BOTH_DIAL").is_ok_and(|v| v == "1")
}

fn new_friend(theirs: &PairKey, ours: &PairKey, addr: Option<SocketAddr>) -> NewFriend {
    NewFriend {
        name: "friend".to_owned(),
        friend_ed: theirs.public_key(),
        friend_x: theirs.kx_public(),
        our_ed: ours.public_key(),
        our_x: ours.kx_public(),
        addrs: addr.map(known).into_iter().collect(),
        now_unix: SystemClock::new().now_unix(),
    }
}

/// Пара участников `x` и `y` с зеркальной дружбой, оба соединены.
struct Duo {
    x: Side,
    y: Side,
    px: PairId,
    py: PairId,
}

fn tcfg(partial: &Path) -> TransferConfig {
    let mut c = TransferConfig::new(partial.to_path_buf());
    c.progress_interval = Duration::from_millis(20);
    c.checkpoint_interval = Duration::from_millis(100);
    c
}

async fn duo(fx: impl FnOnce(&mut TransferConfig), fy: impl FnOnce(&mut TransferConfig)) -> Duo {
    let (sx, sy) = (Arc::new(MemStore::default()), Arc::new(MemStore::default()));
    let (dx, dy) = (TestDir::new(), TestDir::new());
    let mut bx_book = FriendBook::open(&dx.file(), &*sx).unwrap();
    let mut by_book = FriendBook::open(&dy.file(), &*sy).unwrap();
    let (bx, by) = (bind(0), bind(0));
    let (px, kx) = bx_book
        .begin_pair(&*sx, PendingRole::Inviter, u64::MAX)
        .unwrap();
    let (py, ky) = by_book
        .begin_pair(&*sy, PendingRole::Invitee, u64::MAX)
        .unwrap();
    bx_book
        .finish_pair(
            &*sx,
            &px,
            new_friend(&ky, &kx, both_dial().then_some(by.addr)),
        )
        .unwrap();
    by_book
        .finish_pair(&*sy, &py, new_friend(&kx, &ky, Some(bx.addr)))
        .unwrap();
    let (partial_x, dest_x, partial_y, dest_y) = (
        TestDir::new(),
        TestDir::new(),
        TestDir::new(),
        TestDir::new(),
    );
    let (mut cx, mut cy) = (tcfg(partial_x.path()), tcfg(partial_y.path()));
    fx(&mut cx);
    fy(&mut cy);
    let x = start_side(bx, sx, dx, Some(bx_book), partial_x, dest_x, cx);
    let y = start_side(by, sy, dy, Some(by_book), partial_y, dest_y, cy);
    let d = Duo { x, y, px, py };
    assert!(
        wait_conn(&d.x.engine, &d.px, 20).await,
        "x not connected to y"
    );
    assert!(
        wait_conn(&d.y.engine, &d.py, 20).await,
        "y not connected to x"
    );
    settle(&d).await;
    d
}

/// Встречный набор (оба друга знают адреса друг друга) оставляет одно соединение, второе
/// закрывается: ждём, пока номера соединений у обоих концов перестанут меняться.
async fn settle(d: &Duo) {
    let ids = |d: &Duo| {
        (
            d.x.engine.connection(&d.px).map(|c| c.conn_id()),
            d.y.engine.connection(&d.py).map(|c| c.conn_id()),
        )
    };
    let end = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let before = ids(d);
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let after = ids(d);
        if before == after && after.0.is_some() && after.1.is_some() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < end,
            "connections did not settle"
        );
    }
}

async fn wait_conn(engine: &Eng, pair: &PairId, secs: u64) -> bool {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < end {
        if engine.connection(pair).is_some() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

// ---------------------------------------------------------------------- события

fn key_of(e: &TransferEvent) -> TransferKey {
    match e {
        TransferEvent::OfferReceived { key }
        | TransferEvent::OfferAnswered { key, .. }
        | TransferEvent::Started { key }
        | TransferEvent::Progress { key, .. }
        | TransferEvent::Verifying { key }
        | TransferEvent::Preparing { key, .. }
        | TransferEvent::FileReceived { key, .. }
        | TransferEvent::FileDelivered { key, .. }
        | TransferEvent::FileFailed { key, .. }
        | TransferEvent::Paused { key, .. }
        | TransferEvent::Resumed { key }
        | TransferEvent::Completed { key }
        | TransferEvent::Cancelled { key, .. }
        | TransferEvent::Failed { key, .. } => *key,
        _ => panic!("unknown event"),
    }
}

async fn wait_ev(
    tag: &str,
    ev: &mut TransferEvents,
    secs: u64,
    f: impl Fn(&TransferEvent) -> bool,
) -> TransferEvent {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let left = end.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(left, ev.recv()).await {
            Ok(Some(e)) if f(&e) => return e,
            Ok(Some(e @ (TransferEvent::Failed { .. } | TransferEvent::Cancelled { .. }))) => {
                panic!("transfer ended while waiting: {e:?}")
            }
            Ok(Some(_)) => {}
            Ok(None) => panic!("events closed"),
            Err(_) => panic!("timed out waiting for event {tag}"),
        }
    }
}

/// Принимает предложение (получатель всегда отвечает сам).
async fn accept(y: &mut Side) -> TransferKey {
    let e = wait_ev("accept", &mut y.ev, 30, |e| {
        matches!(e, TransferEvent::OfferReceived { .. })
    })
    .await;
    let k = key_of(&e);
    y.tr.respond(&k, true).unwrap();
    k
}

/// Ждёт, пока выполнено не меньше 40 % работы (по событию `Progress` получателя).
async fn wait_40(y: &mut Side, kb: &TransferKey) {
    wait_ev("wait40", &mut y.ev, 120, |e| {
        matches!(e, TransferEvent::Progress { key, done, total }
            if key == kb && *done * 10 >= *total * 4)
    })
    .await;
}

/// `Completed` на обеих сторонах; пока ждёт, раз в секунду подталкивает набор друг друга.
/// Возвращает события получателя (кроме `Progress`) с моментом получения.
async fn finish(
    x: &mut Side,
    kx: &TransferKey,
    px: &PairId,
    y: &mut Side,
    ky: &TransferKey,
    py: &PairId,
    secs: u64,
) -> Vec<(Instant, TransferEvent)> {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    let (mut gx, mut gy) = (false, false);
    let mut seen = Vec::new();
    while !(gx && gy) {
        assert!(
            tokio::time::Instant::now() < end,
            "transfer did not complete in time (sender done: {gx}, receiver done: {gy})"
        );
        tokio::select! {
            e = x.ev.recv(), if !gx => match e {
                Some(TransferEvent::Completed { key }) if key == *kx => gx = true,
                Some(e @ (TransferEvent::Failed { .. } | TransferEvent::Cancelled { .. })) =>
                    panic!("sender side ended: {e:?}"),
                Some(_) => {}
                None => panic!("sender events closed"),
            },
            e = y.ev.recv(), if !gy => match e {
                Some(TransferEvent::Completed { key }) if key == *ky => {
                    seen.push((Instant::now(), TransferEvent::Completed { key }));
                    gy = true;
                }
                Some(e @ (TransferEvent::Failed { .. } | TransferEvent::Cancelled { .. })) =>
                    panic!("receiver side ended: {e:?}"),
                Some(TransferEvent::Progress { .. }) => {}
                Some(e) => seen.push((Instant::now(), e)),
                None => panic!("receiver events closed"),
            },
            () = tokio::time::sleep(Duration::from_secs(1)) => {
                let _ = x.engine.connect_now(px);
                let _ = y.engine.connect_now(py);
            }
        }
    }
    seen
}

/// Ждёт, пока оба конца получат новое живое соединение (номер отличается от `old_*`).
async fn wait_new_conn(d: &Duo, old_x: u64, old_y: u64, secs: u64) {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    loop {
        let _ = d.x.engine.connect_now(&d.px);
        let _ = d.y.engine.connect_now(&d.py);
        let nx = d.x.engine.connection(&d.px).map(|c| c.conn_id());
        let ny = d.y.engine.connection(&d.py).map(|c| c.conn_id());
        if nx.is_some_and(|n| n != old_x) && ny.is_some_and(|n| n != old_y) {
            return;
        }
        if tokio::time::Instant::now() >= end {
            let xc = match d.x.engine.connection(&d.px) {
                Some(c) => tokio::time::timeout(Duration::ZERO, c.closed())
                    .await
                    .is_ok(),
                None => false,
            };
            let yc = match d.y.engine.connection(&d.py) {
                Some(c) => tokio::time::timeout(Duration::ZERO, c.closed())
                    .await
                    .is_ok(),
                None => false,
            };
            panic!(
                "no new connection in time: old=({old_x},{old_y}) now=({nx:?},{ny:?}) closed x={xc} y={yc}"
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

// ----------------------------------------------------------------------- данные

/// Псевдослучайный мегабайт (xorshift64*).
fn rand_mib(seed: u64, n: usize) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    let mut out = vec![0u8; n];
    for c in out.chunks_mut(8) {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        let v = x.wrapping_mul(0x2545_F491_4F6C_DD1D).to_le_bytes();
        let k = c.len();
        c.copy_from_slice(&v[..k]);
    }
    out
}

/// `n` байт: мегабайтная основа, у каждого мегабайта своя метка (быстро, блоки различны).
fn rand_bytes(seed: u64, n: usize) -> Vec<u8> {
    let base = rand_mib(seed, n.min(1 << 20));
    let mut out = Vec::with_capacity(n);
    let mut j = 0u64;
    while out.len() < n {
        let start = out.len();
        let take = (n - start).min(base.len());
        out.extend_from_slice(&base[..take]);
        if take >= 16 {
            out[start..start + 8].copy_from_slice(&j.to_le_bytes());
            out[start + 8..start + 16].copy_from_slice(&seed.to_le_bytes());
        }
        j += 1;
    }
    out
}

fn mp4_box(kind: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(payload.len() + 8);
    b.extend_from_slice(&u32::try_from(payload.len() + 8).unwrap().to_be_bytes());
    b.extend_from_slice(kind);
    b.extend_from_slice(payload);
    b
}

fn png_chunk(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(&u32::try_from(data.len()).unwrap().to_be_bytes());
    c.extend_from_slice(kind);
    c.extend_from_slice(data);
    c.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
    c
}

/// Образцы форматов фото, видео и звука (структура настоящая, содержимое случайное).
fn media_samples() -> Vec<(String, Vec<u8>)> {
    let mut v: Vec<(String, Vec<u8>)> = Vec::new();
    // JPEG с сегментом EXIF (APP1)
    let mut jpg = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    jpg.extend_from_slice(b"JFIF\0\x01\x01\x00\x00\x01\x00\x01\x00\x00");
    let mut exif = b"Exif\0\0II*\0\x08\0\0\0".to_vec();
    exif.extend_from_slice(&rand_mib(1, 1000));
    jpg.extend_from_slice(&[0xFF, 0xE1]);
    jpg.extend_from_slice(&u16::try_from(exif.len() + 2).unwrap().to_be_bytes());
    jpg.extend_from_slice(&exif);
    jpg.extend_from_slice(&[0xFF, 0xDA]);
    jpg.extend_from_slice(&rand_bytes(2, 3 << 20));
    jpg.extend_from_slice(&[0xFF, 0xD9]);
    v.push(("photo.jpg".into(), jpg));
    // PNG с текстовым блоком tEXt
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    png.extend(png_chunk(b"IHDR", &[0, 0, 4, 0, 0, 0, 3, 0, 8, 2, 0, 0, 0]));
    png.extend(png_chunk(b"tEXt", b"Comment\0chervo test"));
    png.extend(png_chunk(b"IDAT", &rand_bytes(3, 2 << 20)));
    png.extend(png_chunk(b"IEND", &[]));
    v.push(("scan.png".into(), png));
    // HEIC (ISO-BMFF, ftyp heic)
    let mut heic = mp4_box(b"ftyp", b"heic\0\0\0\0mif1heic");
    heic.extend(mp4_box(b"meta", &rand_mib(4, 4096)));
    heic.extend(mp4_box(b"mdat", &rand_bytes(5, 4 << 20)));
    v.push(("img.heic".into(), heic));
    // MP4: ftyp, moov, mdat 40 МиБ
    let mut mp4 = mp4_box(b"ftyp", b"isom\0\0\x02\0isomiso2avc1mp41");
    mp4.extend(mp4_box(b"moov", &rand_mib(6, 20 << 10)));
    mp4.extend(mp4_box(b"mdat", &rand_bytes(7, 40 << 20)));
    v.push(("clip.mp4".into(), mp4));
    // MOV: moov в конце файла
    let mut mov = mp4_box(b"ftyp", b"qt  \0\0\0\0qt  ");
    mov.extend(mp4_box(b"mdat", &rand_bytes(8, 40 << 20)));
    mov.extend(mp4_box(b"moov", &rand_mib(9, 30 << 10)));
    v.push(("видео.mov".into(), mov));
    // WAV (RIFF) 10 МиБ
    let pcm = rand_bytes(10, 10 << 20);
    let mut wav = b"RIFF".to_vec();
    wav.extend_from_slice(&u32::try_from(pcm.len() + 36).unwrap().to_le_bytes());
    wav.extend_from_slice(
        b"WAVEfmt \x10\0\0\0\x01\0\x02\0\x44\xAC\0\0\x10\xB1\x02\0\x04\0\x10\0data",
    );
    wav.extend_from_slice(&u32::try_from(pcm.len()).unwrap().to_le_bytes());
    wav.extend_from_slice(&pcm);
    v.push(("voice.wav".into(), wav));
    // FLAC: метка, STREAMINFO, случайные кадры
    let mut flac = b"fLaC\x80\0\0\x22".to_vec();
    flac.extend_from_slice(&rand_mib(11, 34));
    flac.extend_from_slice(&rand_bytes(12, 6 << 20));
    v.push(("song.flac".into(), flac));
    // MP3 с тегом ID3v2
    let mut mp3 = b"ID3\x03\0\0\0\0\x08\0".to_vec();
    mp3.extend_from_slice(&rand_mib(13, 1024));
    mp3.extend_from_slice(&[0xFF, 0xFB, 0x90, 0x00]);
    mp3.extend_from_slice(&rand_bytes(14, 5 << 20));
    v.push(("track.mp3".into(), mp3));
    // крупный файл случайных байт
    v.push(("big.bin".into(), rand_bytes(15, 200 << 20)));
    // пустой и размер на единицу больше мегабайта
    v.push(("empty.dat".into(), Vec::new()));
    v.push(("odd.bin".into(), rand_bytes(16, (1 << 20) + 1)));
    v
}

fn write_sources(dir: &Path, files: &[(String, Vec<u8>)]) -> Vec<SourceFile> {
    files
        .iter()
        .enumerate()
        .map(|(i, (name, data))| {
            // на диске имя служебное: путь не зависит от проверяемых имён
            let path = dir.join(format!("src{i}.bin"));
            std::fs::write(&path, data).unwrap();
            SourceFile {
                path,
                name: name.clone(),
            }
        })
        .collect()
}

fn sha256_stream(mut f: impl Read) -> [u8; 32] {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA256);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    out
}

/// Побайтное и по SHA-256 равенство двух файлов; размеры равны.
fn assert_identical(src: &Path, dst: &Path) {
    let (ms, md) = (
        std::fs::metadata(src).unwrap(),
        std::fs::metadata(dst).unwrap(),
    );
    assert_eq!(ms.len(), md.len(), "size differs");
    let (mut a, mut b) = (
        std::fs::File::open(src).unwrap(),
        std::fs::File::open(dst).unwrap(),
    );
    let (mut ba, mut bb) = (vec![0u8; 1 << 20], vec![0u8; 1 << 20]);
    loop {
        let n = a.read(&mut ba).unwrap();
        if n == 0 {
            break;
        }
        b.read_exact(&mut bb[..n]).unwrap();
        assert!(ba[..n] == bb[..n], "bytes differ");
    }
    assert_eq!(
        sha256_stream(std::fs::File::open(src).unwrap()),
        sha256_stream(std::fs::File::open(dst).unwrap()),
        "sha256 differs"
    );
}

fn final_name(k: &TransferKey, index: usize) -> String {
    format!("chervo-{}-{index}", state_dir_name(&k.pair, &k.id))
}

/// Все файлы предложения на месте под итоговыми именами, лишнего в каталоге нет.
fn assert_all_placed(dest: &TestDir, kb: &TransferKey, srcs: &[SourceFile]) {
    let names = dest.list();
    assert_eq!(names.len(), srcs.len(), "extra or missing files: {names:?}");
    for (i, s) in srcs.iter().enumerate() {
        let n = final_name(kb, i);
        assert!(names.contains(&n), "file {i} missing");
        assert_identical(&s.path, &dest.path().join(n));
    }
}

/// Каталог временных данных пустеет после завершения (с короткой паузой на уборку).
async fn assert_partial_empty(partial: &TestDir) {
    for _ in 0..50 {
        if partial.list().is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("partial dir not empty: {:?}", partial.list());
}

/// В каталоге назначения только целиком принятые файлы: каждое имя соответствует файлу,
/// равному исходному; `absent` не имеет итогового имени вообще.
fn assert_dest_only_complete(dest: &TestDir, kb: &TransferKey, srcs: &[SourceFile], absent: usize) {
    for n in dest.list() {
        let idx: usize = n.rsplit('-').next().unwrap().parse().unwrap();
        assert!(n.starts_with("chervo-"), "unexpected file {n}");
        assert_ne!(idx, absent, "interrupted file visible under final name");
        assert_eq!(n, final_name(kb, idx));
        assert_identical(&srcs[idx].path, &dest.path().join(&n));
    }
}

fn is_ours_file(n: &str) -> bool {
    if matches!(n, "state" | "state.tmp" | "names" | "names.tmp") {
        return true;
    }
    let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
    for suffix in [".part", ".hashes", ".hashes.tmp"] {
        if let Some(stem) = n.strip_suffix(suffix) {
            return digits(stem);
        }
    }
    false
}

/// Во временном каталоге только каталоги состояния (32 hex) с нашими файлами.
fn assert_partial_only_ours(partial: &TestDir) {
    for d in partial.list() {
        assert!(
            d.len() == 32 && d.bytes().all(|b| b.is_ascii_hexdigit()),
            "foreign entry {d}"
        );
        for e in std::fs::read_dir(partial.path().join(&d)).unwrap() {
            let n = e.unwrap().file_name().to_string_lossy().into_owned();
            assert!(is_ours_file(&n), "unexpected file {n}");
        }
    }
}

// ------------------------------------------------------------------------ тесты

#[tokio::test]
async fn net_media_samples_identical() {
    let mut d = duo(|_| {}, |_| {}).await;
    let src = TestDir::new();
    let files = write_sources(src.path(), &media_samples());
    let kx = d.x.tr.send(&d.px, files.clone()).unwrap();
    let ky = accept(&mut d.y).await;
    assert_eq!(kx.id, ky.id);
    finish(&mut d.x, &kx, &d.px, &mut d.y, &ky, &d.py, 300).await;
    assert_all_placed(&d.y.dest, &ky, &files);
    assert_partial_empty(&d.y.partial).await;
    assert!(d.x.dest.list().is_empty());
}

/// Обрыв соединения на ~40 %: пауза, новое соединение, возобновление, равенство.
#[tokio::test]
async fn net_disconnect_mid_transfer_resumes() {
    let mut d = duo(
        |_| {},
        |c| {
            c.streams = 2;
            c.per_stream_window = 1;
        },
    )
    .await;
    let src = TestDir::new();
    let files = write_sources(
        src.path(),
        &[
            ("a.bin".into(), rand_bytes(21, 3 << 20)),
            ("b.bin".into(), rand_bytes(22, 160 << 20)),
        ],
    );
    let kx = d.x.tr.send(&d.px, files.clone()).unwrap();
    let ky = accept(&mut d.y).await;
    wait_40(&mut d.y, &ky).await;
    let (old_x, old_y) = (
        d.x.engine.connection(&d.px).unwrap().conn_id(),
        d.y.engine.connection(&d.py).unwrap().conn_id(),
    );
    // закрываются оба конца: иначе живая запись второго конца может держаться за мёртвое
    // соединение, пока то не заметит обрыв сам (поведение движка при явном закрытии одной стороной)
    d.y.engine.connection(&d.py).unwrap().close();
    d.x.engine.connection(&d.px).unwrap().close();
    wait_ev("disc_paused", &mut d.y.ev, 30, |e| {
        matches!(
            e,
            TransferEvent::Paused {
                reason: PauseReason::Disconnected,
                ..
            }
        )
    })
    .await;
    // пока пауза, недокачанный файл не виден под итоговым именем
    assert_dest_only_complete(&d.y.dest, &ky, &files, 1);
    assert_partial_only_ours(&d.y.partial);
    wait_new_conn(&d, old_x, old_y, 60).await;
    wait_ev("disc_resumed", &mut d.y.ev, 60, |e| {
        matches!(e, TransferEvent::Resumed { .. })
    })
    .await;
    finish(&mut d.x, &kx, &d.px, &mut d.y, &ky, &d.py, 300).await;
    assert_all_placed(&d.y.dest, &ky, &files);
    assert_partial_empty(&d.y.partial).await;
}

/// Получатель меняет локальное гнездо (`rebind`) на ~40 %: миграция или возобновление.
#[tokio::test]
async fn net_rebind_mid_transfer_completes() {
    let mut d = duo(
        |_| {},
        |c| {
            c.streams = 2;
            c.per_stream_window = 1;
        },
    )
    .await;
    let src = TestDir::new();
    let files = write_sources(
        src.path(),
        &[
            ("a.bin".into(), rand_bytes(31, 2 << 20)),
            ("b.bin".into(), rand_bytes(32, 160 << 20)),
        ],
    );
    let kx = d.x.tr.send(&d.px, files.clone()).unwrap();
    let ky = accept(&mut d.y).await;
    wait_40(&mut d.y, &ky).await;
    let sock = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
    d.y.t.rebind(sock).unwrap();
    finish(&mut d.x, &kx, &d.px, &mut d.y, &ky, &d.py, 300).await;
    assert_all_placed(&d.y.dest, &ky, &files);
    assert_partial_empty(&d.y.partial).await;
}

/// Недокачанный файл не виден под итоговым именем ни в ходе, ни после отмены.
#[tokio::test]
async fn net_interrupted_file_not_visible_under_final_name() {
    let mut d = duo(
        |_| {},
        |c| {
            c.streams = 2;
            c.per_stream_window = 1;
        },
    )
    .await;
    let src = TestDir::new();
    let files = write_sources(
        src.path(),
        &[
            ("a.bin".into(), rand_bytes(41, 3 << 20)),
            ("b.bin".into(), rand_bytes(42, 160 << 20)),
        ],
    );
    let kx = d.x.tr.send(&d.px, files.clone()).unwrap();
    let ky = accept(&mut d.y).await;
    wait_40(&mut d.y, &ky).await;
    assert_dest_only_complete(&d.y.dest, &ky, &files, 1);
    assert_partial_only_ours(&d.y.partial);
    assert_eq!(d.y.partial.list().len(), 1);
    d.y.tr.cancel(&ky).unwrap();
    wait_ev("interr_cancelled", &mut d.y.ev, 30, |e| {
        matches!(e, TransferEvent::Cancelled { .. })
    })
    .await;
    assert_partial_empty(&d.y.partial).await;
    assert_dest_only_complete(&d.y.dest, &ky, &files, 1);
    let _ = kx;
}

/// Получатель перезапущен целиком (движок и транспорт на том же порту, `Transfers` заново),
/// на диске испорчено начало временных файлов: добирается недостающее, равенство.
#[tokio::test]
async fn net_receiver_restart_resumes() {
    let mut d = duo(
        |_| {},
        |c| {
            c.streams = 2;
            c.per_stream_window = 1;
        },
    )
    .await;
    let src = TestDir::new();
    let files = write_sources(
        src.path(),
        &[
            ("a.bin".into(), rand_bytes(51, 3 << 20)),
            ("b.bin".into(), rand_bytes(52, 160 << 20)),
        ],
    );
    let kx = d.x.tr.send(&d.px, files.clone()).unwrap();
    let ky = accept(&mut d.y).await;
    wait_40(&mut d.y, &ky).await;
    // остановка получателя
    let Side {
        engine,
        t,
        store,
        bookdir,
        partial,
        dest,
        tr,
        ev,
        addr,
        cfg,
    } = d.y;
    tr.shutdown();
    tr.wait_stopped().await;
    drop(tr);
    drop(ev);
    engine.shutdown();
    t.shutdown();
    drop(engine);
    drop(t);
    // пока получатель выключен: порча начала временных файлов, итоговых имён нет
    assert_dest_only_complete(&dest, &ky, &files, 1);
    let sdir = partial.path().join(state_dir_name(&ky.pair, &ky.id));
    let mut corrupted = 0;
    for e in std::fs::read_dir(&sdir).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "part") {
            let mut f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&p)
                .unwrap();
            let len = f.metadata().unwrap().len();
            for off in [17u64, (1 << 20) + 17] {
                if off < len {
                    let mut byte = [0u8; 1];
                    f.seek(SeekFrom::Start(off)).unwrap();
                    f.read_exact(&mut byte).unwrap();
                    byte[0] ^= 0x80;
                    f.seek(SeekFrom::Start(off)).unwrap();
                    f.write_all(&byte).unwrap();
                    corrupted += 1;
                }
            }
        }
    }
    assert!(corrupted > 0, "no partial data to corrupt");
    // запуск на том же порту
    let mut rebound = None;
    for _ in 0..50 {
        let allow = AllowSet::new();
        let filter: Arc<dyn PeerFilter> = allow.clone();
        match QuinnTransport::bind(addr, quinn_cfg(), filter) {
            Ok(t) => {
                rebound = Some(Bound {
                    t: Arc::new(t),
                    allow,
                    addr,
                });
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    d.y = start_side(
        rebound.expect("port not freed"),
        store,
        bookdir,
        None,
        partial,
        dest,
        cfg,
    );
    let seen = finish(&mut d.x, &kx, &d.px, &mut d.y, &ky, &d.py, 300).await;
    assert!(
        seen.iter()
            .any(|(_, e)| matches!(e, TransferEvent::Verifying { .. })),
        "no re-verification after restart"
    );
    assert_all_placed(&d.y.dest, &ky, &files);
    assert_partial_empty(&d.y.partial).await;
}

#[tokio::test]
async fn net_streams_1_and_8_identical() {
    for (streams, window) in [(1u8, 1u8), (8, 2)] {
        let mut d = duo(
            |_| {},
            move |c| {
                c.streams = streams;
                c.per_stream_window = window;
            },
        )
        .await;
        let src = TestDir::new();
        let files = write_sources(
            src.path(),
            &[
                ("a.bin".into(), rand_bytes(61, 30 << 20)),
                ("b.bin".into(), rand_bytes(62, (5 << 20) + 3)),
                ("c.bin".into(), Vec::new()),
                ("d.bin".into(), rand_bytes(63, 20 << 20)),
            ],
        );
        let kx = d.x.tr.send(&d.px, files.clone()).unwrap();
        let ky = accept(&mut d.y).await;
        finish(&mut d.x, &kx, &d.px, &mut d.y, &ky, &d.py, 300).await;
        assert_all_placed(&d.y.dest, &ky, &files);
        assert_partial_empty(&d.y.partial).await;
    }
}

#[tokio::test]
async fn net_two_way_simultaneous() {
    let mut d = duo(|_| {}, |_| {}).await;
    let (sx, sy) = (TestDir::new(), TestDir::new());
    let fx = write_sources(
        sx.path(),
        &[
            ("x1.bin".into(), rand_bytes(71, 25 << 20)),
            ("x2.bin".into(), rand_bytes(72, 7 << 20)),
        ],
    );
    let fy = write_sources(
        sy.path(),
        &[
            ("y1.bin".into(), rand_bytes(73, 30 << 20)),
            ("y2.bin".into(), rand_bytes(74, (1 << 20) + 1)),
        ],
    );
    // оба предлагают одновременно; обе стороны получают и отправляют
    let kx = d.x.tr.send(&d.px, fx.clone()).unwrap();
    let ky = d.y.tr.send(&d.py, fy.clone()).unwrap();
    let kx_at_y = accept(&mut d.y).await;
    let ky_at_x = accept(&mut d.x).await;
    assert_eq!(kx_at_y.id, kx.id);
    assert_eq!(ky_at_x.id, ky.id);
    // на каждой стороне ждём оба `Completed` (свой исходящий и чужой входящий)
    let (mut need_x, mut need_y) = (vec![kx, ky_at_x], vec![ky, kx_at_y]);
    let end = tokio::time::Instant::now() + Duration::from_secs(300);
    while !(need_x.is_empty() && need_y.is_empty()) {
        assert!(tokio::time::Instant::now() < end, "two-way timed out");
        tokio::select! {
            e = d.x.ev.recv(), if !need_x.is_empty() => match e {
                Some(TransferEvent::Completed { key }) => need_x.retain(|k| *k != key),
                Some(e @ (TransferEvent::Failed { .. } | TransferEvent::Cancelled { .. })) =>
                    panic!("x side ended: {e:?}"),
                Some(_) => {}
                None => panic!("x events closed"),
            },
            e = d.y.ev.recv(), if !need_y.is_empty() => match e {
                Some(TransferEvent::Completed { key }) => need_y.retain(|k| *k != key),
                Some(e @ (TransferEvent::Failed { .. } | TransferEvent::Cancelled { .. })) =>
                    panic!("y side ended: {e:?}"),
                Some(_) => {}
                None => panic!("y events closed"),
            },
            () = tokio::time::sleep(Duration::from_secs(1)) => {}
        }
    }
    assert_all_placed(&d.y.dest, &kx_at_y, &fx);
    assert_all_placed(&d.x.dest, &ky_at_x, &fy);
    assert_partial_empty(&d.x.partial).await;
    assert_partial_empty(&d.y.partial).await;
}

/// Очень большой файл: пока отправитель хэширует файл для `GET_MANIFEST`, получатель ждёт
/// ответ под `stall_timeout` (60 с). Тест проверяет, что передача проходит без `Stalled`, и
/// печатает измерения. Размер: `CHERVO_BIG_GIB` (по умолчанию 4). Долгий: запуск вручную
/// `cargo test -p chervo-transfer --test transfer_net -- --ignored --nocapture big_file`.
#[tokio::test]
#[ignore = "large file (CHERVO_BIG_GIB GiB of temp disk, minutes); run with --ignored"]
async fn net_big_file_manifest_hash_no_stall() {
    let gib: u64 = std::env::var("CHERVO_BIG_GIB")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);
    let size = gib << 30;
    let src = TestDir::new();
    let path = src.path().join("big.bin");
    let t0 = Instant::now();
    {
        // 16 МиБ-основа; у каждого куска своя метка (блоки различны)
        let base = rand_bytes(99, 16 << 20);
        let mut f =
            std::io::BufWriter::with_capacity(1 << 20, std::fs::File::create(&path).unwrap());
        let mut chunk = base.clone();
        let mut written = 0u64;
        let mut j = 0u64;
        while written < size {
            chunk[..8].copy_from_slice(&j.to_le_bytes());
            f.write_all(&chunk).unwrap();
            written += chunk.len() as u64;
            j += 1;
        }
        f.flush().unwrap();
    }
    eprintln!(
        "BIG: wrote {gib} GiB source in {:.1} s",
        t0.elapsed().as_secs_f64()
    );
    // `CHERVO_BIG_STALL_MS`: сократить `stall_timeout` получателя, чтобы показать сам механизм
    let stall_ms: Option<u64> = std::env::var("CHERVO_BIG_STALL_MS")
        .ok()
        .and_then(|s| s.parse().ok());
    let mut d = duo(
        |_| {},
        |c| {
            if let Some(ms) = stall_ms {
                c.stall_timeout = Duration::from_millis(ms);
            }
        },
    )
    .await;
    let files = vec![SourceFile {
        path: path.clone(),
        name: "big.bin".into(),
    }];
    let t_send = Instant::now();
    let kx = d.x.tr.send(&d.px, files.clone()).unwrap();
    let ky = accept(&mut d.y).await;
    let t_accept = Instant::now();
    // первое продвижение: после ответа на GET_MANIFEST (хэш всего файла готов) и первого блока
    let first = wait_ev("big_first", &mut d.y.ev, 900, |e| {
        matches!(
            e,
            TransferEvent::Progress { done, .. } if *done > 0
        ) || matches!(
            e,
            TransferEvent::Paused {
                reason: PauseReason::Stalled,
                ..
            }
        )
    })
    .await;
    let manifest_wait = t_accept.elapsed();
    eprintln!(
        "BIG: accept -> first progress {:.1} s (offer->accept {:.1} s)",
        manifest_wait.as_secs_f64(),
        t_accept.duration_since(t_send).as_secs_f64()
    );
    assert!(
        !matches!(first, TransferEvent::Paused { .. }),
        "STALLED while sender hashed the file (accept -> pause {:.1} s)",
        manifest_wait.as_secs_f64()
    );
    let seen = finish(&mut d.x, &kx, &d.px, &mut d.y, &ky, &d.py, 3600).await;
    let total = t_send.elapsed();
    let stalled = seen.iter().any(|(_, e)| {
        matches!(
            e,
            TransferEvent::Paused {
                reason: PauseReason::Stalled,
                ..
            }
        )
    });
    eprintln!(
        "BIG: total {:.1} s ({:.1} MiB/s), stalled event: {stalled}",
        total.as_secs_f64(),
        (size >> 20) as f64 / total.as_secs_f64()
    );
    assert!(!stalled, "Paused(Stalled) observed");
    // справка: чистое время хэширования файла (кэш страниц тёплый)
    let t_hash = Instant::now();
    {
        let l = layout(size).unwrap();
        let mut f = std::fs::File::open(&path).unwrap();
        let mut buf = vec![0u8; l.block_size as usize];
        let mut leaves = Vec::new();
        for i in 0..l.block_count {
            let n = block_len(size, l, i).unwrap() as usize;
            f.read_exact(&mut buf[..n]).unwrap();
            leaves.push(leaf_hash(i, &buf[..n]));
        }
        file_root(size, l, &leaves).unwrap();
    }
    let h = t_hash.elapsed().as_secs_f64();
    eprintln!(
        "BIG: pure hash of {gib} GiB: {h:.1} s = {:.2} GiB/s; 60 s stall limit is reached at about {:.0} GiB",
        gib as f64 / h,
        60.0 * gib as f64 / h
    );
    let dst = d.y.dest.path().join(final_name(&ky, 0));
    assert_identical(&path, &dst);
    assert_partial_empty(&d.y.partial).await;
}
