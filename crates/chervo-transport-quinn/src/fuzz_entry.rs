//! Этап 17, B6/C04, исправление S1 M3/L6: точка входа для фаззинга (libFuzzer в `fuzz/`, вне
//! рабочего пространства). Модуль есть только в тестовой сборке и со свойством `fuzzing`;
//! в продуктовой сборке его нет (там гнездо и исполнитель tokio создавать негде).
//!
//! Поведение не меняется: обёртка вызывает тот же `try_knock`/`consume_attempt`, что и свой
//! fuzz-смоук (`src/tests/fuzz.rs`). Состояние строится лениво и один раз на процесс. Сбой при
//! его постройке (сокет, ключи) или непрохождение положительного контроля даёт
//! `fuzz_knock_ready() == false`; цель libFuzzer обязана это проверить (иначе фаззер молча
//! проверял бы пустую таблицу, S1 M3). `unwrap`/`panic` запрещены охраной крейта.
//!
//! Фикстура: пара с двумя РАЗНЫМИ ключами X25519 (наш и друга). Ключ друга, равный нашему,
//! `knock_keys` отвергает, и таблица остаётся пустой.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use chervo_identity::{IdentityError, KxPeer, PairId, create, load};
use chervo_transport::PeerFilter;
use quinn::Runtime;
use tokio::sync::broadcast;
use zeroize::Zeroizing;

use crate::QuinnConfig;
use crate::knock::{KnockState, window_at};
use crate::limits::Counters;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

struct FuzzAllowAll;

impl PeerFilter for FuzzAllowAll {
    fn is_allowed(&self, _pair: &PairId) -> bool {
        true
    }
}

/// Память: только для одноразовых ключей сторон этой точки входа.
#[derive(Default)]
struct FuzzMemStore(Mutex<HashMap<PairId, Vec<u8>>>);

impl chervo_identity::SecretStore for FuzzMemStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(lock(&self.0).get(pair).cloned().map(Zeroizing::new))
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        lock(&self.0).insert(*pair, blob.to_vec());
        Ok(())
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        lock(&self.0).remove(pair);
        Ok(())
    }
}

/// Сторона пары: хранилище позволяет получить независимые копии `KxPeer`.
struct Side {
    pair: PairId,
    store: FuzzMemStore,
    public: chervo_identity::PublicKey,
    kx_public: chervo_identity::KxPublicKey,
}

impl Side {
    fn new(pair: PairId) -> Option<Self> {
        let store = FuzzMemStore::default();
        let key = create(&store, &pair).ok()?;
        let public = key.public_key();
        let kx_public = key.kx_public();
        Some(Self {
            pair,
            store,
            public,
            kx_public,
        })
    }

    fn peer(&self, theirs: chervo_identity::KxPublicKey) -> Option<KxPeer> {
        let key = load(&self.store, &self.pair, &self.public).ok()?;
        Some(KxPeer::new(self.pair, key.into_kx(), theirs))
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

/// Состояние стука с парой двух разных сторон и положительным контролем: настоящий стук другой
/// стороны допускает свой адрес (поэтому таблица не пуста и разбор доходит до проверки тега).
fn fuzz_fixture() -> Option<Arc<KnockState>> {
    let cfg = QuinnConfig {
        knock_required: true,
        ..QuinnConfig::default()
    };
    let counters = Arc::new(Counters::default());
    let (events, _rx) = broadcast::channel(8);
    let std_sock = std::net::UdpSocket::bind("127.0.0.1:0").ok()?;
    std_sock.set_nonblocking(true).ok()?;
    let raw = quinn::TokioRuntime.wrap_udp_socket(std_sock).ok()?;
    let state = KnockState::new(&cfg, counters.clone(), Arc::new(FuzzAllowAll), events, raw);
    let pid = PairId::generate().ok()?;
    let (a, b) = (Side::new(pid)?, Side::new(pid)?);
    // наша сторона A принимает стук стороны B; ключи X25519 разные
    let ours = a.peer(b.kx_public)?;
    let theirs = b.peer(a.kx_public)?;
    state.set_peers(&[ours]);
    // таблица ключей непуста и содержит ровно эту пару
    if state.key_pairs() != [pid] {
        return None;
    }
    // положительный контроль: настоящий стук B допускает свой адрес, чужой адрес без стука нет
    let control: SocketAddr = "127.0.0.1:2".parse().ok()?;
    let knock = theirs.knock_keys().ok()?.make(window_at(now_ms())).ok()?;
    if !state.try_knock(control, &knock) || !state.consume_attempt(control) {
        return None;
    }
    if counters.knock_ok.load(std::sync::atomic::Ordering::Relaxed) != 1 {
        return None;
    }
    Some(state)
}

fn fuzz_state() -> Option<&'static Arc<KnockState>> {
    static STATE: std::sync::OnceLock<Option<Arc<KnockState>>> = std::sync::OnceLock::new();
    // обёртка гнезда нуждается в активном исполнителе tokio только на постройке
    static RT: std::sync::OnceLock<Option<tokio::runtime::Runtime>> = std::sync::OnceLock::new();
    let rt = RT.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()
    });
    let state = STATE.get_or_init(|| match rt {
        Some(rt) => {
            let _guard = rt.enter();
            fuzz_fixture()
        }
        None => None,
    });
    state.as_ref()
}

/// `true`: фикстура построена, в таблице ровно одна пара, положительный контроль (настоящий
/// стук другой стороны) допустил. Цель libFuzzer проверяет это до первого входа.
pub fn fuzz_knock_ready() -> bool {
    fuzz_state().is_some()
}

/// `true`: датаграмма `data` допустила бы адрес (оно не должно происходить ни для какого
/// `data`, кроме настоящего стука текущего ключа этой точки входа, который наружу не выходит).
pub fn fuzz_knock_admits(data: &[u8]) -> bool {
    let Some(state) = fuzz_state() else {
        return false;
    };
    let addr: SocketAddr = match "127.0.0.1:1".parse() {
        Ok(a) => a,
        Err(_) => return false,
    };
    let _ = state.try_knock(addr, data);
    state.consume_attempt(addr)
}
