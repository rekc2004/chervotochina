//! Fuzz-смоук проверки стука на stable (этап 17, B3): датаграмма любой длины и любого
//! содержимого, кроме настоящего стука друга для текущего окна, никогда не даёт допуска.
//! ГПСЧ xorshift64*; число итераций `CHERVO_FUZZ_ITERS` (по умолчанию 20 000 в release,
//! 2 000 в debug), зерно `CHERVO_FUZZ_SEED`. Здесь нельзя печатать (охрана `src_guard`).
//!
//! Свойства: ни одной паники; `knock_ok` остаётся 0, `consume_attempt` для источника всегда
//! `false`, `filter_batch` ничего не отдаёт quinn с неадмитированного адреса; положительный
//! контроль в конце: настоящий стук допускает, его повтор с другого адреса нет.

use std::io::IoSliceMut;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use chervo_identity::KNOCK_LEN;
use quinn::Runtime;
use quinn::udp::RecvMeta;

use super::kit::*;
use crate::QuinnConfig;
use crate::knock::KnockState;
use crate::limits::Counters;

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n.max(1) as u64)) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn fuzz_iters() -> u64 {
    let default = if cfg!(debug_assertions) {
        2_000
    } else {
        20_000
    };
    std::env::var("CHERVO_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Зерно цели: без `CHERVO_FUZZ_SEED` ровно `default`; с ней splitmix64 от `seed ^ default`.
/// Пустое значение считается незаданным, неразборное вызывает панику.
fn fuzz_seed(default: u64) -> u64 {
    let Ok(raw) = std::env::var("CHERVO_FUZZ_SEED") else {
        return default;
    };
    if raw.trim().is_empty() {
        return default;
    }
    let seed: u64 = raw
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("CHERVO_FUZZ_SEED must be a u64, got {raw:?}"));
    let mut z = (seed ^ default).wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn mutate(rng: &mut XorShift, src: &[u8]) -> Vec<u8> {
    let mut v = src.to_vec();
    match rng.below(6) {
        0 if !v.is_empty() => {
            let i = rng.below(v.len());
            v[i] ^= 1 << rng.below(8);
        }
        1 => {
            let i = rng.below(v.len() + 1);
            let len = 1 + rng.below(4);
            for (k, b) in rng.bytes(len).into_iter().enumerate() {
                v.insert(i + k, b);
            }
        }
        2 if !v.is_empty() => {
            let i = rng.below(v.len());
            v.remove(i);
        }
        3 => {
            let n = rng.below(v.len() + 1);
            v.truncate(n);
        }
        4 => {
            // продолжение настоящего стука лишними байтами
            let extra = 1 + rng.below(32);
            v.extend(rng.bytes(extra));
        }
        _ if !v.is_empty() => {
            let i = rng.below(v.len());
            v[i] = rng.next() as u8;
        }
        _ => {}
    }
    v
}

fn bare(k: &Keys) -> (Arc<KnockState>, Arc<Counters>) {
    let cfg = QuinnConfig {
        knock_required: true,
        ..QuinnConfig::default()
    };
    let counters = Arc::new(Counters::default());
    let (events, _) = tokio::sync::broadcast::channel(8);
    let std_sock = std::net::UdpSocket::bind(lo()).unwrap();
    std_sock.set_nonblocking(true).unwrap();
    let raw = quinn::TokioRuntime.wrap_udp_socket(std_sock).unwrap();
    let state = KnockState::new(&cfg, counters.clone(), Arc::new(AllowAll), events, raw);
    state.set_peers(&[k.peer_b()]);
    (state, counters)
}

/// Одна датаграмма через `filter_batch`; возвращает, сколько записей осталось для quinn.
fn feed(state: &KnockState, addr: SocketAddr, payload: &[u8], stride: usize) -> usize {
    let mut storage = vec![0u8; payload.len().max(1)];
    storage[..payload.len()].copy_from_slice(payload);
    let mut bufs = [IoSliceMut::new(&mut storage)];
    let mut meta = [RecvMeta::default()];
    meta[0].addr = addr;
    meta[0].len = payload.len();
    meta[0].stride = stride;
    state.filter_batch(&mut bufs, &mut meta, 1)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fuzz_smoke_knock_never_admits() {
    let n = fuzz_iters();
    let mut rng = XorShift(fuzz_seed(0x4B0C_5EED_00C0_FFEE).max(1));
    let k = Keys::new();
    let (state, counters) = bare(&k);
    let friend = k.peer_a().knock_keys().unwrap();
    let valid = friend.make(now_window()).unwrap();
    assert_eq!(valid.len(), KNOCK_LEN);
    let rd = |c: &std::sync::atomic::AtomicU64| c.load(Ordering::Relaxed);

    let mut fed = 0u64;
    for i in 0..n {
        // источник каждый раз новый, чужой и не тот, что у контроля в конце
        let addr: SocketAddr = format!("127.0.0.1:{}", 20_000 + (i % 40_000))
            .parse()
            .unwrap();
        let (payload, stride) = match rng.below(7) {
            0 => {
                let len = rng.below(1501);
                (rng.bytes(len), 0)
            }
            1 => (rng.bytes(KNOCK_LEN), KNOCK_LEN),
            2 => (mutate(&mut rng, &valid), 0),
            3 => {
                // верный id (по нему находится пара), остальное случайное
                let mut v = valid[..16].to_vec();
                v.extend(rng.bytes(32));
                (v, KNOCK_LEN)
            }
            4 => {
                // верные id и nonce, случайный тег
                let mut v = valid[..32].to_vec();
                v.extend(rng.bytes(16));
                (v, KNOCK_LEN)
            }
            5 => {
                // склейка нескольких испорченных стуков (GRO)
                let parts = 1 + rng.below(4);
                let mut v = Vec::new();
                for _ in 0..parts {
                    let mut piece = valid.to_vec();
                    let at = rng.below(KNOCK_LEN);
                    piece[at] ^= 1 << rng.below(8);
                    v.extend(piece);
                }
                (v, KNOCK_LEN)
            }
            _ => {
                // испорченный стук, продолженный или обрезанный
                let once = mutate(&mut rng, &valid);
                (mutate(&mut rng, &once), 0)
            }
        };
        // настоящий стук (или склейка с ним) здесь недопустим: он честно допускает
        if payload.chunks(KNOCK_LEN).any(|c| c == valid.as_slice()) {
            continue;
        }
        let stride = if stride == 0 {
            payload.len().max(1)
        } else {
            stride
        };
        let kept = feed(&state, addr, &payload, stride);
        assert_eq!(
            kept, 0,
            "итерация {i}: датаграмма передана quinn с закрытого адреса"
        );
        if rng.below(2) == 0 {
            // и прямой разбор одного сегмента
            let _ = state.try_knock(addr, &payload);
        }
        assert!(
            !state.consume_attempt(addr),
            "итерация {i}: допуск получен без настоящего стука ({} байт)",
            payload.len()
        );
        fed += 1;
    }
    assert_eq!(
        rd(&counters.knock_ok),
        0,
        "knock_ok != 0 без настоящего стука"
    );

    // положительный контроль: настоящий стук допускает, его повтор с другого адреса нет
    let friend_addr: SocketAddr = "127.0.0.1:19999".parse().unwrap();
    let other_addr: SocketAddr = "127.0.0.1:19998".parse().unwrap();
    assert_eq!(feed(&state, friend_addr, &valid, KNOCK_LEN), 0);
    assert_eq!(
        rd(&counters.knock_ok),
        1,
        "настоящий стук не допущен (контроль)"
    );
    assert!(
        state.consume_attempt(friend_addr),
        "допуск друга не открылся"
    );
    assert_eq!(feed(&state, other_addr, &valid, KNOCK_LEN), 0);
    assert_eq!(
        rd(&counters.knock_ok),
        1,
        "повтор стука с другого адреса дал допуск"
    );
    assert!(!state.consume_attempt(other_addr));
    assert!(fed > 0 || n == 0);
}
