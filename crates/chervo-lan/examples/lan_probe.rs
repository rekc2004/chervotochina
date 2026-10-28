//! Ручная проверка поиска в локальной сети (этап 13в). Не часть продукта.
//!
//! ```text
//! cargo run -p chervo-lan --example lan_probe -- join-check
//! cargo run -p chervo-lan --example lan_probe -- listen [SECS]
//! cargo run -p chervo-lan --example lan_probe -- announce-test --i-know [SECS]
//! ```
//!
//! `join-check` ничего не отправляет: открывает приём на маршрутном адресе, входит в группу и
//! сообщает, получилось ли (код возврата 0 или 1).
//! `listen` то же, но держит приём SECS секунд (по умолчанию 10, не больше 3600) и печатает,
//! сколько датаграмм принято и сколько из них прошло ограничение. Ничего не отправляет.
//! `announce-test` РАССЫЛАЕТ маяк в локальную сеть с выдуманной парой (для проверки приёма на
//! другой машине); без явного `--i-know` отказывается.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use chervo_addr::{LanDiscovery, LanLocal, LanMode, LanStatus, probe_route_sources};
use chervo_identity::{IdentityError, KxPeer, PairId, SecretStore, create};
use chervo_lan::{LAN_PORT, LanBeacon, status_text};
use zeroize::Zeroizing;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn start(mode: LanMode, own: Ipv4Addr) -> LanBeacon {
    let b = LanBeacon::new(mode, Arc::new(now_unix));
    b.set_local(Some(LanLocal {
        own,
        listen_port: 45_000,
    }));
    b
}

/// Ждёт, пока служба выйдет из начального состояния, но не дольше 2 с.
fn wait_status(b: &LanBeacon, want: LanStatus) -> LanStatus {
    let end = Instant::now() + Duration::from_secs(2);
    while Instant::now() < end {
        if b.status() == want {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    b.status()
}

fn secs_arg(args: &[String], at: usize) -> u64 {
    args.get(at)
        .and_then(|s| s.parse().ok())
        .unwrap_or(10)
        .clamp(1, 3600)
}

#[derive(Default)]
struct MemStore(Mutex<HashMap<PairId, Zeroizing<Vec<u8>>>>);

impl SecretStore for MemStore {
    fn read(&self, p: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        let g = self
            .0
            .lock()
            .map_err(|_| IdentityError::StorageUnavailable)?;
        Ok(g.get(p).map(|v| Zeroizing::new(v.to_vec())))
    }
    fn write(&self, p: &PairId, b: &[u8]) -> Result<(), IdentityError> {
        let mut g = self
            .0
            .lock()
            .map_err(|_| IdentityError::StorageUnavailable)?;
        g.insert(*p, Zeroizing::new(b.to_vec()));
        Ok(())
    }
    fn delete(&self, p: &PairId) -> Result<(), IdentityError> {
        let mut g = self
            .0
            .lock()
            .map_err(|_| IdentityError::StorageUnavailable)?;
        g.remove(p);
        Ok(())
    }
}

/// Выдуманная пара: ключи случайные, нигде не сохраняются, друга с такими ключами не существует.
fn fake_peer() -> Option<KxPeer> {
    let pair = PairId::generate().ok()?;
    let (sa, sb) = (MemStore::default(), MemStore::default());
    let ka = create(&sa, &pair).ok()?;
    let kb = create(&sb, &pair).ok()?;
    let theirs = kb.kx_public();
    Some(KxPeer::new(pair, ka.into_kx(), theirs))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or_default();
    if !matches!(cmd, "join-check" | "listen" | "announce-test") {
        println!(
            "использование: lan_probe join-check | listen [SECS] | announce-test --i-know [SECS]"
        );
        return ExitCode::FAILURE;
    }
    if cmd == "announce-test" && args.get(1).map(String::as_str) != Some("--i-know") {
        println!(
            "announce-test рассылает маяк в вашу локальную сеть; запустите с --i-know, если это нужно"
        );
        return ExitCode::FAILURE;
    }
    let Some(own) = probe_route_sources().v4 else {
        println!("нет маршрутного IPv4");
        return ExitCode::FAILURE;
    };
    println!("порт маяка {LAN_PORT}, маршрутный адрес {own}");

    match cmd {
        "join-check" | "listen" => {
            let b = start(LanMode::Listen, own);
            let st = wait_status(&b, LanStatus::Listening);
            println!("{cmd}: {st:?}: {}", status_text(st));
            if st != LanStatus::Listening {
                b.shutdown();
                return ExitCode::FAILURE;
            }
            if cmd == "listen" {
                let secs = secs_arg(&args, 1);
                std::thread::sleep(Duration::from_secs(secs));
                let (rx, passed) = b.rx_stats();
                println!("за {secs} с принято датаграмм {rx}, прошло ограничение {passed}");
            }
            b.shutdown();
            println!("{cmd}: OK");
            ExitCode::SUCCESS
        }
        _ => {
            let Some(peer) = fake_peer() else {
                println!("не удалось создать выдуманную пару");
                return ExitCode::FAILURE;
            };
            let b = start(LanMode::Announce, own);
            b.set_peers(vec![peer]);
            let st = wait_status(&b, LanStatus::Announcing);
            println!("announce-test: {st:?}: {}", status_text(st));
            if st != LanStatus::Announcing {
                b.shutdown();
                return ExitCode::FAILURE;
            }
            let secs = secs_arg(&args, 2);
            std::thread::sleep(Duration::from_secs(secs));
            b.shutdown();
            println!("announce-test: готово");
            ExitCode::SUCCESS
        }
    }
}
