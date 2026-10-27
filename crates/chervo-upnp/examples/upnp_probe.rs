//! Ручная проверка на настоящем роутере (этап 13а). Не часть продукта.
//!
//! ```text
//! cargo run -p chervo-upnp --example upnp_probe -- identify
//! cargo run -p chervo-upnp --example upnp_probe -- map [PORT] [UDN]
//! cargo run -p chervo-upnp --example upnp_probe -- release [PORT] [UDN]
//! ```
//!
//! `identify` ищет роутер (один поиск и одно описание) и печатает его UDN.
//! `map` открывает UDP-порт (по умолчанию 40123; на порту никто не слушает), печатает итог,
//! продлевает по `retry_after` и по Enter закрывает проброс. Без UDN в аргументах роутер
//! сначала определяется так же, как в `identify`, и считается разрешённым (это явное действие
//! владельца в своей сети). `release`: открыть и сразу закрыть (проверка круга).
//! Проброс помнится только в памяти процесса, поэтому закрыть чужой запуск отдельной командой
//! нельзя: после аварийного завершения запись снимется при следующем запуске `map` или по
//! окончании аренды (не более часа).

use std::net::SocketAddrV4;
use std::process::ExitCode;
use std::sync::mpsc;
use std::thread;

use chervo_addr::{MapRequest, PortMapper, probe_route_sources};
use chervo_upnp::{AllowedRouter, RouterId, UpnpMapper, UpnpSettings, status_text};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or_default();
    let Some(own) = probe_route_sources().v4 else {
        println!("нет маршрутного IPv4");
        return ExitCode::FAILURE;
    };
    let mapper = UpnpMapper::new(UpnpSettings::default());
    match cmd {
        "identify" => match mapper.identify(own) {
            Ok(id) => {
                println!("{}", id.to_setting());
                ExitCode::SUCCESS
            }
            Err(e) => {
                println!("identify: {e:?}");
                ExitCode::FAILURE
            }
        },
        "map" | "release" => run(&mapper, own, &args, cmd == "release"),
        _ => {
            println!(
                "использование: upnp_probe identify | map [PORT] [UDN] | release [PORT] [UDN]"
            );
            ExitCode::FAILURE
        }
    }
}

fn run(mapper: &UpnpMapper, own: std::net::Ipv4Addr, args: &[String], once: bool) -> ExitCode {
    let port: u16 = args
        .get(1)
        .and_then(|p| p.parse().ok())
        .filter(|&p| p != 0)
        .unwrap_or(40123);
    let id = match args.get(2) {
        Some(udn) => match RouterId::from_setting(udn) {
            Ok(id) => id,
            Err(e) => {
                println!("UDN: {e:?}");
                return ExitCode::FAILURE;
            }
        },
        None => match mapper.identify(own) {
            Ok(id) => id,
            Err(e) => {
                println!("identify: {e:?}");
                return ExitCode::FAILURE;
            }
        },
    };
    mapper.set_settings(UpnpSettings {
        routers: vec![AllowedRouter {
            id,
            permanent_ok: false,
        }],
    });
    let req = MapRequest {
        internal: SocketAddrV4::new(own, port),
    };
    let (tx, rx) = mpsc::channel::<()>();
    if !once {
        thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::stdin().read_line(&mut line);
            let _ = tx.send(());
        });
    }
    loop {
        let rep = mapper.refresh(req);
        println!("{:?}: {}", rep.status, status_text(rep.status));
        if let Some(g) = rep.gateway {
            println!("внешний адрес роутера: {:?}", g.wan_ip);
            println!("проброс: {:?}", g.mapping);
        }
        println!("следующая проверка через {} с", rep.retry_after.as_secs());
        if once {
            break;
        }
        println!("Enter: закрыть проброс и выйти");
        if rx.recv_timeout(rep.retry_after).is_ok() {
            break;
        }
    }
    mapper.release();
    println!("проброс закрыт (release)");
    ExitCode::SUCCESS
}
