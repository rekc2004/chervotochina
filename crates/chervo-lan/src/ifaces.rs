//! Выбор интерфейсов без системных перечислений (дополнение 1 к спецификации 13в).
//!
//! Системного перебора интерфейсов нет (он потребовал бы небезопасного кода). Вместо него
//! опрос маршрутов: для каждой из 533 типичных домашних цифр `x.x.x.1` спрашивается «с какого
//! своего адреса ушёл бы пакет к ней» (`UDP connect` без отправки). Самый длинный префикс
//! маршрутов выбирает интерфейс, в чьей сети лежит цель, как бы ни был занят маршрут по
//! умолчанию (VPN с метрикой 0). Различные частные ответы дают набор интерфейсов, до
//! `MAX_IFACES`. Чистый код: сам опрос приходит снаружи.

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

use chervo_addr::{AddrClass, classify};

use crate::limits::{MAX_IFACES, SWEEP_CHUNK, SWEEP_PORT};
use crate::wire::SrcPolicy;

/// Цели опроса по порядку: `192.168.N.1` (N 0..=255), `10.N.0.1` (N 0..=255), пять частых
/// адресов роутеров `10.x`, `172.N.0.1` (N 16..=31). Всего 533, все частные.
pub(crate) fn sweep_targets() -> impl Iterator<Item = SocketAddrV4> {
    let a = (0..=255u8).map(|n| Ipv4Addr::new(192, 168, n, 1));
    let b = (0..=255u8).map(|n| Ipv4Addr::new(10, n, 0, 1));
    let c = [
        Ipv4Addr::new(10, 0, 1, 1),
        Ipv4Addr::new(10, 1, 1, 1),
        Ipv4Addr::new(10, 1, 10, 1),
        Ipv4Addr::new(10, 10, 10, 1),
        Ipv4Addr::new(10, 90, 90, 1),
    ]
    .into_iter();
    let d = (16..=31u8).map(|n| Ipv4Addr::new(172, n, 0, 1));
    a.chain(b)
        .chain(c)
        .chain(d)
        .map(|ip| SocketAddrV4::new(ip, SWEEP_PORT))
}

fn usable(ip: Ipv4Addr, policy: SrcPolicy) -> bool {
    match classify(IpAddr::V4(ip)) {
        AddrClass::Private => true,
        AddrClass::Loopback => policy.allow_loopback,
        _ => false,
    }
}

/// Набор интерфейсов: адрес по умолчанию (если частный), затем различные частные ответы
/// опроса в порядке целей; не больше `MAX_IFACES`. `stop` проверяется каждые `SWEEP_CHUNK`
/// обращений к опросу: на остановке возвращается то, что найдено.
pub(crate) fn select(
    default: Ipv4Addr,
    oracle: &mut dyn FnMut(SocketAddrV4) -> Option<IpAddr>,
    policy: SrcPolicy,
    stop: &dyn Fn() -> bool,
) -> Vec<Ipv4Addr> {
    let mut out: Vec<Ipv4Addr> = Vec::new();
    if usable(default, policy) {
        out.push(default);
    }
    for (i, target) in sweep_targets().enumerate() {
        if out.len() >= MAX_IFACES {
            break;
        }
        if i % SWEEP_CHUNK == 0 && stop() {
            break;
        }
        if let Some(IpAddr::V4(ip)) = oracle(target)
            && usable(ip, policy)
            && !out.contains(&ip)
        {
            out.push(ip);
        }
    }
    out
}
