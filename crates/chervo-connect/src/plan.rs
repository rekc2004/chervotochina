//! Выбор пути (U7): какие адреса пробовать и в каком порядке. Адреса берутся только из книги
//! друга (`usable_known`) или из токена приглашения; ничего другого сюда не попадает.

use std::net::SocketAddr;

use chervo_addr::{AddrClass, AddrSource, KnownAddr, classify, normalize};
use tokio::time::Instant;

use crate::limiter::Limiter;

/// Сколько адресов уходит в один вызов `connect`.
pub(crate) const MAX_DIAL_ADDRS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub(crate) addr: SocketAddr,
    pub(crate) hint: bool,
    /// Адрес известен только со слов друга (`AddressUpdate`, подсказка): набор не чаще раза
    /// в `dial_base` (+ запас) в любом режиме, быстрое окно срок не сокращает (этап 17, X02a).
    pub(crate) strict: bool,
}

/// Упорядоченные кандидаты до применения ограничителя.
pub(crate) struct Plan {
    pub(crate) cands: Vec<Candidate>,
}

/// Информативный вид пути для таблиц этапа 16 (приблизительный).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    Lan,
    Ipv6,
    PortMapped,
    SimultaneousOpen,
}

fn is_lan(addr: &SocketAddr) -> bool {
    matches!(
        classify(addr.ip()),
        AddrClass::Private | AddrClass::Loopback
    )
}

/// Адрес, на который стучать бессмысленно или опасно, даже если он попал в книгу.
fn dialable(addr: &SocketAddr) -> bool {
    addr.port() != 0
        && !matches!(
            classify(addr.ip()),
            AddrClass::Unspecified
                | AddrClass::Multicast
                | AddrClass::Broadcast
                | AddrClass::V4Mapped
        )
}

/// Семейства, которыми умеет пользоваться транспорт (по его адресам прослушивания).
fn family_ok(addr: &SocketAddr, local: &[SocketAddr]) -> bool {
    local.iter().any(|l| l.is_ipv4() == addr.is_ipv4())
}

fn build(raw: impl Iterator<Item = (SocketAddr, bool, bool)>, local: &[SocketAddr]) -> Plan {
    let mut cands: Vec<Candidate> = Vec::new();
    for (addr, hint, strict) in raw {
        let addr = normalize(addr);
        if !dialable(&addr) || !family_ok(&addr, local) {
            continue;
        }
        if let Some(c) = cands.iter_mut().find(|c| c.addr == addr) {
            // тот же адрес из более доверенного источника (приглашение, контакт) снимает предел
            c.strict &= strict;
            continue;
        }
        cands.push(Candidate { addr, hint, strict });
    }
    // устойчивая сортировка: сначала локальная сеть, дальше порядок книги
    cands.sort_by_key(|c| !is_lan(&c.addr));
    Plan { cands }
}

/// Кандидаты друга: записи `usable_known` (порядок книги: обновление без подсказки,
/// приглашение, контакт, подсказки), семейство по `local`, сначала LAN.
pub(crate) fn friend_plan(entries: &[KnownAddr], local: &[SocketAddr]) -> Plan {
    build(
        entries.iter().map(|k| (k.addr, k.hint, is_strict(k))),
        local,
    )
}

/// Слова друга, не подтверждённые соединением и не полученные от пользователя вне линии.
fn is_strict(k: &KnownAddr) -> bool {
    k.hint
        || matches!(
            k.source,
            AddrSource::AddressUpdate | AddrSource::ObservedByFriend
        )
}

/// Кандидаты гостевой пары приглашённого: только адреса токена.
pub(crate) fn guest_plan(token_addrs: &[SocketAddr], local: &[SocketAddr]) -> Plan {
    build(token_addrs.iter().map(|a| (*a, false, false)), local)
}

/// Только IPv6 в книге, а транспорт IPv6 не слушает: причина `NoIpv6`.
pub(crate) fn only_unusable_v6(entries: &[KnownAddr], local: &[SocketAddr]) -> bool {
    !entries.is_empty()
        && entries.iter().all(|k| normalize(k.addr).is_ipv6())
        && !local.iter().any(SocketAddr::is_ipv6)
}

/// Применить ограничитель: адрес входит в набор, только если `take` разрешил и учёл его.
/// Вызывать лишь тогда, когда набор действительно будет набран.
pub(crate) fn select(plan: &Plan, limiter: &mut Limiter, now: Instant) -> Vec<Candidate> {
    let mut out = Vec::new();
    for c in &plan.cands {
        if out.len() >= MAX_DIAL_ADDRS {
            break;
        }
        if limiter.take(c.addr, c.strict, now) {
            out.push(*c);
        }
    }
    out
}

/// Вид пути соединения. `book_entries` — записи друга до `note_contact`.
pub(crate) fn path_kind(
    remote: SocketAddr,
    initiator: bool,
    book_entries: &[KnownAddr],
    own_stable: bool,
) -> PathKind {
    let r = normalize(remote);
    match classify(r.ip()) {
        AddrClass::Private | AddrClass::Loopback | AddrClass::LinkLocal => return PathKind::Lan,
        _ => {}
    }
    if r.is_ipv6() {
        return PathKind::Ipv6;
    }
    if classify(r.ip()) == AddrClass::Global {
        // запись `Contact` не считается: она сама появилась из прошлого соединения и
        // сделала бы «одновременное открытие» похожим на постоянный адрес
        let known_stable = book_entries
            .iter()
            .any(|k| normalize(k.addr) == r && !k.hint && k.source != AddrSource::Contact);
        if (initiator && known_stable) || (!initiator && own_stable) {
            return PathKind::PortMapped;
        }
    }
    PathKind::SimultaneousOpen
}
