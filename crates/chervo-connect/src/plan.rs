//! Выбор пути (U7): какие адреса пробовать и в каком порядке. Адреса берутся только из книги
//! друга (`usable_known`) или из токена приглашения; ничего другого сюда не попадает.

use std::net::{Ipv6Addr, SocketAddr};

use chervo_addr::{
    AddrClass, AddrSource, KnownAddr, OwnAddrs, classify, normalize, v6_egress_ok, v6_peer_ok,
};
use tokio::time::Instant;

use crate::limiter::Limiter;

/// Сколько адресов уходит в один вызов `connect`.
pub(crate) const MAX_DIAL_ADDRS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Candidate {
    pub(crate) addr: SocketAddr,
    pub(crate) hint: bool,
    /// Адрес известен только со слов друга (`AddressUpdate`, подсказка): набор не чаще раза
    /// в `dial_base` (+ запас) в любом режиме, быстрое окно срок не сокращает (этап 17, X02a, S2 M1).
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

/// Адрес, на который стучать бессмысленно или опасно, даже если он попал в книгу. У IPv6
/// допустимы только глобальные, ULA и `::1` (`v6_peer_ok`): link-local, Teredo, 6to4, NAT64,
/// документация, multicast и прочее не набираются (этап 13г, реш. 5).
pub(crate) fn dialable(addr: &SocketAddr) -> bool {
    addr.port() != 0
        && !matches!(
            classify(addr.ip()),
            AddrClass::Unspecified
                | AddrClass::Multicast
                | AddrClass::Broadcast
                | AddrClass::V4Mapped
        )
        && match addr {
            SocketAddr::V4(_) => true,
            SocketAddr::V6(v6) => v6_peer_ok(v6.ip()),
        }
}

/// Семейства, которыми умеет пользоваться транспорт, и наличие собственного выхода в IPv6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Families {
    pub(crate) v4: bool,
    pub(crate) v6: bool,
    /// Есть маршрутный источник IPv6, глобальный или ULA (`v6_egress_ok`).
    pub(crate) v6_egress: bool,
}

/// Семейства по адресам прослушивания транспорта и маршрутному источнику IPv6 (`own.local()`).
pub(crate) fn families(local: &[SocketAddr], route_v6: Option<Ipv6Addr>) -> Families {
    Families {
        v4: local.iter().any(SocketAddr::is_ipv4),
        v6: local.iter().any(SocketAddr::is_ipv6),
        v6_egress: v6_egress_ok(route_v6),
    }
}

/// Семейства для планировщика и диагноза: `route_v6` берётся из снимка `own.local()`. Пока снимка
/// нет, собственного выхода в IPv6 нет (глобальные IPv6 не набираются).
pub(crate) fn families_of(own: &OwnAddrs, local: &[SocketAddr]) -> Families {
    families(local, own.local().and_then(|l| l.route.v6))
}

/// Можно ли набирать адрес с нашей стороны: IPv4 при IPv4 в `local_addrs`; IPv6 при IPv6 в
/// `local_addrs`, допустимом классе цели, а глобальный ещё и при собственном выходе в IPv6
/// (иначе Teredo или отсутствие маршрута слали бы трафик через третьи стороны, реш. 7).
/// ULA и `::1` идут при одном лишь IPv6 в `local_addrs`.
pub(crate) fn family_ok(addr: &SocketAddr, fam: &Families) -> bool {
    match addr {
        SocketAddr::V4(_) => fam.v4,
        SocketAddr::V6(v6) => {
            fam.v6
                && v6_peer_ok(v6.ip())
                && (classify(addr.ip()) != AddrClass::Global || fam.v6_egress)
        }
    }
}

fn build(raw: impl Iterator<Item = (SocketAddr, bool, bool)>, fam: &Families) -> Plan {
    let mut cands: Vec<Candidate> = Vec::new();
    for (addr, hint, strict) in raw {
        let addr = normalize(addr);
        if !dialable(&addr) || !family_ok(&addr, fam) {
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
pub(crate) fn friend_plan(entries: &[KnownAddr], fam: &Families) -> Plan {
    build(entries.iter().map(|k| (k.addr, k.hint, is_strict(k))), fam)
}

/// Как `friend_plan`, но адреса, подтверждённые нашим соединением (`confirmed_addrs`), не
/// строгие, даже если запись в порядке набора принадлежит более раннему источнику (приглашение,
/// обновление): повтор адреса в `usable_known` убран, и подтверждение иначе терялось бы.
pub(crate) fn friend_plan_confirmed(
    entries: &[KnownAddr],
    confirmed: &[SocketAddr],
    fam: &Families,
) -> Plan {
    let mut plan = friend_plan(entries, fam);
    for c in &mut plan.cands {
        if !c.hint && confirmed.contains(&c.addr) {
            c.strict = false;
        }
    }
    plan
}

/// Слова друга, не подтверждённые нашим соединением. Быстрое окно (5 с) остаётся только у
/// `Contact`: адрес, с которого друг уже подключался по проверенному соединению. Адреса
/// приглашения тоже со слов пригласившего (этап 17, S2, M1: лгущий пригласивший вписывает в
/// токен адреса жертв), поэтому у друга с состоявшейся дружбой они строгие. Гостевая пара до
/// дружбы идёт через `guest_plan`: там адреса токена нужны для самого первого соединения.
fn is_strict(k: &KnownAddr) -> bool {
    k.hint || k.source != AddrSource::Contact
}

/// Кандидаты гостевой пары приглашённого: только адреса токена.
pub(crate) fn guest_plan(token_addrs: &[SocketAddr], fam: &Families) -> Plan {
    build(token_addrs.iter().map(|a| (*a, false, false)), fam)
}

/// В книге есть записи, все они IPv6, и ни одна не проходит `family_ok` (нет IPv6 в
/// `local_addrs` или нет собственного выхода для глобальных): причина `NoIpv6`.
pub(crate) fn only_unusable_v6(entries: &[KnownAddr], fam: &Families) -> bool {
    !entries.is_empty()
        && entries.iter().all(|k| normalize(k.addr).is_ipv6())
        && !entries.iter().any(|k| family_ok(&normalize(k.addr), fam))
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
