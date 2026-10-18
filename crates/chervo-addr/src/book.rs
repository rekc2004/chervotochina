//! Адреса друга: правила слияния, сроки жизни, порядок набора номера, «найдём ли друг друга».
//! Только чистые функции над `Vec<KnownAddr>`; время передаёт вызывающий (`now_unix`).
//! Адреса друга сюда попадают из приглашения, проверенного токена обновления и проверенного
//! соединения; обратного пути к `PublishSet` нет (U6 v6): `UpdateAddr` здесь только читается.

use std::net::SocketAddr;

use crate::{AddrClass, AddrSource, KnownAddr, UpdateAddr, classify, normalize};

pub const SHORT_LIVED_TTL_SECS: u64 = 86_400;
pub const HINT_TTL_SECS: u64 = 86_400;
pub const CONTACT_TTL_SECS: u64 = 86_400;
pub const CONTACT_REFRESH_SECS: u64 = 3_600;
pub const MAX_CONTACT_ADDRS: usize = 4;
/// Срок жизни любой записи друга с частным адресом (RFC 1918, ULA), независимо от источника.
/// ПРЕДВАРИТЕЛЬНО: решение владельца по сроку не окончательное, см. docs/OWNER_DECISIONS.md,
/// «16а Q1». Менять только эту константу.
pub const PRIVATE_TTL_SECS: u64 = 86_400;
/// Срок жизни записи `Invite` (этап 17, S2, M1). Запись создаётся при установлении дружбы, то
/// есть сразу после первого успешного соединения; адреса токена приглашения это слова
/// пригласившего и вечными быть не должны. Дальше друг достижим по `Contact` и обновлениям
/// адреса. 30 суток.
pub const INVITE_TTL_SECS: u64 = 30 * 86_400;
/// Сколько адресов берётся из приглашения.
const MAX_INVITE_KEEP: usize = 8;

pub const NEED_TOKEN_TEXT: &str = "Ни у вас, ни у друга нет постоянного адреса, а известные адреса не отвечают. Без сервера-посредника вы не найдёте друг друга автоматически: отправьте другу токен обновления адреса или попросите прислать свой (любым мессенджером).";
pub const NO_PUBLIC_ADDR_TEXT: &str = "Не удалось определить ваш внешний адрес: нет белого IP, проброса порта или подсказки от друга. Подключитесь к другу сами, когда узнаете его адрес.";

/// Срок вышел: `now >= last_seen + ttl`. Будущее `last_seen` (часы ушли назад) не истекает.
fn expired(last_seen: u64, ttl: u64, now_unix: u64) -> bool {
    now_unix >= last_seen.saturating_add(ttl)
}

/// Адреса приглашения: источник `Invite`, IPv6 короткоживущие, первые 8.
pub fn from_invite(addrs: &[SocketAddr], now_unix: u64) -> Vec<KnownAddr> {
    addrs
        .iter()
        .take(MAX_INVITE_KEEP)
        .map(|a| KnownAddr {
            addr: *a,
            source: AddrSource::Invite,
            last_seen_unix: now_unix,
            short_lived: a.is_ipv6(),
            hint: false,
        })
        .collect()
}

/// Убрать все `Invite` и `AddressUpdate`, вставить адреса обновления как `AddressUpdate`
/// (`last_seen = now`) в начало, остальное (в первую очередь `Contact`) оставить. Остальная
/// запись с тем же адресом, что у обновления, заменяется записью обновления.
/// Исключение (L1): обновление только из подсказок (`hint`) не вытесняет прежние
/// `AddressUpdate` без подсказки с глобальным адресом: они остаются после новых подсказок
/// (частные записи не остаются: их срок `PRIVATE_TTL_SECS`). Лимит записей на
/// стороне вызывающего (`trim`).
/// Из принимаемых полей `short_lived` берётся не из флага отправителя, а по семейству
/// адреса: `short_lived = addr.is_ipv6()` (L3).
pub fn merge_update(addrs: &mut Vec<KnownAddr>, update: &[UpdateAddr], now_unix: u64) {
    let hints_only = !update.is_empty() && update.iter().all(|u| u.hint);
    let mut out: Vec<KnownAddr> = Vec::with_capacity(update.len().saturating_add(addrs.len()));
    for u in update {
        if out.iter().any(|k| k.addr == u.addr) {
            continue;
        }
        out.push(KnownAddr {
            addr: u.addr,
            source: AddrSource::AddressUpdate,
            last_seen_unix: now_unix,
            short_lived: u.addr.is_ipv6(),
            hint: u.hint,
        });
    }
    let fresh = out.len();
    for k in addrs.drain(..) {
        let keep_prev_update = hints_only
            && k.source == AddrSource::AddressUpdate
            && !k.hint
            && classify(normalize(k.addr).ip()) == AddrClass::Global;
        if matches!(k.source, AddrSource::Invite | AddrSource::AddressUpdate) && !keep_prev_update {
            continue;
        }
        if out.iter().take(fresh).any(|n| n.addr == k.addr) {
            continue;
        }
        out.push(k);
    }
    *addrs = out;
}

/// Запись `Contact` (адрес нормализуется). `true`, если вектор изменился: новый адрес или
/// `last_seen` не моложе `CONTACT_REFRESH_SECS`. Остаются `MAX_CONTACT_ADDRS` самых новых.
pub fn note_contact(addrs: &mut Vec<KnownAddr>, addr: SocketAddr, now_unix: u64) -> bool {
    let addr = normalize(addr);
    let mut changed = false;
    match addrs
        .iter_mut()
        .find(|k| k.source == AddrSource::Contact && k.addr == addr)
    {
        Some(k) => {
            if k.last_seen_unix > now_unix
                || expired(k.last_seen_unix, CONTACT_REFRESH_SECS, now_unix)
            {
                k.last_seen_unix = now_unix;
                changed = true;
            }
        }
        None => {
            addrs.push(KnownAddr {
                addr,
                source: AddrSource::Contact,
                last_seen_unix: now_unix,
                short_lived: addr.is_ipv6(),
                hint: false,
            });
            changed = true;
        }
    }
    // лишние (самые старые) `Contact` убираются; при равенстве уходит более ранняя запись
    loop {
        let contacts = addrs
            .iter()
            .filter(|k| k.source == AddrSource::Contact)
            .count();
        if contacts <= MAX_CONTACT_ADDRS {
            break;
        }
        let oldest = addrs
            .iter()
            .enumerate()
            .filter(|(_, k)| k.source == AddrSource::Contact)
            .min_by_key(|(_, k)| k.last_seen_unix)
            .map(|(i, _)| i);
        match oldest {
            Some(i) => {
                addrs.remove(i);
                changed = true;
            }
            None => break,
        }
    }
    changed
}

fn dead(k: &KnownAddr, now_unix: u64) -> bool {
    (k.short_lived && expired(k.last_seen_unix, SHORT_LIVED_TTL_SECS, now_unix))
        || (k.hint && expired(k.last_seen_unix, HINT_TTL_SECS, now_unix))
        || (k.source == AddrSource::Contact
            && expired(k.last_seen_unix, CONTACT_TTL_SECS, now_unix))
        || (k.source == AddrSource::Invite && expired(k.last_seen_unix, INVITE_TTL_SECS, now_unix))
        || (expired(k.last_seen_unix, PRIVATE_TTL_SECS, now_unix)
            && classify(normalize(k.addr).ip()) == AddrClass::Private)
}

/// Убрать короткоживущие и подсказки старше их сроков, `Contact` старше `CONTACT_TTL_SECS`.
pub fn prune(addrs: &mut Vec<KnownAddr>, now_unix: u64) {
    addrs.retain(|k| !dead(k, now_unix));
}

/// Группа порядка набора: обновление без подсказки, приглашение, контакт, подсказка, прочее.
fn group(k: &KnownAddr) -> u8 {
    if k.hint {
        3
    } else {
        match k.source {
            AddrSource::AddressUpdate => 0,
            AddrSource::Invite => 1,
            AddrSource::Contact => 2,
            _ => 4,
        }
    }
}

/// Очищенный вид для набора. Порядок: `AddressUpdate` без подсказки, `Invite`, `Contact`,
/// подсказки, прочее; внутри группы IPv4 раньше IPv6; повторы убираются.
pub fn usable(addrs: &[KnownAddr], now_unix: u64) -> Vec<SocketAddr> {
    let mut live: Vec<&KnownAddr> = addrs.iter().filter(|k| !dead(k, now_unix)).collect();
    // сортировка устойчивая: внутри (группа, семейство) сохраняется порядок хранения
    live.sort_by_key(|k| (group(k), k.addr.is_ipv6()));
    let mut out: Vec<SocketAddr> = Vec::with_capacity(live.len());
    for k in live {
        if !out.contains(&k.addr) {
            out.push(k.addr);
        }
    }
    out
}

/// Те же записи и порядок, что у `usable`, но с флагами (`source`, `short_lived`, `hint`):
/// слою соединения нужны источник и подсказка для лимитера и порядка. Повторы адреса
/// убираются, остаётся первая запись в порядке набора.
pub fn usable_entries(addrs: &[KnownAddr], now_unix: u64) -> Vec<KnownAddr> {
    let mut live: Vec<&KnownAddr> = addrs.iter().filter(|k| !dead(k, now_unix)).collect();
    live.sort_by_key(|k| (group(k), k.addr.is_ipv6()));
    let mut out: Vec<KnownAddr> = Vec::with_capacity(live.len());
    for k in live {
        if !out.iter().any(|o| o.addr == k.addr) {
            out.push(k.clone());
        }
    }
    out
}

/// Живые адреса, подтверждённые нашим соединением (`Contact`, не подсказка), нормализованные.
/// `usable_entries` убирает повтор адреса и оставляет запись более раннего источника
/// (`AddressUpdate`, `Invite`), а подтверждение соединением этим теряется: слою соединения
/// оно нужно для быстрого окна (этап 17, S2, M1).
pub fn confirmed_addrs(addrs: &[KnownAddr], now_unix: u64) -> Vec<SocketAddr> {
    addrs
        .iter()
        .filter(|k| k.source == AddrSource::Contact && !k.hint && !dead(k, now_unix))
        .map(|k| normalize(k.addr))
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Findability {
    Ok,
    NeedToken,
}

/// Постоянный адрес друга: непросроченная запись `Invite` или `AddressUpdate`, не
/// короткоживущая, не подсказка, глобальная. `NeedToken` тогда и только тогда, когда нет ни
/// своего постоянного адреса, ни постоянного адреса друга.
pub fn findability(own_stable: bool, friend: &[KnownAddr], now_unix: u64) -> Findability {
    let friend_stable = friend.iter().any(|k| {
        !dead(k, now_unix)
            && matches!(k.source, AddrSource::Invite | AddrSource::AddressUpdate)
            && !k.short_lived
            && !k.hint
            && classify(normalize(k.addr).ip()) == AddrClass::Global
    });
    if !own_stable && !friend_stable {
        Findability::NeedToken
    } else {
        Findability::Ok
    }
}
