//! Контракт поиска в LAN (этап 13в, D9): типы и неблокирующий интерфейс. Реализация
//! (маяки по multicast) живёт в `chervo-lan`, потребитель (`chervo-connect`) видит только этот
//! интерфейс. Сокетного кода здесь нет.

use std::fmt;
use std::net::SocketAddrV4;

use chervo_identity::{LanKeys, PairId};

/// Сколько найденных адресов отдаёт один `take_found` (и сколько хранит очередь).
pub const LAN_FOUND_MAX: usize = 64;

/// Найден частный адрес друга: подсказка для набора, не доверие.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LanFound {
    pub pair: PairId,
    pub addr: SocketAddrV4,
}

impl fmt::Debug for LanFound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LanFound(..)")
    }
}

/// Пара и её ключи поиска в LAN. Без `Clone`: ключи не копируются.
pub struct LanPeer {
    pub pair: PairId,
    pub keys: LanKeys,
}

impl fmt::Debug for LanPeer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LanPeer(..)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LanStatus {
    /// Сокеты закрыты по выключателю или ещё нет локального адреса.
    Off,
    /// Нет ни одного активного друга: ничего не шлём и не слушаем.
    NoPeers,
    /// Нет частного маршрутного IPv4.
    NoLan,
    /// Сокеты не открылись (порт занят, запрет); повтор через 30 с.
    Unavailable,
    Running,
}

/// Каждый метод неблокирующий (замок и запись значения, без ввода-вывода) и возвращается
/// за миллисекунды.
pub trait LanLink: Send + Sync {
    /// Наш частный IPv4 маршрута по умолчанию и порт прослушивания QUIC; `None` закрывает сокеты.
    fn set_local(&self, local: Option<SocketAddrV4>);
    /// Заменяет всех друзей. Удалённая пара больше не анонсируется и не находится, сразу.
    fn set_peers(&self, peers: Vec<LanPeer>);
    /// Пары без живого соединения. Читается с первым маяком следующей эпохи.
    fn set_wanted(&self, wanted: Vec<PairId>);
    /// Серия маяков (запуск, действие пользователя). Предел частоты действует.
    fn trigger(&self);
    /// Не больше `LAN_FOUND_MAX`, старые первыми; очередь опустошается.
    fn take_found(&self) -> Vec<LanFound>;
    fn status(&self) -> LanStatus;
    /// Закрывает сокеты, останавливает поток (ожидание не дольше 1 с). Повторный вызов безвреден.
    fn shutdown(&self);
}
