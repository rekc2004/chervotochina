//! Контракт поиска друзей в локальной сети (этап 13в, часть L2): типы и интерфейс. Сокетного
//! кода здесь нет; реализация (свой маяк) живёт в `chervo-lan`, потребитель (`chervo-connect`)
//! видит только этот интерфейс, как `PortMapper` в этапе 13а.
//! Спецификация: `docs/specs/stage-13v-lan.md`.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};

use chervo_identity::{KxPeer, PairId};

/// Режим: `Off` ничего не делает; `Listen` только слушает и ничего не рассылает;
/// `Announce` рассылает маяк и тоже слушает.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LanMode {
    Off,
    Listen,
    Announce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LanStatus {
    Off,
    NoPrivateRoute,
    PortBusy,
    Listening,
    Announcing,
    Failed,
}

/// Наш адрес маршрута по умолчанию и порт прослушивания транспорта (не 0).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LanLocal {
    /// IPv4 маршрута по умолчанию любого класса (петля и неуказанный адрес не передаются).
    /// Под VPN это адрес туннеля: какие интерфейсы частные и годятся для поиска, решает
    /// `chervo-lan` опросом маршрутов.
    pub own: Ipv4Addr,
    pub listen_port: u16,
}

impl fmt::Debug for LanLocal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LanLocal(..)")
    }
}

/// Друг услышан по маяку: пара и адрес для набора. Только кандидат, не факт.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LanSighting {
    pub pair: PairId,
    pub addr: SocketAddrV4,
}

impl fmt::Debug for LanSighting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LanSighting(..)")
    }
}

pub trait LanDiscovery: Send + Sync {
    /// `None`: перестать слать и слушать, закрыть сокеты.
    fn set_local(&self, local: Option<LanLocal>);
    /// Только действующие друзья; ключи выводятся в потоке службы, не здесь.
    fn set_peers(&self, peers: Vec<KxPeer>);
    /// Без блокировки; не больше 64, по одному на пару.
    fn take_sightings(&self) -> Vec<LanSighting>;
    fn status(&self) -> LanStatus;
    /// Сигнал без блокировки; поток службы завершается не позже чем через 250 мс.
    fn shutdown(&self);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacted() {
        let l = LanLocal {
            own: Ipv4Addr::new(192, 168, 1, 5),
            listen_port: 40_000,
        };
        assert_eq!(format!("{l:?}"), "LanLocal(..)");
        let s = LanSighting {
            pair: PairId::from_bytes([9; 16]),
            addr: SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 6), 40_001),
        };
        assert_eq!(format!("{s:?}"), "LanSighting(..)");
        assert_eq!(format!("{s:#?}"), "LanSighting(..)");
    }

    #[test]
    fn trait_is_object_safe() {
        fn _takes(_: &dyn LanDiscovery) {}
    }
}
