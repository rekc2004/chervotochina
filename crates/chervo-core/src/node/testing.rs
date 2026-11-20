//! Единственное место, где узлу подставляется хранилище ключей, и единственное окно в узел для
//! тестов. Продуктовый код этим не пользуется: страж `tests/test_store_guard.rs` проверяет, что
//! имя точки входа нигде в `crates/*/src`, кроме этого файла, не встречается.

use std::sync::Arc;

use chervo_timesync::{ClockOffset, SyncError};

use super::error::NodeError;
use super::events::NodeEvents;
use super::store::KeyBackend;
use super::views::ClockSync;
use super::{Node, NodeConfig, OpenMode, StoreSource, open_node};
use crate::HardenReport;

/// Тестовый узел слушает только петлю (этап 18е): без этого Windows спрашивает разрешение для
/// каждого пересобранного тестового бинаря. Без свойства `test-net` ничего не делает.
fn enable_loopback() {
    #[cfg(any(test, feature = "test-net"))]
    super::loopback::bind_loopback_only();
}

/// Режим запуска для тестов (как три `open*` продукта).
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TestOpen {
    Normal,
    AcceptOlder,
    StartOver,
}

impl Node {
    /// Запуск с подставленным хранилищем (только тесты).
    #[doc(hidden)]
    pub fn open_with_store_for_tests(
        cfg: NodeConfig,
        h: &HardenReport,
        store: Arc<dyn KeyBackend>,
    ) -> Result<(Node, NodeEvents), NodeError> {
        enable_loopback();
        open_node(cfg, h, OpenMode::Normal, StoreSource::Given(store))
    }

    /// То же с выбором режима (`AcceptOlder`, `StartOver`).
    #[doc(hidden)]
    pub fn open_with_store_for_tests_mode(
        cfg: NodeConfig,
        h: &HardenReport,
        store: Arc<dyn KeyBackend>,
        mode: TestOpen,
    ) -> Result<(Node, NodeEvents), NodeError> {
        let mode = match mode {
            TestOpen::Normal => OpenMode::Normal,
            TestOpen::AcceptOlder => OpenMode::AcceptOlder,
            TestOpen::StartOver => OpenMode::StartOver,
        };
        enable_loopback();
        open_node(cfg, h, mode, StoreSource::Given(store))
    }

    /// Интервал поддержания адреса ждущих приглашений вместо `KEEPALIVE_EVERY` (этап 13д;
    /// действует на приглашения, созданные после вызова).
    #[doc(hidden)]
    pub fn set_keepalive_every_for_tests(&self, every: std::time::Duration) {
        *self
            .core
            .echo
            .every_override
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(every);
    }

    /// Запомнить адрес разрешённого роутера с заданным источником маршрута, как это делает
    /// `upnp_allow` (без сети и записи настроек; этап 13д, круг 1).
    #[doc(hidden)]
    pub fn set_allowed_router_for_tests(
        &self,
        ip: std::net::Ipv4Addr,
        source: Option<std::net::Ipv4Addr>,
    ) {
        let Ok(id) = chervo_upnp::RouterId::from_setting("uuid:test-router") else {
            return;
        };
        *self
            .core
            .allowed_router
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(super::echo::AllowedAddr::with_source(id, ip, source));
    }

    /// Найден роутер с данным UDN; `in_list`: он уже в списке разрешённых (только в памяти,
    /// без записи настроек и сети). Возвращает, запомнился ли адрес (этап 13д, круг 1).
    #[doc(hidden)]
    pub fn note_identified_for_tests(
        &self,
        udn: &str,
        ip: std::net::Ipv4Addr,
        in_list: bool,
    ) -> bool {
        let Ok(id) = chervo_upnp::RouterId::from_setting(udn) else {
            return false;
        };
        if in_list {
            self.core
                .settings
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .routers
                .push(chervo_upnp::AllowedRouter {
                    id: id.clone(),
                    permanent_ok: false,
                });
        }
        self.note_identified(&id, ip);
        self.core
            .allowed_router
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .is_some_and(|a| a.is_router(&id))
    }

    /// Что помощник возьмёт за адрес роутера и источник маршрута, если сейчас источник
    /// маршрута к роутеру равен `now` (этап 13д, круг 1).
    #[doc(hidden)]
    pub fn allowed_router_for_tests(
        &self,
        now: Option<std::net::Ipv4Addr>,
    ) -> (Option<std::net::Ipv4Addr>, Option<std::net::Ipv4Addr>) {
        self.allowed_router_with(|_| now)
    }

    /// Сколько приглашений сейчас поддерживают адрес (этап 13д).
    #[doc(hidden)]
    pub fn keepalive_count_for_tests(&self) -> usize {
        self.core
            .echo
            .keepalives
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Итог сверки часов без сети (тесты порога в 5 минут).
    #[doc(hidden)]
    pub fn clock_result_for_tests(
        &self,
        result: Result<ClockOffset, SyncError>,
    ) -> Result<ClockSync, NodeError> {
        self.decide_clock(result)
    }

    /// Разрешение на проверку новых версий с заданным временем, секунды UTC (тесты правил
    /// Р19г-6: настоящие часы подменить нельзя).
    #[doc(hidden)]
    pub fn update_check_permit_at_for_tests(
        &self,
        now_unix_secs: u64,
        manual: bool,
    ) -> Result<Option<crate::update::UpdateCheckPermit>, NodeError> {
        self.update_check_permit_at(now_unix_secs, manual)
    }
}
