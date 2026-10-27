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
        open_node(cfg, h, mode, StoreSource::Given(store))
    }

    /// Итог сверки часов без сети (тесты порога в 5 минут).
    #[doc(hidden)]
    pub fn clock_result_for_tests(
        &self,
        result: Result<ClockOffset, SyncError>,
    ) -> Result<ClockSync, NodeError> {
        self.decide_clock(result)
    }
}
