//! Фасад без UI для оболочек (CLI, GUI, мобильные). Обобщён по трейту транспорта
//! и не зависит от конкретной реализации транспорта.

use std::path::PathBuf;

mod harden;

pub use chervo_addr;
pub use chervo_connect;
pub use chervo_friends;
pub use chervo_identity;
pub use chervo_receive;
pub use chervo_token;
pub use chervo_transfer;
pub use chervo_transport;

pub use harden::{HardenReport, harden_process};

use chervo_receive::ReceiveLimits;
use chervo_transport::Transport;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// `Debug` без пути `data_dir`: путь содержит имя пользователя (этап 17, B3).
#[derive(Clone, PartialEq, Eq)]
pub struct NodeConfig {
    pub data_dir: PathBuf,
    pub receive_limits: ReceiveLimits,
}

impl std::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeConfig")
            .field("receive_limits", &self.receive_limits)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoreError {
    NotImplemented,
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("not implemented")
    }
}

impl std::error::Error for CoreError {}

/// Конструктор ничего не открывает и не пишет.
pub struct Node<T: Transport> {
    transport: T,
    config: NodeConfig,
}

impl<T: Transport> Node<T> {
    pub fn new(transport: T, config: NodeConfig) -> Self {
        Self { transport, config }
    }

    pub fn transport(&self) -> &T {
        &self.transport
    }

    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Заглушка: всегда `NotImplemented`.
    pub fn start(&self) -> Result<(), CoreError> {
        Err(CoreError::NotImplemented)
    }
}
