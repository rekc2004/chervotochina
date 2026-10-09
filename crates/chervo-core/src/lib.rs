//! Фасад без UI для оболочек (CLI, GUI, мобильные). Обобщён по трейту транспорта
//! и не зависит от конкретной реализации транспорта.

use std::path::PathBuf;

pub use chervo_addr;
pub use chervo_connect;
pub use chervo_friends;
pub use chervo_identity;
pub use chervo_receive;
pub use chervo_token;
pub use chervo_transfer;
pub use chervo_transport;

use chervo_receive::ReceiveLimits;
use chervo_transport::Transport;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConfig {
    pub data_dir: PathBuf,
    pub receive_limits: ReceiveLimits,
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
