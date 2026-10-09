//! Список друзей: типы и заглушка хранилища.

use std::fmt;

use chervo_addr::KnownAddr;
use chervo_identity::DeviceId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoAcceptLimits {
    pub max_total_bytes: u64,
    pub max_files: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Permission {
    #[default]
    Ask,
    AutoAccept(AutoAcceptLimits),
}

/// Без Debug: имена и адреса не печатаются через derive.
#[derive(Clone)]
pub struct Friend {
    pub name: String,
    pub id: DeviceId,
    pub known_addrs: Vec<KnownAddr>,
    pub permission: Permission,
    pub last_addr_seq: u64,
    pub blocked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FriendsError {
    NotImplemented,
}

impl fmt::Display for FriendsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not implemented")
    }
}

impl std::error::Error for FriendsError {}

pub trait FriendStore {
    fn list(&self) -> Result<Vec<Friend>, FriendsError>;
    fn get(&self, id: &DeviceId) -> Result<Option<Friend>, FriendsError>;
    fn upsert(&mut self, friend: Friend) -> Result<(), FriendsError>;
    fn remove(&mut self, id: &DeviceId) -> Result<(), FriendsError>;
}

/// Заглушка хранилища: всегда `NotImplemented`.
pub struct UnavailableFriendStore;

impl FriendStore for UnavailableFriendStore {
    fn list(&self) -> Result<Vec<Friend>, FriendsError> {
        Err(FriendsError::NotImplemented)
    }

    fn get(&self, _id: &DeviceId) -> Result<Option<Friend>, FriendsError> {
        Err(FriendsError::NotImplemented)
    }

    fn upsert(&mut self, _friend: Friend) -> Result<(), FriendsError> {
        Err(FriendsError::NotImplemented)
    }

    fn remove(&mut self, _id: &DeviceId) -> Result<(), FriendsError> {
        Err(FriendsError::NotImplemented)
    }
}
