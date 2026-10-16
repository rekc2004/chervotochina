use chervo_addr::KnownAddr;
use chervo_identity::{KxPublicKey, PairId, PublicKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AutoAcceptLimits {
    pub max_total_bytes: u64,
    pub max_files: u32,
}

/// По умолчанию всегда `Ask`: автоприём только явно и с лимитами.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Permission {
    #[default]
    Ask,
    AutoAccept(AutoAcceptLimits),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FriendState {
    Active,
    Blocked,
    RevokedByPeer,
}

/// Без `Debug`: имена, адреса и ключи не печатаются через derive.
#[derive(Clone)]
pub struct Friend {
    pub pair: PairId,
    pub name: String,
    pub friend_ed: PublicKey,
    pub friend_x: KxPublicKey,
    /// Метка нашего ключа пары (ожидаемый публичный ключ для `identity::load`).
    pub our_ed: PublicKey,
    pub state: FriendState,
    pub permission: Permission,
    pub known_addrs: Vec<KnownAddr>,
    /// Наибольший принятый номер обновления адреса от друга (строго растёт).
    pub last_addr_seq: u64,
    /// Последний выпущенный нами номер обновления для этого друга (сохраняется до выдачи токена).
    pub addr_seq_out: u64,
    pub added_at_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingRole {
    Inviter,
    Invitee,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingEntry {
    pub pair: PairId,
    pub role: PendingRole,
    pub expires_at_unix: u64,
}

/// Содержимое файла списка.
#[derive(Clone, Default)]
pub struct BookData {
    pub friends: Vec<Friend>,
    pub pending: Vec<PendingEntry>,
}
