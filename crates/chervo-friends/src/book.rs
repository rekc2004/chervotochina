//! Книга друзей: CRUD, права, блокировка, удаление, смена ключа, приём отзыва поверх
//! зашифрованного файла списка (этап 11, часть О1). Только вызовы API `chervo-identity`,
//! `chervo-token` и `vault`; своей криптографии нет.
//!
//! # Порядок приложения (проверяется сетевыми тестами `tests/invite_net.rs`)
//!
//! Сторона A (пригласившая): `begin_pair(Inviter, now + ttl)`, запомнить `key.public_key()`
//! и `key.kx_public()`, `chervo_token::issue_invite`, `transport.set_peers(kx_peers +
//! KxPeer(pair, key.into_kx(), pending.guest_public()))`, на соединение гостевой пары
//! `begin_session`, `flow::inviter_exchange`, показать SAS, `flow::exchange_decision`.
//! Оба подтвердили: `conn.close()`, `finish_pair(B_ed, B_x, ..)`, `set_peers(kx_peers)`.
//! Иначе `abort_pair` и `set_peers` без гостя.
//!
//! Сторона B (приглашённая): `decode`, `check_time`, `begin_pair(Invitee,
//! token.expires_at() + CLOCK_TOLERANCE_SECS)`, `InviteeSession::start`, `set_peers(+
//! KxPeer(pair, token.guest_secret()?.into_kx(), token.inviter_x()))`, `connect`,
//! `flow::invitee_exchange`, SAS, `flow::exchange_decision`. Оба подтвердили:
//! `finish_pair(A_ed, A_x, ..)`, `set_peers(kx_peers)`; иначе `abort_pair`.
//!
//! После любого изменения книги (блокировка, удаление, отзыв, смена ключа) вызывающий делает
//! `set_peers(kx_peers + гостевые пары)`: живые соединения исключённых пар рвутся.
//! При старте приложения вызывается `drop_all_pending` (секреты незавершённых сессий жили
//! только в памяти), раз в минуту `expire`.

use std::ffi::OsString;
use std::fmt;
use std::io::{ErrorKind, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use chervo_addr::{Findability, KnownAddr, PublishSet};
use chervo_identity::{
    IdentityError, KxPeer, KxPublicKey, LIST_KEY_LEN, ListKeyStore, PairId, PairKey, PublicKey,
    SecretStore, create, load,
};
use chervo_token::{
    AddrUpdate, IssuedAddrUpdate, RevocationReason, SignedAddrUpdate, Token, TokenError, decode,
    issue_addr_update, issue_revocation,
};
use zeroize::Zeroizing;

use crate::plain::name_ok;
use crate::{
    BookData, Friend, FriendState, FriendsError, MAX_ADDRS_PER_FRIEND, MAX_FILE_BYTES, MAX_FRIENDS,
    MAX_PENDING, PendingEntry, PendingRole, Permission, vault,
};

/// Книга друзей. `Debug` не печатает содержимое.
pub struct FriendBook {
    path: PathBuf,
    key: Option<Zeroizing<[u8; 32]>>,
    data: BookData,
    /// Подписанные отзывы, чей ключ пары уже удалён, а запись списка сохранить не удалось
    /// (по одному на пару). Повтор `remove`/`rekey` отдаёт этот текст. Только в памяти.
    unsent: Vec<(PairId, String)>,
    /// Время последнего применённого обновления адреса по соединению (на пару). Только в памяти.
    inband: Vec<(PairId, u64)>,
}

/// Минимальный интервал между принятыми обновлениями адреса по соединению для одной пары.
pub const MIN_INBAND_UPDATE_INTERVAL_SECS: u64 = 10;
/// Множитель времени в номере обновления: `seq >= now_unix * SEQ_TIME_SCALE` (номер переживает
/// откат файла списка к копии, пока часы не ушли назад).
const SEQ_TIME_SCALE: u64 = 1000;

/// Следующий номер обновления: `max(prev + 1, now * 1000)`; `None` при переполнении `prev + 1`.
pub(crate) fn next_seq(prev: u64, now_unix: u64) -> Option<u64> {
    let step = prev.checked_add(1)?;
    Some(step.max(now_unix.saturating_mul(SEQ_TIME_SCALE)))
}

/// Не больше `MAX_ADDRS_PER_FRIEND` записей: лишние (самые давние по `last_seen`) убираются.
fn trim_addrs(addrs: &mut Vec<KnownAddr>) {
    while addrs.len() > MAX_ADDRS_PER_FRIEND {
        let oldest = addrs
            .iter()
            .enumerate()
            .min_by_key(|(_, k)| k.last_seen_unix)
            .map(|(i, _)| i);
        match oldest {
            Some(i) => {
                addrs.remove(i);
            }
            None => break,
        }
    }
}

impl fmt::Debug for FriendBook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FriendBook(..)")
    }
}

/// Данные нового друга при завершении приглашения. Без `Debug`: имя, адреса, ключи.
pub struct NewFriend {
    pub name: String,
    pub friend_ed: PublicKey,
    pub friend_x: KxPublicKey,
    pub our_ed: PublicKey,
    pub our_x: KxPublicKey,
    pub addrs: Vec<KnownAddr>,
    pub now_unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// Ключа пары нет, он испорчен или не совпал с ожидаемым: показать `KEY_LOST_TEXT`.
    MissingOrChanged,
    /// Запись ключа неизвестной версии: спросить пользователя, автоматически ничего не делать.
    NeedsDecision,
}

/// Результат `kx_peers`: пары для транспорта и пары с потерянным ключом.
pub type KxPeerSet = (Vec<KxPeer>, Vec<(PairId, KeyStatus)>);

fn map_identity(e: IdentityError) -> FriendsError {
    match e {
        IdentityError::RandomUnavailable => FriendsError::RandomUnavailable,
        IdentityError::KeyAlreadyExists => FriendsError::AlreadyExists,
        // StorageLocked, StorageUnavailable и прочее: одна и та же ошибка (Н1)
        _ => FriendsError::KeyStorageUnavailable,
    }
}

fn tmp_path(path: &Path) -> PathBuf {
    let mut s: OsString = path.as_os_str().to_os_string();
    s.push(".tmp");
    PathBuf::from(s)
}

fn key_from(raw: &[u8]) -> Result<Zeroizing<[u8; 32]>, FriendsError> {
    if raw.len() != LIST_KEY_LEN {
        return Err(FriendsError::Corrupt);
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(raw);
    Ok(k)
}

fn read_file(path: &Path) -> Result<Option<Zeroizing<Vec<u8>>>, FriendsError> {
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(FriendsError::Io),
    };
    if meta.len() > MAX_FILE_BYTES as u64 {
        return Err(FriendsError::Corrupt);
    }
    match std::fs::read(path) {
        Ok(v) => Ok(Some(Zeroizing::new(v))),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(_) => Err(FriendsError::Io),
    }
}

impl FriendBook {
    /// Файла нет: пустая книга (ключ читается, если он есть). Файл есть, ключа нет:
    /// `ListKeyMissing`, файл не трогается.
    pub fn open<K: ListKeyStore + ?Sized>(path: &Path, keys: &K) -> Result<Self, FriendsError> {
        let stored = keys.read_list_key().map_err(map_identity)?;
        let key = match stored {
            Some(raw) => Some(key_from(&raw)?),
            None => None,
        };
        match read_file(path)? {
            None => Ok(Self {
                path: path.to_path_buf(),
                key,
                data: BookData::default(),
                unsent: Vec::new(),
                inband: Vec::new(),
            }),
            Some(file) => {
                let k = key.ok_or(FriendsError::ListKeyMissing)?;
                let data = vault::open(&k, &file)?;
                Ok(Self {
                    path: path.to_path_buf(),
                    key: Some(k),
                    data,
                    unsent: Vec::new(),
                    inband: Vec::new(),
                })
            }
        }
    }

    /// Явно: переименовать нечитаемый файл в `"<path>.unreadable-<now>"` и начать пустую книгу.
    pub fn start_over<K: ListKeyStore + ?Sized>(
        path: &Path,
        keys: &K,
        now_unix: u64,
    ) -> Result<Self, FriendsError> {
        let stored = keys.read_list_key().map_err(map_identity)?;
        let key = match stored {
            Some(raw) => Some(key_from(&raw)?),
            None => None,
        };
        let mut moved: OsString = path.as_os_str().to_os_string();
        moved.push(format!(".unreadable-{now_unix}"));
        match std::fs::rename(path, PathBuf::from(moved)) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(_) => return Err(FriendsError::Io),
        }
        Ok(Self {
            path: path.to_path_buf(),
            key,
            data: BookData::default(),
            unsent: Vec::new(),
            inband: Vec::new(),
        })
    }

    pub fn friends(&self) -> &[Friend] {
        &self.data.friends
    }

    pub fn get(&self, pair: &PairId) -> Option<&Friend> {
        self.data.friends.iter().find(|f| f.pair == *pair)
    }

    pub fn pending(&self) -> &[PendingEntry] {
        &self.data.pending
    }

    /// Ключ списка: из памяти, из хранилища или (только если нет ни файла, ни ключа) новый.
    fn ensure_key<K: ListKeyStore + ?Sized>(
        &mut self,
        keys: &K,
    ) -> Result<Zeroizing<[u8; 32]>, FriendsError> {
        if let Some(k) = &self.key {
            return Ok(k.clone());
        }
        let found = keys.read_list_key().map_err(map_identity)?;
        let k = match found {
            Some(raw) => key_from(&raw)?,
            None => {
                if self.path.try_exists().map_err(|_| FriendsError::Io)? {
                    return Err(FriendsError::ListKeyMissing);
                }
                let mut fresh = Zeroizing::new([0u8; 32]);
                getrandom::fill(fresh.as_mut_slice())
                    .map_err(|_| FriendsError::RandomUnavailable)?;
                keys.write_list_key(fresh.as_slice())
                    .map_err(map_identity)?;
                let back = keys.read_list_key().map_err(map_identity)?;
                match back {
                    Some(b) if b.as_slice() == fresh.as_slice() => fresh,
                    _ => return Err(FriendsError::KeyStorageUnavailable),
                }
            }
        };
        self.key = Some(k.clone());
        Ok(k)
    }

    /// seal, запись в `<path>.tmp` (новый файл 0600), `sync_all`, `rename` поверх `path`, fsync каталога.
    fn save<K: ListKeyStore + ?Sized>(&mut self, keys: &K) -> Result<(), FriendsError> {
        let k = self.ensure_key(keys)?;
        let bytes = vault::seal(&k, &self.data)?;
        let tmp = tmp_path(&self.path);
        let written = (|| -> std::io::Result<()> {
            // старый `.tmp` (в том числе симлинк) убирается, не открывается; `create_new` не
            // следует симлинкам; на unix права 0600
            match std::fs::remove_file(&tmp) {
                Err(e) if e.kind() != ErrorKind::NotFound => return Err(e),
                _ => {}
            }
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
            let mut f = opts.open(&tmp)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, &self.path)?;
            // fsync каталога: перемещение записи переживает сбой питания. `rename` уже
            // выполнен, поэтому ошибка здесь не откатывает запись.
            #[cfg(unix)]
            if let Some(dir) = self.path.parent() {
                let dir = if dir.as_os_str().is_empty() {
                    Path::new(".")
                } else {
                    dir
                };
                if let Ok(d) = std::fs::File::open(dir) {
                    let _ = d.sync_all();
                }
            }
            Ok(())
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&tmp);
            return Err(FriendsError::Io);
        }
        Ok(())
    }

    /// Применить изменение и сохранить; при любой ошибке состояние в памяти откатывается.
    fn commit<K: ListKeyStore + ?Sized, T>(
        &mut self,
        keys: &K,
        f: impl FnOnce(&mut BookData) -> Result<T, FriendsError>,
    ) -> Result<T, FriendsError> {
        let backup = self.data.clone();
        let out = match f(&mut self.data) {
            Ok(v) => v,
            Err(e) => {
                self.data = backup;
                return Err(e);
            }
        };
        if let Err(e) = self.save(keys) {
            self.data = backup;
            return Err(e);
        }
        Ok(out)
    }

    /// Начать пару: запись pending сохраняется ДО создания ключа (Н2); при ошибке создания
    /// ключ и запись убираются.
    pub fn begin_pair<S: SecretStore + ListKeyStore + ?Sized>(
        &mut self,
        store: &S,
        role: PendingRole,
        expires_at_unix: u64,
    ) -> Result<(PairId, PairKey), FriendsError> {
        if self.data.pending.len() >= MAX_PENDING {
            return Err(FriendsError::LimitExceeded);
        }
        let pair = PairId::generate().map_err(map_identity)?;
        self.commit(store, |d| {
            d.pending.push(PendingEntry {
                pair,
                role,
                expires_at_unix,
            });
            Ok(())
        })?;
        match create(store, &pair) {
            Ok(key) => Ok((pair, key)),
            Err(e) => {
                let _ = SecretStore::delete(store, &pair);
                let _ = self.commit(store, |d| {
                    d.pending.retain(|p| p.pair != pair);
                    Ok(())
                });
                Err(map_identity(e))
            }
        }
    }

    /// Прервать незавершённую пару: удалить ключ, затем запись. Ошибка хранилища: запись
    /// остаётся (повтор позже).
    pub fn abort_pair<S: SecretStore + ListKeyStore + ?Sized>(
        &mut self,
        store: &S,
        pair: &PairId,
    ) -> Result<(), FriendsError> {
        if !self.data.pending.iter().any(|p| p.pair == *pair) {
            return Err(FriendsError::UnknownPair);
        }
        SecretStore::delete(store, pair).map_err(map_identity)?;
        self.commit(store, |d| {
            d.pending.retain(|p| p.pair != *pair);
            Ok(())
        })
    }

    /// `abort_pair` для всех записей со сроком `<= now`. Возвращает число прерванных.
    pub fn expire<S: SecretStore + ListKeyStore + ?Sized>(
        &mut self,
        store: &S,
        now_unix: u64,
    ) -> Result<usize, FriendsError> {
        let due: Vec<PairId> = self
            .data
            .pending
            .iter()
            .filter(|p| p.expires_at_unix <= now_unix)
            .map(|p| p.pair)
            .collect();
        let mut n = 0usize;
        for pair in due {
            self.abort_pair(store, &pair)?;
            n = n.saturating_add(1);
        }
        Ok(n)
    }

    /// `abort_pair` для всех записей (при старте приложения).
    pub fn drop_all_pending<S: SecretStore + ListKeyStore + ?Sized>(
        &mut self,
        store: &S,
    ) -> Result<usize, FriendsError> {
        let all: Vec<PairId> = self.data.pending.iter().map(|p| p.pair).collect();
        let mut n = 0usize;
        for pair in all {
            self.abort_pair(store, &pair)?;
            n = n.saturating_add(1);
        }
        Ok(n)
    }

    /// Завершить приглашение: pending превращается в друга `Active` с правом `Ask`.
    pub fn finish_pair<S: SecretStore + ListKeyStore + ?Sized>(
        &mut self,
        store: &S,
        pair: &PairId,
        f: NewFriend,
    ) -> Result<(), FriendsError> {
        if !self.data.pending.iter().any(|p| p.pair == *pair) {
            return Err(FriendsError::UnknownPair);
        }
        if !name_ok(&f.name) {
            return Err(FriendsError::InvalidName);
        }
        if f.friend_ed == f.our_ed || f.friend_x == f.our_x {
            return Err(FriendsError::KeyMissingOrChanged);
        }
        if self.data.friends.iter().any(|x| x.pair == *pair) {
            return Err(FriendsError::AlreadyExists);
        }
        if self.data.friends.len() >= MAX_FRIENDS {
            return Err(FriendsError::LimitExceeded);
        }
        let mut addrs = f.addrs;
        addrs.truncate(MAX_ADDRS_PER_FRIEND);
        let friend = Friend {
            pair: *pair,
            name: f.name,
            friend_ed: f.friend_ed,
            friend_x: f.friend_x,
            our_ed: f.our_ed,
            state: FriendState::Active,
            permission: Permission::Ask,
            known_addrs: addrs,
            last_addr_seq: 0,
            addr_seq_out: 0,
            added_at_unix: f.now_unix,
        };
        self.commit(store, |d| {
            d.pending.retain(|p| p.pair != *pair);
            d.friends.push(friend);
            Ok(())
        })
    }

    pub fn rename<K: ListKeyStore + ?Sized>(
        &mut self,
        keys: &K,
        pair: &PairId,
        name: &str,
    ) -> Result<(), FriendsError> {
        if !name_ok(name) {
            return Err(FriendsError::InvalidName);
        }
        self.commit(keys, |d| {
            let fr = d
                .friends
                .iter_mut()
                .find(|x| x.pair == *pair)
                .ok_or(FriendsError::UnknownPair)?;
            fr.name = name.to_owned();
            Ok(())
        })
    }

    /// По умолчанию всегда `Ask`; `AutoAccept` только явно и с ненулевыми лимитами.
    pub fn set_permission<K: ListKeyStore + ?Sized>(
        &mut self,
        keys: &K,
        pair: &PairId,
        p: Permission,
    ) -> Result<(), FriendsError> {
        if let Permission::AutoAccept(l) = p
            && (l.max_files == 0 || l.max_total_bytes == 0)
        {
            return Err(FriendsError::InvalidLimits);
        }
        self.commit(keys, |d| {
            let fr = d
                .friends
                .iter_mut()
                .find(|x| x.pair == *pair)
                .ok_or(FriendsError::UnknownPair)?;
            fr.permission = p;
            Ok(())
        })
    }

    fn switch_state<K: ListKeyStore + ?Sized>(
        &mut self,
        keys: &K,
        pair: &PairId,
        from: FriendState,
        to: FriendState,
    ) -> Result<(), FriendsError> {
        self.commit(keys, |d| {
            let fr = d
                .friends
                .iter_mut()
                .find(|x| x.pair == *pair && x.state == from)
                .ok_or(FriendsError::UnknownPair)?;
            fr.state = to;
            Ok(())
        })
    }

    /// `Active` -> `Blocked`. Вызывающий затем делает `set_peers`.
    pub fn block<K: ListKeyStore + ?Sized>(
        &mut self,
        keys: &K,
        pair: &PairId,
    ) -> Result<(), FriendsError> {
        self.switch_state(keys, pair, FriendState::Active, FriendState::Blocked)
    }

    /// `Blocked` -> `Active`.
    pub fn unblock<K: ListKeyStore + ?Sized>(
        &mut self,
        keys: &K,
        pair: &PairId,
    ) -> Result<(), FriendsError> {
        self.switch_state(keys, pair, FriendState::Blocked, FriendState::Active)
    }

    /// Текст отзыва, подписанный нашим ключом пары; `required` — ошибка, если ключ не загрузился.
    fn revocation_for<S: SecretStore + ?Sized>(
        store: &S,
        fr: &Friend,
        reason: RevocationReason,
        now_unix: u64,
    ) -> Result<Option<String>, FriendsError> {
        match load(store, &fr.pair, &fr.our_ed) {
            Ok(key) => issue_revocation(&key, reason, now_unix)
                .map(Some)
                .map_err(|_| FriendsError::BadRevocation),
            Err(
                IdentityError::KeyMissing
                | IdentityError::KeyMismatch
                | IdentityError::CorruptKey
                | IdentityError::UnsupportedKeyVersion,
            ) => Ok(None),
            Err(e) => Err(map_identity(e)),
        }
    }

    fn drop_friend<S: SecretStore + ListKeyStore + ?Sized>(
        &mut self,
        store: &S,
        pair: &PairId,
        text: Option<&str>,
    ) -> Result<(), FriendsError> {
        SecretStore::delete(store, pair).map_err(map_identity)?;
        let saved = self.commit(store, |d| {
            d.friends.retain(|x| x.pair != *pair);
            Ok(())
        });
        self.unsent.retain(|(p, _)| p != pair);
        if saved.is_err()
            && let Some(t) = text
        {
            // ключ уже удалён, запись осталась: текст отзыва не теряем до повтора
            self.unsent.push((*pair, t.to_owned()));
        }
        saved
    }

    fn unsent_for(&self, pair: &PairId) -> Option<String> {
        self.unsent
            .iter()
            .find(|(p, _)| p == pair)
            .map(|(_, t)| t.clone())
    }

    /// Отзыв (`Removed`), если ключ загрузился; затем удалить ключ и запись. Если запись
    /// списка сохранить не удалось (`Io`), ключ уже удалён, а подписанный текст отзыва
    /// хранится в памяти: повтор `remove` вернёт его (до перезапуска программы).
    pub fn remove<S: SecretStore + ListKeyStore + ?Sized>(
        &mut self,
        store: &S,
        pair: &PairId,
        now_unix: u64,
    ) -> Result<Option<String>, FriendsError> {
        let fr = self.get(pair).ok_or(FriendsError::UnknownPair)?;
        let text = match self.unsent_for(pair) {
            Some(t) => Some(t),
            None => Self::revocation_for(store, fr, RevocationReason::Removed, now_unix)?,
        };
        self.drop_friend(store, pair, text.as_deref())?;
        Ok(text)
    }

    /// «Пересоздать ключ»: отзыв (`Rekey`) старым ключом, удалить ключ и запись. Ключ не
    /// загрузился: ошибка, ничего не удалено. Сбой записи списка после удаления ключа:
    /// как у `remove`, повтор `rekey` вернёт сохранённый в памяти текст отзыва.
    pub fn rekey<S: SecretStore + ListKeyStore + ?Sized>(
        &mut self,
        store: &S,
        pair: &PairId,
        now_unix: u64,
    ) -> Result<String, FriendsError> {
        let fr = self.get(pair).ok_or(FriendsError::UnknownPair)?;
        let text = match self.unsent_for(pair) {
            Some(t) => t,
            None => match load(store, &fr.pair, &fr.our_ed) {
                Ok(key) => issue_revocation(&key, RevocationReason::Rekey, now_unix)
                    .map_err(|_| FriendsError::BadRevocation)?,
                Err(IdentityError::UnsupportedKeyVersion) => {
                    return Err(FriendsError::KeyNeedsDecision);
                }
                Err(
                    IdentityError::KeyMissing
                    | IdentityError::KeyMismatch
                    | IdentityError::CorruptKey,
                ) => return Err(FriendsError::KeyMissingOrChanged),
                Err(e) => return Err(map_identity(e)),
            },
        };
        self.drop_friend(store, pair, Some(&text))?;
        Ok(text)
    }

    /// Отзыв от друга: `decode`; друг с теми же `friend_ed` и `friend_x`, не `RevokedByPeer`,
    /// получает `RevokedByPeer`, наш ключ пары удаляется. Иначе `Ok(None)`.
    pub fn apply_revocation<S: SecretStore + ListKeyStore + ?Sized>(
        &mut self,
        store: &S,
        text: &str,
    ) -> Result<Option<PairId>, FriendsError> {
        let notice = match decode(text) {
            Ok(Token::Revocation(n)) => n,
            _ => return Err(FriendsError::BadRevocation),
        };
        let pair = match self.data.friends.iter().find(|f| {
            f.friend_ed == notice.revoked_ed
                && f.friend_x == notice.revoked_x
                && f.state != FriendState::RevokedByPeer
        }) {
            Some(f) => f.pair,
            None => return Ok(None),
        };
        // сначала ключ (идемпотентно), затем запись: при сбое сохранения отзыв можно применить снова
        SecretStore::delete(store, &pair).map_err(map_identity)?;
        self.commit(store, |d| {
            let fr = d
                .friends
                .iter_mut()
                .find(|x| x.pair == pair)
                .ok_or(FriendsError::UnknownPair)?;
            fr.state = FriendState::RevokedByPeer;
            Ok(())
        })?;
        Ok(Some(pair))
    }

    /// Только `Active`: `load` -> `into_kx` -> `KxPeer`. Пары с потерянным ключом попадают во
    /// второй список; ключ молча не создаётся.
    pub fn kx_peers<S: SecretStore + ?Sized>(&self, store: &S) -> Result<KxPeerSet, FriendsError> {
        let mut peers = Vec::new();
        let mut bad = Vec::new();
        for fr in self
            .data
            .friends
            .iter()
            .filter(|f| f.state == FriendState::Active)
        {
            match load(store, &fr.pair, &fr.our_ed) {
                Ok(key) => peers.push(KxPeer::new(fr.pair, key.into_kx(), fr.friend_x)),
                Err(
                    IdentityError::KeyMissing
                    | IdentityError::KeyMismatch
                    | IdentityError::CorruptKey,
                ) => bad.push((fr.pair, KeyStatus::MissingOrChanged)),
                Err(IdentityError::UnsupportedKeyVersion) => {
                    bad.push((fr.pair, KeyStatus::NeedsDecision));
                }
                Err(e) => return Err(map_identity(e)),
            }
        }
        Ok((peers, bad))
    }

    /// Друг есть и его состояние `Active`.
    pub fn is_active(&self, pair: &PairId) -> bool {
        self.get(pair)
            .is_some_and(|f| f.state == FriendState::Active)
    }

    /// Друг `Active`: иначе `UnknownPair` (такой пары нет) или `NotActive`.
    fn active(&self, pair: &PairId) -> Result<&Friend, FriendsError> {
        let fr = self.get(pair).ok_or(FriendsError::UnknownPair)?;
        if fr.state != FriendState::Active {
            return Err(FriendsError::NotActive);
        }
        Ok(fr)
    }

    /// Токен обновления адреса для друга `pair` (только `Active`, набор не пуст). Порядок
    /// (критично): загрузить ключ пары, посчитать `seq`, СОХРАНИТЬ `addr_seq_out = seq` в файле
    /// списка и только потом подписать и вернуть токен. Ошибка сохранения: токена нет, значение
    /// в памяти прежнее. Номер, потраченный на неудавшуюся подпись, не возвращается.
    pub fn issue_addr_update<S: SecretStore + ListKeyStore + ?Sized>(
        &mut self,
        store: &S,
        pair: &PairId,
        set: &PublishSet,
        now_unix: u64,
    ) -> Result<IssuedAddrUpdate, FriendsError> {
        let fr = self.active(pair)?;
        if set.is_empty() {
            return Err(FriendsError::NoAddresses);
        }
        let (friend_ed, prev) = (fr.friend_ed, fr.addr_seq_out);
        let key = match load(store, pair, &fr.our_ed) {
            Ok(k) => k,
            Err(IdentityError::UnsupportedKeyVersion) => {
                return Err(FriendsError::KeyNeedsDecision);
            }
            Err(
                IdentityError::KeyMissing | IdentityError::KeyMismatch | IdentityError::CorruptKey,
            ) => return Err(FriendsError::KeyMissingOrChanged),
            Err(e) => return Err(map_identity(e)),
        };
        let seq = next_seq(prev, now_unix).ok_or(FriendsError::SeqExhausted)?;
        self.commit(store, |d| {
            let fr = d
                .friends
                .iter_mut()
                .find(|x| x.pair == *pair && x.state == FriendState::Active)
                .ok_or(FriendsError::UnknownPair)?;
            fr.addr_seq_out = seq;
            Ok(())
        })?;
        // номер уже на диске: теперь подпись
        issue_addr_update(&key, &friend_ed, seq, set)
            .map(|t| t.for_pair(*pair))
            .map_err(|e| match e {
                TokenError::RandomUnavailable => FriendsError::RandomUnavailable,
                _ => FriendsError::BadAddrUpdate,
            })
    }

    /// Применить проверенное обновление: номер строго больше `last_addr_seq` (`StaleSeq`),
    /// слияние, `prune`, лимит записей, сохранение; при ошибке откат в памяти (`commit`).
    fn apply_verified<K: ListKeyStore + ?Sized>(
        &mut self,
        keys: &K,
        pair: &PairId,
        update: &AddrUpdate,
        now_unix: u64,
    ) -> Result<(), FriendsError> {
        let seq = update.seq();
        let addrs = update.addrs();
        self.commit(keys, |d| {
            let fr = d
                .friends
                .iter_mut()
                .find(|x| x.pair == *pair && x.state == FriendState::Active)
                .ok_or(FriendsError::UnknownPair)?;
            if seq <= fr.last_addr_seq {
                return Err(FriendsError::StaleSeq);
            }
            chervo_addr::merge_update(&mut fr.known_addrs, addrs, now_unix);
            chervo_addr::prune(&mut fr.known_addrs, now_unix);
            trim_addrs(&mut fr.known_addrs);
            fr.last_addr_seq = seq;
            Ok(())
        })
    }

    /// Вставленный текст `CHA1...`: `decode` должен дать `Token::AddrUpdate`; подпись
    /// проверяется с каждым `Active` другом (`friend_ed`, `our_ed`), совпасть должен ровно
    /// один (иначе `BadAddrUpdate`); `seq <= last_addr_seq`: `StaleSeq`. Блокированные и чужие
    /// пары не принимаются. Возвращает пару.
    pub fn apply_addr_update_text<K: ListKeyStore + ?Sized>(
        &mut self,
        keys: &K,
        text: &str,
        now_unix: u64,
    ) -> Result<PairId, FriendsError> {
        let signed = match decode(text) {
            Ok(Token::AddrUpdate(s)) => s,
            _ => return Err(FriendsError::BadAddrUpdate),
        };
        let mut found: Option<(PairId, AddrUpdate)> = None;
        for fr in self
            .data
            .friends
            .iter()
            .filter(|f| f.state == FriendState::Active)
        {
            if let Ok(u) = signed.verify(&fr.friend_ed, &fr.our_ed) {
                if found.is_some() {
                    return Err(FriendsError::BadAddrUpdate);
                }
                found = Some((fr.pair, u));
            }
        }
        let (pair, update) = found.ok_or(FriendsError::BadAddrUpdate)?;
        self.apply_verified(keys, &pair, &update, now_unix)?;
        Ok(pair)
    }

    /// Номер строго больше `last_addr_seq` (`StaleSeq`) и не чаще одного принятого обновления
    /// на пару за `MIN_INBAND_UPDATE_INTERVAL_SECS` (`RateLimited`). Часы назад (`now < at`)
    /// считаются «внутри интервала». Неактивная пара: ошибка `active`.
    fn check_inband(&self, pair: &PairId, seq: u64, now_unix: u64) -> Result<(), FriendsError> {
        let fr = self.active(pair)?;
        if seq <= fr.last_addr_seq {
            return Err(FriendsError::StaleSeq);
        }
        if let Some((_, at)) = self.inband.iter().find(|(p, _)| p == pair)
            && now_unix.saturating_sub(*at) < MIN_INBAND_UPDATE_INTERVAL_SECS
        {
            return Err(FriendsError::RateLimited);
        }
        Ok(())
    }

    /// Обновление по проверенному соединению (`pair = conn.remote_pair()`): только `Active`;
    /// подпись только с ключами этого друга (иначе `BadAddrUpdate`); `StaleSeq`; не чаще одного
    /// принятого обновления на пару за `MIN_INBAND_UPDATE_INTERVAL_SECS` (`RateLimited`,
    /// счётчик в памяти). Время фиксируется только после успешного сохранения.
    pub fn apply_addr_update<K: ListKeyStore + ?Sized>(
        &mut self,
        keys: &K,
        pair: &PairId,
        update: &SignedAddrUpdate,
        now_unix: u64,
    ) -> Result<(), FriendsError> {
        // дешёвые проверки по ещё не проверенному номеру (ведут только к отказу), затем подпись
        self.check_inband(pair, update.unverified_seq(), now_unix)?;
        let fr = self.active(pair)?;
        let verified = update
            .verify(&fr.friend_ed, &fr.our_ed)
            .map_err(|_| FriendsError::BadAddrUpdate)?;
        // повторная проверка по проверенному номеру, затем фиксация
        self.check_inband(pair, verified.seq(), now_unix)?;
        self.apply_verified(keys, pair, &verified, now_unix)?;
        // записи удалённых друзей в памяти не копятся
        let friends = &self.data.friends;
        self.inband
            .retain(|(p, _)| p != pair && friends.iter().any(|f| f.pair == *p));
        self.inband.push((*pair, now_unix));
        Ok(())
    }

    /// Адрес, с которого друг подключился по проверенному соединению. Только `Active`;
    /// сохранение только если `chervo_addr::note_contact` изменил запись.
    pub fn note_contact<K: ListKeyStore + ?Sized>(
        &mut self,
        keys: &K,
        pair: &PairId,
        addr: SocketAddr,
        now_unix: u64,
    ) -> Result<(), FriendsError> {
        let fr = self.active(pair)?;
        let mut probe = fr.known_addrs.clone();
        if !chervo_addr::note_contact(&mut probe, addr, now_unix) {
            return Ok(());
        }
        self.commit(keys, |d| {
            let fr = d
                .friends
                .iter_mut()
                .find(|x| x.pair == *pair && x.state == FriendState::Active)
                .ok_or(FriendsError::UnknownPair)?;
            chervo_addr::note_contact(&mut fr.known_addrs, addr, now_unix);
            trim_addrs(&mut fr.known_addrs);
            Ok(())
        })
    }

    /// Адреса для набора (очищенные, по порядку). Неизвестная пара и не `Active` друг
    /// (`Blocked`, `RevokedByPeer`): пусто, чтобы не стучать и не раскрывать новый адрес;
    /// сохранённые адреса остаются в списке (после `unblock` они снова видны).
    pub fn usable_addrs(&self, pair: &PairId, now_unix: u64) -> Vec<SocketAddr> {
        match self.get(pair) {
            Some(f) if f.state == FriendState::Active => {
                chervo_addr::usable(&f.known_addrs, now_unix)
            }
            _ => Vec::new(),
        }
    }

    /// Как `usable_addrs`, но записи с флагами (источник, подсказка): для слоя соединения.
    /// Неизвестная пара и не `Active` друг: пусто.
    pub fn usable_known(&self, pair: &PairId, now_unix: u64) -> Vec<KnownAddr> {
        match self.get(pair) {
            Some(f) if f.state == FriendState::Active => {
                chervo_addr::usable_entries(&f.known_addrs, now_unix)
            }
            _ => Vec::new(),
        }
    }

    /// `Findability::NeedToken`, если нет постоянного адреса ни у нас (`own_stable`), ни у друга.
    /// Для не `Active` друга адресов нет (как в `usable_addrs`).
    pub fn findability(
        &self,
        pair: &PairId,
        own_stable: bool,
        now_unix: u64,
    ) -> Result<Findability, FriendsError> {
        let f = self.get(pair).ok_or(FriendsError::UnknownPair)?;
        let known: &[chervo_addr::KnownAddr] = if f.state == FriendState::Active {
            &f.known_addrs
        } else {
            &[]
        };
        Ok(chervo_addr::findability(own_stable, known, now_unix))
    }
}
