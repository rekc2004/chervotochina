//! Друзья, приглашения и токены (этап 18а, A3). Каждое изменение списка идёт через
//! `Engine::update_book`: он публикует пары транспорту и снимает живые соединения тех, кто
//! перестал быть `Active`.
//!
//! Сбой записи якоря ПОСЛЕ сохранения файла (`FriendsError::SavedAnchorStale`, S1 L3) это не
//! «не удалось»: действие выполнено, узел отвечает `Ok` и шлёт `NodeEvent::Warning(
//! AnchorNotUpdated)`. Для `remove` и `rekey` повтор идемпотентен (запись уже `Retired`), он тут
//! же заканчивает удаление ключа и отдаёт тот же текст отзыва.

use std::net::SocketAddr;

use chervo_connect::{Clock, InviteAddrs};
use chervo_friends::{FriendBook, FriendState, FriendsError, Permission, TrustConfirmation};
use chervo_identity::PairId;

use super::core::lock;
use super::error::NodeError;
use super::store::NodeStore;
use super::views::{
    AddrToken, FriendRef, FriendStatus, FriendView, InviteRef, NodeWarning, RevocationText,
};
use super::{MAX_INPUT_BYTES, Node};

/// Вставленный текст: обрезка пробелов, предел 4096 байт до любого разбора (инвариант 5).
pub(crate) fn checked_input(text: &str) -> Result<&str, NodeError> {
    let t = text.trim();
    if t.len() > MAX_INPUT_BYTES {
        return Err(NodeError::InputTooLong);
    }
    Ok(t)
}

fn nothing(_: &mut FriendBook, _: &NodeStore) -> Result<(), FriendsError> {
    Ok(())
}

fn status_of(s: FriendState) -> FriendStatus {
    match s {
        FriendState::Active => FriendStatus::Active,
        FriendState::Blocked => FriendStatus::Blocked,
        FriendState::RevokedByPeer => FriendStatus::RevokedByPeer,
        FriendState::Retired => FriendStatus::Retired,
    }
}

impl Node {
    /// Снимок списка друзей: имя, состояние, на связи ли, автоприём, проблема ключа.
    pub fn friends(&self) -> Vec<FriendView> {
        let raw: Vec<(PairId, String, FriendState, bool)> = self.core.engine.read_book(|b| {
            b.friends()
                .iter()
                .map(|f| {
                    (
                        f.pair,
                        f.name.clone(),
                        f.state,
                        matches!(f.permission, Permission::AutoAccept(_)),
                    )
                })
                .collect()
        });
        let online: Vec<bool> = raw
            .iter()
            .map(|(p, ..)| self.core.engine.connection(p).is_some())
            .collect();
        let reg = lock(&self.core.reg);
        raw.into_iter()
            .zip(online)
            .map(|((pair, name, state, auto), online)| FriendView {
                friend: FriendRef::new(pair),
                name,
                state: status_of(state),
                online,
                auto_accept: auto,
                key_problem: reg.key_problems.contains(&pair),
                last_path: reg.last_path.get(&pair).copied(),
            })
            .collect()
    }

    /// Изменение списка. `recover` выполняется в том же `update_book`, если `op` вернул
    /// `SavedAnchorStale`: изменение уже сохранено, нужно только достать результат.
    fn book_op<R>(
        &self,
        op: impl FnOnce(&mut FriendBook, &NodeStore) -> Result<R, FriendsError>,
        recover: impl FnOnce(&mut FriendBook, &NodeStore) -> Result<R, FriendsError>,
    ) -> Result<R, NodeError> {
        let _g = self.enter();
        let mut stale = false;
        let result = self
            .core
            .engine
            .update_book(|book, store| match op(book, store) {
                Err(FriendsError::SavedAnchorStale) => {
                    stale = true;
                    recover(book, store)
                }
                other => other,
            });
        match result {
            Ok(v) => {
                if stale {
                    self.core.warn(NodeWarning::AnchorNotUpdated);
                }
                Ok(v)
            }
            Err(e) => Err(NodeError::from(e)),
        }
    }

    /// Приглашение: токен с вашими адресами. Срок жизни из настроек (по умолчанию 15 минут).
    /// `manual_addr`: адрес с пробросом порта вместо найденных. Токен раскрывает ваш IP.
    pub fn create_invite(
        &self,
        same_network: bool,
        manual_addr: Option<SocketAddr>,
    ) -> Result<(InviteRef, AddrToken), NodeError> {
        let ttl = lock(&self.core.settings).invite_ttl_secs;
        let addrs = match manual_addr {
            Some(a) => InviteAddrs::Manual(vec![a]),
            None => InviteAddrs::Auto { same_network },
        };
        let _g = self.enter();
        let (pair, text) = self.core.engine.create_invite(ttl, addrs)?;
        Ok((InviteRef::new(pair), AddrToken::new(text)))
    }

    /// Принять приглашение друга (вставленный текст, до 4096 байт).
    pub fn accept_invite(&self, text: &str) -> Result<InviteRef, NodeError> {
        let t = checked_input(text)?;
        let _g = self.enter();
        let pair = self.core.engine.accept_invite(t)?;
        Ok(InviteRef::new(pair))
    }

    /// Решение человека по проверочному коду: `yes` только если коды на двух экранах совпали.
    /// Имя друга нужно при `yes`.
    pub fn confirm_sas(&self, invite: InviteRef, yes: bool, name: &str) -> Result<(), NodeError> {
        let name = name.trim();
        if name.len() > MAX_INPUT_BYTES {
            return Err(NodeError::InputTooLong);
        }
        let _g = self.enter();
        self.core.engine.confirm_sas(invite.inner(), yes, name)?;
        Ok(())
    }

    pub fn cancel_invite(&self, invite: InviteRef) -> Result<(), NodeError> {
        let _g = self.enter();
        self.core.engine.cancel_invite(invite.inner())?;
        Ok(())
    }

    pub fn rename(&self, friend: FriendRef, name: &str) -> Result<(), NodeError> {
        let name = name.trim();
        if name.len() > MAX_INPUT_BYTES {
            return Err(NodeError::InputTooLong);
        }
        let pair = *friend.inner();
        self.book_op(|b, s| b.rename(s, &pair, name), nothing)
    }

    /// Блокировка: живое соединение с другом закрывается сразу.
    pub fn block(&self, friend: FriendRef) -> Result<(), NodeError> {
        let pair = *friend.inner();
        self.book_op(|b, s| b.block(s, &pair), nothing)
    }

    pub fn unblock(&self, friend: FriendRef) -> Result<(), NodeError> {
        let pair = *friend.inner();
        self.book_op(|b, s| b.unblock(s, &pair), nothing)
    }

    /// Удалить друга. `Some(текст отзыва)`: его нужно отправить другу вручную, иначе он узнает
    /// об удалении только когда не сможет соединиться. `None`: ключа пары уже не было.
    pub fn remove(&self, friend: FriendRef) -> Result<Option<RevocationText>, NodeError> {
        let pair = *friend.inner();
        let now = self.core.clock.now_unix();
        self.book_op(
            |b, s| b.remove(s, &pair, now),
            |b, s| match b.remove(s, &pair, now) {
                // запись уже убрана (ключа не было): отзыва нет
                Err(FriendsError::UnknownPair) => Ok(None),
                other => other,
            },
        )
        .map(|o| o.map(RevocationText::new))
    }

    /// «Пересоздать ключ»: отзыв старого ключа. Текст нужно отправить другу, затем создать для
    /// него новое приглашение.
    pub fn rekey(&self, friend: FriendRef) -> Result<RevocationText, NodeError> {
        let pair = *friend.inner();
        let now = self.core.clock.now_unix();
        self.book_op(|b, s| b.rekey(s, &pair, now), |b, s| b.rekey(s, &pair, now))
            .map(RevocationText::new)
    }

    /// «Пересоздать все ключи»: по каждому другу `Active` или `Blocked` свой результат.
    pub fn rekey_all(&self) -> Vec<(FriendRef, Result<RevocationText, NodeError>)> {
        let targets: Vec<FriendRef> = self
            .friends()
            .into_iter()
            .filter(|f| matches!(f.state, FriendStatus::Active | FriendStatus::Blocked))
            .map(|f| f.friend)
            .collect();
        targets.into_iter().map(|f| (f, self.rekey(f))).collect()
    }

    /// Тексты отзыва, которые ещё не сняты с учёта (удалённые или пересозданные друзья).
    pub fn retired(&self) -> Vec<(FriendRef, RevocationText)> {
        self.core.engine.read_book(|b| {
            b.retired()
                .into_iter()
                .map(|(p, t)| (FriendRef::new(p), RevocationText::new(t)))
                .collect()
        })
    }

    /// Снять отзыв с учёта (друг получил текст или пользователь отказался).
    pub fn forget_retired(&self, friend: FriendRef) -> Result<(), NodeError> {
        let pair = *friend.inner();
        self.book_op(|b, s| b.forget_retired(s, &pair), nothing)
    }

    /// Отзыв от друга, вставленный из мессенджера (до 4096 байт). `Some(друг)`: друг теперь
    /// `RevokedByPeer`; `None`: отзыв подлинный, но никому из друзей не подходит.
    pub fn apply_revocation_text(&self, text: &str) -> Result<Option<FriendRef>, NodeError> {
        let t = checked_input(text)?;
        let before: Vec<PairId> = self.core.engine.read_book(|b| {
            b.friends()
                .iter()
                .filter(|f| !matches!(f.state, FriendState::RevokedByPeer | FriendState::Retired))
                .map(|f| f.pair)
                .collect()
        });
        self.book_op(
            |b, s| b.apply_revocation(s, t),
            |b, _| {
                Ok(before.iter().copied().find(|p| {
                    b.get(p)
                        .is_some_and(|f| f.state == FriendState::RevokedByPeer)
                }))
            },
        )
        .map(|o| o.map(FriendRef::new))
    }

    /// Токен адреса для друга («отправить свой адрес»). `same_network`: добавить адреса
    /// локальной сети. Токен раскрывает ваш IP.
    pub fn issue_addr_update_text(
        &self,
        friend: FriendRef,
        same_network: bool,
    ) -> Result<AddrToken, NodeError> {
        let _g = self.enter();
        let text = self
            .core
            .engine
            .issue_addr_update_text(friend.inner(), same_network)?;
        Ok(AddrToken::new(text))
    }

    /// Токен адреса друга, вставленный из мессенджера (до 4096 байт). После вставки сразу
    /// пробуем соединиться (действие пользователя).
    pub fn apply_addr_update_text(&self, text: &str) -> Result<FriendRef, NodeError> {
        let t = checked_input(text)?;
        let _g = self.enter();
        let pair = self.core.engine.apply_addr_update_text(t)?;
        // действие пользователя «вставить токен»: набор сразу, как в узле 16
        let _ = self.core.engine.connect_now(&pair);
        Ok(FriendRef::new(pair))
    }

    /// Кнопка «Соединить». Узел сам её не нажимает.
    pub fn connect_now(&self, friend: FriendRef) -> Result<(), NodeError> {
        let _g = self.enter();
        self.core.engine.connect_now(friend.inner())?;
        Ok(())
    }

    /// Включить автоприём для друга. Вызывать только после того, как пользователь увидел вопрос
    /// `texts::TRUST_QUESTION_TEXT` («Вы доверяете этому человеку и знаете, зачем он будет
    /// присылать файлы?») и ответил «да»: `TrustConfirmation::user_confirmed_trust()` создаётся
    /// именно в этот момент.
    pub fn enable_auto_accept(
        &self,
        friend: FriendRef,
        confirmation: TrustConfirmation,
    ) -> Result<(), NodeError> {
        let pair = *friend.inner();
        self.book_op(|b, s| b.enable_auto_accept(s, &pair, confirmation), nothing)
    }

    pub fn disable_auto_accept(&self, friend: FriendRef) -> Result<(), NodeError> {
        let pair = *friend.inner();
        self.book_op(|b, s| b.set_permission(s, &pair, Permission::Ask), nothing)
    }
}
