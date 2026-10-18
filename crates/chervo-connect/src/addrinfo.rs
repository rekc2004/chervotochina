//! Жизненный цикл ADDR_INFO: когда мы выпускаем токен обновления, как применяем присланное,
//! повтор после `RateLimited`.
//!
//! Токен выпускается лениво (решение 9): только при обмене с живым другом и только если набор
//! публикации изменился. Отправитель включает свой последний токен в каждый ADDR_INFO.

use std::net::SocketAddr;
use std::sync::Arc;

use chervo_addr::PublishCtx;
use chervo_friends::{FriendsError, MIN_INBAND_UPDATE_INTERVAL_SECS};
use chervo_identity::{ListKeyStore, PairId, SecretStore};
use chervo_token::IssuedAddrUpdate;
use chervo_token::SignedAddrUpdate;
use chervo_token::addr_flow::{PeerAddrInfo, exchange_addr_info};
use chervo_transport::{Connection, ManagedTransport};
use tokio::time::Instant;

use crate::engine::{ConnectError, Engine, Inner, State};

/// Предел длины вставленного текста токена обновления, байт. Самый длинный токен
/// (8 записей IPv6, 235 байт) в тексте занимает менее 400 байт; всё длиннее отвергается
/// без разбора.
const MAX_MANUAL_TOKEN_TEXT_LEN: usize = 1024;

impl<T, S> Engine<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    /// Действие пользователя «отправить токен адреса этому другу». Только `Active`. Адреса:
    /// `own.publishable(PublishCtx { include_lan }, now)` (частные адреса только по явному
    /// выбору). Номер сохраняется на диск до подписи (`FriendBook::issue_addr_update`).
    /// Пустой набор: `NoAddresses`, номер не тратится. Возвращает текст `CHA1`, в журнал
    /// ничего не пишется. Запись `last_sent` для ADDR_INFO не трогается.
    pub fn issue_addr_update_text(
        &self,
        pair: &PairId,
        include_lan: bool,
    ) -> Result<String, ConnectError> {
        let inner = &self.inner;
        if inner.is_shut() {
            return Err(ConnectError::Shutdown);
        }
        let unix = inner.clock.now_unix();
        let mut st = inner.lock();
        if st.book.get(pair).is_none() {
            return Err(ConnectError::UnknownPair);
        }
        if !st.book.is_active(pair) {
            return Err(ConnectError::NotActive);
        }
        let set = st.own.publishable(PublishCtx { include_lan }, unix);
        if set.is_empty() {
            return Err(ConnectError::NoAddresses);
        }
        match st.book.issue_addr_update(&*inner.store, pair, &set, unix) {
            Ok(token) => Ok(token.text()),
            Err(FriendsError::NoAddresses) => Err(ConnectError::NoAddresses),
            Err(e) => Err(ConnectError::Friends(e)),
        }
    }

    /// Действие пользователя «вставить токен адреса». Текст длиннее 1024 байт:
    /// `Friends(BadAddrUpdate)` без разбора. Иначе применение через `update_book` (публикация
    /// пар, сброс ограничителя адресов этого друга); подпись проверяется до любого доверия
    /// содержимому. Возвращает пару. Не набирает: вызывающий сам зовёт `connect_now`.
    pub fn apply_addr_update_text(&self, text: &str) -> Result<PairId, ConnectError> {
        if text.len() > MAX_MANUAL_TOKEN_TEXT_LEN {
            return Err(ConnectError::Friends(FriendsError::BadAddrUpdate));
        }
        let unix = self.inner.clock.now_unix();
        let text = text.trim();
        self.inner
            .update_book(|book, store| book.apply_addr_update_text(store, text, unix))
    }
}

impl<T, S> Inner<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    /// Наш токен для друга `pair` на соединении с адресом `remote`. Набор пуст: `None`. Набор
    /// равен последнему отправленному: прежний токен, номер не растёт. Иначе выпуск
    /// (`issue_addr_update` сохраняет номер на диск до подписи).
    pub(crate) fn ours(
        &self,
        st: &mut State<T::Conn>,
        pair: &PairId,
        remote: SocketAddr,
        unix: u64,
    ) -> Option<IssuedAddrUpdate> {
        let set = st.own.publishable(PublishCtx::for_connection(remote), unix);
        if set.is_empty() {
            return None;
        }
        if let Some((last, token)) = st.friends.get(pair).and_then(|r| r.last_sent.as_ref())
            && *last == set
        {
            return Some(token.clone());
        }
        match st.book.issue_addr_update(&*self.store, pair, &set, unix) {
            Ok(token) => {
                st.friends.entry(*pair).or_default().last_sent = Some((set, token.clone()));
                Some(token)
            }
            Err(_) => None,
        }
    }

    /// Живые друзья, которым пора отправить ADDR_INFO: не чаще `addr_info_out_interval`.
    /// Пропущенная отправка остаётся помеченной и повторяется следующим тактом.
    pub(crate) fn collect_sends(
        &self,
        st: &mut State<T::Conn>,
        now: Instant,
        out: &mut Vec<(PairId, T::Conn)>,
    ) {
        let interval = self.cfg.addr_info_out_interval;
        let State {
            live,
            friends,
            book,
            ..
        } = st;
        for (pair, l) in live.iter() {
            if !book.is_active(pair) {
                continue;
            }
            let rt = friends.entry(*pair).or_default();
            let due = rt
                .last_sent_at
                .is_none_or(|t| now.saturating_duration_since(t) >= interval);
            if rt.want_addr_info && !rt.sending && due {
                rt.want_addr_info = false;
                rt.sending = true;
                rt.last_sent_at = Some(now);
                out.push((*pair, l.conn.clone()));
            }
        }
    }

    pub(crate) fn spawn_send(self: &Arc<Self>, pair: PairId, conn: T::Conn) {
        let inner = self.clone();
        self.spawn_task(async move { inner.send_addr_info(pair, conn).await });
    }

    /// Мы открываем поток ADDR_INFO. Ошибка или срок: поток сбрасывается, соединение живо.
    async fn send_addr_info(self: Arc<Self>, pair: PairId, conn: T::Conn) {
        let unix = self.clock.now_unix();
        let ours = {
            let mut st = self.lock();
            self.ours(&mut st, &pair, conn.remote_addr(), unix)
        };
        let res = tokio::time::timeout(
            self.cfg.addr_info_timeout,
            exchange_addr_info(&conn, &pair, ours.as_ref()),
        )
        .await;
        let now = Instant::now();
        let unix = self.clock.now_unix();
        let mut st = self.lock();
        if let Some(rt) = st.friends.get_mut(&pair) {
            rt.sending = false;
        }
        if let Ok(Ok(info)) = res {
            self.apply_peer_info(&mut st, pair, info, now, unix);
        }
    }

    /// Присланное другом (по любую сторону обмена). Только `Active`: наблюдение
    /// «как вы выглядите снаружи» и подписанное обновление.
    pub(crate) fn apply_peer_info(
        &self,
        st: &mut State<T::Conn>,
        pair: PairId,
        info: PeerAddrInfo,
        now: Instant,
        unix: u64,
    ) {
        if !st.book.is_active(&pair) {
            return;
        }
        let _ = st.own.observe(pair, info.via, info.observed_me, unix);
        if let Some(update) = info.update {
            self.apply_update(st, pair, update, now, unix);
        }
    }

    fn apply_update(
        &self,
        st: &mut State<T::Conn>,
        pair: PairId,
        update: SignedAddrUpdate,
        now: Instant,
        unix: u64,
    ) {
        match st
            .book
            .apply_addr_update(&*self.store, &pair, &update, unix)
        {
            Ok(()) => {
                // новый номер от друга сбрасывает ограничитель только его адресов
                let addrs = Self::friend_addrs(st, &pair);
                st.limiter.reset_pair(&addrs, now);
                st.friends.entry(pair).or_default().deferred = None;
            }
            Err(FriendsError::RateLimited) => {
                let rt = st.friends.entry(pair).or_default();
                let newer = rt
                    .deferred
                    .as_ref()
                    .is_none_or(|(d, _)| d.unverified_seq() < update.unverified_seq());
                if newer {
                    let at = unix.saturating_add(MIN_INBAND_UPDATE_INTERVAL_SECS);
                    rt.deferred = Some((update, at));
                }
            }
            // `StaleSeq`, неверная подпись, не `Active`: обновление просто не применяется
            Err(_) => {}
        }
    }

    /// Повтор отложенных (отклонённых по частоте) обновлений.
    pub(crate) fn retry_deferred(&self, st: &mut State<T::Conn>, now: Instant, unix: u64) {
        let due: Vec<PairId> = st
            .friends
            .iter()
            .filter(|(_, r)| r.deferred.as_ref().is_some_and(|(_, at)| *at <= unix))
            .map(|(p, _)| *p)
            .collect();
        for pair in due {
            let taken = st
                .friends
                .get_mut(&pair)
                .and_then(|r| r.deferred.take())
                .map(|(u, _)| u);
            if let Some(update) = taken {
                self.apply_update(st, pair, update, now, unix);
            }
        }
    }
}
