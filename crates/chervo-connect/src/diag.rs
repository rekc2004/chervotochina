//! Диагностика «нет прямого пути»: причина, порядок проверок и тексты (спецификация 13, C3).

use std::net::SocketAddr;

use chervo_addr::{AddrClass, Findability, KnownAddr, NatView, classify, normalize};
use chervo_identity::{ListKeyStore, PairId, SecretStore};
use chervo_transport::ManagedTransport;
use tokio::time::Instant;

use crate::engine::{Inner, State};
use crate::plan::{families_of, only_unusable_v6};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NoDirectPath {
    NoKnownAddress,
    NeedToken,
    BehindCgnat,
    /// Роутер сам стоит за другим NAT (его внешний адрес частный) или внешний адрес не совпадает
    /// с тем, что видят друзья.
    DoubleNat,
    SymmetricNat,
    UdpBlockedSuspected,
    NoIpv6,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Diagnosis {
    pub reason: NoDirectPath,
    /// Истинно только для `BehindCgnat`, `DoubleNat` и `NeedToken`.
    pub rendezvous_could_help: bool,
}

impl Diagnosis {
    pub(crate) fn of(reason: NoDirectPath) -> Self {
        Self {
            reason,
            rendezvous_could_help: matches!(
                reason,
                NoDirectPath::BehindCgnat | NoDirectPath::DoubleNat | NoDirectPath::NeedToken
            ),
        }
    }
}

/// Постоянный адрес друга: не подсказка, глобальный IPv4.
fn stable_global_v4(k: &KnownAddr) -> bool {
    let a: SocketAddr = normalize(k.addr);
    !k.hint && a.is_ipv4() && classify(a.ip()) == AddrClass::Global
}

impl<T, S> Inner<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    /// Общая эвристика: нет ни одного живого соединения, ни одного успеха за окно, и не
    /// меньше `udp_blocked_min_friends` разных активных друзей с постоянным глобальным
    /// IPv4-адресом получали только «нет ответа».
    fn udp_blocked_suspected(&self, st: &State<T::Conn>, now: Instant, unix: u64) -> bool {
        if !st.live.is_empty() {
            return false;
        }
        let window = self.cfg.udp_blocked_window;
        if st
            .last_success_any
            .is_some_and(|t| now.saturating_duration_since(t) <= window)
        {
            return false;
        }
        let mut count = 0usize;
        for (pair, rt) in &st.friends {
            if !st.book.is_active(pair) {
                continue;
            }
            let mut any = false;
            let mut only_silent = true;
            for rec in &rt.history {
                if now.saturating_duration_since(rec.at) <= window {
                    any = true;
                    if !rec.no_response {
                        only_silent = false;
                    }
                }
            }
            if !any || !only_silent {
                continue;
            }
            if st
                .book
                .usable_known(pair, unix)
                .iter()
                .any(stable_global_v4)
            {
                count = count.saturating_add(1);
            }
        }
        count >= self.cfg.udp_blocked_min_friends
    }

    /// Первое совпадение; `None`: соединение есть или причину пока не решить (набора ещё не
    /// было и структурных причин нет).
    pub(crate) fn diagnose_locked(
        &self,
        st: &State<T::Conn>,
        pair: &PairId,
        local: &[SocketAddr],
        now: Instant,
        unix: u64,
    ) -> Option<Diagnosis> {
        if st.live.contains_key(pair) {
            return None;
        }
        let entries = st.book.usable_known(pair, unix);
        let own_stable = st.own.stable_reachable(unix);
        let need_token = matches!(
            st.book.findability(pair, own_stable, unix),
            Ok(Findability::NeedToken)
        );
        if entries.is_empty() {
            return Some(Diagnosis::of(if need_token {
                NoDirectPath::NeedToken
            } else {
                NoDirectPath::NoKnownAddress
            }));
        }
        if only_unusable_v6(&entries, &families_of(&st.own, local)) {
            return Some(Diagnosis::of(NoDirectPath::NoIpv6));
        }
        let seen = st
            .friends
            .get(pair)
            .is_some_and(|r| r.consecutive_fails > 0 || !r.history.is_empty());
        if !seen {
            return None;
        }
        match st.own.nat_view(unix) {
            NatView::BehindCgnat => return Some(Diagnosis::of(NoDirectPath::BehindCgnat)),
            NatView::DoubleNat => return Some(Diagnosis::of(NoDirectPath::DoubleNat)),
            NatView::Symmetric => return Some(Diagnosis::of(NoDirectPath::SymmetricNat)),
            _ => {}
        }
        if self.udp_blocked_suspected(st, now, unix) {
            return Some(Diagnosis::of(NoDirectPath::UdpBlockedSuspected));
        }
        if need_token {
            return Some(Diagnosis::of(NoDirectPath::NeedToken));
        }
        Some(Diagnosis::of(NoDirectPath::Unknown))
    }
}
