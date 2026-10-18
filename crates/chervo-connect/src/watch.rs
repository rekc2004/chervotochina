//! Слежение за собственными адресами (9b N3, этап 12): снимок маршрута и адресов
//! прослушивания, при изменении повторный стук, сброс ограничителя, быстрое окно и
//! повторная рассылка ADDR_INFO.

use std::sync::Arc;

use chervo_addr::{LocalSnapshot, PublishCtx};
use chervo_identity::{ListKeyStore, SecretStore};
use chervo_transport::ManagedTransport;
use tokio::time::Instant;

use crate::engine::{EngineEvent, Inner, State, period};

impl<T, S> Inner<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    /// Единственное место, где строится снимок: маршрут только из пробы, адреса
    /// прослушивания только из транспорта. `true`: набор отличается от прошлого снимка
    /// (первый вызов тоже `true`, его результат вызывающий отбрасывает).
    pub(crate) fn snapshot_local(&self, st: &mut State<T::Conn>) -> bool {
        let snap = LocalSnapshot {
            route: self.probe.probe(),
            listen: self.transport.local_addrs(),
        };
        st.own.set_local(snap)
    }

    /// F2: наблюдаемый снаружи набор (то, что мы объявили бы всем: `publishable` без частных
    /// адресов) за такт. Пустой набор молчит; первый непустой запоминается молча; изменение
    /// объявляется не чаще `ext_announce_gap`. `true`: объявить (повторный стук и событие
    /// делает вызывающий после снятия замка; ADDR_INFO живым друзьям помечен здесь). Это не
    /// собственное событие для набора номера: ни быстрого окна, ни сброса ограничителя (набор
    /// приходит от друзей, лгущий друг иначе держал бы нас в быстром режиме).
    pub(crate) fn check_external(&self, st: &mut State<T::Conn>, now: Instant, unix: u64) -> bool {
        let set = st.own.publishable(PublishCtx::default(), unix);
        if set.is_empty() {
            return false;
        }
        if !st.ext_baseline {
            st.ext_baseline = true;
            st.ext_announced = Some(set);
            return false;
        }
        if st.ext_announced.as_ref() == Some(&set) {
            return false;
        }
        let inside_gap = st
            .ext_last
            .is_some_and(|t| now.saturating_duration_since(t) < self.cfg.ext_announce_gap);
        if inside_gap {
            return false;
        }
        st.ext_announced = Some(set);
        st.ext_last = Some(now);
        let State {
            live,
            friends,
            book,
            ..
        } = st;
        for pair in live.keys().filter(|p| book.is_active(p)) {
            friends.entry(*pair).or_default().want_addr_info = true;
        }
        true
    }

    /// Свои адреса сменились.
    fn on_own_change(&self) {
        self.transport.reknock();
        let now = Instant::now();
        {
            let mut st = self.lock();
            st.limiter.reset_all(now);
            self.start_fast_global(&mut st, now);
            let State { live, friends, .. } = &mut *st;
            for pair in live.keys() {
                friends.entry(*pair).or_default().want_addr_info = true;
            }
        }
        self.gw.wake();
        self.emit(EngineEvent::OwnAddrsChanged);
    }

    pub(crate) async fn run_watcher(self: Arc<Self>) {
        loop {
            tokio::time::sleep(period(self.cfg.probe_interval)).await;
            let changed = {
                let mut st = self.lock();
                let changed = self.snapshot_local(&mut st);
                if changed {
                    // F2: смена маршрута объявляется целиком (`on_own_change`); новый набор
                    // запоминается в том же замке, чтобы такт не объявил её второй раз.
                    // `ext_last` не трогается: следующее наблюдение в новой сети объявится
                    let unix = self.clock.now_unix();
                    st.ext_announced = Some(st.own.publishable(PublishCtx::default(), unix));
                    st.ext_baseline = true;
                }
                changed
            };
            if changed {
                self.on_own_change();
            }
        }
    }
}
