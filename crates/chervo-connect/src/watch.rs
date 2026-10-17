//! Слежение за собственными адресами (9b N3, этап 12): снимок маршрута и адресов
//! прослушивания, при изменении повторный стук, сброс ограничителя, быстрое окно и
//! повторная рассылка ADDR_INFO.

use std::sync::Arc;

use chervo_addr::LocalSnapshot;
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
                self.snapshot_local(&mut st)
            };
            if changed {
                self.on_own_change();
            }
        }
    }
}
