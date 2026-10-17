//! Автоматический проброс порта на роутере (этап 13а, часть U3).
//!
//! Слой соединения не знает, как именно открывается порт: он держит `Arc<dyn PortMapper>`
//! (интерфейс из `chervo-addr`) и вызывает его только внутри `spawn_blocking`. Сокетов здесь
//! нет. Одна задача, поэтому вызовы отображателя никогда не идут параллельно. Расписание
//! принадлежит движку (подключение, смена своих адресов, таймер `retry_after`, действие
//! пользователя), состояние протокола принадлежит отображателю.
//!
//! Результат применяется, только если снимок, для которого он запрошен, ещё текущий
//! (`route.v4` и порт прослушивания IPv4): иначе он описывает старую сеть.

use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use chervo_addr::{
    AddrClass, GatewayInfo, MapReport, MapRequest, MapStatus, PortMapper, PublishCtx, classify,
};
use chervo_identity::{ListKeyStore, SecretStore};
use chervo_transport::ManagedTransport;
use tokio::sync::Notify;
use tokio::task::spawn_blocking;
use tokio::time::timeout;

use crate::engine::{ConnectError, Engine, EngineEvent, Inner, State};

/// Предел одного `refresh` по контракту (U0).
const MAX_REFRESH: Duration = Duration::from_secs(25);
/// Запас сверх предела отображателя: за ним поток считается брошенным.
const REFRESH_SLACK: Duration = Duration::from_secs(5);
/// Предел `release` по контракту (U0) и запас.
const RELEASE_LIMIT: Duration = Duration::from_secs(5);
/// Повтор после сбоя или таймаута.
const FAIL_RETRY: Duration = Duration::from_secs(60);
/// Нижняя граница ожидания: отображатель с нулевым `retry_after` не должен крутить цикл.
const MIN_WAIT: Duration = Duration::from_secs(1);
/// Страховка, если после устаревшего результата сигнал смены адресов не пришёл.
const STALE_RETRY: Duration = Duration::from_secs(60);

/// Состояние задачи проброса внутри `Inner`.
pub(crate) struct Gateway {
    mapper: OnceLock<Arc<dyn PortMapper>>,
    notify: Notify,
    status: Mutex<Option<MapStatus>>,
}

impl Gateway {
    pub(crate) fn new() -> Self {
        Self {
            mapper: OnceLock::new(),
            notify: Notify::new(),
            status: Mutex::new(None),
        }
    }

    /// Разбудить задачу (смена своих адресов, действие пользователя). Сигнал хранится, если
    /// задача сейчас занята вызовом.
    pub(crate) fn wake(&self) {
        self.notify.notify_one();
    }
}

/// Запрос к отображателю по снимку: маршрутный IPv4 класса `Private` и порт прослушивания
/// IPv4, не нулевой. Иначе проброс не нужен (белый адрес, CGNAT, нет IPv4, нет порта).
fn request_of<C>(st: &State<C>) -> Option<MapRequest> {
    let local = st.own.local()?;
    let ip = local.route.v4?;
    if classify(IpAddr::V4(ip)) != AddrClass::Private {
        return None;
    }
    let port = local
        .listen
        .iter()
        .find_map(|a| match a {
            SocketAddr::V4(v4) => Some(v4.port()),
            SocketAddr::V6(_) => None,
        })
        .filter(|p| *p != 0)?;
    Some(MapRequest {
        internal: SocketAddrV4::new(ip, port),
    })
}

fn failed(retry_after: Duration) -> MapReport {
    MapReport {
        status: MapStatus::Failed,
        gateway: None,
        retry_after,
    }
}

impl<T, S> Inner<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    /// Единственное место, где задаётся шлюз. Применяет итог, только если запрос по текущему
    /// снимку всё ещё равен `expect` (`None`: проброс не нужен). `false`: результат устарел
    /// и выброшен целиком, состояние не тронуто. Изменение публикуемого набора помечает всех
    /// живых друзей для ADDR_INFO и даёт `OwnAddrsChanged` (без нового стука, без сброса
    /// ограничителя и быстрого окна: адрес своего роутера, а не новая сеть).
    fn commit_gateway(
        &self,
        expect: Option<MapRequest>,
        status: MapStatus,
        gateway: Option<GatewayInfo>,
    ) -> bool {
        let publish_changed = {
            let mut st = self.lock();
            if request_of(&st) != expect {
                return false;
            }
            let unix = self.clock.now_unix();
            let before = st.own.publishable(PublishCtx::default(), unix);
            st.own.set_gateway(gateway);
            let after = st.own.publishable(PublishCtx::default(), unix);
            let changed = before != after;
            if changed {
                let State { live, friends, .. } = &mut *st;
                for pair in live.keys() {
                    friends.entry(*pair).or_default().want_addr_info = true;
                }
            }
            changed
        };
        let status_changed = {
            let mut cur = self
                .gw
                .status
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let changed = *cur != Some(status);
            *cur = Some(status);
            changed
        };
        if publish_changed {
            self.emit(EngineEvent::OwnAddrsChanged);
        }
        if status_changed {
            self.emit(EngineEvent::MappingChanged { status });
        }
        true
    }

    /// Ждёт сигнала или срока. `None`: только сигнал.
    async fn gateway_wait(&self, wait: Option<Duration>) {
        match wait {
            None => self.gw.notify.notified().await,
            Some(d) => {
                let _ = timeout(d, self.gw.notify.notified()).await;
            }
        }
    }

    pub(crate) async fn run_gateway(self: Arc<Self>) {
        let Some(mapper) = self.gw.mapper.get().cloned() else {
            return;
        };
        // отображатель мог получить запрос (и держать проброс): при потере частного маршрута
        // его нужно освободить, один раз
        let mut asked = false;
        let mut wait: Option<Duration> = None;
        loop {
            self.gateway_wait(wait).await;
            if self.is_shut() {
                return;
            }
            let req = request_of(&self.lock());
            let Some(req) = req else {
                if asked {
                    let m = mapper.clone();
                    let _ = timeout(
                        RELEASE_LIMIT + REFRESH_SLACK,
                        spawn_blocking(move || m.release()),
                    )
                    .await;
                    asked = false;
                    self.commit_gateway(None, MapStatus::Off, None);
                }
                wait = None;
                continue;
            };
            asked = true;
            let m = mapper.clone();
            let joined = timeout(
                MAX_REFRESH + REFRESH_SLACK,
                spawn_blocking(move || m.refresh(req)),
            )
            .await;
            // таймаут или паника потока: считается сбоем, поток брошен (отменить его нельзя)
            let report = match joined {
                Ok(Ok(r)) => r,
                _ => failed(FAIL_RETRY),
            };
            if self.commit_gateway(Some(req), report.status, report.gateway) {
                wait = Some(report.retry_after.max(MIN_WAIT));
            } else {
                wait = Some(STALE_RETRY);
            }
        }
    }
}

impl<T, S> Engine<T, S>
where
    T: ManagedTransport,
    T::Conn: Clone,
    S: SecretStore + ListKeyStore + 'static,
{
    /// Подключает отображатель портов и запускает задачу проброса. Второй вызов:
    /// `ConnectError::Internal`. Сам вызов сети не делает; первый опрос идёт сразу в задаче.
    pub fn attach_mapper(&self, m: Arc<dyn PortMapper>) -> Result<(), ConnectError> {
        if self.inner.is_shut() {
            return Err(ConnectError::Shutdown);
        }
        if self.inner.gw.mapper.set(m).is_err() {
            return Err(ConnectError::Internal);
        }
        self.inner.spawn_task(self.inner.clone().run_gateway());
        self.inner.gw.wake();
        Ok(())
    }

    /// Действие пользователя или смена настроек отображателя: повторить опрос сейчас.
    pub fn refresh_mapping(&self) {
        if !self.inner.is_shut() {
            self.inner.gw.wake();
        }
    }

    /// Последний применённый итог проброса; `None`, пока итога не было.
    pub fn mapping_status(&self) -> Option<MapStatus> {
        *self
            .inner
            .gw
            .status
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }
}
