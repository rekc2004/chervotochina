//! Эхо-проба и проверка доступа (этап 13д, Р2 и Р5): запросы нашему эхо-серверу уходят с
//! ОСНОВНОГО гнезда QUIC, чтобы сервер видел то же отображение NAT, что и друзья. Ответы
//! забираются в `KnockSocket::filter_batch` до классификации допуска: допуск никому не
//! открывается, мы ничего не отвечаем. Принимаются только 48-байтные сегменты с точного
//! `ip:порт` сервера (эхо) или с IP сервера и другого порта (проверка доступа) и с nonce текущей
//! пробы; всё остальное идёт обычным путём. Протокол: `chervo-rendezvous-wire`.
//!
//! Обход VPN: адрес источника на один пакет (`Transmit::src_ip`). Опций на весь сокет нет.
//! Запросы строятся и разбираются только в этом модуле; отправляет `KnockState::send_echo`.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use chervo_rendezvous_wire::{
    NONCE_LEN, Nonce, REQUEST_LEN, RESPONSE_LEN, encode_echo_request, encode_reach_request,
    parse_response,
};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::Notify;
use tokio::time::{Instant, timeout_at};

use crate::QuinnTransport;
use crate::knock::KnockState;

/// Не больше стольких путей (адресов источника) в одной пробе.
pub const ECHO_MAX_PATHS: usize = 4;
/// Запросов на путь за пробу.
pub const ECHO_TRIES: u32 = 3;
/// Пауза между повторами одного запроса.
pub const ECHO_RETRY: Duration = Duration::from_secs(1);
/// Срок всей пробы.
pub const ECHO_DEADLINE: Duration = Duration::from_secs(3);

/// Почему проба не началась. Ничего не отправлено ни в одном из случаев.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoError {
    /// Другая проба ещё идёт.
    Busy,
    /// Адрес сервера неуказанный, групповой, широковещательный или с портом 0.
    BadServer,
    /// Путей больше `ECHO_MAX_PATHS`.
    TooManyPaths,
    /// Гнездо не IPv4: клиент v1 только IPv4.
    SocketFamily,
    /// Генератор случайных чисел не дал nonce.
    Random,
}

/// Итог одного пути пробы.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EchoPathResult {
    /// Сервер ответил: так нас видно снаружи; `reach_port` порт проверки сервера (0: нет).
    Observed { addr: SocketAddrV4, reach_port: u16 },
    /// Ответа не было, запрос уходил.
    NoAnswer,
    /// Ни один запрос не принят гнездом.
    SendFailed,
}

/// Что ждём: эхо (точный источник) или ответ проверки доступа (другой порт того же IP).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WaitKind {
    Echo,
    Reach,
}

struct Slot {
    nonce: Nonce,
    got: Option<(SocketAddrV4, u16)>,
}

/// Ожидание ответов текущей пробы: живёт в `KnockState` под замком.
pub(crate) struct EchoWait {
    server: SocketAddrV4,
    kind: WaitKind,
    slots: Vec<Slot>,
    notify: Arc<Notify>,
}

impl EchoWait {
    /// Сегмент датаграммы от `src`: `true`, если это ответ текущей пробы (его вырезают, он не
    /// идёт дальше). Чужой источник, длина, nonce, тип и разбор проверяются здесь; повтор того
    /// же ответа (тот же nonce) тоже вырезается, но результат не меняет.
    pub(crate) fn offer(&mut self, src: SocketAddr, seg: &[u8]) -> bool {
        if seg.len() != RESPONSE_LEN {
            return false;
        }
        let SocketAddr::V4(src) = src else {
            return false;
        };
        let source_ok = match self.kind {
            WaitKind::Echo => src == self.server,
            WaitKind::Reach => src.ip() == self.server.ip() && src.port() != self.server.port(),
        };
        if !source_ok {
            return false;
        }
        let want_reach = self.kind == WaitKind::Reach;
        for slot in &mut self.slots {
            let Ok(resp) = parse_response(seg, &slot.nonce) else {
                continue;
            };
            if resp.reach != want_reach {
                return false;
            }
            let SocketAddr::V4(observed) = resp.observed else {
                return false;
            };
            if slot.got.is_none() {
                slot.got = Some((observed, resp.reach_port));
            }
            self.notify.notify_one();
            return true;
        }
        false
    }

    fn answered(&self, i: usize) -> bool {
        self.slots.get(i).is_some_and(|s| s.got.is_some())
    }

    fn all_answered(&self) -> bool {
        self.slots.iter().all(|s| s.got.is_some())
    }
}

/// Занятая проба: при уничтожении (в том числе при отмене будущего) гнездо перестаёт забирать
/// ответы и ожидание сбрасывается.
struct EchoGuard {
    knock: Arc<KnockState>,
    notify: Arc<Notify>,
}

impl EchoGuard {
    /// `Busy`, если другая проба уже идёт. Иначе записывает ожидание и включает фильтр гнезда.
    fn start(
        knock: &Arc<KnockState>,
        kind: WaitKind,
        server: SocketAddrV4,
        nonces: &[Nonce],
    ) -> Result<Self, EchoError> {
        let notify = Arc::new(Notify::new());
        let mut slot = knock
            .echo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slot.is_some() {
            return Err(EchoError::Busy);
        }
        *slot = Some(EchoWait {
            server,
            kind,
            slots: nonces
                .iter()
                .map(|n| Slot {
                    nonce: *n,
                    got: None,
                })
                .collect(),
            notify: notify.clone(),
        });
        knock
            .echo_active
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(Self {
            knock: knock.clone(),
            notify,
        })
    }

    fn with_wait<R>(&self, f: impl FnOnce(&EchoWait) -> R) -> Option<R> {
        let slot = self
            .knock
            .echo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slot.as_ref().map(f)
    }

    fn results(&self) -> Vec<Option<(SocketAddrV4, u16)>> {
        self.with_wait(|w| w.slots.iter().map(|s| s.got).collect())
            .unwrap_or_default()
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        let mut slot = self
            .knock
            .echo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *slot = None;
        self.knock
            .echo_active
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

/// Сервер годится для запросов: адрес не неуказанный, не групповой, не широковещательный, порт
/// не 0. Петля и частные адреса допустимы (тесты, домашняя сеть).
fn server_ok(server: SocketAddrV4) -> bool {
    let ip = server.ip();
    server.port() != 0 && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast()
}

/// Свои случайные nonce, по одному на путь. Сбой генератора: ничего не отправлено.
fn fresh_nonces(n: usize) -> Result<Vec<Nonce>, EchoError> {
    let rng = SystemRandom::new();
    (0..n)
        .map(|_| {
            let mut b = [0u8; NONCE_LEN];
            rng.fill(&mut b).map_err(|_| EchoError::Random)?;
            Ok(Nonce(b))
        })
        .collect()
}

/// Одна задача отправки: адрес источника пути и готовый запрос.
type Job = (Option<Ipv4Addr>, [u8; REQUEST_LEN]);

impl QuinnTransport {
    /// Основное гнездо только IPv4.
    fn check_echo_family(&self) -> Result<(), EchoError> {
        match self.inner.endpoint.local_addr() {
            Ok(SocketAddr::V4(_)) => Ok(()),
            _ => Err(EchoError::SocketFamily),
        }
    }

    /// Рассылка запросов с повторами: до `ECHO_TRIES` на путь через `ECHO_RETRY`, срок
    /// `ECHO_DEADLINE`. Возвращает, принято ли гнездом хоть одно отправление пути.
    async fn drive(&self, guard: &EchoGuard, server: SocketAddrV4, jobs: &[Job]) -> Vec<bool> {
        let knock = &self.inner.knock;
        let start = Instant::now();
        let deadline = start + ECHO_DEADLINE;
        let mut sent = vec![false; jobs.len()];
        for attempt in 0..ECHO_TRIES {
            for (i, (src, request)) in jobs.iter().enumerate() {
                if guard.with_wait(|w| w.answered(i)).unwrap_or(true) {
                    continue;
                }
                if knock.send_echo(SocketAddr::V4(server), request, *src).await
                    && let Some(flag) = sent.get_mut(i)
                {
                    *flag = true;
                }
            }
            let until = (start + ECHO_RETRY.saturating_mul(attempt + 1)).min(deadline);
            loop {
                if guard.with_wait(EchoWait::all_answered).unwrap_or(true) {
                    return sent;
                }
                if timeout_at(until, guard.notify.notified()).await.is_err() {
                    break;
                }
            }
        }
        sent
    }

    /// Эхо-проба: по запросу на каждый путь (адрес источника на один пакет, `None`: выбор
    /// системы) с основного гнезда. Итоги в порядке `sources`. Не больше `ECHO_MAX_PATHS` путей.
    /// Допуск адреса сервера не открывается.
    pub async fn echo_probe(
        &self,
        server: SocketAddrV4,
        sources: &[Option<Ipv4Addr>],
    ) -> Result<Vec<EchoPathResult>, EchoError> {
        if !server_ok(server) {
            return Err(EchoError::BadServer);
        }
        if sources.len() > ECHO_MAX_PATHS {
            return Err(EchoError::TooManyPaths);
        }
        self.check_echo_family()?;
        let nonces = fresh_nonces(sources.len())?;
        let guard = EchoGuard::start(&self.inner.knock, WaitKind::Echo, server, &nonces)?;
        let jobs: Vec<Job> = sources
            .iter()
            .zip(&nonces)
            .map(|(src, n)| (*src, encode_echo_request(n)))
            .collect();
        let sent = self.drive(&guard, server, &jobs).await;
        let got = guard.results();
        Ok(sent
            .iter()
            .enumerate()
            .map(|(i, ok)| match got.get(i).copied().flatten() {
                Some((addr, reach_port)) => EchoPathResult::Observed { addr, reach_port },
                None if *ok => EchoPathResult::NoAnswer,
                None => EchoPathResult::SendFailed,
            })
            .collect())
    }

    /// Проверка доступа: запрос на основной порт сервера с просьбой ответить со второго порта на
    /// `target_port` этого же компьютера. `true`: ответ проверки пришёл с IP сервера и порта,
    /// отличного от `server.port()`, за `ECHO_DEADLINE`. Не больше `ECHO_TRIES` запросов.
    pub async fn reach_probe(
        &self,
        server: SocketAddrV4,
        source: Option<Ipv4Addr>,
        target_port: u16,
    ) -> Result<bool, EchoError> {
        if !server_ok(server) || target_port == 0 {
            return Err(EchoError::BadServer);
        }
        self.check_echo_family()?;
        let nonces = fresh_nonces(1)?;
        let guard = EchoGuard::start(&self.inner.knock, WaitKind::Reach, server, &nonces)?;
        let jobs: Vec<Job> = nonces
            .iter()
            .map(|n| (source, encode_reach_request(n, target_port)))
            .collect();
        let _ = self.drive(&guard, server, &jobs).await;
        Ok(guard.results().first().copied().flatten().is_some())
    }
}
