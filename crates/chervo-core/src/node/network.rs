//! Сеть и часы (этап 18а, A4.6-A4.8). Сеть только по выбору пользователя: ни одного пакета UPnP,
//! пока список разрешённых роутеров пуст; `upnp_identify` и сверка часов только по кнопке (их
//! узел сам никогда не вызывает); DNS только для серверов времени на этой кнопке.

use std::sync::Arc;

use chervo_addr::{MapStatus, NatView, PortMapper};
use chervo_connect::RouteProbe;
use chervo_timesync::{ClockOffset, SyncConfig, SyncError};
use chervo_upnp::{AllowedRouter, UpnpError, UpnpMapper, UpnpSettings};

use super::Node;
use super::core::{diagnosis_view, lock};
use super::error::NodeError;
use super::profile;
use super::settings::{self, MAX_CLOCK_OFFSET_MS};
use super::views::{ClockProposal, ClockSync, DiagnosisView, FriendRef, RouterCandidate};

/// Поправка больше этого значения (5 минут) применяется только после подтверждения человека
/// (SECURITY_REVIEW разд. 8, T15).
pub(crate) const CLOCK_CONFIRM_MS: u64 = 5 * 60 * 1000;

impl Node {
    /// Почему друг недоступен. `None`: соединение есть или причину пока не решить.
    pub fn diagnose(&self, friend: FriendRef) -> Result<Option<DiagnosisView>, NodeError> {
        let d = self.core.engine.diagnose(friend.inner())?;
        Ok(d.map(diagnosis_view))
    }

    pub fn nat_view(&self) -> NatView {
        self.core.engine.nat_view()
    }

    /// Последний итог проброса; `None`, пока итога не было (или проброс не включён).
    pub fn mapping_status(&self) -> Option<MapStatus> {
        self.core.engine.mapping_status()
    }

    /// Кнопка «обновить проброс»: повторить опрос роутера сейчас.
    pub fn refresh_mapping(&self) {
        self.core.engine.refresh_mapping();
    }

    /// Кнопка «Найти роутер». Берёт собственный IPv4 основного маршрута у пробы маршрута (она
    /// пакетов не отправляет), затем делает один поиск SSDP и одно описание. Блокирует поток.
    pub fn upnp_identify(&self) -> Result<RouterCandidate, NodeError> {
        let Some(own) = self.core.probe.probe().v4 else {
            return Err(NodeError::Upnp(UpnpError::NoGateway));
        };
        let attached = lock(&self.core.mapper).clone();
        let mapper = attached.unwrap_or_else(|| Arc::new(UpnpMapper::new(UpnpSettings::default())));
        let id = mapper.identify(own).map_err(NodeError::Upnp)?;
        Ok(RouterCandidate(id))
    }

    /// Разрешить роутеру открывать порт. `permanent_ok`: согласие на бессрочную аренду (после
    /// `NEED_PERMANENT_TEXT`). Сохраняется в настройках; проброс подключается, если ещё нет.
    pub fn upnp_allow(
        &self,
        router: &RouterCandidate,
        permanent_ok: bool,
    ) -> Result<(), NodeError> {
        self.update_settings(|s| {
            if let Some(r) = s.routers.iter_mut().find(|r| r.id == router.0) {
                r.permanent_ok = permanent_ok;
            } else {
                if s.routers.len() >= settings::MAX_ROUTERS {
                    return Err(NodeError::InputTooLong);
                }
                s.routers.push(AllowedRouter {
                    id: router.0.clone(),
                    permanent_ok,
                });
            }
            Ok(())
        })?;
        self.sync_mapper()
    }

    /// Убрать роутер из разрешённых. Если у него был бессрочный проброс, он снимается (при
    /// подтверждении роутера, T16).
    pub fn upnp_forget(&self, router: &RouterCandidate) -> Result<(), NodeError> {
        self.update_settings(|s| {
            s.routers.retain(|r| r.id != router.0);
            Ok(())
        })?;
        self.sync_mapper()
    }

    /// Привести отображатель портов в соответствие со списком в настройках.
    fn sync_mapper(&self) -> Result<(), NodeError> {
        let routers = lock(&self.core.settings).routers.clone();
        let existing = {
            let _g = self.enter();
            let mut slot = lock(&self.core.mapper);
            if slot.is_none() && !routers.is_empty() {
                let m = Arc::new(UpnpMapper::new(UpnpSettings {
                    routers: routers.clone(),
                }));
                let dynamic: Arc<dyn PortMapper> = m.clone();
                self.core.engine.attach_mapper(dynamic)?;
                *slot = Some(m);
                None
            } else {
                slot.clone()
            }
        };
        if let Some(m) = existing {
            // может сходить к роутеру (снять бессрочный проброс): без замка узла
            m.set_settings(UpnpSettings { routers });
        }
        self.core.engine.refresh_mapping();
        Ok(())
    }

    /// Кнопка «Сверить часы» (автоматической сверки нет). Серверы времени из настроек или по
    /// умолчанию. Поправка до 5 минут применяется и сохраняется; больше: `NeedsConfirm`, пока
    /// человек не подтвердит (`confirm_clock`). Блокирует поток (DNS и UDP).
    pub fn sync_clock(&self) -> Result<ClockSync, NodeError> {
        let servers = lock(&self.core.settings).ntp_servers.clone();
        let mut cfg = SyncConfig::default();
        if !servers.is_empty() {
            cfg.servers = servers;
        }
        self.decide_clock(chervo_timesync::sync_clock(&cfg))
    }

    pub(crate) fn decide_clock(
        &self,
        result: Result<ClockOffset, SyncError>,
    ) -> Result<ClockSync, NodeError> {
        let off = result.map_err(NodeError::Clock)?.offset_ms;
        if off.unsigned_abs() > CLOCK_CONFIRM_MS {
            return Ok(ClockSync::NeedsConfirm(ClockProposal { offset_ms: off }));
        }
        self.set_clock(off, profile::now_unix())?;
        Ok(ClockSync::Applied { offset_ms: off })
    }

    /// Подтверждение поправки больше 5 минут.
    pub fn confirm_clock(&self, proposal: ClockProposal) -> Result<(), NodeError> {
        self.set_clock(proposal.offset_ms, profile::now_unix())
    }

    /// Кнопка «Сбросить поправку».
    pub fn reset_clock(&self) -> Result<(), NodeError> {
        self.set_clock(0, 0)
    }

    /// Сначала запись в настройки, потом действующие часы: при сбое записи ничего не меняется.
    fn set_clock(&self, ms: i64, at: u64) -> Result<(), NodeError> {
        if ms.unsigned_abs() > MAX_CLOCK_OFFSET_MS.unsigned_abs() {
            return Err(NodeError::Clock(SyncError::TooLarge));
        }
        self.update_settings(|s| {
            s.clock_offset_ms = ms;
            s.clock_offset_at = at;
            Ok(())
        })?;
        self.core
            .clock
            .set_offset_ms(ms)
            .map_err(|_| NodeError::Clock(SyncError::TooLarge))?;
        self.core
            .transport
            .set_clock_offset(ms)
            .map_err(|_| NodeError::Clock(SyncError::TooLarge))?;
        Ok(())
    }
}
