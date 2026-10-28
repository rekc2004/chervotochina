//! Согласие на проверку новых версий и разрешение на запрос (этап 19г-1, Р19г-5 и Р19г-6).
//! Решения принимает `crate::update::decide` без ввода-вывода; здесь только хранение.

use super::Node;
use super::core::lock;
use super::error::NodeError;
use super::settings;
use crate::update::{Decision, UpdateCheckPermit, UpdateConsent, decide};

impl Node {
    /// Ответ пользователя на вопрос «проверять новые версии?». Включение само ничего не
    /// отправляет; запрос возможен только через `update_check_permit`.
    pub fn set_update_consent(&self, enabled: bool) -> Result<(), NodeError> {
        self.update_settings(|s| {
            s.update_consent = Some(enabled);
            Ok(())
        })
    }

    /// Разрешение на один сетевой запрос по правилам Р19г-6. `Ok(None)`: нельзя сейчас (согласия
    /// нет, рано, часы ушли назад). Время проверки записывается ДО запроса, при выдаче разрешения,
    /// поэтому сбой запроса не вызывает повтора; ошибка записи это `Err` и разрешения нет.
    /// При отказе файл настроек не трогается.
    pub fn update_check_permit(
        &self,
        now_unix_secs: u64,
        manual: bool,
    ) -> Result<Option<UpdateCheckPermit>, NodeError> {
        let mut g = lock(&self.core.settings);
        let consent = match g.update_consent {
            None => UpdateConsent::NotAsked,
            Some(true) => UpdateConsent::Enabled,
            Some(false) => UpdateConsent::Disabled,
        };
        let decision = decide(consent, g.update_checked_at, now_unix_secs, manual);
        if decision == Decision::Deny {
            return Ok(None);
        }
        let mut next = g.clone();
        next.update_checked_at = now_unix_secs;
        settings::save(&self.core.dir, &next)?;
        *g = next;
        Ok((decision == Decision::Permit).then(UpdateCheckPermit::issue))
    }
}
