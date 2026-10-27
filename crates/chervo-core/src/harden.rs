//! Укрепление процесса (этап 17, решение 6, C07): запрет дампов памяти, где это можно сделать
//! без `unsafe` (в крейте `unsafe_code = "forbid"`).
//!
//! * Linux: `prctl(PR_SET_DUMPABLE, 0)` и `RLIMIT_CORE = 0` (мягкий и жёсткий пределы).
//! * macOS: `RLIMIT_CORE = 0` (мягкий и жёсткий). `PT_DENY_ATTACH` требует `unsafe`: не делается.
//! * Windows: ничего. Отчёты WER и подключение отладчика тем же пользователем остаются
//!   принятым остатком (T10, решение владельца Q4); без `unsafe` и без сторонних крейтов
//!   исключить процесс из WER нельзя.
//!
//! Функция не возвращает ошибок: сбой одной меры не мешает остальным и виден в
//! [`HardenReport`] (каждое поле проверено чтением обратно, а не принято на веру).
//!
//! Требование к оболочкам: вызывать первой строкой `main`, до загрузки любого ключа
//! (CLI: `crates/chervo-cli/src/main.rs`; GUI этапа 18 обязан делать то же).

/// Закрытый маркер: вне модуля значение `Sealed` не построить.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Sealed;

/// Что реально применено и подтверждено чтением обратно.
///
/// Отчёт запечатан (этап 18а): у него есть закрытое поле и нет `Default`, поэтому вне
/// `chervo-core` получить его можно только из [`harden_process`]. `Node::open` принимает
/// `&HardenReport` как доказательство, что укрепление выполнено до загрузки ключей.
///
/// ```compile_fail
/// // нет `Default`: пустой отчёт «укреплено» построить нельзя
/// let _ = chervo_core::HardenReport::default();
/// ```
///
/// ```compile_fail
/// // закрытое поле: литерал структуры вне крейта не собрать
/// let _ = chervo_core::HardenReport {
///     not_dumpable: true,
///     core_limit_zero: true,
/// };
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardenReport {
    /// Linux: `PR_SET_DUMPABLE = 0` установлен (процесс не дампится и не трассируется чужим
    /// процессом без прав).
    pub not_dumpable: bool,
    /// Linux и macOS: `RLIMIT_CORE` равен 0 (мягкий и жёсткий пределы): файлы core не создаются.
    pub core_limit_zero: bool,
    /// Печать запечатывания: поле закрыто, значит `HardenReport` строит только этот модуль.
    sealed: Sealed,
}

impl HardenReport {
    /// Применена ли хотя бы одна мера (на Windows всегда `false`).
    pub fn any_applied(&self) -> bool {
        self.not_dumpable || self.core_limit_zero
    }
}

/// Применяет доступные меры против дампов памяти. Вызывать как можно раньше.
pub fn harden_process() -> HardenReport {
    #[allow(unused_mut)]
    let mut report = HardenReport {
        not_dumpable: false,
        core_limit_zero: false,
        sealed: Sealed,
    };
    #[cfg(target_os = "linux")]
    {
        report.not_dumpable = imp::set_not_dumpable();
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        report.core_limit_zero = imp::set_core_limit_zero();
    }
    report
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod imp {
    use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};

    /// Предел core: 0/0. Жёсткий предел тоже 0, чтобы позже его нельзя было поднять в процессе.
    pub(super) fn set_core_limit_zero() -> bool {
        let zero = Rlimit {
            current: Some(0),
            maximum: Some(0),
        };
        if setrlimit(Resource::Core, zero).is_err() {
            return false;
        }
        let now = getrlimit(Resource::Core);
        now.current == Some(0) && now.maximum == Some(0)
    }

    #[cfg(target_os = "linux")]
    pub(super) fn set_not_dumpable() -> bool {
        use rustix::process::{DumpableBehavior, dumpable_behavior, set_dumpable_behavior};
        if set_dumpable_behavior(DumpableBehavior::NotDumpable).is_err() {
            return false;
        }
        matches!(dumpable_behavior(), Ok(DumpableBehavior::NotDumpable))
    }
}
