//! Выход из тупиков запуска без окна (этап 18в, круг 1): принять старый список друзей, начать
//! список заново, сбросить настройки. Каждое действие необратимо или ослабляет защиту, поэтому
//! сначала объяснение, что именно будет потеряно, затем явное подтверждение словом `ДА`.
//! Без терминала на стандартном вводе подтверждение словом не принимается: нужен флаг `--yes`.

use crate::out;

/// Слово подтверждения (регистр важен).
pub const CONFIRM_WORD: &str = "ДА";

pub const ACCEPT_OLDER_WARNING: &str = "Принять старый список друзей. Программа обнаружила, что список старше последнего изменения безопасности (удаления, блокировки, пересоздания ключа): возможно, файл подменили старой копией. Если принять его, друзья, которых вы уже удалили или заблокировали, снова станут действующими, а изменения после этой копии пропадут. Продолжайте, только если знаете, откуда взялась старая копия (например, вы сами вернули её из резервной).";
pub const START_OVER_WARNING: &str = "Начать список друзей заново. Все друзья пропадут из списка, их придётся добавить снова новыми приглашениями. Старый файл останется рядом (расширение .unreadable-ВРЕМЯ), но без потерянного ключа прочитать его нельзя.";
pub const RESET_SETTINGS_WARNING: &str = "Сбросить настройки. Файл настроек будет убран в сторону (копия settings.v1.bad-ВРЕМЯ). Пропадут выбор папки приёма, дополнительные папки приёма, список разрешённых роутеров и поправка часов; порт выберется заново, поэтому друзьям понадобятся ваши новые адреса (token-for). Список друзей и ключи не затрагиваются. После сброса выполните: chervo init --receive ПАПКА";
pub const FORGET_RETIRED_WARNING: &str = "Забыть текст отзыва. Его нельзя будет показать снова: если друг ещё не получил этот текст, он узнает об удалении или смене ключа только при неудачной попытке соединиться.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    AcceptOlder,
    StartOver,
    ResetSettings,
}

impl Recovery {
    fn warning(self) -> &'static str {
        match self {
            Self::AcceptOlder => ACCEPT_OLDER_WARNING,
            Self::StartOver => START_OVER_WARNING,
            Self::ResetSettings => RESET_SETTINGS_WARNING,
        }
    }
}

pub fn is_confirm(s: &str) -> bool {
    s.trim() == CONFIRM_WORD
}

/// Показывает объяснение и решает, продолжать ли. `interactive`: на стандартном вводе терминал.
/// `read` читает одну строку ответа (вызывается, только если нужно спросить).
pub fn confirm(
    what: Recovery,
    yes: bool,
    interactive: bool,
    read: impl FnOnce() -> Option<String>,
) -> bool {
    out::line(what.warning());
    if yes {
        return true;
    }
    if !interactive {
        out::err(
            "Стандартный ввод не терминал: подтвердить словом нельзя. Добавьте --yes, если уверены.",
        );
        return false;
    }
    out::line(&format!("Для подтверждения введите {CONFIRM_WORD}:"));
    if read().is_some_and(|a| is_confirm(&a)) {
        true
    } else {
        out::err("Отменено: ничего не изменено.");
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decisions() {
        let asked = std::cell::Cell::new(false);
        let never = || -> Option<String> {
            asked.set(true);
            Some(CONFIRM_WORD.to_owned())
        };
        // без терминала слово не принимается, и спрашивать не пытаются
        assert!(!confirm(Recovery::StartOver, false, false, never));
        // --yes обходит вопрос
        assert!(confirm(Recovery::StartOver, true, false, never));
        assert!(!asked.get(), "ввод не должен читаться");
        // с терминалом нужно точное слово
        let ans = |s: &'static str| move || Some(s.to_owned());
        assert!(confirm(Recovery::AcceptOlder, false, true, ans("ДА")));
        assert!(confirm(Recovery::AcceptOlder, false, true, ans("  ДА ")));
        assert!(!confirm(Recovery::AcceptOlder, false, true, ans("да")));
        assert!(!confirm(Recovery::AcceptOlder, false, true, ans("yes")));
        assert!(!confirm(Recovery::AcceptOlder, false, true, ans("")));
        assert!(!confirm(Recovery::AcceptOlder, false, true, || None));
    }
}
