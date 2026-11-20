//! Системное уведомление о входящих файлах (этап 18е, SPEC 5). Здесь два слоя.
//!
//! * Без ОС: тексты и очистка. Имя друга и имена файлов приходят от другой стороны и считаются
//!   враждебным вводом: управляющие и невидимые символы убираются, длина ограничена. Разметки в
//!   тексте нет: Windows получает его значением узла XML (`SetInnerText`, разбор разметки не
//!   выполняется; проверено по исходникам `tauri-winrt-notification 0.8.1`), поэтому знаки
//!   `<`, `>`, `&` остаются обычными буквами и НЕ экранируются здесь (двойное экранирование
//!   показало бы `&amp;`).
//! * Windows: показ через `tauri-winrt-notification`. Остальные ОС: ничего (остаётся мигание
//!   окна в панели задач и в Dock).

use std::sync::atomic::{AtomicBool, Ordering};

use crate::rows::Id;
use crate::texts::human_size;

/// Идентификатор приложения (AppUserModelID) для уведомлений Windows. Тот же текст стоит в
/// ярлыке установщика (`packaging/windows/chervotochina.iss`, строка `[Icons]`): Windows
/// сопоставляет уведомление с ярлыком меню «Пуск» по этому идентификатору. Стабильный, без
/// версии: менять нельзя (тест сверяет его с установщиком).
#[cfg_attr(not(windows), allow(dead_code))]
pub const APP_ID: &str = "Chervotochina.App";

/// Заголовок уведомления.
#[cfg_attr(not(windows), allow(dead_code))]
pub const TITLE: &str = "Червоточина";
/// Сколько символов имени друга или файла показывается.
pub const MAX_NAME_CHARS: usize = 64;

/// Что известно о предложении к моменту уведомления (собирает фоновый поток).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OfferNote {
    pub transfer: Id,
    /// Имя друга как в списке (недоверенное: очищается при показе).
    pub friend: String,
    /// Сколько файлов в предложении; 0: неизвестно (автоприём).
    pub files: usize,
    pub total: u64,
    /// Имя первого файла (недоверенное).
    pub first_name: Option<String>,
}

/// Уведомление, готовое к показу.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Toast {
    pub text: String,
}

/// Невидимые символы форматирования и управления направлением письма: ими можно подменить вид
/// имени. Управляющие (`char::is_control`) отдельно.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{034F}'
            | '\u{061C}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FFA0}'
            | '\u{E0000}'..='\u{E007F}'
            | '\u{E0100}'..='\u{E01EF}'
            | '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206F}'
            | '\u{FEFF}'
            | '\u{FFF9}'..='\u{FFFB}'
    )
}

/// Очистка недоверенного имени: управляющие символы (в том числе переводы строк и табуляция)
/// становятся пробелом, невидимые отбрасываются, подряд идущие пробелы сливаются, края
/// обрезаются, длина не больше `max` символов (при обрезке в конце `…`).
pub fn clean(text: &str, max: usize) -> String {
    let mut out = String::new();
    let mut space = false;
    for c in text.chars() {
        if is_invisible(c) {
            continue;
        }
        if c.is_control() || c.is_whitespace() {
            space = !out.is_empty();
            continue;
        }
        if space {
            out.push(' ');
            space = false;
        }
        out.push(c);
    }
    if out.chars().count() > max {
        let keep = max.saturating_sub(1);
        let mut cut: String = out.chars().take(keep).collect();
        while cut.ends_with(' ') {
            cut.pop();
        }
        cut.push('…');
        out = cut;
    }
    out
}

fn friend_label(friend: &str) -> String {
    let c = clean(friend, MAX_NAME_CHARS);
    if c.is_empty() {
        "Друг".to_owned()
    } else {
        c
    }
}

/// «{друг} прислал файлы: {N} шт., {размер}»; для одного файла с именем: «{друг} прислал файл
/// «{имя}», {размер}».
pub fn incoming_text(n: &OfferNote) -> String {
    let friend = friend_label(&n.friend);
    let size = human_size(n.total);
    if n.files == 1
        && let Some(name) = n
            .first_name
            .as_deref()
            .map(|s| clean(s, MAX_NAME_CHARS))
            .filter(|s| !s.is_empty())
    {
        return format!("{friend} прислал файл «{name}», {size}");
    }
    format!("{friend} прислал файлы: {} шт., {size}", n.files)
}

/// «{друг}: файлы приняты» (автоприём, по завершении).
pub fn auto_text(friend: &str) -> String {
    format!("{}: файлы приняты", friend_label(friend))
}

/// Щелчок по уведомлению (ставит фоновый обработчик ОС, читает окно).
static CLICKED: AtomicBool = AtomicBool::new(false);

/// Был ли щелчок по уведомлению с прошлого вызова (один раз на щелчок).
pub fn take_clicked() -> bool {
    CLICKED.swap(false, Ordering::SeqCst)
}

/// Показать уведомление. `wake`: разбудить окно (оно прочитает `take_clicked`). Любая ошибка ОС
/// молчаливо игнорируется: мигание окна остаётся.
#[cfg(windows)]
pub fn show(toast: &Toast, wake: impl Fn() + Send + 'static) {
    use tauri_winrt_notification::Toast as Win;
    // Свой идентификатор: заголовок и значок над текстом Windows берёт из ярлыка установщика с
    // тем же AppUserModelID (`APP_ID`). Без установки (запуск из папки сборки) ярлыка нет, и
    // Windows может не показать уведомление совсем: тогда остаётся мигание окна.
    let _ = Win::new(APP_ID)
        .title(TITLE)
        .text1(&toast.text)
        .on_activated(move |_| {
            CLICKED.store(true, Ordering::SeqCst);
            wake();
            Ok(())
        })
        .show();
}

/// Не Windows: системного уведомления нет (мигание окна остаётся).
#[cfg(not(windows))]
pub fn show(_toast: &Toast, _wake: impl Fn() + Send + 'static) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(friend: &str, files: usize, first: Option<&str>) -> OfferNote {
        OfferNote {
            transfer: Id(1),
            friend: friend.to_owned(),
            files,
            total: 3 * 1024 * 1024,
            first_name: first.map(str::to_owned),
        }
    }

    /// Идентификатор в коде и в ярлыке установщика один и тот же.
    #[test]
    fn app_id_matches_the_installer_shortcut() {
        let iss = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/windows/chervotochina.iss");
        let text = std::fs::read_to_string(iss).unwrap();
        let want = format!("AppUserModelID: \"{APP_ID}\"");
        let lines: Vec<&str> = text
            .lines()
            .filter(|l| l.starts_with("Name: \"{autoprograms}"))
            .collect();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].contains(&want), "{}", lines[0]);
        assert!(!APP_ID.contains(char::is_whitespace) && APP_ID.contains('.'));
    }

    #[test]
    fn control_and_invisible_characters_are_removed() {
        assert_eq!(clean("a\r\nb\tc\u{0}d", 64), "a b c d");
        assert_eq!(clean("  x\u{202E}y\u{200B}z  ", 64), "xyz");
        assert_eq!(clean("\u{7}\u{1b}[31m", 64), "[31m");
        assert_eq!(clean("\n\n", 64), "");
        assert_eq!(clean("а  б", 64), "а б");
        // ревью 18е: теги, селекторы вариантов, хангыльские заполнители и CGJ тоже невидимы
        assert_eq!(
            clean("a\u{E0041}\u{FE0F}\u{3164}\u{115F}\u{034F}\u{FFA0}\u{E0100}b", 64),
            "ab"
        );
    }

    #[test]
    fn length_is_cut_in_characters_not_bytes() {
        let long = "ж".repeat(200);
        let c = clean(&long, MAX_NAME_CHARS);
        assert_eq!(c.chars().count(), MAX_NAME_CHARS);
        assert!(c.ends_with('…'));
        assert_eq!(clean("коротко", MAX_NAME_CHARS), "коротко");
        // ровно по границе не режется
        let edge = "a".repeat(MAX_NAME_CHARS);
        assert_eq!(clean(&edge, MAX_NAME_CHARS), edge);
    }

    #[test]
    fn markup_characters_stay_plain_text() {
        // разметки нет: значение узла XML экранирует ОС-слой; здесь символы не трогаются
        let c = clean("<b>&amp;</b> \"x\" 'y'", 64);
        assert_eq!(c, "<b>&amp;</b> \"x\" 'y'");
        let t = incoming_text(&note("<toast>", 2, None));
        assert!(t.starts_with("<toast> прислал файлы: 2 шт."));
    }

    #[test]
    fn incoming_text_forms() {
        let t = incoming_text(&note("Аня", 3, Some("a.txt")));
        assert!(t.starts_with("Аня прислал файлы: 3 шт., "), "{t}");
        let one = incoming_text(&note("Аня", 1, Some("отчёт\n.pdf")));
        assert!(one.starts_with("Аня прислал файл «отчёт .pdf», "), "{one}");
        // имя единственного файла пустое после очистки: общая форма
        let empty = incoming_text(&note("Аня", 1, Some("\u{200B}\n")));
        assert!(empty.starts_with("Аня прислал файлы: 1 шт., "), "{empty}");
        // пустое имя друга
        assert!(incoming_text(&note(" \n ", 2, None)).starts_with("Друг прислал"));
        assert_eq!(auto_text("Аня"), "Аня: файлы приняты");
        assert_eq!(auto_text(""), "Друг: файлы приняты");
    }

    #[test]
    fn hostile_names_are_bounded_in_the_final_text() {
        let evil = format!("{}\n\u{202E}evil", "я".repeat(500));
        let t = incoming_text(&note(&evil, 1, Some(&evil)));
        assert!(!t.contains('\n') && !t.contains('\u{202E}'), "{t}");
        // два имени по 64 символа плюс служебные слова и размер
        assert!(t.chars().count() < 64 * 2 + 60, "{}", t.chars().count());
    }
}
