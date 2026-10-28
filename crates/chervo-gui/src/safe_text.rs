//! Очистка строк перед показом (SPEC 19г, Р19г-8, находка 19а Low 1): имена из подписанного
//! списка и имена файлов, выбранных пользователем, не могут подменить отображение через
//! управляющие символы и символы направления письма (bidi).

/// Предел длины показываемого имени, символов.
pub const LABEL_MAX_CHARS: usize = 64;
/// Вместо пустого имени.
pub const NO_NAME: &str = "(без имени)";

/// Символ, который заменяется на U+FFFD: управляющие и невидимые форматирующие.
fn is_hostile(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
        )
}

/// Строка, безопасная для показа: опасные символы заменены на U+FFFD, длиннее `max_chars`
/// обрезается по символам с «…», пустая становится «(без имени)».
pub fn safe_label(s: &str, max_chars: usize) -> String {
    if s.is_empty() {
        return NO_NAME.to_owned();
    }
    let mut out = String::new();
    for (n, c) in s.chars().enumerate() {
        if n == max_chars {
            out.push('…');
            break;
        }
        out.push(if is_hostile(c) { '\u{FFFD}' } else { c });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_label_table() {
        let f = '\u{FFFD}';
        let cases: [(&str, String); 16] = [
            ("plain.txt", "plain.txt".to_owned()),
            ("файл-отчёт.pdf", "файл-отчёт.pdf".to_owned()),
            ("a\u{7}b", format!("a{f}b")),
            ("a\u{0}b", format!("a{f}b")),
            ("a\u{7F}b", format!("a{f}b")),
            ("a\u{85}b", format!("a{f}b")),
            ("a\u{61C}b", format!("a{f}b")),
            ("a\u{180E}b", format!("a{f}b")),
            ("a\u{200B}\u{200F}b", format!("a{f}{f}b")),
            ("a\u{2028}\u{2029}b", format!("a{f}{f}b")),
            ("exe.\u{202E}gpj", format!("exe.{f}gpj")),
            ("a\u{2060}\u{2066}\u{206F}b", format!("a{f}{f}{f}b")),
            ("\u{FEFF}a", format!("{f}a")),
            ("a\u{FFF9}\u{FFFB}b", format!("a{f}{f}b")),
            // границы диапазонов: рядом стоящие обычные символы не трогаются
            (
                "a\u{2010}\u{2057}\u{2070}b",
                "a\u{2010}\u{2057}\u{2070}b".to_owned(),
            ),
            ("", NO_NAME.to_owned()),
        ];
        for (input, want) in cases {
            assert_eq!(safe_label(input, 64), want, "{input:?}");
        }
    }

    #[test]
    fn safe_label_cuts_by_chars() {
        let s64 = "ж".repeat(64);
        assert_eq!(safe_label(&s64, 64), s64);
        let s65 = "ж".repeat(65);
        assert_eq!(safe_label(&s65, 64), format!("{s64}…"));
        // опасный символ в хвосте обрезается вместе с хвостом
        let tail = format!("{s64}\u{202E}");
        assert_eq!(safe_label(&tail, 64), format!("{s64}…"));
    }
}
