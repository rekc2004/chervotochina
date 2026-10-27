//! Единственный модуль CLI, который пишет в терминал (этап 18в). Всё, что видит человек,
//! проходит через `line` и `err`; охрана `no_logger.rs` запрещает вывод и журналы в остальном
//! коде крейта. Здесь же очистка текста от управляющих символов: имена друзей и файлов не должны
//! управлять терминалом.

use std::io::Write;

/// Заменяет управляющие символы (в том числе ESC) на `?`.
pub fn clean(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

/// Строка в стандартный вывод.
pub fn line(s: &str) {
    let mut o = std::io::stdout().lock();
    // закрытый терминал или канал не повод падать: узел всё равно должен остановиться штатно
    let _ = writeln!(o, "{s}");
    let _ = o.flush();
}

/// Стандартный вывод для команд выпусков (этап 19), которые пишут в переданный `Write`.
pub fn main_sink() -> std::io::StdoutLock<'static> {
    std::io::stdout().lock()
}

/// Стандартный вывод ошибок для команд выпусков (этап 19).
pub fn err_sink() -> std::io::StderrLock<'static> {
    std::io::stderr().lock()
}

/// Строка в стандартный вывод ошибок.
pub fn err(s: &str) {
    let mut o = std::io::stderr().lock();
    let _ = writeln!(o, "{s}");
    let _ = o.flush();
}
