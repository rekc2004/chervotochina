//! Ввод строк с ограничением длины и разбор строки команды. Вставленный текст недоверенный:
//! строка длиннее предела не накапливается в памяти, а отбрасывается до конца.

use std::io::{BufRead, ErrorKind};
use std::sync::mpsc::{Receiver, sync_channel};

/// Предел одной строки, байт (токены не длиннее 4096; ядро проверяет это ещё раз).
pub const MAX_LINE: usize = 8192;

#[derive(Debug, PartialEq, Eq)]
pub enum Input {
    Line(String),
    TooLong,
    /// Строка не в UTF-8.
    BadText,
    Eof,
}

pub fn read_line<R: BufRead>(r: &mut R) -> Input {
    let mut buf: Vec<u8> = Vec::new();
    let mut over = false;
    let mut any = false;
    loop {
        let (used, done) = {
            let chunk = match r.fill_buf() {
                Ok(c) => c,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return Input::Eof,
            };
            if chunk.is_empty() {
                if !any {
                    return Input::Eof;
                }
                break;
            }
            any = true;
            let (part, used, done) = match chunk.iter().position(|b| *b == b'\n') {
                Some(i) => (chunk.get(..i).unwrap_or_default(), i + 1, true),
                None => (chunk, chunk.len(), false),
            };
            if !over {
                if buf.len() + part.len() > MAX_LINE {
                    over = true;
                    buf.clear();
                } else {
                    buf.extend_from_slice(part);
                }
            }
            (used, done)
        };
        r.consume(used);
        if done {
            break;
        }
    }
    if over {
        return Input::TooLong;
    }
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    match String::from_utf8(buf) {
        Ok(s) => Input::Line(s),
        Err(_) => Input::BadText,
    }
}

/// Строки со стандартного ввода из отдельного потока. После `Eof` поток завершается.
pub fn stdin_lines() -> Receiver<Input> {
    let (tx, rx) = sync_channel(16);
    let spawned = std::thread::Builder::new()
        .name("chervo-stdin".to_owned())
        .spawn(move || {
            let stdin = std::io::stdin();
            let mut lock = stdin.lock();
            loop {
                let i = read_line(&mut lock);
                let eof = i == Input::Eof;
                if tx.send(i).is_err() || eof {
                    break;
                }
            }
        });
    if spawned.is_err() {
        // потока нет: канал закрыт, REPL увидит конец ввода
        let (_tx, rx) = sync_channel(1);
        return rx;
    }
    rx
}

/// Слова строки команды. Двойные кавычки склеивают слово с пробелами (пути, имена); других
/// escape-последовательностей нет. `None`: кавычка не закрыта.
pub fn tokenize(line: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut has = false;
    for c in line.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                has = true;
            }
            c if c.is_whitespace() && !quoted => {
                if has {
                    out.push(std::mem::take(&mut cur));
                    has = false;
                }
            }
            c => {
                cur.push(c);
                has = true;
            }
        }
    }
    if quoted {
        return None;
    }
    if has {
        out.push(cur);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
    use super::*;
    use std::io::Cursor;

    #[test]
    fn lines_and_limits() {
        let mut c = Cursor::new(b"abc\r\nsecond\nlast".to_vec());
        assert_eq!(read_line(&mut c), Input::Line("abc".into()));
        assert_eq!(read_line(&mut c), Input::Line("second".into()));
        assert_eq!(read_line(&mut c), Input::Line("last".into()));
        assert_eq!(read_line(&mut c), Input::Eof);

        let mut long = vec![b'x'; MAX_LINE + 1];
        long.push(b'\n');
        long.extend_from_slice(b"next\n");
        let mut c = Cursor::new(long);
        assert_eq!(read_line(&mut c), Input::TooLong);
        assert_eq!(read_line(&mut c), Input::Line("next".into()));

        let mut ok = vec![b'y'; MAX_LINE];
        ok.push(b'\n');
        assert!(matches!(read_line(&mut Cursor::new(ok)), Input::Line(s) if s.len() == MAX_LINE));

        let mut c = Cursor::new(vec![0xff, 0xfe, b'\n']);
        assert_eq!(read_line(&mut c), Input::BadText);
    }

    #[test]
    fn tokens() {
        assert_eq!(
            tokenize(r#"send "Боб Иванов" "C:\a b\c.txt" d"#),
            Some(vec![
                "send".into(),
                "Боб Иванов".into(),
                r"C:\a b\c.txt".into(),
                "d".into()
            ])
        );
        assert_eq!(tokenize("  "), Some(vec![]));
        assert_eq!(tokenize(r#"a "b"#), None);
        assert_eq!(tokenize(r#"a """#), Some(vec!["a".into(), String::new()]));
    }
}
