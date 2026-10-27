//! Разбор HTTP-ответа и `Location` без сети.

use crate::fuzz::Counting;
use crate::http::{Response, parse_location, read_response, request_bytes};
use crate::{
    ALLOWED_HOSTS, CheckError, LATEST_BASE, MANIFEST_FILE, MAX_HEADER_BYTES, MAX_LOCATION_LEN,
    MAX_MANIFEST_LEN, MAX_MINISIG_LEN, SIGNATURE_FILE,
};

fn parse(bytes: &[u8], max: usize) -> Result<Response, CheckError> {
    read_response(bytes, max)
}

#[test]
fn request_bytes_exact() {
    let got = request_bytes("github.com", "/a/b?c=d");
    assert_eq!(
        got,
        b"GET /a/b?c=d HTTP/1.1\r\nHost: github.com\r\nUser-Agent: chervo\r\nAccept: */*\r\nConnection: close\r\n\r\n"
    );
    let text = String::from_utf8(got).expect("ascii");
    let lower = text.to_ascii_lowercase();
    for banned in [
        "cookie",
        "referer",
        "accept-encoding",
        "accept-language",
        "authorization",
        "version",
    ] {
        assert!(!lower.contains(banned), "лишний заголовок {banned}");
    }
}

#[test]
fn start_addresses_are_valid_and_embedded() {
    for file in [MANIFEST_FILE, SIGNATURE_FILE] {
        let l = parse_location(&format!("{LATEST_BASE}{file}")).expect("start");
        assert_eq!(l.host, "github.com");
        assert_eq!(
            l.path,
            format!("/rekc2004/chervotochina/releases/latest/download/{file}")
        );
    }
    assert!(crate::RELEASES_PAGE.starts_with("https://github.com/rekc2004/chervotochina"));
}

fn ok(body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

#[test]
fn http_parse_good_cases() {
    assert_eq!(
        parse(&ok("hello"), 100),
        Ok(Response::Body(b"hello".to_vec()))
    );
    assert_eq!(parse(&ok(""), 100), Ok(Response::Body(Vec::new())));
    // без Content-Length тело до закрытия
    assert_eq!(
        parse(b"HTTP/1.1 200 OK\r\n\r\nabc", 100),
        Ok(Response::Body(b"abc".to_vec()))
    );
    // регистр имени, пробелы вокруг значения, лишние заголовки и Set-Cookie игнорируются
    assert_eq!(
        parse(
            b"HTTP/1.1 200\r\ncontent-LENGTH:  3 \r\nSet-Cookie: a=b\r\nX-Any: \xc3\xa9\r\n\r\nabc",
            100
        ),
        Ok(Response::Body(b"abc".to_vec()))
    );
    for code in [301, 302, 303, 307, 308] {
        let r = format!(
            "HTTP/1.1 {code} Found\r\nLocation: https://github.com/x\r\nContent-Length: 0\r\n\r\n"
        );
        assert_eq!(
            parse(r.as_bytes(), 100),
            Ok(Response::Redirect("https://github.com/x".to_owned()))
        );
    }
    // тело перенаправления не читается: после заголовков мусор не мешает
    assert!(matches!(
        parse(
            b"HTTP/1.1 302 Found\r\nLocation: https://github.com/x\r\n\r\n\xff\xff\xff",
            100
        ),
        Ok(Response::Redirect(_))
    ));
}

#[test]
fn http_parse_table() {
    let long_header = format!(
        "HTTP/1.1 200 OK\r\nX: {}\r\nContent-Length: 0\r\n\r\n",
        "a".repeat(MAX_HEADER_BYTES)
    );
    let big_cl = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", 101);
    let huge_cl = "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n";
    let long_location = format!(
        "HTTP/1.1 302 Found\r\nLocation: https://github.com/{}\r\n\r\n",
        "a".repeat(MAX_LOCATION_LEN)
    );
    let many_headers: String = (0..2000).map(|i| format!("X-{i}: v\r\n")).collect();
    let many = format!("HTTP/1.1 200 OK\r\n{many_headers}Content-Length: 0\r\n\r\n");
    let bad: Vec<(&str, Vec<u8>)> = vec![
        ("пусто", Vec::new()),
        ("нет CRLFCRLF", b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n".to_vec()),
        ("только LF", b"HTTP/1.1 200 OK\nContent-Length: 0\n\nabc".to_vec()),
        ("заголовки больше предела", long_header.into_bytes()),
        ("много заголовков", many.into_bytes()),
        (
            "повтор Content-Length",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na".to_vec(),
        ),
        ("Content-Length больше предела", big_cl.into_bytes()),
        ("Content-Length огромный", huge_cl.as_bytes().to_vec()),
        (
            "Content-Length с плюсом",
            b"HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\na".to_vec(),
        ),
        (
            "Content-Length с минусом",
            b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\na".to_vec(),
        ),
        (
            "Content-Length буквы",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1a\r\n\r\na".to_vec(),
        ),
        (
            "Content-Length пустой",
            b"HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\n".to_vec(),
        ),
        (
            "Content-Length шестнадцатеричный",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0x1\r\n\r\na".to_vec(),
        ),
        (
            "Transfer-Encoding chunked",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n".to_vec(),
        ),
        (
            "Transfer-Encoding identity",
            b"HTTP/1.1 200 OK\r\ntransfer-encoding: identity\r\nContent-Length: 1\r\n\r\na".to_vec(),
        ),
        (
            "Transfer-Encoding и длина",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\na".to_vec(),
        ),
        ("1xx", b"HTTP/1.1 100 Continue\r\n\r\n".to_vec()),
        ("204", b"HTTP/1.1 204 No Content\r\n\r\n".to_vec()),
        ("304", b"HTTP/1.1 304 Not Modified\r\n\r\n".to_vec()),
        ("404", b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec()),
        ("500", b"HTTP/1.1 500 Oops\r\nContent-Length: 0\r\n\r\n".to_vec()),
        ("статус 300", b"HTTP/1.1 300 Multiple\r\nLocation: https://github.com/x\r\n\r\n".to_vec()),
        ("статус 200 без ответа тела и без закрытия", b"HTTP/1.1 200 OK".to_vec()),
        ("кривая версия", b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()),
        ("кривая статусная строка", b"200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()),
        ("статус две цифры", b"HTTP/1.1 20 OK\r\n\r\n".to_vec()),
        ("статус буквы", b"HTTP/1.1 2x0 OK\r\n\r\n".to_vec()),
        ("статус слитно с текстом", b"HTTP/1.1 200OK\r\n\r\n".to_vec()),
        ("статус 600", b"HTTP/1.1 600 X\r\n\r\n".to_vec()),
        ("NUL в статусе", b"HTTP/1.1 200 O\0K\r\nContent-Length: 0\r\n\r\n".to_vec()),
        ("заголовок без двоеточия", b"HTTP/1.1 200 OK\r\nBroken\r\nContent-Length: 0\r\n\r\n".to_vec()),
        ("пустое имя", b"HTTP/1.1 200 OK\r\n: v\r\nContent-Length: 0\r\n\r\n".to_vec()),
        (
            "продолжение строки пробелом",
            b"HTTP/1.1 200 OK\r\nX: a\r\n b\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ),
        (
            "продолжение строки табуляцией",
            b"HTTP/1.1 200 OK\r\nX: a\r\n\tb\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ),
        (
            "пробел в имени",
            b"HTTP/1.1 200 OK\r\nBad Name: a\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ),
        (
            "NUL в значении",
            b"HTTP/1.1 200 OK\r\nX: a\0b\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ),
        (
            "одиночный CR в значении",
            b"HTTP/1.1 200 OK\r\nX: a\rb\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ),
        (
            "DEL в значении",
            b"HTTP/1.1 200 OK\r\nX: a\x7fb\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ),
        ("тело короче заявленного", b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc".to_vec()),
        ("тело длиннее заявленного", b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nabc".to_vec()),
        (
            "тело без длины больше предела",
            format!("HTTP/1.1 200 OK\r\n\r\n{}", "a".repeat(101)).into_bytes(),
        ),
        ("перенаправление без Location", b"HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n".to_vec()),
        (
            "повтор Location",
            b"HTTP/1.1 302 Found\r\nLocation: https://github.com/a\r\nLocation: https://github.com/b\r\n\r\n".to_vec(),
        ),
        ("пустой Location", b"HTTP/1.1 302 Found\r\nLocation:\r\n\r\n".to_vec()),
        ("Location длиннее предела", long_location.into_bytes()),
        (
            "Location не UTF-8",
            b"HTTP/1.1 302 Found\r\nLocation: https://github.com/\xff\r\n\r\n".to_vec(),
        ),
    ];
    assert!(bad.len() >= 25);
    for (name, bytes) in &bad {
        let r = parse(bytes, 100);
        assert!(r.is_err(), "{name}: принят {r:?}");
    }
}

#[test]
fn header_limit_boundary() {
    // ровно MAX_HEADER_BYTES заголовков проходит, на один байт больше нет
    let fixed = "HTTP/1.1 200 OK\r\nX: ".len() + "\r\nContent-Length: 0".len();
    let pad = MAX_HEADER_BYTES - fixed;
    let at = format!(
        "HTTP/1.1 200 OK\r\nX: {}\r\nContent-Length: 0\r\n\r\n",
        "a".repeat(pad)
    );
    assert_eq!(parse(at.as_bytes(), 10), Ok(Response::Body(Vec::new())));
    let over = format!(
        "HTTP/1.1 200 OK\r\nX: {}\r\nContent-Length: 0\r\n\r\n",
        "a".repeat(pad + 1)
    );
    assert!(parse(over.as_bytes(), 10).is_err());
}

#[test]
fn location_table() {
    let long = format!("https://github.com/{}", "a".repeat(MAX_LOCATION_LEN));
    let bad = [
        "/relative/path",
        "relative",
        "//github.com/x",
        "http://github.com/x",
        "HTTPS://github.com/x",
        "https://github.com",
        "https://github.com:443/x",
        "https://github.com@evil.example/",
        "https://evil.example@github.com/x",
        "https://github.com./x",
        "https://[::1]/x",
        "https://127.0.0.1/x",
        "https://140.82.112.3/x",
        "https://evil.example/x",
        "https://githubusercontent.com/x",
        "https://sub.github.com/x",
        "https://github.com.evil.example/x",
        "https://GitHub.com/x",
        "https://GITHUB.COM/x",
        "https://%67ithub.com/x",
        "https://github.com/x#frag",
        "https://github.com/x y",
        "https://github.com/x\ty",
        "https://github.com/x\ny",
        "https://github.com/\u{e9}",
        "https:///x",
        "",
        long.as_str(),
    ];
    for s in bad {
        assert!(parse_location(s).is_err(), "принят: {s:?}");
    }
    for h in ALLOWED_HOSTS {
        let l = parse_location(&format!("https://{h}/a/b?x=1&y=%2F;z=2")).expect(h);
        assert_eq!(l.host, h);
        assert_eq!(l.path, "/a/b?x=1&y=%2F;z=2");
    }
}

/// Тело читается не дальше предела (счётчик выданных байт).
#[test]
fn oversize_bodies_rejected() {
    // с длиной: сверх предела отказ до чтения тела
    for max in [MAX_MINISIG_LEN, MAX_MANIFEST_LEN] {
        let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", max + 1);
        let mut data = head.into_bytes();
        data.extend(std::iter::repeat_n(b'a', max + 10));
        let mut r = Counting {
            data: &data,
            taken: 0,
        };
        assert_eq!(read_response(&mut r, max), Err(CheckError::BadResponse));
        // тело не читалось: взято не больше первого куска заголовков
        assert!(r.taken <= crate::http::READ_CHUNK, "взято {}", r.taken);

        // ровно предел проходит
        let mut ok = format!("HTTP/1.1 200 OK\r\nContent-Length: {max}\r\n\r\n").into_bytes();
        ok.extend(std::iter::repeat_n(b'a', max));
        assert!(matches!(parse(&ok, max), Ok(Response::Body(b)) if b.len() == max));

        // без длины: читается не больше предела + 1 байт и отказ
        let mut chunkless = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        let head_len = chunkless.len();
        chunkless.extend(std::iter::repeat_n(b'a', max * 4));
        let mut r = Counting {
            data: &chunkless,
            taken: 0,
        };
        assert_eq!(read_response(&mut r, max), Err(CheckError::BadResponse));
        assert!(
            r.taken <= head_len + max + 1 + crate::http::READ_CHUNK,
            "взято {}",
            r.taken
        );
    }
}

#[test]
fn error_display_fixed() {
    let all = [
        (
            CheckError::NoTrustedKeys,
            "ключи владельца не вшиты: проверка невозможна",
        ),
        (CheckError::Network, "нет связи с GitHub"),
        (CheckError::Timeout, "время ожидания ответа вышло"),
        (CheckError::BadResponse, "ответ не прошёл проверку"),
        (CheckError::BadSignature, "подпись ответа неверна"),
    ];
    for (e, text) in all {
        assert_eq!(e.to_string(), text);
        // Debug без данных: только имя варианта
        assert!(format!("{e:?}").chars().all(|c| c.is_ascii_alphabetic()));
    }
}
