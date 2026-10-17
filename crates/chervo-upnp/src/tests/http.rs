use super::target;
use crate::desc::ServiceKind;
use crate::error::HttpError;
use crate::http::{get_request, parse_response, post_request};
use crate::limits::{BODY_MAX, HTTP_HEAD_MAX, HTTP_MAX_HEADERS};

fn resp(head_lines: &str, body: &[u8]) -> Vec<u8> {
    let mut v = format!("{head_lines}\r\n\r\n").into_bytes();
    v.extend_from_slice(body);
    v
}

fn ok(buf: &[u8]) -> crate::http::Reply {
    parse_response(buf).unwrap()
}

fn err(buf: &[u8]) -> HttpError {
    parse_response(buf).unwrap_err()
}

#[test]
fn http_request_exact_bytes() {
    let t = target();
    assert_eq!(
        get_request(&t.gw, &t.path),
        b"GET /rootDesc.xml HTTP/1.0\r\nHost: 192.168.1.1:5000\r\nConnection: close\r\n\r\n"
            .to_vec()
    );
    let body = "<x/>";
    let post = post_request(
        &t.gw,
        &t.path,
        ServiceKind::WanIp1.urn(),
        "GetExternalIPAddress",
        body,
    );
    assert_eq!(
        post,
        b"POST /rootDesc.xml HTTP/1.0\r\nHost: 192.168.1.1:5000\r\nContent-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#GetExternalIPAddress\"\r\nContent-Length: 4\r\nConnection: close\r\n\r\n<x/>"
            .to_vec()
    );
}

#[test]
fn http_status_lines() {
    assert_eq!(ok(&resp("HTTP/1.0 200 OK", b"b")).body, b"b");
    assert_eq!(ok(&resp("HTTP/1.1 200 OK", b"")).status, 200);
    // без пояснения
    assert_eq!(ok(&resp("HTTP/1.1 200", b"")).status, 200);
    assert_eq!(
        ok(&resp("HTTP/1.1 500 Internal Server Error", b"f")).status,
        500
    );
    for bad in [
        "HTTP/1.1 2000 OK",
        "HTTP/1.1 20 OK",
        "HTTP/1.1  200 OK",
        "HTTP/2 200 OK",
        "HTTP/0.9 200 OK",
        "http/1.1 200 OK",
        "HTTP/1.1 099 X",
        "HTTP/1.1 600 X",
        "HTTP/1.1 2x0 X",
        "HTTP/1.1 200OK",
        "",
        "200 OK",
    ] {
        assert_eq!(err(&resp(bad, b"")), HttpError::BadStatusLine, "{bad:?}");
    }
    assert_eq!(
        err(&resp("HTTP/1.1 404 Not Found", b"")),
        HttpError::Status(404)
    );
    assert_eq!(
        err(&resp("HTTP/1.1 100 Continue", b"")),
        HttpError::Status(100)
    );
    assert_eq!(
        err(&resp("HTTP/1.1 501 Not Implemented", b"")),
        HttpError::Status(501)
    );
    // обрыв до конца заголовков
    assert_eq!(err(b"HTTP/1.1 200 OK\r\nA: b\r\n"), HttpError::Truncated);
    assert_eq!(err(b""), HttpError::Truncated);
    // одиночные CR и LF, не ASCII в заголовках
    assert_eq!(err(b"HTTP/1.1 200 OK\nA: b\r\n\r\n"), HttpError::BadHeader);
    assert_eq!(
        err(b"HTTP/1.1 200 OK\r\nA: b\nc\r\n\r\n"),
        HttpError::BadHeader
    );
    assert_eq!(
        err(b"HTTP/1.1 200 OK\r\nA: \xC3\xA9\r\n\r\n"),
        HttpError::NonAscii
    );
    assert_eq!(
        err(b"HTTP/1.1 200 OK\r\nA: b\tc\r\n\r\n"),
        HttpError::NonAscii
    );
    // тело произвольных байт допустимо
    assert_eq!(ok(&resp("HTTP/1.1 200 OK", &[0, 255, 7])).body, [0, 255, 7]);
}

#[test]
fn http_rejects_transfer_encoding() {
    for h in [
        "Transfer-Encoding: chunked",
        "transfer-encoding: identity",
        "TrAnSfEr-EnCoDiNg: ChUnKeD",
        "TRANSFER-ENCODING:",
        "Transfer-Encoding: gzip, chunked",
    ] {
        let s = format!("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n{h}");
        assert_eq!(err(&resp(&s, b"")), HttpError::Chunked, "{h}");
    }
    // и в ответе 500
    let s = "HTTP/1.1 500 X\r\nTransfer-Encoding: chunked";
    assert_eq!(err(&resp(s, b"")), HttpError::Chunked);
}

#[test]
fn http_content_length_duplicate_or_bad() {
    assert_eq!(
        ok(&resp("HTTP/1.1 200 OK\r\nContent-Length: 3", b"abc")).body,
        b"abc"
    );
    assert_eq!(
        ok(&resp("HTTP/1.1 200 OK\r\ncontent-length:  3 ", b"abc")).body,
        b"abc"
    );
    for h in [
        "Content-Length: 3\r\nContent-Length: 3",
        "Content-Length: 3\r\ncontent-length: 4",
        "Content-Length: abc",
        "Content-Length: -1",
        "Content-Length: +3",
        "Content-Length: 0x3",
        "Content-Length:",
        "Content-Length: 1 2",
        "Content-Length: 3.0",
        "Content-Length: 99999999999999999999",
        "Content-Length: 1234567",
    ] {
        let s = format!("HTTP/1.1 200 OK\r\n{h}");
        assert_eq!(err(&resp(&s, b"abc")), HttpError::BadContentLength, "{h}");
    }
    let s = format!("HTTP/1.1 200 OK\r\nContent-Length: {}", BODY_MAX + 1);
    assert_eq!(err(&resp(&s, b"")), HttpError::TooLarge);
}

#[test]
fn http_body_over_limit_with_and_without_length() {
    // без Content-Length: до EOF
    let big = vec![b'a'; BODY_MAX];
    assert_eq!(ok(&resp("HTTP/1.1 200 OK", &big)).body.len(), BODY_MAX);
    let big = vec![b'a'; BODY_MAX + 1];
    assert_eq!(err(&resp("HTTP/1.1 200 OK", &big)), HttpError::TooLarge);
    // с Content-Length
    let s = format!("HTTP/1.1 200 OK\r\nContent-Length: {BODY_MAX}");
    let body = vec![b'a'; BODY_MAX];
    assert_eq!(ok(&resp(&s, &body)).body.len(), BODY_MAX);
    let s = format!("HTTP/1.1 200 OK\r\nContent-Length: {}", BODY_MAX + 1);
    assert_eq!(
        err(&resp(&s, &vec![b'a'; BODY_MAX + 1])),
        HttpError::TooLarge
    );
    // лишние байты после Content-Length игнорируются
    let big = vec![b'a'; BODY_MAX + 10];
    let s = "HTTP/1.1 200 OK\r\nContent-Length: 5";
    assert_eq!(ok(&resp(s, &big)).body, b"aaaaa");
}

#[test]
fn http_head_over_8k() {
    // голова ровно HTTP_HEAD_MAX байт вместе с пустой строкой
    let make = |total: usize| {
        let first = "HTTP/1.1 200 OK\r\n";
        let tail = "\r\n\r\n";
        let pad = total - first.len() - "X: ".len() - tail.len();
        format!("{first}X: {}{tail}", "a".repeat(pad)).into_bytes()
    };
    let h = make(HTTP_HEAD_MAX);
    assert_eq!(h.len(), HTTP_HEAD_MAX);
    ok(&h);
    let h = make(HTTP_HEAD_MAX + 1);
    assert_eq!(err(&h), HttpError::HeadTooLarge);
    // без завершения и длиннее предела
    let mut h = b"HTTP/1.1 200 OK\r\nX: ".to_vec();
    h.extend(std::iter::repeat_n(b'a', HTTP_HEAD_MAX));
    assert_eq!(err(&h), HttpError::HeadTooLarge);
    // завершение найдено, но за пределом, большое тело ни при чём
    let mut h = make(HTTP_HEAD_MAX + 100);
    h.extend(std::iter::repeat_n(b'b', 1000));
    assert_eq!(err(&h), HttpError::HeadTooLarge);
}

#[test]
fn http_too_many_headers() {
    let make = |n: usize| {
        let mut s = String::from("HTTP/1.1 200 OK");
        for i in 0..n {
            s.push_str(&format!("\r\nX-{i}: v"));
        }
        resp(&s, b"")
    };
    ok(&make(HTTP_MAX_HEADERS));
    assert_eq!(err(&make(HTTP_MAX_HEADERS + 1)), HttpError::TooManyHeaders);
    // перенос заголовка и мусорные строки
    assert_eq!(
        err(&resp("HTTP/1.1 200 OK\r\nA: b\r\n continued", b"")),
        HttpError::ObsFold
    );
    assert_eq!(
        err(&resp("HTTP/1.1 200 OK\r\nno colon", b"")),
        HttpError::BadHeader
    );
    assert_eq!(
        err(&resp("HTTP/1.1 200 OK\r\n: v", b"")),
        HttpError::BadHeader
    );
    assert_eq!(
        err(&resp("HTTP/1.1 200 OK\r\nbad name: v", b"")),
        HttpError::BadHeader
    );
}

#[test]
fn http_redirect_is_error() {
    for code in [300, 301, 302, 303, 307, 308, 399] {
        let s = format!("HTTP/1.1 {code} Moved\r\nLocation: http://192.168.1.2/x");
        assert_eq!(err(&resp(&s, b"")), HttpError::Redirect, "{code}");
    }
}

#[test]
fn http_short_body() {
    let s = "HTTP/1.1 200 OK\r\nContent-Length: 10";
    assert_eq!(err(&resp(s, b"12345")), HttpError::ShortBody);
    assert_eq!(err(&resp(s, b"")), HttpError::ShortBody);
    assert_eq!(ok(&resp(s, b"1234567890")).body, b"1234567890");
    // Content-Length: 0 при непустых лишних байтах: тело пустое
    let s = "HTTP/1.1 200 OK\r\nContent-Length: 0";
    assert!(ok(&resp(s, b"junk")).body.is_empty());
}
