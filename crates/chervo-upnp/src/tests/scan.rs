use crate::error::ScanError;
use crate::limits::{BODY_MAX, XML_MAX_DEPTH, XML_MAX_ELEMENTS, XML_NAME_MAX};
use crate::scan::{Event, Leaf, Node, scan, value, walk};

/// События в виде строк; при ошибке второй элемент содержит события до неё.
fn run(body: &[u8]) -> (Result<(), ScanError>, Vec<String>) {
    let mut out = Vec::new();
    let r = scan(body, |e| {
        out.push(match e {
            Event::Start { name } => format!("S:{name}"),
            Event::End { name } => format!("E:{name}"),
            Event::Text { raw } => format!("T:{}", String::from_utf8_lossy(raw)),
        });
        Ok::<(), ScanError>(())
    });
    (r, out)
}

fn ok(body: &[u8]) -> Vec<String> {
    let (r, ev) = run(body);
    assert_eq!(r, Ok(()), "{}", String::from_utf8_lossy(body));
    ev
}

fn err(body: &[u8]) -> ScanError {
    run(body).0.unwrap_err()
}

#[test]
fn scan_rejects_doctype() {
    assert_eq!(err(b"<!DOCTYPE a><a/>"), ScanError::Markup);
    assert_eq!(
        err(b"<?xml version=\"1.0\"?><!DOCTYPE a [<!ENTITY x \"y\">]><a>&x;</a>"),
        ScanError::Markup
    );
    // отказ до первого события: ни одного события не выдано
    let (r, ev) = run(b"<a>x</a><!DOCTYPE a>");
    assert_eq!(r, Err(ScanError::Markup));
    assert!(ev.is_empty());
}

/// Параметрическая бомба вида ревью 8 (п. 1). Точные 547 байт того образца в репозитории не
/// сохранены; здесь тот же приём: цепочка параметрических сущностей, каждая в 10 раз длиннее.
const BOMB: &str = concat!(
    "<?xml version=\"1.0\"?>\n<!DOCTYPE root [\n",
    "<!ENTITY % a \"AAAAAAAAAA\">\n",
    "<!ENTITY % b \"%a;%a;%a;%a;%a;%a;%a;%a;%a;%a;\">\n",
    "<!ENTITY % c \"%b;%b;%b;%b;%b;%b;%b;%b;%b;%b;\">\n",
    "<!ENTITY % d \"%c;%c;%c;%c;%c;%c;%c;%c;%c;%c;\">\n",
    "<!ENTITY % e \"%d;%d;%d;%d;%d;%d;%d;%d;%d;%d;\">\n",
    "<!ENTITY % f \"%e;%e;%e;%e;%e;%e;%e;%e;%e;%e;\">\n",
    "<!ENTITY % g \"%f;%f;%f;%f;%f;%f;%f;%f;%f;%f;\">\n",
    "<!ENTITY % h \"%g;%g;%g;%g;%g;%g;%g;%g;%g;%g;\">\n",
    "<!ENTITY % i \"%h;%h;%h;%h;%h;%h;%h;%h;%h;%h;\">\n",
    "%i;\n]>\n<root/>\n"
);

#[test]
fn scan_rejects_review8_bomb() {
    assert!(BOMB.len() > 400 && BOMB.len() < 700);
    let (r, ev) = run(BOMB.as_bytes());
    assert_eq!(r, Err(ScanError::Markup));
    assert!(ev.is_empty());
}

#[test]
fn scan_rejects_billion_laughs() {
    let laughs = "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\">\
        <!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\
        <!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">]>\
        <lolz>&lol3;</lolz>";
    assert_eq!(err(laughs.as_bytes()), ScanError::Markup);
    // без DTD ссылка на сущность не раскрывается: неизвестная сущность
    assert_eq!(err(b"<lolz>&lol3;</lolz>"), ScanError::Entity);
}

#[test]
fn scan_rejects_comment_cdata() {
    assert_eq!(err(b"<a><!-- x --></a>"), ScanError::Markup);
    assert_eq!(err(b"<a><![CDATA[x]]></a>"), ScanError::Markup);
    assert_eq!(err(b"<a b=\"<!--\"/>"), ScanError::Markup);
    assert_eq!(err(b"<!-- c --><a/>"), ScanError::Markup);
}

#[test]
fn scan_rejects_pi_not_first() {
    assert_eq!(err(b"<a><?pi x?></a>"), ScanError::Markup);
    assert_eq!(err(b"<a/><?pi x?>"), ScanError::Markup);
    assert_eq!(err(b"<?pi x?><a/>"), ScanError::Markup);
    assert_eq!(
        err(b"<?xml version=\"1.0\"?><?xml version=\"1.0\"?><a/>"),
        ScanError::Markup
    );
    assert_eq!(err(b"<a/><?xml version=\"1.0\"?>"), ScanError::Markup);
    // объявление после пробелов допустимо
    ok(b" \n<?xml version=\"1.0\"?>\n<a/>");
}

#[test]
fn scan_xml_decl_rules() {
    ok(b"<?xml version=\"1.0\"?><a/>");
    ok(b"<?xml version=\"1.0\" encoding=\"utf-8\"?><a/>");
    // не закрыто
    assert_eq!(err(b"<?xml version=\"1.0\"<a/>"), ScanError::Markup);
    // запрещённые знаки внутри
    assert_eq!(err(b"<?xml version=\"1.0\" [?><a/>"), ScanError::Markup);
    assert_eq!(err(b"<?xml version=\"&amp;\"?><a/>"), ScanError::Markup);
    assert_eq!(err(b"<?xml version=\"%x\"?><a/>"), ScanError::Markup);
    assert_eq!(err(b"<?xml version=\"1.0\" <?><a/>"), ScanError::Markup);
    // слишком длинное: 128 байт целиком допустимо, 129 нет
    let make = |total: usize| {
        let pad = total - "<?xml ?>".len();
        let mut v = b"<?xml ".to_vec();
        v.extend(std::iter::repeat_n(b'a', pad));
        v.extend_from_slice(b"?><a/>");
        v
    };
    ok(&make(128));
    assert_eq!(err(&make(129)), ScanError::Markup);
    // не объявление xml
    assert_eq!(err(b"<?xmlfoo?><a/>"), ScanError::Markup);
    assert_eq!(err(b"<?xml?><a/>"), ScanError::Markup);
    // не ASCII внутри
    assert_eq!(
        err("<?xml version=\"1.0\" x=\"é\"?><a/>".as_bytes()),
        ScanError::Markup
    );
}

#[test]
fn scan_rejects_unknown_entity_and_char_ref() {
    assert_eq!(err(b"<a>&foo;</a>"), ScanError::Entity);
    assert_eq!(err(b"<a>&#65;</a>"), ScanError::Entity);
    assert_eq!(err(b"<a>&#x41;</a>"), ScanError::Entity);
    assert_eq!(err(b"<a>a & b</a>"), ScanError::Entity);
    assert_eq!(err(b"<a>&amp</a>"), ScanError::Entity);
    assert_eq!(err(b"<a>&AMP;</a>"), ScanError::Entity);
    assert_eq!(err(b"<a b=\"&x;\"/>"), ScanError::Entity);
    assert_eq!(err(b"<a b='&#1;'/>"), ScanError::Entity);
    // сущность вне кавычек в теге
    assert_eq!(err(b"<a &amp; />"), ScanError::Entity);
    // вне корня
    assert_eq!(err(b"&amp;<a/>"), ScanError::Syntax);
}

#[test]
fn scan_decodes_five_entities() {
    assert_eq!(value(b"&amp;&lt;&gt;&quot;&apos;").unwrap(), "&<>\"'");
    assert_eq!(value(b"  a &amp; b \r\n").unwrap(), "a & b");
    // в событии текст остаётся сырым, но проверенным
    let ev = ok(b"<a>x&lt;y</a>");
    assert_eq!(ev, ["S:a", "T:x&lt;y", "E:a"]);
    assert_eq!(value(b"&#65;").unwrap_err(), ScanError::Entity);
    assert_eq!(value(b"&foo;").unwrap_err(), ScanError::Entity);
    ok(b"<a b=\"&amp;&lt;&gt;&quot;&apos;\"/>");
}

fn nested(n: usize) -> Vec<u8> {
    let mut v = Vec::new();
    for _ in 0..n {
        v.extend_from_slice(b"<a>");
    }
    for _ in 0..n {
        v.extend_from_slice(b"</a>");
    }
    v
}

#[test]
fn scan_depth_limit() {
    assert_eq!(XML_MAX_DEPTH, 16);
    ok(&nested(16));
    assert_eq!(err(&nested(17)), ScanError::Depth);
    // самозакрывающийся элемент на глубине 17 тоже отвергается
    let mut v = Vec::new();
    for _ in 0..16 {
        v.extend_from_slice(b"<a>");
    }
    v.extend_from_slice(b"<b/>");
    for _ in 0..16 {
        v.extend_from_slice(b"</a>");
    }
    assert_eq!(err(&v), ScanError::Depth);
}

#[test]
fn scan_element_limit() {
    let make = |children: usize| {
        let mut v = b"<r>".to_vec();
        for _ in 0..children {
            v.extend_from_slice(b"<a/>");
        }
        v.extend_from_slice(b"</r>");
        v
    };
    ok(&make(XML_MAX_ELEMENTS - 1));
    assert_eq!(err(&make(XML_MAX_ELEMENTS)), ScanError::Elements);
}

#[test]
fn scan_mismatched_close() {
    assert_eq!(err(b"<a></b>"), ScanError::Mismatch);
    assert_eq!(err(b"<a><b></a></b>"), ScanError::Mismatch);
    assert_eq!(err(b"<s:a></t:a>"), ScanError::Mismatch);
    assert_eq!(err(b"<s:a></a>"), ScanError::Mismatch);
    assert_eq!(err(b"</a>"), ScanError::Mismatch);
    assert_eq!(err(b"<a/></a>"), ScanError::Mismatch);
    // пробел перед `>` в закрывающем теге допустим
    ok(b"<a></a >");
    assert_eq!(err(b"<a></a b>"), ScanError::Syntax);
}

#[test]
fn scan_unclosed_eof() {
    assert_eq!(err(b"<a><b>"), ScanError::Syntax);
    assert_eq!(err(b"<a"), ScanError::Syntax);
    assert_eq!(err(b"<a b=\"x"), ScanError::Syntax);
    assert_eq!(err(b"<a></a"), ScanError::Syntax);
    assert_eq!(err(b""), ScanError::Syntax);
    assert_eq!(err(b"   "), ScanError::Syntax);
    assert_eq!(err(b"text"), ScanError::Syntax);
    assert_eq!(err(b"<"), ScanError::Syntax);
    assert_eq!(err(b"<a>x"), ScanError::Syntax);
}

#[test]
fn scan_two_roots() {
    assert_eq!(err(b"<a/><b/>"), ScanError::Syntax);
    assert_eq!(err(b"<a></a><a></a>"), ScanError::Syntax);
    assert_eq!(err(b"<a/>x"), ScanError::Syntax);
    assert_eq!(err(b"x<a/>"), ScanError::Syntax);
    ok(b"<a/>\n  \r\n");
}

#[test]
fn scan_control_chars() {
    for c in [0x00u8, 0x01, 0x08, 0x0B, 0x0C, 0x0E, 0x1F, 0x7F] {
        let body = [b"<a>".as_slice(), &[c], b"</a>"].concat();
        assert_eq!(err(&body), ScanError::Control, "byte {c:#x}");
    }
    // табуляция, LF и CR допустимы
    ok(b"<a>\t\n\r</a>");
    // управляющий байт в атрибуте и вне корня
    assert_eq!(err(b"<a b=\"\x01\"/>"), ScanError::Control);
    assert_eq!(err(b"\x00<a/>"), ScanError::Control);
    // проверка по всему телу до событий
    let (r, ev) = run(b"<a>ok</a>\x01");
    assert_eq!(r, Err(ScanError::Control));
    assert!(ev.is_empty());
}

#[test]
fn scan_non_ascii_text_ok_name_rejected() {
    let ev = ok("<a>привет</a>".as_bytes());
    assert_eq!(ev.len(), 3);
    assert_eq!(err("<é/>".as_bytes()), ScanError::Syntax);
    assert_eq!(err("<aé/>".as_bytes()), ScanError::Syntax);
    assert_eq!(err("<a></aé>".as_bytes()), ScanError::Syntax);
    // в значении атрибута допустимо, вне кавычек нет
    ok("<a b=\"é\"/>".as_bytes());
    assert_eq!(err("<a é=\"1\"/>".as_bytes()), ScanError::Syntax);
    // вне корня нет
    assert_eq!(err("é<a/>".as_bytes()), ScanError::Syntax);
    // значение поля из не ASCII отвергается
    assert_eq!(value("é".as_bytes()).unwrap_err(), ScanError::Value);
}

#[test]
fn scan_attr_quotes() {
    // `>` в кавычках не закрывает тег
    assert_eq!(ok(b"<a b=\">\">x</a>"), ["S:a", "T:x", "E:a"]);
    ok(b"<a b='x\"y' c=\"p'q\"/>");
    // `<` в кавычках запрещён
    assert_eq!(err(b"<a b=\"<\"/>"), ScanError::Syntax);
    assert_eq!(err(b"<a b='<'/>"), ScanError::Syntax);
    // незакрытая кавычка
    assert_eq!(err(b"<a b=\"x>"), ScanError::Syntax);
    // `<` вне кавычек
    assert_eq!(err(b"<a <b/>"), ScanError::Syntax);
    // `/` не перед `>`
    assert_eq!(err(b"<a / >"), ScanError::Syntax);
    assert_eq!(err(b"<a b=\"x\"/ >"), ScanError::Syntax);
    ok(b"<a b=\"x\" />");
    // сразу после имени допустимы только пробел, `>` и `/`
    assert_eq!(err(b"<a\"x\">"), ScanError::Syntax);
    assert_eq!(err(b"<a=b/>"), ScanError::Syntax);
}

#[test]
fn scan_name_too_long() {
    let name = |n: usize| "a".repeat(n);
    let doc = |n: usize| format!("<{0}></{0}>", name(n));
    ok(doc(XML_NAME_MAX).as_bytes());
    assert_eq!(
        err(doc(XML_NAME_MAX + 1).as_bytes()),
        ScanError::NameTooLong
    );
    assert_eq!(
        err(format!("<a></{}>", name(XML_NAME_MAX + 1)).as_bytes()),
        ScanError::NameTooLong
    );
    // имя с цифры, пустое локальное имя
    assert_eq!(err(b"<1a/>"), ScanError::Syntax);
    assert_eq!(err(b"<a:/>"), ScanError::Syntax);
    assert_eq!(err(b"<a:1/>"), ScanError::Syntax);
    // локальное имя после последнего двоеточия
    assert_eq!(ok(b"<s:Envelope/>"), ["S:Envelope", "E:Envelope"]);
}

#[test]
fn scan_bom_ok() {
    let mut v = vec![0xEF, 0xBB, 0xBF];
    v.extend_from_slice(b"<?xml version=\"1.0\"?><a/>");
    ok(&v);
    // BOM не в начале
    let mut w = b" ".to_vec();
    w.extend_from_slice(&v);
    assert_eq!(err(&w), ScanError::Syntax);
    // два BOM
    let mut x = vec![0xEF, 0xBB, 0xBF];
    x.extend_from_slice(&v);
    assert_eq!(err(&x), ScanError::Syntax);
}

#[test]
fn scan_body_size_limit() {
    let make = |n: usize| {
        let mut v = b"<a>".to_vec();
        v.extend(std::iter::repeat_n(b'x', n - "<a></a>".len()));
        v.extend_from_slice(b"</a>");
        v
    };
    ok(&make(BODY_MAX));
    assert_eq!(err(&make(BODY_MAX + 1)), ScanError::TooLarge);
}

#[test]
fn scan_walk_leaves() {
    let mut log = Vec::new();
    walk(b"<r><a>x</a><b/><c><d/></c><e> </e></r>", |n| {
        if let Node::Close { path, leaf } = n {
            log.push((path.join("/"), leaf));
        }
        Ok::<(), ScanError>(())
    })
    .unwrap();
    assert_eq!(
        log,
        [
            ("r/a".to_owned(), Leaf::Text(b"x")),
            ("r/b".to_owned(), Leaf::Empty),
            ("r/c/d".to_owned(), Leaf::Empty),
            ("r/c".to_owned(), Leaf::Branch),
            ("r/e".to_owned(), Leaf::Text(b" ")),
            ("r".to_owned(), Leaf::Branch),
        ]
    );
}
