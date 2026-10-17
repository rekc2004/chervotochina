use std::net::SocketAddrV4;

use super::ip;
use crate::desc::ServiceKind;
use crate::error::{ScanError, SoapError};
use crate::scan::value;
use crate::soap::{Action, Fault, parse_add_any, parse_external_ip, parse_fault, parse_specific};
use crate::url::parse_ipv4;

const KINDS: [ServiceKind; 3] = [
    ServiceKind::WanIp2,
    ServiceKind::WanIp1,
    ServiceKind::WanPpp1,
];

fn internal() -> SocketAddrV4 {
    SocketAddrV4::new(ip(192, 168, 1, 10), 4455)
}

/// Ожидаемый конверт, собранный независимо от кода шаблона.
fn envelope(action: &str, urn: &str, args: &str) -> String {
    let mut s = String::new();
    s += "<?xml version=\"1.0\"?>";
    s += "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" ";
    s += "s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">";
    s += "<s:Body>";
    s += &format!("<u:{action} xmlns:u=\"{urn}\">{args}</u:{action}>");
    s += "</s:Body></s:Envelope>";
    s
}

#[test]
fn soap_templates_golden() {
    // полный литерал для одного вида
    assert_eq!(
        Action::GetExternalIp.body(ServiceKind::WanIp1),
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:GetExternalIPAddress xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"></u:GetExternalIPAddress></s:Body></s:Envelope>"
    );
    assert_eq!(
        Action::Add {
            ext: 4455,
            internal: internal(),
            lease: 3600
        }
        .body(ServiceKind::WanIp2),
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:2\"><NewRemoteHost></NewRemoteHost><NewExternalPort>4455</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>4455</NewInternalPort><NewInternalClient>192.168.1.10</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>udp</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>"
    );
    // пять действий на три вида службы
    let key = |e: u16| {
        format!(
            "<NewRemoteHost></NewRemoteHost><NewExternalPort>{e}</NewExternalPort><NewProtocol>UDP</NewProtocol>"
        )
    };
    let full = |e: u16, p: u16, l: u32| {
        format!(
            "{}<NewInternalPort>{p}</NewInternalPort><NewInternalClient>192.168.1.10</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>udp</NewPortMappingDescription><NewLeaseDuration>{l}</NewLeaseDuration>",
            key(e)
        )
    };
    let cases: [(Action, &str, String); 5] = [
        (Action::GetExternalIp, "GetExternalIPAddress", String::new()),
        (
            Action::Add {
                ext: 50000,
                internal: internal(),
                lease: 0,
            },
            "AddPortMapping",
            full(50000, 4455, 0),
        ),
        (
            Action::AddAny {
                ext: 4455,
                internal: internal(),
                lease: 3600,
            },
            "AddAnyPortMapping",
            full(4455, 4455, 3600),
        ),
        (
            Action::GetSpecific { ext: 4455 },
            "GetSpecificPortMappingEntry",
            key(4455),
        ),
        (Action::Delete { ext: 1 }, "DeletePortMapping", key(1)),
    ];
    let mut seen = 0;
    for kind in KINDS {
        for (action, name, args) in &cases {
            assert_eq!(action.name(), *name);
            assert_eq!(action.body(kind), envelope(name, kind.urn(), args));
            seen += 1;
        }
    }
    assert_eq!(seen, 15);
    // нет пробелов между тегами
    assert!(
        !Action::GetExternalIp
            .body(ServiceKind::WanIp1)
            .contains("> <")
    );
}

fn resp(action: &str, fields: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action}Response xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">{fields}</u:{action}Response></s:Body></s:Envelope>"
    )
}

fn ext_ip(fields: &str) -> Result<Option<std::net::Ipv4Addr>, SoapError> {
    parse_external_ip(resp("GetExternalIPAddress", fields).as_bytes())
}

#[test]
fn soap_parse_external_ip() {
    let f = |v: &str| format!("<NewExternalIPAddress>{v}</NewExternalIPAddress>");
    assert_eq!(ext_ip(&f("203.0.113.7")).unwrap(), Some(ip(203, 0, 113, 7)));
    assert_eq!(ext_ip(&f("  10.0.0.1\r\n")).unwrap(), Some(ip(10, 0, 0, 1)));
    // пусто: роутер за CGNAT
    assert_eq!(ext_ip(&f("")).unwrap(), None);
    assert_eq!(ext_ip("<NewExternalIPAddress/>").unwrap(), None);
    assert_eq!(ext_ip(&f("   ")).unwrap(), None);
    // лишние дети игнорируются
    let extra = format!("<Other>x</Other>{}<Third><a/></Third>", f("1.2.3.4"));
    assert_eq!(ext_ip(&extra).unwrap(), Some(ip(1, 2, 3, 4)));
    // нет поля, неверный формат
    assert_eq!(ext_ip("").unwrap_err(), SoapError::Missing);
    assert_eq!(ext_ip(&f("1.2.3")).unwrap_err(), SoapError::BadValue);
    assert_eq!(ext_ip(&f("01.2.3.4")).unwrap_err(), SoapError::BadValue);
    assert_eq!(ext_ip(&f("256.1.1.1")).unwrap_err(), SoapError::BadValue);
    assert_eq!(ext_ip(&f("example.com")).unwrap_err(), SoapError::BadValue);
    assert_eq!(ext_ip(&f("1.2.3.4 5")).unwrap_err(), SoapError::BadValue);
    // поле не лист
    assert_eq!(
        ext_ip("<NewExternalIPAddress><a/></NewExternalIPAddress>").unwrap_err(),
        SoapError::Malformed
    );
    // не ASCII и сущность-ссылка на символ
    assert_eq!(
        ext_ip(&f("é")).unwrap_err(),
        SoapError::Scan(ScanError::Value)
    );
    assert_eq!(
        ext_ip(&f("&#49;.2.3.4")).unwrap_err(),
        SoapError::Scan(ScanError::Entity)
    );
}

fn spec_fields(port: &str, client: &str, enabled: &str, desc: &str, lease: &str) -> String {
    format!(
        "<NewInternalPort>{port}</NewInternalPort><NewInternalClient>{client}</NewInternalClient><NewEnabled>{enabled}</NewEnabled><NewPortMappingDescription>{desc}</NewPortMappingDescription><NewLeaseDuration>{lease}</NewLeaseDuration>"
    )
}

fn specific(fields: &str) -> Result<crate::soap::Entry, SoapError> {
    parse_specific(resp("GetSpecificPortMappingEntry", fields).as_bytes())
}

#[test]
fn soap_parse_specific_entry() {
    let e = specific(&spec_fields("4455", "192.168.1.10", "1", "udp", "3600")).unwrap();
    assert_eq!(e.internal_port, 4455);
    assert_eq!(e.internal_client, ip(192, 168, 1, 10));
    assert!(e.enabled);
    assert!(e.description_is_ours);
    assert_eq!(e.lease, 3600);
    // регистр `Enabled`, нулевая аренда и верхняя граница
    for (v, want) in [
        ("true", true),
        ("TRUE", true),
        ("False", false),
        ("0", false),
    ] {
        let e = specific(&spec_fields("1", "10.0.0.2", v, "udp", "0")).unwrap();
        assert_eq!(e.enabled, want, "{v}");
        assert_eq!(e.lease, 0);
    }
    let e = specific(&spec_fields("65535", "10.0.0.2", "1", "udp", "604800")).unwrap();
    assert_eq!(e.lease, 604_800);
    // описание не наше: другой регистр, пусто, чужое, не ASCII, слишком длинное
    for d in [
        "UDP",
        "",
        "chervo",
        "ud",
        "udpp",
        "привет",
        &"a".repeat(300),
    ] {
        let e = specific(&spec_fields("4455", "192.168.1.10", "1", d, "3600")).unwrap();
        assert!(!e.description_is_ours, "{d:?}");
    }
    // пробелы вокруг значения обрезаются, как у всех полей
    let e = specific(&spec_fields("4455", "192.168.1.10", "1", " udp ", "3600")).unwrap();
    assert!(e.description_is_ours);
    // описание с сущностью: `u&amp;dp` это `u&dp`, не наше
    let e = specific(&spec_fields(
        "4455",
        "192.168.1.10",
        "1",
        "u&amp;dp",
        "3600",
    ))
    .unwrap();
    assert!(!e.description_is_ours);

    let bad = |f: String, want: SoapError| assert_eq!(specific(&f).unwrap_err(), want);
    bad(
        spec_fields("0", "10.0.0.2", "1", "udp", "1"),
        SoapError::BadValue,
    );
    bad(
        spec_fields("65536", "10.0.0.2", "1", "udp", "1"),
        SoapError::BadValue,
    );
    bad(
        spec_fields("x", "10.0.0.2", "1", "udp", "1"),
        SoapError::BadValue,
    );
    bad(
        spec_fields("1", "host", "1", "udp", "1"),
        SoapError::BadValue,
    );
    bad(
        spec_fields("1", "10.0.0.2", "yes", "udp", "1"),
        SoapError::BadValue,
    );
    bad(
        spec_fields("1", "10.0.0.2", "1", "udp", "604801"),
        SoapError::BadValue,
    );
    bad(
        spec_fields("1", "10.0.0.2", "1", "udp", "-1"),
        SoapError::BadValue,
    );
    bad(
        spec_fields("1", "10.0.0.2", "1", "udp", ""),
        SoapError::BadValue,
    );
    // любое из пяти полей отсутствует
    for skip in [
        "NewInternalPort",
        "NewInternalClient",
        "NewEnabled",
        "NewPortMappingDescription",
        "NewLeaseDuration",
    ] {
        let all = spec_fields("1", "10.0.0.2", "1", "udp", "1");
        let open = format!("<{skip}>");
        let close = format!("</{skip}>");
        let start = all.find(&open).unwrap();
        let end = all.find(&close).unwrap() + close.len();
        let cut = format!("{}{}", &all[..start], &all[end..]);
        assert_eq!(specific(&cut).unwrap_err(), SoapError::Missing, "{skip}");
    }
}

fn fault(code_xml: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail><UPnPError xmlns=\"urn:schemas-upnp-org:control-1-0\">{code_xml}<errorDescription>text</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>"
    )
}

#[test]
fn soap_fault_code() {
    let f = |c: &str| parse_fault(fault(&format!("<errorCode>{c}</errorCode>")).as_bytes());
    assert_eq!(f("718"), Fault::Upnp(718));
    assert_eq!(f(" 725 "), Fault::Upnp(725));
    assert_eq!(f("0718"), Fault::Upnp(718));
    assert_eq!(f("5"), Fault::Upnp(5));
    assert_eq!(f("9999"), Fault::Upnp(9999));
    // 0 цифр, 5 цифр, не цифры, знак
    for bad in ["", "12345", "abc", "-1", "+7", "7 1", "7.0"] {
        assert_eq!(f(bad), Fault::NoCode, "{bad:?}");
    }
}

#[test]
fn soap_fault_without_code() {
    assert_eq!(parse_fault(fault("").as_bytes()), Fault::NoCode);
    // два кода
    let two = fault("<errorCode>718</errorCode><errorCode>718</errorCode>");
    assert_eq!(parse_fault(two.as_bytes()), Fault::NoCode);
    // код не по тому пути
    let wrong = "<s:Envelope><s:Body><errorCode>718</errorCode></s:Body></s:Envelope>";
    assert_eq!(parse_fault(wrong.as_bytes()), Fault::NoCode);
    // мусор, DTD, обрыв
    assert_eq!(parse_fault(b"not xml"), Fault::NoCode);
    assert_eq!(parse_fault(b""), Fault::NoCode);
    let dtd = format!("<!DOCTYPE a>{}", fault("<errorCode>718</errorCode>"));
    assert_eq!(parse_fault(dtd.as_bytes()), Fault::NoCode);
    let cut = fault("<errorCode>718</errorCode>");
    assert_eq!(parse_fault(&cut.as_bytes()[..cut.len() - 5]), Fault::NoCode);
    // код-ветка
    assert_eq!(
        parse_fault(fault("<errorCode><a/></errorCode>").as_bytes()),
        Fault::NoCode
    );
}

#[test]
fn soap_duplicate_field_rejected() {
    let f = "<NewExternalIPAddress>1.2.3.4</NewExternalIPAddress><NewExternalIPAddress>1.2.3.4</NewExternalIPAddress>";
    assert_eq!(ext_ip(f).unwrap_err(), SoapError::Duplicate);
    let mut s = spec_fields("1", "10.0.0.2", "1", "udp", "1");
    s += "<NewInternalPort>2</NewInternalPort>";
    assert_eq!(specific(&s).unwrap_err(), SoapError::Duplicate);
    let two = "<NewReservedPort>5</NewReservedPort><NewReservedPort>5</NewReservedPort>";
    let r = parse_add_any(resp("AddAnyPortMapping", two).as_bytes());
    assert_eq!(r.unwrap_err(), SoapError::Duplicate);
    let one = parse_add_any(
        resp(
            "AddAnyPortMapping",
            "<NewReservedPort>50001</NewReservedPort>",
        )
        .as_bytes(),
    );
    assert_eq!(one.unwrap(), 50001);
    for bad in ["0", "65536", "x", ""] {
        let f = format!("<NewReservedPort>{bad}</NewReservedPort>");
        let r = parse_add_any(resp("AddAnyPortMapping", &f).as_bytes());
        assert_eq!(r.unwrap_err(), SoapError::BadValue, "{bad:?}");
    }
}

#[test]
fn soap_wrong_response_element_rejected() {
    let f = "<NewExternalIPAddress>1.2.3.4</NewExternalIPAddress>";
    // ответ на другое действие
    let other = resp("GetSpecificPortMappingEntry", f);
    assert_eq!(
        parse_external_ip(other.as_bytes()).unwrap_err(),
        SoapError::NoResponse
    );
    // элемент ответа дважды
    let two = resp("GetExternalIPAddress", f).replace(
        "</s:Body>",
        &format!("<u:GetExternalIPAddressResponse>{f}</u:GetExternalIPAddressResponse></s:Body>"),
    );
    assert_eq!(
        parse_external_ip(two.as_bytes()).unwrap_err(),
        SoapError::Duplicate
    );
    // корень не Envelope
    let root = resp("GetExternalIPAddress", f).replace("s:Envelope", "s:Other");
    assert_eq!(
        parse_external_ip(root.as_bytes()).unwrap_err(),
        SoapError::WrongRoot
    );
    // ответ не под Body
    let nobody = format!(
        "<s:Envelope><u:GetExternalIPAddressResponse>{f}</u:GetExternalIPAddressResponse></s:Envelope>"
    );
    assert_eq!(
        parse_external_ip(nobody.as_bytes()).unwrap_err(),
        SoapError::NoResponse
    );
    // поле глубже, чем нужно
    let deep = resp(
        "GetExternalIPAddress",
        "<x><NewExternalIPAddress>1.2.3.4</NewExternalIPAddress></x>",
    );
    assert_eq!(
        parse_external_ip(deep.as_bytes()).unwrap_err(),
        SoapError::Missing
    );
    // другой префикс пространства имён допустим: сравниваются локальные имена
    let alt = "<a:Envelope xmlns:a=\"x\"><a:Body><b:GetExternalIPAddressResponse xmlns:b=\"y\"><NewExternalIPAddress>1.2.3.4</NewExternalIPAddress></b:GetExternalIPAddressResponse></a:Body></a:Envelope>";
    assert_eq!(
        parse_external_ip(alt.as_bytes()).unwrap(),
        Some(ip(1, 2, 3, 4))
    );
    // DTD и обрыв
    let dtd = format!("<!DOCTYPE a>{}", resp("GetExternalIPAddress", f));
    assert_eq!(
        parse_external_ip(dtd.as_bytes()).unwrap_err(),
        SoapError::Scan(ScanError::Markup)
    );
    assert_eq!(
        parse_external_ip(b"<s:Envelope><s:Body>").unwrap_err(),
        SoapError::Scan(ScanError::Syntax)
    );
}

#[test]
fn soap_value_limits() {
    let ok = "a".repeat(256);
    assert_eq!(value(ok.as_bytes()).unwrap(), ok);
    assert_eq!(
        value("a".repeat(257).as_bytes()).unwrap_err(),
        ScanError::Value
    );
    // пробелы по краям не считаются
    let padded = format!("  {ok}  ");
    assert_eq!(value(padded.as_bytes()).unwrap(), ok);
    // предел считается после раскрытия сущностей
    assert_eq!(value("&amp;".repeat(256).as_bytes()).unwrap().len(), 256);
    assert_eq!(
        value("&amp;".repeat(257).as_bytes()).unwrap_err(),
        ScanError::Value
    );
    // не ASCII, управляющие, внутренние переводы строк
    assert_eq!(value("é".as_bytes()).unwrap_err(), ScanError::Value);
    assert_eq!(value(b"a\x07b").unwrap_err(), ScanError::Value);
    assert_eq!(value(b"a\nb").unwrap_err(), ScanError::Value);
    assert_eq!(value(b"a\tb").unwrap_err(), ScanError::Value);
    assert_eq!(value(b"\x7f").unwrap_err(), ScanError::Value);
    assert_eq!(value(b"").unwrap(), "");
    assert_eq!(value(b" \r\n\t ").unwrap(), "");
    assert_eq!(value(b"~ !").unwrap(), "~ !");
}

#[test]
fn soap_ipv4_strict() {
    assert_eq!(parse_ipv4("203.0.113.7"), Some(ip(203, 0, 113, 7)));
    assert_eq!(parse_ipv4("0.0.0.0"), Some(ip(0, 0, 0, 0)));
    for bad in [
        "",
        "1.2.3",
        "1.2.3.4.5",
        "01.2.3.4",
        "256.0.0.0",
        "1.2.3.4/24",
        "1.2.3.4:80",
        "1.2.3.-1",
        "::1",
        "0x7f.0.0.1",
        "127.1",
        "1.2.3.4\n",
    ] {
        assert_eq!(parse_ipv4(bad), None, "{bad:?}");
    }
}
