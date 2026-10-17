use super::target;
use crate::desc::{ServiceKind, Udn, parse_description};
use crate::error::{DescError, ScanError, UrlError};

const IGD1: &str = "urn:schemas-upnp-org:device:InternetGatewayDevice:1";
const IP1: &str = "urn:schemas-upnp-org:service:WANIPConnection:1";
const IP2: &str = "urn:schemas-upnp-org:service:WANIPConnection:2";
const PPP1: &str = "urn:schemas-upnp-org:service:WANPPPConnection:1";

fn svc(kind: &str, ctl: &str) -> String {
    format!(
        "<service><serviceType>{kind}</serviceType><serviceId>urn:upnp-org:serviceId:x</serviceId>\
         <controlURL>{ctl}</controlURL><SCPDURL>/scpd.xml</SCPDURL></service>"
    )
}

/// Типичное описание: IGD с вложенными WANDevice и WANConnectionDevice.
fn doc_with(urlbase: &str, device_type: &str, udn_xml: &str, services: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?><root xmlns=\"urn:schemas-upnp-org:device-1-0\">\
         <specVersion><major>1</major><minor>0</minor></specVersion>{urlbase}\
         <device><deviceType>{device_type}</deviceType><friendlyName>Router</friendlyName>{udn_xml}\
         <serviceList>{l3}</serviceList>\
         <deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>\
         <UDN>uuid:wan-1</UDN><deviceList><device>\
         <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>\
         <UDN>uuid:conn-1</UDN><serviceList>{services}</serviceList>\
         </device></deviceList></device></deviceList></device></root>",
        l3 = svc("urn:schemas-upnp-org:service:Layer3Forwarding:1", "/l3f"),
    )
}

fn doc(services: &str) -> String {
    doc_with("", IGD1, "<UDN>uuid:abc-123</UDN>", services)
}

fn parse(s: &str) -> Result<crate::desc::Description, DescError> {
    parse_description(s.as_bytes(), &target())
}

#[test]
fn desc_extracts_wanip1() {
    let d = parse(&doc(&svc(IP1, "/ctl/IPConn"))).unwrap();
    assert_eq!(d.udn.as_str(), "uuid:abc-123");
    assert_eq!(d.services.len(), 1);
    assert_eq!(d.services[0].kind, ServiceKind::WanIp1);
    assert_eq!(d.services[0].control.as_str(), "/ctl/IPConn");
    // IGD версии 2, относительный и полный controlURL, URLBase того же хоста
    let xml = doc_with(
        "<URLBase>http://192.168.1.1:5000/</URLBase>",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
        "<UDN>uuid:abc-123</UDN>",
        &(svc(IP1, "ctl/rel") + &svc(PPP1, "http://192.168.1.1:5000/ctl/full")),
    );
    let d = parse(&xml).unwrap();
    assert_eq!(d.services[0].control.as_str(), "/ctl/rel");
    assert_eq!(d.services[1].control.as_str(), "/ctl/full");
    // BOM допустим
    let mut bytes = vec![0xEF, 0xBB, 0xBF];
    bytes.extend_from_slice(doc(&svc(IP1, "/ctl")).as_bytes());
    let d = parse_description(&bytes, &target()).unwrap();
    assert_eq!(d.services[0].control.as_str(), "/ctl");
    // сущность раскрывается в значение, а знак `&` в пути запрещён
    assert_eq!(
        parse(&doc(&svc(IP1, "/a&amp;b"))).unwrap_err(),
        DescError::Url(UrlError::PathChar)
    );
    let d = parse(&doc(&svc(IP1, "/a&apos;b"))).unwrap();
    assert_eq!(d.services[0].control.as_str(), "/a'b");
}

#[test]
fn desc_prefers_v2_v1_ppp() {
    let xml = doc(&(svc(PPP1, "/ppp") + &svc(IP1, "/ip1") + &svc(IP2, "/ip2")));
    let d = parse(&xml).unwrap();
    let got: Vec<_> = d
        .services
        .iter()
        .map(|s| (s.kind, s.control.as_str().to_owned()))
        .collect();
    assert_eq!(
        got,
        [
            (ServiceKind::WanIp2, "/ip2".to_owned()),
            (ServiceKind::WanIp1, "/ip1".to_owned()),
            (ServiceKind::WanPpp1, "/ppp".to_owned()),
        ]
    );
    // стабильность внутри вида
    let xml = doc(&(svc(IP1, "/b") + &svc(IP1, "/a")));
    let d = parse(&xml).unwrap();
    assert_eq!(d.services[0].control.as_str(), "/b");
    assert_eq!(d.services[1].control.as_str(), "/a");
}

#[test]
fn desc_duplicate_control_url_rejected() {
    let s = format!(
        "<service><serviceType>{IP1}</serviceType><controlURL>/a</controlURL><controlURL>/b</controlURL></service>"
    );
    assert_eq!(parse(&doc(&s)).unwrap_err(), DescError::Duplicate);
    // даже в службе чужого типа
    let s = "<service><serviceType>urn:x:service:Y:1</serviceType>\
             <controlURL>/a</controlURL><controlURL>/b</controlURL></service>";
    assert_eq!(parse(&doc(s)).unwrap_err(), DescError::Duplicate);
}

#[test]
fn desc_duplicate_service_type_rejected() {
    let s = format!(
        "<service><serviceType>{IP1}</serviceType><serviceType>{IP2}</serviceType>\
         <controlURL>/a</controlURL></service>"
    );
    assert_eq!(parse(&doc(&s)).unwrap_err(), DescError::Duplicate);
}

#[test]
fn desc_duplicate_udn_rejected() {
    let xml = doc_with(
        "",
        IGD1,
        "<UDN>uuid:abc-123</UDN><UDN>uuid:other</UDN>",
        &svc(IP1, "/c"),
    );
    assert_eq!(parse(&xml).unwrap_err(), DescError::Duplicate);
    let xml = doc_with(
        "",
        IGD1,
        &format!("<deviceType>{IGD1}</deviceType><UDN>uuid:abc</UDN>"),
        &svc(IP1, "/c"),
    );
    assert_eq!(parse(&xml).unwrap_err(), DescError::Duplicate);
    // два URLBase
    let xml = doc_with(
        "<URLBase>http://192.168.1.1:5000/</URLBase><URLBase>http://192.168.1.1:5000/</URLBase>",
        IGD1,
        "<UDN>uuid:abc</UDN>",
        &svc(IP1, "/c"),
    );
    assert_eq!(parse(&xml).unwrap_err(), DescError::Duplicate);
}

#[test]
fn desc_root_not_igd_rejected() {
    let xml = doc_with(
        "",
        "urn:schemas-upnp-org:device:MediaServer:1",
        "<UDN>uuid:a</UDN>",
        &svc(IP1, "/c"),
    );
    assert_eq!(parse(&xml).unwrap_err(), DescError::NotIgd);
    let xml = doc_with(
        "",
        "urn:schemas-upnp-org:device:InternetGatewayDevice:3",
        "<UDN>uuid:a</UDN>",
        &svc(IP1, "/c"),
    );
    assert_eq!(parse(&xml).unwrap_err(), DescError::NotIgd);
    // корень не `root`
    let xml = doc(&svc(IP1, "/c"))
        .replace("<root ", "<other ")
        .replace("</root>", "</other>");
    assert_eq!(parse(&xml).unwrap_err(), DescError::NotRoot);
    // deviceType не прямой ребёнок корневого устройства
    let xml = "<root><device><x><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1\
        </deviceType></x><UDN>uuid:a</UDN></device></root>";
    assert_eq!(parse(xml).unwrap_err(), DescError::NotIgd);
    // deviceType только у вложенного устройства
    let xml = format!(
        "<root><device><UDN>uuid:a</UDN><deviceList><device><deviceType>{IGD1}</deviceType>\
         </device></deviceList></device></root>"
    );
    assert_eq!(parse(&xml).unwrap_err(), DescError::NotIgd);
    // нет устройства вообще
    assert_eq!(parse("<root/>").unwrap_err(), DescError::NotIgd);
    // URLBase другого хоста
    let xml = doc_with(
        "<URLBase>http://192.168.1.2:5000/</URLBase>",
        IGD1,
        "<UDN>uuid:a</UDN>",
        &svc(IP1, "/c"),
    );
    assert_eq!(
        parse(&xml).unwrap_err(),
        DescError::Url(UrlError::HostMismatch)
    );
    // бомба и DTD
    let xml = format!(
        "<!DOCTYPE root [<!ENTITY a \"b\">]>{}",
        doc(&svc(IP1, "/c"))
    );
    assert_eq!(parse(&xml).unwrap_err(), DescError::Scan(ScanError::Markup));
}

#[test]
fn desc_no_service() {
    // только чужие службы
    assert_eq!(parse(&doc("")).unwrap_err(), DescError::NoService);
    let s = svc(
        "urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1",
        "/c",
    );
    assert_eq!(parse(&doc(&s)).unwrap_err(), DescError::NoService);
    // чужой тип с негодным controlURL не мешает
    let s = svc("urn:x:service:Y:1", "http://1.2.3.4/x") + &svc(IP1, "/c");
    assert_eq!(parse(&doc(&s)).unwrap().services.len(), 1);
    // нужный тип без controlURL или с негодным: документ отвергнут
    let s = format!("<service><serviceType>{IP1}</serviceType></service>");
    assert_eq!(parse(&doc(&s)).unwrap_err(), DescError::MissingControl);
    let s = svc(IP1, "http://192.168.1.2:5000/c");
    assert_eq!(
        parse(&doc(&s)).unwrap_err(),
        DescError::Url(UrlError::HostMismatch)
    );
    let s = svc(IP1, "/a/../b");
    assert_eq!(
        parse(&doc(&s)).unwrap_err(),
        DescError::Url(UrlError::DotSegment)
    );
    let s = svc(IP1, "");
    assert_eq!(
        parse(&doc(&s)).unwrap_err(),
        DescError::Url(UrlError::Empty)
    );
    // вложенный service
    let s = format!(
        "<service><serviceType>{IP1}</serviceType><controlURL>/a</controlURL>\
         <service><serviceType>{IP1}</serviceType></service></service>"
    );
    assert_eq!(parse(&doc(&s)).unwrap_err(), DescError::Malformed);
    // сложное содержимое у serviceType
    let s = "<service><serviceType><b/></serviceType><controlURL>/a</controlURL></service>";
    assert_eq!(parse(&doc(s)).unwrap_err(), DescError::Malformed);
}

#[test]
fn desc_udn_rules() {
    for ok in [
        "uuid:a",
        "uuid:12345678-90ab-cdef-1234-567890abcdef",
        "uuid:A.b_c:d-e",
    ] {
        assert_eq!(Udn::parse(ok).unwrap().as_str(), ok);
    }
    let long_ok = format!("uuid:{}", "a".repeat(128 - 5));
    let long_bad = format!("uuid:{}", "a".repeat(128 - 4));
    Udn::parse(&long_ok).unwrap();
    assert_eq!(Udn::parse(&long_bad).unwrap_err(), DescError::BadUdn);
    for bad in [
        "", "uuid:", "abc", "UUID:abc", "uuid:a b", "uuid:é", "uuid:a/b", "uuid:a<b", " uuid:a",
    ] {
        assert_eq!(Udn::parse(bad).unwrap_err(), DescError::BadUdn, "{bad:?}");
    }
    // в документе
    let xml = doc_with("", IGD1, "", &svc(IP1, "/c"));
    assert_eq!(parse(&xml).unwrap_err(), DescError::MissingUdn);
    let xml = doc_with("", IGD1, "<UDN>abc</UDN>", &svc(IP1, "/c"));
    assert_eq!(parse(&xml).unwrap_err(), DescError::BadUdn);
    let xml = doc_with("", IGD1, "<UDN>uuid:a&amp;b</UDN>", &svc(IP1, "/c"));
    assert_eq!(parse(&xml).unwrap_err(), DescError::BadUdn);
    // UDN только у вложенного устройства не считается
    let xml = doc_with("", IGD1, "", &svc(IP1, "/c"));
    assert_eq!(parse(&xml).unwrap_err(), DescError::MissingUdn);
    // пробелы вокруг значения обрезаются
    let xml = doc_with("", IGD1, "<UDN> uuid:a \n</UDN>", &svc(IP1, "/c"));
    assert_eq!(parse(&xml).unwrap().udn.as_str(), "uuid:a");
}

#[test]
fn desc_max_services() {
    let mut s = String::new();
    for i in 0..6 {
        s += &svc(IP1, &format!("/c{i}"));
    }
    let d = parse(&doc(&s)).unwrap();
    assert_eq!(d.services.len(), 4);
    assert_eq!(d.services[3].control.as_str(), "/c3");
    // повторы (вид, путь) схлопываются
    let s = svc(IP1, "/same") + &svc(IP1, "/other") + &svc(IP1, "/same") + &svc(PPP1, "/same");
    let d = parse(&doc(&s)).unwrap();
    let got: Vec<_> = d
        .services
        .iter()
        .map(|x| (x.kind, x.control.as_str().to_owned()))
        .collect();
    assert_eq!(
        got,
        [
            (ServiceKind::WanIp1, "/same".to_owned()),
            (ServiceKind::WanIp1, "/other".to_owned()),
            (ServiceKind::WanPpp1, "/same".to_owned()),
        ]
    );
}
