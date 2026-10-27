//! Часть U2: клиент против поддельного IGD на петле (потоки std, SSDP по unicast).
//! Настоящий multicast и TTL 1 на SYN здесь не проверяются (см. отчёт этапа).

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use chervo_addr::{GatewayInfo, MapStatus, PortMapper};

use super::fake_igd::{
    CTL, Cfg, Entry, Lab, LeaseMode, OWN, PORT, Reply, SVC_V1, SVC_V2, UDN, WAN, allow, req,
    req_for, skip, soap_ok,
};
use crate::error::HttpError;
use crate::error::{NetError, UpnpError};
use crate::http::{get_request, parse_response};
use crate::mapper::{AllowedRouter, RouterId, UpnpMapper, UpnpSettings};
use crate::net::Net;
use crate::url::parse_location;

fn wan() -> Ipv4Addr {
    WAN.parse().unwrap()
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn ours(ext: u16, lease: u32) -> Entry {
    Entry {
        ext,
        internal_port: ext,
        client: "127.0.0.1".to_owned(),
        desc: "udp".to_owned(),
        lease,
    }
}

fn with_hook(
    f: impl Fn(&super::fake_igd::Req, &mut super::fake_igd::Inner) -> Option<Reply>
    + Send
    + Sync
    + 'static,
) -> Cfg {
    Cfg {
        hook: Some(Arc::new(f)),
        ..Cfg::default()
    }
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_map_happy_path() {
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::Mapped);
    assert_eq!(rep.retry_after, secs(1800));
    assert_eq!(
        rep.gateway,
        Some(GatewayInfo {
            wan_ip: Some(wan()),
            mapping: Some(SocketAddrV4::new(wan(), PORT)),
        })
    );
    assert_eq!(lab.r().entries(), vec![ours(PORT, 3600)]);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_request_values_only_ours() {
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    assert_eq!(m.refresh(req()).status, MapStatus::Mapped);
    let adds = lab.r().requests("AddPortMapping");
    assert_eq!(adds.len(), 1);
    let a = &adds[0];
    assert_eq!(a.arg("NewInternalClient"), Some("127.0.0.1"));
    assert_eq!(a.arg("NewPortMappingDescription"), Some("udp"));
    assert_eq!(a.arg("NewRemoteHost"), Some(""));
    assert_eq!(a.arg("NewProtocol"), Some("UDP"));
    assert_eq!(a.arg("NewEnabled"), Some("1"));
    assert_eq!(a.arg("NewExternalPort"), Some(PORT.to_string().as_str()));
    assert_eq!(a.arg("NewInternalPort"), Some(PORT.to_string().as_str()));
    let lease: u32 = a.arg("NewLeaseDuration").unwrap().parse().unwrap();
    assert!(lease > 0 && lease <= 3600);
    assert!(a.head.starts_with("POST /ctl/IPConn HTTP/1.0\r\n"));
    assert!(a.head.contains(&format!("Host: {}\r\n", lab.r().addr)));
    assert!(
        a.head
            .contains(&format!("SOAPAction: \"{SVC_V1}#AddPortMapping\"\r\n"))
    );
    let all = lab.r().with(|i| i.state.log.clone());
    assert!(all.iter().filter(|r| r.is_post).all(|r| r.path == CTL));
    assert!(
        all.iter()
            .filter(|r| !r.is_post)
            .all(|r| r.path == "/desc.xml")
    );
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_tcp_bound_to_internal_ip() {
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    assert_eq!(m.refresh(req()).status, MapStatus::Mapped);
    let log = lab.r().with(|i| i.state.log.clone());
    assert!(log.len() >= 5);
    assert!(log.iter().all(|r| r.peer == OWN));
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_bomb_description_no_crash() {
    let bomb = r#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]><root>&c;</root>"#;
    let Some(lab) = Lab::new(vec![Cfg {
        description: Some(bomb.to_owned()),
        ..Cfg::default()
    }]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::NoGateway);
    assert_eq!(lab.r().soap_count(), 0);
    assert_eq!(lab.r().actions(), vec!["GET".to_owned()]);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_slowloris_deadline() {
    let Some(lab) = Lab::new(vec![with_hook(|r, _| (!r.is_post).then_some(Reply::Drip))]) else {
        skip()
    };
    let t = parse_location(&lab.r().location(), lab.r().ip).unwrap();
    let get = get_request(&t.gw, &t.path);
    // сначала сокращённый срок стенда, затем рабочие 3 с
    for net in [lab.net(), Net::production()] {
        let start = Instant::now();
        let r = net.http(&t.gw, OWN, &get, start + secs(30));
        let el = start.elapsed();
        assert_eq!(r, Err(NetError::Timeout));
        assert!(
            el >= net.http_deadline - Duration::from_millis(150),
            "{el:?}"
        );
        assert!(
            el <= net.http_deadline + Duration::from_millis(500),
            "{el:?}"
        );
    }
    // на уровне API: поиск роутера не зависает
    let m = lab.mapper(allow(UDN, false));
    let start = Instant::now();
    assert_eq!(m.identify(OWN), Err(UpnpError::NoGateway));
    assert!(start.elapsed() <= secs(3));
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_oversized_body() {
    let Some(lab) = Lab::new(vec![with_hook(|r, _| {
        (!r.is_post).then_some(Reply::BigBody(100_000))
    })]) else {
        skip()
    };
    let t = parse_location(&lab.r().location(), lab.r().ip).unwrap();
    let get = get_request(&t.gw, &t.path);
    let r = lab.net().http(&t.gw, OWN, &get, Instant::now() + secs(10));
    assert_eq!(r, Err(NetError::TooLarge));
    let m = lab.mapper(allow(UDN, false));
    assert_eq!(m.refresh(req()).status, MapStatus::NoGateway);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_huge_headers() {
    let Some(lab) = Lab::new(vec![with_hook(|r, _| {
        (!r.is_post).then_some(Reply::HugeHead)
    })]) else {
        skip()
    };
    let t = parse_location(&lab.r().location(), lab.r().ip).unwrap();
    let get = get_request(&t.gw, &t.path);
    let bytes = lab
        .net()
        .http(&t.gw, OWN, &get, Instant::now() + secs(10))
        .unwrap();
    assert!(bytes.len() > 8192);
    assert_eq!(parse_response(&bytes).unwrap_err(), HttpError::HeadTooLarge);
    let m = lab.mapper(allow(UDN, false));
    assert_eq!(m.refresh(req()).status, MapStatus::NoGateway);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_chunked_rejected() {
    let chunked =
        b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec();
    // описание в chunked: роутер не найден
    let c1 = chunked.clone();
    let Some(lab) = Lab::new(vec![with_hook(move |r, _| {
        (!r.is_post).then(|| Reply::Raw(c1.clone()))
    })]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    assert_eq!(m.refresh(req()).status, MapStatus::NoGateway);
    // ответ SOAP в chunked: сбой, проброса нет
    let c2 = chunked;
    let Some(lab) = Lab::new(vec![with_hook(move |r, _| {
        r.is_post.then(|| Reply::Raw(c2.clone()))
    })]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::Failed);
    assert!(rep.gateway.is_none());
    assert_eq!(lab.r().count("AddPortMapping"), 0);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_redirect_not_followed() {
    let Some(lab) = Lab::new(vec![
        Cfg::default(),
        Cfg {
            advertise: false,
            ..Cfg::default()
        },
    ]) else {
        skip()
    };
    let target = lab.routers[1].location();
    // 1. перенаправление описания
    let t1 = target.clone();
    lab.r().with(|i| {
        i.cfg.hook = Some(Arc::new(move |r, _| {
            (!r.is_post).then(|| Reply::Redirect(t1.clone()))
        }));
    });
    let m = lab.mapper(allow(UDN, false));
    assert_eq!(m.refresh(req()).status, MapStatus::NoGateway);
    // 2. перенаправление ответа SOAP
    lab.r().with(|i| {
        i.cfg.hook = Some(Arc::new(move |r, _| {
            r.is_post.then(|| Reply::Redirect(target.clone()))
        }));
    });
    assert_eq!(m.refresh(req()).status, MapStatus::Failed);
    thread::sleep(Duration::from_millis(150));
    assert_eq!(lab.routers[1].connections(), 0);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_wrong_location_host_no_connect() {
    let off = || Cfg {
        advertise: false,
        ..Cfg::default()
    };
    let Some(lab) = Lab::new(vec![off(), off()]) else {
        skip()
    };
    // роутер .2 заявляет адрес описания на другом хосте (.3)
    lab.ssdp
        .advertise(lab.routers[0].ip, lab.routers[1].location());
    let m = lab.mapper(allow(UDN, false));
    assert_eq!(m.refresh(req()).status, MapStatus::NoGateway);
    thread::sleep(Duration::from_millis(150));
    assert_eq!(lab.routers[0].connections(), 0);
    assert_eq!(lab.routers[1].connections(), 0);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_control_url_other_port_no_connect() {
    let Some(lab) = Lab::new(vec![
        Cfg::default(),
        Cfg {
            advertise: false,
            ..Cfg::default()
        },
    ]) else {
        skip()
    };
    let other = lab.routers[1].addr.port();
    lab.r().with(|i| {
        i.cfg.services = vec![(SVC_V1.to_owned(), format!("http://127.0.0.2:{other}/ctl"))];
    });
    let m = lab.mapper(allow(UDN, false));
    assert_eq!(m.refresh(req()).status, MapStatus::NoGateway);
    thread::sleep(Duration::from_millis(150));
    assert_eq!(lab.routers[1].connections(), 0);
    assert_eq!(lab.r().soap_count(), 0);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_malformed_soap() {
    let Some(lab) = Lab::new(vec![with_hook(|r, _| {
        (r.is_post && r.action == "GetExternalIPAddress").then(|| Reply::Body("<x><y>".to_owned()))
    })]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::Failed);
    assert_eq!(rep.retry_after, secs(60));
    assert!(rep.gateway.is_none());
    assert_eq!(lab.r().count("AddPortMapping"), 0);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_conflict_718_alt_port() {
    // IGDv1: случайный порт из 49152..=65535, AddAny не используется
    let Some(lab) = Lab::new(vec![Cfg {
        taken: vec![PORT],
        ..Cfg::default()
    }]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::Mapped);
    let mapped = rep.gateway.unwrap().mapping.unwrap();
    assert_eq!(*mapped.ip(), wan());
    assert!((49152..=65535).contains(&mapped.port()) && mapped.port() != PORT);
    assert_eq!(lab.r().count("AddPortMapping"), 2);
    assert_eq!(lab.r().count("AddAnyPortMapping"), 0);
    assert_eq!(lab.r().entries().len(), 1);
    assert_eq!(lab.r().entries()[0].ext, mapped.port());

    // IGDv2: AddAnyPortMapping, порт выбирает роутер
    let Some(lab) = Lab::new(vec![Cfg {
        taken: vec![PORT],
        services: vec![(SVC_V2.to_owned(), CTL.to_owned())],
        ..Cfg::default()
    }]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::Mapped);
    assert_eq!(rep.gateway.unwrap().mapping.unwrap().port(), 50555);
    assert_eq!(lab.r().count("AddPortMapping"), 1);
    assert_eq!(lab.r().count("AddAnyPortMapping"), 1);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_725_needs_consent_then_permanent_same_port() {
    let cfg = || Cfg {
        only_permanent: true,
        ..Cfg::default()
    };
    let Some(lab) = Lab::new(vec![cfg()]) else {
        skip()
    };
    // нет согласия: проброса нет
    let m = lab.mapper(allow(UDN, false));
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::NeedPermanentConsent);
    assert_eq!(rep.retry_after, secs(1800));
    assert!(lab.r().entries().is_empty());
    // согласие: роутер уже известен как «только бессрочно», сразу L = 0 на том же порту
    m.set_settings(allow(UDN, true));
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::MappedPermanent);
    assert_eq!(rep.retry_after, secs(1800));
    assert_eq!(lab.r().entries(), vec![ours(PORT, 0)]);

    // новый запуск с согласием: 725 на L = 3600, повтор L = 0 в том же refresh
    let Some(lab) = Lab::new(vec![cfg()]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, true));
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::MappedPermanent);
    let adds = lab.r().requests("AddPortMapping");
    assert_eq!(adds.len(), 2);
    assert_eq!(adds[0].arg("NewLeaseDuration"), Some("3600"));
    assert_eq!(adds[1].arg("NewLeaseDuration"), Some("0"));
    assert_eq!(
        adds[1].arg("NewExternalPort"),
        Some(PORT.to_string().as_str())
    );
    // выход удаляет и бессрочный проброс
    m.release();
    assert!(lab.r().entries().is_empty());
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_606_refused_backoff() {
    let Some(lab) = Lab::new(vec![with_hook(|r, _| {
        (r.is_post && r.action == "AddPortMapping").then_some(Reply::Fault(606))
    })]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    let mut waits = Vec::new();
    for _ in 0..3 {
        let rep = m.refresh(req());
        assert_eq!(rep.status, MapStatus::Refused(606));
        assert!(rep.gateway.is_none());
        waits.push(rep.retry_after);
    }
    assert_eq!(waits, vec![secs(60), secs(120), secs(240)]);
    // смена сети (другой внутренний адрес) сбрасывает задержку
    let rep = m.refresh(req_for(PORT + 1));
    assert_eq!(rep.retry_after, secs(60));
}

fn wan_case(wan_text: &str) -> (MapStatus, Option<GatewayInfo>, usize, Duration) {
    let Some(lab) = Lab::new(vec![Cfg {
        wan: wan_text.to_owned(),
        ..Cfg::default()
    }]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    let rep = m.refresh(req());
    (
        rep.status,
        rep.gateway,
        lab.r().count("AddPortMapping") + lab.r().count("AddAnyPortMapping"),
        rep.retry_after,
    )
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_wan_empty_unknown_no_add() {
    let (st, gw, adds, retry) = wan_case("");
    if st == MapStatus::Mapped {
        return;
    }
    assert_eq!(st, MapStatus::WanUnknown);
    assert!(gw.is_none());
    assert_eq!(adds, 0);
    assert_eq!(retry, secs(60));
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_wan_cgnat_no_add() {
    let (st, gw, adds, retry) = wan_case("100.64.1.2");
    if st == MapStatus::Mapped {
        return;
    }
    assert_eq!(st, MapStatus::BehindCgnat);
    assert_eq!(
        gw,
        Some(GatewayInfo {
            wan_ip: Some("100.64.1.2".parse().unwrap()),
            mapping: None,
        })
    );
    assert_eq!(adds, 0);
    assert_eq!(retry, secs(1800));
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_wan_private_double_nat_no_add() {
    let (st, gw, adds, _) = wan_case("192.168.0.5");
    if st == MapStatus::Mapped {
        return;
    }
    assert_eq!(st, MapStatus::DoubleNat);
    assert_eq!(gw.unwrap().mapping, None);
    assert_eq!(adds, 0);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_wan_bogus_rejected() {
    for bogus in ["0.0.0.0", "127.0.0.1", "224.0.0.1", "192.0.2.1"] {
        let (st, gw, adds, _) = wan_case(bogus);
        if st == MapStatus::Mapped {
            return;
        }
        assert_eq!(st, MapStatus::Failed, "{bogus}");
        assert!(gw.is_none(), "{bogus}");
        assert_eq!(adds, 0, "{bogus}");
    }
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_specific_other_client_not_confirmed() {
    let other = soap_ok(
        SVC_V1,
        "GetSpecificPortMappingEntry",
        "<NewInternalPort>40123</NewInternalPort><NewInternalClient>127.0.0.77</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>udp</NewPortMappingDescription><NewLeaseDuration>3600</NewLeaseDuration>",
    );
    let Some(lab) = Lab::new(vec![with_hook(move |r, _| {
        (r.is_post && r.action == "GetSpecificPortMappingEntry").then(|| Reply::Body(other.clone()))
    })]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::Failed);
    assert!(rep.gateway.is_none());
    // чужая запись не удаляется
    assert_eq!(lab.r().count("DeletePortMapping"), 0);
    // проброс не засчитан, поэтому release ничего не шлёт
    let before = lab.r().actions().len();
    m.release();
    assert_eq!(lab.r().actions().len(), before);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_router_permanent_silently() {
    let Some(lab) = Lab::new(vec![Cfg {
        lease_mode: LeaseMode::Permanent,
        ..Cfg::default()
    }]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::MappedPermanent);
    assert_eq!(rep.retry_after, secs(1800));
    assert!(rep.gateway.unwrap().mapping.is_some());
    assert_eq!(lab.r().entries(), vec![ours(PORT, 0)]);
    m.release();
    assert!(lab.r().entries().is_empty());
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_router_short_lease_renew_half() {
    let Some(lab) = Lab::new(vec![Cfg {
        lease_mode: LeaseMode::Cap(300),
        ..Cfg::default()
    }]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::Mapped);
    assert_eq!(rep.retry_after, secs(150));
    assert_eq!(
        lab.r().actions(),
        [
            "GET",
            "GetExternalIPAddress",
            "GetSpecificPortMappingEntry",
            "AddPortMapping",
            "GetSpecificPortMappingEntry"
        ]
    );
    // продление: без очистки перед добавлением
    let n = lab.r().actions().len();
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::Mapped);
    assert_eq!(
        lab.r().actions()[n..],
        [
            "GET",
            "GetExternalIPAddress",
            "AddPortMapping",
            "GetSpecificPortMappingEntry"
        ]
    );
    // половина аренды, но не меньше 60 с
    lab.r().with(|i| i.cfg.lease_mode = LeaseMode::Cap(100));
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::Mapped);
    assert_eq!(rep.retry_after, secs(60));
    assert_eq!(lab.r().count("DeletePortMapping"), 0);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_stale_own_deleted_at_start() {
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    lab.r().put_entry(ours(PORT, 0));
    let m = lab.mapper(allow(UDN, false));
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::Mapped);
    assert_eq!(
        lab.r().actions(),
        [
            "GET",
            "GetExternalIPAddress",
            "GetSpecificPortMappingEntry",
            "DeletePortMapping",
            "AddPortMapping",
            "GetSpecificPortMappingEntry"
        ]
    );
    assert_eq!(lab.r().entries(), vec![ours(PORT, 3600)]);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_stale_foreign_not_deleted() {
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    let foreign = Entry {
        ext: PORT,
        internal_port: 1234,
        client: "127.0.0.50".to_owned(),
        desc: "other".to_owned(),
        lease: 0,
    };
    lab.r().put_entry(foreign.clone());
    let m = lab.mapper(allow(UDN, false));
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::Mapped);
    assert_eq!(lab.r().count("DeletePortMapping"), 0);
    assert!(lab.r().entries().contains(&foreign));
    assert_eq!(lab.r().entries().len(), 2);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_release_deletes_only_ours() {
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    assert_eq!(m.refresh(req()).status, MapStatus::Mapped);
    m.release();
    assert!(lab.r().entries().is_empty());
    assert_eq!(lab.r().count("DeletePortMapping"), 1);
    // запись перехвачена другим клиентом: не удаляем
    assert_eq!(m.refresh(req()).status, MapStatus::Mapped);
    lab.r()
        .with(|i| i.state.table[0].client = "127.0.0.50".to_owned());
    m.release();
    assert_eq!(lab.r().entries().len(), 1);
    assert_eq!(lab.r().count("DeletePortMapping"), 1);
    // второй release ничего не шлёт
    let n = lab.r().actions().len();
    m.release();
    assert_eq!(lab.r().actions().len(), n);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_network_change_deletes_old() {
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    assert_eq!(m.refresh(req_for(PORT)).status, MapStatus::Mapped);
    assert_eq!(m.refresh(req_for(PORT + 1)).status, MapStatus::Mapped);
    assert_eq!(lab.r().count("DeletePortMapping"), 1);
    assert_eq!(lab.r().entries(), vec![ours(PORT + 1, 3600)]);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_settings_cleared_forgets_without_sending() {
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    assert_eq!(m.refresh(req()).status, MapStatus::Mapped);
    let (d0, c0, a0) = (
        lab.ssdp.count(),
        lab.r().connections(),
        lab.r().actions().len(),
    );
    m.set_settings(UpnpSettings::default());
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::Off);
    assert!(rep.gateway.is_none());
    // пустой список: ни одного пакета, запись остаётся до конца аренды (ред. 2, L2)
    assert_eq!(lab.r().entries(), vec![ours(PORT, 3600)]);
    assert_eq!(
        (
            lab.ssdp.count(),
            lab.r().connections(),
            lab.r().actions().len()
        ),
        (d0, c0, a0)
    );
    // дальше ни одного пакета
    let (d, c, a) = (
        lab.ssdp.count(),
        lab.r().connections(),
        lab.r().actions().len(),
    );
    assert_eq!(m.refresh(req()).status, MapStatus::Off);
    m.release();
    assert_eq!(
        (
            lab.ssdp.count(),
            lab.r().connections(),
            lab.r().actions().len()
        ),
        (d, c, a)
    );
}

/// Роутер «только бессрочно», согласие дано: проброс с арендой 0 записан в `current`.
fn permanent_lab() -> Option<(Lab, UpnpMapper)> {
    let lab = Lab::new(vec![Cfg {
        only_permanent: true,
        ..Cfg::default()
    }])?;
    let m = lab.mapper(allow(UDN, true));
    assert_eq!(m.refresh(req()).status, MapStatus::MappedPermanent);
    assert_eq!(lab.r().entries(), vec![ours(PORT, 0)]);
    Some((lab, m))
}

fn assert_no_traffic_after(lab: &Lab, m: &UpnpMapper) {
    let before = (
        lab.ssdp.count(),
        lab.r().connections(),
        lab.r().actions().len(),
    );
    assert_eq!(m.refresh(req()).status, MapStatus::Off);
    m.release();
    assert_eq!(
        (
            lab.ssdp.count(),
            lab.r().connections(),
            lab.r().actions().len()
        ),
        before
    );
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_settings_cleared_permanent_deleted_once() {
    let Some((lab, m)) = permanent_lab() else {
        skip()
    };
    // список сохраняет роутер (меняется только согласие): ничего не удаляется
    m.set_settings(allow(UDN, false));
    assert_eq!(lab.r().count("DeletePortMapping"), 0);
    assert_eq!(lab.r().entries(), vec![ours(PORT, 0)]);
    // очистка списка: одно подтверждённое удаление по старому списку
    m.set_settings(UpnpSettings::default());
    assert_eq!(lab.r().count("DeletePortMapping"), 1);
    assert!(lab.r().entries().is_empty());
    // дальше ни одного пакета, второго удаления нет
    assert_no_traffic_after(&lab, &m);
    assert_eq!(lab.r().count("DeletePortMapping"), 1);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_settings_other_router_permanent_deleted_once() {
    let Some((lab, m)) = permanent_lab() else {
        skip()
    };
    m.set_settings(allow("uuid:someone-else", false));
    assert_eq!(lab.r().count("DeletePortMapping"), 1);
    assert!(lab.r().entries().is_empty());
    m.release();
    assert_eq!(lab.r().count("DeletePortMapping"), 1);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_settings_cleared_permanent_unconfirmed_sends_nothing() {
    let Some((lab, m)) = permanent_lab() else {
        skip()
    };
    let soap = lab.r().soap_count();
    // в сети по сохранённому адресу уже другой роутер: SOAP не уходит, запись остаётся
    // (остаточный риск T16: бессрочная запись без подтверждённого роутера)
    lab.r()
        .with(|i| i.cfg.udn = "uuid:foreign-router".to_owned());
    m.set_settings(UpnpSettings::default());
    assert_eq!(lab.r().soap_count(), soap);
    assert_eq!(lab.r().count("DeletePortMapping"), 0);
    assert_eq!(lab.r().entries(), vec![ours(PORT, 0)]);
    assert_no_traffic_after(&lab, &m);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_not_home_network_no_soap() {
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    let m = lab.mapper(allow("uuid:someone-else", false));
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::NotHomeNetwork);
    assert_eq!(rep.retry_after, secs(1800));
    assert!(rep.gateway.is_none());
    assert_eq!(lab.r().soap_count(), 0);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_off_no_traffic() {
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    let m = lab.mapper(UpnpSettings::default());
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::Off);
    assert_eq!(rep.retry_after, secs(1800));
    m.release();
    thread::sleep(Duration::from_millis(100));
    assert_eq!(lab.ssdp.count(), 0);
    assert_eq!(lab.r().connections(), 0);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_ambiguous_two_responders() {
    let Some(lab) = Lab::new(vec![Cfg::default(), Cfg::default()]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::Ambiguous);
    assert!(rep.gateway.is_none());
    assert_eq!(lab.routers[0].soap_count() + lab.routers[1].soap_count(), 0);
    assert_eq!(m.identify(OWN), Err(UpnpError::Ambiguous));
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_identify_returns_udn() {
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    let m = lab.mapper(UpnpSettings::default());
    let id = m.identify(OWN).unwrap();
    assert_eq!(id.to_setting(), UDN);
    assert_eq!(id, RouterId::from_setting(UDN).unwrap());
    assert_eq!(lab.r().soap_count(), 0);
    // чужой (не частный) собственный адрес: поиска нет
    let n = lab.ssdp.count();
    assert_eq!(
        m.identify(Ipv4Addr::new(8, 8, 4, 4)),
        Err(UpnpError::NoGateway)
    );
    assert_eq!(lab.ssdp.count(), n);
    // никого нет
    let Some(empty) = Lab::new(vec![]) else {
        skip()
    };
    assert_eq!(
        empty.mapper(UpnpSettings::default()).identify(OWN),
        Err(UpnpError::NoGateway)
    );
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_refresh_bounded_by_max_refresh() {
    let Some(lab) = Lab::new(vec![Cfg {
        services: vec![
            (SVC_V2.to_owned(), "/ctl/a".to_owned()),
            (SVC_V1.to_owned(), "/ctl/b".to_owned()),
        ],
        hook: Some(Arc::new(|r, _| r.is_post.then_some(Reply::Stall))),
        ..Cfg::default()
    }]) else {
        skip()
    };
    let net = Net {
        http_deadline: secs(2),
        max_refresh: secs(3),
        ..lab.net()
    };
    let m = UpnpMapper::with_net(allow(UDN, false), net);
    let start = Instant::now();
    let rep = m.refresh(req());
    let el = start.elapsed();
    assert_eq!(rep.status, MapStatus::Failed);
    assert!(el <= secs(3) + Duration::from_millis(500), "{el:?}");
    assert!(el >= secs(2), "{el:?}");
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_settings_limited_to_four() {
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    let mut routers: Vec<AllowedRouter> = (1..=4)
        .map(|n| AllowedRouter {
            id: RouterId::from_setting(&format!("uuid:other-{n}")).unwrap(),
            permanent_ok: false,
        })
        .collect();
    routers.push(AllowedRouter {
        id: RouterId::from_setting(UDN).unwrap(),
        permanent_ok: false,
    });
    let m = lab.mapper(UpnpSettings { routers });
    assert_eq!(m.refresh(req()).status, MapStatus::NotHomeNetwork);
}

/// Поиск неоднозначен и для `refresh`, и для `identify`; SOAP никуда не уходит.
fn assert_ambiguous_everywhere(lab: &Lab, m: &UpnpMapper) {
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::Ambiguous);
    assert!(rep.gateway.is_none());
    // политика спецификации: Ambiguous это 1800 с без удвоения, и от поиска, и от двух кандидатов
    assert_eq!(rep.retry_after, secs(1800));
    assert_eq!(m.refresh(req()).retry_after, secs(1800));
    assert_eq!(m.identify(OWN), Err(UpnpError::Ambiguous));
    for r in &lab.routers {
        assert_eq!(r.soap_count(), 0);
    }
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_conflicting_location_ambiguous() {
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    // тот же IP присылает второй, другой LOCATION: настоящий роутер не выбрасывается молча
    let r = lab.r();
    lab.ssdp
        .advertise(r.ip, format!("http://{}:{}/other.xml", r.ip, r.addr.port()));
    let m = lab.mapper(allow(UDN, false));
    assert_ambiguous_everywhere(&lab, &m);
    assert_eq!(lab.r().connections(), 0);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_datagram_cap_hit_ambiguous() {
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    // 61 источник x 2 цели уже в первом раунде дают 122 датаграммы > 64 (потом ещё столько
    // же), все с одним и тем же LOCATION: конфликта нет, неоднозначность только из-за предела
    for _ in 0..60 {
        lab.ssdp.advertise(lab.r().ip, lab.r().location());
    }
    let m = lab.mapper(allow(UDN, false));
    assert_ambiguous_everywhere(&lab, &m);
    assert_eq!(lab.r().connections(), 0);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_more_than_eight_responders_ambiguous() {
    let Some(lab) = Lab::new((0..9).map(|_| Cfg::default()).collect()) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    assert_ambiguous_everywhere(&lab, &m);
    assert!(lab.routers.iter().all(|r| r.connections() == 0));

    // ровно восемь: не неоднозначно, берётся единственный разрешённый
    let cfgs = (0..8)
        .map(|i| Cfg {
            udn: format!("uuid:r-{i}"),
            ..Cfg::default()
        })
        .collect();
    let Some(lab) = Lab::new(cfgs) else { skip() };
    let m = lab.mapper(allow("uuid:r-3", false));
    assert_eq!(m.refresh(req()).status, MapStatus::Mapped);
    assert_eq!(lab.routers[3].entries().len(), 1);
    assert_eq!(m.identify(OWN), Err(UpnpError::Ambiguous));
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_unevaluated_responder_ambiguous() {
    // описание первого роутера не приходит до общего срока: второй мог остаться неоценённым
    let Some(lab) = Lab::new(vec![
        with_hook(|r, _| (!r.is_post).then_some(Reply::Stall)),
        Cfg::default(),
    ]) else {
        skip()
    };
    let net = Net {
        http_deadline: secs(1),
        max_refresh: Duration::from_millis(1200),
        ..lab.net()
    };
    let m = UpnpMapper::with_net(allow(UDN, false), net);
    assert_ambiguous_everywhere(&lab, &m);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_foreign_network_same_addressing_sends_nothing() {
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    assert_eq!(m.refresh(req()).status, MapStatus::Mapped);
    let soap = lab.r().soap_count();
    // чужая сеть с той же адресацией: по сохранённому адресу другой роутер
    lab.r()
        .with(|i| i.cfg.udn = "uuid:foreign-router".to_owned());
    let rep = m.refresh(req());
    assert_eq!(rep.status, MapStatus::NotHomeNetwork);
    assert_eq!(lab.r().soap_count(), soap);
    // сохранённый проброс забыт: выход тоже ничего не шлёт, даже если дома снова всё как было
    lab.r().with(|i| i.cfg.udn = UDN.to_owned());
    m.release();
    assert_eq!(lab.r().soap_count(), soap);
    assert_eq!(lab.r().entries(), vec![ours(PORT, 3600)]);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_release_unconfirmed_router_sends_nothing() {
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    assert_eq!(m.refresh(req()).status, MapStatus::Mapped);
    let soap = lab.r().soap_count();
    lab.r()
        .with(|i| i.cfg.udn = "uuid:foreign-router".to_owned());
    m.release();
    assert_eq!(lab.r().soap_count(), soap);
    assert_eq!(lab.r().count("DeletePortMapping"), 0);
    assert_eq!(lab.r().entries().len(), 1);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_current_forgotten_when_no_gateway_or_ambiguous() {
    // NoGateway: описание больше не отдаётся
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    assert_eq!(m.refresh(req()).status, MapStatus::Mapped);
    let soap = lab.r().soap_count();
    lab.r().with(|i| {
        i.cfg.hook = Some(Arc::new(|r, _| (!r.is_post).then_some(Reply::Status(404))));
    });
    assert_eq!(m.refresh(req()).status, MapStatus::NoGateway);
    lab.r().with(|i| i.cfg.hook = None);
    m.release();
    assert_eq!(lab.r().soap_count(), soap);

    // Ambiguous: появился второй такой же роутер
    let Some(lab) = Lab::new(vec![
        Cfg::default(),
        Cfg {
            advertise: false,
            ..Cfg::default()
        },
    ]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    assert_eq!(m.refresh(req()).status, MapStatus::Mapped);
    let soap = lab.r().soap_count();
    lab.ssdp
        .advertise(lab.routers[1].ip, lab.routers[1].location());
    assert_eq!(m.refresh(req()).status, MapStatus::Ambiguous);
    m.release();
    assert_eq!(lab.r().soap_count(), soap);
    assert_eq!(lab.routers[1].soap_count(), 0);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_unrequested_permanent_on_alt_port_deleted() {
    // v1 (случайный порт) и v2 (AddAny): роутер сделал запасной порт бессрочным без просьбы
    for services in [
        vec![(SVC_V1.to_owned(), CTL.to_owned())],
        vec![(SVC_V2.to_owned(), CTL.to_owned())],
    ] {
        let Some(lab) = Lab::new(vec![Cfg {
            taken: vec![PORT],
            lease_mode: LeaseMode::Permanent,
            services,
            ..Cfg::default()
        }]) else {
            skip()
        };
        let m = lab.mapper(allow(UDN, false));
        let rep = m.refresh(req());
        assert_eq!(rep.status, MapStatus::Failed);
        assert!(rep.gateway.is_none());
        assert!(lab.r().entries().is_empty());
        assert_eq!(lab.r().count("DeletePortMapping"), 1);
        // проброс не засчитан, выход ничего не шлёт
        let n = lab.r().actions().len();
        m.release();
        assert_eq!(lab.r().actions().len(), n);
    }
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_second_refresh_while_busy_fails_fast() {
    let Some(lab) = Lab::new(vec![with_hook(|r, _| {
        (r.is_post && r.action == "GetExternalIPAddress").then_some(Reply::Stall)
    })]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    thread::scope(|sc| {
        let first = sc.spawn(|| m.refresh(req()));
        let t0 = Instant::now();
        while lab.r().count("GetExternalIPAddress") == 0 {
            assert!(t0.elapsed() < secs(5), "первый refresh не дошёл до SOAP");
            thread::sleep(Duration::from_millis(10));
        }
        let before = (
            lab.ssdp.count(),
            lab.r().connections(),
            lab.r().actions().len(),
        );
        let start = Instant::now();
        let rep = m.refresh(req());
        assert!(start.elapsed() < Duration::from_millis(300));
        assert_eq!(rep.status, MapStatus::Failed);
        assert!(rep.gateway.is_none());
        assert_eq!(rep.retry_after, secs(60));
        assert_eq!(
            (
                lab.ssdp.count(),
                lab.r().connections(),
                lab.r().actions().len()
            ),
            before
        );
        assert_eq!(first.join().unwrap().status, MapStatus::Failed);
    });
    // занятость снята: следующий refresh работает
    lab.r().with(|i| i.cfg.hook = None);
    assert_eq!(m.refresh(req()).status, MapStatus::Mapped);
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_stale_delete_bounded_by_overall() {
    let Some(lab) = Lab::new(vec![Cfg::default()]) else {
        skip()
    };
    let net = Net {
        http_deadline: secs(2),
        max_refresh: secs(3),
        ..lab.net()
    };
    let m = UpnpMapper::with_net(allow(UDN, false), net);
    assert_eq!(m.refresh(req_for(PORT)).status, MapStatus::Mapped);
    // смена сети: удаление старого проброса, роутер молчит на каждый SOAP
    lab.r().with(|i| {
        i.cfg.hook = Some(Arc::new(|r, _| r.is_post.then_some(Reply::Stall)));
    });
    let start = Instant::now();
    let rep = m.refresh(req_for(PORT + 1));
    let el = start.elapsed();
    assert_eq!(rep.status, MapStatus::Failed);
    assert!(el <= secs(3) + Duration::from_millis(500), "{el:?}");
}

#[test]
#[cfg_attr(target_os = "macos", ignore = "needs 127.0.0.x aliases")]
fn igd_control_url_semicolon_rejected() {
    let Some(lab) = Lab::new(vec![Cfg {
        services: vec![(SVC_V1.to_owned(), "/ctl;x=1".to_owned())],
        ..Cfg::default()
    }]) else {
        skip()
    };
    let m = lab.mapper(allow(UDN, false));
    assert_eq!(m.refresh(req()).status, MapStatus::NoGateway);
    assert_eq!(lab.r().soap_count(), 0);
}

#[test]
fn router_id_setting_roundtrip_and_limits() {
    let id = RouterId::from_setting("uuid:abc-123_X.y:z").unwrap();
    assert_eq!(id.to_setting(), "uuid:abc-123_X.y:z");
    assert_eq!(RouterId::from_setting(&id.to_setting()).unwrap(), id);
    let ok = format!("uuid:{}", "a".repeat(123));
    assert_eq!(ok.len(), 128);
    assert!(RouterId::from_setting(&ok).is_ok());
    let long = format!("uuid:{}", "a".repeat(124));
    for bad in [
        "", "abc", "uuid:", "uuid:a b", "uuid:a/b", "UUID:abc", "uuid:é", &long,
    ] {
        assert_eq!(
            RouterId::from_setting(bad),
            Err(UpnpError::Rejected),
            "{bad}"
        );
    }
}

#[test]
fn debug_redacted() {
    let id = RouterId::from_setting("uuid:secret-udn").unwrap();
    let allowed = AllowedRouter {
        id: id.clone(),
        permanent_ok: true,
    };
    let s = UpnpSettings {
        routers: vec![allowed.clone()],
    };
    let m = UpnpMapper::new(s.clone());
    for text in [
        format!("{id:?}"),
        format!("{allowed:?}"),
        format!("{s:?}"),
        format!("{m:?}"),
    ] {
        assert!(text.ends_with("(..)"), "{text}");
        assert!(!text.contains("secret"), "{text}");
    }
}

#[test]
#[ignore = "ручной запуск в своей сети: настоящий multicast"]
fn multicast_discovery_real_lan() {
    let own = chervo_addr::probe_route_sources()
        .v4
        .expect("нет маршрутного IPv4");
    let m = UpnpMapper::new(UpnpSettings::default());
    println!("identify: {:?}", m.identify(own));
}
