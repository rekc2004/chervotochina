//! Редакция вывода UPnP (этап 17, B3, решение 1c; BRIEF 7, T8, T16, SEC-8 #4): `Debug` типов
//! с данными роутера (IP шлюза, порт, пути, UDN, тела ответов) и ошибок не содержит ни одного
//! такого значения. Здесь нельзя печатать, только сравнения.

use std::net::Ipv4Addr;

use super::{ip, target};
use crate::desc::{Description, Service, ServiceKind, Udn};
use crate::error::UpnpError;
use crate::http::Reply;
use crate::soap::Entry;
use crate::ssdp::Responder;
use crate::url::parse_location;
use crate::{AllowedRouter, RouterId, UpnpMapper, UpnpSettings, status_text};

const UDN: &str = "uuid:ROUTERMARK-1234-abcd";

#[test]
fn upnp_types_hide_router_data() {
    let t = target();
    let udn = Udn::parse(UDN).unwrap();
    let router = RouterId::from_setting(UDN).unwrap();
    let settings = UpnpSettings {
        routers: vec![AllowedRouter {
            id: router.clone(),
            permanent_ok: true,
        }],
    };
    let svc = Service {
        kind: ServiceKind::WanIp1,
        control: t.path.clone(),
    };
    let desc = Description {
        udn: udn.clone(),
        services: vec![svc.clone()],
    };
    let responder = Responder {
        ip: ip(192, 168, 1, 1),
        target: t.clone(),
    };
    let reply = Reply {
        status: 200,
        body: b"<ROUTERMARK-body>external 203.0.113.9</ROUTERMARK-body>".to_vec(),
    };
    let entry = Entry {
        internal_port: 44_444,
        internal_client: Ipv4Addr::new(192, 168, 1, 77),
        enabled: true,
        description_is_ours: true,
        lease: 3600,
    };
    let mapper = UpnpMapper::new(settings.clone());
    let parsed =
        parse_location("http://192.168.1.1:5000/rootDesc.xml", ip(192, 168, 1, 1)).unwrap();

    let mut texts: Vec<String> = Vec::new();
    macro_rules! both {
        ($v:expr) => {{
            texts.push(format!("{:?}", $v));
            texts.push(format!("{:#?}", $v));
        }};
    }
    both!(t);
    both!(t.gw);
    both!(t.path);
    both!(parsed);
    both!(udn);
    both!(router);
    both!(settings);
    both!(settings.routers[0]);
    both!(svc);
    both!(desc);
    both!(responder);
    both!(reply);
    both!(entry);
    both!(mapper);
    for e in [
        UpnpError::NoGateway,
        UpnpError::Ambiguous,
        UpnpError::Timeout,
        UpnpError::Io,
        UpnpError::Protocol,
        UpnpError::Rejected,
    ] {
        texts.push(format!("{e:?}"));
    }
    for s in [
        crate::AMBIGUOUS_TEXT,
        crate::CGNAT_UPNP_TEXT,
        crate::DOUBLE_NAT_UPNP_TEXT,
        crate::ENABLE_ON_ROUTER_TEXT,
        crate::NEED_PERMANENT_TEXT,
        crate::NOT_HOME_TEXT,
        crate::REFUSED_TEXT,
    ] {
        texts.push(s.to_owned());
    }
    let _ = status_text;

    for text in &texts {
        for needle in [
            "ROUTERMARK",
            "192.168.1",
            "203.0.113",
            ":5000",
            "5000",
            "rootDesc",
            "44444",
            "44_444",
            "3600",
        ] {
            assert!(!text.contains(needle), "утечка `{needle}` в `{text}`");
        }
    }
    assert!(texts.len() > 25);
}
