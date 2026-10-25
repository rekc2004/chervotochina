#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
//! Контракт поиска в LAN (этап 13в): `Debug` не печатает ни адрес, ни порт, ни пару, ни ключи.

use std::collections::HashMap;
use std::net::SocketAddrV4;
use std::sync::Mutex;

use chervo_addr::{LAN_FOUND_MAX, LanFound, LanPeer, LanStatus};
use chervo_identity::{IdentityError, KxPeer, PairId, SecretStore, create};
use zeroize::Zeroizing;

#[derive(Default)]
struct Mem(Mutex<HashMap<PairId, Zeroizing<Vec<u8>>>>);

impl SecretStore for Mem {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .get(pair)
            .map(|v| Zeroizing::new(v.to_vec())))
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        self.0
            .lock()
            .unwrap()
            .insert(*pair, Zeroizing::new(blob.to_vec()));
        Ok(())
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        self.0.lock().unwrap().remove(pair);
        Ok(())
    }
}

#[test]
fn lan_found_debug_redacted() {
    let f = LanFound {
        pair: PairId::from_bytes([0x5a; 16]),
        addr: SocketAddrV4::new("192.168.77.13".parse().unwrap(), 41_234),
    };
    let text = format!("{f:?} {f:#?}");
    assert!(text.contains("LanFound(..)"));
    for needle in ["192", "168", "77", "41234", "5a", "90", "addr", "pair"] {
        assert!(!text.contains(needle), "утечка {needle}: {text}");
    }
    assert_eq!(LAN_FOUND_MAX, 64);
    assert_eq!(format!("{:?}", LanStatus::Running), "Running");
}

#[test]
fn lan_peer_debug_redacted() {
    let pid = PairId::from_bytes([0x5a; 16]);
    let (sa, sb) = (Mem::default(), Mem::default());
    let ka = create(&sa, &pid).unwrap();
    let kb = create(&sb, &pid).unwrap();
    let pb = kb.kx_public();
    let keys = KxPeer::new(pid, ka.into_kx(), pb).lan_keys().unwrap();
    let peer = LanPeer { pair: pid, keys };
    let text = format!("{peer:?} {peer:#?}");
    assert!(text.contains("LanPeer(..)"));
    for needle in ["5a", "90", "pair", "keys", "id_", "seal"] {
        assert!(!text.contains(needle), "утечка {needle}: {text}");
    }
    assert_eq!(format!("{:?}", peer.keys), "LanKeys(..)");
}
