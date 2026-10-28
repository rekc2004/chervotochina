#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
//! Тесты чистых модулей (этап 13в, часть L2).

mod fuzz;
mod misc;
mod rate;
mod table;
mod wire;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use chervo_identity::{LanKeys, PairId};

use crate::table::IdTable;
use crate::testkit::duo;

pub const W: u64 = 56_789_012;
pub const OWN: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 1);
pub const SRC: Ipv4Addr = Ipv4Addr::new(192, 168, 50, 7);
pub const PORT: u16 = 45_000;

pub fn sock(ip: Ipv4Addr) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(ip, 55_555))
}

/// `n` пар: ключи отправителя, ключи получателя, открытые ключи обмена.
pub struct Fx {
    pub sender: Vec<(PairId, LanKeys)>,
    pub receiver: Vec<(PairId, LanKeys)>,
    pub pubs: Vec<[u8; 32]>,
}

pub fn fixture(n: usize) -> Fx {
    let mut fx = Fx {
        sender: Vec::new(),
        receiver: Vec::new(),
        pubs: Vec::new(),
    };
    for _ in 0..n {
        let d = duo().unwrap();
        fx.sender.push((d.pair, d.a));
        fx.receiver.push((d.pair, d.b));
        fx.pubs.extend(d.pubs);
    }
    fx
}

impl Fx {
    pub fn refs(&self) -> Vec<(PairId, &LanKeys)> {
        self.sender.iter().map(|(p, k)| (*p, k)).collect()
    }

    pub fn pair_ids(&self) -> Vec<PairId> {
        self.sender.iter().map(|(p, _)| *p).collect()
    }

    /// Таблица получателя на окно `w`; ключи получателя отдаются таблице.
    pub fn table(&mut self, w: u64) -> IdTable {
        IdTable::from_peers(std::mem::take(&mut self.receiver), w)
    }
}
