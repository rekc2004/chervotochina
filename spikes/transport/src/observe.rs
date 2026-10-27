//! Пассивный наблюдатель G12: разбор pcap руками, расшифровка QUIC Initial ключами из открытых данных.
//! Вход только наш (захват из нашего стенда), но любой срез проверяется по длине; битое пропускается.
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use quinn_proto::ConnectionId;
use quinn_proto::crypto::ServerConfig as _;
use quinn_proto::crypto::rustls::QuicServerConfig;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use crate::util::{BoxErr, err, unhex};

const QUIC_V1: u32 = 1;
const QUIC_V2: u32 = 0x6b33_43cf;
const MAX_RECORD: usize = 262_144;
const MAX_CANDIDATES: usize = 4096;
const WINDOW: usize = 8;

pub struct Needle {
    pub label: String,
    pub bytes: Vec<u8>,
}

/// Строки вида `метка hex <hex>` или `метка str <текст>`.
pub fn parse_needles(text: &str) -> Result<Vec<Needle>, BoxErr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.splitn(3, ' ');
        let (Some(label), Some(kind), Some(val)) = (it.next(), it.next(), it.next()) else {
            return Err(err(format!("игла: плохая строка '{line}'")));
        };
        let bytes = match kind {
            "hex" => unhex(val)?,
            "str" => val.as_bytes().to_vec(),
            _ => return Err(err(format!("игла: неизвестный тип {kind}"))),
        };
        out.push(Needle { label: label.to_string(), bytes });
    }
    Ok(out)
}

/// Ищет иглы. Двоичные иглы ≥ 16 байт: совпадение любого окна в 8 байт (разрыв между CRYPTO-кадрами).
pub struct Matcher {
    windows: HashMap<u64, usize>,
    exact: Vec<usize>,
    needles: Vec<Needle>,
}

fn key8(b: &[u8]) -> Option<u64> {
    let a: [u8; WINDOW] = b.get(..WINDOW)?.try_into().ok()?;
    Some(u64::from_le_bytes(a))
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    let Some(&first) = needle.first() else {
        return false;
    };
    if needle.len() > hay.len() {
        return false;
    }
    let last = hay.len() - needle.len();
    let mut i = 0;
    while i <= last {
        if hay.get(i) == Some(&first) && hay.get(i..i + needle.len()) == Some(needle) {
            return true;
        }
        i += 1;
    }
    false
}

impl Matcher {
    pub fn new(needles: Vec<Needle>) -> Self {
        let mut windows = HashMap::new();
        let mut exact = Vec::new();
        for (idx, n) in needles.iter().enumerate() {
            if n.bytes.len() >= 16 {
                for w in n.bytes.windows(WINDOW) {
                    if let Some(k) = key8(w) {
                        windows.entry(k).or_insert(idx);
                    }
                }
            } else if n.bytes.len() >= 4 {
                exact.push(idx);
            }
        }
        Self { windows, exact, needles }
    }

    /// Метки найденных игл (без повторов).
    pub fn find(&self, hay: &[u8]) -> Vec<String> {
        let mut hit: HashSet<usize> = HashSet::new();
        if !self.windows.is_empty() {
            for w in hay.windows(WINDOW) {
                if let Some(&idx) = key8(w).and_then(|k| self.windows.get(&k)) {
                    hit.insert(idx);
                }
            }
        }
        for &idx in &self.exact {
            if self.needles.get(idx).is_some_and(|n| contains(hay, &n.bytes)) {
                hit.insert(idx);
            }
        }
        let mut v: Vec<String> = hit
            .into_iter()
            .filter_map(|i| self.needles.get(i).map(|n| n.label.clone()))
            .collect();
        v.sort();
        v
    }

    pub fn short_needles(&self) -> Vec<&str> {
        self.needles
            .iter()
            .filter(|n| n.bytes.len() < 4)
            .map(|n| n.label.as_str())
            .collect()
    }
}

// ------------------------------------------------------------------ pcap

struct Reader<'a> {
    d: &'a [u8],
    le: bool,
}

impl Reader<'_> {
    fn u32(&self, off: usize) -> Option<u32> {
        let a: [u8; 4] = self.d.get(off..off.checked_add(4)?)?.try_into().ok()?;
        Some(if self.le { u32::from_le_bytes(a) } else { u32::from_be_bytes(a) })
    }
}

pub struct Datagram<'a> {
    pub idx: usize,
    pub src: (IpAddr, u16),
    pub dst: (IpAddr, u16),
    pub payload: &'a [u8],
}

fn be16(b: &[u8], off: usize) -> Option<usize> {
    let a: [u8; 2] = b.get(off..off.checked_add(2)?)?.try_into().ok()?;
    Some(usize::from(u16::from_be_bytes(a)))
}

/// Ethernet-кадр → UDP-датаграмма.
fn udp_of_frame(f: &[u8]) -> Result<(Ep, Ep, &[u8]), &'static str> {
    let mut off = 12usize;
    let mut et = be16(f, off).ok_or("eth_short")?;
    off += 2;
    while et == 0x8100 || et == 0x88a8 {
        off += 2;
        et = be16(f, off).ok_or("vlan_short")?;
        off += 2;
    }
    let ip = f.get(off..).ok_or("eth_short")?;
    match et {
        0x0800 => {
            let b0 = *ip.first().ok_or("ip4_short")?;
            if b0 >> 4 != 4 {
                return Err("ip4_version");
            }
            let ihl = usize::from(b0 & 0x0f) * 4;
            if ihl < 20 || ip.len() < ihl {
                return Err("ip4_short");
            }
            if ip.get(9) != Some(&17) {
                return Err("not_udp");
            }
            let frag = be16(ip, 6).ok_or("ip4_short")?;
            if frag & 0x3fff != 0 {
                return Err("ip4_fragment");
            }
            let tot = be16(ip, 2).ok_or("ip4_short")?;
            let end = tot.min(ip.len());
            let s: [u8; 4] = ip.get(12..16).ok_or("ip4_short")?.try_into().map_err(|_| "ip4_short")?;
            let d: [u8; 4] = ip.get(16..20).ok_or("ip4_short")?.try_into().map_err(|_| "ip4_short")?;
            let udp = ip.get(ihl..end).ok_or("udp_short")?;
            udp_parts(udp, IpAddr::V4(Ipv4Addr::from(s)), IpAddr::V4(Ipv4Addr::from(d)))
        }
        0x86dd => {
            if ip.len() < 40 {
                return Err("ip6_short");
            }
            if ip.get(6) != Some(&17) {
                return Err("not_udp");
            }
            let plen = be16(ip, 4).ok_or("ip6_short")?;
            let end = 40usize.saturating_add(plen).min(ip.len());
            let s: [u8; 16] = ip.get(8..24).ok_or("ip6_short")?.try_into().map_err(|_| "ip6_short")?;
            let d: [u8; 16] = ip.get(24..40).ok_or("ip6_short")?.try_into().map_err(|_| "ip6_short")?;
            let udp = ip.get(40..end).ok_or("udp_short")?;
            udp_parts(udp, IpAddr::V6(Ipv6Addr::from(s)), IpAddr::V6(Ipv6Addr::from(d)))
        }
        _ => Err("not_ip"),
    }
}

type Ep = (IpAddr, u16);

fn udp_parts(udp: &[u8], s: IpAddr, d: IpAddr) -> Result<(Ep, Ep, &[u8]), &'static str> {
    if udp.len() < 8 {
        return Err("udp_short");
    }
    let sp = be16(udp, 0).ok_or("udp_short")?;
    let dp = be16(udp, 2).ok_or("udp_short")?;
    let ulen = be16(udp, 4).ok_or("udp_short")?;
    if ulen < 8 {
        return Err("udp_len");
    }
    let end = ulen.min(udp.len());
    let payload = udp.get(8..end).ok_or("udp_short")?;
    Ok(((s, u16::try_from(sp).map_err(|_| "port")?), (d, u16::try_from(dp).map_err(|_| "port")?), payload))
}

// ------------------------------------------------------------------ QUIC

fn varint(b: &[u8], pos: &mut usize) -> Option<u64> {
    let first = *b.get(*pos)?;
    let len = 1usize << (first >> 6);
    let slice = b.get(*pos..pos.checked_add(len)?)?;
    let mut v = u64::from(first & 0x3f);
    for x in slice.iter().skip(1) {
        v = (v << 8) | u64::from(*x);
    }
    *pos += len;
    Some(v)
}

struct LongHdr {
    version: u32,
    ptype: u8,
    dcid: Vec<u8>,
    scid: Vec<u8>,
    pn_offset: usize,
    pkt_len: usize,
}

fn parse_long(b: &[u8]) -> Result<LongHdr, &'static str> {
    let first = *b.first().ok_or("quic_short")?;
    if first & 0x80 == 0 {
        return Err("short_header");
    }
    let vb: [u8; 4] = b.get(1..5).ok_or("quic_short")?.try_into().map_err(|_| "quic_short")?;
    let version = u32::from_be_bytes(vb);
    if version == 0 {
        return Err("version_negotiation");
    }
    let mut pos = 5usize;
    let dl = usize::from(*b.get(pos).ok_or("quic_short")?);
    pos += 1;
    if dl > 20 {
        return Err("cid_len");
    }
    let dcid = b.get(pos..pos + dl).ok_or("quic_short")?.to_vec();
    pos += dl;
    let sl = usize::from(*b.get(pos).ok_or("quic_short")?);
    pos += 1;
    if sl > 20 {
        return Err("cid_len");
    }
    let scid = b.get(pos..pos + sl).ok_or("quic_short")?.to_vec();
    pos += sl;
    let t = (first >> 4) & 3;
    let ptype = if version == QUIC_V2 { (t + 3) & 3 } else { t }; // v2: Initial=1 → 0 и т.д.
    if ptype == 3 {
        return Ok(LongHdr { version, ptype, dcid, scid, pn_offset: pos, pkt_len: b.len() });
    }
    if ptype == 0 {
        let tl = varint(b, &mut pos).ok_or("quic_short")?;
        let tl = usize::try_from(tl).map_err(|_| "token_len")?;
        pos = pos.checked_add(tl).ok_or("token_len")?;
        if pos > b.len() {
            return Err("quic_short");
        }
    }
    let len = varint(b, &mut pos).ok_or("quic_short")?;
    let len = usize::try_from(len).map_err(|_| "length")?;
    let pkt_len = pos.checked_add(len).ok_or("length")?;
    if pkt_len > b.len() {
        return Err("quic_truncated");
    }
    Ok(LongHdr { version, ptype, dcid, scid, pn_offset: pos, pkt_len })
}

struct NoCert;
impl std::fmt::Debug for NoCert {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NoCert")
    }
}
impl ResolvesServerCert for NoCert {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        None
    }
}

fn initial_cfg() -> Result<QuicServerConfig, BoxErr> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let sc = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(NoCert));
    Ok(QuicServerConfig::try_from(sc)?)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Dir {
    ToServer,
    ToClient,
}

/// Снимает защиту заголовка и расшифровывает Initial. `dir` выбирает ключ `remote` или `local`.
fn decrypt_initial(
    cfg: &QuicServerConfig,
    version: u32,
    key_dcid: &[u8],
    pkt: &[u8],
    pn_offset: usize,
    dir: Dir,
) -> Result<Vec<u8>, &'static str> {
    if key_dcid.len() > 20 {
        return Err("cid_len");
    }
    let keys = cfg
        .initial_keys(version, &ConnectionId::new(key_dcid))
        .map_err(|_| "unsupported_version")?;
    let (hk, pk) = match dir {
        Dir::ToServer => (&keys.header.remote, &keys.packet.remote),
        Dir::ToClient => (&keys.header.local, &keys.packet.local),
    };
    // Для образца нужно pn_offset + 4 + sample_size байт, иначе библиотека выйдет за границы.
    let need = pn_offset.checked_add(4).and_then(|x| x.checked_add(hk.sample_size())).ok_or("length")?;
    if pkt.len() < need {
        return Err("too_short_for_sample");
    }
    let mut buf = pkt.to_vec();
    hk.decrypt(pn_offset, &mut buf);
    let pn_len = usize::from(*buf.first().ok_or("quic_short")? & 3) + 1;
    let hdr_len = pn_offset.checked_add(pn_len).ok_or("length")?;
    let pn_bytes = buf.get(pn_offset..hdr_len).ok_or("quic_short")?;
    let mut pn = 0u64;
    for x in pn_bytes {
        pn = (pn << 8) | u64::from(*x);
    }
    let header = buf.get(..hdr_len).ok_or("quic_short")?;
    let payload = buf.get(hdr_len..).ok_or("quic_short")?;
    if payload.len() < pk.tag_len() {
        return Err("payload_short");
    }
    // Тип BytesMut без зависимости `bytes`: выводится из сигнатуры PacketKey::decrypt.
    let mut p = From::from(payload);
    pk.decrypt(pn, header, &mut p).map_err(|_| "aead_fail")?;
    let plain: &[u8] = &p;
    Ok(plain.to_vec())
}

// ------------------------------------------------------------------ анализ

#[derive(Default, Debug)]
pub struct Report {
    pub lines: Vec<String>,
    pub datagrams: usize,
    pub initials: usize,
    pub client_decrypted: usize,
    pub server_decrypted: usize,
    pub hits: Vec<(String, String)>,
    pub alpn_found: bool,
    pub skips: usize,
    pub versions: Vec<u32>,
    pub dcid_lens: Vec<usize>,
    pub scid_lens: Vec<usize>,
    /// (scid клиента, первый dcid клиента) по соединениям.
    pub conns: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Report {
    pub fn verdict(&self) -> (&'static str, String) {
        if !self.hits.is_empty() {
            let h: Vec<String> = self.hits.iter().map(|(n, w)| format!("{n}@{w}")).collect();
            return ("FAIL", format!("найдены иглы: {}", h.join(",")));
        }
        if !self.alpn_found {
            return ("INCONCLUSIVE", "ALPN не найден в расшифрованном Initial клиента".into());
        }
        if self.server_decrypted == 0 {
            return ("INCONCLUSIVE", "ни один Initial сервера не расшифрован (AEAD)".into());
        }
        let scids: HashSet<&Vec<u8>> = self.conns.iter().map(|c| &c.0).collect();
        let dcids: HashSet<&Vec<u8>> = self.conns.iter().map(|c| &c.1).collect();
        if scids.len() < 2 || dcids.len() < 2 {
            return ("INCONCLUSIVE", format!("соединений с разными CID: scid={} dcid={}", scids.len(), dcids.len()));
        }
        ("PASS", "совпадений нет; положительные контроли выполнены".into())
    }
}

struct ClientInit {
    scid: Vec<u8>,
    dcid: Vec<u8>,
}

pub fn analyze(pcap: &[u8], needles: Vec<Needle>, alpn: &[u8], version: u32) -> Result<Report, BoxErr> {
    let mut rep = Report::default();
    let matcher = Matcher::new(needles);
    for s in matcher.short_needles() {
        rep.lines.push(format!("SKIP reason=needle_too_short needle={s}"));
    }
    let magic: [u8; 4] = pcap.get(..4).ok_or_else(|| err("pcap: короче заголовка"))?.try_into().map_err(|_| err("pcap"))?;
    let le = match u32::from_le_bytes(magic) {
        0xa1b2_c3d4 | 0xa1b2_3c4d => true,
        0xd4c3_b2a1 | 0x4d3c_b2a1 => false,
        _ => return Err(err("pcap: неизвестная сигнатура")),
    };
    let rd = Reader { d: pcap, le };
    let link = rd.u32(20).ok_or_else(|| err("pcap: нет заголовка"))?;
    if link != 1 {
        return Err(err(format!("pcap: ожидался Ethernet (1), linktype={link}")));
    }
    let cfg = initial_cfg()?;
    let mut off = 24usize;
    let mut dgs: Vec<Datagram<'_>> = Vec::new();
    let mut idx = 0usize;
    while off < pcap.len() {
        let (Some(incl), Some(_orig)) = (rd.u32(off + 8), rd.u32(off + 12)) else {
            rep.lines.push(format!("SKIP reason=pcap_record_header_truncated off={off}"));
            rep.skips += 1;
            break;
        };
        let incl = incl as usize;
        let start = off + 16;
        let Some(end) = start.checked_add(incl) else { break };
        if incl > MAX_RECORD || end > pcap.len() {
            rep.lines.push(format!("SKIP reason=pcap_record_truncated pkt={idx}"));
            rep.skips += 1;
            break;
        }
        off = end;
        idx += 1;
        let Some(frame) = pcap.get(start..end) else { break };
        match udp_of_frame(frame) {
            Ok((src, dst, payload)) => dgs.push(Datagram { idx: idx - 1, src, dst, payload }),
            Err(r) => {
                if r != "not_udp" && r != "not_ip" {
                    rep.lines.push(format!("SKIP reason={r} pkt={}", idx - 1));
                    rep.skips += 1;
                }
            }
        }
    }
    rep.datagrams = dgs.len();

    // Иглы в сыром UDP всех пакетов.
    for d in &dgs {
        for h in matcher.find(d.payload) {
            rep.hits.push((h, format!("raw_udp pkt={}", d.idx)));
        }
    }

    // Initial-пакеты: сначала направление клиент → сервер (ключ от своего DCID).
    struct Pending<'a> {
        dg: usize,
        bytes: &'a [u8],
        hdr: LongHdr,
    }
    let mut pending: Vec<Pending<'_>> = Vec::new();
    for (di, d) in dgs.iter().enumerate() {
        let mut rest = d.payload;
        while !rest.is_empty() {
            let hdr = match parse_long(rest) {
                Ok(h) => h,
                Err(r) => {
                    if r != "short_header" {
                        rep.lines.push(format!("SKIP reason={r} pkt={}", d.idx));
                        rep.skips += 1;
                    }
                    break;
                }
            };
            let Some(pkt) = rest.get(..hdr.pkt_len) else { break };
            let next = hdr.pkt_len;
            if hdr.ptype == 0 {
                if hdr.version != version && !(version == QUIC_V1 && hdr.version == QUIC_V1) {
                    rep.lines.push(format!("SKIP reason=version_mismatch pkt={} v={:#x}", d.idx, hdr.version));
                    rep.skips += 1;
                } else {
                    rep.initials += 1;
                    pending.push(Pending { dg: di, bytes: pkt, hdr });
                }
            }
            if hdr_is_last(next, rest.len()) {
                break;
            }
            rest = rest.get(next..).unwrap_or(&[]);
        }
    }

    let mut client_inits: Vec<ClientInit> = Vec::new();
    let mut by_scid: HashMap<Vec<u8>, Vec<Vec<u8>>> = HashMap::new();
    let mut client_plain: Vec<Vec<u8>> = Vec::new();
    let mut unresolved: Vec<&Pending<'_>> = Vec::new();
    for p in &pending {
        let d = &dgs[p.dg];
        match decrypt_initial(&cfg, p.hdr.version, &p.hdr.dcid, p.bytes, p.hdr.pn_offset, Dir::ToServer) {
            Ok(plain) => {
                rep.client_decrypted += 1;
                for h in matcher.find(&plain) {
                    rep.hits.push((h, format!("initial_client pkt={}", d.idx)));
                }
                if contains(&plain, alpn) {
                    rep.alpn_found = true;
                }
                rep.versions.push(p.hdr.version);
                rep.dcid_lens.push(p.hdr.dcid.len());
                rep.scid_lens.push(p.hdr.scid.len());
                let e = by_scid.entry(p.hdr.scid.clone()).or_default();
                if e.len() < MAX_CANDIDATES && !e.contains(&p.hdr.dcid) {
                    e.push(p.hdr.dcid.clone());
                }
                client_inits.push(ClientInit { scid: p.hdr.scid.clone(), dcid: p.hdr.dcid.clone() });
                client_plain.push(plain);
            }
            Err(_) => unresolved.push(p),
        }
    }
    // Остальные Initial: ключи выводятся от самого первого DCID клиента (после Retry от нового), а не от
    // текущего DCID пакета. Клиентские пакеты опознаём по своему SCID, серверные по DCID = SCID клиента.
    for p in unresolved {
        let d = &dgs[p.dg];
        let (cands, dir) = if let Some(c) = by_scid.get(&p.hdr.scid) {
            (c, Dir::ToServer)
        } else if let Some(c) = by_scid.get(&p.hdr.dcid) {
            (c, Dir::ToClient)
        } else {
            rep.lines.push(format!(
                "SKIP reason=no_key_candidate pkt={} src={}:{} len={} dcid={} scid={}",
                d.idx, d.src.0, d.src.1, p.bytes.len(), crate::util::hex(&p.hdr.dcid), crate::util::hex(&p.hdr.scid)
            ));
            rep.skips += 1;
            continue;
        };
        let mut done = false;
        for c in cands {
            if let Ok(plain) = decrypt_initial(&cfg, p.hdr.version, c, p.bytes, p.hdr.pn_offset, dir) {
                let (where_, ctr) = if dir == Dir::ToServer {
                    ("initial_client", &mut rep.client_decrypted)
                } else {
                    ("initial_server", &mut rep.server_decrypted)
                };
                *ctr += 1;
                for h in matcher.find(&plain) {
                    rep.hits.push((h, format!("{where_} pkt={}", d.idx)));
                }
                if dir == Dir::ToServer {
                    if contains(&plain, alpn) {
                        rep.alpn_found = true;
                    }
                    client_plain.push(plain);
                }
                done = true;
                break;
            }
        }
        if !done {
            rep.lines.push(format!(
                "SKIP reason=aead_fail pkt={} src={}:{} len={}",
                d.idx, d.src.0, d.src.1, p.bytes.len()
            ));
            rep.skips += 1;
        }
    }
    // Положительный контроль ALPN допускает разрыв между пакетами.
    if !rep.alpn_found {
        let all: Vec<u8> = client_plain.concat();
        if contains(&all, alpn) {
            rep.alpn_found = true;
        }
    }
    // Соединения: уникальные scid клиента и их первый DCID.
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    for ci in &client_inits {
        if seen.insert(ci.scid.clone()) {
            rep.conns.push((ci.scid.clone(), ci.dcid.clone()));
        }
    }
    Ok(rep)
}

fn hdr_is_last(consumed: usize, total: usize) -> bool {
    consumed >= total
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn le32(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    fn pcap_with(records: &[Vec<u8>]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&le32(0xa1b2_c3d4));
        p.extend_from_slice(&[2, 0, 4, 0]);
        p.extend_from_slice(&[0u8; 8]);
        p.extend_from_slice(&le32(65535));
        p.extend_from_slice(&le32(1));
        for r in records {
            p.extend_from_slice(&le32(0));
            p.extend_from_slice(&le32(0));
            p.extend_from_slice(&le32(r.len() as u32));
            p.extend_from_slice(&le32(r.len() as u32));
            p.extend_from_slice(r);
        }
        p
    }

    fn eth_ipv4_udp(payload: &[u8]) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend_from_slice(&[0x08, 0x00]);
        let tot = 20 + 8 + payload.len();
        let mut ip = vec![0x45, 0, (tot >> 8) as u8, tot as u8, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2];
        ip.extend_from_slice(&[0x12, 0x34, 0x11, 0x51]);
        let ulen = 8 + payload.len();
        ip.extend_from_slice(&[(ulen >> 8) as u8, ulen as u8, 0, 0]);
        ip.extend_from_slice(payload);
        f.extend_from_slice(&ip);
        f
    }

    #[test]
    fn observe_window_match_split_needle() {
        let needle: Vec<u8> = (0u8..32).map(|x| x.wrapping_mul(7).wrapping_add(3)).collect();
        let m = Matcher::new(vec![Needle { label: "pub".into(), bytes: needle.clone() }]);
        // Игла разорвана между кадрами: в данных только середина (8 байт) и мусор вокруг.
        let mut hay = vec![0xeeu8; 20];
        hay.extend_from_slice(&needle[12..20]);
        hay.extend_from_slice(&[0xddu8; 20]);
        assert_eq!(m.find(&hay), vec!["pub".to_string()]);
        // Нет совпадения: только 7 подряд идущих байт иглы.
        let mut hay2 = vec![0xeeu8; 20];
        hay2.extend_from_slice(&needle[12..19]);
        hay2.extend_from_slice(&[0xddu8; 20]);
        assert!(m.find(&hay2).is_empty());
        // Короткая игла-строка ищется целиком.
        let m2 = Matcher::new(vec![Needle { label: "s".into(), bytes: b"iroh.invalid".to_vec() }]);
        assert_eq!(m2.find(b"xxiroh.invalidyy"), vec!["s".to_string()]);
        assert!(m2.find(b"xxiroh.invalyy").is_empty());
        // Целиком через analyze: сырой UDP с иглой даёт FAIL.
        let mut payload = vec![0x40u8; 10];
        payload.extend_from_slice(&needle[4..12]);
        let pc = pcap_with(&[eth_ipv4_udp(&payload)]);
        let rep = analyze(&pc, vec![Needle { label: "pub".into(), bytes: needle }], b"alpn", 1).unwrap();
        assert_eq!(rep.hits.len(), 1);
        assert_eq!(rep.verdict().0, "FAIL");
    }

    #[test]
    fn observe_skips_truncated_packet() {
        // Усечённый QUIC long header в нормальной датаграмме.
        let quic = eth_ipv4_udp(&[0xc0, 0, 0, 0, 1, 20, 1, 2, 3]);
        // Усечённый IPv4 и усечённая запись pcap в конце.
        let short = vec![0u8; 14];
        let mut pc = pcap_with(&[quic, short, eth_ipv4_udp(&[0xc0u8; 40])]);
        let new_len = pc.len() - 10;
        pc.truncate(new_len);
        let rep = analyze(&pc, vec![], b"alpn", 1).unwrap();
        assert!(rep.skips >= 2, "{:?}", rep.lines);
        assert_eq!(rep.verdict().0, "INCONCLUSIVE");
        // Мусор вместо pcap не вызывает панику.
        assert!(analyze(&[1, 2, 3], vec![], b"a", 1).is_err());
    }
}
