//! Зонд типа NAT, отражатель и имитация посредника (спайк этапа 8). В продукт не идёт.
//! UDP-службы отвечают только на сообщения точной длины и ничего никуда не пересылают.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};

use crate::keys::rand16;
use crate::util::{BoxErr, err};

pub const PROBE_MAGIC: &[u8; 4] = b"CHP8";
pub const PROBE_REQ_LEN: usize = 13;
pub const PROBE_RSP_LEN: usize = 19;
pub const RDV_MAGIC: &[u8; 4] = b"CHR8";
pub const REG_LEN: usize = 21;
pub const GO_LEN: usize = 12;
/// Не больше стольких регистраций одновременно (недоверенный ввод).
pub const MAX_REGS: usize = 16;
const REG_TTL: Duration = Duration::from_secs(120);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatpErr {
    Len,
    Magic,
    Cmd,
    Side,
    V6,
}

impl std::fmt::Display for NatpErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for NatpErr {}

// ---------------------------------------------------------------- зонд

pub fn enc_probe_req(cmd: u8, nonce: [u8; 8]) -> [u8; PROBE_REQ_LEN] {
    let mut o = [0u8; PROBE_REQ_LEN];
    o[..4].copy_from_slice(PROBE_MAGIC);
    o[4] = cmd;
    o[5..13].copy_from_slice(&nonce);
    o
}

/// Запрос: ровно 13 байт, магия, cmd 1..=3.
pub fn parse_probe_req(b: &[u8]) -> Result<(u8, [u8; 8]), NatpErr> {
    if b.len() != PROBE_REQ_LEN {
        return Err(NatpErr::Len);
    }
    let (Some(m), Some(&cmd), Some(n)) = (b.get(..4), b.get(4), b.get(5..13)) else {
        return Err(NatpErr::Len);
    };
    if m != PROBE_MAGIC {
        return Err(NatpErr::Magic);
    }
    if !(1..=3).contains(&cmd) {
        return Err(NatpErr::Cmd);
    }
    let nonce = <[u8; 8]>::try_from(n).map_err(|_| NatpErr::Len)?;
    Ok((cmd, nonce))
}

fn put_addr(o: &mut Vec<u8>, a: SocketAddr) -> Result<(), NatpErr> {
    let IpAddr::V4(ip) = a.ip() else {
        return Err(NatpErr::V6);
    };
    o.extend_from_slice(&ip.octets());
    o.extend_from_slice(&a.port().to_be_bytes());
    Ok(())
}

fn get_addr(b: &[u8]) -> Result<SocketAddr, NatpErr> {
    let (Some(ip), Some(p)) = (b.get(..4), b.get(4..6)) else {
        return Err(NatpErr::Len);
    };
    let ip = <[u8; 4]>::try_from(ip).map_err(|_| NatpErr::Len)?;
    let p = <[u8; 2]>::try_from(p).map_err(|_| NatpErr::Len)?;
    Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), u16::from_be_bytes(p)))
}

pub fn enc_probe_rsp(cmd: u8, nonce: [u8; 8], seen: SocketAddr) -> Result<Vec<u8>, NatpErr> {
    let mut o = Vec::with_capacity(PROBE_RSP_LEN);
    o.extend_from_slice(PROBE_MAGIC);
    o.push(cmd);
    o.extend_from_slice(&nonce);
    put_addr(&mut o, seen)?;
    Ok(o)
}

/// Ответ: ровно 19 байт.
pub fn parse_probe_rsp(b: &[u8]) -> Result<(u8, [u8; 8], SocketAddr), NatpErr> {
    if b.len() != PROBE_RSP_LEN {
        return Err(NatpErr::Len);
    }
    let (Some(m), Some(&cmd), Some(n), Some(a)) = (b.get(..4), b.get(4), b.get(5..13), b.get(13..19)) else {
        return Err(NatpErr::Len);
    };
    if m != PROBE_MAGIC {
        return Err(NatpErr::Magic);
    }
    let nonce = <[u8; 8]>::try_from(n).map_err(|_| NatpErr::Len)?;
    Ok((cmd, nonce, get_addr(a)?))
}

/// Отражатель на трёх адресах (R1a, R1b, R2). Эхо: ответ с того же гнезда; cmd 2: ответ с R1b; cmd 3: с R2.
pub async fn reflect(binds: [SocketAddr; 3]) -> Result<(), BoxErr> {
    let mut socks = Vec::new();
    for a in binds {
        socks.push(Arc::new(UdpSocket::bind(a).await.map_err(|e| err(format!("bind {a}: {e}")))?));
    }
    crate::ev!("reflect_bound", "r1a={} r1b={} r2={}", binds[0], binds[1], binds[2]);
    let mut tasks = Vec::new();
    for i in 0..3usize {
        let socks = socks.clone();
        tasks.push(tokio::spawn(async move {
            let Some(me) = socks.get(i).cloned() else { return };
            let mut buf = [0u8; 64];
            loop {
                let Ok((n, from)) = me.recv_from(&mut buf).await else { continue };
                let Some(pkt) = buf.get(..n) else { continue };
                let Ok((cmd, nonce)) = parse_probe_req(pkt) else { continue };
                let out_idx = match cmd {
                    2 => 1,
                    3 => 2,
                    _ => i,
                };
                let Some(out) = socks.get(out_idx) else { continue };
                let Ok(rsp) = enc_probe_rsp(cmd, nonce, from) else { continue };
                let _ = out.send_to(&rsp, from).await;
            }
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub mapping: &'static str,
    pub filtering: &'static str,
    pub ext_r1a: Option<SocketAddr>,
    pub ext_r1b: Option<SocketAddr>,
    pub ext_r2: Option<SocketAddr>,
    pub r1b_reply: bool,
    pub r2_reply: bool,
}

/// Одно обращение: запрос `cmd` на `to`, ждём ответ `cmd` с адреса `from` (None = любой), до 3 попыток по 1 с.
async fn exchange(sock: &UdpSocket, to: SocketAddr, cmd: u8, from: SocketAddr) -> Option<SocketAddr> {
    let mut nonce = [0u8; 8];
    nonce.copy_from_slice(rand16().ok()?.get(..8)?);
    let req = enc_probe_req(cmd, nonce);
    let mut buf = [0u8; 64];
    for _ in 0..3 {
        sock.send_to(&req, to).await.ok()?;
        let end = Instant::now() + Duration::from_secs(1);
        loop {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let Ok(Ok((n, src))) = timeout(left, sock.recv_from(&mut buf)).await else { break };
            if src != from {
                continue;
            }
            let Some(pkt) = buf.get(..n) else { continue };
            if let Ok((c, nn, seen)) = parse_probe_rsp(pkt)
                && c == cmd
                && nn == nonce
            {
                return Some(seen);
            }
        }
    }
    None
}

/// Зонд: порядок из спецификации. Гнездо `local` одно на все обращения.
pub async fn probe(local: SocketAddr, r1a: SocketAddr, r1b: SocketAddr, r2: SocketAddr) -> Result<ProbeResult, BoxErr> {
    let sock = UdpSocket::bind(local).await.map_err(|e| err(format!("bind {local}: {e}")))?;
    let ext_r1a = exchange(&sock, r1a, 1, r1a).await;
    let r1b_ans = exchange(&sock, r1a, 2, r1b).await;
    let r2_ans = exchange(&sock, r1a, 3, r2).await;
    let ext_r1b = exchange(&sock, r1b, 1, r1b).await;
    let ext_r2 = exchange(&sock, r2, 1, r2).await;
    let mapping = match (ext_r1a, ext_r1b, ext_r2) {
        (Some(a), Some(b), Some(c)) if a == b && b == c => "EIM",
        (Some(_), Some(_), Some(_)) => "EDM",
        _ => "UNKNOWN",
    };
    let filtering = match (r1b_ans.is_some(), r2_ans.is_some()) {
        (true, true) => "EIF",
        (true, false) => "ADF",
        (false, false) => "APDF",
        (false, true) => "ODD",
    };
    Ok(ProbeResult {
        mapping,
        filtering,
        ext_r1a,
        ext_r1b,
        ext_r2,
        r1b_reply: r1b_ans.is_some(),
        r2_reply: r2_ans.is_some(),
    })
}

// ---------------------------------------------------------------- посредник (имитация)

pub fn enc_reg(tag: [u8; 16], side: u8) -> [u8; REG_LEN] {
    let mut o = [0u8; REG_LEN];
    o[..4].copy_from_slice(RDV_MAGIC);
    o[4..20].copy_from_slice(&tag);
    o[20] = side;
    o
}

/// REG: ровно 21 байт, сторона 1 или 2.
pub fn parse_reg(b: &[u8]) -> Result<([u8; 16], u8), NatpErr> {
    if b.len() != REG_LEN {
        return Err(NatpErr::Len);
    }
    let (Some(m), Some(t), Some(&side)) = (b.get(..4), b.get(4..20), b.get(20)) else {
        return Err(NatpErr::Len);
    };
    if m != RDV_MAGIC {
        return Err(NatpErr::Magic);
    }
    if side != 1 && side != 2 {
        return Err(NatpErr::Side);
    }
    Ok((<[u8; 16]>::try_from(t).map_err(|_| NatpErr::Len)?, side))
}

pub fn enc_go(peer: SocketAddr, delay_ms: u16) -> Result<[u8; GO_LEN], NatpErr> {
    let mut v = Vec::with_capacity(GO_LEN);
    v.extend_from_slice(RDV_MAGIC);
    put_addr(&mut v, peer)?;
    v.extend_from_slice(&delay_ms.to_be_bytes());
    <[u8; GO_LEN]>::try_from(v.as_slice()).map_err(|_| NatpErr::Len)
}

/// GO: ровно 12 байт.
pub fn parse_go(b: &[u8]) -> Result<(SocketAddr, u16), NatpErr> {
    if b.len() != GO_LEN {
        return Err(NatpErr::Len);
    }
    let (Some(m), Some(a), Some(d)) = (b.get(..4), b.get(4..10), b.get(10..12)) else {
        return Err(NatpErr::Len);
    };
    if m != RDV_MAGIC {
        return Err(NatpErr::Magic);
    }
    let d = <[u8; 2]>::try_from(d).map_err(|_| NatpErr::Len)?;
    Ok((get_addr(a)?, u16::from_be_bytes(d)))
}

struct Reg {
    tag: [u8; 16],
    sides: [Option<SocketAddr>; 2],
    paired: Option<Instant>,
    touched: Instant,
}

/// Состояние посредника: только регистрации и ответы GO, пересылки данных нет.
#[derive(Default)]
pub struct Rdv {
    regs: Vec<Reg>,
}

pub const GO_DELAY_MS: u16 = 500;

impl Rdv {
    pub fn len(&self) -> usize {
        self.regs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.regs.is_empty()
    }

    /// Обрабатывает REG. Возвращает пары (кому, GO).
    pub fn on_reg(&mut self, tag: [u8; 16], side: u8, from: SocketAddr, now: Instant) -> Vec<(SocketAddr, [u8; GO_LEN])> {
        self.regs.retain(|r| now.saturating_duration_since(r.touched) < REG_TTL);
        let si = usize::from(side.saturating_sub(1)).min(1);
        let pos = match self.regs.iter().position(|r| r.tag == tag) {
            Some(p) => p,
            None => {
                if self.regs.len() >= MAX_REGS {
                    return Vec::new();
                }
                self.regs.push(Reg { tag, sides: [None, None], paired: None, touched: now });
                self.regs.len() - 1
            }
        };
        let Some(r) = self.regs.get_mut(pos) else { return Vec::new() };
        r.touched = now;
        if let Some(s) = r.sides.get_mut(si) {
            *s = Some(from);
        }
        let (Some(a), Some(b)) = (r.sides[0], r.sides[1]) else { return Vec::new() };
        let mut out = Vec::new();
        match r.paired {
            None => {
                r.paired = Some(now);
                if let Ok(g) = enc_go(b, GO_DELAY_MS) {
                    out.push((a, g));
                }
                if let Ok(g) = enc_go(a, GO_DELAY_MS) {
                    out.push((b, g));
                }
            }
            Some(t0) => {
                // повторный REG уже спаренной стороны: GO только ей, с остатком задержки
                let left = Duration::from_millis(u64::from(GO_DELAY_MS)).saturating_sub(now.saturating_duration_since(t0));
                let d = u16::try_from(left.as_millis()).unwrap_or(0);
                let (to, other) = if si == 0 { (a, b) } else { (b, a) };
                if let Ok(g) = enc_go(other, d) {
                    out.push((to, g));
                }
            }
        }
        out
    }
}

pub async fn rdv_serve(listen: SocketAddr) -> Result<(), BoxErr> {
    let sock = UdpSocket::bind(listen).await.map_err(|e| err(format!("bind {listen}: {e}")))?;
    crate::ev!("rdv_bound", "addr={listen}");
    let mut st = Rdv::default();
    let mut buf = [0u8; 64];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf).await else { continue };
        let Some(pkt) = buf.get(..n) else { continue };
        let Ok((tag, side)) = parse_reg(pkt) else { continue };
        if !from.is_ipv4() {
            continue;
        }
        crate::ev!("rdv_reg", "side={side} from={from}");
        for (to, go) in st.on_reg(tag, side, from, Instant::now()) {
            let _ = sock.send_to(&go, to).await;
            crate::ev!("rdv_go", "to={to}");
        }
    }
}

/// Регистрация с готового std-гнезда до передачи его в quinn: REG раз в секунду, пока не придёт GO.
/// Возвращает (адрес другой стороны, задержка мс). Блокирующая функция (вызывать в `spawn_blocking`).
pub fn rdv_register_blocking(
    sock: &std::net::UdpSocket,
    rdv: SocketAddr,
    tag: [u8; 16],
    side: u8,
    wait: Duration,
) -> Result<(SocketAddr, u16), BoxErr> {
    sock.set_read_timeout(Some(Duration::from_millis(250)))?;
    let reg = enc_reg(tag, side);
    let end = std::time::Instant::now() + wait;
    let mut last = None::<std::time::Instant>;
    let mut buf = [0u8; 64];
    while std::time::Instant::now() < end {
        if last.is_none_or(|t| t.elapsed() >= Duration::from_secs(1)) {
            sock.send_to(&reg, rdv)?;
            last = Some(std::time::Instant::now());
        }
        match sock.recv_from(&mut buf) {
            Ok((n, src)) if src == rdv => {
                if let Some(p) = buf.get(..n)
                    && let Ok(go) = parse_go(p)
                {
                    sock.set_read_timeout(None)?;
                    return Ok(go);
                }
            }
            Ok(_) => {}
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(e) => return Err(e.into()),
        }
    }
    Err(err("rdv: GO не получен до дедлайна"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_rejects_bad_len() {
        let ok = enc_probe_req(1, [1; 8]);
        assert_eq!(parse_probe_req(&ok), Ok((1, [1; 8])));
        for n in 0..PROBE_REQ_LEN {
            assert_eq!(parse_probe_req(&ok[..n]), Err(NatpErr::Len), "n={n}");
        }
        let mut long = ok.to_vec();
        long.push(0);
        assert_eq!(parse_probe_req(&long), Err(NatpErr::Len));
        let mut bad = ok;
        bad[4] = 4;
        assert_eq!(parse_probe_req(&bad), Err(NatpErr::Cmd));
        bad[4] = 0;
        assert_eq!(parse_probe_req(&bad), Err(NatpErr::Cmd));
        let mut bad = ok;
        bad[0] = b'X';
        assert_eq!(parse_probe_req(&bad), Err(NatpErr::Magic));
        let a: SocketAddr = "198.51.100.10:4433".parse().expect("addr");
        let rsp = enc_probe_rsp(2, [9; 8], a).expect("rsp");
        assert_eq!(rsp.len(), PROBE_RSP_LEN);
        assert_eq!(parse_probe_rsp(&rsp), Ok((2, [9; 8], a)));
        for n in 0..PROBE_RSP_LEN {
            assert!(parse_probe_rsp(&rsp[..n]).is_err(), "n={n}");
        }
        assert_eq!(enc_probe_rsp(1, [0; 8], "[::1]:1".parse().expect("v6")), Err(NatpErr::V6));
    }

    #[test]
    fn rdv_rejects_bad_len() {
        let ok = enc_reg([5; 16], 1);
        assert_eq!(parse_reg(&ok), Ok(([5; 16], 1)));
        for n in 0..REG_LEN {
            assert_eq!(parse_reg(&ok[..n]), Err(NatpErr::Len), "n={n}");
        }
        let mut long = ok.to_vec();
        long.push(0);
        assert_eq!(parse_reg(&long), Err(NatpErr::Len));
        let mut bad = ok;
        bad[20] = 3;
        assert_eq!(parse_reg(&bad), Err(NatpErr::Side));
        bad[20] = 0;
        assert_eq!(parse_reg(&bad), Err(NatpErr::Side));
        let mut bad = ok;
        bad[1] = b'x';
        assert_eq!(parse_reg(&bad), Err(NatpErr::Magic));
        let a: SocketAddr = "198.51.100.10:4433".parse().expect("addr");
        let go = enc_go(a, 500).expect("go");
        assert_eq!(go.len(), GO_LEN);
        assert_eq!(parse_go(&go), Ok((a, 500)));
        for n in 0..GO_LEN {
            assert!(parse_go(&go[..n]).is_err(), "n={n}");
        }
        assert_eq!(enc_go("[::1]:1".parse().expect("v6"), 1), Err(NatpErr::V6));
    }

    #[tokio::test]
    async fn rdv_pairs_and_limits_registrations() {
        let mut r = Rdv::default();
        let a: SocketAddr = "198.51.100.10:4433".parse().expect("a");
        let b: SocketAddr = "198.51.100.20:4433".parse().expect("b");
        let t = Instant::now();
        assert!(r.on_reg([1; 16], 1, a, t).is_empty());
        let out = r.on_reg([1; 16], 2, b, t);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, a);
        assert_eq!(parse_go(&out[0].1), Ok((b, GO_DELAY_MS)));
        assert_eq!(out[1].0, b);
        assert_eq!(parse_go(&out[1].1), Ok((a, GO_DELAY_MS)));
        for i in 0..40u8 {
            let _ = r.on_reg([100 + i; 16], 1, a, t);
        }
        assert!(r.len() <= MAX_REGS);
    }
}
