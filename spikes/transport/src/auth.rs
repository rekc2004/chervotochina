//! U10b в упрощённом виде для спайка: подписи ключом пары над экспортёром TLS.
//! Своей криптографии нет: Ed25519 только вызовами ed25519-dalek, экспортёр отдаёт транспорт.
use std::future::Future;
use std::time::Duration;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout_at};

use crate::util::BoxErr;

pub const TAG: &[u8] = b"chervotochina/v1/conn-auth\0";
pub const EKM_LABEL: &[u8] = b"EXPERIMENTAL-chervotochina-conn-auth-v1";
pub const EKM_CONTEXT: &[u8] = b"";
pub const AUTH1_LEN: usize = 82;
pub const AUTH2_LEN: usize = 66;
pub const AUTH1_READ_LIMIT: usize = 83;
pub const AUTH2_READ_LIMIT: usize = 67;
pub const AUTH_TIMEOUT: Duration = Duration::from_secs(5);
pub const ROLE_CALLER: u8 = 0x01;
pub const ROLE_CALLEE: u8 = 0x02;
pub const VERSION: u8 = 0x01;

pub type PairId = [u8; 16];

pub struct PairKeys {
    pub id: PairId,
    pub caller_sk: SigningKey,
    pub caller_pk: VerifyingKey,
    pub callee_sk: SigningKey,
    pub callee_pk: VerifyingKey,
}

pub struct PairSet(pub Vec<PairKeys>);

impl PairSet {
    pub fn find(&self, id: &PairId) -> Option<&PairKeys> {
        self.0.iter().find(|p| &p.id == id)
    }
}

/// Транспорт, на котором работает аутентификация.
pub trait Conn: Send + Sync + 'static {
    type S: AsyncWrite + Unpin + Send + 'static;
    type R: AsyncRead + Unpin + Send + 'static;
    fn open_bi(&self) -> impl Future<Output = Result<(Self::S, Self::R), BoxErr>> + Send;
    fn accept_bi(&self) -> impl Future<Output = Result<(Self::S, Self::R), BoxErr>> + Send;
    /// Экспортёр TLS: метка `EKM_LABEL`, контекст `EKM_CONTEXT`, 32 байта.
    fn ekm(&self, out: &mut [u8; 32]) -> Result<(), BoxErr>;
    fn close(&self, code: u32);
    fn wait_closed(&self) -> impl Future<Output = String> + Send;
    fn peer_identity(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthFail {
    Len,
    Ver,
    Role,
    Pair,
    Sig,
    Timeout,
    PeerSig,
    Closed(String),
}

impl AuthFail {
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Len => "len",
            Self::Ver => "ver",
            Self::Role => "role",
            Self::Pair => "pair",
            Self::Sig => "sig",
            Self::Timeout => "timeout",
            Self::PeerSig => "peer_sig",
            Self::Closed(_) => "closed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Ok,
    BadSig,
    WrongPair,
    WrongKey,
    OtherConn,
    WrongRole,
    Timeout,
    TooLong,
    EarlyApp,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "ok" => Self::Ok,
            "bad-sig" => Self::BadSig,
            "wrong-pair" => Self::WrongPair,
            "wrong-key" => Self::WrongKey,
            "other-conn" => Self::OtherConn,
            "wrong-role" => Self::WrongRole,
            "timeout" => Self::Timeout,
            "too-long" => Self::TooLong,
            "early-app" => Self::EarlyApp,
            _ => return None,
        })
    }
}

fn sig_msg(role: u8, pair: &PairId, ekm: &[u8; 32]) -> Vec<u8> {
    let mut m = Vec::with_capacity(TAG.len() + 1 + 16 + 32);
    m.extend_from_slice(TAG);
    m.push(role);
    m.extend_from_slice(pair);
    m.extend_from_slice(ekm);
    m
}

fn sign(sk: &SigningKey, role: u8, pair: &PairId, ekm: &[u8; 32]) -> [u8; 64] {
    sk.sign(&sig_msg(role, pair, ekm)).to_bytes()
}

fn verify(pk: &VerifyingKey, role: u8, pair: &PairId, ekm: &[u8; 32], sig: &[u8]) -> bool {
    let Ok(arr) = <[u8; 64]>::try_from(sig) else {
        return false;
    };
    pk.verify_strict(&sig_msg(role, pair, ekm), &Signature::from_bytes(&arr))
        .is_ok()
}

/// Чтение не больше `max` байт до EOF, до `deadline`. Возвращает (данные, дошли ли до EOF).
pub async fn read_limited<R: AsyncRead + Unpin>(
    r: &mut R,
    max: usize,
    deadline: Instant,
) -> Result<(Vec<u8>, bool), AuthFail> {
    let mut out: Vec<u8> = Vec::new();
    let mut buf = [0u8; 128];
    while out.len() < max {
        let want = (max - out.len()).min(buf.len());
        let Some(slot) = buf.get_mut(..want) else {
            return Err(AuthFail::Len);
        };
        match timeout_at(deadline, r.read(slot)).await {
            Err(_) => return Err(AuthFail::Timeout),
            Ok(Err(e)) => return Err(AuthFail::Closed(e.to_string())),
            Ok(Ok(0)) => return Ok((out, true)),
            Ok(Ok(n)) => {
                if let Some(chunk) = buf.get(..n) {
                    out.extend_from_slice(chunk);
                }
            }
        }
    }
    Ok((out, false))
}

/// Вызываемая сторона. Ничего не пишет до успешной проверки AUTH1; второй поток не принимает.
/// При `Err` вызывающий обязан сделать `conn.close(1)`.
pub async fn callee_auth<C: Conn>(
    conn: &C,
    pairs: &PairSet,
    ekm: &[u8; 32],
    bad_auth2: bool,
) -> Result<PairId, AuthFail> {
    let deadline = Instant::now() + AUTH_TIMEOUT;
    let (mut s, mut r) = match timeout_at(deadline, conn.accept_bi()).await {
        Err(_) => return Err(AuthFail::Timeout),
        Ok(Err(e)) => return Err(AuthFail::Closed(e.to_string())),
        Ok(Ok(p)) => p,
    };
    let (data, _eof) = read_limited(&mut r, AUTH1_READ_LIMIT, deadline).await?;
    if data.len() != AUTH1_LEN {
        return Err(AuthFail::Len);
    }
    let (Some(&ver), Some(&role), Some(pid), Some(sig)) =
        (data.first(), data.get(1), data.get(2..18), data.get(18..82))
    else {
        return Err(AuthFail::Len);
    };
    if ver != VERSION {
        return Err(AuthFail::Ver);
    }
    if role != ROLE_CALLER {
        return Err(AuthFail::Role);
    }
    let Ok(pid) = PairId::try_from(pid) else {
        return Err(AuthFail::Len);
    };
    let Some(pair) = pairs.find(&pid) else {
        return Err(AuthFail::Pair);
    };
    if !verify(&pair.caller_pk, ROLE_CALLER, &pid, ekm, sig) {
        return Err(AuthFail::Sig);
    }
    let mut sig2 = sign(&pair.callee_sk, ROLE_CALLEE, &pid, ekm);
    if bad_auth2 {
        sig2[0] ^= 0x01;
    }
    let mut out = Vec::with_capacity(AUTH2_LEN);
    out.push(VERSION);
    out.push(ROLE_CALLEE);
    out.extend_from_slice(&sig2);
    s.write_all(&out)
        .await
        .map_err(|e| AuthFail::Closed(e.to_string()))?;
    s.shutdown()
        .await
        .map_err(|e| AuthFail::Closed(e.to_string()))?;
    Ok(pid)
}

pub struct CallerCfg<'a> {
    pub mode: Mode,
    pub pair: &'a PairKeys,
    /// Ключи другой пары (для `wrong-key`).
    pub other: &'a PairKeys,
    /// EKM другого соединения (для `other-conn`).
    pub ekm_override: Option<[u8; 32]>,
    /// Случайный pair_id для `wrong-pair`.
    pub random_pair: PairId,
}

#[derive(Default)]
pub struct Stats {
    pub app_sent: u64,
}

fn closed<E: std::fmt::Display>(e: E) -> AuthFail {
    AuthFail::Closed(e.to_string())
}

/// Звонящая сторона. Возвращает Ok только если AUTH2 проверен.
pub async fn caller_auth<C: Conn>(
    conn: &C,
    cfg: &CallerCfg<'_>,
    ekm: &[u8; 32],
    stats: &mut Stats,
) -> Result<(), AuthFail> {
    let (mut s, mut r) = conn.open_bi().await.map_err(closed)?;
    let mut read_for = AUTH_TIMEOUT;
    match cfg.mode {
        Mode::Timeout => {
            read_for = Duration::from_secs(12);
        }
        Mode::TooLong => {
            s.write_all(&vec![0x01u8; 4096]).await.map_err(closed)?;
            s.shutdown().await.map_err(closed)?;
        }
        Mode::EarlyApp => {
            let (mut s2, _r2) = conn.open_bi().await.map_err(closed)?;
            let app = [0x5au8; 256];
            s2.write_all(&app).await.map_err(closed)?;
            stats.app_sent += app.len() as u64;
        }
        m => {
            let role = if m == Mode::WrongRole { ROLE_CALLEE } else { ROLE_CALLER };
            let pid = if m == Mode::WrongPair { cfg.random_pair } else { cfg.pair.id };
            let sk = if m == Mode::WrongKey { &cfg.other.caller_sk } else { &cfg.pair.caller_sk };
            let used = if m == Mode::OtherConn { cfg.ekm_override.unwrap_or(*ekm) } else { *ekm };
            let mut sig = sign(sk, role, &pid, &used);
            if m == Mode::BadSig {
                sig[10] ^= 0x01;
            }
            let mut out = Vec::with_capacity(AUTH1_LEN);
            out.push(VERSION);
            out.push(role);
            out.extend_from_slice(&pid);
            out.extend_from_slice(&sig);
            s.write_all(&out).await.map_err(closed)?;
            s.shutdown().await.map_err(closed)?;
        }
    }
    let deadline = Instant::now() + read_for;
    let (data, eof) = read_limited(&mut r, AUTH2_READ_LIMIT, deadline).await?;
    if data.is_empty() && eof {
        return Err(AuthFail::Closed("eof".into()));
    }
    check_auth2(&data, cfg.pair, ekm)
}

fn check_auth2(data: &[u8], pair: &PairKeys, ekm: &[u8; 32]) -> Result<(), AuthFail> {
    if data.len() != AUTH2_LEN {
        return Err(AuthFail::Len);
    }
    let (Some(&ver), Some(&role), Some(sig)) = (data.first(), data.get(1), data.get(2..66)) else {
        return Err(AuthFail::Len);
    };
    if ver != VERSION {
        return Err(AuthFail::Ver);
    }
    if role != ROLE_CALLEE {
        return Err(AuthFail::Role);
    }
    if !verify(&pair.callee_pk, ROLE_CALLEE, &pair.id, ekm, sig) {
        return Err(AuthFail::PeerSig);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::io::{DuplexStream, ReadHalf, WriteHalf, duplex, split};

    struct TestConn {
        ekm: [u8; 32],
        slot: std::sync::Arc<Mutex<Option<DuplexStream>>>,
        peer_slot: std::sync::Arc<Mutex<Option<DuplexStream>>>,
        closed: AtomicU32,
    }

    fn test_pair(ekm_a: [u8; 32], ekm_b: [u8; 32]) -> (TestConn, TestConn) {
        let a2b = std::sync::Arc::new(Mutex::new(None));
        let b2a = std::sync::Arc::new(Mutex::new(None));
        (
            TestConn { ekm: ekm_a, slot: b2a.clone(), peer_slot: a2b.clone(), closed: AtomicU32::new(0) },
            TestConn { ekm: ekm_b, slot: a2b, peer_slot: b2a, closed: AtomicU32::new(0) },
        )
    }

    impl Conn for TestConn {
        type S = WriteHalf<DuplexStream>;
        type R = ReadHalf<DuplexStream>;
        async fn open_bi(&self) -> Result<(Self::S, Self::R), BoxErr> {
            let (a, b) = duplex(8192);
            *self.peer_slot.lock().unwrap() = Some(b);
            let (r, w) = split(a);
            Ok((w, r))
        }
        async fn accept_bi(&self) -> Result<(Self::S, Self::R), BoxErr> {
            loop {
                if let Some(d) = self.slot.lock().unwrap().take() {
                    let (r, w) = split(d);
                    return Ok((w, r));
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        fn ekm(&self, out: &mut [u8; 32]) -> Result<(), BoxErr> {
            *out = self.ekm;
            Ok(())
        }
        fn close(&self, code: u32) {
            self.closed.store(code, Ordering::SeqCst);
        }
        async fn wait_closed(&self) -> String {
            String::new()
        }
    }

    fn mkpair(seed: u8) -> PairKeys {
        let ck = SigningKey::from_bytes(&[seed; 32]);
        let ee = SigningKey::from_bytes(&[seed.wrapping_add(100); 32]);
        PairKeys {
            id: [seed; 16],
            caller_pk: ck.verifying_key(),
            caller_sk: ck,
            callee_pk: ee.verifying_key(),
            callee_sk: ee,
        }
    }

    async fn run(
        mode: Mode,
        ekm_c: [u8; 32],
        ekm_s: [u8; 32],
        ovr: Option<[u8; 32]>,
        bad2: bool,
    ) -> (Result<PairId, AuthFail>, Result<(), AuthFail>) {
        let (c, s) = test_pair(ekm_c, ekm_s);
        let p1 = mkpair(1);
        let p2 = mkpair(2);
        let server_pairs = PairSet(vec![mkpair(1), mkpair(2)]);
        let cfg = CallerCfg { mode, pair: &p1, other: &p2, ekm_override: ovr, random_pair: [9; 16] };
        let mut st = Stats::default();
        let srv = callee_auth(&s, &server_pairs, &ekm_s, bad2);
        let cli = async {
            let r = caller_auth(&c, &cfg, &ekm_c, &mut st).await;
            r
        };
        let (sr, cr) = tokio::join!(srv, cli);
        (sr, cr)
    }

    #[tokio::test]
    async fn auth_roundtrip_ok() {
        let (s, c) = run(Mode::Ok, [7; 32], [7; 32], None, false).await;
        assert_eq!(s, Ok([1; 16]));
        assert_eq!(c, Ok(()));
    }

    #[tokio::test]
    async fn auth_rejects_bad_sig() {
        let (s, c) = run(Mode::BadSig, [7; 32], [7; 32], None, false).await;
        assert_eq!(s, Err(AuthFail::Sig));
        assert!(matches!(c, Err(AuthFail::Closed(_))), "{c:?}");
    }

    #[tokio::test]
    async fn auth_rejects_wrong_role() {
        let (s, _) = run(Mode::WrongRole, [7; 32], [7; 32], None, false).await;
        assert_eq!(s, Err(AuthFail::Role));
    }

    #[tokio::test]
    async fn auth_rejects_wrong_key() {
        let (s, _) = run(Mode::WrongKey, [7; 32], [7; 32], None, false).await;
        assert_eq!(s, Err(AuthFail::Sig));
    }

    #[tokio::test]
    async fn auth_rejects_unknown_pair() {
        let (s, _) = run(Mode::WrongPair, [7; 32], [7; 32], None, false).await;
        assert_eq!(s, Err(AuthFail::Pair));
    }

    #[tokio::test]
    async fn auth_rejects_other_ekm() {
        let (s, _) = run(Mode::OtherConn, [7; 32], [7; 32], Some([8; 32]), false).await;
        assert_eq!(s, Err(AuthFail::Sig));
        // EKM у сторон разные (как при MITM из двух TLS-сессий).
        let (s2, _) = run(Mode::Ok, [7; 32], [8; 32], None, false).await;
        assert_eq!(s2, Err(AuthFail::Sig));
    }

    #[tokio::test]
    async fn auth_rejects_len_81_and_83() {
        for n in [81usize, 83, 0, 4096] {
            let (c, s) = test_pair([7; 32], [7; 32]);
            let pairs = PairSet(vec![mkpair(1)]);
            let srv = callee_auth(&s, &pairs, &[7; 32], false);
            let cli = async {
                let (mut w, _r) = c.open_bi().await.unwrap();
                w.write_all(&vec![0x01u8; n]).await.unwrap();
                w.shutdown().await.unwrap();
            };
            let (sr, ()) = tokio::join!(srv, cli);
            assert_eq!(sr, Err(AuthFail::Len), "n={n}");
        }
    }

    #[tokio::test]
    async fn auth_rejects_bad_auth2() {
        let (s, c) = run(Mode::Ok, [7; 32], [7; 32], None, true).await;
        assert_eq!(s, Ok([1; 16]));
        assert_eq!(c, Err(AuthFail::PeerSig));
    }
}
