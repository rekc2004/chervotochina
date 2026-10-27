#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;

use chervo_identity::{
    GuestSecret, IdentityError, PairId, PairKey, SecretStore, SignDomain, create,
};
use chervo_token::{
    InviteDraft, InviteToken, InviteeSession, M1_LEN, PendingInvite, Token, decode, issue_invite,
};
use zeroize::Zeroizing;

#[derive(Default)]
pub struct MemStore {
    map: Mutex<HashMap<PairId, Zeroizing<Vec<u8>>>>,
}

impl SecretStore for MemStore {
    fn read(&self, pair: &PairId) -> Result<Option<Zeroizing<Vec<u8>>>, IdentityError> {
        Ok(self
            .map
            .lock()
            .unwrap()
            .get(pair)
            .map(|v| Zeroizing::new(v.to_vec())))
    }

    fn write(&self, pair: &PairId, blob: &[u8]) -> Result<(), IdentityError> {
        self.map
            .lock()
            .unwrap()
            .insert(*pair, Zeroizing::new(blob.to_vec()));
        Ok(())
    }

    fn delete(&self, pair: &PairId) -> Result<(), IdentityError> {
        self.map.lock().unwrap().remove(pair);
        Ok(())
    }
}

/// Новый ключ пары.
pub fn key() -> PairKey {
    create(&MemStore::default(), &PairId::generate().unwrap()).unwrap()
}

pub fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

pub fn draft(ttl: u64) -> InviteDraft {
    InviteDraft {
        issued_at: 1_000_000,
        ttl_secs: ttl,
        addrs: vec![addr("203.0.113.7:4455")],
    }
}

// ---------- независимый base32 (сторона теста) ----------

const ALPHA: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub fn b32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut bits: Vec<bool> = Vec::new();
    for b in data {
        for i in (0..8).rev() {
            bits.push((b >> i) & 1 == 1);
        }
    }
    for chunk in bits.chunks(5) {
        let mut v = 0usize;
        for i in 0..5 {
            v = (v << 1) | usize::from(*chunk.get(i).unwrap_or(&false));
        }
        out.push(ALPHA[v] as char);
    }
    out
}

/// Разбор без проверок каноничности: байты по полным восьмёркам бит.
pub fn b32_decode(s: &str) -> Vec<u8> {
    let mut bits: Vec<bool> = Vec::new();
    for c in s.bytes() {
        let v = ALPHA.iter().position(|a| *a == c).expect("символ base32");
        for i in (0..5).rev() {
            bits.push((v >> i) & 1 == 1);
        }
    }
    bits.as_chunks::<8>()
        .0
        .iter()
        .map(|c| c.iter().fold(0u8, |a, b| (a << 1) | u8::from(*b)))
        .collect()
}

/// Двоичные байты токена из текста `CHV1…` или `CHR1…`.
pub fn text_bytes(text: &str) -> Vec<u8> {
    b32_decode(&text[4..])
}

// ---------- построитель приглашения (независимая реализация формата) ----------

pub struct Fields {
    pub issued: u64,
    pub expires: u64,
    pub a_ed: [u8; 32],
    pub a_x: [u8; 32],
    pub g: [u8; 32],
    pub c: [u8; 32],
    /// Готовые байты адресов (семейство, IP, порт).
    pub addr_bytes: Vec<Vec<u8>>,
    pub n: u8,
}

pub fn enc_addr(a: &SocketAddr) -> Vec<u8> {
    let mut v = Vec::new();
    match a.ip() {
        std::net::IpAddr::V4(ip) => {
            v.push(4);
            v.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            v.push(6);
            v.extend_from_slice(&ip.octets());
        }
    }
    v.extend_from_slice(&a.port().to_be_bytes());
    v
}

/// Поля с правильными ключами `key` и одним адресом.
pub fn fields(key: &PairKey) -> Fields {
    Fields {
        issued: 1_000_000,
        expires: 1_000_900,
        a_ed: key.public_key().to_bytes(),
        a_x: key.kx_public().to_bytes(),
        g: *GuestSecret::generate().unwrap().to_token_bytes(),
        c: [0x5C; 32],
        addr_bytes: vec![enc_addr(&addr("203.0.113.7:4455"))],
        n: 1,
    }
}

pub fn with_addrs(mut f: Fields, addrs: &[SocketAddr]) -> Fields {
    f.addr_bytes = addrs.iter().map(enc_addr).collect();
    f.n = u8::try_from(addrs.len()).unwrap();
    f
}

pub fn body(f: &Fields) -> Vec<u8> {
    let mut b = vec![1u8, 1u8];
    b.extend_from_slice(&f.issued.to_be_bytes());
    b.extend_from_slice(&f.expires.to_be_bytes());
    b.extend_from_slice(&f.a_ed);
    b.extend_from_slice(&f.a_x);
    b.extend_from_slice(&f.g);
    b.extend_from_slice(&f.c);
    b.push(f.n);
    for a in &f.addr_bytes {
        b.extend_from_slice(a);
    }
    b
}

/// Тело и подпись `signer` в домене `domain`.
pub fn signed(f: &Fields, signer: &PairKey, domain: SignDomain) -> Vec<u8> {
    let mut b = body(f);
    let sig = signer.sign(domain, &b).unwrap();
    b.extend_from_slice(&sig);
    b
}

pub fn text_of(bytes: &[u8]) -> String {
    chervo_token::encode_invite_bytes(bytes)
}

pub fn decode_err(text: &str) -> Option<chervo_token::TokenError> {
    decode(text).err()
}

pub fn invite_of(text: &str) -> InviteToken {
    match decode(text) {
        Ok(Token::Invite(t)) => t,
        Ok(_) => panic!("не приглашение"),
        Err(e) => panic!("decode: {e}"),
    }
}

// ---------- честный сценарий ----------

pub struct Honest {
    pub a_key: PairKey,
    pub b_key: PairKey,
    pub pending: PendingInvite,
    pub text: String,
    pub session: InviteeSession,
    pub m1: [u8; M1_LEN],
}

pub fn honest() -> Honest {
    let a_key = key();
    let b_key = key();
    let (pending, text) = issue_invite(&draft(900), &a_key).unwrap();
    let token = invite_of(&text);
    let (session, m1) = InviteeSession::start(&token, &b_key).unwrap();
    Honest {
        a_key,
        b_key,
        pending,
        text,
        session,
        m1,
    }
}

/// M1 по частям: `token_hash`, ключи, `r_B`, подпись `signer` в домене `InviteAccept`.
pub fn build_m1(
    token_hash: &[u8],
    b_ed: &[u8; 32],
    b_x: &[u8; 32],
    r_b: &[u8; 32],
    signer: &PairKey,
) -> Vec<u8> {
    let mut m = vec![0x11u8, 0x01];
    m.extend_from_slice(token_hash);
    m.extend_from_slice(b_ed);
    m.extend_from_slice(b_x);
    m.extend_from_slice(r_b);
    let sig = signer.sign(SignDomain::InviteAccept, &m).unwrap();
    m.extend_from_slice(&sig);
    m
}

// ---------- ГПСЧ для fuzz-смоука ----------

pub struct XorShift(u64);

impl XorShift {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % (n.max(1) as u64)) as usize
    }

    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

/// Число итераций: `CHERVO_FUZZ_ITERS`; по умолчанию 20 000 (release) или 2 000 (debug:
/// эллиптические кривые без оптимизаций дорогие, 20 000 итераций занимают минуты).
pub fn fuzz_iters() -> u64 {
    let default = if cfg!(debug_assertions) {
        2_000
    } else {
        20_000
    };
    std::env::var("CHERVO_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Зерно ГПСЧ цели (этап 17, B3). Без `CHERVO_FUZZ_SEED` ровно `default`, как раньше. С ней
/// у каждой цели своё зерно (splitmix64 от `seed ^ default`), так что длинные прогоны идут по
/// новым последовательностям. Пустое значение считается незаданным; неразборное (не `u64`)
/// вызывает панику, чтобы прогон не пошёл молча по старому зерну.
pub fn fuzz_seed(default: u64) -> u64 {
    let Ok(raw) = std::env::var("CHERVO_FUZZ_SEED") else {
        return default;
    };
    if raw.trim().is_empty() {
        return default;
    }
    let seed: u64 = raw
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("CHERVO_FUZZ_SEED must be a u64, got {raw:?}"));
    let mut z = (seed ^ default).wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Одна случайная мутация: переворот бита, вставка, удаление, обрезка.
pub fn mutate(rng: &mut XorShift, src: &[u8]) -> Vec<u8> {
    let mut v = src.to_vec();
    match rng.below(5) {
        0 if !v.is_empty() => {
            let i = rng.below(v.len());
            v[i] ^= 1 << rng.below(8);
        }
        1 => {
            let i = rng.below(v.len() + 1);
            let len = 1 + rng.below(4);
            let extra = rng.bytes(len);
            for (k, b) in extra.into_iter().enumerate() {
                v.insert(i + k, b);
            }
        }
        2 if !v.is_empty() => {
            let i = rng.below(v.len());
            v.remove(i);
        }
        3 => {
            let n = rng.below(v.len() + 1);
            v.truncate(n);
        }
        _ if !v.is_empty() => {
            let i = rng.below(v.len());
            v[i] = rng.next() as u8;
        }
        _ => {}
    }
    v
}
