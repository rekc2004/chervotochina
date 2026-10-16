mod common;

use std::time::Instant;

use chervo_identity::{
    BINDING_LEN, ChannelBinding, GuestSecret, IdentityError, KK_KIND_V1, KK_MSG1_LEN, KK_MSG2_LEN,
    KK_MSG3_LEN, KK_PROLOGUE_TAG, KkInitiator, KkResponder, KxPeer, NOISE_PARAMS, PairId, create,
    kk_initiate, kk_respond,
};
use common::MemStore;

fn binding(b: u8) -> ChannelBinding {
    ChannelBinding::from_bytes([b; BINDING_LEN])
}

/// Одна пара с двух сторон: (вид звонящего, вид вызываемого).
fn make_pair() -> (KxPeer, KxPeer) {
    let pid = PairId::generate().unwrap();
    let (sa, sb) = (MemStore::new(), MemStore::new());
    let ka = create(&sa, &pid).unwrap();
    let kb = create(&sb, &pid).unwrap();
    let (pa, pb) = (ka.kx_public(), kb.kx_public());
    (
        KxPeer::new(pid, ka.into_kx(), pb),
        KxPeer::new(pid, kb.into_kx(), pa),
    )
}

/// Полное рукопожатие; возвращает PairId с точки зрения вызываемого.
fn handshake(
    caller: &KxPeer,
    callee_set: &[&KxPeer],
    b_caller: &ChannelBinding,
    b_callee: &ChannelBinding,
) -> Result<PairId, IdentityError> {
    let (init, m1) = kk_initiate(caller, b_caller)?;
    let (resp, m2) = kk_respond(callee_set, b_callee, &m1)?;
    let m3 = init.finish(&m2)?;
    resp.finish(&m3)
}

#[test]
fn kk_roundtrip_ok() {
    let (caller, callee) = make_pair();
    let b = binding(1);
    assert_eq!(handshake(&caller, &[&callee], &b, &b), Ok(caller.pair()));
    // и в обратную сторону: вызываемый может быть звонящим
    assert_eq!(handshake(&callee, &[&caller], &b, &b), Ok(caller.pair()));
}

#[test]
fn kk_message_sizes() {
    let (caller, callee) = make_pair();
    let b = binding(1);
    let (init, m1) = kk_initiate(&caller, &b).unwrap();
    assert_eq!(m1.len(), 49);
    assert_eq!(m1[0], KK_KIND_V1);
    let (_resp, m2) = kk_respond(&[&callee], &b, &m1).unwrap();
    assert_eq!(m2.len(), 48);
    let m3 = init.finish(&m2).unwrap();
    assert_eq!(m3.len(), 16);
    assert_eq!((KK_MSG1_LEN, KK_MSG2_LEN, KK_MSG3_LEN), (49, 48, 16));
    assert_eq!(NOISE_PARAMS, "Noise_KK_25519_ChaChaPoly_BLAKE2s");
    assert_eq!(KK_PROLOGUE_TAG.len(), 25);
}

#[test]
fn kk_match_any_position() {
    let b = binding(2);
    let pairs: Vec<(KxPeer, KxPeer)> = (0..5).map(|_| make_pair()).collect();
    let callee_set: Vec<&KxPeer> = pairs.iter().map(|(_, c)| c).collect();
    for pos in [0usize, 2, 4] {
        let caller = &pairs[pos].0;
        assert_eq!(
            handshake(caller, &callee_set, &b, &b),
            Ok(pairs[pos].0.pair()),
            "позиция {pos}"
        );
    }
}

#[test]
fn kk_types_are_send() {
    fn f<T: Send>() {}
    f::<KkInitiator>();
    f::<KkResponder>();
    f::<KxPeer>();
}

#[test]
fn kx_peer_is_send_sync() {
    // этапу 9 нужен `Arc<Vec<KxPeer>>` между потоками
    fn g<T: Send + Sync>() {}
    g::<KxPeer>();
}

#[test]
fn kk_rejects_stranger() {
    let b = binding(3);
    let pairs: Vec<(KxPeer, KxPeer)> = (0..3).map(|_| make_pair()).collect();
    let callee_set: Vec<&KxPeer> = pairs.iter().map(|(_, c)| c).collect();
    let (stranger, _) = make_pair();
    assert_eq!(
        handshake(&stranger, &callee_set, &b, &b),
        Err(IdentityError::AuthFailed)
    );
}

fn prologue_bytes(binding_byte: u8) -> Vec<u8> {
    let mut p = KK_PROLOGUE_TAG.to_vec();
    p.push(KK_KIND_V1);
    p.extend_from_slice(&[binding_byte; BINDING_LEN]);
    p
}

#[test]
fn kk_rejects_public_keys_only() {
    let b = binding(4);
    let (caller, callee) = make_pair();
    // положительный контроль: настоящий звонящий проходит
    assert!(handshake(&caller, &[&callee], &b, &b).is_ok());

    // атакующий знает публичные ключи обеих сторон, но не секрет пары:
    // свой случайный статический ключ, remote = ключ вызываемого, верный prologue
    let mut own = [0u8; 32];
    getrandom::fill(&mut own).unwrap();
    let remote = callee.ours_public().to_bytes();
    let plog = prologue_bytes(4);
    let mut hs = snow::Builder::new(NOISE_PARAMS.parse().unwrap())
        .local_private_key(&own)
        .unwrap()
        .remote_public_key(&remote)
        .unwrap()
        .prologue(&plog)
        .unwrap()
        .build_initiator()
        .unwrap();
    let mut body = [0u8; 48];
    assert_eq!(hs.write_message(&[], &mut body).unwrap(), 48);
    let mut forged = vec![KK_KIND_V1];
    forged.extend_from_slice(&body);
    assert_eq!(
        kk_respond(&[&callee], &b, &forged).err(),
        Some(IdentityError::AuthFailed)
    );

    // случайные 48 байт после байта вида
    for _ in 0..20 {
        let mut rnd = [0u8; 48];
        getrandom::fill(&mut rnd).unwrap();
        let mut m = vec![KK_KIND_V1];
        m.extend_from_slice(&rnd);
        assert_eq!(
            kk_respond(&[&callee], &b, &m).err(),
            Some(IdentityError::AuthFailed)
        );
    }
}

#[test]
fn kk_rejects_other_binding() {
    let (caller, callee) = make_pair();
    assert_eq!(
        handshake(&caller, &[&callee], &binding(5), &binding(6)),
        Err(IdentityError::AuthFailed)
    );
    // различие в одном бите
    let mut a = [7u8; BINDING_LEN];
    let b = a;
    a[31] ^= 0x01;
    assert_eq!(
        handshake(
            &caller,
            &[&callee],
            &ChannelBinding::from_bytes(a),
            &ChannelBinding::from_bytes(b)
        ),
        Err(IdentityError::AuthFailed)
    );
}

#[test]
fn kk_rejects_replay_other_binding() {
    let (caller, callee) = make_pair();
    let (ba, bb) = (binding(8), binding(9));
    let (_init, m1) = kk_initiate(&caller, &ba).unwrap();
    // положительный контроль: под своим binding сообщение принимается
    assert!(kk_respond(&[&callee], &ba, &m1).is_ok());
    // то же сообщение под другим binding отвергается
    assert_eq!(
        kk_respond(&[&callee], &bb, &m1).err(),
        Some(IdentityError::AuthFailed)
    );
}

#[test]
fn kk_rejects_reflection() {
    let (x, y) = make_pair();
    let b = binding(10);
    // положительный контроль: от X к Y проходит
    assert!(handshake(&x, &[&y], &b, &b).is_ok());
    // X как звонящий для пары P; то же сообщение подано самой X как ответчику для P
    let (_init, m1) = kk_initiate(&x, &b).unwrap();
    assert_eq!(
        kk_respond(&[&x], &b, &m1).err(),
        Some(IdentityError::AuthFailed)
    );
}

#[test]
fn kk_rejects_bad_msg2() {
    let (caller, callee) = make_pair();
    let b = binding(11);
    for i in [0usize, 31, 32, 47] {
        for bit in [0x01u8, 0x80] {
            let (init, m1) = kk_initiate(&caller, &b).unwrap();
            let (_resp, mut m2) = kk_respond(&[&callee], &b, &m1).unwrap();
            m2[i] ^= bit;
            assert_eq!(
                init.finish(&m2),
                Err(IdentityError::AuthFailed),
                "{i}/{bit}"
            );
        }
    }
}

#[test]
fn kk_rejects_bad_msg3() {
    let (caller, callee) = make_pair();
    let b = binding(12);
    for i in [0usize, 8, 15] {
        for bit in [0x01u8, 0x80] {
            let (init, m1) = kk_initiate(&caller, &b).unwrap();
            let (resp, m2) = kk_respond(&[&callee], &b, &m1).unwrap();
            let mut m3 = init.finish(&m2).unwrap();
            m3[i] ^= bit;
            assert_eq!(
                resp.finish(&m3),
                Err(IdentityError::AuthFailed),
                "{i}/{bit}"
            );
        }
    }
}

#[test]
fn kk_rejects_msg3_from_other_session() {
    let (caller, callee) = make_pair();
    let b = binding(13);
    let (init1, m1a) = kk_initiate(&caller, &b).unwrap();
    let (resp1, m2a) = kk_respond(&[&callee], &b, &m1a).unwrap();
    let _ = init1.finish(&m2a).unwrap();

    let (init2, m1b) = kk_initiate(&caller, &b).unwrap();
    let (resp2, m2b) = kk_respond(&[&callee], &b, &m1b).unwrap();
    let m3_other = init2.finish(&m2b).unwrap();

    // msg3 второй сессии подан первому ответчику
    assert_eq!(resp1.finish(&m3_other), Err(IdentityError::AuthFailed));
    // контроль: своему ответчику msg3 подходит
    assert_eq!(resp2.finish(&m3_other), Ok(caller.pair()));

    // другая пара сессий (другая пара ключей)
    let (caller2, callee2) = make_pair();
    let (init3, m1c) = kk_initiate(&caller2, &b).unwrap();
    let (_resp3, m2c) = kk_respond(&[&callee2], &b, &m1c).unwrap();
    let m3_foreign = init3.finish(&m2c).unwrap();
    let (_i, m1d) = kk_initiate(&caller, &b).unwrap();
    let (resp4, _m2d) = kk_respond(&[&callee], &b, &m1d).unwrap();
    assert_eq!(resp4.finish(&m3_foreign), Err(IdentityError::AuthFailed));
}

#[test]
fn kk_rejects_wrong_lengths() {
    let (caller, callee) = make_pair();
    let b = binding(14);

    // msg1: любые длины 0..=100 кроме 49
    for len in (0..=100usize).filter(|l| *l != KK_MSG1_LEN) {
        let m = vec![KK_KIND_V1; len];
        assert_eq!(
            kk_respond(&[&callee], &b, &m).err(),
            Some(IdentityError::AuthFailed),
            "msg1 len {len}"
        );
    }
    // msg1 длины 49 с видом, отличным от 1
    let (_init, good) = kk_initiate(&caller, &b).unwrap();
    for kind in 0..=255u8 {
        if kind == KK_KIND_V1 {
            continue;
        }
        let mut m = good;
        m[0] = kind;
        assert_eq!(
            kk_respond(&[&callee], &b, &m).err(),
            Some(IdentityError::AuthFailed),
            "kind {kind}"
        );
    }
    // msg2 длины 0..=100 кроме 48
    for len in (0..=100usize).filter(|l| *l != KK_MSG2_LEN) {
        let (init, _m1) = kk_initiate(&caller, &b).unwrap();
        assert_eq!(
            init.finish(&vec![0u8; len]),
            Err(IdentityError::AuthFailed),
            "msg2 len {len}"
        );
    }
    // msg3 длины 0..=64 кроме 16
    for len in (0..=64usize).filter(|l| *l != KK_MSG3_LEN) {
        let (init, m1) = kk_initiate(&caller, &b).unwrap();
        let (resp, _m2) = kk_respond(&[&callee], &b, &m1).unwrap();
        drop(init);
        assert_eq!(
            resp.finish(&vec![0u8; len]),
            Err(IdentityError::AuthFailed),
            "msg3 len {len}"
        );
    }
    // 1 МиБ без паники
    let big = vec![KK_KIND_V1; 1 << 20];
    assert_eq!(
        kk_respond(&[&callee], &b, &big).err(),
        Some(IdentityError::AuthFailed)
    );
}

#[test]
fn kk_empty_peer_set_fails() {
    let (caller, _callee) = make_pair();
    let b = binding(15);
    let (_init, m1) = kk_initiate(&caller, &b).unwrap();
    assert_eq!(
        kk_respond(&[], &b, &m1).err(),
        Some(IdentityError::AuthFailed)
    );
}

/// Пара, у которой ключ друга равен нашему собственному.
fn self_peer() -> KxPeer {
    let pid = PairId::generate().unwrap();
    let k = create(&MemStore::new(), &pid).unwrap();
    let own = k.kx_public();
    KxPeer::new(pid, k.into_kx(), own)
}

#[test]
fn kk_rejects_peer_key_equal_to_ours() {
    let b = binding(30);
    let (caller, callee) = make_pair();
    // положительный контроль: обычная пара работает
    assert!(handshake(&caller, &[&callee], &b, &b).is_ok());

    let bad = self_peer();
    assert_eq!(bad.theirs(), bad.ours_public());
    assert_eq!(
        kk_initiate(&bad, &b).err(),
        Some(IdentityError::AuthFailed),
        "звонящий с ключом друга == своему"
    );
    // как кандидат вызываемого такая пара не совпадает, остальные работают
    let (_, m1) = kk_initiate(&caller, &b).unwrap();
    assert_eq!(
        kk_respond(&[&bad], &b, &m1).err(),
        Some(IdentityError::AuthFailed)
    );
    assert_eq!(
        handshake(&caller, &[&bad, &callee], &b, &b),
        Ok(caller.pair())
    );
}

#[test]
fn kk_rejects_low_order_ephemeral() {
    let b = binding(31);
    let (caller, callee) = make_pair();
    // положительный контроль: честное рукопожатие проходит
    assert!(handshake(&caller, &[&callee], &b, &b).is_ok());

    let mut points: Vec<[u8; 32]> = vec![[0u8; 32]];
    points.extend(
        curve25519_dalek::constants::EIGHT_TORSION
            .iter()
            .map(|t| t.to_montgomery().to_bytes()),
    );
    for (i, pt) in points.iter().enumerate() {
        let mut tag = [0u8; 16];
        getrandom::fill(&mut tag).unwrap();
        // msg1 = [вид] ++ малая точка ++ случайный тег
        let mut m1 = vec![KK_KIND_V1];
        m1.extend_from_slice(pt);
        m1.extend_from_slice(&tag);
        assert_eq!(m1.len(), KK_MSG1_LEN);
        assert_eq!(
            kk_respond(&[&callee], &b, &m1).err(),
            Some(IdentityError::AuthFailed),
            "msg1, точка {i}"
        );
        // msg2 = малая точка ++ случайный тег
        let (init, _) = kk_initiate(&caller, &b).unwrap();
        let mut m2 = pt.to_vec();
        m2.extend_from_slice(&tag);
        assert_eq!(m2.len(), KK_MSG2_LEN);
        assert_eq!(
            init.finish(&m2).err(),
            Some(IdentityError::AuthFailed),
            "msg2, точка {i}"
        );
    }
}

fn median(v: &mut [u128]) -> u128 {
    v.sort_unstable();
    v[v.len() / 2]
}

/// Замер: запускать в `--release`. Порога нет, цифры идут в отчёт.
#[test]
#[ignore = "замер; запускать в --release с --nocapture"]
fn kk_trial_cost() {
    let b = binding(20);
    let (stranger, _) = make_pair();
    println!("N | no-match, us | match-first, us | match-last, us | first/last | match/none");
    for n in [1usize, 10, 50, 200] {
        let pairs: Vec<(KxPeer, KxPeer)> = (0..n).map(|_| make_pair()).collect();
        let callee_set: Vec<&KxPeer> = pairs.iter().map(|(_, c)| c).collect();
        let m1_none = kk_initiate(&stranger, &b).unwrap().1;
        let m1_first = kk_initiate(&pairs[0].0, &b).unwrap().1;
        let m1_last = kk_initiate(&pairs[n - 1].0, &b).unwrap().1;
        let mut res = Vec::new();
        for m1 in [&m1_none, &m1_first, &m1_last] {
            let mut t = Vec::new();
            for _ in 0..50 {
                let start = Instant::now();
                let r = kk_respond(&callee_set, &b, m1);
                t.push(start.elapsed().as_micros());
                drop(r);
            }
            res.push(median(&mut t));
        }
        // позиционная утечка: первым против последним (оба «совпало»);
        // постоянная добавка совпадения (msg2): совпало против нет совпадения
        let (first, last) = (res[1].max(1) as f64, res[2].max(1) as f64);
        let positional = first.max(last) / first.min(last);
        let matched = (res[1] + res[2]) as f64 / 2.0;
        let overhead = matched / res[0].max(1) as f64;
        println!(
            "{n} | {} | {} | {} | {positional:.3} | {overhead:.2}",
            res[0], res[1], res[2]
        );
    }
}

/// Гостевая пара: A знает G, B знает секрет g и ключ A из токена.
#[test]
fn guest_into_kx_knock_and_kk_work() {
    let pid = PairId::generate().unwrap();
    let store = MemStore::new();
    let ka = create(&store, &pid).unwrap();
    let a_x = ka.kx_public();
    let guest = GuestSecret::generate().unwrap();
    let g_pub = guest.public();
    let a_peer = KxPeer::new(pid, ka.into_kx(), g_pub);
    let b_peer = KxPeer::new(pid, guest.into_kx(), a_x);

    // стук: B стучит, A проверяет по recv_id
    let a_keys = a_peer.knock_keys().unwrap();
    let b_keys = b_peer.knock_keys().unwrap();
    let knock = b_keys.make(42).unwrap();
    assert_eq!(&knock[..16], &a_keys.recv_id(42)[..]);
    assert!(a_keys.verify(42, &knock));

    // KK в обе стороны
    let b = binding(9);
    assert_eq!(handshake(&b_peer, &[&a_peer], &b, &b), Ok(pid));
    assert_eq!(handshake(&a_peer, &[&b_peer], &b, &b), Ok(pid));
}
