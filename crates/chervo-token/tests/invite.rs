mod common;

use chervo_identity::{GuestSecret, SignDomain};
use chervo_token::{
    DECISION_LEN, InviteError, InviteeSession, M1_LEN, M2_LEN, MAX_INVITE_SESSIONS,
    decode_decision, encode_decision, issue_invite,
};
use common::*;

/// Честный прогон: A принимает M1 B, B принимает M2 A; обе стороны получают один SAS.
#[test]
fn sas_equal_honest() {
    let mut h = honest();
    h.pending.begin_session(1_000_100).unwrap();
    let (m2, sas_a, keys) = h.pending.on_m1(&h.m1).unwrap();
    assert_eq!(keys.ed, h.b_key.public_key());
    assert_eq!(keys.x, h.b_key.kx_public());
    assert_eq!(m2.len(), M2_LEN);
    assert_eq!(m2[0], 0x12);
    assert_eq!(m2[1], 0x01);
    let sas_b = h.session.on_m2(&m2).unwrap();
    assert_eq!(sas_a, sas_b);
    assert_eq!(sas_a.as_bytes(), sas_b.as_bytes());
    assert_eq!(format!("{sas_a:?}"), "Sas(..)");
    assert_eq!(format!("{keys:?}"), "InviteeKeys(..)");
    assert_eq!(format!("{:?}", h.pending), "PendingInvite(..)");
    // два разных приглашения дают разные SAS
    let mut h2 = honest();
    h2.pending.begin_session(1_000_100).unwrap();
    let (_m2, sas2, _) = h2.pending.on_m1(&h2.m1).unwrap();
    assert_ne!(sas_a, sas2);
}

#[test]
fn sas_digits_format() {
    let mut h = honest();
    h.pending.begin_session(1_000_100).unwrap();
    let (_m2, sas, _) = h.pending.on_m1(&h.m1).unwrap();
    let d = sas.digits();
    assert_eq!(d.len(), 9);
    assert_eq!(d.as_bytes()[4], b' ');
    assert!(
        d.bytes()
            .enumerate()
            .all(|(i, c)| i == 4 || c.is_ascii_digit())
    );
    let n = u64::from_be_bytes(*sas.as_bytes()) % 100_000_000;
    assert_eq!(d, format!("{:04} {:04}", n / 10_000, n % 10_000));
    assert_eq!(chervo_token::SAS_DIGITS, 8);
    // много случайных SAS: формат всегда тот же, цифры не вырождены
    let mut distinct = std::collections::HashSet::new();
    for _ in 0..30 {
        let mut h = honest();
        h.pending.begin_session(1_000_100).unwrap();
        let (_m2, s, _) = h.pending.on_m1(&h.m1).unwrap();
        let d = s.digits();
        assert_eq!(d.len(), 9);
        distinct.insert(d);
    }
    assert!(distinct.len() > 25);
}

/// MITM подменил токен: A видит M, B видит токен M. SAS двух сессий различны, M1 B не принимается A.
#[test]
fn sas_mitm_substituted_token_differs() {
    let a_key = key();
    let (mut pend_a, text_a) = issue_invite(&draft(900), &a_key).unwrap();
    let token_a = invite_of(&text_a);

    // M: свой ключ и своё приглашение с теми же адресами; B получает токен M
    let m_key = key();
    let (mut pend_m, text_m) = issue_invite(&draft(900), &m_key).unwrap();
    let token_m = invite_of(&text_m);
    let b_key = key();

    // B -> (токен M) -> M
    let (sess_b, m1_b) = InviteeSession::start(&token_m, &b_key).unwrap();
    // M как приглашённый перед A, по настоящему токену A
    let m_as_invitee = key();
    let (sess_m, m1_m) = InviteeSession::start(&token_a, &m_as_invitee).unwrap();

    pend_a.begin_session(1_000_100).unwrap();
    pend_m.begin_session(1_000_100).unwrap();

    // ретрансляция M1 B к A без изменений не проходит
    assert_eq!(pend_a.on_m1(&m1_b).err(), Some(InviteError::WrongToken));

    let (m2_a, sas_a, _) = pend_a.on_m1(&m1_m).unwrap();
    let sas_m_side = sess_m.on_m2(&m2_a).unwrap();
    assert_eq!(sas_a, sas_m_side);
    let (m2_m, sas_m_to_b, _) = pend_m.on_m1(&m1_b).unwrap();
    let sas_b = sess_b.on_m2(&m2_m).unwrap();
    assert_eq!(sas_m_to_b, sas_b);
    assert_ne!(sas_a, sas_b, "SAS двух сессий не должны совпасть");

    // M не может раскрыть B значение A: обязательство в токене M, а не A
    let (sess_b2, _m1) = InviteeSession::start(&token_m, &b_key).unwrap();
    let mut honest_a = honest();
    honest_a.pending.begin_session(1_000_100).unwrap();
    let (m2_other, _, _) = honest_a.pending.on_m1(&honest_a.m1).unwrap();
    assert_eq!(
        sess_b2.on_m2(&m2_other).err(),
        Some(InviteError::CommitMismatch)
    );
}

#[test]
fn m1_wrong_token_hash() {
    let mut h = honest();
    h.pending.begin_session(1_000_100).unwrap();
    for i in 2..34 {
        let mut m = h.m1;
        m[i] ^= 0x01;
        assert_eq!(
            h.pending.on_m1(&m).err(),
            Some(InviteError::WrongToken),
            "байт {i}"
        );
    }
    // M1 от другого приглашения
    let other = honest();
    assert_eq!(
        h.pending.on_m1(&other.m1).err(),
        Some(InviteError::WrongToken)
    );
    // и после отказов настоящий принимается
    assert!(h.pending.on_m1(&h.m1).is_ok());
}

#[test]
fn m1_bad_signature() {
    let mut h = honest();
    h.pending.begin_session(1_000_100).unwrap();
    // r_B (98..130) и подпись (130..194) под подписью: любое изменение даёт BadSignature
    for i in (98..194).step_by(3) {
        let mut m = h.m1;
        m[i] ^= 0x04;
        assert_eq!(
            h.pending.on_m1(&m).err(),
            Some(InviteError::BadSignature),
            "байт {i}"
        );
    }
    // подпись в чужом домене (Invite вместо InviteAccept)
    let th = h.m1[2..34].to_vec();
    let mut m = vec![0x11u8, 0x01];
    m.extend_from_slice(&th);
    m.extend_from_slice(&h.b_key.public_key().to_bytes());
    m.extend_from_slice(&h.b_key.kx_public().to_bytes());
    m.extend_from_slice(&[7u8; 32]);
    let sig = h.b_key.sign(SignDomain::Invite, &m).unwrap();
    m.extend_from_slice(&sig);
    assert_eq!(h.pending.on_m1(&m).err(), Some(InviteError::BadSignature));
    // подпись чужим ключом
    let other = key();
    let m = build_m1(
        &th,
        &h.b_key.public_key().to_bytes(),
        &h.b_key.kx_public().to_bytes(),
        &[7u8; 32],
        &other,
    );
    assert_eq!(h.pending.on_m1(&m).err(), Some(InviteError::BadSignature));
    // контроль: правильно подписанный принимается
    let m = build_m1(
        &th,
        &h.b_key.public_key().to_bytes(),
        &h.b_key.kx_public().to_bytes(),
        &[7u8; 32],
        &h.b_key,
    );
    assert!(h.pending.on_m1(&m).is_ok());
}

#[test]
fn m1_bad_keys() {
    let mut h = honest();
    h.pending.begin_session(1_000_100).unwrap();
    let th = h.m1[2..34].to_vec();
    let b_ed = h.b_key.public_key().to_bytes();
    let b_x = h.b_key.kx_public().to_bytes();
    let a_x = h.a_key.kx_public().to_bytes();
    let g_pub = h.pending.guest_public().to_bytes();
    let r = [9u8; 32];
    let mut zero_x = [0u8; 32];
    let mut one_x = [0u8; 32];
    one_x[0] = 1;
    zero_x[31] = 0;
    let mut weak_ed = [0u8; 32];
    weak_ed[0] = 1;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("B_x == A_x", build_m1(&th, &b_ed, &a_x, &r, &h.b_key)),
        ("B_x == G", build_m1(&th, &b_ed, &g_pub, &r, &h.b_key)),
        (
            "B_ed == A_ed",
            build_m1(&th, &h.a_key.public_key().to_bytes(), &b_x, &r, &h.a_key),
        ),
        (
            "малый порядок X (0)",
            build_m1(&th, &b_ed, &zero_x, &r, &h.b_key),
        ),
        (
            "малый порядок X (1)",
            build_m1(&th, &b_ed, &one_x, &r, &h.b_key),
        ),
        ("слабый Ed", build_m1(&th, &weak_ed, &b_x, &r, &h.b_key)),
        (
            "не-точка Ed",
            build_m1(&th, &[0xFF; 32], &b_x, &r, &h.b_key),
        ),
    ];
    for (name, m) in cases {
        assert_eq!(m.len(), M1_LEN);
        assert_eq!(
            h.pending.on_m1(&m).err(),
            Some(InviteError::BadKey),
            "{name}"
        );
    }
    // отказы не расходуют приглашение
    assert!(h.pending.on_m1(&h.m1).is_ok());
}

#[test]
fn m1_every_wrong_length() {
    let mut h = honest();
    h.pending.begin_session(1_000_100).unwrap();
    for n in 0..=400usize {
        if n == M1_LEN {
            continue;
        }
        let mut v = h.m1.to_vec();
        v.resize(n, 0xAA);
        assert_eq!(
            h.pending.on_m1(&v).err(),
            Some(InviteError::Malformed),
            "длина {n}"
        );
    }
    // неверные заголовки
    for (i, val) in [(0usize, 0x12u8), (0, 0), (1, 0), (1, 2), (1, 0xFF)] {
        let mut m = h.m1;
        m[i] = val;
        assert_eq!(
            h.pending.on_m1(&m).err(),
            Some(InviteError::Malformed),
            "{i}:{val}"
        );
    }
    assert!(h.pending.on_m1(&h.m1).is_ok());
}

#[test]
fn m1_accepted_once() {
    let mut h = honest();
    h.pending.begin_session(1_000_100).unwrap();
    assert!(h.pending.on_m1(&h.m1).is_ok());
    assert_eq!(h.pending.on_m1(&h.m1).err(), Some(InviteError::Used));
    // ни новая сессия, ни другой M1 не оживляют приглашение
    assert_eq!(
        h.pending.begin_session(1_000_100).err(),
        Some(InviteError::Used)
    );
    let (_s, other_m1) = {
        let token = invite_of(&h.text);
        InviteeSession::start(&token, &key()).unwrap()
    };
    assert_eq!(h.pending.on_m1(&other_m1).err(), Some(InviteError::Used));
    // даже мусор получает Used, а не Malformed
    assert_eq!(h.pending.on_m1(&[]).err(), Some(InviteError::Used));
}

#[test]
fn m1_without_session() {
    let mut h = honest();
    assert_eq!(h.pending.on_m1(&h.m1).err(), Some(InviteError::NoSession));
    assert_eq!(h.pending.on_m1(&[]).err(), Some(InviteError::NoSession));
    // отказ не расходует M1: после begin_session тот же M1 принимается
    h.pending.begin_session(1_000_100).unwrap();
    assert!(h.pending.on_m1(&h.m1).is_ok());
}

#[test]
fn session_limits() {
    let k = key();
    let (mut p, _t) = issue_invite(&draft(900), &k).unwrap();
    let exp = p.expires_at();
    assert_eq!(exp, 1_000_900);
    assert_eq!(p.begin_session(exp), Err(InviteError::Expired));
    assert_eq!(p.begin_session(exp + 1), Err(InviteError::Expired));
    assert_eq!(p.begin_session(u64::MAX), Err(InviteError::Expired));
    // просроченные попытки не считаются сессиями
    for i in 0..MAX_INVITE_SESSIONS {
        assert_eq!(p.begin_session(exp - 1), Ok(()), "сессия {i}");
    }
    assert_eq!(p.begin_session(exp - 1), Err(InviteError::TooManySessions));
    assert_eq!(MAX_INVITE_SESSIONS, 3);
    // и по истечении срока сначала Expired
    assert_eq!(p.begin_session(exp), Err(InviteError::Expired));
}

#[test]
fn m2_commit_mismatch() {
    let mut h = honest();
    h.pending.begin_session(1_000_100).unwrap();
    let (m2, _sas, _) = h.pending.on_m1(&h.m1).unwrap();
    // два одинаковых сеанса B нужны, чтобы проверить несколько искажений: `on_m2` расходует состояние
    let token = invite_of(&h.text);
    for i in 2..M2_LEN {
        let (s, _m1) = InviteeSession::start(&token, &h.b_key).unwrap();
        let mut bad = m2;
        bad[i] ^= 0x01;
        assert_eq!(
            s.on_m2(&bad).err(),
            Some(InviteError::CommitMismatch),
            "байт {i}"
        );
    }
    // чужой r_A
    let (s, _m1) = InviteeSession::start(&token, &h.b_key).unwrap();
    let mut other = m2;
    other[2..].copy_from_slice(&[0u8; 32]);
    assert_eq!(s.on_m2(&other).err(), Some(InviteError::CommitMismatch));
    // неверный заголовок
    for (i, v) in [(0usize, 0x11u8), (0, 0), (1, 0), (1, 2)] {
        let (s, _m1) = InviteeSession::start(&token, &h.b_key).unwrap();
        let mut bad = m2;
        bad[i] = v;
        assert_eq!(s.on_m2(&bad).err(), Some(InviteError::Malformed));
    }
    // контроль
    assert!(h.session.on_m2(&m2).is_ok());
}

#[test]
fn m2_every_wrong_length() {
    let h = honest();
    let token = invite_of(&h.text);
    for n in 0..=100usize {
        if n == M2_LEN {
            continue;
        }
        let (s, _m1) = InviteeSession::start(&token, &h.b_key).unwrap();
        assert_eq!(
            s.on_m2(&vec![0x12; n]).err(),
            Some(InviteError::Malformed),
            "длина {n}"
        );
    }
}

#[test]
fn start_rejects_own_keys() {
    let a = key();
    let (_p, text) = issue_invite(&draft(900), &a).unwrap();
    let token = invite_of(&text);
    // тот же ключ пары (B_ed == A_ed и B_x == A_x)
    assert_eq!(
        InviteeSession::start(&token, &a).err(),
        Some(InviteError::BadKey)
    );
    // контроль
    assert!(InviteeSession::start(&token, &key()).is_ok());
    assert_eq!(
        format!("{:?}", InviteeSession::start(&token, &key()).unwrap().0),
        "InviteeSession(..)"
    );
    // гостевой секрет токена даёт пару с ключом пригласившего
    let g = token.guest_secret().unwrap();
    assert_ne!(g.public(), token.inviter_x());
    let _ = GuestSecret::generate().unwrap();
}

#[test]
fn decision_only_exact() {
    assert_eq!(encode_decision(true), [0x13, 0x01, 0x01]);
    assert_eq!(encode_decision(false), [0x13, 0x01, 0x00]);
    assert_eq!(DECISION_LEN, 3);
    assert_eq!(decode_decision(&encode_decision(true)), Ok(true));
    assert_eq!(decode_decision(&encode_decision(false)), Ok(false));
    let pool = [0u8, 1, 2, 0x12, 0x13, 0xFF];
    for len in 0..=5usize {
        let mut idx = vec![0usize; len];
        loop {
            let b: Vec<u8> = idx.iter().map(|i| pool[*i]).collect();
            let r = decode_decision(&b);
            let exact = len == 3 && b[0] == 0x13 && b[1] == 0x01 && b[2] <= 1;
            assert_eq!(r.is_ok(), exact, "{b:?}");
            if !exact {
                assert_eq!(r, Err(InviteError::Malformed));
            }
            let mut p = 0;
            while p < len {
                idx[p] += 1;
                if idx[p] < pool.len() {
                    break;
                }
                idx[p] = 0;
                p += 1;
            }
            if p == len {
                break;
            }
        }
    }
}

#[test]
fn error_display_fixed() {
    use chervo_token::{FlowError, TokenError};
    // тексты не содержат байтов ввода и различаются
    let all = [
        InviteError::Malformed,
        InviteError::WrongToken,
        InviteError::BadKey,
        InviteError::BadSignature,
        InviteError::CommitMismatch,
        InviteError::Expired,
        InviteError::TooManySessions,
        InviteError::Used,
        InviteError::NoSession,
        InviteError::RandomUnavailable,
        InviteError::SigningFailed,
    ];
    let texts: std::collections::HashSet<String> = all.iter().map(|e| e.to_string()).collect();
    assert_eq!(texts.len(), all.len());
    assert_eq!(TokenError::TooLong.to_string(), "token text too long");
    assert_eq!(FlowError::Truncated.to_string(), "invite message truncated");
}
