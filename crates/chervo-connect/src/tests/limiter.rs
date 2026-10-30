//! Ограничитель набора: тесты решения 5 (обзор 12, M1).

use std::time::Duration;

use tokio::time::Instant;

use super::kit::*;
use crate::ConnectConfig;
use crate::limiter::{Limiter, backoff};
use crate::plan::{Candidate, Plan, select};

fn plan_of(ip: &str, ports: std::ops::Range<u16>) -> Plan {
    Plan {
        cands: ports
            .map(|p| Candidate {
                addr: addr(&format!("{ip}:{p}")),
                hint: false,
                strict: false,
            })
            .collect(),
    }
}

#[tokio::test(start_paused = true)]
async fn limiter_backoff_and_cap() {
    let mut l = Limiter::new(&ConnectConfig::default());
    let a = addr("5.6.7.8:4000");
    let t0 = Instant::now();
    for (i, want) in [30u64, 60, 120, 240, 480, 600, 600, 600].iter().enumerate() {
        l.failed(&[a], false, false, t0);
        let (fails, wait) = l.entry_state(a, t0).unwrap();
        assert_eq!(fails as usize, i + 1);
        assert_eq!(wait, secs(*want));
        assert!(!l.allow(a, false, t0 + secs(*want) - Duration::from_millis(1)));
        assert!(l.allow(a, false, t0 + secs(*want)));
    }
}

#[tokio::test(start_paused = true)]
async fn limiter_hint_slower() {
    let mut l = Limiter::new(&ConnectConfig::default());
    let (plain, hint) = (addr("5.6.7.8:4000"), addr("6.7.8.9:4000"));
    let t0 = Instant::now();
    for want in [60u64, 120, 240, 480, 960, 1800, 1800] {
        l.failed(&[hint], true, false, t0);
        assert_eq!(l.entry_state(hint, t0).unwrap().1, secs(want));
    }
    l.failed(&[plain], false, false, t0);
    assert_eq!(l.entry_state(plain, t0).unwrap().1, secs(30));
}

#[tokio::test(start_paused = true)]
async fn limiter_per_ip_cap_across_pairs_and_ports() {
    let cfg = ConnectConfig::default();
    let mut l = Limiter::new(&cfg);
    let t0 = Instant::now();
    // жертва перечислена тремя друзьями, у каждого восемь портов
    let mut taken = 0usize;
    for (i, _friend) in ["a", "b", "c"].iter().enumerate() {
        let from = 1000 + (i as u16) * 8;
        let plan = plan_of("5.6.7.8", from..from + 8);
        taken += select(&plan, &mut l, t0).len();
    }
    assert!(taken <= cfg.per_ip_dials as usize, "taken {taken}");
    assert_eq!(taken, cfg.per_ip_dials as usize);
    // внутри окна больше нельзя ни с какого порта
    let later = t0 + secs(9);
    assert!(select(&plan_of("5.6.7.8", 2000..2008), &mut l, later).is_empty());
    // окно прошло: снова не больше предела
    let after = t0 + secs(10);
    let again = select(&plan_of("5.6.7.8", 3000..3008), &mut l, after).len();
    assert_eq!(again, cfg.per_ip_dials as usize);
}

#[tokio::test(start_paused = true)]
async fn limiter_new_seq_resets_pair_only() {
    let mut l = Limiter::new(&ConnectConfig::default());
    let (x, y) = (addr("5.6.7.8:4000"), addr("6.7.8.9:4000"));
    let t0 = Instant::now();
    l.failed(&[x, y], false, false, t0);
    assert!(!l.allow(x, false, t0 + secs(1)));
    l.reset_pair(&[x], t0 + secs(1));
    assert!(l.allow(x, false, t0 + secs(1)));
    assert!(!l.allow(y, false, t0 + secs(1)));
    assert_eq!(l.entry_state(x, t0).unwrap().0, 0);
    assert_eq!(l.entry_state(y, t0).unwrap().0, 1);
}

#[tokio::test(start_paused = true)]
async fn limiter_capacity_evicts() {
    let cfg = ConnectConfig {
        limiter_capacity: 4,
        ..ConnectConfig::default()
    };
    let mut l = Limiter::new(&cfg);
    let t0 = Instant::now();
    let addrs: Vec<_> = (1..=6).map(|i| addr(&format!("5.6.7.{i}:4000"))).collect();
    for (i, a) in addrs.iter().enumerate() {
        l.charge(&[*a], t0 + secs(i as u64));
    }
    assert!(l.entries_len() <= 4);
    assert!(!l.has_entry(addrs[0]));
    assert!(!l.has_entry(addrs[1]));
    assert!(l.has_entry(addrs[5]));
    // журнал IP тоже ограничен
    for i in 0..50u16 {
        l.charge(
            &[addr(&format!("9.9.{}.{}:1", i / 200, i % 200 + 1))],
            t0 + secs(100),
        );
    }
    assert!(l.entries_len() <= 4);
}

#[tokio::test(start_paused = true)]
async fn limiter_saturating() {
    let huge = Duration::MAX;
    let cfg = ConnectConfig {
        dial_base: huge,
        dial_cap: huge,
        hint_base: huge,
        hint_cap: huge,
        fast_period: huge,
        ..ConnectConfig::default()
    };
    let mut l = Limiter::new(&cfg);
    let a = addr("5.6.7.8:4000");
    let t0 = Instant::now();
    for _ in 0..70 {
        l.failed(&[a], false, false, t0);
        l.failed(&[a], true, true, t0);
    }
    assert!(!l.allow(a, false, t0 + secs(3600)));
    // шаг степени и произведение не переполняются
    assert_eq!(backoff(secs(30), secs(600), u32::MAX), secs(600));
    assert_eq!(backoff(huge, secs(600), 70), secs(600));
    assert_eq!(backoff(secs(30), huge, 0), secs(30));
}

#[tokio::test(start_paused = true)]
async fn limiter_fast_window_only_local_triggers() {
    let mut pre_a = Pre::new();
    let mut pre_b = Pre::new();
    let (pa, pb) = befriend(&mut pre_a, &mut pre_b, vec![inv("5.6.7.8:4000")], vec![]);
    let c_addr = addr("5.5.5.5:4000");
    let pc = pre_a.solo_friend(vec![inv("5.5.5.5:4000")]);
    let a = Node::start_with(
        pre_a,
        ConnectConfig::default(),
        FakeTransport::new(),
        FakeProbe::new(Some("7.7.7.7")),
    );
    let b = Node::start_with(
        pre_b,
        ConnectConfig::default(),
        FakeTransport::new(),
        FakeProbe::new(Some("8.8.8.8")),
    );
    let _links = link_nodes(&a, pa, "5.6.7.8:4000", &b, pb, "7.7.7.7:4000");
    // быстрое окно запуска прошло; друг C недоступен, его интервал вырос
    tokio::time::sleep(secs(300)).await;
    // ждём, пока до следующей попытки к C останется больше окна проверки
    for _ in 0..100 {
        let now = Instant::now();
        let remaining = a
            .engine
            .inner
            .lock()
            .limiter
            .entry_state(c_addr, now)
            .unwrap()
            .1;
        if remaining > secs(60) {
            break;
        }
        tokio::time::sleep(secs(10)).await;
    }
    let c_calls = a.t.calls_for(&pc).len();
    assert!(c_calls >= 3);
    let now = Instant::now();
    let (fails, _) = a
        .engine
        .inner
        .lock()
        .limiter
        .entry_state(c_addr, now)
        .unwrap();
    assert!(!a.engine.inner.lock().limiter.allow(c_addr, false, now));
    assert!(a.engine.inner.lock().fast_global_until.is_none());

    // друг B меняет адрес: от него приходит новое обновление, оно применяется
    b.probe.set_v4(Some("8.8.4.4"));
    tokio::time::sleep(secs(15)).await;
    let learned = a.engine.read_book(|bk| {
        bk.get(&pa)
            .unwrap()
            .known_addrs
            .iter()
            .any(|k| k.addr == addr("8.8.4.4:4000"))
    });
    assert!(learned, "the in-band update was applied");

    // но чужое обновление не открывает быстрого окна и не сбрасывает интервалы других пар
    let now = Instant::now();
    let st = a.engine.inner.lock();
    assert!(st.fast_global_until.is_none());
    assert!(st.friends.get(&pa).unwrap().fast_until.is_none());
    assert!(st.friends.get(&pc).unwrap().fast_until.is_none());
    assert_eq!(st.limiter.entry_state(c_addr, now).unwrap().0, fails);
    assert!(!st.limiter.allow(c_addr, false, now));
    drop(st);
    assert_eq!(a.t.calls_for(&pc).len(), c_calls, "C was not redialed");
}

#[tokio::test(start_paused = true)]
async fn limiter_pasted_token_resets_that_pair_only() {
    use chervo_addr::{LocalSnapshot, OwnAddrs, RouteSources};
    use chervo_transport::TransportError as TE;

    let mut pre_a = Pre::new();
    let mut pre_b = Pre::new();
    let (pa, pb) = befriend(&mut pre_a, &mut pre_b, vec![inv("5.6.7.8:4000")], vec![]);
    let pc = pre_a.solo_friend(vec![inv("5.5.5.5:4000")]);
    // друг B присылает токен с тем же адресом, что у нас уже записан
    let mut own = OwnAddrs::new();
    own.set_local(LocalSnapshot {
        route: RouteSources {
            v4: Some("5.6.7.8".parse().unwrap()),
            v6: None,
        },
        listen: vec![addr("0.0.0.0:4000")],
    });
    let set = own.publishable(chervo_addr::PublishCtx::default(), BASE_UNIX);
    let text = pre_b
        .book
        .issue_addr_update(&*pre_b.store, &pb, &set, BASE_UNIX)
        .unwrap()
        .text();
    let n = Node::start(pre_a, ConnectConfig::default());
    n.t.set_script(|_, _| Action::Fail(TE::TimedOut, Duration::ZERO));
    tokio::time::sleep(secs(400)).await;
    let (b_addr, c_addr) = (addr("5.6.7.8:4000"), addr("5.5.5.5:4000"));
    let now = Instant::now();
    let (b_fails, _) = n
        .engine
        .inner
        .lock()
        .limiter
        .entry_state(b_addr, now)
        .unwrap();
    let (c_fails, _) = n
        .engine
        .inner
        .lock()
        .limiter
        .entry_state(c_addr, now)
        .unwrap();
    assert!(b_fails >= 3 && c_fails >= 3);

    n.engine
        .update_book(|b, s| b.apply_addr_update_text(s, &text, BASE_UNIX + 400))
        .unwrap();
    let st = n.engine.inner.lock();
    let now = Instant::now();
    assert_eq!(st.limiter.entry_state(b_addr, now).unwrap().0, 0, "B reset");
    assert!(st.limiter.allow(b_addr, false, now));
    assert_eq!(st.limiter.entry_state(c_addr, now).unwrap().0, c_fails);
    assert!(!st.limiter.allow(c_addr, false, now));
    assert!(
        st.fast_global_until.is_none_or(|t| t <= now),
        "no fast window"
    );
    assert!(st.friends.get(&pa).unwrap().fast_until.is_none());
    assert!(st.friends.get(&pc).unwrap().fast_until.is_none());
}

// ------------------------------------------------------------ этап 13г: ключ жертвы IPv6 /64

#[tokio::test(start_paused = true)]
async fn limiter_v6_strict_per_64() {
    let cfg = ConnectConfig::default();
    let mut l = Limiter::new(&cfg);
    let t0 = Instant::now();
    // лгущий друг называет разные адреса одной чужой /64: строгий набор один на 32 с
    let a = addr("[2606:4700:1:2::1]:4000");
    let b = addr("[2606:4700:1:2:aaaa:bbbb:cccc:dddd]:5000");
    let other64 = addr("[2606:4700:1:3::1]:4000");
    assert!(l.take(a, true, t0));
    assert!(!l.take(b, true, t0 + secs(1)), "та же /64");
    assert!(!l.take(b, true, t0 + secs(31)), "предел 30 с + запас 2 с");
    assert!(l.take(other64, true, t0 + secs(1)), "другая /64");
    assert!(l.take(b, true, t0 + secs(32)));
    // нестрогий адрес этой же /64 предел строгих не трогает
    assert!(l.allow(addr("[2606:4700:1:2::77]:1"), false, t0 + secs(33)));
}

#[tokio::test(start_paused = true)]
async fn limiter_v6_per_ip_cap_per_64() {
    let cfg = ConnectConfig::default();
    let mut l = Limiter::new(&cfg);
    let t0 = Instant::now();
    // восемь разных адресов одной /64: не больше `per_ip_dials` за окно
    let mut taken = 0u32;
    for i in 1..=8u16 {
        if l.take(addr(&format!("[2606:4700:1:2::{i:x}]:4000")), false, t0) {
            taken += 1;
        }
    }
    assert_eq!(taken, cfg.per_ip_dials);
    // соседняя /64 не затронута
    assert!(l.take(addr("[2606:4700:1:9::1]:4000"), false, t0));
    // после окна снова можно
    assert!(l.take(
        addr("[2606:4700:1:2::9]:4000"),
        false,
        t0 + cfg.per_ip_window
    ));
}

#[tokio::test(start_paused = true)]
async fn limiter_v4_mapped_same_key_as_v4() {
    let cfg = ConnectConfig::default();
    let mut l = Limiter::new(&cfg);
    let t0 = Instant::now();
    assert_eq!(
        crate::limiter::victim_key(addr("[::ffff:5.6.7.8]:1")),
        crate::limiter::victim_key(addr("5.6.7.8:2"))
    );
    assert!(l.take(addr("5.6.7.8:4000"), true, t0));
    assert!(!l.take(addr("[::ffff:5.6.7.8]:4001"), true, t0 + secs(1)));
    // предел на IP считает обе записи вместе
    let mut taken = 1u32;
    for p in 0..8u16 {
        let a = if p % 2 == 0 {
            addr(&format!("[::ffff:5.6.7.8]:{}", 5000 + p))
        } else {
            addr(&format!("5.6.7.8:{}", 5000 + p))
        };
        if l.take(a, false, t0 + secs(2)) {
            taken += 1;
        }
    }
    assert_eq!(taken, cfg.per_ip_dials);
}

#[tokio::test(start_paused = true)]
async fn limiter_v4_unchanged() {
    // IPv4 по-прежнему по /32: соседние адреса одной /24 независимы
    let cfg = ConnectConfig::default();
    let mut l = Limiter::new(&cfg);
    let t0 = Instant::now();
    assert!(l.take(addr("5.6.7.8:4000"), true, t0));
    assert!(l.take(addr("5.6.7.9:4000"), true, t0));
    assert!(!l.take(addr("5.6.7.8:4001"), true, t0 + secs(1)));
    for i in 1..=cfg.per_ip_dials {
        assert!(l.take(addr(&format!("5.6.7.10:{}", 5000 + i)), false, t0));
    }
    assert!(!l.take(addr("5.6.7.10:6000"), false, t0));
    assert_eq!(
        crate::limiter::victim_key(addr("5.6.7.8:1")),
        "5.6.7.8".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(
        crate::limiter::victim_key(addr("[2606:4700:1:2:3:4:5:6]:1")),
        "2606:4700:1:2::".parse::<std::net::IpAddr>().unwrap()
    );
}
