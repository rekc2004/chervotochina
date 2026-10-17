//! Чистая логика живости сессии (`liveness.rs`): сроки считаются на уровне сессии и не
//! обнуляются новой попыткой.

use std::time::Duration;

use tokio::time::Instant;

use crate::liveness::Liveness;

#[tokio::test(start_paused = true)]
async fn growth_resets_silence_but_not_rate() {
    let mut lv = Liveness::new();
    let t0 = Instant::now();
    let stall = Duration::from_secs(10);
    lv.begin_wait(t0, 0);
    let rate0 = lv.rate_deadline(stall, 1 << 20, 8 << 20, None).unwrap();
    assert_eq!(rate0, t0 + Duration::from_secs(18));
    tokio::time::advance(Duration::from_secs(5)).await;
    lv.hash_grew(Instant::now());
    assert_eq!(
        lv.silence_deadline(stall, None).unwrap(),
        t0 + Duration::from_secs(15)
    );
    // новая попытка и рост не двигают предел по скорости
    lv.begin_attempt(Instant::now());
    lv.begin_wait(Instant::now(), 123);
    assert_eq!(
        lv.rate_deadline(stall, 1 << 20, 8 << 20, None).unwrap(),
        rate0
    );
}

#[tokio::test(start_paused = true)]
async fn grace_covers_only_an_attempt_without_frames() {
    let mut lv = Liveness::new();
    let stall = Duration::from_secs(10);
    let t0 = Instant::now();
    lv.begin_wait(t0, 0);
    tokio::time::advance(Duration::from_secs(3600)).await;
    let att = Instant::now();
    // долгая потеря связи: у новой попытки до первого кадра есть `stall`
    assert_eq!(lv.silence_deadline(stall, Some(att)).unwrap(), att + stall);
    assert_eq!(
        lv.rate_deadline(stall, 1 << 20, 8 << 20, Some(att))
            .unwrap(),
        att + stall
    );
    // после кадра сроки прежние, давно истёкшие
    assert!(lv.silence_deadline(stall, None).unwrap() < att);
    assert!(lv.rate_deadline(stall, 1 << 20, 8 << 20, None).unwrap() < att);
}

#[tokio::test(start_paused = true)]
async fn retry_resets_everything() {
    let mut lv = Liveness::new();
    lv.begin_wait(Instant::now(), 5);
    lv.stall();
    lv.reset();
    assert!(lv.silence_deadline(Duration::from_secs(1), None).is_none());
    assert_eq!(lv.stall(), 1);
}

#[tokio::test(start_paused = true)]
async fn futile_attempts_counted_until_progress() {
    let mut lv = Liveness::new();
    let seq0 = lv.begin_attempt(Instant::now());
    assert_eq!(lv.futile_attempt(seq0), 1);
    let seq1 = lv.begin_attempt(Instant::now());
    assert_eq!(lv.futile_attempt(seq1), 2);
    let seq2 = lv.begin_attempt(Instant::now());
    lv.progress(Instant::now());
    // продвижение внутри попытки: она не бесплодна, счёт обнулён
    assert_eq!(lv.futile_attempt(seq2), 0);
}

#[tokio::test(start_paused = true)]
async fn idle_counts_only_connected_demand_time() {
    let mut lv = Liveness::new();
    let limit = Duration::from_secs(30);
    lv.begin_attempt(Instant::now());
    tokio::time::advance(Duration::from_secs(20)).await;
    lv.end_attempt(Instant::now(), true);
    // долгий простой без связи не копится
    tokio::time::advance(Duration::from_secs(3600)).await;
    let t1 = Instant::now();
    lv.begin_attempt(t1);
    assert_eq!(
        lv.idle_deadline(limit).unwrap(),
        t1 + Duration::from_secs(10)
    );
    lv.progress(Instant::now());
    assert_eq!(lv.idle_deadline(limit).unwrap(), t1 + limit);
    // время без спроса на данные не копится
    lv.end_attempt(Instant::now(), false);
    assert!(!lv.idle_over(limit));
}
