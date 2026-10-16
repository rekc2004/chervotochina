use crate::FriendsError;
use crate::book::next_seq;

#[test]
fn next_seq_rules() {
    // временной пол: now * 1000 выше prev + 1
    assert_eq!(next_seq(0, 1_700_000_000), Some(1_700_000_000_000));
    assert_eq!(next_seq(5, 10), Some(10_000));
    // prev + 1 выше пола (повтор в ту же секунду, часы назад)
    assert_eq!(next_seq(10_000, 10), Some(10_001));
    assert_eq!(
        next_seq(1_700_000_000_000, 1_700_000_000),
        Some(1_700_000_000_001)
    );
    assert_eq!(next_seq(1_700_000_000_000, 5), Some(1_700_000_000_001));
    // строго возрастает при любых now
    let mut prev = 0u64;
    for now in [0u64, 0, 1, 1, 1, 0, 7, 7, 1_000_000_000_000] {
        let n = next_seq(prev, now).unwrap();
        assert!(n > prev);
        prev = n;
    }
    // пол не переполняется (saturating); prev + 1 = u64::MAX допустим
    assert_eq!(next_seq(0, u64::MAX), Some(u64::MAX));
    assert_eq!(next_seq(u64::MAX - 1, 1), Some(u64::MAX));
    // u64::MAX: следующего номера нет
    assert_eq!(next_seq(u64::MAX, 0), None);
    assert_eq!(next_seq(u64::MAX, u64::MAX), None);
    assert_eq!(
        FriendsError::SeqExhausted.to_string(),
        "address update numbers exhausted"
    );
}
