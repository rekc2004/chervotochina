//! Политика приёма: враждебное отклоняется, по умолчанию спрашиваем, автоприём только для
//! чистых обычных файлов в пределах лимитов друга, потолка и скользящих 24 часов.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use chervo_friends::{AutoAcceptLimits, Permission};
use chervo_identity::PairId;
use chervo_receive::{ReceiveConfig, ReceivePolicy};
use chervo_transfer::{AcceptPolicy, OfferView, OfferedFile, PolicyVerdict, UntrustedName};
use common::{Env, key};

fn view(files: &[(&str, u64)]) -> OfferView {
    let files: Vec<OfferedFile> = files
        .iter()
        .map(|(n, s)| OfferedFile {
            name: UntrustedName::new(n).expect("valid name"),
            size: *s,
        })
        .collect();
    OfferView {
        key: key(1),
        total_size: files.iter().map(|f| f.size).sum(),
        files,
    }
}

fn auto(bytes: u64, files: u32) -> Permission {
    Permission::AutoAccept(AutoAcceptLimits {
        max_total_bytes: bytes,
        max_files: files,
    })
}

fn pair(n: u8) -> PairId {
    PairId::from_bytes([n; 16])
}

fn policy(env: &Env) -> ReceivePolicy {
    ReceivePolicy::new(env.root.clone(), &env.cfg)
}

const GIB: u64 = 1024 * 1024 * 1024;

#[test]
fn policy_hostile_declined() {
    let env = Env::new("phostile");
    let p = policy(&env);
    for perm in [Permission::Ask, auto(GIB, 10)] {
        for name in ["../x", "/etc/passwd", "C:\\Windows\\x", "a//b", "a/./b"] {
            assert_eq!(
                p.decide(&pair(1), perm, &view(&[(name, 1)])),
                PolicyVerdict::Decline,
                "{name}"
            );
        }
    }
    assert_eq!(p.declined_hostile(), 10);
    // чистое предложение счётчик не трогает
    assert_eq!(
        p.decide(&pair(1), Permission::Ask, &view(&[("a.txt", 1)])),
        PolicyVerdict::Ask
    );
    assert_eq!(p.declined_hostile(), 10);
    // слишком много файлов и слишком большой размер тоже отклоняются целиком
    let big = view(&[("a.txt", 3 * 1024 * GIB)]);
    assert_eq!(
        p.decide(&pair(1), Permission::Ask, &big),
        PolicyVerdict::Decline
    );
    assert_eq!(p.declined_hostile(), 11);
}

#[test]
fn policy_ask_by_default() {
    let env = Env::new("pask");
    let p = policy(&env);
    let v = view(&[("a.txt", 10), ("dir/b.jpg", 20)]);
    assert_eq!(
        p.decide(&pair(1), Permission::default(), &v),
        PolicyVerdict::Ask
    );
    assert_eq!(p.decide(&pair(1), Permission::Ask, &v), PolicyVerdict::Ask);
}

#[test]
fn policy_auto_accept_clean_within_limits() {
    let env = Env::new("pauto");
    let p = policy(&env);
    let v = view(&[
        ("a.txt", 10),
        ("dir/b.jpg", 20),
        ("Фото/Отпуск 2024/IMG_1.JPG", 30),
    ]);
    assert_eq!(
        p.decide(&pair(1), auto(1000, 10), &v),
        PolicyVerdict::Accept
    );
    // свыше лимита друга (по размеру или по числу файлов): спросить
    assert_eq!(
        p.decide(&pair(2), auto(59, 10), &v),
        PolicyVerdict::Ask,
        "bytes over the friend's limit"
    );
    assert_eq!(
        p.decide(&pair(2), auto(1000, 2), &v),
        PolicyVerdict::Ask,
        "files over the friend's limit"
    );
    // ровно в пределе допустимо
    assert_eq!(p.decide(&pair(3), auto(60, 3), &v), PolicyVerdict::Accept);
}

#[test]
fn policy_archives_auto_accepted() {
    // решение владельца: архивы обычные файлы
    let env = Env::new("parch");
    let p = policy(&env);
    let v = view(&[("photos.zip", 10), ("backup.tar.gz", 10), ("x.7z", 10)]);
    assert_eq!(
        p.decide(&pair(1), auto(1000, 10), &v),
        PolicyVerdict::Accept
    );
}

#[test]
fn policy_auto_never_for_risky() {
    let env = Env::new("prisky");
    let p = policy(&env);
    let mut cases: Vec<(&str, String)> = vec![
        ("executable", "setup.exe".to_owned()),
        ("script", "run.ps1".to_owned()),
        ("shell", "install.sh".to_owned()),
        ("app bundle", "My.app/Contents/MacOS/My".to_owned()),
        ("disk image", "disk.iso".to_owned()),
        ("dmg", "installer.dmg".to_owned()),
        ("macro document", "report.docm".to_owned()),
        ("web page", "page.html".to_owned()),
        ("deceptive", "photo.jpg.exe".to_owned()),
        ("deceptive spaces", "photo.jpg      .exe".to_owned()),
        ("hidden bidi", "photo\u{202E}gpj.txt".to_owned()),
        ("invisible", "a\u{200B}b.txt".to_owned()),
        ("changed reserved", "CON.txt".to_owned()),
        ("changed char", "ab:c.txt".to_owned()),
        ("changed hidden", ".bashrc".to_owned()),
        ("changed trailing dot", "file.txt.".to_owned()),
    ];
    if cfg!(windows) {
        let seg = "d".repeat(100);
        cases.push(("long path", format!("{seg}/{seg}/{seg}/file.txt")));
    }
    for (what, name) in &cases {
        let v = view(&[(name.as_str(), 10)]);
        assert_eq!(
            p.decide(&pair(1), auto(GIB, 100), &v),
            PolicyVerdict::Ask,
            "{what}: {name:?}"
        );
        // один рискованный файл среди чистых тоже блокирует автоприём
        let mixed = view(&[("clean.txt", 10), (name.as_str(), 10)]);
        assert_eq!(
            p.decide(&pair(1), auto(GIB, 100), &mixed),
            PolicyVerdict::Ask,
            "{what} mixed"
        );
    }
    // коллизия имён внутри предложения (имя переименовано)
    let v = view(&[("a.txt", 1), ("A.TXT", 1)]);
    assert_eq!(p.decide(&pair(1), auto(GIB, 100), &v), PolicyVerdict::Ask);
    assert_eq!(p.declined_hostile(), 0, "risky is asked, not declined");
}

#[test]
fn policy_ceiling_applies() {
    let env = Env::new("pceil");
    // потолок по умолчанию: 16 ГиБ и 1000 файлов
    let cfg = ReceiveConfig::new(env.root.root().to_path_buf());
    assert_eq!(cfg.auto_ceiling.max_total_bytes, 16 * GIB);
    assert_eq!(cfg.auto_ceiling.max_files, 1000);
    let p = policy(&env);
    let huge = auto(1024 * GIB, 1_000_000);
    assert_eq!(
        p.decide(&pair(1), huge, &view(&[("a.dat", 16 * GIB)])),
        PolicyVerdict::Accept,
        "exactly the ceiling"
    );
    assert_eq!(
        p.decide(&pair(2), huge, &view(&[("a.dat", 16 * GIB + 1)])),
        PolicyVerdict::Ask,
        "friend allows more, the ceiling does not"
    );
    let many: Vec<(String, u64)> = (0..1001).map(|i| (format!("f{i}.txt"), 1)).collect();
    let many_ref: Vec<(&str, u64)> = many.iter().map(|(n, s)| (n.as_str(), *s)).collect();
    assert_eq!(
        p.decide(&pair(3), huge, &view(&many_ref)),
        PolicyVerdict::Ask,
        "1001 files over the ceiling"
    );
    assert_eq!(
        p.decide(&pair(4), huge, &view(many_ref.get(..1000).expect("slice"))),
        PolicyVerdict::Accept
    );
    // потолок из настроек
    let env2 = Env::with("pceil2", |c| {
        c.auto_ceiling = AutoAcceptLimits {
            max_total_bytes: 100,
            max_files: 2,
        };
    });
    let p2 = policy(&env2);
    assert_eq!(
        p2.decide(&pair(1), huge, &view(&[("a", 100), ("b", 0)])),
        PolicyVerdict::Accept
    );
    assert_eq!(
        p2.decide(&pair(2), huge, &view(&[("a", 101)])),
        PolicyVerdict::Ask
    );
    assert_eq!(
        p2.decide(&pair(3), huge, &view(&[("a", 1), ("b", 1), ("c", 1)])),
        PolicyVerdict::Ask
    );
}

/// Часы, которые двигает тест.
fn clock() -> (Arc<AtomicU64>, Arc<dyn Fn() -> Instant + Send + Sync>) {
    let base = Instant::now();
    let secs = Arc::new(AtomicU64::new(0));
    let s2 = secs.clone();
    (
        secs,
        Arc::new(move || base + Duration::from_secs(s2.load(Ordering::SeqCst))),
    )
}

#[test]
fn policy_rolling_quota_24h() {
    let env = Env::new("pquota");
    let (secs, clk) = clock();
    let p = ReceivePolicy::with_clock(env.root.clone(), &env.cfg, clk);
    let friend = auto(100, 10);
    let v = view(&[("a.dat", 60)]);
    assert_eq!(p.decide(&pair(1), friend, &v), PolicyVerdict::Accept);
    // в окне осталось 40 байт
    assert_eq!(p.decide(&pair(1), friend, &v), PolicyVerdict::Ask);
    secs.store(23 * 3600 + 59 * 60, Ordering::SeqCst);
    assert_eq!(p.decide(&pair(1), friend, &v), PolicyVerdict::Ask);
    // другой друг считается отдельно
    assert_eq!(p.decide(&pair(2), friend, &v), PolicyVerdict::Accept);
    // первая запись вышла из окна
    secs.store(24 * 3600, Ordering::SeqCst);
    assert_eq!(p.decide(&pair(1), friend, &v), PolicyVerdict::Accept);
    assert_eq!(p.decide(&pair(1), friend, &v), PolicyVerdict::Ask);
    // по числу файлов окно тоже скользит
    let few = auto(1000, 3);
    let three = view(&[("a", 1), ("b", 1), ("c", 1)]);
    secs.store(100 * 3600, Ordering::SeqCst);
    assert_eq!(p.decide(&pair(3), few, &three), PolicyVerdict::Accept);
    assert_eq!(
        p.decide(&pair(3), few, &view(&[("d", 1)])),
        PolicyVerdict::Ask
    );
    secs.store(125 * 3600, Ordering::SeqCst);
    assert_eq!(
        p.decide(&pair(3), few, &view(&[("d", 1)])),
        PolicyVerdict::Accept
    );
}

#[test]
fn policy_quota_counts_on_accept() {
    let env = Env::new("pcount");
    let (_secs, clk) = clock();
    let p = ReceivePolicy::with_clock(env.root.clone(), &env.cfg, clk);
    let friend = auto(100, 10);
    // отказ по лимиту, рискованное и враждебное предложения расход не создают
    assert_eq!(
        p.decide(&pair(1), friend, &view(&[("big.dat", 101)])),
        PolicyVerdict::Ask
    );
    assert_eq!(
        p.decide(&pair(1), friend, &view(&[("setup.exe", 90)])),
        PolicyVerdict::Ask
    );
    assert_eq!(
        p.decide(&pair(1), friend, &view(&[("../x", 90)])),
        PolicyVerdict::Decline
    );
    assert_eq!(
        p.decide(&pair(1), Permission::Ask, &view(&[("a.dat", 90)])),
        PolicyVerdict::Ask
    );
    // всё окно ещё свободно
    assert_eq!(
        p.decide(&pair(1), friend, &view(&[("ok.dat", 100)])),
        PolicyVerdict::Accept
    );
    // а теперь занято
    assert_eq!(
        p.decide(&pair(1), friend, &view(&[("ok2.dat", 1)])),
        PolicyVerdict::Ask
    );
}
