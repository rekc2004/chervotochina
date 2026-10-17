//! Политика приёма (Рев. 3): враждебное отклоняется, по умолчанию спрашиваем, автоприём только
//! для списка заведомо безопасных типов с чистыми именами, лимитов объёма нет, единственная
//! защита это свободное место на томе после приёма.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chervo_friends::{AutoAcceptLimits, Permission};
use chervo_identity::PairId;
use chervo_receive::{
    ASK_FILE_TEXT, DiskSpace, ReceiveConfig, ReceivePolicy, TRUST_QUESTION_TEXT, disk_space,
};
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

/// Значения лимитов политикой не читаются: любые ненулевые.
fn auto() -> Permission {
    Permission::AutoAccept(AutoAcceptLimits {
        max_total_bytes: 1,
        max_files: 1,
    })
}

fn pair(n: u8) -> PairId {
    PairId::from_bytes([n; 16])
}

const GIB: u64 = 1024 * 1024 * 1024;
const TIB: u64 = 1024 * GIB;

/// Том 1 ТиБ со свободным местом, которое двигает тест.
fn fake_disk(avail: u64) -> (Arc<AtomicU64>, ReceivePolicyFactory) {
    let free = Arc::new(AtomicU64::new(avail));
    (free.clone(), ReceivePolicyFactory { free })
}

struct ReceivePolicyFactory {
    free: Arc<AtomicU64>,
}

impl ReceivePolicyFactory {
    fn policy(&self, env: &Env) -> ReceivePolicy {
        let free = self.free.clone();
        ReceivePolicy::with_space_probe(
            env.root.clone(),
            &env.cfg,
            Arc::new(move |_| {
                Some(DiskSpace {
                    total_bytes: TIB,
                    available_bytes: free.load(Ordering::SeqCst),
                })
            }),
        )
    }
}

/// Политика с достаточно большим диском.
fn policy(env: &Env) -> ReceivePolicy {
    fake_disk(TIB).1.policy(env)
}

#[test]
fn policy_hostile_declined() {
    let env = Env::new("phostile");
    let p = policy(&env);
    for perm in [Permission::Ask, auto()] {
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
    // слишком много файлов отклоняется целиком (предел протокола), а объём нет
    let many: Vec<(String, u64)> = (0..10_001).map(|i| (format!("f{i}.txt"), 1)).collect();
    let many_ref: Vec<(&str, u64)> = many.iter().map(|(n, s)| (n.as_str(), *s)).collect();
    assert_eq!(
        p.decide(&pair(1), Permission::Ask, &view(&many_ref)),
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
fn policy_auto_accept_known_inert() {
    let env = Env::new("pauto");
    let p = policy(&env);
    let v = view(&[
        ("a.txt", 10),
        ("dir/b.jpg", 20),
        ("Фото/Отпуск 2024/IMG_1.JPG", 30),
        ("raw/IMG_0001.CR3", 40),
        ("raw/IMG_0002.ARW", 40),
        ("clip.mov", 40),
        ("song.flac", 40),
        ("doc.pdf", 40),
        ("model.gguf", 40),
        ("weights.safetensors", 40),
    ]);
    assert_eq!(p.decide(&pair(1), auto(), &v), PolicyVerdict::Accept);
}

#[test]
fn policy_archives_auto_accepted() {
    // решение владельца: архивы обычные файлы
    let env = Env::new("parch");
    let p = policy(&env);
    let v = view(&[
        ("photos.zip", 10),
        ("backup.tar.gz", 10),
        ("x.7z", 10),
        ("y.rar", 10),
        ("z.tar", 10),
    ]);
    assert_eq!(p.decide(&pair(1), auto(), &v), PolicyVerdict::Accept);
}

#[test]
fn policy_unknown_type_asks() {
    // неизвестное расширение, без расширения, `.bin`: вопрос «Вы доверяете отправителю...»
    let env = Env::new("punknown");
    let p = policy(&env);
    for name in [
        "data.dat",
        "weights.bin",
        "model.pt",
        "model.ckpt",
        "README",
        "table.csv",
        "notes.rtf",
        "photo.psd",
        "font.ttf",
    ] {
        let v = view(&[(name, 10)]);
        assert_eq!(p.decide(&pair(1), auto(), &v), PolicyVerdict::Ask, "{name}");
        let mixed = view(&[("clean.txt", 10), (name, 10)]);
        assert_eq!(
            p.decide(&pair(1), auto(), &mixed),
            PolicyVerdict::Ask,
            "{name} mixed"
        );
    }
    // тексты для экрана
    assert!(TRUST_QUESTION_TEXT.contains("Вы доверяете этому человеку"));
    assert_eq!(
        ASK_FILE_TEXT,
        "Вы доверяете отправителю и знаете, зачем этот файл?"
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
        ("old office", "report.doc".to_owned()),
        ("old excel", "table.xls".to_owned()),
        ("svg", "pic.svg".to_owned()),
        ("web page", "page.html".to_owned()),
        ("onenote", "n.one".to_owned()),
        ("access", "db.accdb".to_owned()),
        ("launcher", "x.appref-ms".to_owned()),
        ("macos loc", "x.inetloc".to_owned()),
        ("prefpane bundle", "My.prefpane/a.txt".to_owned()),
        ("deceptive", "photo.jpg.exe".to_owned()),
        ("deceptive spaces", "photo.jpg      .exe".to_owned()),
        ("hidden bidi", "photo\u{202E}gpj.txt".to_owned()),
        ("invisible", "a\u{200B}b.txt".to_owned()),
        ("long s ext", "x.vb\u{17F}".to_owned()),
        ("dotless i ext", "x.ms\u{131}".to_owned()),
        ("non-ascii ext of known type", "photo.jp\u{435}g".to_owned()),
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
            p.decide(&pair(1), auto(), &v),
            PolicyVerdict::Ask,
            "{what}: {name:?}"
        );
        // один рискованный файл среди чистых тоже блокирует автоприём
        let mixed = view(&[("clean.txt", 10), (name.as_str(), 10)]);
        assert_eq!(
            p.decide(&pair(1), auto(), &mixed),
            PolicyVerdict::Ask,
            "{what} mixed"
        );
    }
    // коллизия имён внутри предложения (имя переименовано)
    let v = view(&[("a.txt", 1), ("A.TXT", 1)]);
    assert_eq!(p.decide(&pair(1), auto(), &v), PolicyVerdict::Ask);
    assert_eq!(p.declined_hostile(), 0, "risky is asked, not declined");
}

#[test]
fn policy_no_volume_limit() {
    // ни лимита друга, ни потолка, ни суточного окна: пакет ~650 ГБ дважды подряд
    let env = Env::new("pnolimit");
    let (_free, f) = fake_disk(TIB);
    let p = f.policy(&env);
    let huge = Permission::AutoAccept(AutoAcceptLimits {
        max_total_bytes: 1,
        max_files: 1,
    });
    let v = view(&[("shoot.zip", 650 * GIB)]);
    for _ in 0..5 {
        assert_eq!(p.decide(&pair(1), huge, &v), PolicyVerdict::Accept);
    }
    let many: Vec<(String, u64)> = (0..2000).map(|i| (format!("f{i}.jpg"), 1)).collect();
    let many_ref: Vec<(&str, u64)> = many.iter().map(|(n, s)| (n.as_str(), *s)).collect();
    assert_eq!(
        p.decide(&pair(1), huge, &view(&many_ref)),
        PolicyVerdict::Accept,
        "more than 1000 files is fine"
    );
}

#[test]
fn policy_free_space_guard() {
    let env = Env::new("pspace");
    assert_eq!(env.cfg.min_free_percent, 10, "default is 10 percent");
    // диск 1 ТиБ; минимум 10 % = 102.4 ГиБ
    let (free, f) = fake_disk(500 * GIB);
    let p = f.policy(&env);
    let max_ok = 500 * GIB - TIB * 10 / 100;
    assert_eq!(
        p.decide(&pair(1), auto(), &view(&[("a.mp4", max_ok)])),
        PolicyVerdict::Accept,
        "exactly down to the minimum"
    );
    assert_eq!(
        p.decide(&pair(1), auto(), &view(&[("a.mp4", max_ok + 1)])),
        PolicyVerdict::Ask,
        "one byte below the minimum"
    );
    // больше свободного места вообще
    assert_eq!(
        p.decide(&pair(1), auto(), &view(&[("a.mp4", 600 * GIB)])),
        PolicyVerdict::Ask
    );
    // место ушло: тот же файл теперь вопрос
    free.store(50 * GIB, Ordering::SeqCst);
    assert_eq!(
        p.decide(&pair(1), auto(), &view(&[("a.mp4", 1)])),
        PolicyVerdict::Ask,
        "free space already under the minimum"
    );
    // обычный друг (Ask) от места не зависит
    assert_eq!(
        p.decide(&pair(1), Permission::Ask, &view(&[("a.mp4", 1)])),
        PolicyVerdict::Ask
    );
}

#[test]
fn policy_free_space_configurable() {
    let env0 = Env::with("pspace0", |c: &mut ReceiveConfig| c.min_free_percent = 0);
    let (_f0, fd) = fake_disk(100 * GIB);
    let p0 = fd.policy(&env0);
    assert_eq!(
        p0.decide(&pair(1), auto(), &view(&[("a.mp4", 100 * GIB)])),
        PolicyVerdict::Accept,
        "0 percent: only has to fit"
    );
    assert_eq!(
        p0.decide(&pair(1), auto(), &view(&[("a.mp4", 100 * GIB + 1)])),
        PolicyVerdict::Ask
    );
    let env50 = Env::with("pspace50", |c: &mut ReceiveConfig| c.min_free_percent = 50);
    let (_f1, fd) = fake_disk(600 * GIB);
    let p50 = fd.policy(&env50);
    assert_eq!(
        p50.decide(&pair(1), auto(), &view(&[("a.mp4", 88 * GIB)])),
        PolicyVerdict::Accept
    );
    assert_eq!(
        p50.decide(&pair(1), auto(), &view(&[("a.mp4", 100 * GIB)])),
        PolicyVerdict::Ask
    );
}

#[test]
fn policy_unknown_free_space_asks() {
    // место узнать нельзя (Windows без FFI): автоприём не срабатывает, спрашиваем
    let env = Env::new("punk");
    let p = ReceivePolicy::with_space_probe(env.root.clone(), &env.cfg, Arc::new(|_| None));
    assert_eq!(
        p.decide(&pair(1), auto(), &view(&[("a.txt", 1)])),
        PolicyVerdict::Ask
    );
}

#[test]
fn disk_space_allows_arithmetic() {
    let s = DiskSpace {
        total_bytes: 1000,
        available_bytes: 300,
    };
    assert!(s.allows(200, 10));
    assert!(!s.allows(201, 10));
    assert!(s.allows(300, 0));
    assert!(!s.allows(301, 0));
    assert!(!s.allows(u64::MAX, 0));
    // проценты свыше 100 считаются за 100
    assert!(!s.allows(0, 200), "total 1000 kept, only 300 free");
    let full = DiskSpace {
        total_bytes: u64::MAX,
        available_bytes: u64::MAX,
    };
    assert!(full.allows(0, 100), "no overflow at the extremes");
}

#[test]
fn real_disk_space_probe() {
    let env = Env::new("preal");
    let got = disk_space(env.root.root());
    if cfg!(unix) {
        let s = got.expect("statvfs works on unix");
        assert!(s.total_bytes > 0 && s.available_bytes <= s.total_bytes);
        println!(
            "real_disk_space_probe: total {} available {}",
            s.total_bytes, s.available_bytes
        );
    } else {
        // Windows: безопасного способа без `unsafe` нет (спецификация 15, Рев. 3)
        assert_eq!(got, None);
        println!("real_disk_space_probe: unknown on this OS, auto-accept asks");
    }
}
