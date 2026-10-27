//! Размещение на этой ОС: нет перезаписи, нет входа в чужие каталоги и по ссылкам, журналы,
//! метки происхождения. Windows запускается локально, остальные ОС в CI.

mod common;

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use chervo_receive::{ReceiveConfig, ReceivePlacement, TestPoint, sanitize_path};
use chervo_transfer::{PlaceError, Placement};
#[cfg(windows)]
use common::Tmp;
use common::rows::{Exp, rows};
use common::{Env, key, link_dir_or_skip, offered, place_offer, placed_path, stage, tree};

fn data(seed: u8, n: usize) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn canon(p: &Path) -> std::path::PathBuf {
    fs::canonicalize(p).expect("canonicalize")
}

#[test]
fn place_table_on_this_os() {
    let l = chervo_receive::ReceiveLimits::default();
    let table = rows();
    let mut ok_rows = 0usize;
    for (n, (input, exp)) in table.iter().enumerate() {
        let Exp::Out(_, _) = exp else { continue };
        ok_rows += 1;
        let (expected, _) = sanitize_path(input, &l).expect("ok row");
        let env = Env::new(&format!("tbl{n}"));
        let d = data(n as u8, 1500);
        let res = place_offer(&env, &key(1), &[(input.as_str(), d.clone())]);
        let placed = placed_path(res.first().expect("one result"));
        // ровно один путь, внутри канонического корня, содержимое идентично
        let mut want = env.root.root().to_path_buf();
        for c in expected.components() {
            want.push(c);
        }
        assert_eq!(placed, want, "input {input:?}");
        assert!(
            canon(&placed).starts_with(env.root.root()),
            "input {input:?}"
        );
        assert_eq!(fs::read(&placed).expect("read"), d, "input {input:?}");
        // в корне только дерево этого файла; рядом с корнем ничего нет
        let files: Vec<String> = env
            .tree()
            .into_iter()
            .filter(|e| !e.ends_with('/'))
            .collect();
        assert_eq!(files, [expected.display()], "input {input:?}");
        let siblings: Vec<_> = fs::read_dir(env.tmp.path())
            .expect("read tmp")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(siblings.len(), 2, "recv and outside only: {siblings:?}");
        assert!(
            fs::read_dir(&env.outside)
                .expect("outside")
                .next()
                .is_none(),
            "input {input:?}"
        );
    }
    println!(
        "place_table_on_this_os: os={} rows={ok_rows}",
        std::env::consts::OS
    );
}

#[test]
fn existing_file_not_overwritten() {
    let env = Env::new("exist");
    let a = env.root.root().join("a.txt");
    fs::write(&a, b"original").expect("write");
    let res = place_offer(&env, &key(1), &[("a.txt", b"new content".to_vec())]);
    let p = placed_path(res.first().expect("r"));
    assert_eq!(p, env.root.root().join("a (2).txt"));
    assert_eq!(fs::read(&a).expect("read"), b"original");
    assert_eq!(fs::read(&p).expect("read"), b"new content");
    // следующая передача того же имени получает следующий номер
    let res = place_offer(&env, &key(2), &[("a.txt", b"third".to_vec())]);
    assert_eq!(
        placed_path(res.first().expect("r")),
        env.root.root().join("a (3).txt")
    );
    assert_eq!(fs::read(&a).expect("read"), b"original");
}

#[test]
fn existing_user_dir_not_entered() {
    let env = Env::new("userdir");
    let photos = env.root.root().join("Photos");
    fs::create_dir(&photos).expect("mkdir");
    fs::write(photos.join("keep.txt"), b"mine").expect("write");
    let res = place_offer(&env, &key(1), &[("Photos/x.jpg", b"img".to_vec())]);
    let p = placed_path(res.first().expect("r"));
    assert_eq!(p, env.root.root().join("Photos (2)").join("x.jpg"));
    assert_eq!(tree(&photos), ["keep.txt"]);
    // папка из предложения всегда новая и для следующей передачи
    let res = place_offer(&env, &key(2), &[("Photos/y.jpg", b"img2".to_vec())]);
    assert_eq!(
        placed_path(res.first().expect("r")),
        env.root.root().join("Photos (3)").join("y.jpg")
    );
}

#[test]
fn folders_of_one_offer_share_one_new_folder() {
    let env = Env::new("shared");
    let res = place_offer(
        &env,
        &key(1),
        &[
            ("Album/a.jpg", data(1, 10)),
            ("album/b.jpg", data(2, 10)),
            ("Album/sub/c.jpg", data(3, 10)),
            ("top.txt", data(4, 10)),
        ],
    );
    assert!(res.iter().all(Result::is_ok));
    assert_eq!(
        env.tree(),
        [
            "Album/",
            "Album/a.jpg",
            "Album/b.jpg",
            "Album/sub/",
            "Album/sub/c.jpg",
            "top.txt"
        ]
    );
}

#[test]
fn case_twin_on_disk() {
    let env = Env::new("casetwin");
    fs::write(env.root.root().join("A.TXT"), b"upper").expect("write");
    let res = place_offer(&env, &key(1), &[("a.txt", b"lower".to_vec())]);
    let p = placed_path(res.first().expect("r"));
    let name = p.file_name().expect("name").to_string_lossy().into_owned();
    println!(
        "case_twin_on_disk: os={} placed as {name}",
        std::env::consts::OS
    );
    if cfg!(any(windows, target_os = "macos")) {
        assert_eq!(name, "a (2).txt");
    } else {
        assert_eq!(name, "a.txt");
    }
    assert_eq!(
        fs::read(env.root.root().join("A.TXT")).expect("read"),
        b"upper"
    );
}

#[test]
fn nfd_twin_on_disk() {
    // NFC на диске, предложение NFD: санитайзер приводит имя к NFC, поэтому везде (2)
    let env = Env::new("nfd1");
    fs::write(env.root.root().join("\u{439}.txt"), b"nfc").expect("write");
    let res = place_offer(&env, &key(1), &[("\u{438}\u{306}.txt", b"nfd".to_vec())]);
    let p = placed_path(res.first().expect("r"));
    assert_eq!(
        p.file_name().expect("n").to_string_lossy(),
        "\u{439} (2).txt"
    );
    // NFD на диске, предложение NFC: macOS считает имена равными, остальные ОС нет
    let env = Env::new("nfd2");
    fs::write(env.root.root().join("\u{438}\u{306}.txt"), b"nfd").expect("write");
    let res = place_offer(&env, &key(2), &[("\u{439}.txt", b"nfc".to_vec())]);
    let p = placed_path(res.first().expect("r"));
    let name = p.file_name().expect("n").to_string_lossy().into_owned();
    println!(
        "nfd_twin_on_disk: os={} placed as {name:?}",
        std::env::consts::OS
    );
    if cfg!(target_os = "macos") {
        assert_eq!(name, "\u{439} (2).txt");
    } else {
        assert_eq!(name, "\u{439}.txt");
        assert_eq!(env.tree().len(), 2, "both twins exist");
    }
}

#[test]
fn short_name_alias() {
    let env = Env::new("short");
    let long = env.root.root().join("LONGDIRECTORYNAME");
    fs::create_dir(&long).expect("mkdir");
    let res = place_offer(&env, &key(1), &[("LONGDI~1/x.txt", b"x".to_vec())]);
    let p = placed_path(res.first().expect("r"));
    // `~1` переписывается санитайзером в любом случае
    assert_eq!(p, env.root.root().join("LONGDI_1").join("x.txt"));
    assert!(tree(&long).is_empty());
    if cfg!(windows) {
        match fs::create_dir(env.root.root().join("LONGDI~1")) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                println!("short_name_alias: AlreadyExists, 8.3 names are on for this volume");
            }
            Ok(()) => println!("short_name_alias: created, 8.3 off on this volume"),
            Err(e) => println!("short_name_alias: other result {:?}", e.kind()),
        }
    } else {
        println!(
            "short_name_alias: os={} (8.3 check is Windows only)",
            std::env::consts::OS
        );
    }
}

#[test]
fn symlink_in_root_not_followed() {
    let env = Env::new("symroot");
    let link = env.root.root().join("Photos");
    let Some(_) = link_dir_or_skip("symlink_in_root_not_followed", &env.outside, &link) else {
        return;
    };
    let res = place_offer(&env, &key(1), &[("Photos/x", b"img".to_vec())]);
    let p = placed_path(res.first().expect("r"));
    assert_eq!(p, env.root.root().join("Photos (2)").join("x"));
    assert!(
        fs::read_dir(&env.outside)
            .expect("outside")
            .next()
            .is_none()
    );
}

#[test]
fn dangling_symlink_final_not_followed() {
    let env = Env::new("dangle");
    let target = env.outside.join("victim.txt");
    if let Err(why) = common::link_file(&target, &env.root.root().join("a.txt")) {
        println!("dangling_symlink_final_not_followed: SKIPPED, cannot create a file link: {why}");
        return;
    }
    let res = place_offer(&env, &key(1), &[("a.txt", b"payload".to_vec())]);
    let p = placed_path(res.first().expect("r"));
    assert_eq!(p, env.root.root().join("a (2).txt"));
    assert!(
        !target.exists(),
        "nothing created through the dangling link"
    );
    // ссылка на месте (на Windows `symlink_metadata` висячей ссылки даёт NotFound, поэтому
    // проверяем списком каталога)
    assert_eq!(env.tree(), ["a (2).txt", "a.txt"]);
    println!(
        "dangling_symlink_final_not_followed: os={} symlink_metadata(dangling)={:?}",
        std::env::consts::OS,
        fs::symlink_metadata(env.root.root().join("a.txt")).map_err(|e| e.kind())
    );
}

#[test]
fn dangling_dir_symlink_not_followed() {
    let env = Env::new("danglingdir");
    let missing = env.outside.join("missing-dir");
    if let Err(why) = common::link_dir(&missing, &env.root.root().join("Photos")) {
        println!("dangling_dir_symlink_not_followed: SKIPPED, cannot create a link: {why}");
        return;
    }
    // junction на несуществующую цель создать нельзя: этот тест идёт только с настоящей ссылкой
    let res = place_offer(&env, &key(1), &[("Photos/x", b"img".to_vec())]);
    assert_eq!(
        placed_path(&res[0]),
        env.root.root().join("Photos (2)").join("x")
    );
    assert!(!missing.exists());
    // висячая ссылка внутри нашего дерева
    let k = key(2);
    env.place
        .prepare(&k, &offered(&[("d/sub/x.txt", 4)]))
        .expect("prepare");
    common::link_dir(&missing, &env.root.root().join("d").join("sub")).expect("link");
    let cf = stage(&env, &k, 0, "d/sub/x.txt", b"data");
    assert_eq!(env.place.place(&cf).unwrap_err(), PlaceError::Refused);
    assert!(!missing.exists());
}

#[test]
fn link_inside_our_tree_refused() {
    let env = Env::new("intree");
    env.place
        .prepare(&key(1), &offered(&[("d/sub/x.txt", 4)]))
        .expect("prepare");
    // в нашем дереве каталог `sub` оказался ссылкой
    let link = env.root.root().join("d").join("sub");
    let Some(_) = link_dir_or_skip("link_inside_our_tree_refused", &env.outside, &link) else {
        return;
    };
    let cf = stage(&env, &key(1), 0, "d/sub/x.txt", b"data");
    assert_eq!(env.place.place(&cf).unwrap_err(), PlaceError::Refused);
    assert!(
        fs::read_dir(&env.outside)
            .expect("outside")
            .next()
            .is_none()
    );
}

#[cfg(windows)]
#[test]
fn junction_detected_as_link() {
    let env = Env::new("junction");
    let link = env.root.root().join("Photos");
    if let Err(why) = common::junction(&env.outside, &link) {
        println!("junction_detected_as_link: SKIPPED, mklink /J failed: {why}");
        return;
    }
    let m = fs::symlink_metadata(&link).expect("meta");
    println!(
        "junction_detected_as_link: is_symlink={} is_dir={}",
        m.file_type().is_symlink(),
        m.file_type().is_dir()
    );
    assert!(
        m.file_type().is_symlink(),
        "std reports a junction as a link"
    );
    let res = place_offer(&env, &key(1), &[("Photos/x", b"img".to_vec())]);
    assert_eq!(
        placed_path(res.first().expect("r")),
        env.root.root().join("Photos (2)").join("x")
    );
    assert!(
        fs::read_dir(&env.outside)
            .expect("outside")
            .next()
            .is_none()
    );
    // junction внутри нашего дерева
    env.place
        .prepare(&key(2), &offered(&[("d/sub/x.txt", 4)]))
        .expect("prepare");
    common::junction(&env.outside, &env.root.root().join("d").join("sub")).expect("junction");
    let cf = stage(&env, &key(2), 0, "d/sub/x.txt", b"data");
    assert_eq!(env.place.place(&cf).unwrap_err(), PlaceError::Refused);
    assert!(
        fs::read_dir(&env.outside)
            .expect("outside")
            .next()
            .is_none()
    );
}

#[test]
fn swap_dir_for_link_detected() {
    let env = Env::new("swap");
    let k = key(1);
    env.place
        .prepare(&k, &offered(&[("d/x.txt", 4)]))
        .expect("prepare");
    let probe = env.tmp.path().join("probe-link");
    if link_dir_or_skip("swap_dir_for_link_detected", &env.outside, &probe).is_none() {
        return;
    }
    let _ = fs::remove_dir(&probe).or_else(|_| fs::remove_file(&probe));
    let dir = env.root.root().join("d");
    let outside = env.outside.clone();
    let done = Arc::new(AtomicBool::new(false));
    let d2 = done.clone();
    env.place.set_test_hook(Arc::new(move |p| {
        if let TestPoint::BeforeLink { dir: checked } = p
            && checked == dir
            && !d2.swap(true, Ordering::SeqCst)
        {
            // между проверкой и ссылкой наш каталог подменяется ссылкой наружу
            fs::remove_dir(&dir)?;
            common::link_dir(&outside, &dir).map_err(std::io::Error::other)?;
        }
        Ok(())
    }));
    let cf = stage(&env, &k, 0, "d/x.txt", b"data");
    assert_eq!(env.place.place(&cf).unwrap_err(), PlaceError::Refused);
    assert!(done.load(Ordering::SeqCst), "the swap happened");
    let left = fs::read_dir(&env.outside).expect("outside").count();
    if cfg!(unix) {
        // Unix: файл опознан по устройству и inode и убран
        assert_eq!(left, 0, "outside must be empty afterwards");
    } else {
        // Windows (Рев. 3, F1): ничего не удаляем, чтобы не стать подставным исполнителем
        // удаления чужого файла; наш собственный файл остаётся снаружи (остаток записан)
        println!("swap_dir_for_link_detected: {left} stray file(s) left outside, none deleted");
        assert!(left <= 1);
    }
}

#[test]
fn confused_deputy_does_not_delete_user_file() {
    // F1: после ссылки каталог D подменяется ссылкой на V, где лежит файл пользователя с тем же
    // именем и той же длиной. Проверка не проходит; чужой файл удалять нельзя ни на одной ОС.
    let env = Env::new("deputy");
    let k = key(1);
    env.place
        .prepare(&k, &offered(&[("d/x.txt", 4)]))
        .expect("prepare");
    let probe = env.tmp.path().join("probe-link2");
    if link_dir_or_skip(
        "confused_deputy_does_not_delete_user_file",
        &env.outside,
        &probe,
    )
    .is_none()
    {
        return;
    }
    let _ = fs::remove_dir(&probe).or_else(|_| fs::remove_file(&probe));
    let victim = env.outside.join("x.txt");
    fs::write(&victim, b"USER").expect("victim");
    let dir = env.root.root().join("d");
    let outside = env.outside.clone();
    let done = Arc::new(AtomicBool::new(false));
    let d2 = done.clone();
    env.place.set_test_hook(Arc::new(move |p| {
        if let TestPoint::AfterLink { dir: made } = p
            && made == dir
            && !d2.swap(true, Ordering::SeqCst)
        {
            // наш файл и папка убираются, на месте папки ссылка к файлу пользователя
            fs::remove_file(dir.join("x.txt"))?;
            fs::remove_dir(&dir)?;
            common::link_dir(&outside, &dir).map_err(std::io::Error::other)?;
        }
        Ok(())
    }));
    let cf = stage(&env, &k, 0, "d/x.txt", b"data");
    assert_eq!(env.place.place(&cf).unwrap_err(), PlaceError::Refused);
    assert!(done.load(Ordering::SeqCst), "the swap happened");
    // файл пользователя цел (и содержимое, и длина совпадают с нашим 4 байта)
    assert_eq!(fs::read(&victim).expect("victim survives"), b"USER");
}

#[test]
fn small_max_name_never_makes_overlong_name() {
    // F7: при малом `max_name_bytes` суффикс ` (2)` не помещается: отказ, а не слишком длинное имя
    let env = Env::with("smallname", |c: &mut ReceiveConfig| {
        c.limits.max_name_bytes = 7
    });
    fs::write(env.root.root().join("a.txt"), b"mine").expect("write");
    let res = place_offer(&env, &key(1), &[("a.txt", data(1, 10))]);
    assert!(
        matches!(res.first(), Some(Err(PlaceError::Refused))),
        "{res:?}"
    );
    for e in fs::read_dir(env.root.root()).expect("dir").flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name != ".chervo-partial" {
            assert!(name.len() <= 7, "{name}");
        }
    }
    assert_eq!(
        fs::read(env.root.root().join("a.txt")).expect("read"),
        b"mine"
    );
}

#[cfg(unix)]
#[test]
fn no_exec_bit() {
    use std::os::unix::fs::PermissionsExt;
    let env = Env::new("noexec");
    let res = place_offer(
        &env,
        &key(1),
        &[("d/sub/run.sh", data(1, 10)), ("top.bin", data(2, 10))],
    );
    let mode = |p: &Path| fs::metadata(p).expect("meta").permissions().mode() & 0o777;
    for r in &res {
        let p = placed_path(r);
        assert_eq!(mode(&p) & 0o111, 0, "{:o}", mode(&p));
    }
    let root = env.root.root();
    assert_eq!(mode(&root.join("d")), 0o700);
    assert_eq!(mode(&root.join("d").join("sub")), 0o700);
    assert_eq!(mode(env.root.partial_dir()), 0o700);
    assert_eq!(mode(&env.root.partial_dir().join("receive")), 0o700);
    // журналы закрыты для остальных
    for e in fs::read_dir(env.root.partial_dir().join("receive"))
        .expect("read")
        .flatten()
    {
        assert_eq!(mode(&e.path()) & 0o077, 0);
    }
}

#[cfg(windows)]
#[test]
fn motw_written() {
    let env = Env::new("motw");
    let res = place_offer(&env, &key(1), &[("doc.pdf", data(1, 3000))]);
    let p = placed_path(res.first().expect("r"));
    let mut stream = p.clone().into_os_string();
    stream.push(":Zone.Identifier");
    let got = fs::read_to_string(&stream).expect("Zone.Identifier stream is present");
    assert_eq!(got, "[ZoneTransfer]\r\nZoneId=3\r\n");
    // основной поток нетронут
    assert_eq!(fs::read(&p).expect("read"), data(1, 3000));
    // временное имя ушло, метка осталась у размещённого файла (жёсткая ссылка её сохранила)
    println!("motw_written: Zone.Identifier survived the hard link: {got:?}");
    // и поток исчез вместе с отключением метки в настройках
    let env = Env::with("motw-off", |c| c.mark_of_the_web = false);
    let res = place_offer(&env, &key(1), &[("doc.pdf", data(1, 3000))]);
    let mut stream = placed_path(res.first().expect("r")).into_os_string();
    stream.push(":Zone.Identifier");
    assert!(fs::read(&stream).is_err(), "no stream when the mark is off");
}

#[cfg(windows)]
#[test]
fn motw_survives_rename_observation() {
    // наблюдение для отчёта: переносит ли переименование поток (запасной путь этапа 14)
    let tmp = Tmp::new("motwren");
    let a = tmp.path().join("a.placing");
    fs::write(&a, b"data").expect("write");
    let mut s = a.clone().into_os_string();
    s.push(":Zone.Identifier");
    fs::write(&s, "[ZoneTransfer]\r\nZoneId=3\r\n").expect("ads");
    let b = tmp.path().join("b.txt");
    fs::rename(&a, &b).expect("rename");
    let mut sb = b.clone().into_os_string();
    sb.push(":Zone.Identifier");
    let kept = fs::read_to_string(&sb);
    println!("motw rename observation: stream after rename = {kept:?}");
    assert_eq!(
        kept.expect("stream moved with the file"),
        "[ZoneTransfer]\r\nZoneId=3\r\n"
    );
}

#[test]
fn motw_failure_ignored() {
    let env = Env::new("motwfail");
    env.place.set_test_hook(Arc::new(|p| match p {
        TestPoint::BeforeMark => Err(std::io::Error::other("forced mark failure")),
        _ => Ok(()),
    }));
    let res = place_offer(&env, &key(1), &[("doc.pdf", data(1, 100))]);
    let p = placed_path(res.first().expect("r"));
    assert_eq!(fs::read(&p).expect("read"), data(1, 100));
    #[cfg(windows)]
    {
        let mut s = p.into_os_string();
        s.push(":Zone.Identifier");
        assert!(fs::read(&s).is_err(), "the mark was skipped");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn quarantine_written() {
    let env = Env::new("quar");
    let res = place_offer(&env, &key(1), &[("doc.pdf", data(1, 100))]);
    let p = placed_path(res.first().expect("r"));
    let out = std::process::Command::new("xattr")
        .arg("-p")
        .arg("com.apple.quarantine")
        .arg(&p)
        .output()
        .expect("run xattr");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    println!("quarantine_written: {text:?}");
    assert!(text.starts_with("0081;"), "{text:?}");
}

fn journal_files(env: &Env) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(env.root.partial_dir().join("receive"))
        .expect("read")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn replay_after_crash_returns_same_path() {
    let mut env = Env::new("replay");
    let k = key(1);
    let files = [("Album/a.jpg", data(1, 2000)), ("note.txt", data(2, 50))];
    // у `Album` уже есть пользовательский каталог: в журнале должно остаться `Album (2)`
    fs::create_dir(env.root.root().join("Album")).expect("mkdir");
    let first = place_offer(&env, &k, &files);
    let (p0, p1) = (placed_path(&first[0]), placed_path(&first[1]));
    assert_eq!(p0, env.root.root().join("Album (2)").join("a.jpg"));
    // крах: ссылка сделана, состояние не записано, процесс перезапущен; этап 14 снова
    // готовит временные файлы и вызывает размещение
    env.restart();
    let off = offered(&[("Album/a.jpg", 2000), ("note.txt", 50)]);
    env.place.prepare(&k, &off).expect("prepare again");
    let r0 = env
        .place
        .place(&stage(&env, &k, 0, "Album/a.jpg", &files[0].1))
        .expect("replay 0");
    let r1 = env
        .place
        .place(&stage(&env, &k, 1, "note.txt", &files[1].1))
        .expect("replay 1");
    assert_eq!((r0.path, r1.path), (p0, p1));
    assert_eq!(
        env.tree(),
        ["Album (2)/", "Album (2)/a.jpg", "Album/", "note.txt"],
        "no duplicates, no Album (3)"
    );
    assert_eq!(env.place.full_reads(), 2);
    // и повтор в том же процессе
    let again = env
        .place
        .place(&stage(&env, &k, 1, "note.txt", &files[1].1))
        .expect("again");
    assert_eq!(again.path, env.root.root().join("note.txt"));
    assert_eq!(env.tree().len(), 4);
}

#[test]
fn replay_lost_record_makes_duplicate_not_overwrite() {
    let mut env = Env::new("lost");
    let k = key(1);
    let files = [("a.txt", data(1, 100))];
    let first = place_offer(&env, &k, &files);
    let p0 = placed_path(&first[0]);
    // запись журнала потеряна (ОС не успела записать)
    env.restart();
    let jp = env.root.partial_dir().join("receive").join(format!(
        "{}.placed",
        chervo_transfer::state_dir_name(&k.pair, &k.id)
    ));
    fs::write(&jp, b"").expect("truncate journal");
    env.place
        .prepare(&k, &offered(&[("a.txt", 100)]))
        .expect("prepare");
    let r = env
        .place
        .place(&stage(&env, &k, 0, "a.txt", &files[0].1))
        .expect("place");
    assert_eq!(r.path, env.root.root().join("a (2).txt"));
    assert_eq!(
        fs::read(&p0).expect("read"),
        files[0].1,
        "original untouched"
    );
    assert_eq!(env.place.full_reads(), 0);
}

#[test]
fn replay_reads_at_most_once() {
    let mut env = Env::new("reads");
    let k = key(1);
    // 20 файлов одного размера (хитрый друг: много равных по размеру файлов)
    let files: Vec<(String, Vec<u8>)> = (0..20u8)
        .map(|i| (format!("f{i}.bin"), data(i, 4096)))
        .collect();
    let borrowed: Vec<(&str, Vec<u8>)> =
        files.iter().map(|(n, d)| (n.as_str(), d.clone())).collect();
    let first = place_offer(&env, &k, &borrowed);
    assert!(first.iter().all(Result::is_ok));
    env.restart();
    let off: Vec<(&str, usize)> = borrowed.iter().map(|(n, d)| (*n, d.len())).collect();
    env.place.prepare(&k, &offered(&off)).expect("prepare");
    for (i, (n, d)) in borrowed.iter().enumerate() {
        env.place
            .place(&stage(&env, &k, i as u32, n, d))
            .expect("replay");
    }
    assert_eq!(
        env.place.full_reads(),
        20,
        "one full read per file, no more"
    );
    assert_eq!(env.tree().len(), 20);
}

/// Меняет байты `.dirs`, пересчитывает контрольную сумму.
fn patch_dirs(path: &Path, patch: impl FnOnce(&mut Vec<u8>), fix_sum: bool) {
    let mut raw = fs::read(path).expect("read dirs");
    let body_len = raw.len() - 32;
    raw.truncate(body_len);
    patch(&mut raw);
    if fix_sum {
        let sum = ring::digest::digest(&ring::digest::SHA256, &raw);
        raw.extend_from_slice(sum.as_ref());
    } else {
        raw.extend_from_slice(&[0u8; 32]);
    }
    fs::write(path, raw).expect("write dirs");
}

#[test]
fn journal_tampered_rejected() {
    // каждая порча `.dirs` даёт безопасный пересчёт: новая папка, существующая не трогается
    type Patch = Box<dyn Fn(&Path)>;
    let cases: Vec<(&str, Patch)> = vec![
        ("bad checksum", Box::new(|p| patch_dirs(p, |_| {}, false))),
        (
            "k = 1000",
            Box::new(|p| {
                patch_dirs(
                    p,
                    |b| {
                        let off = 8 + 16 + 16 + 32 + 4;
                        b[off..off + 2].copy_from_slice(&1000u16.to_be_bytes());
                    },
                    true,
                );
            }),
        ),
        (
            "k = 0",
            Box::new(|p| {
                patch_dirs(
                    p,
                    |b| {
                        let off = 8 + 16 + 16 + 32 + 4;
                        b[off..off + 2].copy_from_slice(&0u16.to_be_bytes());
                    },
                    true,
                );
            }),
        ),
        (
            "wrong plan digest",
            Box::new(|p| {
                patch_dirs(p, |b| b[8 + 16 + 16] ^= 0xFF, true);
            }),
        ),
        (
            "wrong folder identity",
            Box::new(|p| {
                // F5: k и контрольные суммы верны, но папка не та, что мы создали
                patch_dirs(p, |b| b[8 + 16 + 16 + 32 + 4 + 2 + 7] ^= 0x55, true);
            }),
        ),
        (
            "old format magic",
            Box::new(|p| {
                patch_dirs(p, |b| b[7] = b'1', true);
            }),
        ),
        (
            "wrong key",
            Box::new(|p| {
                patch_dirs(p, |b| b[8] ^= 0xFF, true);
            }),
        ),
        (
            "wrong count",
            Box::new(|p| {
                patch_dirs(p, |b| b[8 + 16 + 16 + 32 + 3] = 7, true);
            }),
        ),
    ];
    for (n, (what, tamper)) in cases.iter().enumerate() {
        let mut env = Env::new(&format!("tamper{n}"));
        let k = key(1);
        let files = [("Dir/x.txt", data(1, 100))];
        let first = place_offer(&env, &k, &files);
        assert_eq!(
            placed_path(&first[0]),
            env.root.root().join("Dir").join("x.txt")
        );
        let hex = chervo_transfer::state_dir_name(&k.pair, &k.id);
        tamper(
            &env.root
                .partial_dir()
                .join("receive")
                .join(format!("{hex}.dirs")),
        );
        env.restart();
        env.place
            .prepare(&k, &offered(&[("Dir/x.txt", 100)]))
            .expect("prepare");
        let r = env
            .place
            .place(&stage(&env, &k, 0, "Dir/x.txt", &files[0].1))
            .expect("place");
        assert_eq!(
            r.path,
            env.root.root().join("Dir (2)").join("x.txt"),
            "{what}: tampered journal must not lead into an existing folder"
        );
        assert_eq!(
            fs::read(env.root.root().join("Dir").join("x.txt")).expect("read"),
            files[0].1,
            "{what}"
        );
    }
    // порча `.placed`: негодный хвост отбрасывается, журнал остаётся рабочим
    let mut env = Env::new("tamperplaced");
    let k = key(2);
    let files = [("a.txt", data(1, 100))];
    let first = place_offer(&env, &k, &files);
    let p0 = placed_path(&first[0]);
    let hex = chervo_transfer::state_dir_name(&k.pair, &k.id);
    let jp = env
        .root
        .partial_dir()
        .join("receive")
        .join(format!("{hex}.placed"));
    let mut raw = fs::read(&jp).expect("read");
    raw.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
    fs::write(&jp, raw).expect("write");
    env.restart();
    env.place
        .prepare(&k, &offered(&[("a.txt", 100)]))
        .expect("prepare");
    let r = env
        .place
        .place(&stage(&env, &k, 0, "a.txt", &files[0].1))
        .expect("replay");
    assert_eq!(r.path, p0);
    assert_eq!(fs::metadata(&jp).expect("meta").len() % 8, 0);
}

#[test]
fn forget_removes_journals_and_empty_dirs() {
    let env = Env::new("forget");
    let k = key(1);
    env.place
        .prepare(&k, &offered(&[("Dir/sub/x.txt", 10), ("y.txt", 10)]))
        .expect("prepare");
    assert_eq!(
        env.tree(),
        ["Dir/"],
        "top-level folder is created at prepare"
    );
    assert_eq!(journal_files(&env).len(), 2, "{:?}", journal_files(&env));
    env.place.forget(&k);
    assert!(journal_files(&env).is_empty());
    assert!(env.tree().is_empty(), "{:?}", env.tree());
    // передача, из которой что-то уже размещено: файлы и каталоги остаются
    let k2 = key(2);
    let files = [("Dir/sub/x.txt", data(1, 10)), ("Dir/z.txt", data(2, 10))];
    env.place
        .prepare(&k2, &offered(&[("Dir/sub/x.txt", 10), ("Dir/z.txt", 10)]))
        .expect("prepare");
    env.place
        .place(&stage(&env, &k2, 0, "Dir/sub/x.txt", &files[0].1))
        .expect("place");
    env.place.forget(&k2);
    assert!(journal_files(&env).is_empty());
    assert_eq!(env.tree(), ["Dir/", "Dir/sub/", "Dir/sub/x.txt"]);
    // повторный forget и forget неизвестного ключа безвредны
    env.place.forget(&k2);
    env.place.forget(&key(9));
}

#[test]
fn sweep_removes_orphan_journals_only() {
    let mut env = Env::new("sweep");
    let (ka, kb) = (key(1), key(2));
    for k in [&ka, &kb] {
        env.place
            .prepare(k, &offered(&[("D/x.txt", 10)]))
            .expect("prepare");
    }
    let hex_a = chervo_transfer::state_dir_name(&ka.pair, &ka.id);
    let hex_b = chervo_transfer::state_dir_name(&kb.pair, &kb.id);
    // каталог сеанса есть только у A
    fs::create_dir(env.root.partial_dir().join(&hex_a)).expect("session dir");
    let foreign = env.root.partial_dir().join("receive").join("notes.txt");
    fs::write(&foreign, b"mine").expect("foreign");
    assert!(journal_files(&env).iter().any(|n| n.starts_with(&hex_b)));
    env.restart();
    let left = journal_files(&env);
    assert!(left.iter().any(|n| n.starts_with(&hex_a)), "{left:?}");
    assert!(!left.iter().any(|n| n.starts_with(&hex_b)), "{left:?}");
    assert!(left.contains(&"notes.txt".to_owned()), "{left:?}");
}

#[test]
fn temp_outside_partial_refused() {
    let env = Env::new("tempout");
    let k = key(1);
    env.place
        .prepare(&k, &offered(&[("a.txt", 4)]))
        .expect("prepare");
    let good = stage(&env, &k, 0, "a.txt", b"data");
    // временный файл вне служебного каталога
    let elsewhere = env.outside.join("0.placing");
    fs::write(&elsewhere, b"data").expect("write");
    let bad = chervo_transfer::CompletedFile::new_for_test(
        k,
        0,
        good.name.clone(),
        4,
        good.root,
        elsewhere.clone(),
    );
    assert_eq!(env.place.place(&bad).unwrap_err(), PlaceError::Refused);
    // `..` в пути
    let dotted = env
        .root
        .partial_dir()
        .join("..")
        .join("..")
        .join("outside")
        .join("0.placing");
    let bad =
        chervo_transfer::CompletedFile::new_for_test(k, 0, good.name.clone(), 4, good.root, dotted);
    assert_eq!(env.place.place(&bad).unwrap_err(), PlaceError::Refused);
    assert!(env.tree().is_empty());
    assert!(elsewhere.exists(), "foreign file untouched");
    // настоящий временный файл размещается
    env.place.place(&good).expect("good");
}

#[test]
fn name_mismatch_refused() {
    let env = Env::new("mismatch");
    let k = key(1);
    env.place
        .prepare(&k, &offered(&[("a.txt", 4), ("b.txt", 4)]))
        .expect("prepare");
    // имя не то, что предложено под этим номером
    let cf = stage(&env, &k, 0, "b.txt", b"data");
    assert_eq!(env.place.place(&cf).unwrap_err(), PlaceError::Refused);
    // номер вне предложения
    let cf = stage(&env, &k, 5, "a.txt", b"data");
    assert_eq!(env.place.place(&cf).unwrap_err(), PlaceError::Refused);
    // размер не тот
    let cf = stage(&env, &k, 0, "a.txt", b"datadata");
    assert_eq!(env.place.place(&cf).unwrap_err(), PlaceError::Refused);
    // передача не подготовлена
    let cf = stage(&env, &key(7), 0, "a.txt", b"data");
    assert_eq!(env.place.place(&cf).unwrap_err(), PlaceError::Refused);
    assert!(env.tree().is_empty());
}

#[test]
fn prepare_refuses_hostile_offer() {
    let env = Env::new("hostile");
    for name in ["../x", "/etc/passwd", "a/../../b", "C:\\x"] {
        assert_eq!(
            env.place
                .prepare(&key(1), &offered(&[(name, 1)]))
                .unwrap_err(),
            PlaceError::Refused,
            "{name}"
        );
    }
    assert!(env.tree().is_empty());
    assert!(journal_files(&env).is_empty());
}

#[test]
fn temp_that_is_a_link_refused() {
    let env = Env::new("templink");
    let k = key(1);
    env.place
        .prepare(&k, &offered(&[("a.txt", 4)]))
        .expect("prepare");
    let real = env.outside.join("real.bin");
    fs::write(&real, b"data").expect("write");
    let good = stage(&env, &k, 0, "a.txt", b"data");
    let temp = good.temp_path().to_path_buf();
    fs::remove_file(&temp).expect("remove");
    if let Err(why) = common::link_file(&real, &temp) {
        println!("temp_that_is_a_link_refused: SKIPPED, cannot create a file link: {why}");
        return;
    }
    assert_eq!(env.place.place(&good).unwrap_err(), PlaceError::Refused);
    assert!(env.tree().is_empty());
}

#[test]
fn zero_length_file_placed() {
    let env = Env::new("empty");
    let res = place_offer(&env, &key(1), &[("empty.txt", Vec::new())]);
    let p = placed_path(&res[0]);
    assert_eq!(fs::metadata(&p).expect("meta").len(), 0);
}

#[cfg(windows)]
#[test]
fn long_path_over_260_placed() {
    let env = Env::new("longpath");
    let seg = "d".repeat(100);
    let name = format!("{seg}/{seg}/{seg}/file.txt");
    let plan = chervo_receive::plan_offer_for_root(
        &offered(&[(name.as_str(), 5)]),
        &env.cfg.limits,
        &env.root,
    )
    .expect("plan");
    let f = plan.files.first().expect("file");
    assert!(f.flags.long_path, "long_path flag must be raised");
    let res = place_offer(&env, &key(1), &[(name.as_str(), b"12345".to_vec())]);
    let p = placed_path(&res[0]);
    let units = p
        .to_string_lossy()
        .trim_start_matches(r"\\?\")
        .encode_utf16()
        .count();
    println!("long_path_over_260_placed: path length {units} UTF-16 units");
    assert!(units > 260);
    assert_eq!(fs::read(&p).expect("read"), b"12345");
}

#[test]
fn bad_limits_fall_back_to_defaults() {
    let env = Env::with("badlimits", |c: &mut ReceiveConfig| c.limits.max_files = 0);
    // конфигурация с нулём не отключает проверки: действуют значения по умолчанию
    let again = ReceivePlacement::new(env.root.clone(), &env.cfg);
    let res = {
        again
            .prepare(&key(1), &offered(&[("a.txt", 1)]))
            .expect("prepare");
        again.place(&stage(&env, &key(1), 0, "a.txt", b"x"))
    };
    assert!(res.is_ok());
}

#[test]
fn existing_dir_blocks_file_name() {
    let env = Env::new("dirblocks");
    fs::create_dir(env.root.root().join("a")).expect("mkdir");
    fs::write(env.root.root().join("a").join("keep"), b"mine").expect("write");
    let res = place_offer(&env, &key(1), &[("a", b"file".to_vec())]);
    let p = placed_path(&res[0]);
    assert_eq!(p, env.root.root().join("a (2)"));
    assert_eq!(fs::read(&p).expect("read"), b"file");
    assert_eq!(
        fs::read(env.root.root().join("a").join("keep")).expect("read"),
        b"mine"
    );
}

#[test]
fn concurrent_places_in_one_new_folder() {
    let env = Env::new("concurrent");
    let k = key(1);
    let names: Vec<String> = (0..16)
        .map(|i| format!("Top/s{}/f{i}.txt", i % 4))
        .collect();
    let off: Vec<(&str, usize)> = names.iter().map(|n| (n.as_str(), 8)).collect();
    env.place.prepare(&k, &offered(&off)).expect("prepare");
    // top-level folder removed after prepare: concurrent writers must not fail spuriously
    fs::remove_dir(env.root.root().join("Top")).expect("rmdir");
    let staged: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(i, n)| stage(&env, &k, i as u32, n, &data(i as u8, 8)))
        .collect();
    let results: Vec<_> = std::thread::scope(|s| {
        let hs: Vec<_> = staged
            .iter()
            .map(|cf| s.spawn(|| env.place.place(cf)))
            .collect();
        hs.into_iter().map(|h| h.join().expect("thread")).collect()
    });
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    assert_eq!(env.tree().iter().filter(|e| !e.ends_with('/')).count(), 16);
}
