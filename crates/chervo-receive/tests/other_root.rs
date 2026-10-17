//! Принять предложение в другую папку приёма (Рев. 5): место проверяется заново на томе новой
//! папки, размещение работает там с теми же гарантиями (санитайзер, ничего не перезаписывается,
//! временные файлы в её `.chervo-partial`), выбор находится после перезапуска.

mod common;

use std::fs;
use std::path::Path;
use std::sync::Arc;

use chervo_receive::{ChooseRootError, DiskSpace, ReceiveConfig, ReceivePlacement, ReceiveRoot};
use chervo_transfer::{
    CompletedFile, InboundReservation, OfferView, PlaceError, Placement, TransferKey,
    UntrustedName, state_dir_name,
};
use common::{Env, key, offered, root_of, tree};

fn second_root(env: &Env, name: &str) -> ReceiveRoot {
    let dir = env.tmp.path().join(name);
    fs::create_dir(&dir).expect("create second root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod");
    }
    ReceiveRoot::open(&ReceiveConfig::new(dir)).expect("open second root")
}

fn view(k: &TransferKey, files: &[(&str, usize)], inbound: Vec<InboundReservation>) -> OfferView {
    let files = offered(files);
    OfferView {
        key: *k,
        total_size: files.iter().map(|f| f.size).sum(),
        files,
        inbound,
    }
}

/// Временный файл передачи внутри `.chervo-partial` указанной папки (как после этапа 14).
fn stage_in(
    root: &ReceiveRoot,
    k: &TransferKey,
    index: u32,
    name: &str,
    data: &[u8],
) -> CompletedFile {
    let dir = root.partial_dir().join(state_dir_name(&k.pair, &k.id));
    let _ = fs::create_dir(&dir);
    let temp = dir.join(format!("{index}.placing"));
    fs::write(&temp, data).expect("write temp");
    CompletedFile::new_for_test(
        *k,
        index,
        UntrustedName::new(name).expect("valid name"),
        data.len() as u64,
        root_of(data),
        temp,
    )
}

/// Размещение с подставным местом: у папок под `small` мало места, у остальных много.
fn placement(env: &Env, small: Option<&ReceiveRoot>) -> ReceivePlacement {
    let small = small.map(|r| r.root().to_path_buf());
    ReceivePlacement::new(env.root.clone(), &env.cfg).with_space_probe(Arc::new(move |p: &Path| {
        let low = small.as_ref().is_some_and(|s| p.starts_with(s));
        Some(DiskSpace {
            total_bytes: 1000,
            available_bytes: if low { 100 } else { 100_000 },
        })
    }))
}

fn tops(env: &Env) -> Vec<String> {
    tree(env.root.root())
}

#[test]
fn choose_root_rechecks_space_on_the_new_root() {
    let env = Env::new("cr-space");
    let small = second_root(&env, "small");
    let big = second_root(&env, "big");
    let p = placement(&env, Some(&small));
    let k = key(1);
    // 500 байт и запас 10 % от 1000 = 100: нужно 600
    let v = view(&k, &[("a.jpg", 500)], vec![]);
    match p.choose_root(&v, small.clone()) {
        Err(ChooseRootError::Insufficient(s)) => {
            assert_eq!((s.needed, s.available), (600, 100));
            assert_eq!(s.root, small.root());
        }
        other => panic!("expected Insufficient, got {other:?}"),
    }
    assert_eq!(
        p.partial_base(&k),
        None,
        "a failed choice is not remembered"
    );
    p.choose_root(&v, big.clone())
        .expect("fits on the big root");
    assert_eq!(p.partial_base(&k), Some(big.partial_dir().to_path_buf()));
    // резерв остальных приёмов вычитается и на новой папке (тот же том, что их каталог)
    let busy = view(
        &k,
        &[("a.jpg", 500)],
        vec![InboundReservation {
            partial_dir: env.root.partial_dir().to_path_buf(),
            outstanding: 99_500,
        }],
    );
    match p.choose_root(&busy, big.clone()) {
        Err(ChooseRootError::Insufficient(s)) => assert_eq!((s.needed, s.available), (600, 500)),
        other => panic!("expected Insufficient, got {other:?}"),
    }
    // выбор снимается
    p.unchoose_root(&k);
    assert_eq!(p.partial_base(&k), None);
}

#[test]
fn choose_root_unknown_space_keeps_the_choice() {
    let env = Env::new("cr-unknown");
    let other = second_root(&env, "other");
    let p = ReceivePlacement::new(env.root.clone(), &env.cfg).with_space_probe(Arc::new(|_| None));
    let k = key(1);
    p.choose_root(&view(&k, &[("a.jpg", 5)], vec![]), other.clone())
        .expect("an explicit choice stands when space is unknown");
    assert_eq!(p.partial_base(&k), Some(other.partial_dir().to_path_buf()));
}

#[test]
fn choose_root_hostile_offer_is_refused() {
    let env = Env::new("cr-hostile");
    let other = second_root(&env, "other");
    let p = placement(&env, None);
    let k = key(1);
    let r = p.choose_root(&view(&k, &[("../x", 1)], vec![]), other);
    assert!(matches!(r, Err(ChooseRootError::Plan(_))), "{r:?}");
}

#[test]
fn accepted_into_other_root_is_placed_there_with_the_same_guarantees() {
    let env = Env::new("cr-place");
    let other = second_root(&env, "other");
    let p = placement(&env, None);
    let k = key(1);
    let files: Vec<(&str, Vec<u8>)> = vec![
        ("a.txt", b"first".to_vec()),
        ("Photos/CON.txt", b"second".to_vec()),
        ("Photos/ab:c.jpg", b"third".to_vec()),
    ];
    // в новой папке уже лежат чужие файлы и папка с тем же именем: ничего не перезаписывается
    fs::write(other.root().join("a.txt"), b"mine").expect("pre-existing");
    fs::create_dir(other.root().join("Photos")).expect("pre-existing dir");
    let off: Vec<(&str, usize)> = files.iter().map(|(n, d)| (*n, d.len())).collect();
    p.choose_root(&view(&k, &off, vec![]), other.clone())
        .expect("choose");
    p.prepare(&k, &offered(&off)).expect("prepare");
    let mut placed = Vec::new();
    for (i, (n, d)) in files.iter().enumerate() {
        let cf = stage_in(&other, &k, i as u32, n, d);
        placed.push(p.place(&cf).expect("placed").path);
    }
    for path in &placed {
        let c = fs::canonicalize(path).expect("canonical");
        assert!(
            c.starts_with(other.root()),
            "{path:?} is outside the chosen root"
        );
        assert!(
            !c.starts_with(env.root.root()),
            "{path:?} is in the main root"
        );
    }
    assert_eq!(fs::read(other.root().join("a.txt")).unwrap(), b"mine");
    assert_eq!(
        fs::read(other.root().join("a (2).txt")).unwrap(),
        b"first",
        "no overwrite"
    );
    // имена те же, что дал бы санитайзер: `CON.txt` и `ab:c.jpg` переписаны, папка новая
    let t = tree(other.root());
    assert!(t.contains(&"Photos (2)/".to_owned()), "{t:?}");
    assert!(t.contains(&"Photos (2)/_CON.txt".to_owned()), "{t:?}");
    assert!(t.contains(&"Photos (2)/ab_c.jpg".to_owned()), "{t:?}");
    // основная папка не тронута
    assert!(
        tops(&env).is_empty(),
        "main root untouched: {:?}",
        tops(&env)
    );
    // временный файл из основной папки для этой передачи не принимается
    let wrong = stage_in(&env.root, &k, 0, "a.txt", b"first");
    assert_eq!(p.place(&wrong).err(), Some(PlaceError::Refused));
    // журналы лежат у новой папки; `forget` убирает их и снимает выбор
    let journals = other.partial_dir().join("receive");
    assert!(fs::read_dir(&journals).expect("journals").next().is_some());
    p.forget(&k);
    assert!(fs::read_dir(&journals).expect("journals").next().is_none());
    assert_eq!(p.partial_base(&k), None);
}

#[test]
fn other_root_session_is_found_after_restart_when_the_root_is_known() {
    let env = Env::new("cr-restart");
    let other = second_root(&env, "other");
    let k = key(3);
    let data = b"payload".to_vec();
    // прежняя жизнь процесса: каталог передачи в `.chervo-partial` выбранной папки
    let staged = stage_in(&other, &k, 0, "x.jpg", &data);

    // перезапуск без списка папок: передача не привязана к новой папке, размещение отказывает
    let lost = placement(&env, None);
    assert!(lost.extra_partial_dirs().is_empty());
    lost.prepare(&k, &offered(&[("x.jpg", data.len())]))
        .expect("prepare in the main root");
    assert_eq!(lost.place(&staged).err(), Some(PlaceError::Refused));
    lost.forget(&k);

    // перезапуск со списком известных папок: сеанс найден по каталогу, файл лёг в новую папку
    let found = placement(&env, None);
    found.add_known_root(other.clone());
    found.add_known_root(other.clone());
    assert_eq!(
        found.extra_partial_dirs(),
        vec![other.partial_dir().to_path_buf()],
        "listed once so the transfer layer scans it at start"
    );
    found
        .prepare(&k, &offered(&[("x.jpg", data.len())]))
        .expect("prepare");
    let path = found.place(&staged).expect("placed").path;
    assert!(fs::canonicalize(&path).unwrap().starts_with(other.root()));
    assert_eq!(fs::read(&path).unwrap(), data);
    assert!(tops(&env).is_empty());
}
