//! Классы файлов и правило автоприёма. Без файловой системы.

use chervo_receive::{FileClass, ReceiveLimits, TypeInfo, classify, plan_offer, sanitize_path};
use chervo_transfer::{OfferedFile, UntrustedName};

fn info(name: &str) -> TypeInfo {
    let (p, _) = sanitize_path(name, &ReceiveLimits::default()).expect("sanitizable");
    classify(&p)
}

fn is(name: &str, class: FileClass, deceptive: bool) {
    assert_eq!(info(name), TypeInfo { class, deceptive }, "name {name:?}");
}

#[test]
fn classify_table() {
    use FileClass::*;
    for n in [
        "a.exe",
        "A.EXE",
        "x.bat",
        "x.cmd",
        "x.ps1",
        "x.vbs",
        "x.js",
        "x.msi",
        "x.lnk",
        "x.url",
        "x.dll",
        "x.jar",
        "x.hta",
        "x.reg",
        "x.scr",
        "x.app",
        "x.command",
        "x.pkg",
        "x.workflow",
        "x.sh",
        "x.bash",
        "x.run",
        "x.AppImage",
        "x.deb",
        "x.rpm",
        "x.py",
        "x.pl",
        "x.rb",
        "x.php",
        "x.library-ms",
        "x.settingcontent-ms",
        "x.msixbundle",
        "x.theme",
    ] {
        is(n, Executable, false);
    }
    for n in ["x.iso", "x.IMG", "x.vhd", "x.vhdx", "x.dmg"] {
        is(n, DiskImage, false);
    }
    for n in [
        "x.docm", "x.XLSM", "x.pptm", "x.xlsb", "x.html", "x.htm", "x.mhtml", "x.xhtml",
    ] {
        is(n, ActiveDocument, false);
    }
    // Архивы по решению владельца обычные файлы.
    for n in [
        "a.zip", "a.7z", "a.rar", "a.tar", "a.gz", "a.tar.gz", "a.tgz", "a.bz2", "a.xz", "a.zst",
        "a.cab", "a.cpio",
    ] {
        is(n, Ordinary, false);
    }
    for n in [
        "noext",
        "a.txt",
        "a.jpg",
        "a.pdf",
        "a.docx",
        "a.mp4",
        "a.exe.jpg",
        "x.exe.jpg",
    ] {
        is(n, Ordinary, false);
    }
    // Обман расширением.
    is("photo.jpg.exe", Executable, true);
    is("photo.jpg      .exe", Executable, true);
    is("Photo.JPG.EXE", Executable, true);
    is("report.pdf.scr", Executable, true);
    is("a.tar.gz.sh", Executable, false);
    is("setup.exe", Executable, false);
    is("jpg.exe", Executable, false);
    // RTL-приём нейтрализован заменой, но остаётся программой.
    is("photo\u{202E}gpj.exe", Executable, false);
    // Кириллические «е» и «х» это не программа ни в одной ОС.
    is("a.\u{435}\u{445}\u{435}", Ordinary, false);
    // Пакеты и каталоги.
    is("My.app/Contents/MacOS/My", Executable, false);
    is("dir.APP/readme.txt", Executable, false);
    is("x.framework/a", Executable, false);
    is("x.bundle/a", Executable, false);
    is("x.plugin/a", Executable, false);
    is("x.kext/a", Executable, false);
    is("x.appex/a", Executable, false);
    is("My.app.bak/readme.txt", Ordinary, false);
    is("apps/readme.txt", Ordinary, false);
    // Старший класс побеждает.
    is("x.app/disk.iso", Executable, false);
    // Слишком длинное расширение не расширение.
    let long_ext = format!("a.{}", "e".repeat(40));
    is(&long_ext, Ordinary, false);
    // Порядок классов.
    assert!(Ordinary < ActiveDocument && ActiveDocument < DiskImage && DiskImage < Executable);
}

fn offer(names: &[&str]) -> Vec<OfferedFile> {
    names
        .iter()
        .map(|n| OfferedFile {
            name: UntrustedName::new(n).expect("valid"),
            size: 5,
        })
        .collect()
}

fn auto_ok(names: &[&str]) -> bool {
    plan_offer(&offer(names), &ReceiveLimits::default())
        .expect("plan")
        .auto_ok()
}

#[test]
fn auto_ok_rules() {
    assert!(auto_ok(&["a.txt", "dir/b.jpg", "pics/c.png"]));
    // Архивы можно принимать автоматически.
    assert!(auto_ok(&["a.zip", "b.tar.gz", "c.7z"]));
    assert!(auto_ok(&[]));
    // Любой не обычный класс.
    assert!(!auto_ok(&["a.txt", "setup.exe"]));
    assert!(!auto_ok(&["x.iso"]));
    assert!(!auto_ok(&["x.docm"]));
    assert!(!auto_ok(&["x.html"]));
    assert!(!auto_ok(&["photo.jpg.exe"]));
    assert!(!auto_ok(&["My.app/a.txt"]));
    // Любой флаг имени.
    assert!(!auto_ok(&["CON.txt"]));
    assert!(!auto_ok(&["ab:c.txt"]));
    assert!(!auto_ok(&["a\u{200B}b.txt"]));
    assert!(!auto_ok(&["a.txt", "A.TXT"]));
    assert!(!auto_ok(&[".hidden"]));
    assert!(!auto_ok(&["x.\u{202E}txt"]));
    // Рев. 3: неизвестное расширение и файл без расширения не автоприём
    assert!(!auto_ok(&["a.dat"]));
    assert!(!auto_ok(&["noext"]));
    assert!(!auto_ok(&["a.bin"]));
}

#[test]
fn classify_review_gaps_f2() {
    use FileClass::*;
    for n in [
        "x.appref-ms",
        "x.msu",
        "x.ppkg",
        "x.vsto",
        "x.xbap",
        "x.deskthemepack",
        "x.searchConnector-ms",
        "x.diagcfg",
        "x.diagpkg",
        "x.wsb",
        "x.pyz",
        "x.pyzw",
        "x.dqy",
        "x.rqy",
        "x.wll",
        "x.fileloc",
        "x.inetloc",
        "x.flatpak",
        "My.prefpane/a",
        "My.saver/a",
        "My.scptd/a",
        "My.workflow/a",
        "My.action/a",
        "My.mpkg/a",
        "My.wdgt/a",
        "My.qlgenerator/a",
        "My.mdimporter/a",
        "My.xpc/a",
        "My.osax/a",
    ] {
        is(n, Executable, false);
    }
    is("x.sparseimage", DiskImage, false);
    for n in [
        "x.svg", "x.svgz", "x.xht", "x.shtml", "x.doc", "x.dot", "x.xls", "x.xlt", "x.xla",
        "x.ppt", "x.pot", "x.pps", "x.ppa", "x.wbk", "x.mdb", "x.accdb", "x.accde", "x.mde",
        "x.adp", "x.ade", "x.one", "x.onepkg", "X.DOC",
    ] {
        is(n, ActiveDocument, false);
    }
}

#[test]
fn classify_by_folded_extension_f3() {
    use FileClass::*;
    // длинная s и турецкая i без точки сворачиваются в ASCII
    is("x.vb\u{17F}", Executable, false);
    is("x.ms\u{131}", Executable, false);
    is("x.p\u{131}f", Executable, false);
    is("photo.jpg.vb\u{17F}", Executable, true);
    // полноширинная `a` в ASCII не сворачивается
    is("x.b\u{FF41}t", Ordinary, false);
    // не-ASCII в расширении поднимает `suspicious` на уровне плана, и это не автоприём
    for n in [
        "x.vb\u{17F}",
        "x.ms\u{131}",
        "a.\u{435}\u{445}\u{435}",
        "photo.jp\u{435}g",
    ] {
        let p = plan_offer(&offer(&[n]), &ReceiveLimits::default()).expect("plan");
        let f = p.files.first().expect("file");
        assert!(f.flags.suspicious, "{n:?} must be suspicious");
        assert!(!p.auto_ok(), "{n:?}");
    }
    // ASCII-расширение без странностей не подозрительно
    let p = plan_offer(
        &offer(&["a.jpg", "Фото/日本語.txt"]),
        &ReceiveLimits::default(),
    )
    .expect("plan");
    assert!(p.files.iter().all(|f| !f.flags.suspicious));
    assert!(p.auto_ok());
}

#[test]
fn known_inert_allowlist() {
    use chervo_receive::is_known_inert;
    let inert = |n: &str| {
        let (p, _) = sanitize_path(n, &ReceiveLimits::default()).expect("sanitizable");
        is_known_inert(&p)
    };
    for n in [
        "a.jpg",
        "a.JPEG",
        "a.png",
        "a.heic",
        "a.CR2",
        "a.cr3",
        "a.nef",
        "a.arw",
        "a.dng",
        "a.raf",
        "a.orf",
        "a.rw2",
        "a.mp4",
        "a.MOV",
        "a.mkv",
        "a.avi",
        "a.webm",
        "a.mp3",
        "a.wav",
        "a.flac",
        "a.m4a",
        "a.ogg",
        "a.pdf",
        "a.txt",
        "a.zip",
        "a.7z",
        "a.rar",
        "a.tar",
        "a.gz",
        "a.tar.gz",
        "a.tgz",
        "a.xz",
        "a.zst",
        "a.bz2",
        "m.gguf",
        "m.safetensors",
        "dir/sub/a.jpg",
    ] {
        assert!(inert(n), "{n}");
    }
    for n in [
        "noext",
        "a.bin",
        "a.dat",
        "a.pt",
        "a.pth",
        "a.ckpt",
        "a.pkl",
        "a.exe",
        "a.doc",
        "a.docx",
        "a.xlsx",
        "a.csv",
        "a.rtf",
        "a.svg",
        "a.html",
        "a.iso",
        "a.cab",
        "a.ttf",
        "a.psd",
        "a.ts",
        "a.jpg.exe",
        "My.app/a.jpg",
        "a.\u{435}\u{445}\u{435}",
        "a.jp\u{435}g",
    ] {
        assert!(!inert(n), "{n}");
    }
}
