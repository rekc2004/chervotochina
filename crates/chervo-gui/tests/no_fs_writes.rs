//! Охрана «GUI сам ничего не пишет на диск» (этап 18б, SPEC 4.4): в `src/` нет записи и
//! изменения файлов и папок (`fs::write`, `File::create`, `OpenOptions`, создание, удаление,
//! переименование, копирование) и нет диалога сохранения. Всё, что нужно сохранить, сохраняет
//! узел (настройки, список друзей).

mod common;

const FORBIDDEN: [&str; 16] = [
    "fs::write",
    "File::create",
    "File::create_new",
    "File::options",
    ".options()",
    "OpenOptions",
    "create_dir",
    "remove_file",
    "remove_dir",
    "fs::rename",
    "fs::copy",
    "hard_link",
    "set_permissions",
    "set_modified",
    "save_file",
    "std::fs::File",
];

#[test]
fn gui_src_writes_no_files() {
    let hits = common::hits(&common::src_files(), &FORBIDDEN);
    assert!(hits.is_empty(), "{hits:#?}");
}

#[test]
fn control_guard_can_fail() {
    let sample = |s: &str| vec![("src/x.rs".to_owned(), s.to_owned())];
    for bad in [
        "std::fs::write(p, b)",
        "let f = File::create(p);",
        "std::fs::OpenOptions::new()",
        "let f = File::options().append(true).open(p);",
        "let f = std::fs::File::options();",
        "let o = path.metadata_options().options();",
        "let u = \"https://x\"; let f = File::create(p);",
        "fs::create_dir_all(p)",
        "std::fs::remove_file(p)",
        "rfd::FileDialog::new().save_file()",
    ] {
        assert!(!common::hits(&sample(bad), &FORBIDDEN).is_empty(), "{bad}");
    }
    assert!(common::hits(&sample("rfd::FileDialog::new().pick_folder()"), &FORBIDDEN).is_empty());
    assert!(common::hits(&sample("// std::fs::write(p, b)"), &FORBIDDEN).is_empty());
}
