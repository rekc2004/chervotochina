//! Проверка формата готового манифеста выпуска (запускает `assemble` в 19б):
//! `CHERVO_MANIFEST=<путь> cargo test -p chervo-update --test manifest_file -- --include-ignored`.

use chervo_update::Manifest;

#[test]
#[ignore = "нужен путь в CHERVO_MANIFEST"]
fn manifest_file_is_canonical() {
    let path = std::env::var_os("CHERVO_MANIFEST").expect("задайте CHERVO_MANIFEST=<путь>");
    let bytes = std::fs::read(&path).expect("манифест читается");
    let manifest = Manifest::parse(&bytes).expect("манифест разбирается");
    assert_eq!(
        manifest.to_canonical_bytes(),
        bytes,
        "файл не совпадает с канонической записью"
    );
}
