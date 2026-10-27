//! Единственное место, где строятся пути внутри `partial_dir`. Пути состоят только из
//! `partial_dir`, имени каталога из 32 hex-цифр и фиксированных имён (`state`, `state.tmp`,
//! `<i>.part`, `<i>.placing`, `<i>.hashes`, `<i>.hashes.tmp`). Недоверенное имя сюда не попадает.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::limits::{MAX_NAMES_LEN, MAX_STATE_LEN};

const STATE: &str = "state";
const STATE_TMP: &str = "state.tmp";
const NAMES: &str = "names";
const NAMES_TMP: &str = "names.tmp";

pub(crate) fn session_dir(base: &Path, name: &str) -> PathBuf {
    base.join(name)
}

pub(crate) fn part_path(sdir: &Path, index: u32) -> PathBuf {
    sdir.join(format!("{index}.part"))
}

/// Готовый файл перед размещением: `<i>.part` переименовывается сюда до `Placement`, и этот
/// путь только читается. Размещённый жёсткой ссылкой файл так никогда не оказывается вторым
/// именем файла, в который пишет получатель.
pub(crate) fn placing_path(sdir: &Path, index: u32) -> PathBuf {
    sdir.join(format!("{index}.placing"))
}

pub(crate) fn hashes_path(sdir: &Path, index: u32) -> PathBuf {
    sdir.join(format!("{index}.hashes"))
}

fn hashes_tmp_path(sdir: &Path, index: u32) -> PathBuf {
    sdir.join(format!("{index}.hashes.tmp"))
}

/// 32 строчные hex-цифры.
pub(crate) fn is_session_name(name: &str) -> bool {
    name.len() == 32
        && name
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Имя файла по нашим шаблонам; только такие файлы мы удаляем.
pub(crate) fn is_ours_file(name: &str) -> bool {
    if name == STATE || name == STATE_TMP || name == NAMES || name == NAMES_TMP {
        return true;
    }
    let digits = |s: &str| !s.is_empty() && s.len() <= 10 && s.bytes().all(|b| b.is_ascii_digit());
    for suffix in [".part", ".placing", ".hashes.tmp", ".hashes"] {
        if let Some(stem) = name.strip_suffix(suffix) {
            return digits(stem);
        }
    }
    false
}

/// Настоящий каталог (не ссылка).
pub(crate) fn is_real_dir(p: &Path) -> bool {
    fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_dir())
}

/// Создаёт `partial_dir/<name>`; существующий настоящий каталог допустим.
pub(crate) fn create_session_dir(base: &Path, name: &str) -> io::Result<PathBuf> {
    let p = session_dir(base, name);
    match fs::create_dir(&p) {
        Ok(()) => Ok(p),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists && is_real_dir(&p) => Ok(p),
        Err(e) => Err(e),
    }
}

/// Имена настоящих подкаталогов `partial_dir` с именем из 32 hex-цифр.
pub(crate) fn list_session_dirs(base: &Path) -> io::Result<Vec<String>> {
    let mut out = Vec::new();
    for e in fs::read_dir(base)? {
        let Ok(e) = e else { continue };
        let Ok(name) = e.file_name().into_string() else {
            continue;
        };
        if is_session_name(&name) && is_real_dir(&session_dir(base, &name)) {
            out.push(name);
        }
    }
    out.sort();
    Ok(out)
}

fn retryable(e: &io::Error) -> bool {
    e.kind() == io::ErrorKind::PermissionDenied
}

/// Windows: антивирус и индексатор на мгновение держат файл; 5 попыток по 100 мс.
pub(crate) fn rename_retry(from: &Path, to: &Path) -> io::Result<()> {
    let mut tries = 0;
    loop {
        match fs::rename(from, to) {
            Err(e) if cfg!(windows) && retryable(&e) && tries < 5 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(100));
            }
            other => return other,
        }
    }
}

pub(crate) fn remove_file_retry(p: &Path) -> io::Result<()> {
    let mut tries = 0;
    loop {
        match fs::remove_file(p) {
            Err(e) if cfg!(windows) && retryable(&e) && tries < 5 => {
                tries += 1;
                std::thread::sleep(Duration::from_millis(100));
            }
            other => return other,
        }
    }
}

fn write_atomic(tmp: &Path, fin: &Path, bytes: &[u8]) -> io::Result<()> {
    {
        let mut f = File::create(tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    rename_retry(tmp, fin)
}

pub(crate) fn write_state(sdir: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic(&sdir.join(STATE_TMP), &sdir.join(STATE), bytes)
}

/// Файл имён предложения: пишется один раз при принятии.
pub(crate) fn write_names(sdir: &Path, bytes: &[u8]) -> io::Result<()> {
    write_atomic(&sdir.join(NAMES_TMP), &sdir.join(NAMES), bytes)
}

pub(crate) fn write_hashes(sdir: &Path, index: u32, bytes: &[u8]) -> io::Result<()> {
    write_atomic(
        &hashes_tmp_path(sdir, index),
        &hashes_path(sdir, index),
        bytes,
    )
}

/// Читает файл не длиннее `max` байт; длиннее: ошибка до чтения.
fn read_bounded(p: &Path, max: u64) -> io::Result<Vec<u8>> {
    let f = File::open(p)?;
    let len = f.metadata()?.len();
    if len > max {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut out = Vec::new();
    f.take(max.saturating_add(1)).read_to_end(&mut out)?;
    if u64::try_from(out.len()).map_or(true, |n| n > max) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(out)
}

pub(crate) fn read_state(sdir: &Path) -> io::Result<Vec<u8>> {
    read_bounded(&sdir.join(STATE), MAX_STATE_LEN)
}

pub(crate) fn read_names(sdir: &Path) -> io::Result<Vec<u8>> {
    read_bounded(&sdir.join(NAMES), MAX_NAMES_LEN)
}

/// `<i>.hashes` не длиннее `max` (ожидаемая длина считается вызывающим).
pub(crate) fn read_hashes(sdir: &Path, index: u32, max: u64) -> io::Result<Vec<u8>> {
    read_bounded(&hashes_path(sdir, index), max)
}

/// Новый `<i>.part`: `create_new`, существующий файл (в том числе жёсткая ссылка на уже
/// размещённый) никогда не открывается для записи.
pub(crate) fn create_part_new(sdir: &Path, index: u32) -> io::Result<File> {
    let mut o = OpenOptions::new();
    o.write(true).create_new(true);
    // Unix: только владелец; бита исполнения у принятого файла не бывает
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
    o.open(part_path(sdir, index))
}

/// Существующий `<i>.part` для записи без создания и без усечения.
pub(crate) fn open_part_existing(sdir: &Path, index: u32) -> io::Result<File> {
    OpenOptions::new().write(true).open(part_path(sdir, index))
}

/// `<i>.part` существует: есть (его проверили по хэшам) или создан новый пустой.
pub(crate) fn ensure_part(sdir: &Path, index: u32) -> io::Result<()> {
    match open_part_existing(sdir, index) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => create_part_new(sdir, index).map(|_| ()),
        Err(e) => Err(e),
    }
}

/// Удаляет `<i>.part`, ошибка удаления это ошибка (кроме «нет такого файла»): продолжать
/// запись рядом с файлом, который не удалось убрать, нельзя (он мог остаться жёсткой ссылкой
/// на уже размещённый файл).
pub(crate) fn remove_part_strict(sdir: &Path, index: u32) -> io::Result<()> {
    match remove_file_retry(&part_path(sdir, index)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Путь временного файла для `Placement`.
pub(crate) fn temp_for_placement(sdir: &Path, index: u32) -> PathBuf {
    placing_path(sdir, index)
}

/// `<i>.placing` есть и это настоящий файл (ссылка не считается).
pub(crate) fn placing_present(sdir: &Path, index: u32) -> bool {
    fs::symlink_metadata(placing_path(sdir, index)).is_ok_and(|m| m.file_type().is_file())
}

/// Атомарно `<i>.part` -> `<i>.placing` в том же каталоге. Дальше `.part` не существует, а в
/// `.placing` никто не пишет.
pub(crate) fn part_to_placing(sdir: &Path, index: u32) -> io::Result<()> {
    rename_retry(&part_path(sdir, index), &placing_path(sdir, index))
}

/// Удаляет `<i>.placing` (только имя; содержимое не открывается), «нет такого файла» не ошибка.
pub(crate) fn remove_placing_strict(sdir: &Path, index: u32) -> io::Result<()> {
    match remove_file_retry(&placing_path(sdir, index)) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

pub(crate) fn remove_part_and_hashes(sdir: &Path, index: u32) {
    for p in [
        part_path(sdir, index),
        placing_path(sdir, index),
        hashes_path(sdir, index),
        hashes_tmp_path(sdir, index),
    ] {
        let _ = remove_file_retry(&p);
    }
}

pub(crate) fn remove_hashes(sdir: &Path, index: u32) {
    for p in [hashes_path(sdir, index), hashes_tmp_path(sdir, index)] {
        let _ = remove_file_retry(&p);
    }
}

/// Удаляет только файлы по нашим шаблонам (и только настоящие файлы), затем пустой каталог.
/// Чужие файлы остаются, а с ними и каталог. Ссылка вместо каталога не трогается.
pub(crate) fn remove_session(sdir: &Path) {
    if !is_real_dir(sdir) {
        return;
    }
    if let Ok(rd) = fs::read_dir(sdir) {
        for e in rd.flatten() {
            let Ok(name) = e.file_name().into_string() else {
                continue;
            };
            if !is_ours_file(&name) {
                continue;
            }
            let p = sdir.join(&name);
            if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_file()) {
                let _ = remove_file_retry(&p);
            }
        }
    }
    let _ = fs::remove_dir(sdir);
}
