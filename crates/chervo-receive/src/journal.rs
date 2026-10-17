//! Два маленьких журнала на передачу (спецификация 15, решение 10). Имён файлов на диске нет:
//! только номера и счётчики. Из журнала не доверяется ничего: контрольные суммы, привязка к
//! ключу передачи и к плану, `k <= 999`; имена всегда пересчитываются из предложения.
//!
//! * `receive/<hex32>.dirs`: один раз при `prepare`; `k` для каждого каталога верхнего уровня.
//! * `receive/<hex32>.placed`: дописываемые записи по 8 байт `index u32, k u16, check u16`
//!   перед каждой попыткой имени; последняя годная запись индекса побеждает, первая негодная
//!   запись заканчивает разбор.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use ring::digest::{Context, SHA256};

use chervo_transfer::TransferKey;

/// Наибольший номер имени-кандидата (`имя (k)`).
pub(crate) const MAX_K: u16 = 999;
/// Предел размера `.dirs`.
const MAX_DIRS_LEN: u64 = 64 * 1024;
/// Сколько байт `.placed` читается при открытии (дальше запись игнорируется: это даст лишь
/// дубликат имени, не перезапись).
const MAX_PLACED_READ: u64 = 8 * 1024 * 1024;
const DIRS_MAGIC: &[u8; 8] = b"CHVRCVD1";
const DIGEST_DOMAIN: &[u8] = b"chervo-recv-v1-dirs\0";
const CHECK_SALT: u16 = 0xC4E7;
const REC_LEN: usize = 8;

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut ctx = Context::new(&SHA256);
    for p in parts {
        ctx.update(p);
    }
    let d = ctx.finish();
    let mut out = [0u8; 32];
    for (o, i) in out.iter_mut().zip(d.as_ref()) {
        *o = *i;
    }
    out
}

/// Привязка журнала каталогов к плану: SHA-256 от имён каталогов верхнего уровня в порядке
/// плана (длина и байты каждого имени).
pub(crate) fn plan_digest(top_names: &[&str]) -> [u8; 32] {
    let mut ctx = Context::new(&SHA256);
    ctx.update(DIGEST_DOMAIN);
    for n in top_names {
        let len = u32::try_from(n.len()).unwrap_or(u32::MAX);
        ctx.update(&len.to_be_bytes());
        ctx.update(n.as_bytes());
    }
    let d = ctx.finish();
    let mut out = [0u8; 32];
    for (o, i) in out.iter_mut().zip(d.as_ref()) {
        *o = *i;
    }
    out
}

fn dirs_path(dir: &Path, hex: &str) -> PathBuf {
    dir.join(format!("{hex}.dirs"))
}

fn dirs_tmp_path(dir: &Path, hex: &str) -> PathBuf {
    dir.join(format!("{hex}.dirs.tmp"))
}

fn placed_path(dir: &Path, hex: &str) -> PathBuf {
    dir.join(format!("{hex}.placed"))
}

fn private_open(o: &mut OpenOptions) -> &mut OpenOptions {
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut *o, 0o600);
    o
}

/// Читает не больше `max` байт; длиннее: `None`. Только настоящий файл.
fn read_bounded(p: &Path, max: u64) -> Option<Vec<u8>> {
    if !fs::symlink_metadata(p).ok()?.file_type().is_file() {
        return None;
    }
    let f = File::open(p).ok()?;
    let mut out = Vec::new();
    f.take(max.saturating_add(1)).read_to_end(&mut out).ok()?;
    if u64::try_from(out.len()).ok()? > max {
        return None;
    }
    Some(out)
}

struct Cursor<'a>(&'a [u8]);

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, rest) = self.0.split_at_checked(n)?;
        self.0 = rest;
        Some(head)
    }

    fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
}

/// Журнал каталогов, если он годен для этого ключа, плана и числа каталогов; иначе `None`
/// (вызывающий пересчитывает безопасно: новые каталоги).
pub(crate) fn read_dirs(
    dir: &Path,
    hex: &str,
    key: &TransferKey,
    digest: &[u8; 32],
    count: usize,
) -> Option<Vec<u16>> {
    let raw = read_bounded(&dirs_path(dir, hex), MAX_DIRS_LEN)?;
    let body_len = raw.len().checked_sub(32)?;
    let (body, trailer) = raw.split_at_checked(body_len)?;
    if sha256(&[body]).as_slice() != trailer {
        return None;
    }
    let mut c = Cursor(body);
    if c.take(8)? != DIRS_MAGIC {
        return None;
    }
    if c.array::<16>()? != *key.pair.as_bytes() || c.array::<16>()? != key.id.0 {
        return None;
    }
    if c.array::<32>()? != *digest {
        return None;
    }
    let n = usize::try_from(u32::from_be_bytes(c.array::<4>()?)).ok()?;
    if n != count {
        return None;
    }
    let mut ks = Vec::with_capacity(n);
    for _ in 0..n {
        let k = u16::from_be_bytes(c.array::<2>()?);
        if !(1..=MAX_K).contains(&k) {
            return None;
        }
        ks.push(k);
    }
    if !c.0.is_empty() {
        return None;
    }
    Some(ks)
}

/// Записывает журнал каталогов: временный файл, `sync_all`, `rename`.
pub(crate) fn write_dirs(
    dir: &Path,
    hex: &str,
    key: &TransferKey,
    digest: &[u8; 32],
    ks: &[u16],
) -> io::Result<()> {
    let n = u32::try_from(ks.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let mut body = Vec::with_capacity(8 + 16 + 16 + 32 + 4 + ks.len() * 2 + 32);
    body.extend_from_slice(DIRS_MAGIC);
    body.extend_from_slice(key.pair.as_bytes());
    body.extend_from_slice(&key.id.0);
    body.extend_from_slice(digest);
    body.extend_from_slice(&n.to_be_bytes());
    for k in ks {
        body.extend_from_slice(&k.to_be_bytes());
    }
    let sum = sha256(&[&body]);
    body.extend_from_slice(&sum);
    if u64::try_from(body.len()).map_or(true, |l| l > MAX_DIRS_LEN) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let tmp = dirs_tmp_path(dir, hex);
    match fs::remove_file(&tmp) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    {
        let mut f = private_open(OpenOptions::new().write(true).create_new(true)).open(&tmp)?;
        f.write_all(&body)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, dirs_path(dir, hex))
}

fn check_of(index: u32, k: u16) -> u16 {
    let hi = u16::try_from(index >> 16).unwrap_or(0);
    let lo = u16::try_from(index & 0xFFFF).unwrap_or(0);
    hi ^ lo ^ k ^ CHECK_SALT
}

/// Разбор `.placed`: последняя годная запись каждого индекса и число байт годного префикса.
pub(crate) fn parse_placed(bytes: &[u8]) -> (HashMap<u32, u16>, usize) {
    let mut last = HashMap::new();
    let mut valid = 0usize;
    for rec in bytes.as_chunks::<REC_LEN>().0 {
        let mut c = Cursor(rec.as_slice());
        let (Some(i), Some(k), Some(chk)) = (c.array::<4>(), c.array::<2>(), c.array::<2>()) else {
            break;
        };
        let (index, k, chk) = (
            u32::from_be_bytes(i),
            u16::from_be_bytes(k),
            u16::from_be_bytes(chk),
        );
        if !(1..=MAX_K).contains(&k) || chk != check_of(index, k) {
            break;
        }
        last.insert(index, k);
        valid += REC_LEN;
    }
    (last, valid)
}

/// Дописываемый журнал размещения одной передачи.
pub(crate) struct PlacedLog {
    file: File,
    last: HashMap<u32, u16>,
}

impl PlacedLog {
    pub(crate) fn open(dir: &Path, hex: &str) -> io::Result<Self> {
        let path = placed_path(dir, hex);
        let mut raw = Vec::new();
        let mut on_disk = 0u64;
        match fs::symlink_metadata(&path) {
            Ok(m) if m.file_type().is_file() => {
                on_disk = m.len();
                File::open(&path)?
                    .take(MAX_PLACED_READ)
                    .read_to_end(&mut raw)?;
            }
            Ok(_) => return Err(io::ErrorKind::InvalidData.into()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let (last, valid) = parse_placed(&raw);
        let valid = u64::try_from(valid).map_err(|_| io::ErrorKind::InvalidData)?;
        if valid != on_disk {
            // оборванная или негодная запись в хвосте: обрезаем, чтобы новые записи шли ровно
            // по 8 байт от начала
            let f = private_open(OpenOptions::new().write(true).create(true).truncate(false))
                .open(&path)?;
            f.set_len(valid)?;
        }
        let file = private_open(OpenOptions::new().append(true).create(true)).open(&path)?;
        Ok(Self { file, last })
    }

    /// Последний записанный `k` для индекса.
    pub(crate) fn last(&self, index: u32) -> Option<u16> {
        self.last.get(&index).copied()
    }

    /// Запись перед попыткой имени (без `fsync`).
    pub(crate) fn append(&mut self, index: u32, k: u16) -> io::Result<()> {
        let mut rec = [0u8; REC_LEN];
        let parts = [
            index.to_be_bytes().as_slice(),
            k.to_be_bytes().as_slice(),
            check_of(index, k).to_be_bytes().as_slice(),
        ]
        .concat();
        for (d, s) in rec.iter_mut().zip(&parts) {
            *d = *s;
        }
        self.file.write_all(&rec)?;
        self.last.insert(index, k);
        Ok(())
    }
}

/// Удаляет журналы передачи (ошибки удаления игнорируются: остаток уберёт `sweep`).
pub(crate) fn remove_journals(dir: &Path, hex: &str) {
    for p in [
        dirs_path(dir, hex),
        dirs_tmp_path(dir, hex),
        placed_path(dir, hex),
    ] {
        if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_file()) {
            let _ = fs::remove_file(&p);
        }
    }
}

fn is_hex32(s: &str) -> bool {
    s.len() == 32
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Убирает журналы, у которых нет настоящего каталога сеанса в `partial` (остатки отменённых
/// передач). Чужие имена не трогаются.
pub(crate) fn sweep(dir: &Path, partial: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let Ok(name) = e.file_name().into_string() else {
            continue;
        };
        let stem = [".dirs.tmp", ".dirs", ".placed"]
            .iter()
            .find_map(|s| name.strip_suffix(s));
        let Some(stem) = stem.filter(|s| is_hex32(s)) else {
            continue;
        };
        let session = partial.join(stem);
        let has_session = fs::symlink_metadata(&session)
            .is_ok_and(|m| m.file_type().is_dir() && !m.file_type().is_symlink());
        if !has_session {
            let p = dir.join(&name);
            if fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_file()) {
                let _ = fs::remove_file(&p);
            }
        }
    }
}
