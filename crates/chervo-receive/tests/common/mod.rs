//! Общие помощники тестов R2: временные папки, окружение приёма, подготовка временных файлов
//! в стиле этапа 14, ссылки (симлинки и junction), дерево каталога.
#![allow(dead_code)]

pub mod rows;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use chervo_identity::PairId;
use chervo_receive::{ReceiveConfig, ReceivePlacement, ReceiveRoot};
use chervo_transfer::{
    CompletedFile, OfferedFile, PlaceError, Placed, Placement, TransferId, TransferKey,
    UntrustedName, block_len, file_root, layout, leaf_hash, state_dir_name,
};

static SEQ: AtomicUsize = AtomicUsize::new(0);

/// Временный каталог теста; удаляется целиком (только каталоги самих тестов).
pub struct Tmp(PathBuf);

impl Tmp {
    pub fn new(tag: &str) -> Self {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let p = std::env::temp_dir().join(format!("chervo-rcv-{tag}-{}-{n}", std::process::id()));
        fs::create_dir_all(&p).expect("create tmp");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&p, fs::Permissions::from_mode(0o700)).expect("chmod tmp");
        }
        Self(p)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        // junction и ссылки внутри не должны утянуть удаление наружу: сначала убираем их сами
        remove_links(&self.0);
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn remove_links(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let Ok(m) = fs::symlink_metadata(&p) else {
            continue;
        };
        if m.file_type().is_symlink() {
            if fs::remove_dir(&p).is_err() {
                let _ = fs::remove_file(&p);
            }
        } else if m.file_type().is_dir() {
            remove_links(&p);
        }
    }
}

/// Папка приёма `tmp/recv`, соседняя `tmp/outside` и размещение над ними.
pub struct Env {
    pub tmp: Tmp,
    pub cfg: ReceiveConfig,
    pub root: ReceiveRoot,
    pub place: ReceivePlacement,
    pub outside: PathBuf,
}

impl Env {
    pub fn new(tag: &str) -> Self {
        Self::with(tag, |_| {})
    }

    pub fn with(tag: &str, f: impl FnOnce(&mut ReceiveConfig)) -> Self {
        let tmp = Tmp::new(tag);
        let recv = tmp.path().join("recv");
        let outside = tmp.path().join("outside");
        fs::create_dir(&recv).expect("create recv");
        fs::create_dir(&outside).expect("create outside");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&recv, fs::Permissions::from_mode(0o700)).expect("chmod");
        }
        let mut cfg = ReceiveConfig::new(recv);
        f(&mut cfg);
        let root = ReceiveRoot::open(&cfg).expect("open root");
        let place = ReceivePlacement::new(root.clone(), &cfg);
        Self {
            tmp,
            cfg,
            root,
            place,
            outside,
        }
    }

    /// Новое размещение над той же папкой (как перезапуск процесса).
    pub fn restart(&mut self) {
        self.place = ReceivePlacement::new(self.root.clone(), &self.cfg);
    }

    /// Дерево папки приёма без служебного каталога.
    pub fn tree(&self) -> Vec<String> {
        tree(self.root.root())
    }
}

pub fn key(n: u8) -> TransferKey {
    TransferKey {
        pair: PairId::from_bytes([n; 16]),
        id: TransferId([n.wrapping_add(100); 16]),
    }
}

pub fn offered(files: &[(&str, usize)]) -> Vec<OfferedFile> {
    files
        .iter()
        .map(|(n, size)| OfferedFile {
            name: UntrustedName::new(n).expect("valid name"),
            size: *size as u64,
        })
        .collect()
}

pub fn root_of(data: &[u8]) -> chervo_transfer::FileRoot {
    let size = data.len() as u64;
    let l = layout(size).expect("layout");
    let leaves: Vec<_> = (0..l.block_count)
        .map(|i| {
            let len = block_len(size, l, i).expect("block") as usize;
            let start = i as usize * l.block_size as usize;
            leaf_hash(i, &data[start..start + len])
        })
        .collect();
    file_root(size, l, &leaves).expect("root")
}

/// Файл `<partial>/<hex>/<index>.placing` с данными (как после этапа 14) и `CompletedFile`.
pub fn stage(env: &Env, k: &TransferKey, index: u32, name: &str, data: &[u8]) -> CompletedFile {
    let dir = env.root.partial_dir().join(state_dir_name(&k.pair, &k.id));
    let _ = fs::create_dir(&dir);
    let temp = dir.join(format!("{index}.placing"));
    let _ = fs::remove_file(&temp);
    fs::write(&temp, data).expect("write temp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp, fs::Permissions::from_mode(0o600)).expect("chmod temp");
    }
    CompletedFile::new_for_test(
        *k,
        index,
        UntrustedName::new(name).expect("valid name"),
        data.len() as u64,
        root_of(data),
        temp,
    )
}

/// `prepare` предложения и размещение каждого файла по порядку. Данные файла `i`: `data(i)`.
pub fn place_offer(
    env: &Env,
    k: &TransferKey,
    files: &[(&str, Vec<u8>)],
) -> Vec<Result<Placed, PlaceError>> {
    let off: Vec<(&str, usize)> = files.iter().map(|(n, d)| (*n, d.len())).collect();
    env.place.prepare(k, &offered(&off)).expect("prepare");
    files
        .iter()
        .enumerate()
        .map(|(i, (n, d))| {
            let cf = stage(env, k, i as u32, n, d);
            env.place.place(&cf)
        })
        .collect()
}

/// Рекурсивный список относительных путей (каталоги с `/` на конце), без `.chervo-partial`.
pub fn tree(dir: &Path) -> Vec<String> {
    fn walk(base: &Path, rel: &str, out: &mut Vec<String>) {
        let Ok(rd) = fs::read_dir(base) else { return };
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if rel.is_empty() && name == ".chervo-partial" {
                continue;
            }
            let path = e.path();
            let r = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            let t = e.file_type().expect("file type");
            if t.is_dir() && !t.is_symlink() {
                out.push(format!("{r}/"));
                walk(&path, &r, out);
            } else {
                out.push(r);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, "", &mut out);
    out.sort();
    out
}

/// Каталог-ссылка: симлинк, на Windows при отказе junction (`mklink /J`). `Err`: причина.
pub fn link_dir(target: &Path, link: &Path) -> Result<&'static str, String> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).map_err(|e| e.to_string())?;
        Ok("symlink")
    }
    #[cfg(windows)]
    {
        if std::os::windows::fs::symlink_dir(target, link).is_ok() {
            return Ok("symlink_dir");
        }
        junction(target, link)?;
        Ok("junction")
    }
}

/// Junction через `cmd /c mklink /J` (только Windows).
#[cfg(windows)]
pub fn junction(target: &Path, link: &Path) -> Result<(), String> {
    let out = std::process::Command::new("cmd")
        .arg("/C")
        .arg("mklink")
        .arg("/J")
        .arg(link)
        .arg(target)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stdout).into_owned())
    }
}

/// Файловая ссылка (в том числе висячая). Windows: нужна привилегия, иначе `Err`.
pub fn link_file(target: &Path, link: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).map_err(|e| e.to_string())
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link).map_err(|e| e.to_string())
    }
}

/// Печатает причину пропуска и возвращает `None`, если ссылку создать нельзя.
pub fn link_dir_or_skip(test: &str, target: &Path, link: &Path) -> Option<&'static str> {
    match link_dir(target, link) {
        Ok(kind) => {
            println!("{test}: link kind = {kind}");
            Some(kind)
        }
        Err(why) => {
            println!("{test}: SKIPPED, cannot create a directory link here: {why}");
            None
        }
    }
}

pub fn placed_path(r: &Result<Placed, PlaceError>) -> PathBuf {
    r.as_ref().expect("placed").path.clone()
}
