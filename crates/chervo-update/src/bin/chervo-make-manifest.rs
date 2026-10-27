//! Инструмент сборки манифеста выпуска (в релиз не входит).
//!
//! `chervo-make-manifest --version V --commit SHA --out FILE (--artifact TARGET PATH)...`
//! Хэширует файлы потоком (SHA-256), пишет каноничный манифест. Имя артефакта это последний
//! компонент `PATH`. Готовый текст перед записью проходит `Manifest::parse` (те же правила, что
//! у программы проверки). Существующий `--out` не перезаписывается.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;
use std::str::FromStr;

use chervo_update::{Artifact, Manifest, Target, Version};
use ring::digest::{Context, SHA256};

const USAGE: &str =
    "usage: chervo-make-manifest --version V --commit SHA40 --out FILE (--artifact TARGET PATH)...";

fn hash_file(path: &Path) -> Result<([u8; 32], u64), String> {
    let mut f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut ctx = Context::new(&SHA256);
    let mut buf = vec![0u8; 1024 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        total += n as u64;
        ctx.update(&buf[..n]);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    Ok((out, total))
}

fn hex20(s: &str) -> Option<[u8; 20]> {
    if s.len() != 40 {
        return None;
    }
    let b = s.as_bytes();
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 20];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = (nib(b[2 * i])? << 4) | nib(b[2 * i + 1])?;
    }
    Some(out)
}

fn run(args: &[String]) -> Result<(), String> {
    let mut version = None;
    let mut commit = None;
    let mut out_path = None;
    let mut specs: Vec<(Target, String)> = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--version" => version = Some(it.next().ok_or(USAGE)?.clone()),
            "--commit" => commit = Some(it.next().ok_or(USAGE)?.clone()),
            "--out" => out_path = Some(it.next().ok_or(USAGE)?.clone()),
            "--artifact" => {
                let t = it.next().ok_or(USAGE)?;
                let p = it.next().ok_or(USAGE)?;
                let target = Target::from_str(t).map_err(|_| format!("unknown target: {t}"))?;
                specs.push((target, p.clone()));
            }
            _ => return Err(USAGE.to_owned()),
        }
    }
    let version = Version::from_str(&version.ok_or(USAGE)?).map_err(|_| "bad --version")?;
    let commit = hex20(&commit.ok_or(USAGE)?).ok_or("bad --commit (40 lowercase hex)")?;
    let out_path = out_path.ok_or(USAGE)?;
    if specs.is_empty() {
        return Err(USAGE.to_owned());
    }
    let mut artifacts = Vec::with_capacity(specs.len());
    for (target, p) in &specs {
        let path = Path::new(p);
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| format!("{p}: no file name"))?
            .to_owned();
        let (sha256, size) = hash_file(path)?;
        artifacts.push(Artifact {
            target: *target,
            sha256,
            size,
            name,
        });
    }
    let manifest = Manifest {
        version,
        commit,
        artifacts,
    };
    let bytes = manifest.to_canonical_bytes();
    match Manifest::parse(&bytes) {
        Ok(back) if back == manifest => {}
        Ok(_) => return Err("internal error: manifest changed after re-parse".to_owned()),
        Err(e) => return Err(format!("manifest is invalid: {e:?}")),
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&out_path)
        .map_err(|e| format!("{out_path}: {e}"))?;
    f.write_all(&bytes)
        .and_then(|()| f.flush())
        .map_err(|e| format!("{out_path}: {e}"))?;
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            // Без eprintln!: охрана chervo-core запрещает вывод макросами вне main.rs CLI.
            let _ = writeln!(std::io::stderr(), "chervo-make-manifest: {msg}");
            ExitCode::from(2)
        }
    }
}
