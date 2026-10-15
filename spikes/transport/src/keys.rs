//! Тестовые ключи пар (только для спайка). Файлы в `state/<вариант>/`, в git не идут.
use std::path::Path;

use ed25519_dalek::{SigningKey, VerifyingKey};

use crate::auth::{PairId, PairKeys, PairSet};
use crate::util::{BoxErr, err, hex, unhex, unhex32};

pub fn rand32() -> Result<[u8; 32], BoxErr> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| err(format!("getrandom: {e}")))?;
    Ok(b)
}

pub fn rand16() -> Result<[u8; 16], BoxErr> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| err(format!("getrandom: {e}")))?;
    Ok(b)
}

fn write(dir: &Path, name: &str, content: &str) -> Result<(), BoxErr> {
    std::fs::write(dir.join(name), format!("{content}\n"))?;
    Ok(())
}

fn read(dir: &Path, name: &str) -> Result<String, BoxErr> {
    std::fs::read_to_string(dir.join(name)).map_err(|e| err(format!("{name}: {e}")))
}

/// Создаёт ключи пар 1 и 2 (звонящий и вызываемый) и файл игл. Возвращает строки игл.
pub fn keygen_pairs(dir: &Path) -> Result<Vec<String>, BoxErr> {
    std::fs::create_dir_all(dir)?;
    let mut needles = Vec::new();
    for n in 1..=2u8 {
        let id = rand16()?;
        write(dir, &format!("pair{n}.id"), &hex(&id))?;
        needles.push(format!("pair{n}_id hex {}", hex(&id)));
        for role in ["caller", "callee"] {
            let seed = rand32()?;
            let sk = SigningKey::from_bytes(&seed);
            let pk = sk.verifying_key().to_bytes();
            write(dir, &format!("pair{n}.{role}.key"), &hex(&seed))?;
            write(dir, &format!("pair{n}.{role}.pub"), &hex(&pk))?;
            needles.push(format!("pair{n}_{role}_pub hex {}", hex(&pk)));
        }
    }
    Ok(needles)
}

pub fn write_needles(dir: &Path, lines: &[String]) -> Result<(), BoxErr> {
    write(dir, "needles.hex", &lines.join("\n"))
}

fn load_sk(dir: &Path, name: &str) -> Result<SigningKey, BoxErr> {
    Ok(SigningKey::from_bytes(&unhex32(&read(dir, name)?)?))
}

fn load_pk(dir: &Path, name: &str) -> Result<VerifyingKey, BoxErr> {
    let b = unhex32(&read(dir, name)?)?;
    VerifyingKey::from_bytes(&b).map_err(|e| err(format!("{name}: {e}")))
}

pub fn load_pairs(dir: &Path) -> Result<PairSet, BoxErr> {
    let mut v = Vec::new();
    for n in 1..=2u8 {
        let id: PairId = unhex(&read(dir, &format!("pair{n}.id"))?)?
            .try_into()
            .map_err(|_| err("pair id: ожидалось 16 байт"))?;
        v.push(PairKeys {
            id,
            caller_sk: load_sk(dir, &format!("pair{n}.caller.key"))?,
            caller_pk: load_pk(dir, &format!("pair{n}.caller.pub"))?,
            callee_sk: load_sk(dir, &format!("pair{n}.callee.key"))?,
            callee_pk: load_pk(dir, &format!("pair{n}.callee.pub"))?,
        });
    }
    Ok(PairSet(v))
}

/// Ключ endpoint (вариант A): создать, если нет; вернуть seed.
pub fn ensure_seed(dir: &Path, name: &str) -> Result<[u8; 32], BoxErr> {
    let p = dir.join(name);
    if !p.exists() {
        write(dir, name, &hex(&rand32()?))?;
    }
    unhex32(&read(dir, name)?)
}

pub fn load_seed(dir: &Path, name: &str) -> Result<[u8; 32], BoxErr> {
    unhex32(&read(dir, name)?)
}

pub fn write_text(dir: &Path, name: &str, content: &str) -> Result<(), BoxErr> {
    write(dir, name, content)
}

pub fn read_text(dir: &Path, name: &str) -> Result<String, BoxErr> {
    Ok(read(dir, name)?.trim().to_string())
}
