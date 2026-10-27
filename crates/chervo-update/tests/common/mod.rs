//! Общие помощники тестов. Все ключи здесь ТЕСТОВЫЕ: зерно зафиксировано в коде, ключи
//! владельца релизов к ним отношения не имеют и в репозиторий не попадают.
#![allow(dead_code)]

use blake2::{Blake2b512, Digest};
use chervo_update::{Artifact, Manifest, Target, Version};
use ed25519_dalek::{Signer, SigningKey};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Независимый от крейта кодировщик base64 (RFC 4648, с набивкой).
pub fn b64(data: &[u8]) -> String {
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (chunk.get(1).copied().map_or(0, u32::from) << 8)
            | chunk.get(2).copied().map_or(0, u32::from);
        out.push(ALPHABET[((n >> 18) & 63) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Тестовый секретный ключ из фиксированного зерна (НЕ ключ релизов).
pub fn test_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub fn key_id(n: u8) -> [u8; 8] {
    [n, n.wrapping_add(1), 3, 4, 5, 6, 7, 8]
}

/// Файл публичного ключа minisign для тестового ключа.
pub fn pubkey_file(sk: &SigningKey, id: [u8; 8]) -> Vec<u8> {
    pubkey_file_raw(sk.verifying_key().to_bytes(), id)
}

pub fn pubkey_file_raw(pk: [u8; 32], id: [u8; 8]) -> Vec<u8> {
    let mut raw = b"Ed".to_vec();
    raw.extend_from_slice(&id);
    raw.extend_from_slice(&pk);
    format!(
        "untrusted comment: minisign public key (test)\n{}\n",
        b64(&raw)
    )
    .into_bytes()
}

/// Подпись формата minisign над BLAKE2b-512 манифеста; `alg` обычно `ED`.
pub fn sign_alg(
    sk: &SigningKey,
    id: [u8; 8],
    alg: &[u8; 2],
    manifest: &[u8],
    trusted: &str,
) -> Vec<u8> {
    let hash = Blake2b512::digest(manifest);
    let sig = sk.sign(hash.as_slice()).to_bytes();
    let mut raw = alg.to_vec();
    raw.extend_from_slice(&id);
    raw.extend_from_slice(&sig);
    let mut gm = sig.to_vec();
    gm.extend_from_slice(trusted.as_bytes());
    let global = sk.sign(&gm).to_bytes();
    format!(
        "untrusted comment: signature from test key\n{}\ntrusted comment: {}\n{}\n",
        b64(&raw),
        trusted,
        b64(&global)
    )
    .into_bytes()
}

pub fn sign(sk: &SigningKey, id: [u8; 8], manifest: &[u8], trusted: &str) -> Vec<u8> {
    sign_alg(sk, id, b"ED", manifest, trusted)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let d = ring::digest::digest(&ring::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

pub fn artifact(target: Target, name: &str, data: &[u8]) -> Artifact {
    Artifact {
        target,
        sha256: sha256(data),
        size: data.len() as u64,
        name: name.to_owned(),
    }
}

pub fn manifest(version: Version, artifacts: Vec<Artifact>) -> Manifest {
    Manifest {
        version,
        commit: [0xab; 20],
        artifacts,
    }
}

pub fn v(major: u32, minor: u32, patch: u32) -> Version {
    Version {
        major,
        minor,
        patch,
    }
}

/// Образец манифеста из трёх артефактов.
pub fn sample_manifest_bytes() -> Vec<u8> {
    manifest(
        v(1, 2, 3),
        vec![
            artifact(
                Target::LinuxX86_64,
                "chervo-1.2.3-linux-x86_64",
                b"linux-bin",
            ),
            artifact(
                Target::WindowsX86_64,
                "chervo-1.2.3-windows-x86_64.exe",
                b"win-bin",
            ),
            artifact(Target::Any, "chervo-1.2.3-sbom.cdx.json", b"{}"),
        ],
    )
    .to_canonical_bytes()
}
