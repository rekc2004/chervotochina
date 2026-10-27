//! Проверка подписи манифеста и сверка артефакта.

use std::io::Read;
use std::path::Path;

use blake2::{Blake2b512, Digest};
use ed25519_dalek::Signature;
use ring::digest::{Context, SHA256};

use crate::manifest::{Artifact, Manifest, Target, Version};
use crate::{KeyId, KeyRole, KeySet, MAX_MANIFEST_LEN, MAX_MINISIG_LEN, UpdateError, minisig};

/// Блок потокового чтения артефакта.
const READ_BLOCK: usize = 1024 * 1024;

/// Манифест с подтверждённой подписью. Создаётся только `verify_manifest`.
pub struct VerifiedManifest {
    manifest: Manifest,
    signer: (KeyRole, KeyId),
    trusted_comment: String,
}

impl VerifiedManifest {
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    pub fn signer(&self) -> (KeyRole, KeyId) {
        self.signer
    }

    /// Только для показа; решений по нему нет.
    pub fn trusted_comment(&self) -> &str {
        &self.trusted_comment
    }
}

/// Порядок: пределы длины, разбор подписи, поиск ключа по `key_id`, обе подписи, и только
/// потом разбор манифеста.
pub fn verify_manifest(
    keys: &KeySet,
    manifest: &[u8],
    minisig_bytes: &[u8],
) -> Result<VerifiedManifest, UpdateError> {
    if manifest.len() > MAX_MANIFEST_LEN || minisig_bytes.len() > MAX_MINISIG_LEN {
        return Err(UpdateError::TooLarge);
    }
    let sig = minisig::parse_minisig(minisig_bytes)?;
    let (role, key) = keys.find(sig.key_id).ok_or(UpdateError::UnknownKey)?;

    let hash = Blake2b512::digest(manifest);
    key.verify_strict(hash.as_slice(), &Signature::from_bytes(&sig.sig))
        .map_err(|_| UpdateError::BadSignature)?;

    let mut global_msg = Vec::with_capacity(64 + sig.trusted_comment.len());
    global_msg.extend_from_slice(&sig.sig);
    global_msg.extend_from_slice(sig.trusted_comment.as_bytes());
    key.verify_strict(&global_msg, &Signature::from_bytes(&sig.global_sig))
        .map_err(|_| UpdateError::BadGlobalSignature)?;

    let parsed = Manifest::parse(manifest)?;
    Ok(VerifiedManifest {
        manifest: parsed,
        signer: (role, sig.key_id),
        trusted_comment: sig.trusted_comment,
    })
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Freshness {
    Newer,
    Same,
    OlderAllowed,
}

pub struct CheckedArtifact {
    pub artifact: Artifact,
    pub version: Version,
    pub freshness: Freshness,
}

/// Сверяет читаемые байты с подписанным манифестом. Читает потоком блоками по 1 МиБ и
/// останавливается с `NotInManifest`, как только прочитано больше наибольшего `size`.
pub fn check_artifact<R: Read>(
    vm: &VerifiedManifest,
    mut file: R,
    running: Version,
    target: Option<Target>,
    allow_downgrade: bool,
) -> Result<CheckedArtifact, UpdateError> {
    let max_size = vm
        .manifest
        .artifacts
        .iter()
        .map(|a| a.size)
        .max()
        .unwrap_or(0);
    let mut ctx = Context::new(&SHA256);
    let mut buf = vec![0u8; READ_BLOCK];
    let mut total: u64 = 0;
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(UpdateError::Io(e.kind())),
        };
        total = total.saturating_add(n as u64);
        if total > max_size {
            return Err(UpdateError::NotInManifest);
        }
        ctx.update(&buf[..n]);
    }
    let digest = ctx.finish();
    let art = vm
        .manifest
        .artifacts
        .iter()
        .find(|a| a.sha256.as_slice() == digest.as_ref())
        .ok_or(UpdateError::NotInManifest)?;
    if art.target != Target::Any && Some(art.target) != target {
        return Err(UpdateError::WrongTarget {
            expected: target,
            found: art.target,
        });
    }
    if art.size != total {
        return Err(UpdateError::SizeMismatch);
    }
    let offered = vm.manifest.version;
    let freshness = if offered > running {
        Freshness::Newer
    } else if offered == running {
        Freshness::Same
    } else if allow_downgrade {
        Freshness::OlderAllowed
    } else {
        return Err(UpdateError::Downgrade { running, offered });
    };
    Ok(CheckedArtifact {
        artifact: art.clone(),
        version: offered,
        freshness,
    })
}

/// То же для файла на диске. Обычный файл обязателен (не каталог, не устройство).
pub fn check_artifact_path(
    vm: &VerifiedManifest,
    path: &Path,
    running: Version,
    target: Option<Target>,
    allow_downgrade: bool,
) -> Result<CheckedArtifact, UpdateError> {
    let io = |e: std::io::Error| UpdateError::Io(e.kind());
    // До open: открытие FIFO на Unix блокируется до появления писателя.
    if !std::fs::metadata(path).map_err(io)?.is_file() {
        return Err(UpdateError::Io(std::io::ErrorKind::InvalidInput));
    }
    let file = std::fs::File::open(path).map_err(io)?;
    if !file.metadata().map_err(io)?.is_file() {
        return Err(UpdateError::Io(std::io::ErrorKind::InvalidInput));
    }
    check_artifact(vm, file, running, target, allow_downgrade)
}
