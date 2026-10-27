//! Манифест выпуска `chervo-release.txt`: строгий разбор и каноническая запись.
//!
//! Разбор и запись одним кодом: всё, что разобрано успешно, записывается обратно
//! побайтно тем же образом (свойство проверяется тестами и fuzz).

use std::fmt;
use std::str::FromStr;

use crate::{MAX_ARTIFACTS, MAX_MANIFEST_LEN, UpdateError};

const HEADER: &str = "chervo-release-manifest 1";
const HEADER_PREFIX: &str = "chervo-release-manifest ";
const MAX_NAME_LEN: usize = 128;

/// Версия `MAJOR.MINOR.PATCH`: десятичные `u32` без ведущих нулей.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Десятичное число без знака, без ведущих нулей (кроме самого `0`), без пробелов и плюса.
fn dec_digits(s: &str) -> Option<&str> {
    let ok =
        !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    ok.then_some(s)
}

fn parse_u32(s: &str) -> Option<u32> {
    dec_digits(s)?.parse().ok()
}

fn parse_u64(s: &str) -> Option<u64> {
    dec_digits(s)?.parse().ok()
}

impl FromStr for Version {
    type Err = UpdateError;

    fn from_str(s: &str) -> Result<Self, UpdateError> {
        let bad = || UpdateError::MalformedManifest { line: 0 };
        let mut it = s.split('.');
        let major = parse_u32(it.next().ok_or_else(bad)?).ok_or_else(bad)?;
        let minor = parse_u32(it.next().ok_or_else(bad)?).ok_or_else(bad)?;
        let patch = parse_u32(it.next().ok_or_else(bad)?).ok_or_else(bad)?;
        if it.next().is_some() {
            return Err(bad());
        }
        Ok(Version {
            major,
            minor,
            patch,
        })
    }
}

/// Цель артефакта: закрытый список.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Target {
    LinuxX86_64,
    MacosAarch64,
    MacosX86_64,
    WindowsX86_64,
    Any,
}

impl Target {
    /// Цель запущенной программы; `None`, если сочетание ОС и архитектуры не из списка.
    pub fn current() -> Option<Target> {
        match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => Some(Target::LinuxX86_64),
            ("macos", "aarch64") => Some(Target::MacosAarch64),
            ("macos", "x86_64") => Some(Target::MacosX86_64),
            ("windows", "x86_64") => Some(Target::WindowsX86_64),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Target::LinuxX86_64 => "linux-x86_64",
            Target::MacosAarch64 => "macos-aarch64",
            Target::MacosX86_64 => "macos-x86_64",
            Target::WindowsX86_64 => "windows-x86_64",
            Target::Any => "any",
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Target {
    type Err = UpdateError;

    fn from_str(s: &str) -> Result<Self, UpdateError> {
        match s {
            "linux-x86_64" => Ok(Target::LinuxX86_64),
            "macos-aarch64" => Ok(Target::MacosAarch64),
            "macos-x86_64" => Ok(Target::MacosX86_64),
            "windows-x86_64" => Ok(Target::WindowsX86_64),
            "any" => Ok(Target::Any),
            _ => Err(UpdateError::MalformedManifest { line: 0 }),
        }
    }
}

/// Одна строка `artifact` манифеста.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Artifact {
    pub target: Target,
    pub sha256: [u8; 32],
    pub size: u64,
    pub name: String,
}

/// Разобранный манифест выпуска.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Manifest {
    pub version: Version,
    pub commit: [u8; 20],
    pub artifacts: Vec<Artifact>,
}

const HEX: &[u8; 16] = b"0123456789abcdef";

pub(crate) fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(HEX[usize::from(x >> 4)] as char);
        s.push(HEX[usize::from(x & 15)] as char);
    }
    s
}

/// Строчный hex ровно `2 * N` символов.
fn hex_decode<const N: usize>(s: &str) -> Option<[u8; N]> {
    let b = s.as_bytes();
    if b.len() != N * 2 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; N];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = (nib(b[2 * i])? << 4) | nib(b[2 * i + 1])?;
    }
    Some(out)
}

/// `[A-Za-z0-9._-]`, 1..=128 байт, не начинается с `.`.
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME_LEN
        && !s.starts_with('.')
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-')
}

fn line_err(n: usize) -> UpdateError {
    UpdateError::MalformedManifest {
        line: u32::try_from(n).unwrap_or(u32::MAX),
    }
}

fn parse_artifact_line(l: &str, n: usize) -> Result<Artifact, UpdateError> {
    let rest = l.strip_prefix("artifact ").ok_or_else(|| line_err(n))?;
    let f: Vec<&str> = rest.split(' ').collect();
    let [target, sha, size, name] = f.as_slice() else {
        return Err(line_err(n));
    };
    let target = Target::from_str(target).map_err(|_| line_err(n))?;
    let sha256 = hex_decode::<32>(sha).ok_or_else(|| line_err(n))?;
    let size = parse_u64(size).ok_or_else(|| line_err(n))?;
    if !valid_name(name) {
        return Err(line_err(n));
    }
    Ok(Artifact {
        target,
        sha256,
        size,
        name: (*name).to_owned(),
    })
}

impl Manifest {
    /// Строгий разбор недоверенных байт. Вызывать только после проверки подписи.
    pub fn parse(b: &[u8]) -> Result<Manifest, UpdateError> {
        if b.len() > MAX_MANIFEST_LEN {
            return Err(UpdateError::TooLarge);
        }
        if let Some(pos) = b.iter().position(|c| !c.is_ascii()) {
            let line = b[..pos].iter().filter(|&&c| c == b'\n').count() + 1;
            return Err(line_err(line));
        }
        let newlines = b.iter().filter(|&&c| c == b'\n').count();
        if b.last() != Some(&b'\n') {
            return Err(line_err(newlines + 1));
        }
        let text = std::str::from_utf8(&b[..b.len() - 1]).map_err(|_| line_err(1))?;
        let mut it = text.split('\n');

        let l1 = it.next().unwrap_or("");
        if l1 != HEADER {
            if let Some(v) = l1.strip_prefix(HEADER_PREFIX)
                && dec_digits(v).is_some()
            {
                return Err(UpdateError::UnsupportedManifestVersion);
            }
            return Err(line_err(1));
        }
        let l2 = it.next().ok_or_else(|| line_err(2))?;
        let version = l2
            .strip_prefix("version ")
            .and_then(|v| Version::from_str(v).ok())
            .ok_or_else(|| line_err(2))?;
        let l3 = it.next().ok_or_else(|| line_err(3))?;
        let commit = l3
            .strip_prefix("commit ")
            .and_then(hex_decode::<20>)
            .ok_or_else(|| line_err(3))?;

        let mut artifacts: Vec<Artifact> = Vec::new();
        for (k, l) in it.enumerate() {
            let n = 4 + k;
            if artifacts.len() >= MAX_ARTIFACTS {
                return Err(line_err(n));
            }
            let a = parse_artifact_line(l, n)?;
            if artifacts
                .iter()
                .any(|x| x.name == a.name || x.sha256 == a.sha256)
            {
                return Err(line_err(n));
            }
            artifacts.push(a);
        }
        if artifacts.is_empty() {
            return Err(line_err(4));
        }
        Ok(Manifest {
            version,
            commit,
            artifacts,
        })
    }

    /// Каноническая запись: то, что подписывает владелец и что принимает `parse`.
    pub fn to_canonical_bytes(&self) -> Vec<u8> {
        let mut s = String::new();
        s.push_str(HEADER);
        s.push('\n');
        s.push_str(&format!("version {}\n", self.version));
        s.push_str(&format!("commit {}\n", hex_encode(&self.commit)));
        for a in &self.artifacts {
            s.push_str(&format!(
                "artifact {} {} {} {}\n",
                a.target,
                hex_encode(&a.sha256),
                a.size,
                a.name
            ));
        }
        s.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let b = [0u8, 1, 0x7f, 0x80, 0xff];
        assert_eq!(hex_decode::<5>(&hex_encode(&b)), Some(b));
        assert_eq!(hex_decode::<1>("0A"), None);
        assert_eq!(hex_decode::<1>("0"), None);
    }

    #[test]
    fn version_strict() {
        assert!(Version::from_str("0.0.0").is_ok());
        assert!(Version::from_str("1.20.300").is_ok());
        for bad in [
            "",
            "1",
            "1.2",
            "1.2.3.4",
            "01.2.3",
            "1.02.3",
            "1.2.03",
            "+1.2.3",
            "1.2.-3",
            "1.2.3 ",
            " 1.2.3",
            "1.2.4294967296",
            "a.b.c",
            "1..3",
        ] {
            assert!(Version::from_str(bad).is_err(), "{bad:?}");
        }
        assert!(Version::from_str("4294967295.0.0").is_ok());
    }
}
