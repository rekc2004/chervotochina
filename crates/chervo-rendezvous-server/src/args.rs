//! Разбор командной строки. Строгий: неизвестный ключ, повтор одиночного ключа, лишнее слово,
//! число вне границ или неразборный адрес дают отказ (код выхода 2).

use std::ffi::OsString;
use std::net::SocketAddr;
use std::time::Duration;

use chervo_rendezvous_server::ServerConfig;

/// Подсказка по запуску; печатается только при ошибке в аргументах.
pub const USAGE: &str = "usage: chervo-rendezvous --listen IP:PORT [--listen IP6:PORT] \
[--reach-port N] [--allow-private] [--report-secs N]";

/// Срок отчёта по умолчанию и границы, секунды.
const REPORT_DEFAULT: u64 = 600;
const REPORT_MIN: u64 = 60;
const REPORT_MAX: u64 = 86_400;

/// Причина не нужна: на любой отказ печатается `USAGE`.
#[derive(Debug, PartialEq, Eq)]
pub struct ArgsError;

fn number(v: Option<OsString>) -> Result<u64, ArgsError> {
    let s = v.and_then(|s| s.into_string().ok()).ok_or(ArgsError)?;
    // только цифры: без знака, пробелов и шестнадцатеричных форм
    if s.is_empty() || s.len() > 10 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ArgsError);
    }
    s.parse().map_err(|_| ArgsError)
}

pub fn parse<I: IntoIterator<Item = OsString>>(args: I) -> Result<ServerConfig, ArgsError> {
    let mut listen: Vec<SocketAddr> = Vec::new();
    let mut reach_port: Option<u16> = None;
    let mut allow_private = false;
    let mut report_secs: Option<u64> = None;
    let mut it = args.into_iter();
    while let Some(arg) = it.next() {
        match arg.to_str().ok_or(ArgsError)? {
            "--listen" => {
                let s = it
                    .next()
                    .and_then(|s| s.into_string().ok())
                    .ok_or(ArgsError)?;
                listen.push(s.parse().map_err(|_| ArgsError)?);
            }
            "--reach-port" => {
                if reach_port.is_some() {
                    return Err(ArgsError);
                }
                let n = u16::try_from(number(it.next())?).map_err(|_| ArgsError)?;
                if n == 0 {
                    return Err(ArgsError);
                }
                reach_port = Some(n);
            }
            "--allow-private" => {
                if allow_private {
                    return Err(ArgsError);
                }
                allow_private = true;
            }
            "--report-secs" => {
                if report_secs.is_some() {
                    return Err(ArgsError);
                }
                let n = number(it.next())?;
                if !(REPORT_MIN..=REPORT_MAX).contains(&n) {
                    return Err(ArgsError);
                }
                report_secs = Some(n);
            }
            _ => return Err(ArgsError),
        }
    }
    if listen.is_empty() {
        return Err(ArgsError);
    }
    Ok(ServerConfig {
        listen,
        reach_port,
        allow_private,
        report_every: Duration::from_secs(report_secs.unwrap_or(REPORT_DEFAULT)),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

    use super::*;

    fn run(args: &[&str]) -> Result<ServerConfig, ArgsError> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn args_accept_full_form() {
        let c = run(&[
            "--listen",
            "203.0.113.5:45900",
            "--listen",
            "[2001:db8::5]:45900",
            "--reach-port",
            "45901",
            "--allow-private",
            "--report-secs",
            "60",
        ])
        .unwrap();
        assert_eq!(c.listen.len(), 2);
        assert_eq!(c.reach_port, Some(45901));
        assert!(c.allow_private);
        assert_eq!(c.report_every, Duration::from_secs(60));
        let c = run(&["--listen", "203.0.113.5:45900"]).unwrap();
        assert_eq!(c.reach_port, None);
        assert!(!c.allow_private);
        assert_eq!(c.report_every, Duration::from_secs(600));
    }

    #[test]
    fn args_reject_unknown() {
        for bad in [
            &[][..],
            &["--help"][..],
            &["--listen"][..],
            &["--listen", "203.0.113.5"][..],
            &["--listen", "example.org:45900"][..],
            &["--listen", "203.0.113.5:45900", "extra"][..],
            &["--listen", "203.0.113.5:45900", "--bogus"][..],
            &["--listen", "203.0.113.5:45900", "--reach-port"][..],
            &["--listen", "203.0.113.5:45900", "--reach-port", "0"][..],
            &["--listen", "203.0.113.5:45900", "--reach-port", "65536"][..],
            &["--listen", "203.0.113.5:45900", "--reach-port", "-1"][..],
            &["--listen", "203.0.113.5:45900", "--reach-port", "+5"][..],
            &[
                "--listen",
                "203.0.113.5:45900",
                "--reach-port",
                "1",
                "--reach-port",
                "2",
            ][..],
            &["--listen", "203.0.113.5:45900", "--report-secs", "59"][..],
            &["--listen", "203.0.113.5:45900", "--report-secs", "86401"][..],
            &["--listen", "203.0.113.5:45900", "--report-secs", "abc"][..],
            &[
                "--listen",
                "203.0.113.5:45900",
                "--allow-private",
                "--allow-private",
            ][..],
        ] {
            assert_eq!(run(bad).err(), Some(ArgsError), "{bad:?}");
        }
    }
}
