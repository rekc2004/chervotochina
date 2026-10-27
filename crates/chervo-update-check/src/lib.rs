//! Уведомление «вышла новая версия» (этап 19д). Единственный сетевой код проверки выпусков.
//!
//! Один HTTPS-запрос пары файлов `chervo-release.txt` и `chervo-release.txt.minisig` последнего
//! релиза по вшитому адресу GitHub Releases. Версия сообщается только если подпись манифеста
//! верна вшитым ключом (`chervo-update`), версия строго новее запущенной и в манифесте есть
//! файл для этой ОС. Ничего из ответа (адреса, тексты, имена) наружу не выходит. Состояния,
//! cookies и времени проверки крейт не хранит: это дело GUI.
//!
//! Адрес, хосты, пределы и сроки вшиты в код; конфиг, переменные окружения и прокси не читаются.

use std::fmt;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use chervo_update::{
    KeySet, MAX_MANIFEST_LEN, MAX_MINISIG_LEN, Target, UpdateError, Version, verify_manifest,
};

mod http;
mod net;

#[cfg(any(test, feature = "fuzzing"))]
mod fuzz;
#[cfg(test)]
mod tests;

use http::{Response, parse_location};

/// Страница выпусков, на которую ведёт уведомление. Не берётся из сети.
pub const RELEASES_PAGE: &str = "https://github.com/rekc2004/chervotochina/releases";

pub(crate) const LATEST_BASE: &str =
    "https://github.com/rekc2004/chervotochina/releases/latest/download/";
pub(crate) const MANIFEST_FILE: &str = "chervo-release.txt";
pub(crate) const SIGNATURE_FILE: &str = "chervo-release.txt.minisig";
/// Точное совпадение, строчные, без завершающей точки; порт только 443.
pub(crate) const ALLOWED_HOSTS: [&str; 3] = [
    "github.com",
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
];
pub(crate) const MAX_REDIRECTS: usize = 3;
pub(crate) const MAX_HEADER_BYTES: usize = 16 * 1024;
pub(crate) const MAX_LOCATION_LEN: usize = 4096;
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const TOTAL_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UpdateStatus {
    Newer(Version),
    UpToDate,
}

/// Без данных из сети; `Display` это фиксированные строки.
#[non_exhaustive]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CheckError {
    NoTrustedKeys,
    Network,
    Timeout,
    BadResponse,
    BadSignature,
}

impl fmt::Display for CheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CheckError::NoTrustedKeys => "ключи владельца не вшиты: проверка невозможна",
            CheckError::Network => "нет связи с GitHub",
            CheckError::Timeout => "время ожидания ответа вышло",
            CheckError::BadResponse => "ответ не прошёл проверку",
            CheckError::BadSignature => "подпись ответа неверна",
        })
    }
}

impl std::error::Error for CheckError {}

/// Один обмен с одним хостом. Реализация сети: `net::Net`; в тестах подставные.
pub(crate) trait Transport {
    fn request(
        &self,
        host: &'static str,
        path: &str,
        max_body: usize,
    ) -> Result<Response, CheckError>;
}

/// Скачивание одного из двух файлов последнего релиза целиком (с перенаправлениями).
pub(crate) trait Fetch {
    fn get(&self, file: &str, max_body: usize) -> Result<Vec<u8>, CheckError>;
}

/// Идёт по перенаправлениям: не больше `MAX_REDIRECTS` на всю цепочку, каждый раз проверяя
/// `Location` (`https`, хост из белого списка, порт 443).
pub(crate) struct Redirecting<'a>(pub(crate) &'a dyn Transport);

impl Fetch for Redirecting<'_> {
    fn get(&self, file: &str, max_body: usize) -> Result<Vec<u8>, CheckError> {
        let mut target = parse_location(&format!("{LATEST_BASE}{file}"))?;
        let mut redirects = 0;
        loop {
            match self.0.request(target.host, &target.path, max_body)? {
                Response::Body(body) => return Ok(body),
                Response::Redirect(location) => {
                    redirects += 1;
                    if redirects > MAX_REDIRECTS {
                        return Err(CheckError::BadResponse);
                    }
                    target = parse_location(&location)?;
                }
            }
        }
    }
}

fn map_verify(e: &UpdateError) -> CheckError {
    match e {
        UpdateError::NoTrustedKeys => CheckError::NoTrustedKeys,
        UpdateError::TooLarge
        | UpdateError::MalformedSignature
        | UpdateError::UnsupportedAlgorithm
        | UpdateError::UnknownKey
        | UpdateError::BadSignature
        | UpdateError::BadGlobalSignature => CheckError::BadSignature,
        _ => CheckError::BadResponse,
    }
}

/// Ядро проверки без сети. Ключи не вшиты: `NoTrustedKeys` и ни одного запроса. Порядок:
/// подпись, манифест, проверка подписи, и только потом разбор манифеста (внутри `chervo-update`).
pub(crate) fn check_latest_with(
    keys: Result<KeySet, UpdateError>,
    fetcher: &dyn Fetch,
    running: Version,
    target: Option<Target>,
) -> Result<UpdateStatus, CheckError> {
    let keys = keys.map_err(|_| CheckError::NoTrustedKeys)?;
    let signature = fetcher.get(SIGNATURE_FILE, MAX_MINISIG_LEN)?;
    let manifest = fetcher.get(MANIFEST_FILE, MAX_MANIFEST_LEN)?;
    let verified = verify_manifest(&keys, &manifest, &signature).map_err(|e| map_verify(&e))?;
    let m = verified.manifest();
    // Версию показываем, только если для этой ОС есть собственный файл (строка `any` не в счёт).
    let has_target =
        target.is_some_and(|t| t != Target::Any && m.artifacts.iter().any(|a| a.target == t));
    if m.version > running && has_target {
        Ok(UpdateStatus::Newer(m.version))
    } else {
        Ok(UpdateStatus::UpToDate)
    }
}

/// Работа в отдельном потоке; вызывающий ждёт не дольше `total`. Поток сам уважает тот же срок
/// (`deadline`), кроме DNS: его прервать нельзя, он завершится по таймаутам ОС.
pub(crate) fn run_with_deadline<T, F>(total: Duration, work: F) -> Result<T, CheckError>
where
    T: Send + 'static,
    F: FnOnce(Instant) -> Result<T, CheckError> + Send + 'static,
{
    let deadline = Instant::now() + total;
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .name("chervo-update-check".to_owned())
        .spawn(move || {
            let _ = tx.send(work(deadline));
        })
        .map_err(|_| CheckError::Network)?;
    match rx.recv_timeout(total) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(CheckError::Timeout),
        // поток упал без ответа: не частичный результат, а отказ
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(CheckError::BadResponse),
    }
}

/// Проверка последней версии. Ключи не вшиты: `NoTrustedKeys` без сети. Сбой молчаливый для
/// вызывающего: решает он (CLI печатает фиксированную строку).
pub fn check_latest(running: Version) -> Result<UpdateStatus, CheckError> {
    let keys = KeySet::embedded();
    if keys.is_err() {
        return Err(CheckError::NoTrustedKeys);
    }
    run_with_deadline(TOTAL_DEADLINE, move |deadline| {
        let net = net::Net::production(deadline)?;
        check_latest_with(keys, &Redirecting(&net), running, Target::current())
    })
}

/// Только для фаззинга: разбор ответа и `Location` произвольными байтами.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn fuzz_http_response(data: &[u8]) {
    fuzz::exercise(data);
}
