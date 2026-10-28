//! Состояния страницы «Обновления» и карточек (этап 19г-2): согласие на проверку новых
//! версий, найденная версия, ручной итог, форма офлайн-сверки скачанных файлов. Чистые данные и
//! правила, без окна и узла. Правила:
//! * сеть только после записанного согласия (`CheckNow` без `Enabled` команды не даёт; сам
//!   запрос разрешает узел, окно времени не передаёт);
//! * пользователю показываются только фиксированные тексты из `texts.rs` по варианту ошибки,
//!   никогда `Display`/`Debug` ошибок ядра (в `Display` у `Downgrade` есть флаг для CLI);
//! * имена файлов проходят `safe_label`; доверенный комментарий подписи не показывается вовсе.

use std::path::{Path, PathBuf};

use chervo_core::update::{
    self, CheckError, Freshness, KeyRole, ReleaseCheck, UpdateConsent, UpdateError, UpdateStatus,
    Version,
};

use crate::model::{Command, Model, Outcome};
use crate::redact::redacted_debug_enum;
use crate::safe_text::{LABEL_MAX_CHARS, safe_label};
use crate::texts;

redacted_debug_enum!(UpdateIntent);

/// Не больше стольких файлов в одной сверке.
pub const MAX_VERIFY_FILES: usize = 16;

/// Намерения страницы «Обновления» (в коде `U::`).
#[derive(Clone, PartialEq, Eq)]
pub enum UpdateIntent {
    /// Карточка и переключатель: одна ветка.
    SetConsent(bool),
    CheckNow,
    PickManifest(PathBuf),
    PickSignature(PathBuf),
    AddFiles(Vec<PathBuf>),
    ClearFiles,
    AllowDowngrade(bool),
    Verify,
    DismissNewer,
    /// «Где скачать»: показать вшитый адрес страницы выпусков (браузер не запускается).
    LinkOpen,
    LinkClose,
}

/// Ручной итог проверки: ровно одна фиксированная строка.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManualStatus {
    UpToDate,
    NoNetwork,
    BadResponse,
    NoKeys,
    Skipped,
}

impl ManualStatus {
    pub fn text(self) -> String {
        match self {
            Self::UpToDate => texts::upd_up_to_date(chervo_core::VERSION),
            Self::NoNetwork => texts::UPD_NO_NETWORK.to_owned(),
            Self::BadResponse => texts::UPD_BAD_RESPONSE.to_owned(),
            Self::NoKeys => texts::UPD_NO_KEYS.to_owned(),
            Self::Skipped => texts::UPD_SKIPPED.to_owned(),
        }
    }
}

/// Файл формы: путь и безопасное для показа имя.
pub type Picked = (PathBuf, String);

/// Вшитый ключ для показа (сверка с README).
#[derive(Clone, PartialEq, Eq)]
pub struct KeyRow {
    pub role: &'static str,
    pub id: String,
}

/// Итог по одному файлу.
#[derive(Clone, PartialEq, Eq)]
pub struct FileLine {
    /// Имя выбранного файла (после `safe_label`).
    pub label: String,
    /// Имя из подписанного списка (после `safe_label`), если файл найден.
    pub name: Option<String>,
    pub text: &'static str,
    pub ok: bool,
    /// Откат версии, разрешённый пользователем: показать предупреждение.
    pub warn: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// Список или подпись не прошли: файлы не читались.
    Rejected(&'static str),
    Checked {
        version: Version,
        role: &'static str,
        key_id: String,
        files: Vec<FileLine>,
    },
}

pub struct UpdateUi {
    /// Запрос в пути (фон или кнопка).
    pub checking: bool,
    /// Найденная версия: только в памяти.
    pub newer: Option<Version>,
    pub link_open: bool,
    pub manual_status: Option<ManualStatus>,
    pub manifest: Option<Picked>,
    pub minisig: Option<Picked>,
    pub files: Vec<Picked>,
    /// По умолчанию `false` и сбрасывается при каждой сверке.
    pub allow_downgrade: bool,
    pub busy: bool,
    pub result: Option<VerifyResult>,
    /// Вшитые ключи: разбор без ввода-вывода при создании модели.
    pub keys: Vec<KeyRow>,
}

fn role_text(r: KeyRole) -> &'static str {
    match r {
        KeyRole::Primary => texts::UPD_ROLE_PRIMARY,
        KeyRole::Backup => texts::UPD_ROLE_BACKUP,
    }
}

impl Default for UpdateUi {
    fn default() -> Self {
        let keys = update::embedded_keys()
            .unwrap_or_default()
            .into_iter()
            .map(|k| KeyRow {
                role: role_text(k.role),
                id: k.key_id.to_string(),
            })
            .collect();
        Self {
            checking: false,
            newer: None,
            link_open: false,
            manual_status: None,
            manifest: None,
            minisig: None,
            files: Vec::new(),
            allow_downgrade: false,
            busy: false,
            result: None,
            keys,
        }
    }
}

/// Текст ошибки сверки по варианту (SPEC 19г разд. 6). `Display` ядра не используется.
pub fn update_error_text(e: &UpdateError) -> &'static str {
    match e {
        UpdateError::TooLarge => texts::UPD_ERR_TOO_LARGE,
        UpdateError::MalformedSignature | UpdateError::UnsupportedAlgorithm => {
            texts::UPD_ERR_SIG_FORMAT
        }
        UpdateError::NoTrustedKeys => texts::UPD_NO_KEYS,
        UpdateError::UnknownKey => texts::UPD_ERR_UNKNOWN_KEY,
        UpdateError::BadSignature | UpdateError::BadGlobalSignature => texts::UPD_ERR_BAD_SIG,
        UpdateError::UnsupportedManifestVersion | UpdateError::MalformedManifest { .. } => {
            texts::UPD_ERR_MANIFEST_FORMAT
        }
        UpdateError::NotInManifest => texts::UPD_ERR_NOT_IN_MANIFEST,
        UpdateError::WrongTarget { .. } => texts::UPD_ERR_WRONG_TARGET,
        UpdateError::SizeMismatch => texts::UPD_ERR_SIZE,
        UpdateError::Downgrade { .. } => texts::UPD_ERR_DOWNGRADE,
        UpdateError::Io(_) => texts::UPD_ERR_IO,
        _ => texts::UPD_ERR_OTHER,
    }
}

/// Ручной итог по варианту ошибки проверки новой версии.
pub fn check_error_status(e: &CheckError) -> ManualStatus {
    match e {
        CheckError::NoTrustedKeys => ManualStatus::NoKeys,
        CheckError::Network | CheckError::Timeout => ManualStatus::NoNetwork,
        _ => ManualStatus::BadResponse,
    }
}

fn label_of(path: &Path) -> String {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    safe_label(&name, LABEL_MAX_CHARS)
}

impl Model {
    /// Ответ на вопрос о проверке новых версий по снимку узла; пока снимка нет, «не спрашивали».
    pub fn update_consent(&self) -> UpdateConsent {
        self.snapshot
            .settings
            .as_ref()
            .map_or(UpdateConsent::NotAsked, |s| s.update_consent)
    }

    /// Карточка согласия: пока ответа нет.
    pub fn consent_card_visible(&self) -> bool {
        self.node_open && self.update_consent() == UpdateConsent::NotAsked
    }

    fn verify_ready(&self) -> bool {
        let u = &self.update;
        u.manifest.is_some() && u.minisig.is_some() && !u.files.is_empty() && !u.busy
    }

    pub fn update_updates(&mut self, intent: UpdateIntent) -> Vec<Command> {
        use UpdateIntent as U;
        match intent {
            // и карточка, и переключатель: единственное место, где появляется
            // `Command::SetUpdateConsent`
            U::SetConsent(on) => {
                vec![Command::SetUpdateConsent(on)]
            }
            // «Проверить сейчас»: единственное место, где появляется `Command::CheckUpdateNow`
            U::CheckNow => {
                if self.update_consent() != UpdateConsent::Enabled || self.update.checking {
                    return Vec::new();
                }
                self.update.checking = true;
                self.update.manual_status = None;
                vec![Command::CheckUpdateNow]
            }
            U::PickManifest(p) => {
                if !self.update.busy {
                    let label = label_of(&p);
                    self.update.manifest = Some((p, label));
                    self.update.result = None;
                }
                Vec::new()
            }
            U::PickSignature(p) => {
                if !self.update.busy {
                    let label = label_of(&p);
                    self.update.minisig = Some((p, label));
                    self.update.result = None;
                }
                Vec::new()
            }
            U::AddFiles(list) => {
                if !self.update.busy {
                    for p in list {
                        let dup = self.update.files.iter().any(|(q, _)| *q == p);
                        if !dup && self.update.files.len() < MAX_VERIFY_FILES {
                            let label = label_of(&p);
                            self.update.files.push((p, label));
                        }
                    }
                    self.update.result = None;
                }
                Vec::new()
            }
            U::ClearFiles => {
                if !self.update.busy {
                    self.update.files.clear();
                    self.update.result = None;
                }
                Vec::new()
            }
            U::AllowDowngrade(v) => {
                if !self.update.busy {
                    self.update.allow_downgrade = v;
                }
                Vec::new()
            }
            U::Verify => {
                if !self.verify_ready() {
                    return Vec::new();
                }
                let u = &mut self.update;
                let (Some(manifest), Some(minisig)) = (&u.manifest, &u.minisig) else {
                    return Vec::new();
                };
                let cmd = Command::VerifyRelease {
                    manifest: manifest.0.clone(),
                    minisig: minisig.0.clone(),
                    files: u.files.iter().map(|f| f.0.clone()).collect(),
                    allow_downgrade: u.allow_downgrade,
                };
                u.busy = true;
                u.result = None;
                // откат разрешается на одну сверку
                u.allow_downgrade = false;
                vec![cmd]
            }
            U::DismissNewer => {
                self.update.newer = None;
                self.update.link_open = false;
                Vec::new()
            }
            U::LinkOpen => {
                if self.update.newer.is_some() {
                    self.update.link_open = true;
                }
                Vec::new()
            }
            U::LinkClose => {
                self.update.link_open = false;
                Vec::new()
            }
        }
    }

    /// Итоги работы потока обновлений и записи согласия.
    pub fn outcome_updates(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::UpdateConsentSet { result: Err(e), .. } => self.push_notice(e.user_text()),
            Outcome::UpdateCheckStarted { manual } => {
                self.update.checking = true;
                if manual {
                    self.update.manual_status = None;
                }
            }
            Outcome::UpdateSkipped => {
                self.update.checking = false;
                self.update.manual_status = Some(ManualStatus::Skipped);
            }
            Outcome::UpdateChecked { manual, result } => {
                self.update.checking = false;
                match result {
                    Ok(UpdateStatus::Newer(v)) => {
                        // фон: уведомление и карточка; кнопка: карточка
                        if !manual {
                            self.push_notice(texts::upd_newer(&v, chervo_core::VERSION));
                        }
                        self.update.newer = Some(v);
                    }
                    Ok(UpdateStatus::UpToDate) => {
                        if manual {
                            self.update.manual_status = Some(ManualStatus::UpToDate);
                        }
                    }
                    Err(e) => {
                        // фоновые ошибки молчат
                        if manual {
                            self.update.manual_status = Some(check_error_status(&e));
                        }
                    }
                }
            }
            Outcome::ReleaseVerified(r) => {
                self.update.busy = false;
                self.update.result = Some(match r {
                    Err(e) => VerifyResult::Rejected(update_error_text(&e)),
                    Ok(check) => self.verify_lines(check),
                });
            }
            _ => {}
        }
    }

    fn verify_lines(&self, check: ReleaseCheck) -> VerifyResult {
        let labels = self.update.files.iter().map(|f| f.1.clone());
        let files = labels
            .zip(check.files)
            .map(|(label, verdict)| match verdict {
                Ok(v) => FileLine {
                    label,
                    name: Some(safe_label(&v.name, LABEL_MAX_CHARS)),
                    text: match v.freshness {
                        Freshness::Newer => texts::UPD_FILE_NEWER,
                        Freshness::Same => texts::UPD_FILE_SAME,
                        Freshness::OlderAllowed => texts::UPD_FILE_OLDER,
                    },
                    ok: true,
                    warn: v.freshness == Freshness::OlderAllowed,
                },
                Err(e) => FileLine {
                    label,
                    name: None,
                    text: update_error_text(&e),
                    ok: false,
                    warn: false,
                },
            })
            .collect();
        VerifyResult::Checked {
            version: check.version,
            role: role_text(check.signer.role),
            key_id: check.signer.key_id.to_string(),
            files,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::main_model::MainIntent;
    use crate::model::{Intent, Snapshot};
    use crate::rows::SettingsRow;
    use chervo_core::KeyStoreKind;
    use chervo_core::update::{EmbeddedKey, FileVerdict, KeyId, Target};

    fn row(consent: UpdateConsent) -> SettingsRow {
        SettingsRow {
            port: 50000,
            receive_root: "D:/recv".to_owned(),
            extra_roots: Vec::new(),
            min_free_percent: 5,
            manual_forward: None,
            routers: Vec::new(),
            clock_offset_ms: 0,
            ntp_servers: Vec::new(),
            key_store: KeyStoreKind::CredentialManager,
            restart_needed: false,
            update_consent: consent,
        }
    }

    fn model(consent: UpdateConsent) -> Model {
        let (mut m, _) = Model::start();
        m.on_outcome(Outcome::Opened { port_saved: true });
        m.on_outcome(Outcome::Snapshot(Box::new(Snapshot {
            settings: Some(row(consent)),
            ..Snapshot::default()
        })));
        m
    }

    fn ask(m: &mut Model, i: UpdateIntent) -> Vec<Command> {
        m.update(Intent::Main(MainIntent::Update(i)))
    }

    fn ver(major: u32, minor: u32, patch: u32) -> Version {
        Version {
            major,
            minor,
            patch,
        }
    }

    const ALL_CHECK_ERRORS: [CheckError; 5] = [
        CheckError::NoTrustedKeys,
        CheckError::Network,
        CheckError::Timeout,
        CheckError::BadResponse,
        CheckError::BadSignature,
    ];

    #[test]
    fn consent_card_only_when_not_asked() {
        assert!(model(UpdateConsent::NotAsked).consent_card_visible());
        assert!(!model(UpdateConsent::Enabled).consent_card_visible());
        assert!(!model(UpdateConsent::Disabled).consent_card_visible());
        // узел ещё не открыт: карточки нет
        let (m, _) = Model::start();
        assert!(!m.consent_card_visible());
    }

    #[test]
    fn set_consent_builds_one_command() {
        let mut m = model(UpdateConsent::NotAsked);
        assert_eq!(
            ask(&mut m, UpdateIntent::SetConsent(true)),
            vec![Command::SetUpdateConsent(true)]
        );
        assert_eq!(
            ask(&mut m, UpdateIntent::SetConsent(false)),
            vec![Command::SetUpdateConsent(false)]
        );
    }

    #[test]
    fn check_now_needs_consent() {
        for c in [UpdateConsent::NotAsked, UpdateConsent::Disabled] {
            let mut m = model(c);
            assert!(ask(&mut m, UpdateIntent::CheckNow).is_empty());
            assert!(!m.update.checking);
        }
        let mut m = model(UpdateConsent::Enabled);
        assert_eq!(
            ask(&mut m, UpdateIntent::CheckNow),
            vec![Command::CheckUpdateNow]
        );
    }

    #[test]
    fn check_now_not_twice_while_checking() {
        let mut m = model(UpdateConsent::Enabled);
        assert_eq!(ask(&mut m, UpdateIntent::CheckNow).len(), 1);
        assert!(m.update.checking);
        assert!(ask(&mut m, UpdateIntent::CheckNow).is_empty());
        m.on_outcome(Outcome::UpdateChecked {
            manual: true,
            result: Ok(UpdateStatus::UpToDate),
        });
        assert!(!m.update.checking);
        assert_eq!(ask(&mut m, UpdateIntent::CheckNow).len(), 1);
    }

    #[test]
    fn background_failure_is_silent() {
        for e in ALL_CHECK_ERRORS {
            let mut m = model(UpdateConsent::Enabled);
            m.on_outcome(Outcome::UpdateCheckStarted { manual: false });
            m.on_outcome(Outcome::UpdateChecked {
                manual: false,
                result: Err(e),
            });
            assert!(m.notices.is_empty(), "{e:?}");
            assert!(m.update.manual_status.is_none(), "{e:?}");
            assert!(m.update.newer.is_none(), "{e:?}");
            assert!(!m.update.checking);
        }
        let mut m = model(UpdateConsent::Enabled);
        m.on_outcome(Outcome::UpdateChecked {
            manual: false,
            result: Ok(UpdateStatus::UpToDate),
        });
        assert!(m.notices.is_empty() && m.update.manual_status.is_none());
    }

    #[test]
    fn background_newer_shows_version_only() {
        let mut m = model(UpdateConsent::Enabled);
        m.on_outcome(Outcome::UpdateChecked {
            manual: false,
            result: Ok(UpdateStatus::Newer(ver(9, 8, 7))),
        });
        assert_eq!(m.update.newer, Some(ver(9, 8, 7)));
        assert_eq!(
            m.notices,
            vec![texts::upd_newer(&ver(9, 8, 7), chervo_core::VERSION)]
        );
        assert!(m.update.manual_status.is_none());
        // «Где скачать» открывает ссылку только пока версия есть
        ask(&mut m, UpdateIntent::LinkOpen);
        assert!(m.update.link_open);
        ask(&mut m, UpdateIntent::DismissNewer);
        assert!(m.update.newer.is_none() && !m.update.link_open);
        ask(&mut m, UpdateIntent::LinkOpen);
        assert!(!m.update.link_open);
    }

    #[test]
    fn manual_results_fixed_texts() {
        let cases = [
            (Ok(UpdateStatus::UpToDate), ManualStatus::UpToDate),
            (Err(CheckError::Network), ManualStatus::NoNetwork),
            (Err(CheckError::Timeout), ManualStatus::NoNetwork),
            (Err(CheckError::BadResponse), ManualStatus::BadResponse),
            (Err(CheckError::BadSignature), ManualStatus::BadResponse),
            (Err(CheckError::NoTrustedKeys), ManualStatus::NoKeys),
        ];
        for (result, want) in cases {
            let mut m = model(UpdateConsent::Enabled);
            ask(&mut m, UpdateIntent::CheckNow);
            m.on_outcome(Outcome::UpdateChecked {
                manual: true,
                result,
            });
            assert_eq!(m.update.manual_status, Some(want));
            assert!(m.notices.is_empty());
        }
        assert_eq!(
            ManualStatus::NoNetwork.text(),
            "Нет связи с GitHub.".to_owned()
        );
        assert_eq!(
            ManualStatus::BadResponse.text(),
            "Ответ не прошёл проверку.".to_owned()
        );
        // «пропущено» от потока узла
        let mut m = model(UpdateConsent::Enabled);
        ask(&mut m, UpdateIntent::CheckNow);
        m.on_outcome(Outcome::UpdateSkipped);
        assert_eq!(m.update.manual_status, Some(ManualStatus::Skipped));
        assert!(!m.update.checking);
        // ручная новая версия: карточка без уведомления
        m.on_outcome(Outcome::UpdateChecked {
            manual: true,
            result: Ok(UpdateStatus::Newer(ver(2, 0, 0))),
        });
        assert_eq!(m.update.newer, Some(ver(2, 0, 0)));
        assert!(m.notices.is_empty());
        // новый ручной запуск стирает прежний итог
        ask(&mut m, UpdateIntent::CheckNow);
        assert!(m.update.manual_status.is_none());
    }

    fn pick_all(m: &mut Model, files: usize) {
        ask(
            m,
            UpdateIntent::PickManifest(PathBuf::from("D:/d/chervo-release.txt")),
        );
        ask(
            m,
            UpdateIntent::PickSignature(PathBuf::from("D:/d/chervo-release.txt.minisig")),
        );
        ask(
            m,
            UpdateIntent::AddFiles(
                (0..files)
                    .map(|i| PathBuf::from(format!("D:/d/file{i}.bin")))
                    .collect(),
            ),
        );
    }

    #[test]
    fn verify_needs_three_parts() {
        let mut m = model(UpdateConsent::Enabled);
        assert!(ask(&mut m, UpdateIntent::Verify).is_empty());
        ask(
            &mut m,
            UpdateIntent::PickManifest(PathBuf::from("a/chervo-release.txt")),
        );
        assert!(ask(&mut m, UpdateIntent::Verify).is_empty());
        ask(
            &mut m,
            UpdateIntent::PickSignature(PathBuf::from("a/chervo-release.txt.minisig")),
        );
        assert!(ask(&mut m, UpdateIntent::Verify).is_empty());
        ask(
            &mut m,
            UpdateIntent::AddFiles(vec![PathBuf::from("a/x.exe")]),
        );
        let cmd = ask(&mut m, UpdateIntent::Verify);
        assert_eq!(
            cmd,
            vec![Command::VerifyRelease {
                manifest: PathBuf::from("a/chervo-release.txt"),
                minisig: PathBuf::from("a/chervo-release.txt.minisig"),
                files: vec![PathBuf::from("a/x.exe")],
                allow_downgrade: false,
            }]
        );
        // занято: второй раз нельзя, форма заморожена
        assert!(m.update.busy);
        assert!(ask(&mut m, UpdateIntent::Verify).is_empty());
        ask(&mut m, UpdateIntent::ClearFiles);
        assert_eq!(m.update.files.len(), 1);
    }

    #[test]
    fn verify_files_capped_16() {
        let mut m = model(UpdateConsent::Enabled);
        pick_all(&mut m, 40);
        assert_eq!(m.update.files.len(), MAX_VERIFY_FILES);
        // повтор того же пути не добавляется, лишнее тоже
        ask(
            &mut m,
            UpdateIntent::AddFiles(vec![PathBuf::from("D:/d/file0.bin")]),
        );
        ask(
            &mut m,
            UpdateIntent::AddFiles(vec![PathBuf::from("D:/d/other.bin")]),
        );
        assert_eq!(m.update.files.len(), 16);
        ask(&mut m, UpdateIntent::ClearFiles);
        assert!(m.update.files.is_empty());
    }

    #[test]
    fn allow_downgrade_off_by_default_and_reset() {
        let mut m = model(UpdateConsent::Enabled);
        assert!(!m.update.allow_downgrade);
        pick_all(&mut m, 1);
        ask(&mut m, UpdateIntent::AllowDowngrade(true));
        assert!(m.update.allow_downgrade);
        let cmd = ask(&mut m, UpdateIntent::Verify);
        assert!(matches!(
            cmd.as_slice(),
            [Command::VerifyRelease {
                allow_downgrade: true,
                ..
            }]
        ));
        // после отправки флаг снят, а итог его не возвращает
        assert!(!m.update.allow_downgrade);
        m.on_outcome(Outcome::ReleaseVerified(Err(UpdateError::BadSignature)));
        assert!(!m.update.allow_downgrade && !m.update.busy);
        let cmd = ask(&mut m, UpdateIntent::Verify);
        assert!(matches!(
            cmd.as_slice(),
            [Command::VerifyRelease {
                allow_downgrade: false,
                ..
            }]
        ));
    }

    fn checked(freshness: Freshness) -> ReleaseCheck {
        ReleaseCheck {
            version: ver(0, 2, 0),
            signer: EmbeddedKey {
                role: KeyRole::Primary,
                key_id: KeyId([1, 2, 3, 4, 5, 6, 7, 8]),
            },
            files: vec![Ok(FileVerdict {
                name: "chervotochina-0.2.0-linux-x86_64".to_owned(),
                target: Target::LinuxX86_64,
                freshness,
            })],
        }
    }

    #[test]
    fn older_allowed_shows_warning() {
        for (fresh, warn, text) in [
            (Freshness::OlderAllowed, true, texts::UPD_FILE_OLDER),
            (Freshness::Same, false, texts::UPD_FILE_SAME),
            (Freshness::Newer, false, texts::UPD_FILE_NEWER),
        ] {
            let mut m = model(UpdateConsent::Enabled);
            pick_all(&mut m, 1);
            ask(&mut m, UpdateIntent::Verify);
            m.on_outcome(Outcome::ReleaseVerified(Ok(checked(fresh))));
            let Some(VerifyResult::Checked { files, .. }) = &m.update.result else {
                panic!("итог сверки");
            };
            assert_eq!(files.len(), 1);
            assert!(files[0].ok && files[0].warn == warn);
            assert_eq!(files[0].text, text);
        }
    }

    #[test]
    fn error_texts_come_from_the_table_not_from_display() {
        let e = UpdateError::Downgrade {
            running: ver(2, 0, 0),
            offered: ver(1, 0, 0),
        };
        assert!(e.to_string().contains("--allow-downgrade"));
        assert_eq!(update_error_text(&e), texts::UPD_ERR_DOWNGRADE);
        assert!(!update_error_text(&e).contains("--"));
        for e in [
            UpdateError::TooLarge,
            UpdateError::MalformedPubkey,
            UpdateError::KeysetInvalid,
            UpdateError::UnknownKey,
            UpdateError::NotInManifest,
            UpdateError::SizeMismatch,
            UpdateError::Io(std::io::ErrorKind::NotFound),
            UpdateError::WrongTarget {
                expected: None,
                found: Target::Any,
            },
        ] {
            assert!(!update_error_text(&e).contains("--"), "{e:?}");
        }
        assert_eq!(
            update_error_text(&UpdateError::KeysetInvalid),
            texts::UPD_ERR_OTHER
        );
    }

    #[test]
    fn hostile_names_are_cleaned_in_results() {
        let mut m = model(UpdateConsent::Enabled);
        ask(&mut m, UpdateIntent::PickManifest(PathBuf::from("a/m.txt")));
        ask(
            &mut m,
            UpdateIntent::PickSignature(PathBuf::from("a/m.sig")),
        );
        ask(
            &mut m,
            UpdateIntent::AddFiles(vec![PathBuf::from("a/evil\u{202E}gpj\u{7}.exe")]),
        );
        let (_, label) = &m.update.files[0];
        assert!(!label.contains('\u{202E}') && !label.contains('\u{7}'));
        ask(&mut m, UpdateIntent::Verify);
        let mut check = checked(Freshness::Same);
        if let Some(Ok(v)) = check.files.get_mut(0) {
            v.name = "x\u{2066}y".to_owned();
        }
        m.on_outcome(Outcome::ReleaseVerified(Ok(check)));
        let Some(VerifyResult::Checked { files, .. }) = &m.update.result else {
            panic!("итог сверки");
        };
        assert_eq!(files[0].name.as_deref(), Some("x\u{FFFD}y"));
    }
}
