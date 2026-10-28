//! Чистая машина состояний экранов и диалогов. Не знает ни окна, ни узла: получает намерения
//! пользователя (`Intent`) и итоги работы фонового потока (`Outcome`, события узла), возвращает
//! команды для фонового потока (`Command`). Поэтому проверяется модульными тестами без окна.
//!
//! Правило экрана 1: опасные выборы (`принять старый список`, `начать заново`, `сбросить
//! настройки`, `папка вне профиля`) никогда не происходят сами. Модель выдаёт соответствующую
//! команду только по явному намерению, пришедшему из нужного состояния.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use chervo_core::{InviteOutcome, LanMode, MapStatus, NatView, NodeError, NodeEvent, RootError};

use crate::main_model::{AddFriend, Dialog, MainIntent, OfferUi, SendUi};
use crate::redact::{redacted_debug_enum, redacted_debug_struct};
use crate::rows::{DiagRow, FriendRow, Id, OfferRow, RetiredRow, SettingsRow, TransferRow};
use crate::settings_model::SettingsUi;
use crate::texts;
use crate::update_model::UpdateUi;

redacted_debug_enum!(Command, Intent);
redacted_debug_struct!(FirstRun, Problem);

/// Как открыть узел. `AcceptOlder` и `StartOver` бывают только после явного выбора пользователя.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenMode {
    Normal,
    AcceptOlder,
    StartOver,
}

/// Команды фоновому потоку (единственному владельцу узла). Выполняются по порядку.
#[derive(Clone, PartialEq, Eq)]
pub enum Command {
    /// `port`: порт на этот запуск (после `PortInUse`); при успехе узел запоминает его в настройках.
    Open {
        mode: OpenMode,
        port: Option<u16>,
    },
    FirstRunSetup {
        root: PathBuf,
        confirm_shared: bool,
    },
    ResetSettings,
    RequestUnlock,
    Shutdown,
    // друзья и приглашения (экраны 2-3)
    CreateInvite {
        same_network: bool,
        manual: Option<SocketAddr>,
    },
    AcceptInvite(String),
    ConfirmSas {
        invite: Id,
        yes: bool,
        name: String,
    },
    CancelInvite(Id),
    Rename {
        friend: Id,
        name: String,
    },
    Block(Id),
    Unblock(Id),
    Remove(Id),
    Rekey(Id),
    RekeyAll,
    /// Только после ответа «да» на `TRUST_QUESTION_TEXT` (охрана `gated_node_actions`).
    EnableAutoAccept(Id),
    DisableAutoAccept(Id),
    IssueAddrToken {
        friend: Id,
        same_network: bool,
    },
    ApplyAddrToken(String),
    /// Только из обработчика кнопки «Соединить» (охрана `gated_node_actions`).
    ConnectNow(Id),
    // передачи (экраны 4-6)
    Send {
        friend: Id,
        paths: Vec<PathBuf>,
    },
    Accept(Id),
    AcceptInto {
        transfer: Id,
        root: PathBuf,
    },
    Decline(Id),
    CancelTransfer(Id),
    Retry(Id),
    // настройки, сеть, часы (экран 8)
    SetReceiveRoot {
        root: PathBuf,
        confirm_shared: bool,
    },
    SetMinFree(u8),
    SetPort(u16),
    SetManualForward(Option<u16>),
    /// Только из обработчика кнопки «Найти роутер» (охрана `gated_node_actions`).
    UpnpIdentify,
    /// `router`: `None` значит найденный только что, иначе позиция в списке разрешённых.
    UpnpAllow {
        router: Option<Id>,
        permanent: bool,
    },
    UpnpForget(Id),
    RefreshMapping,
    /// Только из ветки выбора режима поиска в локальной сети (охрана `gated_node_actions`):
    /// «Сообщать о себе» включает рассылку в сеть, поэтому только по явному выбору человека.
    SetLanMode(LanMode),
    /// Перечитать состояние узла без действий (например, при открытии раздела настроек).
    RefreshSnapshot,
    /// Только из обработчика кнопки «Сверить часы» (охрана `gated_node_actions`).
    SyncClock,
    ConfirmClock,
    ResetClock,
    ForgetRetired(Id),
    // обновления (этап 19г-2)
    /// Только из ветки намерения `U::SetConsent` (охрана `gated_node_actions`).
    SetUpdateConsent(bool),
    /// Только из ветки намерения `U::CheckNow` (охрана `update_gates`).
    CheckUpdateNow,
    /// Сверка скачанных файлов: узел не нужен, команда пересылается потоку обновлений.
    VerifyRelease {
        manifest: PathBuf,
        minisig: PathBuf,
        files: Vec<PathBuf>,
        allow_downgrade: bool,
    },
}

/// Снимок состояния узла для окна. Считается в фоновом потоке.
#[derive(Clone, Default)]
pub struct Snapshot {
    pub friends: Vec<FriendRow>,
    pub transfers: Vec<TransferRow>,
    /// Предложения, ожидающие ответа человека.
    pub offers: Vec<OfferRow>,
    /// Передачи, которые не завершены (для вопроса при закрытии).
    pub active_transfers: usize,
    pub settings: Option<SettingsRow>,
    pub nat: Option<NatView>,
    pub mapping: Option<MapStatus>,
    pub retired: Vec<RetiredRow>,
    pub diagnoses: Vec<DiagRow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FriendEventKind {
    KeyProblem,
    ClockSkew,
    /// `lan_hint`: был путь по локальной сети, адрес устарел.
    Unreachable {
        text: &'static str,
        lan_hint: bool,
    },
}

/// Итог кнопки «Сверить часы» (смещение в миллисекундах).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClockResult {
    Applied(i64),
    NeedsConfirm(i64),
}

/// Итоги работы фонового потока.
pub enum Outcome {
    /// `port_saved`: false, если порт на этот запуск не удалось записать в настройки.
    Opened {
        port_saved: bool,
    },
    OpenFailed(NodeError),
    SetupDone,
    SetupFailed(NodeError),
    SettingsReset(Result<(), NodeError>),
    Unlocked(Result<(), NodeError>),
    Snapshot(Box<Snapshot>),
    Event(NodeEvent),
    Stopped,
    // ответы на команды экранов 2-6
    InviteCreated(Result<(Id, String), NodeError>),
    InviteAccepted(Result<Id, NodeError>),
    InviteSas {
        invite: Id,
        digits: String,
        spoken: String,
    },
    InviteFinished(InviteOutcome),
    /// Текст отзыва после «Удалить» (`None`: ключа пары уже не было) или «Пересоздать ключ».
    Revocation {
        friend: String,
        text: Result<Option<String>, NodeError>,
        rekey: bool,
    },
    RekeyAll {
        items: Vec<(String, String)>,
        failed: usize,
    },
    AddrToken(Result<String, NodeError>),
    AddrApplied(Result<(), NodeError>),
    Sent(Result<(), NodeError>),
    SasAnswered(Result<(), NodeError>),
    /// Событие, относящееся к другу (имя берёт фоновый поток).
    FriendEvent {
        name: String,
        kind: FriendEventKind,
    },
    /// Итог смены папки приёма (нужен отдельно: `OutsideProfile` ведёт к вопросу).
    RootSet(Result<(), NodeError>),
    UpnpFound(Result<(), NodeError>),
    ClockSynced(Result<ClockResult, NodeError>),
    OfferIncoming,
    AutoAccepted,
    /// Прочие действия: при ошибке показывается её текст.
    Done(Result<(), NodeError>),
    // обновления (этап 19г-2)
    /// Итог записи ответа на вопрос о проверке новых версий.
    UpdateConsentSet {
        enabled: bool,
        result: Result<(), NodeError>,
    },
    /// Запрос ушёл в поток обновлений.
    UpdateCheckStarted {
        manual: bool,
    },
    /// Кнопка «Проверить сейчас», но проверка не началась (выключена, рано, нет времени).
    UpdateSkipped,
    UpdateChecked {
        manual: bool,
        result: Result<chervo_core::update::UpdateStatus, chervo_core::update::CheckError>,
    },
    ReleaseVerified(Result<chervo_core::update::ReleaseCheck, chervo_core::update::UpdateError>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Friends,
    AddFriend,
    Send,
    Offers,
    Transfers,
    Diagnosis,
    Settings,
    Updates,
}

/// Что сделал пользователь (кнопки и поля).
#[derive(Clone, PartialEq, Eq)]
pub enum Intent {
    FolderEdited(String),
    FolderPicked(PathBuf),
    OutsideChecked(bool),
    SubmitFirstRun,
    AcceptOlder,
    StartOver,
    ResetSettings,
    Unlock,
    RetryOpen,
    PortEdited(String),
    UsePort,
    Quit,
    Go(Page),
    CloseRequested,
    CloseConfirmed,
    CloseCancelled,
    Main(MainIntent),
}

/// Форма первого запуска (и смены папки приёма, если прежняя пропала).
#[derive(Clone, Default, PartialEq, Eq)]
pub struct FirstRun {
    pub folder: String,
    /// Папка вне профиля: показано предупреждение и нужна отметка.
    pub outside_warning: bool,
    pub outside_confirmed: bool,
    pub error: Option<&'static str>,
    pub busy: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProblemKind {
    AlreadyRunning,
    KeyStoreLocked,
    KeysLost,
    RolledBack,
    SettingsCorrupt,
    PortInUse,
    /// Прочее: текст из ядра.
    Other(&'static str),
}

#[derive(Clone, PartialEq, Eq)]
pub struct Problem {
    pub kind: ProblemKind,
    pub busy: bool,
    pub note: Option<&'static str>,
    pub port_text: String,
}

impl Problem {
    fn new(kind: ProblemKind) -> Self {
        Self {
            kind,
            busy: false,
            note: None,
            port_text: String::new(),
        }
    }
}

/// Что показано, пока узел не открыт.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Start {
    Opening,
    FirstRun(FirstRun),
    Problem(Problem),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Close {
    None,
    /// Есть активные передачи: ждём ответа пользователя.
    Asking,
    ShuttingDown,
    /// Можно закрывать окно.
    Done,
}

pub struct Model {
    pub start: Start,
    pub node_open: bool,
    open_pending: bool,
    pub page: Page,
    pub snapshot: Snapshot,
    pub notices: Vec<String>,
    /// Предложить «Сверить часы» рядом с уведомлениями (`ClockSkewSuspected`).
    pub clock_hint: bool,
    pub settings_ui: SettingsUi,
    /// Состояние страницы «Обновления» и карточек (этап 19г-2).
    pub update: UpdateUi,
    pub close: Close,
    pub dialog: Dialog,
    pub add: AddFriend,
    pub send: SendUi,
    pub offer_ui: HashMap<Id, OfferUi>,
    /// Просьба к окну привлечь внимание (мигание в панели задач); забирает `take_attention`.
    pub(crate) attention: bool,
}

impl Model {
    /// Запуск программы: сразу просим открыть узел обычным способом.
    pub fn start() -> (Self, Vec<Command>) {
        let m = Self {
            start: Start::Opening,
            node_open: false,
            open_pending: true,
            page: Page::Friends,
            snapshot: Snapshot::default(),
            notices: Vec::new(),
            clock_hint: false,
            settings_ui: SettingsUi::default(),
            update: UpdateUi::default(),
            close: Close::None,
            dialog: Dialog::None,
            add: AddFriend::default(),
            send: SendUi::default(),
            offer_ui: HashMap::new(),
            attention: false,
        };
        (
            m,
            vec![Command::Open {
                mode: OpenMode::Normal,
                port: None,
            }],
        )
    }

    /// Для `--render-check`: без фонового потока, показывает форму первого запуска.
    pub fn preview() -> Self {
        Self {
            start: Start::FirstRun(FirstRun::default()),
            node_open: false,
            open_pending: false,
            page: Page::Friends,
            snapshot: Snapshot::default(),
            notices: Vec::new(),
            clock_hint: false,
            settings_ui: SettingsUi::default(),
            update: UpdateUi::default(),
            close: Close::None,
            dialog: Dialog::None,
            add: AddFriend::default(),
            send: SendUi::default(),
            offer_ui: HashMap::new(),
            attention: false,
        }
    }

    /// Окну можно закрываться без вопроса.
    pub fn may_close_window(&self) -> bool {
        self.close == Close::Done
    }

    fn open(&mut self, mode: OpenMode, port: Option<u16>) -> Vec<Command> {
        self.open_pending = true;
        self.start = Start::Opening;
        vec![Command::Open { mode, port }]
    }

    fn begin_shutdown(&mut self) -> Vec<Command> {
        if self.node_open || self.open_pending {
            self.close = Close::ShuttingDown;
            vec![Command::Shutdown]
        } else {
            self.close = Close::Done;
            Vec::new()
        }
    }

    fn problem_mut(&mut self) -> Option<&mut Problem> {
        match &mut self.start {
            Start::Problem(p) => Some(p),
            _ => None,
        }
    }

    pub fn update(&mut self, intent: Intent) -> Vec<Command> {
        // закрытие: только его намерения
        match intent {
            Intent::CloseRequested => {
                return match self.close {
                    Close::None => {
                        if self.node_open && self.snapshot.active_transfers > 0 {
                            self.close = Close::Asking;
                            Vec::new()
                        } else {
                            self.begin_shutdown()
                        }
                    }
                    _ => Vec::new(),
                };
            }
            Intent::CloseConfirmed => {
                return if self.close == Close::Asking {
                    self.begin_shutdown()
                } else {
                    Vec::new()
                };
            }
            Intent::CloseCancelled => {
                if self.close == Close::Asking {
                    self.close = Close::None;
                }
                return Vec::new();
            }
            _ => {}
        }
        if self.close != Close::None {
            return Vec::new();
        }
        match intent {
            Intent::Go(page) => {
                if self.node_open {
                    self.page = page;
                    // адреса поиска в локальной сети меняются без событий: при открытии
                    // настроек состояние перечитывается
                    if page == Page::Settings {
                        return vec![Command::RefreshSnapshot];
                    }
                }
                Vec::new()
            }
            Intent::Quit => {
                if matches!(
                    self.start,
                    Start::Problem(Problem {
                        kind: ProblemKind::AlreadyRunning,
                        ..
                    })
                ) {
                    self.begin_shutdown()
                } else {
                    Vec::new()
                }
            }
            Intent::FolderEdited(text) => {
                if let Start::FirstRun(f) = &mut self.start
                    && !f.busy
                {
                    f.folder = text;
                    // отметка относилась к прежней папке: для новой предупреждение проверяется заново
                    f.outside_warning = false;
                    f.outside_confirmed = false;
                    f.error = None;
                }
                Vec::new()
            }
            Intent::FolderPicked(path) => {
                self.update(Intent::FolderEdited(path.to_string_lossy().into_owned()))
            }
            Intent::OutsideChecked(v) => {
                if let Start::FirstRun(f) = &mut self.start
                    && f.outside_warning
                    && !f.busy
                {
                    f.outside_confirmed = v;
                }
                Vec::new()
            }
            Intent::SubmitFirstRun => self.submit_first_run(),
            Intent::AcceptOlder => self.problem_action(ProblemKind::RolledBack, |m| {
                m.open(OpenMode::AcceptOlder, None)
            }),
            Intent::StartOver => {
                self.problem_action(ProblemKind::KeysLost, |m| m.open(OpenMode::StartOver, None))
            }
            Intent::ResetSettings => self.problem_action(ProblemKind::SettingsCorrupt, |_| {
                vec![Command::ResetSettings]
            }),
            Intent::Unlock => {
                if cfg!(target_os = "linux") {
                    self.problem_action(ProblemKind::KeyStoreLocked, |_| {
                        vec![Command::RequestUnlock]
                    })
                } else {
                    Vec::new()
                }
            }
            Intent::RetryOpen => {
                let retryable = matches!(
                    &self.start,
                    Start::Problem(Problem {
                        kind: ProblemKind::KeyStoreLocked | ProblemKind::Other(_),
                        busy: false,
                        ..
                    })
                );
                if retryable {
                    self.open(OpenMode::Normal, None)
                } else {
                    Vec::new()
                }
            }
            Intent::PortEdited(text) => {
                if let Some(p) = self.problem_mut()
                    && p.kind == ProblemKind::PortInUse
                {
                    p.port_text = text;
                    p.note = None;
                }
                Vec::new()
            }
            Intent::UsePort => self.use_port(),
            Intent::Main(m) => {
                if self.node_open {
                    self.update_main(m)
                } else {
                    Vec::new()
                }
            }
            Intent::CloseRequested | Intent::CloseConfirmed | Intent::CloseCancelled => Vec::new(),
        }
    }

    /// Действие экрана ошибки: только из нужного вида ошибки и когда ничего не выполняется.
    fn problem_action(
        &mut self,
        wanted: ProblemKind,
        act: impl FnOnce(&mut Self) -> Vec<Command>,
    ) -> Vec<Command> {
        let Some(p) = self.problem_mut() else {
            return Vec::new();
        };
        if p.kind != wanted || p.busy {
            return Vec::new();
        }
        p.busy = true;
        p.note = None;
        act(self)
    }

    fn use_port(&mut self) -> Vec<Command> {
        let Some(p) = self.problem_mut() else {
            return Vec::new();
        };
        if p.kind != ProblemKind::PortInUse || p.busy {
            return Vec::new();
        }
        match p.port_text.trim().parse::<u16>() {
            Ok(port) if port >= 1024 => self.open(OpenMode::Normal, Some(port)),
            _ => {
                p.note = Some(texts::PORT_BAD);
                Vec::new()
            }
        }
    }

    fn submit_first_run(&mut self) -> Vec<Command> {
        let Start::FirstRun(f) = &mut self.start else {
            return Vec::new();
        };
        if f.busy {
            return Vec::new();
        }
        let folder = f.folder.trim();
        if folder.is_empty() {
            f.error = Some(texts::FOLDER_EMPTY);
            return Vec::new();
        }
        // вне профиля: без явной отметки команды нет
        if f.outside_warning && !f.outside_confirmed {
            return Vec::new();
        }
        f.error = None;
        f.busy = true;
        vec![Command::FirstRunSetup {
            root: PathBuf::from(folder),
            confirm_shared: f.outside_confirmed,
        }]
    }

    fn fail_open(&mut self, e: NodeError) {
        self.start = match e {
            NodeError::FirstRun => Start::FirstRun(FirstRun::default()),
            NodeError::ReceiveRoot(r) => Start::FirstRun(FirstRun {
                outside_warning: r == RootError::OutsideProfile,
                error: Some(e.user_text()),
                ..FirstRun::default()
            }),
            NodeError::AlreadyRunning => Start::Problem(Problem::new(ProblemKind::AlreadyRunning)),
            NodeError::KeyStoreLocked => Start::Problem(Problem::new(ProblemKind::KeyStoreLocked)),
            NodeError::KeysLost => Start::Problem(Problem::new(ProblemKind::KeysLost)),
            NodeError::RolledBack => Start::Problem(Problem::new(ProblemKind::RolledBack)),
            NodeError::SettingsCorrupt => {
                Start::Problem(Problem::new(ProblemKind::SettingsCorrupt))
            }
            NodeError::PortInUse => Start::Problem(Problem::new(ProblemKind::PortInUse)),
            other => Start::Problem(Problem::new(ProblemKind::Other(other.user_text()))),
        };
    }

    pub fn on_outcome(&mut self, outcome: Outcome) -> Vec<Command> {
        match outcome {
            Outcome::Opened { port_saved } => {
                self.open_pending = false;
                self.node_open = true;
                if !port_saved {
                    self.push_notice(texts::PORT_NOT_SAVED);
                }
                Vec::new()
            }
            Outcome::OpenFailed(e) => {
                self.open_pending = false;
                self.fail_open(e);
                Vec::new()
            }
            Outcome::SetupDone => self.open(OpenMode::Normal, None),
            Outcome::SetupFailed(e) => {
                match e {
                    NodeError::ReceiveRoot(RootError::OutsideProfile) => {
                        if let Start::FirstRun(f) = &mut self.start {
                            f.busy = false;
                            f.outside_warning = true;
                            f.error = Some(e.user_text());
                        }
                    }
                    NodeError::ReceiveRoot(_) => {
                        if let Start::FirstRun(f) = &mut self.start {
                            f.busy = false;
                            f.error = Some(e.user_text());
                        }
                    }
                    other => self.fail_open(other),
                }
                Vec::new()
            }
            Outcome::SettingsReset(Ok(())) => self.open(OpenMode::Normal, None),
            Outcome::SettingsReset(Err(e)) => {
                if let Some(p) = self.problem_mut() {
                    p.busy = false;
                    p.note = Some(e.user_text());
                }
                Vec::new()
            }
            Outcome::Unlocked(Ok(())) => self.open(OpenMode::Normal, None),
            Outcome::Unlocked(Err(e)) => {
                if let Some(p) = self.problem_mut() {
                    p.busy = false;
                    p.note = Some(e.user_text());
                }
                Vec::new()
            }
            Outcome::Snapshot(s) => {
                self.snapshot = *s;
                Vec::new()
            }
            Outcome::Event(ev) => {
                match ev {
                    NodeEvent::Warning(w) => self.push_notice(w.user_text()),
                    NodeEvent::Internal => self.push_notice(texts::INTERNAL_NOTICE),
                    NodeEvent::OwnAddressChanged => self.push_notice(texts::OWN_ADDR_CHANGED),
                    NodeEvent::MappingChanged { status } => {
                        self.push_notice(chervo_core::texts::mapping_text(status));
                    }
                    _ => {}
                }
                Vec::new()
            }
            Outcome::Stopped => {
                self.node_open = false;
                self.open_pending = false;
                self.close = Close::Done;
                Vec::new()
            }
            o @ (Outcome::UpdateConsentSet { .. }
            | Outcome::UpdateCheckStarted { .. }
            | Outcome::UpdateSkipped
            | Outcome::UpdateChecked { .. }
            | Outcome::ReleaseVerified(_)) => {
                self.outcome_updates(o);
                Vec::new()
            }
            other => {
                self.outcome_main(other);
                Vec::new()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn failed(e: NodeError) -> Model {
        let (mut m, _) = Model::start();
        assert!(m.on_outcome(Outcome::OpenFailed(e)).is_empty());
        m
    }

    #[test]
    fn rolled_back_needs_explicit_accept() {
        let mut m = failed(NodeError::RolledBack);
        // сама модель ничего не открывает и не принимает
        assert!(!m.node_open);
        assert!(matches!(
            &m.start,
            Start::Problem(Problem {
                kind: ProblemKind::RolledBack,
                ..
            })
        ));
        // чужие кнопки не действуют
        assert!(m.update(Intent::StartOver).is_empty());
        assert!(m.update(Intent::ResetSettings).is_empty());
        assert!(m.update(Intent::RetryOpen).is_empty());
        // только явное «Принять старый список»
        assert_eq!(
            m.update(Intent::AcceptOlder),
            vec![Command::Open {
                mode: OpenMode::AcceptOlder,
                port: None
            }]
        );
        // и сразу второй раз уже нельзя
        assert!(m.update(Intent::AcceptOlder).is_empty());
    }

    #[test]
    fn keys_lost_needs_explicit_start_over() {
        let mut m = failed(NodeError::KeysLost);
        assert!(!m.node_open);
        assert!(m.update(Intent::AcceptOlder).is_empty());
        assert!(m.update(Intent::RetryOpen).is_empty());
        assert_eq!(
            m.update(Intent::StartOver),
            vec![Command::Open {
                mode: OpenMode::StartOver,
                port: None
            }]
        );
        assert!(m.update(Intent::StartOver).is_empty());
    }

    #[test]
    fn outside_profile_needs_checkbox() {
        let (mut m, _) = Model::start();
        m.on_outcome(Outcome::OpenFailed(NodeError::FirstRun));
        m.update(Intent::FolderEdited("D:/recv".to_owned()));
        // первая попытка: без предупреждения отметка не нужна
        let first = m.update(Intent::SubmitFirstRun);
        assert_eq!(
            first,
            vec![Command::FirstRunSetup {
                root: PathBuf::from("D:/recv"),
                confirm_shared: false
            }]
        );
        // ядро ответило: вне профиля
        m.on_outcome(Outcome::SetupFailed(NodeError::ReceiveRoot(
            RootError::OutsideProfile,
        )));
        // без отметки команды нет
        assert!(m.update(Intent::SubmitFirstRun).is_empty());
        // отметка до предупреждения ничего не значит, после него работает
        m.update(Intent::OutsideChecked(true));
        assert_eq!(
            m.update(Intent::SubmitFirstRun),
            vec![Command::FirstRunSetup {
                root: PathBuf::from("D:/recv"),
                confirm_shared: true
            }]
        );
        // сменили папку: отметка и предупреждение сброшены
        m.on_outcome(Outcome::SetupFailed(NodeError::ReceiveRoot(
            RootError::OutsideProfile,
        )));
        m.update(Intent::OutsideChecked(true));
        m.update(Intent::FolderEdited("E:/other".to_owned()));
        let Start::FirstRun(f) = &m.start else {
            panic!("форма первого запуска");
        };
        assert!(!f.outside_warning && !f.outside_confirmed);
    }

    #[test]
    fn close_with_transfers_asks() {
        let (mut m, _) = Model::start();
        m.on_outcome(Outcome::Opened { port_saved: true });
        m.on_outcome(Outcome::Snapshot(Box::new(Snapshot {
            active_transfers: 2,
            ..Snapshot::default()
        })));
        // с активными передачами: вопрос, никакой остановки
        assert!(m.update(Intent::CloseRequested).is_empty());
        assert_eq!(m.close, Close::Asking);
        assert!(!m.may_close_window());
        // отказ возвращает к работе
        m.update(Intent::CloseCancelled);
        assert_eq!(m.close, Close::None);
        // подтверждение: остановка узла
        m.update(Intent::CloseRequested);
        assert_eq!(m.update(Intent::CloseConfirmed), vec![Command::Shutdown]);
        assert_eq!(m.close, Close::ShuttingDown);
        assert!(!m.may_close_window());
        m.on_outcome(Outcome::Stopped);
        assert!(m.may_close_window());
    }

    #[test]
    fn close_without_transfers_shuts_down_without_question() {
        let (mut m, _) = Model::start();
        m.on_outcome(Outcome::Opened { port_saved: true });
        assert_eq!(m.update(Intent::CloseRequested), vec![Command::Shutdown]);
        assert_eq!(m.close, Close::ShuttingDown);
    }

    #[test]
    fn close_without_node_needs_no_shutdown() {
        let mut m = failed(NodeError::KeysLost);
        assert!(m.update(Intent::CloseRequested).is_empty());
        assert!(m.may_close_window());
    }

    #[test]
    fn close_while_opening_still_shuts_down_after_open() {
        let (mut m, _) = Model::start();
        assert_eq!(m.update(Intent::CloseRequested), vec![Command::Shutdown]);
    }

    #[test]
    fn already_running_quits_without_shutdown() {
        let mut m = failed(NodeError::AlreadyRunning);
        assert!(m.update(Intent::Quit).is_empty());
        assert!(m.may_close_window());
    }

    #[test]
    fn port_in_use_asks_for_valid_port() {
        let mut m = failed(NodeError::PortInUse);
        m.update(Intent::PortEdited("80".to_owned()));
        assert!(m.update(Intent::UsePort).is_empty());
        m.update(Intent::PortEdited("50000".to_owned()));
        assert_eq!(
            m.update(Intent::UsePort),
            vec![Command::Open {
                mode: OpenMode::Normal,
                port: Some(50000)
            }]
        );
    }

    #[test]
    fn settings_corrupt_resets_only_on_click_then_reopens() {
        let mut m = failed(NodeError::SettingsCorrupt);
        assert_eq!(
            m.update(Intent::ResetSettings),
            vec![Command::ResetSettings]
        );
        let next = m.on_outcome(Outcome::SettingsReset(Ok(())));
        assert_eq!(
            next,
            vec![Command::Open {
                mode: OpenMode::Normal,
                port: None
            }]
        );
    }

    #[test]
    fn missing_receive_folder_shows_first_run_form() {
        let m = failed(NodeError::ReceiveRoot(RootError::NotDir));
        assert!(matches!(&m.start, Start::FirstRun(f) if f.error.is_some() && !f.outside_warning));
    }

    #[test]
    fn empty_folder_is_rejected_locally() {
        let (mut m, _) = Model::start();
        m.on_outcome(Outcome::OpenFailed(NodeError::FirstRun));
        assert!(m.update(Intent::SubmitFirstRun).is_empty());
        assert!(matches!(&m.start, Start::FirstRun(f) if f.error == Some(texts::FOLDER_EMPTY)));
    }
}
