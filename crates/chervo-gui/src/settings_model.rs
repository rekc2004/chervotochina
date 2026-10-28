//! Состояния экрана «Настройки» (8) и уведомления по событиям друзей (9): папка приёма с
//! вопросом «вне профиля», запас места, порт, ручной проброс, роутеры, часы, ключи. Чистые
//! данные и правила, без окна и узла. Сеть только по кнопке: «Найти роутер» и «Сверить часы»
//! выдают команды только из своих веток (охрана `gated_node_actions`); поправка часов больше
//! 5 минут применяется только после явного подтверждения.

use std::path::PathBuf;

use chervo_core::RootError;

use crate::main_model::cap_paste;
use crate::model::{ClockResult, Command, FriendEventKind, Model, Outcome};
use crate::redact::redacted_debug_enum;
use crate::texts;

redacted_debug_enum!(SettingsIntent);

/// Правка папки приёма.
#[derive(Default)]
pub struct RootEdit {
    /// `None`: показывать текущее значение из настроек.
    pub text: Option<String>,
    pub outside_warning: bool,
    pub outside_confirmed: bool,
    pub error: Option<&'static str>,
    pub busy: bool,
}

/// Числовое поле настроек.
#[derive(Default)]
pub struct NumEdit {
    pub text: Option<String>,
    pub error: Option<&'static str>,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub enum UpnpUi {
    #[default]
    Idle,
    Searching,
    /// Роутер найден: вопрос «Открывать порт на этом роутере?».
    Found,
    Message(&'static str),
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub enum ClockUi {
    #[default]
    Idle,
    Syncing,
    /// Поправка больше 5 минут (мс): ждём подтверждения.
    Proposal(i64),
    Message(&'static str),
}

#[derive(Default)]
pub struct SettingsUi {
    pub root: RootEdit,
    pub min_free: NumEdit,
    pub port: NumEdit,
    pub forward: NumEdit,
    pub upnp: UpnpUi,
    pub clock: ClockUi,
}

#[derive(Clone, PartialEq, Eq)]
pub enum SettingsIntent {
    RootEdited(String),
    RootOutsideChecked(bool),
    RootSubmit,
    MinFreeEdited(String),
    MinFreeSubmit,
    PortEdited(String),
    PortSubmit,
    ForwardEdited(String),
    ForwardSubmit,
    UpnpFind,
    UpnpAllowYes,
    UpnpDecline,
    UpnpPermanentYes(crate::rows::Id),
    UpnpForget(crate::rows::Id),
    MappingRefresh,
    ClockSync,
    ClockConfirm,
    ClockDismiss,
    ClockReset,
    ForgetRetired(crate::rows::Id),
}

impl Model {
    pub fn update_settings(&mut self, intent: SettingsIntent) -> Vec<Command> {
        use SettingsIntent as S;
        match intent {
            S::RootEdited(t) => {
                let r = &mut self.settings_ui.root;
                if !r.busy {
                    r.text = Some(cap_paste(t).0);
                    // отметка относилась к прежней папке
                    r.outside_warning = false;
                    r.outside_confirmed = false;
                    r.error = None;
                }
                Vec::new()
            }
            S::RootOutsideChecked(v) => {
                let r = &mut self.settings_ui.root;
                if r.outside_warning && !r.busy {
                    r.outside_confirmed = v;
                }
                Vec::new()
            }
            S::RootSubmit => {
                let r = &mut self.settings_ui.root;
                let folder = r.text.as_deref().unwrap_or("").trim().to_owned();
                if r.busy {
                    return Vec::new();
                }
                if folder.is_empty() {
                    r.error = Some(texts::FOLDER_EMPTY);
                    return Vec::new();
                }
                // вне профиля: без явной отметки команды нет
                if r.outside_warning && !r.outside_confirmed {
                    return Vec::new();
                }
                r.error = None;
                r.busy = true;
                vec![Command::SetReceiveRoot {
                    root: PathBuf::from(folder),
                    confirm_shared: r.outside_confirmed,
                }]
            }
            S::MinFreeEdited(t) => {
                self.settings_ui.min_free = NumEdit {
                    text: Some(cap_paste(t).0),
                    error: None,
                };
                Vec::new()
            }
            S::MinFreeSubmit => {
                let e = &mut self.settings_ui.min_free;
                match e.text.as_deref().unwrap_or("").trim().parse::<u8>() {
                    Ok(p) if p <= 100 => {
                        *e = NumEdit::default();
                        vec![Command::SetMinFree(p)]
                    }
                    _ => {
                        e.error = Some(texts::MIN_FREE_BAD);
                        Vec::new()
                    }
                }
            }
            S::PortEdited(t) => {
                self.settings_ui.port = NumEdit {
                    text: Some(cap_paste(t).0),
                    error: None,
                };
                Vec::new()
            }
            S::PortSubmit => {
                let e = &mut self.settings_ui.port;
                match e.text.as_deref().unwrap_or("").trim().parse::<u16>() {
                    Ok(p) if p >= 1024 => {
                        *e = NumEdit::default();
                        vec![Command::SetPort(p)]
                    }
                    _ => {
                        e.error = Some(texts::PORT_BAD);
                        Vec::new()
                    }
                }
            }
            S::ForwardEdited(t) => {
                self.settings_ui.forward = NumEdit {
                    text: Some(cap_paste(t).0),
                    error: None,
                };
                Vec::new()
            }
            S::ForwardSubmit => {
                let e = &mut self.settings_ui.forward;
                let text = e.text.as_deref().unwrap_or("").trim().to_owned();
                if text.is_empty() {
                    *e = NumEdit::default();
                    return vec![Command::SetManualForward(None)];
                }
                match text.parse::<u16>() {
                    Ok(p) if p != 0 => {
                        *e = NumEdit::default();
                        vec![Command::SetManualForward(Some(p))]
                    }
                    _ => {
                        e.error = Some(texts::FORWARD_BAD);
                        Vec::new()
                    }
                }
            }
            // «Найти роутер»: единственное место, где появляется `Command::UpnpIdentify`
            S::UpnpFind => {
                if matches!(self.settings_ui.upnp, UpnpUi::Searching) {
                    return Vec::new();
                }
                self.settings_ui.upnp = UpnpUi::Searching;
                vec![Command::UpnpIdentify]
            }
            S::UpnpAllowYes => {
                if self.settings_ui.upnp != UpnpUi::Found {
                    return Vec::new();
                }
                self.settings_ui.upnp = UpnpUi::Message(texts::UPNP_ALLOWED);
                vec![Command::UpnpAllow {
                    router: None,
                    permanent: false,
                }]
            }
            S::UpnpDecline => {
                if self.settings_ui.upnp == UpnpUi::Found {
                    self.settings_ui.upnp = UpnpUi::Idle;
                }
                Vec::new()
            }
            S::UpnpPermanentYes(id) => {
                // вопрос о бессрочной аренде задаётся про тот роутер, который этого потребовал
                let asked = self
                    .snapshot
                    .settings
                    .as_ref()
                    .is_some_and(|s| s.routers.iter().any(|r| r.id == id && r.needs_permanent));
                if asked {
                    vec![Command::UpnpAllow {
                        router: Some(id),
                        permanent: true,
                    }]
                } else {
                    Vec::new()
                }
            }
            S::UpnpForget(id) => {
                let known = self
                    .snapshot
                    .settings
                    .as_ref()
                    .is_some_and(|s| s.routers.iter().any(|r| r.id == id));
                if known {
                    vec![Command::UpnpForget(id)]
                } else {
                    Vec::new()
                }
            }
            S::MappingRefresh => vec![Command::RefreshMapping],
            // «Сверить часы»: единственное место, где появляется `Command::SyncClock`
            S::ClockSync => {
                if matches!(
                    self.settings_ui.clock,
                    ClockUi::Syncing | ClockUi::Proposal(_)
                ) {
                    return Vec::new();
                }
                self.settings_ui.clock = ClockUi::Syncing;
                self.clock_hint = false;
                vec![Command::SyncClock]
            }
            S::ClockConfirm => {
                if matches!(self.settings_ui.clock, ClockUi::Proposal(_)) {
                    self.settings_ui.clock = ClockUi::Message(texts::CLOCK_APPLIED);
                    vec![Command::ConfirmClock]
                } else {
                    Vec::new()
                }
            }
            S::ClockDismiss => {
                if matches!(self.settings_ui.clock, ClockUi::Proposal(_)) {
                    self.settings_ui.clock = ClockUi::Idle;
                }
                Vec::new()
            }
            S::ClockReset => {
                if matches!(self.settings_ui.clock, ClockUi::Syncing) {
                    return Vec::new();
                }
                self.settings_ui.clock = ClockUi::Message(texts::CLOCK_RESET);
                vec![Command::ResetClock]
            }
            S::ForgetRetired(id) => {
                if self.snapshot.retired.iter().any(|r| r.id == id) {
                    vec![Command::ForgetRetired(id)]
                } else {
                    Vec::new()
                }
            }
        }
    }

    /// Ответы на команды настроек и события друзей (уведомления, экран 9).
    pub fn outcome_settings(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::RootSet(Ok(())) => {
                self.settings_ui.root = RootEdit::default();
                self.push_notice(texts::ROOT_CHANGED);
            }
            Outcome::RootSet(Err(e)) => {
                let r = &mut self.settings_ui.root;
                r.busy = false;
                r.error = Some(e.user_text());
                if matches!(
                    e,
                    chervo_core::NodeError::ReceiveRoot(RootError::OutsideProfile)
                ) {
                    r.outside_warning = true;
                }
            }
            Outcome::UpnpFound(Ok(())) => self.settings_ui.upnp = UpnpUi::Found,
            Outcome::UpnpFound(Err(e)) => {
                self.settings_ui.upnp = UpnpUi::Message(e.user_text());
            }
            Outcome::ClockSynced(r) => {
                self.settings_ui.clock = match r {
                    Ok(ClockResult::Applied(_)) => ClockUi::Message(texts::CLOCK_APPLIED),
                    Ok(ClockResult::NeedsConfirm(ms)) => ClockUi::Proposal(ms),
                    Err(e) => ClockUi::Message(e.user_text()),
                };
            }
            Outcome::FriendEvent { name, kind } => match kind {
                FriendEventKind::KeyProblem => {
                    self.push_notice(format!("{name}: {}", chervo_core::texts::KEY_LOST_TEXT));
                }
                FriendEventKind::ClockSkew => {
                    self.clock_hint = true;
                    self.push_notice(format!("{name}: {}", texts::CLOCK_SKEW_HINT));
                }
                FriendEventKind::Unreachable { text, lan_hint } => {
                    self.push_notice(format!("{name}: {text}"));
                    if lan_hint {
                        self.push_notice(format!("{name}: {}", texts::LAN_EXPIRED_HINT));
                    }
                }
            },
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::main_model::MainIntent;
    use crate::model::{Intent, Snapshot};
    use crate::rows::{Id, RouterRow, SettingsRow};
    use chervo_core::{KeyStoreKind, MapStatus, NodeError, NodeEvent, NodeWarning};

    fn model() -> Model {
        let (mut m, _) = Model::start();
        m.on_outcome(Outcome::Opened { port_saved: true });
        m
    }

    fn ask(m: &mut Model, i: SettingsIntent) -> Vec<Command> {
        m.update(Intent::Main(MainIntent::Settings(i)))
    }

    fn settings_row(routers: usize) -> SettingsRow {
        SettingsRow {
            port: 50000,
            receive_root: "D:/recv".to_owned(),
            extra_roots: Vec::new(),
            min_free_percent: 5,
            manual_forward: None,
            routers: (0..routers)
                .map(|i| RouterRow {
                    id: Id(i as u32),
                    permanent_ok: false,
                    needs_permanent: false,
                })
                .collect(),
            clock_offset_ms: 0,
            ntp_servers: vec!["pool.example".to_owned()],
            key_store: KeyStoreKind::CredentialManager,
            restart_needed: false,
            update_consent: chervo_core::update::UpdateConsent::NotAsked,
        }
    }

    #[test]
    fn clock_proposal_over_5_min_needs_confirm() {
        let mut m = model();
        // кнопка «Сверить часы» выдаёт команду один раз
        assert_eq!(
            ask(&mut m, SettingsIntent::ClockSync),
            vec![Command::SyncClock]
        );
        assert!(ask(&mut m, SettingsIntent::ClockSync).is_empty());
        // подтверждать пока нечего
        assert!(ask(&mut m, SettingsIntent::ClockConfirm).is_empty());
        // ответ: поправка больше 5 минут. Сам по себе ничего не применяет.
        let next = m.on_outcome(Outcome::ClockSynced(Ok(ClockResult::NeedsConfirm(600_000))));
        assert!(next.is_empty());
        assert!(matches!(m.settings_ui.clock, ClockUi::Proposal(600_000)));
        // пока предложение не решено, новая сверка не стартует
        assert!(ask(&mut m, SettingsIntent::ClockSync).is_empty());
        // отказ ничего не применяет
        ask(&mut m, SettingsIntent::ClockDismiss);
        assert!(ask(&mut m, SettingsIntent::ClockConfirm).is_empty());
        // снова: только явное подтверждение выдаёт ConfirmClock
        ask(&mut m, SettingsIntent::ClockSync);
        m.on_outcome(Outcome::ClockSynced(Ok(ClockResult::NeedsConfirm(
            -700_000,
        ))));
        assert_eq!(
            ask(&mut m, SettingsIntent::ClockConfirm),
            vec![Command::ConfirmClock]
        );
    }

    #[test]
    fn small_clock_offset_is_applied_without_question() {
        let mut m = model();
        ask(&mut m, SettingsIntent::ClockSync);
        m.on_outcome(Outcome::ClockSynced(Ok(ClockResult::Applied(1000))));
        assert!(matches!(m.settings_ui.clock, ClockUi::Message(_)));
        assert!(ask(&mut m, SettingsIntent::ClockConfirm).is_empty());
    }

    #[test]
    fn upnp_find_is_a_button_and_approval_is_explicit() {
        let mut m = model();
        // без нажатия ничего не уходит
        assert!(ask(&mut m, SettingsIntent::UpnpAllowYes).is_empty());
        assert_eq!(
            ask(&mut m, SettingsIntent::UpnpFind),
            vec![Command::UpnpIdentify]
        );
        assert!(ask(&mut m, SettingsIntent::UpnpFind).is_empty());
        // найден: вопрос; без «да» разрешения нет
        m.on_outcome(Outcome::UpnpFound(Ok(())));
        assert!(m.settings_ui.upnp == UpnpUi::Found);
        ask(&mut m, SettingsIntent::UpnpDecline);
        assert!(ask(&mut m, SettingsIntent::UpnpAllowYes).is_empty());
        ask(&mut m, SettingsIntent::UpnpFind);
        m.on_outcome(Outcome::UpnpFound(Ok(())));
        assert_eq!(
            ask(&mut m, SettingsIntent::UpnpAllowYes),
            vec![Command::UpnpAllow {
                router: None,
                permanent: false
            }]
        );
        // ошибка поиска показывается текстом
        ask(&mut m, SettingsIntent::UpnpFind);
        m.on_outcome(Outcome::UpnpFound(Err(NodeError::Unsupported)));
        assert!(matches!(m.settings_ui.upnp, UpnpUi::Message(_)));
    }

    #[test]
    fn permanent_lease_only_when_router_asked_for_it() {
        let mut m = model();
        let mut s = Snapshot {
            settings: Some(settings_row(2)),
            ..Snapshot::default()
        };
        // общий статус "нужно согласие" без указания роутера согласия не открывает
        s.mapping = Some(MapStatus::NeedPermanentConsent);
        m.on_outcome(Outcome::Snapshot(Box::new(s.clone())));
        assert!(ask(&mut m, SettingsIntent::UpnpPermanentYes(Id(0))).is_empty());
        // согласие только для того роутера, который его потребовал (второй: нет)
        if let Some(set) = s.settings.as_mut() {
            set.routers[0].needs_permanent = true;
        }
        m.on_outcome(Outcome::Snapshot(Box::new(s)));
        assert!(ask(&mut m, SettingsIntent::UpnpPermanentYes(Id(1))).is_empty());
        assert!(ask(&mut m, SettingsIntent::UpnpPermanentYes(Id(7))).is_empty());
        assert_eq!(
            ask(&mut m, SettingsIntent::UpnpPermanentYes(Id(0))),
            vec![Command::UpnpAllow {
                router: Some(Id(0)),
                permanent: true
            }]
        );
        assert_eq!(
            ask(&mut m, SettingsIntent::UpnpForget(Id(0))),
            vec![Command::UpnpForget(Id(0))]
        );
        assert!(ask(&mut m, SettingsIntent::UpnpForget(Id(3))).is_empty());
    }

    #[test]
    fn settings_root_outside_profile_needs_checkbox() {
        let mut m = model();
        ask(&mut m, SettingsIntent::RootEdited("E:/shared".to_owned()));
        let first = ask(&mut m, SettingsIntent::RootSubmit);
        assert_eq!(
            first,
            vec![Command::SetReceiveRoot {
                root: PathBuf::from("E:/shared"),
                confirm_shared: false
            }]
        );
        m.on_outcome(Outcome::RootSet(Err(NodeError::ReceiveRoot(
            RootError::OutsideProfile,
        ))));
        assert!(ask(&mut m, SettingsIntent::RootSubmit).is_empty());
        ask(&mut m, SettingsIntent::RootOutsideChecked(true));
        assert_eq!(
            ask(&mut m, SettingsIntent::RootSubmit),
            vec![Command::SetReceiveRoot {
                root: PathBuf::from("E:/shared"),
                confirm_shared: true
            }]
        );
        m.on_outcome(Outcome::RootSet(Ok(())));
        assert!(!m.notices.is_empty());
    }

    #[test]
    fn numeric_settings_are_validated() {
        let mut m = model();
        ask(&mut m, SettingsIntent::MinFreeEdited("101".to_owned()));
        assert!(ask(&mut m, SettingsIntent::MinFreeSubmit).is_empty());
        ask(&mut m, SettingsIntent::MinFreeEdited("10".to_owned()));
        assert_eq!(
            ask(&mut m, SettingsIntent::MinFreeSubmit),
            vec![Command::SetMinFree(10)]
        );
        ask(&mut m, SettingsIntent::PortEdited("80".to_owned()));
        assert!(ask(&mut m, SettingsIntent::PortSubmit).is_empty());
        ask(&mut m, SettingsIntent::PortEdited("51000".to_owned()));
        assert_eq!(
            ask(&mut m, SettingsIntent::PortSubmit),
            vec![Command::SetPort(51000)]
        );
        ask(&mut m, SettingsIntent::ForwardEdited("0".to_owned()));
        assert!(ask(&mut m, SettingsIntent::ForwardSubmit).is_empty());
        ask(&mut m, SettingsIntent::ForwardEdited("50123".to_owned()));
        assert_eq!(
            ask(&mut m, SettingsIntent::ForwardSubmit),
            vec![Command::SetManualForward(Some(50123))]
        );
        ask(&mut m, SettingsIntent::ForwardEdited(String::new()));
        assert_eq!(
            ask(&mut m, SettingsIntent::ForwardSubmit),
            vec![Command::SetManualForward(None)]
        );
    }

    #[test]
    fn event_notices_follow_the_spec() {
        let mut m = model();
        m.on_outcome(Outcome::Event(NodeEvent::Warning(
            NodeWarning::AnchorNotUpdated,
        )));
        let last = m.notices.last().cloned().unwrap_or_default();
        assert_eq!(last, chervo_core::texts::ANCHOR_NOT_UPDATED_TEXT);
        // не «не удалось», а «сохранено ... перезапустите»
        assert!(last.contains("Сохранено") && last.contains("Перезапустите"));
        assert!(!last.to_lowercase().contains("не удалось"));
        m.on_outcome(Outcome::Event(NodeEvent::Internal));
        assert_eq!(
            m.notices.last().map(String::as_str),
            Some(texts::INTERNAL_NOTICE)
        );
        m.on_outcome(Outcome::FriendEvent {
            name: "Маша".to_owned(),
            kind: FriendEventKind::ClockSkew,
        });
        assert!(m.clock_hint);
        m.on_outcome(Outcome::FriendEvent {
            name: "Маша".to_owned(),
            kind: FriendEventKind::Unreachable {
                text: "текст",
                lan_hint: true,
            },
        });
        assert!(
            m.notices
                .last()
                .is_some_and(|n| n.contains(texts::LAN_EXPIRED_HINT))
        );
        // подсказка про часы не запускает сверку сама
        assert!(m.clock_hint && matches!(m.settings_ui.clock, ClockUi::Idle));
    }
}
