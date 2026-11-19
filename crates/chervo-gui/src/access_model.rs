//! Этап 13д: адрес в интернете для приглашения, «Получить свой IP» и помощник «Разрешить входящие
//! подключения». Чистые данные и правила, без окна и узла. Сеть только по кнопкам:
//! «Создать приглашение», «Получить свой IP», «Попробовать автоматически» (поиск роутера, по
//! правилам 13а) и «Проверить»; при пустом адресе сервера к серверу не идёт ни один пакет. Команды,
//! которые трогают сеть или запоминают проброс, выдаются только из своих веток (охрана
//! `gated_node_actions`): `UpnpIdentify` из `A::AccessAuto`, `ReachCheck` из `A::AccessCheck`,
//! `ConfirmForward` из `A::AccessDone`.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use chervo_core::{ExternalPlan, ForwardHelp, MapStatus, ReachResult, SkipReason};

use crate::model::{Command, Model, Outcome};
use crate::redact::redacted_debug_enum;
use crate::texts;

redacted_debug_enum!(AccessIntent, GetIpUi, GetIpResult);

/// Сколько после «Разрешить» ждём, пока роутер откроет доступ (Р10.1).
pub const AUTO_WAIT: Duration = Duration::from_secs(10);

/// Что делать с адресом от сервера при создании приглашения.
#[derive(Clone, PartialEq, Eq)]
pub enum ExternalMode {
    /// Узнать адрес у сервера (если он указан) и вписать по правилам плана. Только из ветки
    /// кнопки «Создать приглашение».
    Probe,
    /// Вписать эти адреса: человек ответил «VPN выключен, вписать адрес».
    Use(Vec<SocketAddr>),
    /// Создать без адреса от сервера: человек ответил «Создать приглашение без этого адреса».
    Without,
}

/// Что стало с адресом от сервера у созданного приглашения (для подписей на экране ожидания).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InviteExt {
    /// Без адреса от сервера по выбору человека.
    Plain,
    /// Сервер не указан.
    NotSet,
    /// Адрес вписан; `vpn_on`: VPN включён, но обойдён (другу по этому адресу не дойти).
    Added {
        addr: SocketAddr,
        vpn_on: bool,
    },
    Skipped(SkipReason),
    /// Сервер указан, но проба не удалась: текст ошибки.
    Failed(&'static str),
}

/// Пометка к найденному адресу.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum GetIpMark {
    Clean,
    MaybeVpn,
    VpnOn,
}

/// Итог кнопки «Получить свой IP».
#[derive(Clone, PartialEq, Eq)]
pub enum GetIpResult {
    Address { addr: SocketAddr, mark: GetIpMark },
    NoAnswer,
    ServerLocal,
    Symmetric,
    Failed(&'static str),
}

impl GetIpResult {
    /// Из плана ядра (тот же вывод, что и для приглашения).
    pub fn from_plan(plan: &ExternalPlan) -> Self {
        match plan {
            ExternalPlan::Add { addrs, vpn_on } => match addrs.first() {
                Some(addr) => Self::Address {
                    addr: *addr,
                    mark: if *vpn_on {
                        GetIpMark::VpnOn
                    } else {
                        GetIpMark::Clean
                    },
                },
                None => Self::NoAnswer,
            },
            ExternalPlan::AskVpn { addrs } => match addrs.first() {
                Some(addr) => Self::Address {
                    addr: *addr,
                    mark: GetIpMark::MaybeVpn,
                },
                None => Self::NoAnswer,
            },
            ExternalPlan::Skip(SkipReason::NoAnswer) => Self::NoAnswer,
            ExternalPlan::Skip(SkipReason::ServerLocal) => Self::ServerLocal,
            ExternalPlan::Skip(SkipReason::Symmetric) => Self::Symmetric,
        }
    }
}

#[derive(Clone, PartialEq, Eq, Default)]
pub enum GetIpUi {
    #[default]
    Idle,
    Busy,
    Result(GetIpResult),
}

/// Состояние автоматической попытки помощника.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessStage {
    #[default]
    Idle,
    /// Ищем роутер (`identify`).
    Searching,
    /// Роутер найден: ждём «Разрешить» или «Не разрешать».
    Asking,
    /// Роутер разрешён, ждём статус проброса до `deadline`.
    Waiting {
        deadline: Instant,
    },
    Ok,
    /// Не вышло; `Some`: текст причины (мелко).
    Failed(Option<&'static str>),
}

/// Итог «Проверить».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckResult {
    Reachable(u16),
    NotReachable(u16),
    NoServer,
    Failed(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CheckUi {
    #[default]
    Idle,
    Checking,
    Done(CheckResult),
}

#[derive(Default)]
pub struct AccessUi {
    pub open: bool,
    pub stage: AccessStage,
    pub help: Option<ForwardHelp>,
    pub check: CheckUi,
    /// «Правило создано» принято узлом.
    pub done: bool,
    pub error: Option<&'static str>,
    /// Итог проброса на момент «Разрешить»: старый итог не считается ответом на разрешение.
    pub map_base: Option<MapStatus>,
    /// Итог проброса, появившийся после «Разрешить» (по новому снимку или событию): «Готово»
    /// только по нему.
    pub map_fresh: Option<MapStatus>,
}

/// Откуда начат поиск роутера: ответ на него относится к этому месту.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpnpOrigin {
    /// «Попробовать автоматически» в помощнике.
    Helper,
    /// «Найти роутер» в настройках.
    Settings,
}

/// Намерения помощника. Имена `Access*` записаны в охране `gated_node_actions`.
#[derive(Clone, PartialEq, Eq)]
pub enum AccessIntent {
    Open,
    Close,
    /// «Попробовать автоматически».
    AccessAuto,
    /// «Разрешить» на вопросе о роутере.
    AccessAllow,
    AccessDeny,
    /// «Проверить».
    AccessCheck,
    /// «Правило создано».
    AccessDone,
    /// Срок ожидания проброса вышел (шлёт экран).
    AutoTimeout,
}

impl AccessUi {
    /// Адрес для подстановки в тексты проверки.
    pub fn first_home(&self) -> String {
        self.help
            .as_ref()
            .and_then(|h| h.home.first())
            .map_or_else(String::new, ToString::to_string)
    }
}

/// Текст `ACC_CHECK_FAIL` с подставленными значениями.
pub fn check_fail_text(port: u16, ip: &str) -> String {
    texts::ACC_CHECK_FAIL
        .replace("{port}", &port.to_string())
        .replace("{ip}", ip)
}

impl Model {
    /// Сервер для подсказки «ваш адрес в интернете» сохранён.
    pub fn echo_server_set(&self) -> bool {
        self.snapshot
            .settings
            .as_ref()
            .is_some_and(|s| s.echo_server.is_some())
    }

    /// Кнопка «Получить свой IP» доступна: сервер указан и ничего не создаётся и не идёт.
    pub fn get_ip_enabled(&self) -> bool {
        self.echo_server_set() && self.add.get_ip != GetIpUi::Busy
    }

    fn need_permanent(&self) -> bool {
        self.snapshot.mapping == Some(MapStatus::NeedPermanentConsent)
            && self
                .snapshot
                .settings
                .as_ref()
                .is_some_and(|s| s.routers.iter().any(|r| r.needs_permanent))
    }

    pub fn update_access(&mut self, intent: AccessIntent) -> Vec<Command> {
        use AccessIntent as A;
        match intent {
            A::Open => {
                self.access = AccessUi {
                    open: true,
                    ..AccessUi::default()
                };
                vec![Command::ForwardHelp]
            }
            A::Close => {
                self.access.open = false;
                Vec::new()
            }
            // «Попробовать автоматически»: единственная ветка помощника, где появляется
            // `Command::UpnpIdentify`
            A::AccessAuto => {
                if !self.access.open
                    || matches!(
                        self.access.stage,
                        AccessStage::Searching | AccessStage::Asking | AccessStage::Waiting { .. }
                    )
                {
                    return Vec::new();
                }
                self.access.stage = AccessStage::Searching;
                if self.upnp_asked.contains(&UpnpOrigin::Helper) {
                    // прежний поиск из помощника ещё идёт: его ответ относится к этому нажатию
                    return Vec::new();
                }
                self.upnp_asked.push(UpnpOrigin::Helper);
                vec![Command::UpnpIdentify]
            }
            A::AccessAllow => {
                if self.access.stage != AccessStage::Asking {
                    return Vec::new();
                }
                // «Готово» только по итогу, который появится после этого нажатия
                self.access.map_base = self.snapshot.mapping;
                self.access.map_fresh = None;
                self.access.stage = AccessStage::Waiting {
                    deadline: Instant::now() + AUTO_WAIT,
                };
                vec![Command::UpnpAllow {
                    router: None,
                    permanent: false,
                }]
            }
            A::AccessDeny => {
                if self.access.stage == AccessStage::Asking {
                    self.access.stage = AccessStage::Idle;
                }
                Vec::new()
            }
            // «Проверить»: единственная ветка, где появляется `Command::ReachCheck`. Без сервера
            // проверять нечем: сразу честный ответ, сеть не трогается.
            A::AccessCheck => {
                if !self.access.open || self.access.check == CheckUi::Checking {
                    return Vec::new();
                }
                if !self.echo_server_set() {
                    self.access.check = CheckUi::Done(CheckResult::NoServer);
                    return Vec::new();
                }
                self.access.check = CheckUi::Checking;
                self.access.done = false;
                vec![Command::ReachCheck]
            }
            // «Правило создано»: единственная ветка, где появляется `Command::ConfirmForward`
            A::AccessDone => {
                if !self.access.open {
                    return Vec::new();
                }
                self.access.error = None;
                vec![Command::ConfirmForward]
            }
            A::AutoTimeout => self.access_progress(),
        }
    }

    /// Шаг ожидания проброса: по новому снимку и по сроку. Возвращает команды (проверка после
    /// удачного проброса запускается сама).
    pub fn access_progress(&mut self) -> Vec<Command> {
        let AccessStage::Waiting { deadline } = self.access.stage else {
            return Vec::new();
        };
        // итог, отличный от бывшего при «Разрешить», новый; прежний итог «Готово» не даёт
        if let Some(now) = self.snapshot.mapping
            && Some(now) != self.access.map_base
        {
            self.access.map_fresh = Some(now);
        }
        match self.access.map_fresh {
            Some(MapStatus::Mapped | MapStatus::MappedPermanent) => {
                self.access.stage = AccessStage::Ok;
                let mut cmds = vec![Command::ForwardHelp];
                cmds.extend(self.update_access(AccessIntent::AccessCheck));
                cmds
            }
            _ if Instant::now() >= deadline && !self.need_permanent() => {
                self.access.stage = AccessStage::Failed(None);
                vec![Command::ForwardHelp]
            }
            _ => Vec::new(),
        }
    }

    /// Ядро прислало итог проброса (событие): после «Разрешить» это и есть новый итог.
    pub fn access_mapping_reported(&mut self, status: MapStatus) -> Vec<Command> {
        if matches!(self.access.stage, AccessStage::Waiting { .. }) {
            self.access.map_fresh = Some(status);
        }
        self.access_progress()
    }

    /// Чей это ответ на поиск роутера: берётся самый старый неотвеченный поиск (узел отвечает по
    /// порядку команд). Без записи (ответ без команды из модели) решает состояние экранов.
    fn take_upnp_origin(&mut self) -> UpnpOrigin {
        if self.upnp_asked.is_empty() {
            return if self.access.stage == AccessStage::Searching {
                UpnpOrigin::Helper
            } else {
                UpnpOrigin::Settings
            };
        }
        self.upnp_asked.remove(0)
    }

    /// Ответ на поиск, начатый в помощнике. Если помощник за это время открыт заново (поиск
    /// больше не ждётся), ответ отбрасывается.
    fn helper_found(&mut self, r: Result<bool, chervo_core::NodeError>) -> Vec<Command> {
        if self.access.stage != AccessStage::Searching {
            return Vec::new();
        }
        match r {
            Ok(true) => {
                // роутер уже разрешён: вопрос не задаётся, «Разрешить» не нажималось, поэтому
                // текущий итог проброса годится
                self.access.map_base = self.snapshot.mapping;
                self.access.map_fresh = self.snapshot.mapping;
                self.access.stage = AccessStage::Waiting {
                    deadline: Instant::now() + AUTO_WAIT,
                };
                vec![Command::ForwardHelp, Command::RefreshMapping]
            }
            Ok(false) => {
                self.access.stage = AccessStage::Asking;
                vec![Command::ForwardHelp]
            }
            Err(e) => {
                self.access.stage = AccessStage::Failed(Some(e.user_text()));
                vec![Command::ForwardHelp]
            }
        }
    }

    /// Ответы на команды помощника и поиск роутера.
    pub fn outcome_access(&mut self, outcome: Outcome) -> Vec<Command> {
        match outcome {
            Outcome::UpnpFound(r) => match self.take_upnp_origin() {
                UpnpOrigin::Helper => self.helper_found(r),
                UpnpOrigin::Settings => {
                    self.outcome_settings(Outcome::UpnpFound(r));
                    Vec::new()
                }
            },
            Outcome::ForwardHelp(h) => {
                self.access.help = Some(*h);
                Vec::new()
            }
            Outcome::Reach(r) => {
                self.access.check = CheckUi::Done(match r {
                    Ok(ReachResult::Reachable { port }) => CheckResult::Reachable(port),
                    Ok(ReachResult::NotReachable { port }) => CheckResult::NotReachable(port),
                    Ok(ReachResult::NoServer | ReachResult::ServerNoReach) => CheckResult::NoServer,
                    Err(e) => CheckResult::Failed(e.user_text()),
                });
                Vec::new()
            }
            Outcome::ForwardConfirmed(r) => {
                match r {
                    Ok(()) => self.access.done = true,
                    Err(e) => self.access.error = Some(e.user_text()),
                }
                Vec::new()
            }
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::main_model::{AddStage, MainIntent};
    use crate::model::{Intent, Snapshot};
    use crate::rows::{Id, LanRow, RouterRow, SettingsRow};
    use chervo_core::{EchoFailure, KeyStoreKind, NodeError};

    fn model() -> Model {
        let (mut m, _) = Model::start();
        m.on_outcome(Outcome::Opened { port_saved: true });
        m
    }

    fn row(echo: Option<&str>) -> SettingsRow {
        SettingsRow {
            port: 50000,
            receive_root: "D:/recv".to_owned(),
            extra_roots: Vec::new(),
            min_free_percent: 5,
            invite_ttl_secs: 900,
            manual_forward: None,
            routers: Vec::new(),
            clock_offset_ms: 0,
            ntp_servers: Vec::new(),
            key_store: KeyStoreKind::CredentialManager,
            restart_needed: false,
            update_consent: chervo_core::update::UpdateConsent::NotAsked,
            lan: LanRow::default(),
            echo_server: echo.map(str::to_owned),
        }
    }

    fn with_server(m: &mut Model, echo: Option<&str>, mapping: Option<MapStatus>) {
        m.on_outcome(Outcome::Snapshot(Box::new(Snapshot {
            settings: Some(row(echo)),
            mapping,
            ..Snapshot::default()
        })));
    }

    fn ask(m: &mut Model, i: MainIntent) -> Vec<Command> {
        m.update(Intent::Main(i))
    }

    fn acc(m: &mut Model, i: AccessIntent) -> Vec<Command> {
        ask(m, MainIntent::Access(i))
    }

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("addr")
    }

    #[test]
    fn invite_without_server_creates_plain_and_hints() {
        let mut m = model();
        with_server(&mut m, None, None);
        // «Создать приглашение» всегда одна команда `Probe`: решение, ходить ли к серверу, у узла
        assert_eq!(
            ask(&mut m, MainIntent::AddCreate),
            vec![Command::CreateInvite {
                same_network: false,
                external: ExternalMode::Probe
            }]
        );
        m.on_outcome(Outcome::InviteCreated(Ok((
            Id(1),
            "CHV1".to_owned(),
            InviteExt::NotSet,
        ))));
        let AddStage::Waiting { ext, .. } = &m.add.stage else {
            panic!("ожидание");
        };
        assert!(*ext == InviteExt::NotSet);
        // без сервера «Проверяем…» не показывается
        assert!(!m.echo_server_set());
    }

    #[test]
    fn invite_probe_only_from_create_button() {
        let mut m = model();
        with_server(&mut m, Some("203.0.113.5:45900"), None);
        // ничто, кроме кнопки, пробу не выдаёт
        for i in [
            MainIntent::AddSameNetwork(true),
            MainIntent::FriendTextOpen,
            MainIntent::AddCancel,
            MainIntent::AddDone,
            MainIntent::AddVpnWithAddr,
            MainIntent::AddVpnWithout,
        ] {
            let cmds = ask(&mut m, i);
            assert!(
                cmds.iter().all(|c| !matches!(
                    c,
                    Command::CreateInvite {
                        external: ExternalMode::Probe,
                        ..
                    }
                )),
                "лишняя проба"
            );
        }
        m.update(Intent::GoSection(crate::model::Section::AddFriend));
        let _ = ask(&mut m, MainIntent::DialogClose);
        let cmds = ask(&mut m, MainIntent::AddCreate);
        assert_eq!(cmds.len(), 1);
        // пока создаётся, второго нажатия нет
        assert!(ask(&mut m, MainIntent::AddCreate).is_empty());
    }

    #[test]
    fn invite_add_shows_small_address_and_tip() {
        let mut m = model();
        with_server(&mut m, Some("203.0.113.5:45900"), None);
        ask(&mut m, MainIntent::AddCreate);
        let a = addr("198.51.100.7:50000");
        m.on_outcome(Outcome::InviteCreated(Ok((
            Id(1),
            "CHV1".to_owned(),
            InviteExt::Added {
                addr: a,
                vpn_on: false,
            },
        ))));
        let AddStage::Waiting { ext, .. } = &m.add.stage else {
            panic!("ожидание");
        };
        assert!(
            *ext == InviteExt::Added {
                addr: a,
                vpn_on: false
            }
        );
        // подпись подставляет адрес
        let line = texts::INV_EXT_ADDED.replace("{addr}", &a.to_string());
        assert!(line.contains("198.51.100.7:50000") && !line.contains("{addr}"));
        // кнопка «Разрешить входящие подключения» открывает помощник
        assert_eq!(acc(&mut m, AccessIntent::Open), vec![Command::ForwardHelp]);
        assert!(m.access.open);
    }

    #[test]
    fn invite_vpn_on_warns() {
        let mut m = model();
        with_server(&mut m, Some("203.0.113.5:45900"), None);
        ask(&mut m, MainIntent::AddCreate);
        m.on_outcome(Outcome::InviteCreated(Ok((
            Id(1),
            "CHV1".to_owned(),
            InviteExt::Added {
                addr: addr("198.51.100.7:50000"),
                vpn_on: true,
            },
        ))));
        let AddStage::Waiting { ext, .. } = &m.add.stage else {
            panic!("ожидание");
        };
        assert!(matches!(*ext, InviteExt::Added { vpn_on: true, .. }));
        // изменение адреса у ждущего приглашения: заметная строка
        m.on_outcome(Outcome::InviteAddrChanged(Id(1)));
        let AddStage::Waiting { addr_changed, .. } = &m.add.stage else {
            panic!("ожидание");
        };
        assert!(*addr_changed);
        // чужое приглашение ничего не меняет
        m.add.stage = AddStage::Waiting {
            invite: Id(2),
            token: None,
            qr: None,
            valid: None,
            ext: InviteExt::Plain,
            addr_changed: false,
        };
        m.on_outcome(Outcome::InviteAddrChanged(Id(1)));
        assert!(matches!(
            m.add.stage,
            AddStage::Waiting {
                addr_changed: false,
                ..
            }
        ));
    }

    #[test]
    fn invite_maybe_vpn_needs_explicit_answer() {
        let mut m = model();
        with_server(&mut m, Some("203.0.113.5:45900"), None);
        ask(&mut m, MainIntent::AddSameNetwork(true));
        ask(&mut m, MainIntent::AddCreate);
        let a = addr("198.51.100.7:50000");
        m.on_outcome(Outcome::InviteVpnAsk(vec![a]));
        // приглашения ещё нет, команд нет, сам по себе ответ ничего не создаёт
        assert!(matches!(m.add.stage, AddStage::VpnAsk { .. }));
        assert!(ask(&mut m, MainIntent::AddCreate).is_empty());
        // без адреса
        let mut without = model();
        with_server(&mut without, Some("203.0.113.5:45900"), None);
        ask(&mut without, MainIntent::AddCreate);
        without.on_outcome(Outcome::InviteVpnAsk(vec![a]));
        assert_eq!(
            ask(&mut without, MainIntent::AddVpnWithout),
            vec![Command::CreateInvite {
                same_network: false,
                external: ExternalMode::Without
            }]
        );
        // только явное «VPN выключен, вписать адрес» вписывает адрес
        assert_eq!(
            ask(&mut m, MainIntent::AddVpnWithAddr),
            vec![Command::CreateInvite {
                same_network: true,
                external: ExternalMode::Use(vec![a])
            }]
        );
        // второй раз: команды нет
        assert!(ask(&mut m, MainIntent::AddVpnWithAddr).is_empty());
        // «Отмена» возвращает к форме без команд
        let mut cancel = model();
        with_server(&mut cancel, Some("203.0.113.5:45900"), None);
        ask(&mut cancel, MainIntent::AddCreate);
        cancel.on_outcome(Outcome::InviteVpnAsk(vec![a]));
        assert!(ask(&mut cancel, MainIntent::AddCancel).is_empty());
        assert!(matches!(cancel.add.stage, AddStage::Form { busy: false }));
    }

    #[test]
    fn invite_skip_reasons_texts() {
        // каждая причина имеет свой текст
        let all = [
            (
                InviteExt::Skipped(SkipReason::NoAnswer),
                texts::INV_EXT_NO_ANSWER,
            ),
            (
                InviteExt::Skipped(SkipReason::ServerLocal),
                texts::INV_EXT_SERVER_LOCAL,
            ),
            (
                InviteExt::Skipped(SkipReason::Symmetric),
                texts::INV_EXT_SYMMETRIC,
            ),
        ];
        for (ext, want) in all {
            assert_eq!(skip_text(ext), Some(want));
        }
        assert_eq!(skip_text(InviteExt::Plain), None);
        // ошибка пробы: текст ядра
        assert_eq!(
            skip_text(InviteExt::Failed(chervo_core::texts::ECHO_BUSY_TEXT)),
            Some(chervo_core::texts::ECHO_BUSY_TEXT)
        );
        let mut m = model();
        with_server(&mut m, Some("203.0.113.5:45900"), None);
        ask(&mut m, MainIntent::AddCreate);
        m.on_outcome(Outcome::InviteCreated(Ok((
            Id(1),
            "CHV1".to_owned(),
            InviteExt::Skipped(SkipReason::Symmetric),
        ))));
        assert!(matches!(m.add.stage, AddStage::Waiting { .. }));
    }

    /// Текст причины, по которой адрес не вписан; общий для экрана и проверки.
    fn skip_text(ext: InviteExt) -> Option<&'static str> {
        crate::screens::invite_ext_note(ext)
    }

    #[test]
    fn invite_no_addresses_shows_open_access() {
        let mut m = model();
        with_server(&mut m, None, None);
        ask(&mut m, MainIntent::AddCreate);
        m.on_outcome(Outcome::InviteCreated(Err(NodeError::Friends(
            chervo_core::FriendsError::NoAddresses,
        ))));
        assert!(matches!(m.add.stage, AddStage::Form { busy: false }));
        assert_eq!(m.add.error, Some(chervo_core::texts::NO_ADDRESS_TEXT));
        assert!(m.add.no_addresses);
        // другая ошибка кнопку помощника не просит
        ask(&mut m, MainIntent::AddCreate);
        m.on_outcome(Outcome::InviteCreated(Err(NodeError::Io)));
        assert!(!m.add.no_addresses);
    }

    #[test]
    fn get_ip_button_disabled_without_server_and_hint() {
        let mut m = model();
        with_server(&mut m, None, None);
        assert!(!m.get_ip_enabled());
        // без сервера намерение ничего не выдаёт и сети не трогает
        assert!(ask(&mut m, MainIntent::GetIp).is_empty());
        assert_eq!(m.add.get_ip, GetIpUi::Idle);
        // подсказка называет вкладку, раздел и строку
        for part in ["Настройки", "Связь через интернет", "Адрес вашего сервера"]
        {
            assert!(texts::GETIP_NO_SERVER.contains(part), "{part}");
        }
        with_server(&mut m, Some("203.0.113.5:45900"), None);
        assert!(m.get_ip_enabled());
        assert_eq!(ask(&mut m, MainIntent::GetIp), vec![Command::EchoProbe]);
        // пока идёт, второй команды нет
        assert!(!m.get_ip_enabled());
        assert!(ask(&mut m, MainIntent::GetIp).is_empty());
    }

    #[test]
    fn get_ip_shows_copy_and_vpn_marks() {
        let a = addr("198.51.100.7:50000");
        let table = [
            (
                ExternalPlan::Add {
                    addrs: vec![a],
                    vpn_on: false,
                },
                GetIpResult::Address {
                    addr: a,
                    mark: GetIpMark::Clean,
                },
            ),
            (
                ExternalPlan::Add {
                    addrs: vec![a],
                    vpn_on: true,
                },
                GetIpResult::Address {
                    addr: a,
                    mark: GetIpMark::VpnOn,
                },
            ),
            (
                ExternalPlan::AskVpn { addrs: vec![a] },
                GetIpResult::Address {
                    addr: a,
                    mark: GetIpMark::MaybeVpn,
                },
            ),
            (
                ExternalPlan::Skip(SkipReason::NoAnswer),
                GetIpResult::NoAnswer,
            ),
            (
                ExternalPlan::Skip(SkipReason::ServerLocal),
                GetIpResult::ServerLocal,
            ),
            (
                ExternalPlan::Skip(SkipReason::Symmetric),
                GetIpResult::Symmetric,
            ),
        ];
        for (plan, want) in table {
            assert!(GetIpResult::from_plan(&plan) == want);
        }
        let mut m = model();
        with_server(&mut m, Some("203.0.113.5:45900"), None);
        ask(&mut m, MainIntent::GetIp);
        m.on_outcome(Outcome::GetIp(GetIpResult::Address {
            addr: a,
            mark: GetIpMark::VpnOn,
        }));
        assert!(
            m.add.get_ip
                == GetIpUi::Result(GetIpResult::Address {
                    addr: a,
                    mark: GetIpMark::VpnOn
                })
        );
        // ошибка ядра показывается её текстом
        ask(&mut m, MainIntent::GetIp);
        m.on_outcome(Outcome::GetIp(GetIpResult::Failed(
            NodeError::Echo(EchoFailure::Resolve).user_text(),
        )));
        assert!(matches!(
            m.add.get_ip,
            GetIpUi::Result(GetIpResult::Failed(_))
        ));
    }

    #[test]
    fn access_auto_asks_before_allow() {
        let mut m = model();
        with_server(&mut m, None, None);
        // помощник закрыт: ничего не делает
        assert!(acc(&mut m, AccessIntent::AccessAuto).is_empty());
        acc(&mut m, AccessIntent::Open);
        // «Разрешить» без найденного роутера не даёт `UpnpAllow`
        assert!(acc(&mut m, AccessIntent::AccessAllow).is_empty());
        // поиск: только после нажатия
        assert_eq!(
            acc(&mut m, AccessIntent::AccessAuto),
            vec![Command::UpnpIdentify]
        );
        assert!(acc(&mut m, AccessIntent::AccessAuto).is_empty());
        // роутер найден: вопрос, команд нет
        let next = m.on_outcome(Outcome::UpnpFound(Ok(false)));
        assert!(!next.iter().any(|c| matches!(c, Command::UpnpAllow { .. })));
        assert_eq!(m.access.stage, AccessStage::Asking);
        // «Не разрешать»: ничего не открыто
        assert!(acc(&mut m, AccessIntent::AccessDeny).is_empty());
        assert_eq!(m.access.stage, AccessStage::Idle);
        assert!(acc(&mut m, AccessIntent::AccessAllow).is_empty());
        // снова, на этот раз «Разрешить»
        acc(&mut m, AccessIntent::AccessAuto);
        m.on_outcome(Outcome::UpnpFound(Ok(false)));
        assert_eq!(
            acc(&mut m, AccessIntent::AccessAllow),
            vec![Command::UpnpAllow {
                router: None,
                permanent: false
            }]
        );
        assert!(matches!(m.access.stage, AccessStage::Waiting { .. }));
        // проброс открылся: автоматически идёт проверка (сервера нет: честный ответ без сети)
        with_server(&mut m, None, Some(MapStatus::Mapped));
        assert_eq!(m.access.stage, AccessStage::Ok);
        assert_eq!(m.access.check, CheckUi::Done(CheckResult::NoServer));
        // с сервером проверка уходит командой
        let mut m = model();
        with_server(&mut m, Some("203.0.113.5:45900"), None);
        acc(&mut m, AccessIntent::Open);
        acc(&mut m, AccessIntent::AccessAuto);
        // роутер уже разрешён: вопрос не задаётся, статус обновляется
        let next = m.on_outcome(Outcome::UpnpFound(Ok(true)));
        assert!(next.contains(&Command::RefreshMapping));
        assert!(!next.iter().any(|c| matches!(c, Command::UpnpAllow { .. })));
        let cmds = m.on_outcome(Outcome::Snapshot(Box::new(Snapshot {
            settings: Some(row(Some("203.0.113.5:45900"))),
            mapping: Some(MapStatus::MappedPermanent),
            ..Snapshot::default()
        })));
        assert!(cmds.contains(&Command::ReachCheck));
        assert_eq!(m.access.check, CheckUi::Checking);
    }

    #[test]
    fn access_auto_failure_shows_manual_steps_and_times_out() {
        let mut m = model();
        with_server(&mut m, None, None);
        acc(&mut m, AccessIntent::Open);
        acc(&mut m, AccessIntent::AccessAuto);
        m.on_outcome(Outcome::UpnpFound(Err(NodeError::Unsupported)));
        assert!(matches!(m.access.stage, AccessStage::Failed(Some(_))));
        // после «Разрешить» срок ожидания 10 с: до срока ждём, после срока ручные шаги
        acc(&mut m, AccessIntent::AccessAuto);
        m.on_outcome(Outcome::UpnpFound(Ok(false)));
        acc(&mut m, AccessIntent::AccessAllow);
        assert!(acc(&mut m, AccessIntent::AutoTimeout).is_empty());
        assert!(matches!(m.access.stage, AccessStage::Waiting { .. }));
        m.access.stage = AccessStage::Waiting {
            deadline: Instant::now() - Duration::from_secs(1),
        };
        acc(&mut m, AccessIntent::AutoTimeout);
        assert_eq!(m.access.stage, AccessStage::Failed(None));
    }

    /// Готовый помощник на вопросе «Разрешить» при старом итоге `Mapped`.
    fn asking_with_old_mapped() -> Model {
        let mut m = model();
        with_server(&mut m, None, Some(MapStatus::Mapped));
        acc(&mut m, AccessIntent::Open);
        acc(&mut m, AccessIntent::AccessAuto);
        m.on_outcome(Outcome::UpnpFound(Ok(false)));
        assert_eq!(m.access.stage, AccessStage::Asking);
        m
    }

    #[test]
    fn old_mapped_status_does_not_finish_after_allow() {
        let mut m = asking_with_old_mapped();
        acc(&mut m, AccessIntent::AccessAllow);
        // тот же старый итог в новом снимке: не «Готово»
        with_server(&mut m, None, Some(MapStatus::Mapped));
        assert!(matches!(m.access.stage, AccessStage::Waiting { .. }));
        assert_eq!(m.access.check, CheckUi::Idle);
        // срок вышел, нового итога нет: ручные шаги, а не «Готово»
        m.access.stage = AccessStage::Waiting {
            deadline: Instant::now() - Duration::from_secs(1),
        };
        acc(&mut m, AccessIntent::AutoTimeout);
        assert_eq!(m.access.stage, AccessStage::Failed(None));
        // новый итог в снимке закрывает ожидание
        let mut m = asking_with_old_mapped();
        acc(&mut m, AccessIntent::AccessAllow);
        with_server(&mut m, None, Some(MapStatus::MappedPermanent));
        assert_eq!(m.access.stage, AccessStage::Ok);
    }

    #[test]
    fn mapping_event_after_allow_is_the_new_status() {
        let mut m = asking_with_old_mapped();
        acc(&mut m, AccessIntent::AccessAllow);
        // событие о том же итоге после «Разрешить» (снимок ещё старый) тоже новое
        m.on_outcome(Outcome::Event(chervo_core::NodeEvent::MappingChanged {
            status: MapStatus::Mapped,
        }));
        assert_eq!(m.access.stage, AccessStage::Ok);
        // событие вне ожидания ничего не открывает
        let mut m = asking_with_old_mapped();
        m.on_outcome(Outcome::Event(chervo_core::NodeEvent::MappingChanged {
            status: MapStatus::Mapped,
        }));
        assert_eq!(m.access.stage, AccessStage::Asking);
    }

    #[test]
    fn router_already_allowed_accepts_current_status() {
        // «Разрешить» не нажималось: текущий итог проброса годится
        let mut m = model();
        with_server(&mut m, None, Some(MapStatus::Mapped));
        acc(&mut m, AccessIntent::Open);
        acc(&mut m, AccessIntent::AccessAuto);
        m.on_outcome(Outcome::UpnpFound(Ok(true)));
        with_server(&mut m, None, Some(MapStatus::Mapped));
        assert_eq!(m.access.stage, AccessStage::Ok);
    }

    #[test]
    fn settings_search_answer_goes_to_settings_not_helper() {
        use crate::settings_model::{SettingsIntent, UpnpUi};
        let mut m = model();
        with_server(&mut m, None, None);
        // поиск начат в настройках, потом открыт помощник и в нём нажато «Попробовать»
        assert_eq!(
            ask(&mut m, MainIntent::Settings(SettingsIntent::UpnpFind)),
            vec![Command::UpnpIdentify]
        );
        acc(&mut m, AccessIntent::Open);
        assert_eq!(
            acc(&mut m, AccessIntent::AccessAuto),
            vec![Command::UpnpIdentify]
        );
        // первый ответ (настройки) не задаёт вопрос в помощнике
        m.on_outcome(Outcome::UpnpFound(Ok(false)));
        assert!(m.settings_ui.upnp == UpnpUi::Found);
        assert_eq!(m.access.stage, AccessStage::Searching);
        // второй ответ (помощник) не трогает настройки
        m.settings_ui.upnp = UpnpUi::Idle;
        m.on_outcome(Outcome::UpnpFound(Ok(false)));
        assert_eq!(m.access.stage, AccessStage::Asking);
        assert!(m.settings_ui.upnp == UpnpUi::Idle);
    }

    #[test]
    fn helper_search_answer_after_reopen_is_dropped() {
        use crate::settings_model::UpnpUi;
        let mut m = model();
        with_server(&mut m, None, None);
        acc(&mut m, AccessIntent::Open);
        acc(&mut m, AccessIntent::AccessAuto);
        // помощник закрыт и открыт заново до ответа: вопроса ни там, ни в настройках
        acc(&mut m, AccessIntent::Close);
        acc(&mut m, AccessIntent::Open);
        m.on_outcome(Outcome::UpnpFound(Ok(false)));
        assert_eq!(m.access.stage, AccessStage::Idle);
        assert!(m.settings_ui.upnp == UpnpUi::Idle);
        // новое нажатие не шлёт второй поиск, пока первый не вернулся
        let mut m = model();
        with_server(&mut m, None, None);
        acc(&mut m, AccessIntent::Open);
        acc(&mut m, AccessIntent::AccessAuto);
        acc(&mut m, AccessIntent::Close);
        acc(&mut m, AccessIntent::Open);
        assert!(acc(&mut m, AccessIntent::AccessAuto).is_empty());
        assert_eq!(m.access.stage, AccessStage::Searching);
        m.on_outcome(Outcome::UpnpFound(Ok(false)));
        assert_eq!(m.access.stage, AccessStage::Asking);
    }

    #[test]
    fn access_manual_steps_have_copy_values() {
        let help = ForwardHelp {
            port: 50000,
            home: vec![
                std::net::Ipv4Addr::new(192, 168, 1, 10),
                std::net::Ipv4Addr::new(10, 0, 0, 5),
            ],
            gw: Some(std::net::Ipv4Addr::new(192, 168, 1, 1)),
            gw_exact: true,
            vpn: false,
            cgnat: false,
        };
        let mut m = model();
        acc(&mut m, AccessIntent::Open);
        m.on_outcome(Outcome::ForwardHelp(Box::new(help)));
        let rows = crate::screens::manual_values(&m.access);
        let all: Vec<&str> = rows.iter().map(|(_, v)| v.as_str()).collect();
        assert!(all.contains(&"Chervotochina"));
        assert!(all.contains(&"UDP"));
        assert_eq!(all.iter().filter(|v| **v == "50000").count(), 2);
        assert!(all.contains(&"192.168.1.10") && all.contains(&"10.0.0.5"));
        assert_eq!(
            crate::screens::gateway_url(&m.access),
            Some("http://192.168.1.1".to_owned())
        );
        // без значений помощника подставлять нечего
        m.access.help = None;
        assert!(crate::screens::manual_values(&m.access).is_empty());
        assert_eq!(crate::screens::gateway_url(&m.access), None);
    }

    #[test]
    fn access_check_texts() {
        let mut m = model();
        with_server(&mut m, Some("203.0.113.5:45900"), None);
        acc(&mut m, AccessIntent::Open);
        assert_eq!(
            acc(&mut m, AccessIntent::AccessCheck),
            vec![Command::ReachCheck]
        );
        // пока идёт, второй команды нет
        assert!(acc(&mut m, AccessIntent::AccessCheck).is_empty());
        m.on_outcome(Outcome::Reach(Ok(ReachResult::NotReachable {
            port: 50000,
        })));
        assert_eq!(
            m.access.check,
            CheckUi::Done(CheckResult::NotReachable(50000))
        );
        m.on_outcome(Outcome::ForwardHelp(Box::new(ForwardHelp {
            port: 50000,
            home: vec![std::net::Ipv4Addr::new(192, 168, 1, 10)],
            gw: None,
            gw_exact: false,
            vpn: false,
            cgnat: false,
        })));
        let t = check_fail_text(50000, &m.access.first_home());
        assert!(t.contains("50000") && t.contains("192.168.1.10") && !t.contains('{'));
        m.on_outcome(Outcome::Reach(Ok(ReachResult::Reachable { port: 50001 })));
        assert_eq!(m.access.check, CheckUi::Done(CheckResult::Reachable(50001)));
        m.on_outcome(Outcome::Reach(Ok(ReachResult::ServerNoReach)));
        assert_eq!(m.access.check, CheckUi::Done(CheckResult::NoServer));
        m.on_outcome(Outcome::Reach(Err(NodeError::Io)));
        assert!(matches!(
            m.access.check,
            CheckUi::Done(CheckResult::Failed(_))
        ));
        // без сервера проверка не ходит в сеть и отвечает честно
        let mut m = model();
        with_server(&mut m, None, None);
        acc(&mut m, AccessIntent::Open);
        assert!(acc(&mut m, AccessIntent::AccessCheck).is_empty());
        assert_eq!(m.access.check, CheckUi::Done(CheckResult::NoServer));
    }

    #[test]
    fn access_done_only_from_button() {
        let mut m = model();
        with_server(&mut m, None, None);
        // закрытый помощник «Правило создано» не принимает
        assert!(acc(&mut m, AccessIntent::AccessDone).is_empty());
        acc(&mut m, AccessIntent::Open);
        // проверка и успех сами «Правило создано» не выдают
        let next = m.on_outcome(Outcome::Reach(Ok(ReachResult::Reachable { port: 50000 })));
        assert!(!next.contains(&Command::ConfirmForward));
        assert_eq!(
            acc(&mut m, AccessIntent::AccessDone),
            vec![Command::ConfirmForward]
        );
        assert!(!m.access.done);
        m.on_outcome(Outcome::ForwardConfirmed(Ok(())));
        assert!(m.access.done);
    }

    #[test]
    fn open_access_on_invite_and_diagnosis() {
        // кнопка есть на «Пригласить» (постоянно) и у друга с причиной в роутере или адресе
        let mut m = model();
        with_server(&mut m, None, None);
        m.update(Intent::GoSection(crate::model::Section::AddFriend));
        let seen = crate::screens::rendered_texts(&m);
        assert!(seen.contains(texts::BTN_OPEN_ACCESS), "{seen}");
        assert!(seen.contains(texts::BTN_GET_IP), "{seen}");
        // диагностика: друг без соединения с причиной «нужен адрес»
        m.on_outcome(Outcome::Snapshot(Box::new(Snapshot {
            friends: vec![crate::rows::FriendRow {
                id: Id(1),
                name: "Маша".to_owned(),
                status: chervo_core::FriendStatus::Active,
                online: false,
                auto_accept: false,
                key_problem: false,
                path: None,
            }],
            diagnoses: vec![crate::rows::DiagRow {
                friend: Id(1),
                text: chervo_core::texts::CGNAT_TEXT,
                could_help: false,
                lan_hint: false,
                open_access: true,
            }],
            settings: Some(row(None)),
            ..Snapshot::default()
        })));
        m.update(Intent::GoSection(crate::model::Section::Diagnosis));
        // вкладка «Настройки» уже несёт одну такую кнопку (раздел «Входящие подключения»),
        // вторая стоит у друга с причиной в роутере
        let seen = crate::screens::rendered_texts(&m);
        assert_eq!(seen.matches(texts::BTN_OPEN_ACCESS).count(), 2, "{seen}");
        // у другой причины второй кнопки нет
        if let Some(d) = m.snapshot.diagnoses.first_mut() {
            d.open_access = false;
        }
        let seen = crate::screens::rendered_texts(&m);
        assert_eq!(seen.matches(texts::BTN_OPEN_ACCESS).count(), 1, "{seen}");
    }

    #[test]
    fn invite_form_has_no_manual_field() {
        // П6 = (а): поля «Свой адрес с пробросом порта» на экране приглашения нет; ручной номер
        // одна строка в «Настройки», раздел «Входящие подключения»
        let mut m = model();
        with_server(&mut m, None, None);
        m.update(Intent::GoSection(crate::model::Section::AddFriend));
        let seen = crate::screens::rendered_texts(&m);
        assert!(!seen.contains("Свой адрес с пробросом"), "{seen}");
        assert!(!seen.contains("IP:порт"), "{seen}");
        m.update(Intent::Go(crate::model::Page::Settings));
        let seen = crate::screens::rendered_texts(&m);
        assert!(seen.contains(texts::ACC_MANUAL_FORWARD_LABEL), "{seen}");
        assert!(seen.contains(texts::SET_TITLE_UPNP), "{seen}");
    }

    /// Дополнение владельца 2026-11-18: пояснения у новых пунктов за значком «?», на экране их
    /// текста нет; обязательные предупреждения остаются на виду.
    #[test]
    fn explanations_hide_behind_help_mark_warnings_stay() {
        let mut m = model();
        with_server(&mut m, None, None);
        // «Пригласить» без сервера: значок есть, текст подсказки на экране не лежит
        m.update(Intent::GoSection(crate::model::Section::AddFriend));
        let seen = crate::screens::rendered_texts(&m);
        assert!(seen.contains(texts::HELP_MARK), "{seen}");
        assert!(!seen.contains(texts::GETIP_NO_SERVER), "{seen}");
        assert!(seen.contains(texts::IP_WARNING), "{seen}");
        // настройки: подпись и значок, длинное описание только во всплывающей подсказке
        m.update(Intent::Go(crate::model::Page::Settings));
        let seen = crate::screens::rendered_texts(&m);
        assert!(seen.contains(texts::EXT_SERVER_LABEL), "{seen}");
        assert!(!seen.contains(texts::EXT_SERVER_HINT), "{seen}");
        // ожидание приглашения без сервера: короткая подпись, длинный совет за значком
        ask(&mut m, MainIntent::AddCreate);
        m.on_outcome(Outcome::InviteCreated(Ok((
            Id(1),
            "CHV1".to_owned(),
            InviteExt::NotSet,
        ))));
        m.update(Intent::GoSection(crate::model::Section::AddFriend));
        let seen = crate::screens::rendered_texts(&m);
        assert!(seen.contains(texts::INV_EXT_NOT_SET_LABEL), "{seen}");
        assert!(!seen.contains(texts::INV_EXT_NOT_SET), "{seen}");
        assert!(seen.contains(texts::IP_WARNING), "{seen}");
        // помощник: описание за значком, вопрос о роутере с предупреждением на виду
        acc(&mut m, AccessIntent::Open);
        acc(&mut m, AccessIntent::AccessAuto);
        m.on_outcome(Outcome::UpnpFound(Ok(false)));
        let seen = crate::screens::rendered_texts(&m);
        assert!(seen.contains(texts::ACC_TITLE), "{seen}");
        assert!(!seen.contains(texts::ACC_INTRO), "{seen}");
        assert!(seen.contains(texts::ACC_ASK_ROUTER), "{seen}");
        assert!(seen.contains(texts::BTN_ACC_ALLOW), "{seen}");
    }

    #[test]
    fn open_access_closes_on_navigation() {
        let mut m = model();
        acc(&mut m, AccessIntent::Open);
        assert!(m.access.open);
        m.update(Intent::Go(crate::model::Page::Friends));
        assert!(!m.access.open);
        acc(&mut m, AccessIntent::Open);
        acc(&mut m, AccessIntent::Close);
        assert!(!m.access.open);
    }

    #[test]
    fn router_asked_for_permanent_keeps_waiting() {
        let mut m = model();
        acc(&mut m, AccessIntent::Open);
        acc(&mut m, AccessIntent::AccessAuto);
        m.on_outcome(Outcome::UpnpFound(Ok(false)));
        acc(&mut m, AccessIntent::AccessAllow);
        let mut set = row(None);
        set.routers = vec![RouterRow {
            id: Id(0),
            permanent_ok: false,
            needs_permanent: true,
        }];
        m.access.stage = AccessStage::Waiting {
            deadline: Instant::now() - Duration::from_secs(1),
        };
        m.on_outcome(Outcome::Snapshot(Box::new(Snapshot {
            settings: Some(set),
            mapping: Some(MapStatus::NeedPermanentConsent),
            ..Snapshot::default()
        })));
        // роутер ждёт ответа человека: ручные шаги не выскакивают
        assert!(matches!(m.access.stage, AccessStage::Waiting { .. }));
    }
}
