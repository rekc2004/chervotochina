//! Состояния главного окна: друзья (экран 2), добавление друга и проверочный код (экран 3),
//! отправка (4), входящие предложения (5), передачи (6). Чистые данные и правила, без окна и
//! узла. Опасные шаги выдаются командой только после явного ответа пользователя:
//! автоприём только после вопроса о доверии, «принять» предложение с рискованными файлами
//! только после отметки, проверочный код только после «Совпадает» и непустого имени.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Instant;

use chervo_core::{FriendStatus, InviteOutcome};

use crate::access_model::{AccessIntent, ExternalMode, GetIpUi, InviteExt};
use crate::model::{Command, FriendTextOutcome, Model, Outcome, Section};
use crate::qr::{self, QrMatrix};
use crate::redact::redacted_debug_enum;
use crate::rows::{Id, PickedPath};
use crate::settings_model::SettingsIntent;
use crate::texts;
use crate::update_model::UpdateIntent;

redacted_debug_enum!(MainIntent);

/// Предел вставленного текста (приглашение, токен), байт: как в узле, чтобы отказывать раньше.
pub const MAX_PASTE: usize = 4096;
/// Сколько уведомлений держим.
const MAX_NOTICES: usize = 20;

/// Обрезает текст до `MAX_PASTE` байт по границе символа; `true`, если текст был длиннее.
pub fn cap_paste(text: String) -> (String, bool) {
    if text.len() <= MAX_PASTE {
        return (text, false);
    }
    let mut cut = MAX_PASTE;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    (text[..cut].to_owned(), true)
}

/// Намерения главного окна.
#[derive(Clone, PartialEq, Eq)]
pub enum MainIntent {
    // друзья
    RenameOpen(Id),
    RenameEdited(String),
    RenameSubmit,
    Block(Id),
    Unblock(Id),
    RemoveAsk(Id),
    RemoveConfirm,
    RekeyAsk(Id),
    RekeyConfirm,
    RekeyAllAsk,
    RekeyAllConfirm,
    AutoAcceptAsk(Id),
    TrustYes,
    AutoAcceptOff(Id),
    AddrTokenOpen(Id),
    AddrTokenNetwork(bool),
    AddrTokenIssue,
    /// «Друг прислал мне текст»: одно поле для приглашения, нового адреса и уведомления об
    /// удалении (на «Друзьях» и на «Добавить друга»).
    FriendTextOpen,
    FriendTextEdited(String),
    FriendTextSubmit,
    ConnectNow(Id),
    FriendSend(Id),
    DialogClose,
    /// Щелчок по системному уведомлению о входящих файлах.
    ShowOffers,
    /// «Скрыть все».
    DismissNotices,
    /// «×» у одной строки (номер строки в списке).
    DismissNotice(usize),
    // добавление друга
    AddSameNetwork(bool),
    AddCreate,
    /// «Получить свой IP».
    GetIp,
    /// Ответ «VPN выключен, вписать адрес» на вопрос о VPN при создании приглашения.
    AddVpnWithAddr,
    /// Ответ «Создать приглашение без этого адреса».
    AddVpnWithout,
    /// Помощник «Разрешить входящие подключения» (этап 13д).
    Access(AccessIntent),
    AddCancel,
    AddDone,
    SasNameEdited(String),
    SasMatch,
    SasMismatch,
    // отправка
    PathsAdded(Vec<PickedPath>),
    PathRemoved(usize),
    SendFriend(Id),
    SendSubmit,
    // входящие
    OfferAck(Id, bool),
    OfferAccept(Id),
    OfferAcceptInto {
        id: Id,
        root: PathBuf,
    },
    OfferDecline(Id),
    // передачи
    TransferCancel(Id),
    TransferRetry(Id),
    /// «Убрать» у завершённой передачи (файлы на диске остаются).
    TransferForget(Id),
    /// «Очистить завершённые» над списком передач.
    TransferForgetFinished,
    /// Кнопка «Открыть папку»: только папка приёма из настроек (Н7).
    OpenReceiveFolder,
    Settings(SettingsIntent),
    Update(UpdateIntent),
}

/// Один диалог за раз; пока он открыт, он занимает место списка друзей.
pub enum Dialog {
    None,
    Rename {
        friend: Id,
        text: String,
    },
    ConfirmRemove(Id),
    ConfirmRekey(Id),
    ConfirmRekeyAll,
    /// Вопрос `TRUST_QUESTION_TEXT`; автоприём включается только ответом «да».
    Trust(Id),
    Revocation(RevocationDialog),
    AddrToken(AddrTokenDialog),
    /// «Друг прислал мне текст» (общее поле).
    FriendText(PasteDialog),
}

pub struct RevocationDialog {
    /// (имя друга, текст отзыва)
    pub items: Vec<(String, String)>,
    pub rekey: bool,
    pub failed: usize,
}

pub struct AddrTokenDialog {
    pub friend: Id,
    pub same_network: bool,
    pub token: Option<String>,
    pub busy: bool,
    pub error: Option<&'static str>,
}

pub struct PasteDialog {
    pub text: String,
    pub too_long: bool,
    pub error: Option<&'static str>,
    pub busy: bool,
}

pub struct SasState {
    pub invite: Id,
    pub digits: String,
    pub spoken: String,
    pub name: String,
    pub error: Option<&'static str>,
    pub busy: bool,
    /// «Совпадает» отправлено, ждём, пока друг тоже ответит.
    pub waiting: bool,
}

pub enum AddStage {
    Form {
        busy: bool,
    },
    /// Приглашение создано (`token`) или принято (`None`): ждём проверочный код.
    Waiting {
        invite: Id,
        token: Option<String>,
        qr: Option<QrMatrix>,
        /// Только у созданного приглашения: когда оно создано и сколько секунд действует.
        valid: Option<(Instant, u64)>,
        /// Что стало с адресом от сервера (только у созданного приглашения).
        ext: InviteExt,
        /// Адрес в интернете изменился, пока приглашение ждёт: оно может не сработать.
        addr_changed: bool,
    },
    /// Похоже на VPN: приглашения ещё нет, ждём ответа человека (адреса от сервера).
    VpnAsk {
        addrs: Vec<SocketAddr>,
    },
    Sas(SasState),
    Finished(&'static str),
}

pub struct AddFriend {
    pub same_network: bool,
    pub error: Option<&'static str>,
    /// Ошибка «нет адреса для приглашения» (В4): рядом кнопка «Разрешить входящие подключения».
    pub no_addresses: bool,
    /// Итог кнопки «Получить свой IP».
    pub get_ip: GetIpUi,
    pub stage: AddStage,
}

impl Default for AddFriend {
    fn default() -> Self {
        Self {
            same_network: false,
            error: None,
            no_addresses: false,
            get_ip: GetIpUi::Idle,
            stage: AddStage::Form { busy: false },
        }
    }
}

#[derive(Default)]
pub struct SendUi {
    pub paths: Vec<PickedPath>,
    pub friend: Option<Id>,
    pub error: Option<&'static str>,
    pub busy: bool,
}

#[derive(Default, Clone, Copy)]
pub struct OfferUi {
    /// Пользователь отметил «доверяю отправителю и знаю, зачем этот файл».
    pub ack: bool,
    pub busy: bool,
}

/// Что за уведомление: от этого зависит, когда оно гаснет само.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NoticeKind {
    /// Гаснет только по «×» и «Скрыть все».
    General,
    /// «Друг недоступен»: гаснет, когда друг снова на связи.
    FriendUnreachable,
    /// «Папка приёма изменена.»: гаснет при следующем действии в настройках.
    RootChanged,
}

/// Строка уведомления в шапке. `friend`: друг, о котором она (если о друге).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Notice {
    pub text: String,
    pub friend: Option<Id>,
    pub kind: NoticeKind,
}

impl Model {
    pub fn push_notice(&mut self, text: impl Into<String>) {
        self.push_notice_for(text, None, NoticeKind::General);
    }

    pub fn push_notice_for(
        &mut self,
        text: impl Into<String>,
        friend: Option<Id>,
        kind: NoticeKind,
    ) {
        let n = Notice {
            text: text.into(),
            friend,
            kind,
        };
        if self.notices.last() == Some(&n) {
            return;
        }
        if self.notices.len() >= MAX_NOTICES {
            self.notices.remove(0);
        }
        self.notices.push(n);
    }

    /// Тексты уведомлений по порядку (для проверок в тестах).
    #[cfg(test)]
    pub fn notice_texts(&self) -> Vec<String> {
        self.notices.iter().map(|n| n.text.clone()).collect()
    }

    /// Друзья `online` снова на связи: уведомления «недоступен» о них больше не нужны.
    pub fn friend_reachable(&mut self, online: &[Id]) {
        self.notices.retain(|n| {
            !(n.kind == NoticeKind::FriendUnreachable
                && n.friend.is_some_and(|f| online.contains(&f)))
        });
    }

    /// Уведомлять ли о входящих файлах: галочка в настройках (до первого снимка включено).
    fn notify_enabled(&self) -> bool {
        self.snapshot
            .settings
            .as_ref()
            .is_none_or(|s| s.notify_incoming)
    }

    /// Уведомление о новом предложении: если включено и по этому предложению ещё не было.
    fn toast_incoming(&mut self, n: &crate::notify::OfferNote) {
        if self.notify_enabled() && self.notified.insert(n.transfer) {
            self.toasts.push(crate::notify::Toast {
                text: crate::notify::incoming_text(n),
            });
        }
    }

    fn push_toast(&mut self, text: String) {
        if self.notify_enabled() {
            self.toasts.push(crate::notify::Toast { text });
        }
    }

    /// Уведомления, которые нужно показать системе (каждое один раз).
    pub fn take_toasts(&mut self) -> Vec<crate::notify::Toast> {
        std::mem::take(&mut self.toasts)
    }

    /// Нужно ли мигнуть окном в панели задач (один раз на событие).
    pub fn take_attention(&mut self) -> bool {
        std::mem::take(&mut self.attention)
    }

    fn friend(&self, id: Id) -> Option<&crate::rows::FriendRow> {
        self.snapshot.friends.iter().find(|f| f.id == id)
    }

    /// Друг, с которым можно действовать: активен и ключ в порядке.
    fn usable_friend(&self, id: Id) -> bool {
        self.friend(id)
            .is_some_and(|f| f.status == FriendStatus::Active && !f.key_problem)
    }

    pub fn update_main(&mut self, intent: MainIntent) -> Vec<Command> {
        use MainIntent as I;
        match intent {
            I::RenameOpen(id) => {
                if let Some(f) = self.friend(id) {
                    self.dialog = Dialog::Rename {
                        friend: id,
                        text: f.name.clone(),
                    };
                }
                Vec::new()
            }
            I::RenameEdited(t) => {
                if let Dialog::Rename { text, .. } = &mut self.dialog {
                    *text = cap_paste(t).0;
                }
                Vec::new()
            }
            I::RenameSubmit => {
                let Dialog::Rename { friend, text } = &self.dialog else {
                    return Vec::new();
                };
                let (friend, name) = (*friend, text.trim().to_owned());
                if name.is_empty() {
                    return Vec::new();
                }
                self.dialog = Dialog::None;
                vec![Command::Rename { friend, name }]
            }
            I::Block(id) => {
                if self
                    .friend(id)
                    .is_some_and(|f| f.status == FriendStatus::Active)
                {
                    vec![Command::Block(id)]
                } else {
                    Vec::new()
                }
            }
            I::Unblock(id) => {
                if self
                    .friend(id)
                    .is_some_and(|f| f.status == FriendStatus::Blocked)
                {
                    vec![Command::Unblock(id)]
                } else {
                    Vec::new()
                }
            }
            I::RemoveAsk(id) => {
                if self.friend(id).is_some() {
                    self.dialog = Dialog::ConfirmRemove(id);
                }
                Vec::new()
            }
            I::RemoveConfirm => {
                if let Dialog::ConfirmRemove(id) = self.dialog {
                    self.dialog = Dialog::None;
                    vec![Command::Remove(id)]
                } else {
                    Vec::new()
                }
            }
            I::RekeyAsk(id) => {
                if self.friend(id).is_some_and(|f| {
                    matches!(f.status, FriendStatus::Active | FriendStatus::Blocked)
                }) {
                    self.dialog = Dialog::ConfirmRekey(id);
                }
                Vec::new()
            }
            I::RekeyConfirm => {
                if let Dialog::ConfirmRekey(id) = self.dialog {
                    self.dialog = Dialog::None;
                    vec![Command::Rekey(id)]
                } else {
                    Vec::new()
                }
            }
            I::RekeyAllAsk => {
                self.dialog = Dialog::ConfirmRekeyAll;
                Vec::new()
            }
            I::RekeyAllConfirm => {
                if matches!(self.dialog, Dialog::ConfirmRekeyAll) {
                    self.dialog = Dialog::None;
                    vec![Command::RekeyAll]
                } else {
                    Vec::new()
                }
            }
            // включить автоприём нельзя без вопроса: сначала только диалог
            I::AutoAcceptAsk(id) => {
                if self.usable_friend(id) {
                    self.dialog = Dialog::Trust(id);
                }
                Vec::new()
            }
            I::TrustYes => {
                if let Dialog::Trust(id) = self.dialog {
                    self.dialog = Dialog::None;
                    vec![Command::EnableAutoAccept(id)]
                } else {
                    Vec::new()
                }
            }
            I::AutoAcceptOff(id) => {
                if self.friend(id).is_some_and(|f| f.auto_accept) {
                    vec![Command::DisableAutoAccept(id)]
                } else {
                    Vec::new()
                }
            }
            I::AddrTokenOpen(id) => {
                if self.usable_friend(id) {
                    self.dialog = Dialog::AddrToken(AddrTokenDialog {
                        friend: id,
                        same_network: false,
                        token: None,
                        busy: false,
                        error: None,
                    });
                }
                Vec::new()
            }
            I::AddrTokenNetwork(v) => {
                if let Dialog::AddrToken(d) = &mut self.dialog
                    && d.token.is_none()
                {
                    d.same_network = v;
                }
                Vec::new()
            }
            I::AddrTokenIssue => {
                if let Dialog::AddrToken(d) = &mut self.dialog
                    && !d.busy
                {
                    d.busy = true;
                    d.error = None;
                    return vec![Command::IssueAddrToken {
                        friend: d.friend,
                        same_network: d.same_network,
                    }];
                }
                Vec::new()
            }
            // «Друг прислал мне текст»: одно поле на любой вид текста; вид определяет узел
            I::FriendTextOpen => {
                // во время ожидания кода или самого кода приглашение не подменяется
                if matches!(self.add.stage, AddStage::Form { busy: false }) {
                    self.dialog = Dialog::FriendText(PasteDialog {
                        text: String::new(),
                        too_long: false,
                        error: None,
                        busy: false,
                    });
                }
                Vec::new()
            }
            I::FriendTextEdited(t) => {
                if let Dialog::FriendText(d) = &mut self.dialog
                    && !d.busy
                {
                    (d.text, d.too_long) = cap_paste(t);
                    d.error = None;
                }
                Vec::new()
            }
            // единственное место, где появляется `Command::ApplyFriendText`
            I::FriendTextSubmit => {
                if let Dialog::FriendText(d) = &mut self.dialog {
                    if d.busy {
                        return Vec::new();
                    }
                    if d.too_long {
                        d.error = Some(chervo_core::texts::INPUT_TOO_LONG_TEXT);
                        return Vec::new();
                    }
                    let text = d.text.trim().to_owned();
                    if text.is_empty() {
                        d.error = Some(texts::PASTE_EMPTY);
                        return Vec::new();
                    }
                    d.busy = true;
                    return vec![Command::ApplyFriendText(text)];
                }
                Vec::new()
            }
            // единственное место, где появляется `Command::OpenReceiveFolder`
            I::OpenReceiveFolder => {
                self.folder_error = None;
                vec![Command::OpenReceiveFolder]
            }
            // «Соединить»: единственное место, где появляется `Command::ConnectNow`
            I::ConnectNow(id) => {
                if self.usable_friend(id) {
                    // до итога показывается «Пробуем соединиться…»
                    if !self.connecting.contains(&id) {
                        self.connecting.push(id);
                    }
                    vec![Command::ConnectNow(id)]
                } else {
                    Vec::new()
                }
            }
            I::FriendSend(id) => {
                if self.usable_friend(id) {
                    self.send.friend = Some(id);
                    self.show_section(Section::Send);
                }
                Vec::new()
            }
            I::DialogClose => {
                self.dialog = Dialog::None;
                Vec::new()
            }
            // щелчок по системному уведомлению: вкладка «Файлы», раздел «Предложения»
            I::ShowOffers => {
                self.show_section(Section::Offers);
                Vec::new()
            }
            I::DismissNotices => {
                self.notices.clear();
                Vec::new()
            }
            I::DismissNotice(i) => {
                if i < self.notices.len() {
                    self.notices.remove(i);
                }
                Vec::new()
            }
            I::Settings(s) => self.update_settings(s),
            I::Update(u) => self.update_updates(u),
            I::Access(a) => self.update_access(a),
            other => self.update_add_send(other),
        }
    }

    fn update_add_send(&mut self, intent: MainIntent) -> Vec<Command> {
        use MainIntent as I;
        match intent {
            I::AddSameNetwork(v) => {
                self.add.same_network = v;
                Vec::new()
            }
            // «Создать приглашение»: единственное место, где появляется проба адреса у сервера
            // (`ExternalMode::Probe`); есть ли сервер и что вписывать, решает узел
            I::AddCreate => {
                if !matches!(self.add.stage, AddStage::Form { busy: false }) {
                    return Vec::new();
                }
                self.add.error = None;
                self.add.no_addresses = false;
                self.add.stage = AddStage::Form { busy: true };
                vec![Command::CreateInvite {
                    same_network: self.add.same_network,
                    external: ExternalMode::Probe,
                }]
            }
            // «Получить свой IP»: единственное место, где появляется `Command::EchoProbe`
            I::GetIp => {
                if !matches!(self.add.stage, AddStage::Form { busy: false })
                    || !self.get_ip_enabled()
                {
                    return Vec::new();
                }
                self.add.get_ip = GetIpUi::Busy;
                vec![Command::EchoProbe]
            }
            // «VPN выключен, вписать адрес»: только после явного ответа на вопрос о VPN
            I::AddVpnWithAddr => {
                let AddStage::VpnAsk { addrs } = &mut self.add.stage else {
                    return Vec::new();
                };
                let addrs = std::mem::take(addrs);
                self.add.stage = AddStage::Form { busy: true };
                vec![Command::CreateInvite {
                    same_network: self.add.same_network,
                    external: ExternalMode::Use(addrs),
                }]
            }
            I::AddVpnWithout => {
                if !matches!(self.add.stage, AddStage::VpnAsk { .. }) {
                    return Vec::new();
                }
                self.add.stage = AddStage::Form { busy: true };
                vec![Command::CreateInvite {
                    same_network: self.add.same_network,
                    external: ExternalMode::Without,
                }]
            }
            I::AddCancel => {
                match self.add.stage {
                    AddStage::Waiting { invite, .. } => {
                        self.add.stage = AddStage::Form { busy: false };
                        return vec![Command::CancelInvite(invite)];
                    }
                    // вопрос о VPN снят: приглашения не было, отменять нечего
                    AddStage::VpnAsk { .. } => {
                        self.add.stage = AddStage::Form { busy: false };
                    }
                    _ => {}
                }
                Vec::new()
            }
            I::AddDone => {
                if matches!(self.add.stage, AddStage::Finished(_)) {
                    self.add = AddFriend::default();
                }
                Vec::new()
            }
            I::SasNameEdited(t) => {
                if let AddStage::Sas(s) = &mut self.add.stage
                    && !s.busy
                {
                    s.name = cap_paste(t).0;
                    s.error = None;
                }
                Vec::new()
            }
            // только явное «Совпадает» с непустым именем подтверждает код
            I::SasMatch => {
                if let AddStage::Sas(s) = &mut self.add.stage {
                    if s.busy {
                        return Vec::new();
                    }
                    let name = s.name.trim().to_owned();
                    if name.is_empty() {
                        s.error = Some(texts::SAS_NAME_EMPTY);
                        return Vec::new();
                    }
                    s.busy = true;
                    // С3: после «Совпадает» ждём, пока друг тоже ответит
                    s.waiting = true;
                    return vec![Command::ConfirmSas {
                        invite: s.invite,
                        yes: true,
                        name,
                    }];
                }
                Vec::new()
            }
            I::SasMismatch => {
                if let AddStage::Sas(s) = &mut self.add.stage {
                    if s.busy {
                        return Vec::new();
                    }
                    s.busy = true;
                    return vec![Command::ConfirmSas {
                        invite: s.invite,
                        yes: false,
                        name: String::new(),
                    }];
                }
                Vec::new()
            }
            I::PathsAdded(list) => {
                for p in list {
                    if !self.send.paths.iter().any(|q| q.path == p.path) {
                        self.send.paths.push(p);
                    }
                }
                self.send.error = None;
                self.show_section(Section::Send);
                Vec::new()
            }
            I::PathRemoved(i) => {
                if i < self.send.paths.len() {
                    self.send.paths.remove(i);
                }
                Vec::new()
            }
            I::SendFriend(id) => {
                if self.usable_friend(id) {
                    self.send.friend = Some(id);
                }
                Vec::new()
            }
            I::SendSubmit => {
                if self.send.busy {
                    return Vec::new();
                }
                let Some(friend) = self.send.friend.filter(|f| self.usable_friend(*f)) else {
                    self.send.error = Some(texts::SEND_NO_FRIEND);
                    return Vec::new();
                };
                if self.send.paths.is_empty() {
                    self.send.error = Some(texts::SEND_NO_FILES);
                    return Vec::new();
                }
                self.send.error = None;
                self.send.busy = true;
                vec![Command::Send {
                    friend,
                    paths: self.send.paths.iter().map(|p| p.path.clone()).collect(),
                }]
            }
            other => self.update_offers(other),
        }
    }

    fn update_offers(&mut self, intent: MainIntent) -> Vec<Command> {
        use MainIntent as I;
        match intent {
            I::OfferAck(id, v) => {
                self.offer_ui.entry(id).or_default().ack = v;
                Vec::new()
            }
            I::OfferAccept(id) => {
                let Some(row) = self.snapshot.offers.iter().find(|o| o.id == id) else {
                    return Vec::new();
                };
                let ui = self.offer_ui.entry(id).or_default();
                // рискованные файлы: только после отметки; нехватка места: только «другая папка»
                if ui.busy || (row.needs_question && !ui.ack) || row.space.short {
                    return Vec::new();
                }
                ui.busy = true;
                vec![Command::Accept(id)]
            }
            I::OfferAcceptInto { id, root } => {
                let Some(row) = self.snapshot.offers.iter().find(|o| o.id == id) else {
                    return Vec::new();
                };
                let ui = self.offer_ui.entry(id).or_default();
                if ui.busy || (row.needs_question && !ui.ack) {
                    return Vec::new();
                }
                ui.busy = true;
                vec![Command::AcceptInto { transfer: id, root }]
            }
            I::OfferDecline(id) => {
                if !self.snapshot.offers.iter().any(|o| o.id == id) {
                    return Vec::new();
                }
                let ui = self.offer_ui.entry(id).or_default();
                if ui.busy {
                    return Vec::new();
                }
                ui.busy = true;
                vec![Command::Decline(id)]
            }
            I::TransferCancel(id) => {
                if self.snapshot.transfers.iter().any(|t| t.id == id) {
                    vec![Command::CancelTransfer(id)]
                } else {
                    Vec::new()
                }
            }
            // убрать из списка можно только завершённую (с итогом); идущая остаётся
            I::TransferForget(id) => {
                let finished = self
                    .snapshot
                    .transfers
                    .iter()
                    .any(|t| t.id == id && t.result.is_some());
                if finished {
                    vec![Command::ForgetTransfer(id)]
                } else {
                    Vec::new()
                }
            }
            I::TransferForgetFinished => {
                if self.snapshot.transfers.iter().any(|t| t.result.is_some()) {
                    vec![Command::ForgetFinished]
                } else {
                    Vec::new()
                }
            }
            I::TransferRetry(id) => {
                let paused = self.snapshot.transfers.iter().any(|t| {
                    t.id == id && matches!(t.state, chervo_core::TransferState::Paused(_))
                });
                if paused {
                    vec![Command::Retry(id)]
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
        }
    }

    fn clear_busy(&mut self) {
        for ui in self.offer_ui.values_mut() {
            ui.busy = false;
        }
        self.send.busy = false;
    }

    /// Ответы фонового потока на команды главного окна.
    pub fn outcome_main(&mut self, outcome: Outcome) {
        match outcome {
            Outcome::InviteCreated(Ok((invite, token, ext))) => {
                let qr = qr::encode(&token);
                let ttl = self
                    .snapshot
                    .settings
                    .as_ref()
                    .map_or(900, |s| s.invite_ttl_secs);
                self.add.stage = AddStage::Waiting {
                    invite,
                    token: Some(token),
                    qr,
                    valid: Some((Instant::now(), ttl)),
                    ext,
                    addr_changed: false,
                };
            }
            Outcome::InviteCreated(Err(e)) => {
                self.add.stage = AddStage::Form { busy: false };
                let text = e.user_text();
                self.add.error = Some(text);
                // В4: «нет адреса» отправляет к помощнику «Разрешить входящие подключения»
                self.add.no_addresses = text == chervo_core::texts::NO_ADDRESS_TEXT;
            }
            Outcome::InviteVpnAsk(addrs) => {
                if matches!(self.add.stage, AddStage::Form { busy: true }) {
                    self.add.stage = AddStage::VpnAsk { addrs };
                }
            }
            Outcome::GetIp(r) => self.add.get_ip = GetIpUi::Result(r),
            Outcome::InviteAddrChanged(id) => {
                if let AddStage::Waiting {
                    invite,
                    addr_changed,
                    ..
                } = &mut self.add.stage
                    && *invite == id
                {
                    *addr_changed = true;
                }
            }
            // текст от друга: ошибка остаётся в окне вставки, остальное по виду текста
            Outcome::FriendText(Err(e)) => {
                if let Dialog::FriendText(d) = &mut self.dialog {
                    d.busy = false;
                    d.error = Some(e.user_text());
                } else {
                    self.push_notice(e.user_text());
                }
            }
            Outcome::FriendText(Ok(done)) => {
                self.dialog = Dialog::None;
                match done {
                    FriendTextOutcome::InviteAccepted(invite) => {
                        // к сверке кода: она показывается на «Добавить друга»
                        self.show_section(Section::AddFriend);
                        // могла прийти раньше проверочного кода: не затираем его
                        if !matches!(self.add.stage, AddStage::Sas(_)) {
                            self.add.stage = AddStage::Waiting {
                                invite,
                                token: None,
                                qr: None,
                                valid: None,
                                ext: InviteExt::Plain,
                                addr_changed: false,
                            };
                        }
                    }
                    FriendTextOutcome::AddressUpdated => self.push_notice(texts::ADDR_APPLIED),
                    FriendTextOutcome::Revoked { applied: true } => {
                        self.push_notice(texts::REVOKED_APPLIED);
                    }
                    FriendTextOutcome::Revoked { applied: false } => {
                        self.push_notice(texts::REVOKED_NOBODY);
                    }
                }
            }
            Outcome::FolderOpened(r) => {
                self.folder_error = match r {
                    Ok(()) => None,
                    Err(chervo_core::NodeError::ReceiveRoot(_)) => Some(texts::OPEN_FOLDER_MISSING),
                    Err(_) => Some(texts::OPEN_FOLDER_FAILED),
                };
            }
            Outcome::InviteSas {
                invite,
                digits,
                spoken,
            } => {
                self.add.stage = AddStage::Sas(SasState {
                    invite,
                    digits,
                    spoken,
                    name: String::new(),
                    error: None,
                    busy: false,
                    waiting: false,
                });
                // поле «Друг прислал мне текст» не должно остаться открытым за сверкой кода
                if matches!(self.dialog, Dialog::FriendText(_)) {
                    self.dialog = Dialog::None;
                }
                self.show_section(Section::AddFriend);
                self.attention = true;
            }
            Outcome::SasAnswered(Err(e)) => {
                if let AddStage::Sas(s) = &mut self.add.stage {
                    s.busy = false;
                    s.waiting = false;
                    s.error = Some(e.user_text());
                }
            }
            Outcome::SasAnswered(Ok(())) => {}
            Outcome::InviteFinished(outcome) => {
                if !matches!(self.add.stage, AddStage::Form { .. }) {
                    self.add.stage = AddStage::Finished(invite_text(outcome));
                }
            }
            Outcome::Revocation {
                friend,
                text,
                rekey,
            } => match text {
                Ok(Some(t)) => {
                    self.dialog = Dialog::Revocation(RevocationDialog {
                        items: vec![(friend, t)],
                        rekey,
                        failed: 0,
                    });
                }
                Ok(None) => self.push_notice(texts::NO_REVOCATION_NEEDED),
                Err(e) => self.push_notice(e.user_text()),
            },
            Outcome::RekeyAll { items, failed } => {
                if items.is_empty() && failed == 0 {
                    self.push_notice(texts::NO_REVOCATION_NEEDED);
                } else {
                    self.dialog = Dialog::Revocation(RevocationDialog {
                        items,
                        rekey: true,
                        failed,
                    });
                }
            }
            Outcome::AddrToken(r) => {
                if let Dialog::AddrToken(d) = &mut self.dialog {
                    d.busy = false;
                    match r {
                        Ok(t) => d.token = Some(t),
                        Err(e) => d.error = Some(e.user_text()),
                    }
                }
            }
            Outcome::Sent(r) => {
                self.send.busy = false;
                match r {
                    Ok(()) => {
                        self.send.paths.clear();
                        self.send.error = None;
                        self.show_section(Section::Transfers);
                    }
                    Err(e) => self.send.error = Some(e.user_text()),
                }
            }
            Outcome::OfferIncoming(note) => {
                self.attention = true;
                if let Some(n) = note {
                    self.toast_incoming(&n);
                }
            }
            Outcome::AutoAccepted(note) => {
                self.push_notice(texts::AUTO_ACCEPTED);
                if let Some(n) = note {
                    self.auto_pending.insert(n.transfer, n.friend);
                }
            }
            Outcome::TransferCompleted(id) => {
                if let Some(friend) = self.auto_pending.remove(&id) {
                    self.push_toast(crate::notify::auto_text(&friend));
                }
            }
            Outcome::Done(Err(e)) => {
                self.clear_busy();
                self.connecting.clear();
                self.push_notice(e.user_text());
            }
            other => self.outcome_settings(other),
        }
    }

    /// Номера предложений для вкладки «Входящие».
    pub fn offers_waiting(&self) -> usize {
        self.snapshot.offers.len()
    }
}

fn invite_text(o: InviteOutcome) -> &'static str {
    match o {
        InviteOutcome::Added => texts::INVITE_ADDED,
        InviteOutcome::Declined => texts::INVITE_DECLINED,
        InviteOutcome::PeerUnreachable => chervo_core::texts::PEER_UNREACHABLE_INVITE_TEXT,
        InviteOutcome::Expired => texts::INVITE_EXPIRED,
        _ => texts::INVITE_FAILED,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Intent, Page, Snapshot};
    use crate::rows::{FileRow, FriendRow, OfferRow, TransferRow};
    use chervo_core::{FileKind, PauseReason, Side, SpaceView, TransferState};

    fn model() -> Model {
        let (mut m, _) = Model::start();
        m.on_outcome(Outcome::Opened { port_saved: true });
        m
    }

    fn friend(id: u32, status: FriendStatus, online: bool) -> FriendRow {
        FriendRow {
            id: Id(id),
            name: format!("друг{id}"),
            status,
            online,
            auto_accept: false,
            key_problem: false,
            path: None,
        }
    }

    fn offer(id: u32, needs_question: bool, short: bool) -> OfferRow {
        OfferRow {
            id: Id(id),
            friend: "друг1".to_owned(),
            files: vec![FileRow {
                name: "a.exe".to_owned(),
                size: 10,
                kind: if needs_question {
                    FileKind::ExecutableLike
                } else {
                    FileKind::Safe
                },
                needs_question,
            }],
            total: 10,
            space: SpaceView {
                needed: 10,
                available: Some(if short { 1 } else { 1000 }),
                short,
            },
            needs_question,
            warnings: Vec::new(),
        }
    }

    fn with_snapshot(m: &mut Model, f: impl FnOnce(&mut Snapshot)) {
        let mut s = Snapshot::default();
        f(&mut s);
        m.on_outcome(Outcome::Snapshot(Box::new(s)));
    }

    fn ask(m: &mut Model, i: MainIntent) -> Vec<Command> {
        m.update(Intent::Main(i))
    }

    #[test]
    fn sas_requires_explicit_answer() {
        let mut m = model();
        // код пришёл: сам по себе ничего не подтверждает и никакой команды нет
        assert!(
            m.on_outcome(Outcome::InviteSas {
                invite: Id(7),
                digits: "1234 5678".to_owned(),
                spoken: "1 2 3 4 5 6 7 8".to_owned(),
            })
            .is_empty()
        );
        assert_eq!(m.page, Page::Friends);
        assert_eq!(m.scroll_to, Some(Section::AddFriend));
        assert!(m.take_attention());
        // «Совпадает» без имени не подтверждает
        assert!(ask(&mut m, MainIntent::SasMatch).is_empty());
        ask(&mut m, MainIntent::SasNameEdited("   ".to_owned()));
        assert!(ask(&mut m, MainIntent::SasMatch).is_empty());
        // с именем: подтверждение, ровно один раз
        ask(&mut m, MainIntent::SasNameEdited("Маша".to_owned()));
        assert_eq!(
            ask(&mut m, MainIntent::SasMatch),
            vec![Command::ConfirmSas {
                invite: Id(7),
                yes: true,
                name: "Маша".to_owned()
            }]
        );
        assert!(ask(&mut m, MainIntent::SasMatch).is_empty());
        assert!(ask(&mut m, MainIntent::SasMismatch).is_empty());
    }

    #[test]
    fn sas_mismatch_declines_without_name() {
        let mut m = model();
        m.on_outcome(Outcome::InviteSas {
            invite: Id(1),
            digits: "1111 2222".to_owned(),
            spoken: String::new(),
        });
        assert_eq!(
            ask(&mut m, MainIntent::SasMismatch),
            vec![Command::ConfirmSas {
                invite: Id(1),
                yes: false,
                name: String::new()
            }]
        );
        m.on_outcome(Outcome::InviteFinished(InviteOutcome::Declined));
        assert!(matches!(m.add.stage, AddStage::Finished(_)));
    }

    #[test]
    fn offer_with_executable_requires_choice() {
        let mut m = model();
        with_snapshot(&mut m, |s| s.offers.push(offer(5, true, false)));
        // без отметки принять нельзя; отклонить можно
        assert!(ask(&mut m, MainIntent::OfferAccept(Id(5))).is_empty());
        assert!(
            ask(
                &mut m,
                MainIntent::OfferAcceptInto {
                    id: Id(5),
                    root: PathBuf::from("D:/x")
                }
            )
            .is_empty()
        );
        ask(&mut m, MainIntent::OfferAck(Id(5), true));
        assert_eq!(
            ask(&mut m, MainIntent::OfferAccept(Id(5))),
            vec![Command::Accept(Id(5))]
        );
        // второй раз, пока ответ не пришёл, нельзя
        assert!(ask(&mut m, MainIntent::OfferAccept(Id(5))).is_empty());
    }

    #[test]
    fn safe_offer_needs_no_ack_and_short_space_needs_other_folder() {
        let mut m = model();
        with_snapshot(&mut m, |s| {
            s.offers.push(offer(1, false, false));
            s.offers.push(offer(2, false, true));
        });
        assert_eq!(
            ask(&mut m, MainIntent::OfferAccept(Id(1))),
            vec![Command::Accept(Id(1))]
        );
        // не хватает места: в основную папку нельзя, в другую можно
        assert!(ask(&mut m, MainIntent::OfferAccept(Id(2))).is_empty());
        assert_eq!(
            ask(
                &mut m,
                MainIntent::OfferAcceptInto {
                    id: Id(2),
                    root: PathBuf::from("E:/big")
                }
            ),
            vec![Command::AcceptInto {
                transfer: Id(2),
                root: PathBuf::from("E:/big")
            }]
        );
    }

    #[test]
    fn decline_works_without_ack() {
        let mut m = model();
        with_snapshot(&mut m, |s| s.offers.push(offer(5, true, false)));
        assert_eq!(
            ask(&mut m, MainIntent::OfferDecline(Id(5))),
            vec![Command::Decline(Id(5))]
        );
    }

    fn friend_text_dialog(m: &Model) -> &PasteDialog {
        match &m.dialog {
            Dialog::FriendText(d) => d,
            _ => panic!("диалог «Друг прислал мне текст» не открыт"),
        }
    }

    #[test]
    fn friend_text_over_4096_rejected() {
        let mut m = model();
        ask(&mut m, MainIntent::FriendTextOpen);
        ask(&mut m, MainIntent::FriendTextEdited("x".repeat(5000)));
        assert!(
            friend_text_dialog(&m).text.len() <= MAX_PASTE,
            "текст в модели обрезан"
        );
        assert!(ask(&mut m, MainIntent::FriendTextSubmit).is_empty());
        assert_eq!(
            friend_text_dialog(&m).error,
            Some(chervo_core::texts::INPUT_TOO_LONG_TEXT)
        );
        // многобайтные символы считаются байтами: 2049 * 2 = 4098
        ask(&mut m, MainIntent::FriendTextEdited("ж".repeat(2049)));
        assert!(ask(&mut m, MainIntent::FriendTextSubmit).is_empty());
        // ровно 4096 байт проходит к узлу (там предел и разбор)
        ask(&mut m, MainIntent::FriendTextEdited("x".repeat(4096)));
        let cmds = ask(&mut m, MainIntent::FriendTextSubmit);
        assert!(matches!(cmds.as_slice(), [Command::ApplyFriendText(t)] if t.len() == 4096));
    }

    #[test]
    fn friend_text_goes_to_one_command_for_every_kind() {
        let mut m = model();
        ask(&mut m, MainIntent::FriendTextOpen);
        // пусто: ошибка в самом окне, команды нет
        assert!(ask(&mut m, MainIntent::FriendTextSubmit).is_empty());
        assert_eq!(friend_text_dialog(&m).error, Some(texts::PASTE_EMPTY));
        // любой вид текста уходит одной командой, пробелы по краям обрезаны; вид решает узел
        for kind in ["CHV1AAAA", "CHA1BBBB", "CHR1CCCC", "мусор"] {
            let mut m = model();
            ask(&mut m, MainIntent::FriendTextOpen);
            ask(&mut m, MainIntent::FriendTextEdited(format!("  {kind}\n ")));
            assert_eq!(
                ask(&mut m, MainIntent::FriendTextSubmit),
                vec![Command::ApplyFriendText(kind.to_owned())]
            );
            // пока ждём ответ, второй команды нет
            assert!(ask(&mut m, MainIntent::FriendTextSubmit).is_empty());
        }
    }

    #[test]
    fn friend_text_outcomes_route_by_kind() {
        use crate::model::FriendTextOutcome as F;
        // приглашение: ждём сверку кода на «Добавить друга», диалог закрыт
        let mut m = model();
        ask(&mut m, MainIntent::FriendTextOpen);
        ask(&mut m, MainIntent::FriendTextEdited("x".to_owned()));
        ask(&mut m, MainIntent::FriendTextSubmit);
        m.on_outcome(Outcome::FriendText(Ok(F::InviteAccepted(Id(4)))));
        assert!(matches!(m.dialog, Dialog::None));
        assert_eq!(m.page, Page::Friends);
        assert_eq!(m.scroll_to, Some(Section::AddFriend));
        assert!(matches!(
            m.add.stage,
            AddStage::Waiting {
                invite: Id(4),
                token: None,
                ..
            }
        ));
        // новый адрес и уведомление об удалении: только сообщение, на странице остаёмся
        for (o, want) in [
            (F::AddressUpdated, texts::ADDR_APPLIED),
            (F::Revoked { applied: true }, texts::REVOKED_APPLIED),
            (F::Revoked { applied: false }, texts::REVOKED_NOBODY),
        ] {
            let mut m = model();
            ask(&mut m, MainIntent::FriendTextOpen);
            ask(&mut m, MainIntent::FriendTextEdited("x".to_owned()));
            ask(&mut m, MainIntent::FriendTextSubmit);
            m.on_outcome(Outcome::FriendText(Ok(o)));
            assert!(matches!(m.dialog, Dialog::None));
            assert_eq!(m.page, Page::Friends);
            assert_eq!(m.notice_texts(), vec![want.to_owned()]);
        }
        // ошибка остаётся в окне вставки, текст ошибки не повторяет вставленное
        let mut m = model();
        ask(&mut m, MainIntent::FriendTextOpen);
        ask(
            &mut m,
            MainIntent::FriendTextEdited("СЕКРЕТ-ТЕКСТ".to_owned()),
        );
        ask(&mut m, MainIntent::FriendTextSubmit);
        m.on_outcome(Outcome::FriendText(Err(
            chervo_core::NodeError::InputTooLong,
        )));
        let d = friend_text_dialog(&m);
        assert!(!d.busy);
        assert_eq!(d.error, Some(chervo_core::texts::INPUT_TOO_LONG_TEXT));
        assert!(!d.error.unwrap_or_default().contains("СЕКРЕТ"));
        assert!(m.notices.is_empty());
    }

    #[test]
    fn friend_text_dialog_is_one_for_friends_and_add_friend() {
        // кнопка одна и та же на обеих вкладках: одно намерение, один диалог
        let mut m = model();
        m.update(Intent::GoSection(Section::AddFriend));
        ask(&mut m, MainIntent::FriendTextOpen);
        assert!(matches!(m.dialog, Dialog::FriendText(_)));
        ask(&mut m, MainIntent::DialogClose);
        m.update(Intent::Go(Page::Friends));
        ask(&mut m, MainIntent::FriendTextOpen);
        assert!(matches!(m.dialog, Dialog::FriendText(_)));
        // во время сверки кода приглашение не подменяется
        let mut m = model();
        m.on_outcome(Outcome::InviteSas {
            invite: Id(1),
            digits: "1234 5678".to_owned(),
            spoken: String::new(),
        });
        ask(&mut m, MainIntent::FriendTextOpen);
        assert!(matches!(m.dialog, Dialog::None));
    }

    #[test]
    fn sas_waiting_text_after_match() {
        let mut m = model();
        m.on_outcome(Outcome::InviteSas {
            invite: Id(7),
            digits: "1234 5678".to_owned(),
            spoken: String::new(),
        });
        ask(&mut m, MainIntent::SasNameEdited("Маша".to_owned()));
        ask(&mut m, MainIntent::SasMatch);
        let AddStage::Sas(s) = &m.add.stage else {
            panic!("сверка кода");
        };
        assert!(s.busy && s.waiting);
        // ошибка снимает ожидание
        m.on_outcome(Outcome::SasAnswered(Err(chervo_core::NodeError::Io)));
        let AddStage::Sas(s) = &m.add.stage else {
            panic!("сверка кода");
        };
        assert!(!s.busy && !s.waiting);
    }

    #[test]
    fn connect_shows_progress_until_online_or_failure() {
        let mut m = model();
        with_snapshot(&mut m, |s| {
            s.friends.push(friend(1, FriendStatus::Active, false));
        });
        assert_eq!(
            ask(&mut m, MainIntent::ConnectNow(Id(1))),
            vec![Command::ConnectNow(Id(1))]
        );
        assert_eq!(m.connecting, vec![Id(1)]);
        // всё ещё не в сети: подпись остаётся
        with_snapshot(&mut m, |s| {
            s.friends.push(friend(1, FriendStatus::Active, false));
        });
        assert_eq!(m.connecting, vec![Id(1)]);
        // стал «в сети»: подпись гаснет
        with_snapshot(&mut m, |s| {
            s.friends.push(friend(1, FriendStatus::Active, true));
        });
        assert!(m.connecting.is_empty());
        // ошибка действия тоже гасит
        with_snapshot(&mut m, |s| {
            s.friends.push(friend(1, FriendStatus::Active, false));
        });
        ask(&mut m, MainIntent::ConnectNow(Id(1)));
        m.on_outcome(Outcome::Done(Err(chervo_core::NodeError::Io)));
        assert!(m.connecting.is_empty());
    }

    #[test]
    fn open_folder_command_only_from_its_intent_and_error_is_local() {
        let mut m = model();
        assert_eq!(
            ask(&mut m, MainIntent::OpenReceiveFolder),
            vec![Command::OpenReceiveFolder]
        );
        // не каталог: текст рядом с кнопкой, а не общее уведомление
        m.on_outcome(Outcome::FolderOpened(Err(
            chervo_core::NodeError::ReceiveRoot(chervo_core::RootError::NotDir),
        )));
        assert_eq!(m.folder_error, Some(texts::OPEN_FOLDER_MISSING));
        m.on_outcome(Outcome::FolderOpened(Err(chervo_core::NodeError::Io)));
        assert_eq!(m.folder_error, Some(texts::OPEN_FOLDER_FAILED));
        assert!(m.notices.is_empty());
        // новая попытка стирает прежнюю ошибку; успех её не возвращает
        ask(&mut m, MainIntent::OpenReceiveFolder);
        assert_eq!(m.folder_error, None);
        m.on_outcome(Outcome::FolderOpened(Ok(())));
        assert_eq!(m.folder_error, None);
    }

    #[test]
    fn auto_accept_needs_trust_answer() {
        let mut m = model();
        with_snapshot(&mut m, |s| {
            s.friends.push(friend(1, FriendStatus::Active, true))
        });
        // просьба включить только открывает вопрос
        assert!(ask(&mut m, MainIntent::AutoAcceptAsk(Id(1))).is_empty());
        assert!(matches!(m.dialog, Dialog::Trust(Id(1))));
        // закрыли вопрос: «да» уже ничего не включает
        ask(&mut m, MainIntent::DialogClose);
        assert!(ask(&mut m, MainIntent::TrustYes).is_empty());
        ask(&mut m, MainIntent::AutoAcceptAsk(Id(1)));
        assert_eq!(
            ask(&mut m, MainIntent::TrustYes),
            vec![Command::EnableAutoAccept(Id(1))]
        );
    }

    #[test]
    fn connect_now_only_for_usable_friend() {
        let mut m = model();
        with_snapshot(&mut m, |s| {
            s.friends.push(friend(1, FriendStatus::Active, false));
            s.friends.push(friend(2, FriendStatus::Blocked, false));
        });
        assert_eq!(
            ask(&mut m, MainIntent::ConnectNow(Id(1))),
            vec![Command::ConnectNow(Id(1))]
        );
        assert!(ask(&mut m, MainIntent::ConnectNow(Id(2))).is_empty());
        assert!(ask(&mut m, MainIntent::ConnectNow(Id(9))).is_empty());
    }

    #[test]
    fn remove_and_rekey_ask_first_then_show_revocation() {
        let mut m = model();
        with_snapshot(&mut m, |s| {
            s.friends.push(friend(1, FriendStatus::Active, true))
        });
        assert!(ask(&mut m, MainIntent::RemoveAsk(Id(1))).is_empty());
        assert_eq!(
            ask(&mut m, MainIntent::RemoveConfirm),
            vec![Command::Remove(Id(1))]
        );
        m.on_outcome(Outcome::Revocation {
            friend: "друг1".to_owned(),
            text: Ok(Some("REVOKE".to_owned())),
            rekey: false,
        });
        let Dialog::Revocation(d) = &m.dialog else {
            panic!("диалог с текстом отзыва");
        };
        assert_eq!(d.items, vec![("друг1".to_owned(), "REVOKE".to_owned())]);
        // подтверждения нет: сама по себе команда не уходит
        assert!(ask(&mut m, MainIntent::RemoveConfirm).is_empty());
        assert!(ask(&mut m, MainIntent::RekeyAllConfirm).is_empty());
    }

    #[test]
    fn create_invite_goes_through_probe_once() {
        let mut m = model();
        ask(&mut m, MainIntent::AddSameNetwork(true));
        let cmds = ask(&mut m, MainIntent::AddCreate);
        assert_eq!(
            cmds,
            vec![Command::CreateInvite {
                same_network: true,
                external: ExternalMode::Probe
            }]
        );
        // пока создаётся, повторное нажатие ничего не делает
        assert!(ask(&mut m, MainIntent::AddCreate).is_empty());
    }

    #[test]
    fn send_needs_friend_and_files() {
        let mut m = model();
        with_snapshot(&mut m, |s| {
            s.friends.push(friend(1, FriendStatus::Active, true))
        });
        assert!(ask(&mut m, MainIntent::SendSubmit).is_empty());
        ask(&mut m, MainIntent::SendFriend(Id(1)));
        assert!(ask(&mut m, MainIntent::SendSubmit).is_empty());
        ask(
            &mut m,
            MainIntent::PathsAdded(vec![PickedPath {
                path: PathBuf::from("D:/a.txt"),
                is_dir: false,
                size: 3,
            }]),
        );
        let cmds = ask(&mut m, MainIntent::SendSubmit);
        assert_eq!(
            cmds,
            vec![Command::Send {
                friend: Id(1),
                paths: vec![PathBuf::from("D:/a.txt")]
            }]
        );
        m.on_outcome(Outcome::Sent(Ok(())));
        assert_eq!(m.page, Page::Files);
        assert_eq!(m.scroll_to, Some(Section::Transfers));
        assert!(m.send.paths.is_empty());
    }

    #[test]
    fn retry_only_for_paused_transfer() {
        let mut m = model();
        let row = |id, state| TransferRow {
            id: Id(id),
            friend: "друг".to_owned(),
            side: Side::Receiver,
            state,
            done: 1,
            total: 2,
            pause: None,
            preparing: None,
            result: None,
            dest_root: None,
        };
        with_snapshot(&mut m, |s| {
            s.transfers
                .push(row(1, TransferState::Paused(PauseReason::Stalled)));
            s.transfers.push(row(2, TransferState::Active));
        });
        assert_eq!(
            ask(&mut m, MainIntent::TransferRetry(Id(1))),
            vec![Command::Retry(Id(1))]
        );
        assert!(ask(&mut m, MainIntent::TransferRetry(Id(2))).is_empty());
    }

    #[test]
    fn debug_output_does_not_contain_tokens_names_or_paths() {
        let secret = "СЕКРЕТНЫЙ-ТОКЕН-12345";
        let cmds = [
            Command::ApplyFriendText(secret.to_owned()),
            Command::Rename {
                friend: Id(1),
                name: secret.to_owned(),
            },
            Command::ConfirmSas {
                invite: Id(1),
                yes: true,
                name: secret.to_owned(),
            },
            Command::Send {
                friend: Id(1),
                paths: vec![PathBuf::from(secret)],
            },
            Command::SetReceiveRoot {
                root: PathBuf::from(secret),
                confirm_shared: false,
            },
        ];
        for c in &cmds {
            assert!(!format!("{c:?}").contains(secret), "{c:?}");
            assert!(!format!("{c:#?}").contains(secret));
        }
        let intents = [
            Intent::Main(MainIntent::FriendTextEdited(secret.to_owned())),
            Intent::Main(MainIntent::SasNameEdited(secret.to_owned())),
            Intent::Main(MainIntent::PathsAdded(vec![PickedPath {
                path: PathBuf::from(secret),
                is_dir: false,
                size: 1,
            }])),
            Intent::FolderEdited(secret.to_owned()),
            Intent::Main(MainIntent::Settings(SettingsIntent::RootEdited(
                secret.to_owned(),
            ))),
        ];
        for i in &intents {
            assert!(!format!("{i:?}").contains(secret), "{i:?}");
        }
        // форма первого запуска тоже не печатает путь
        let (mut m, _) = Model::start();
        m.on_outcome(Outcome::OpenFailed(chervo_core::NodeError::FirstRun));
        m.update(Intent::FolderEdited(secret.to_owned()));
        assert!(!format!("{:?}", m.start).contains(secret));
    }

    #[test]
    fn main_intents_ignored_until_node_open() {
        let (mut m, _) = Model::start();
        assert!(
            m.update(Intent::Main(MainIntent::FriendTextOpen))
                .is_empty()
        );
        assert!(matches!(m.dialog, Dialog::None));
    }

    fn finished_row(id: u32, result: Option<chervo_core::TransferResult>) -> TransferRow {
        TransferRow {
            id: Id(id),
            friend: "друг".to_owned(),
            side: Side::Receiver,
            state: TransferState::Finished,
            done: 1,
            total: 1,
            pause: None,
            preparing: None,
            result,
            dest_root: None,
        }
    }

    /// Этап 18д, п.2: уведомление о недоступном друге гаснет, когда друг на связи; чужие и общие
    /// строки остаются.
    #[test]
    fn friend_notice_clears_when_friend_comes_online() {
        use crate::model::FriendEventKind;
        let mut m = model();
        with_snapshot(&mut m, |s| {
            s.friends.push(friend(1, FriendStatus::Active, false));
            s.friends.push(friend(2, FriendStatus::Active, false));
        });
        m.push_notice("общая строка");
        for f in [Id(1), Id(2)] {
            m.on_outcome(Outcome::FriendEvent {
                friend: f,
                name: format!("друг{}", f.0),
                kind: FriendEventKind::Unreachable {
                    text: "не отвечает",
                    lan_hint: true,
                },
            });
        }
        // две строки на друга и общая
        assert_eq!(m.notices.len(), 5);
        // оба ещё не в сети: снимок ничего не убирает
        with_snapshot(&mut m, |s| {
            s.friends.push(friend(1, FriendStatus::Active, false));
            s.friends.push(friend(2, FriendStatus::Active, false));
        });
        assert_eq!(m.notices.len(), 5);
        // друг 1 на связи: его две строки ушли, друг 2 и общая остались
        with_snapshot(&mut m, |s| {
            s.friends.push(friend(1, FriendStatus::Active, true));
            s.friends.push(friend(2, FriendStatus::Active, false));
        });
        assert_eq!(m.notices.len(), 3);
        assert!(m.notices.iter().all(|n| n.friend != Some(Id(1))));
        assert!(m.notice_texts().contains(&"общая строка".to_owned()));
    }

    /// Этап 18д, п.2: «×» убирает одну строку, «Скрыть все» все.
    #[test]
    fn notice_cross_removes_one_and_hide_all_removes_all() {
        let mut m = model();
        m.push_notice("раз");
        m.push_notice("два");
        m.push_notice("три");
        assert!(ask(&mut m, MainIntent::DismissNotice(1)).is_empty());
        assert_eq!(m.notice_texts(), vec!["раз".to_owned(), "три".to_owned()]);
        // номер за пределами списка ничего не ломает
        ask(&mut m, MainIntent::DismissNotice(9));
        assert_eq!(m.notices.len(), 2);
        ask(&mut m, MainIntent::DismissNotices);
        assert!(m.notices.is_empty());
    }

    /// Этап 18д, п.1/п.2: «Папка приёма изменена.» без слов о перезапуске и гаснет при следующем
    /// действии в настройках.
    #[test]
    fn root_changed_notice_is_short_and_goes_away_on_next_settings_action() {
        let mut m = model();
        m.on_outcome(Outcome::RootSet(Ok(())));
        assert_eq!(m.notice_texts(), vec!["Папка приёма изменена.".to_owned()]);
        ask(
            &mut m,
            MainIntent::Settings(SettingsIntent::RootEdited("x".to_owned())),
        );
        assert!(m.notices.is_empty());
    }

    /// Этап 18д, п.6: убрать можно только завершённую; общая очистка есть, только если есть что
    /// очищать.
    #[test]
    fn forget_is_offered_only_for_finished_transfers() {
        let mut m = model();
        with_snapshot(&mut m, |s| {
            s.transfers.push(finished_row(1, None));
            s.transfers.push(finished_row(
                2,
                Some(chervo_core::TransferResult::Completed),
            ));
        });
        assert!(ask(&mut m, MainIntent::TransferForget(Id(1))).is_empty());
        assert_eq!(
            ask(&mut m, MainIntent::TransferForget(Id(2))),
            vec![Command::ForgetTransfer(Id(2))]
        );
        assert!(ask(&mut m, MainIntent::TransferForget(Id(9))).is_empty());
        assert_eq!(
            ask(&mut m, MainIntent::TransferForgetFinished),
            vec![Command::ForgetFinished]
        );
        with_snapshot(&mut m, |s| s.transfers.push(finished_row(1, None)));
        assert!(ask(&mut m, MainIntent::TransferForgetFinished).is_empty());
    }
}
