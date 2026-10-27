//! Состояния главного окна: друзья (экран 2), добавление друга и проверочный код (экран 3),
//! отправка (4), входящие предложения (5), передачи (6). Чистые данные и правила, без окна и
//! узла. Опасные шаги выдаются командой только после явного ответа пользователя:
//! автоприём только после вопроса о доверии, «принять» предложение с рискованными файлами
//! только после отметки, проверочный код только после «Совпадает» и непустого имени.

use std::net::SocketAddr;
use std::path::PathBuf;

use chervo_core::{FriendStatus, InviteOutcome};

use crate::model::{Command, Model, Outcome, Page};
use crate::qr::{self, QrMatrix};
use crate::rows::{Id, PickedPath};
use crate::texts;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Invite,
    Accept,
}

/// Намерения главного окна.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    PasteTokenOpen,
    PasteTokenEdited(String),
    PasteTokenSubmit,
    ConnectNow(Id),
    FriendSend(Id),
    DialogClose,
    DismissNotices,
    // добавление друга
    AddTab(Tab),
    AddSameNetwork(bool),
    AddManualEdited(String),
    AddCreate,
    AddPasteEdited(String),
    AddAcceptSubmit,
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
    OfferAcceptInto { id: Id, root: PathBuf },
    OfferDecline(Id),
    // передачи
    TransferCancel(Id),
    TransferRetry(Id),
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
    PasteToken(PasteDialog),
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
    },
    Sas(SasState),
    Finished(&'static str),
}

pub struct AddFriend {
    pub tab: Tab,
    pub same_network: bool,
    pub manual_addr: String,
    pub paste: String,
    pub paste_too_long: bool,
    pub error: Option<&'static str>,
    pub stage: AddStage,
}

impl Default for AddFriend {
    fn default() -> Self {
        Self {
            tab: Tab::Invite,
            same_network: false,
            manual_addr: String::new(),
            paste: String::new(),
            paste_too_long: false,
            error: None,
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

impl Model {
    pub fn push_notice(&mut self, text: &'static str) {
        if self.notices.last() == Some(&text) {
            return;
        }
        if self.notices.len() >= MAX_NOTICES {
            self.notices.remove(0);
        }
        self.notices.push(text);
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
            I::PasteTokenOpen => {
                self.dialog = Dialog::PasteToken(PasteDialog {
                    text: String::new(),
                    too_long: false,
                    error: None,
                    busy: false,
                });
                Vec::new()
            }
            I::PasteTokenEdited(t) => {
                if let Dialog::PasteToken(d) = &mut self.dialog
                    && !d.busy
                {
                    (d.text, d.too_long) = cap_paste(t);
                    d.error = None;
                }
                Vec::new()
            }
            I::PasteTokenSubmit => {
                if let Dialog::PasteToken(d) = &mut self.dialog {
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
                    return vec![Command::ApplyAddrToken(text)];
                }
                Vec::new()
            }
            // «Соединить»: единственное место, где появляется `Command::ConnectNow`
            I::ConnectNow(id) => {
                if self.usable_friend(id) {
                    vec![Command::ConnectNow(id)]
                } else {
                    Vec::new()
                }
            }
            I::FriendSend(id) => {
                if self.usable_friend(id) {
                    self.send.friend = Some(id);
                    self.page = Page::Send;
                }
                Vec::new()
            }
            I::DialogClose => {
                self.dialog = Dialog::None;
                Vec::new()
            }
            I::DismissNotices => {
                self.notices.clear();
                Vec::new()
            }
            other => self.update_add_send(other),
        }
    }

    fn update_add_send(&mut self, intent: MainIntent) -> Vec<Command> {
        use MainIntent as I;
        match intent {
            I::AddTab(t) => {
                if matches!(self.add.stage, AddStage::Form { .. }) {
                    self.add.tab = t;
                    self.add.error = None;
                }
                Vec::new()
            }
            I::AddSameNetwork(v) => {
                self.add.same_network = v;
                Vec::new()
            }
            I::AddManualEdited(t) => {
                self.add.manual_addr = t;
                self.add.error = None;
                Vec::new()
            }
            I::AddCreate => {
                if self.add.tab != Tab::Invite
                    || !matches!(self.add.stage, AddStage::Form { busy: false })
                {
                    return Vec::new();
                }
                let manual_text = self.add.manual_addr.trim();
                let manual = if manual_text.is_empty() {
                    None
                } else {
                    match manual_text.parse::<SocketAddr>() {
                        Ok(a) => Some(a),
                        Err(_) => {
                            self.add.error = Some(texts::BAD_MANUAL_ADDR);
                            return Vec::new();
                        }
                    }
                };
                self.add.error = None;
                self.add.stage = AddStage::Form { busy: true };
                vec![Command::CreateInvite {
                    same_network: self.add.same_network,
                    manual,
                }]
            }
            I::AddPasteEdited(t) => {
                if matches!(self.add.stage, AddStage::Form { busy: false }) {
                    (self.add.paste, self.add.paste_too_long) = cap_paste(t);
                    self.add.error = None;
                }
                Vec::new()
            }
            I::AddAcceptSubmit => {
                if self.add.tab != Tab::Accept
                    || !matches!(self.add.stage, AddStage::Form { busy: false })
                {
                    return Vec::new();
                }
                if self.add.paste_too_long {
                    self.add.error = Some(chervo_core::texts::INPUT_TOO_LONG_TEXT);
                    return Vec::new();
                }
                let text = self.add.paste.trim().to_owned();
                if text.is_empty() {
                    self.add.error = Some(texts::PASTE_EMPTY);
                    return Vec::new();
                }
                self.add.error = None;
                self.add.stage = AddStage::Form { busy: true };
                vec![Command::AcceptInvite(text)]
            }
            I::AddCancel => {
                if let AddStage::Waiting { invite, .. } = self.add.stage {
                    self.add.stage = AddStage::Form { busy: false };
                    return vec![Command::CancelInvite(invite)];
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
                self.page = Page::Send;
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
            Outcome::InviteCreated(Ok((invite, token))) => {
                let qr = qr::encode(&token);
                self.add.stage = AddStage::Waiting {
                    invite,
                    token: Some(token),
                    qr,
                };
            }
            Outcome::InviteCreated(Err(e)) | Outcome::InviteAccepted(Err(e)) => {
                self.add.stage = AddStage::Form { busy: false };
                self.add.error = Some(e.user_text());
            }
            Outcome::InviteAccepted(Ok(invite)) => {
                // могла прийти раньше проверочного кода: не затираем его
                if !matches!(self.add.stage, AddStage::Sas(_)) {
                    self.add.stage = AddStage::Waiting {
                        invite,
                        token: None,
                        qr: None,
                    };
                }
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
                });
                self.page = Page::AddFriend;
                self.attention = true;
            }
            Outcome::SasAnswered(Err(e)) => {
                if let AddStage::Sas(s) = &mut self.add.stage {
                    s.busy = false;
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
            Outcome::AddrApplied(r) => match r {
                Ok(()) => {
                    self.dialog = Dialog::None;
                    self.push_notice(texts::ADDR_APPLIED);
                }
                Err(e) => {
                    if let Dialog::PasteToken(d) = &mut self.dialog {
                        d.busy = false;
                        d.error = Some(e.user_text());
                    } else {
                        self.push_notice(e.user_text());
                    }
                }
            },
            Outcome::Sent(r) => {
                self.send.busy = false;
                match r {
                    Ok(()) => {
                        self.send.paths.clear();
                        self.send.error = None;
                        self.page = Page::Transfers;
                    }
                    Err(e) => self.send.error = Some(e.user_text()),
                }
            }
            Outcome::OfferIncoming => self.attention = true,
            Outcome::AutoAccepted => self.push_notice(texts::AUTO_ACCEPTED),
            Outcome::Done(Err(e)) => {
                self.clear_busy();
                self.push_notice(e.user_text());
            }
            _ => {}
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
    use crate::model::{Intent, Snapshot};
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
        m.on_outcome(Outcome::Snapshot(s));
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
        assert_eq!(m.page, Page::AddFriend);
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

    #[test]
    fn paste_over_4096_rejected() {
        let mut m = model();
        ask(&mut m, MainIntent::AddTab(Tab::Accept));
        ask(&mut m, MainIntent::AddPasteEdited("x".repeat(5000)));
        assert!(m.add.paste.len() <= MAX_PASTE, "текст в модели обрезан");
        assert!(ask(&mut m, MainIntent::AddAcceptSubmit).is_empty());
        assert_eq!(m.add.error, Some(chervo_core::texts::INPUT_TOO_LONG_TEXT));
        // многобайтные символы считаются байтами: 2049 * 2 = 4098
        ask(&mut m, MainIntent::AddPasteEdited("ж".repeat(2049)));
        assert!(ask(&mut m, MainIntent::AddAcceptSubmit).is_empty());
        // ровно 4096 байт проходит
        ask(&mut m, MainIntent::AddPasteEdited("x".repeat(4096)));
        let cmds = ask(&mut m, MainIntent::AddAcceptSubmit);
        assert!(matches!(cmds.as_slice(), [Command::AcceptInvite(t)] if t.len() == 4096));
    }

    #[test]
    fn friend_token_paste_over_4096_rejected() {
        let mut m = model();
        ask(&mut m, MainIntent::PasteTokenOpen);
        ask(&mut m, MainIntent::PasteTokenEdited("y".repeat(4097)));
        assert!(ask(&mut m, MainIntent::PasteTokenSubmit).is_empty());
        ask(&mut m, MainIntent::PasteTokenEdited("token".to_owned()));
        assert_eq!(
            ask(&mut m, MainIntent::PasteTokenSubmit),
            vec![Command::ApplyAddrToken("token".to_owned())]
        );
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
    fn manual_addr_must_parse() {
        let mut m = model();
        ask(&mut m, MainIntent::AddManualEdited("не адрес".to_owned()));
        assert!(ask(&mut m, MainIntent::AddCreate).is_empty());
        assert_eq!(m.add.error, Some(texts::BAD_MANUAL_ADDR));
        ask(
            &mut m,
            MainIntent::AddManualEdited("203.0.113.5:50000".to_owned()),
        );
        ask(&mut m, MainIntent::AddSameNetwork(true));
        let cmds = ask(&mut m, MainIntent::AddCreate);
        assert_eq!(
            cmds,
            vec![Command::CreateInvite {
                same_network: true,
                manual: Some("203.0.113.5:50000".parse().expect("addr"))
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
        assert_eq!(m.page, Page::Transfers);
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
    fn main_intents_ignored_until_node_open() {
        let (mut m, _) = Model::start();
        assert!(
            m.update(Intent::Main(MainIntent::PasteTokenOpen))
                .is_empty()
        );
        assert!(matches!(m.dialog, Dialog::None));
    }
}
