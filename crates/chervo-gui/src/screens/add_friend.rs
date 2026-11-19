//! Экран 3: добавить друга. Создание приглашения, кнопка «Друг прислал мне текст» (одно поле
//! для любого текста от друга), ожидание и экран проверочного кода (8 цифр группами 4+4,
//! подпись для диктора цифра за цифрой).

use std::time::{Duration, Instant};

use eframe::egui::{self, FontId, RichText, Role, Sense, WidgetInfo};

use chervo_core::SkipReason;

use crate::access_model::{AccessIntent, GetIpMark, GetIpResult, GetIpUi, InviteExt};
use crate::main_model::{AddFriend, AddStage, Dialog, MainIntent, SasState};
use crate::model::{Intent, Model};
use crate::qr::QrMatrix;
use crate::screens::common::{
    button_with_help, checkbox_with_help, copy_box, enabled_button_with_help, help_mark,
    label_with_help, plain_button, warn,
};
use crate::screens::friends::friend_text_dialog;
use crate::texts;

/// Как часто перерисовывать окно, пока показан срок приглашения.
const VALID_REPAINT: Duration = Duration::from_secs(15);

fn main(i: MainIntent) -> Intent {
    Intent::Main(i)
}

pub fn show(ui: &mut egui::Ui, model: &Model) -> Vec<Intent> {
    let mut out = Vec::new();
    let a = &model.add;
    // поле «Друг прислал мне текст» открыто с этой вкладки: оно занимает место формы
    if let (Dialog::FriendText(p), AddStage::Form { .. }) = (&model.dialog, &a.stage) {
        friend_text_dialog(ui, p, &mut out);
        return out;
    }
    match &a.stage {
        AddStage::Form { busy } => form(ui, model, *busy, &mut out),
        AddStage::VpnAsk { .. } => vpn_ask(ui, &mut out),
        AddStage::Waiting {
            token,
            qr,
            valid,
            ext,
            addr_changed,
            ..
        } => {
            let w = Waiting {
                token: token.as_deref(),
                qr: qr.as_ref(),
                valid: *valid,
                ext: *ext,
                addr_changed: *addr_changed,
            };
            waiting(ui, &w, &mut out);
        }
        AddStage::Sas(s) => sas(ui, s, &mut out),
        AddStage::Finished(text) => {
            ui.label(*text);
            ui.add_space(8.0);
            if plain_button(ui, texts::BTN_OK).clicked() {
                out.push(main(MainIntent::AddDone));
            }
        }
    }
    out
}

/// Причина, по которой адрес от сервера в приглашение не вписан (или проба не удалась); `None`:
/// нечего сказать. Общая для экрана и проверок.
pub fn invite_ext_note(ext: InviteExt) -> Option<&'static str> {
    match ext {
        InviteExt::Skipped(SkipReason::NoAnswer) => Some(texts::INV_EXT_NO_ANSWER),
        InviteExt::Skipped(SkipReason::ServerLocal) => Some(texts::INV_EXT_SERVER_LOCAL),
        InviteExt::Skipped(SkipReason::Symmetric) => Some(texts::INV_EXT_SYMMETRIC),
        InviteExt::Failed(text) => Some(text),
        InviteExt::Plain | InviteExt::NotSet | InviteExt::Added { .. } => None,
    }
}

fn open_access_button(ui: &mut egui::Ui, out: &mut Vec<Intent>) {
    if button_with_help(ui, texts::BTN_OPEN_ACCESS, texts::HELP_OPEN_ACCESS).clicked() {
        out.push(main(MainIntent::Access(AccessIntent::Open)));
    }
}

fn form(ui: &mut egui::Ui, model: &Model, busy: bool, out: &mut Vec<Intent>) {
    let a: &AddFriend = &model.add;
    // друг уже прислал текст: приглашение, новый адрес или уведомление об удалении
    if enabled_button_with_help(ui, !busy, texts::BTN_FRIEND_TEXT, texts::HELP_FRIEND_TEXT)
        .clicked()
    {
        out.push(main(MainIntent::FriendTextOpen));
    }
    ui.separator();
    let mut same = a.same_network;
    if checkbox_with_help(
        ui,
        !busy,
        &mut same,
        texts::LABEL_SAME_NETWORK,
        texts::HELP_SAME_NETWORK,
    )
    .changed()
    {
        out.push(main(MainIntent::AddSameNetwork(same)));
    }
    ui.add_space(6.0);
    warn(ui, texts::IP_WARNING);
    if let Some(e) = a.error {
        warn(ui, e);
        if a.no_addresses {
            open_access_button(ui, out);
        }
    }
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if enabled_button_with_help(
            ui,
            !busy,
            texts::BTN_CREATE_INVITE,
            texts::HELP_CREATE_INVITE,
        )
        .clicked()
        {
            out.push(main(MainIntent::AddCreate));
        }
        // «Получить свой IP»: без сервера недоступна, «?» подсказывает, куда вписать адрес
        let enabled = !busy && model.get_ip_enabled();
        let help = if model.echo_server_set() {
            texts::HELP_GET_IP
        } else {
            texts::GETIP_NO_SERVER
        };
        if enabled_button_with_help(ui, enabled, texts::BTN_GET_IP, help).clicked() {
            out.push(main(MainIntent::GetIp));
        }
    });
    if busy && model.echo_server_set() {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(texts::INV_EXT_CHECKING);
        });
    }
    get_ip_result(ui, &a.get_ip);
    ui.add_space(4.0);
    open_access_button(ui, out);
}

/// Итог «Получить свой IP»: адрес с «Копировать» и заметные пометки про VPN.
fn get_ip_result(ui: &mut egui::Ui, g: &GetIpUi) {
    match g {
        GetIpUi::Idle => {}
        GetIpUi::Busy => {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(texts::INV_EXT_CHECKING);
            });
        }
        GetIpUi::Result(GetIpResult::Address { addr, mark }) => {
            ui.label(texts::GETIP_RESULT);
            crate::screens::common::copy_line(ui, "", &addr.to_string());
            match mark {
                GetIpMark::Clean => {}
                GetIpMark::MaybeVpn => warn(ui, texts::GETIP_MAYBE_VPN),
                GetIpMark::VpnOn => warn(ui, texts::GETIP_VPN_ON),
            }
        }
        GetIpUi::Result(GetIpResult::NoAnswer) => warn(ui, texts::GETIP_NO_ANSWER),
        GetIpUi::Result(GetIpResult::ServerLocal) => warn(ui, texts::INV_EXT_SERVER_LOCAL),
        GetIpUi::Result(GetIpResult::Symmetric) => warn(ui, texts::INV_EXT_SYMMETRIC),
        GetIpUi::Result(GetIpResult::Failed(text)) => warn(ui, text),
    }
}

/// Похоже на VPN: приглашения ещё нет, адрес вписывается только по явной кнопке.
fn vpn_ask(ui: &mut egui::Ui, out: &mut Vec<Intent>) {
    ui.heading(texts::INV_MAYBE_VPN_TITLE);
    warn(ui, texts::INV_MAYBE_VPN_TEXT);
    ui.add_space(8.0);
    if button_with_help(
        ui,
        texts::BTN_INV_WITHOUT_ADDR,
        texts::HELP_INV_WITHOUT_ADDR,
    )
    .clicked()
    {
        out.push(main(MainIntent::AddVpnWithout));
    }
    if button_with_help(ui, texts::BTN_INV_WITH_ADDR, texts::HELP_INV_WITH_ADDR).clicked() {
        out.push(main(MainIntent::AddVpnWithAddr));
    }
    if plain_button(ui, texts::BTN_CANCEL).clicked() {
        out.push(main(MainIntent::AddCancel));
    }
}

/// Что показывает экран ожидания.
struct Waiting<'a> {
    token: Option<&'a str>,
    qr: Option<&'a QrMatrix>,
    valid: Option<(Instant, u64)>,
    ext: InviteExt,
    addr_changed: bool,
}

/// Подписи про адрес в интернете под созданным приглашением.
fn ext_notes(ui: &mut egui::Ui, ext: InviteExt, out: &mut Vec<Intent>) {
    match ext {
        InviteExt::Plain => {}
        InviteExt::NotSet => {
            ui.horizontal(|ui| {
                ui.small(texts::INV_EXT_NOT_SET_LABEL);
                help_mark(ui, texts::INV_EXT_NOT_SET);
            });
        }
        InviteExt::Added { addr, vpn_on } => {
            ui.small(texts::INV_EXT_ADDED.replace("{addr}", &addr.to_string()));
            if vpn_on {
                ui.strong(texts::INV_VPN_ON_TITLE);
                warn(ui, texts::INV_VPN_ON_TEXT);
            }
            ui.label(texts::INV_EXT_FRIEND_TIP);
            open_access_button(ui, out);
        }
        InviteExt::Skipped(SkipReason::Symmetric) => {
            ui.label(texts::INV_EXT_SYMMETRIC);
            open_access_button(ui, out);
        }
        other => {
            if let Some(t) = invite_ext_note(other) {
                ui.label(t);
            }
        }
    }
}

fn waiting(ui: &mut egui::Ui, w: &Waiting<'_>, out: &mut Vec<Intent>) {
    match w.token {
        Some(t) => {
            ui.label(texts::INVITE_WAIT);
            if let Some((created, ttl)) = w.valid {
                let left = ttl.saturating_sub(created.elapsed().as_secs());
                ui.label(texts::invite_valid_text(left));
                if left > 0 {
                    ui.ctx().request_repaint_after(VALID_REPAINT);
                }
            }
            warn(ui, texts::IP_WARNING);
            copy_box(ui, t);
            ext_notes(ui, w.ext, out);
            if w.addr_changed {
                warn(ui, texts::INV_ADDR_CHANGED);
            }
            if let Some(q) = w.qr {
                ui.add_space(8.0);
                draw_qr(ui, q);
            }
        }
        None => {
            ui.label(texts::INVITE_ACCEPT_WAIT);
        }
    }
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        ui.spinner();
        if plain_button(ui, texts::BTN_CANCEL).clicked() {
            out.push(main(MainIntent::AddCancel));
        }
    });
}

fn draw_qr(ui: &mut egui::Ui, q: &QrMatrix) {
    let cell = 4.0_f32;
    let quiet = 4.0_f32;
    let side = (q.width as f32 + 2.0 * quiet) * cell;
    let (rect, response) = ui.allocate_exact_size(egui::vec2(side, side), Sense::hover());
    // QR только для глаз; тот же текст доступен выше как обычный
    response.widget_info(|| WidgetInfo::labeled(Role::Image, true, "QR-код приглашения"));
    let painter = ui.painter_at(rect);
    painter.rect_filled(rect, 0.0, egui::Color32::WHITE);
    for y in 0..q.width {
        for x in 0..q.width {
            if q.dark.get(y * q.width + x).copied().unwrap_or(false) {
                let min =
                    rect.min + egui::vec2((x as f32 + quiet) * cell, (y as f32 + quiet) * cell);
                painter.rect_filled(
                    egui::Rect::from_min_size(min, egui::vec2(cell, cell)),
                    0.0,
                    egui::Color32::BLACK,
                );
            }
        }
    }
}

fn sas(ui: &mut egui::Ui, s: &SasState, out: &mut Vec<Intent>) {
    ui.heading(texts::SAS_TITLE);
    ui.label(texts::SAS_HINT);
    ui.add_space(12.0);
    // 8 цифр группами 4+4 крупно; диктор читает цифру за цифрой
    let digits = ui.label(RichText::new(&s.digits).font(FontId::monospace(56.0)));
    let digits = digits.interact(Sense::focusable_noninteractive());
    digits.widget_info(|| WidgetInfo::labeled(Role::Label, true, s.spoken.as_str()));
    ui.add_space(12.0);
    label_with_help(ui, texts::LABEL_NAME, texts::HELP_SAS_NAME);
    let mut name = s.name.clone();
    if ui
        .add_enabled(!s.busy, egui::TextEdit::singleline(&mut name))
        .changed()
    {
        out.push(main(MainIntent::SasNameEdited(name)));
    }
    if let Some(e) = s.error {
        warn(ui, e);
    }
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        if enabled_button_with_help(ui, !s.busy, texts::BTN_SAS_MATCH, texts::HELP_SAS_MATCH)
            .clicked()
        {
            out.push(main(MainIntent::SasMatch));
        }
        if enabled_button_with_help(
            ui,
            !s.busy,
            texts::BTN_SAS_MISMATCH,
            texts::HELP_SAS_MISMATCH,
        )
        .clicked()
        {
            out.push(main(MainIntent::SasMismatch));
        }
    });
    // после «Совпадает» кнопки серые: без этой строки кажется, что программа зависла
    if s.waiting {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label(texts::SAS_WAITING);
        });
    }
}
