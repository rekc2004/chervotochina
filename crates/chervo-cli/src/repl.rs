//! Интерактивный цикл `chervo run` (этап 18в): строки со стандартного ввода, команды к узлу,
//! события узла выводятся по мере прихода. Только публичный API `chervo_core::Node`. Весь вывод
//! идёт через модуль `out`. Адреса не показываются, кроме текста токена, который человек сам
//! попросил (рядом предупреждение об IP).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::Duration;

use chervo_core::texts::{
    ASK_FILE_TEXT, CHOOSE_OTHER_FOLDER_TEXT, DISCONNECTED_TEXT, DISK_FULL_TEXT,
    ENABLE_ON_ROUTER_TEXT, INPUT_TOO_LONG_TEXT, KEY_LOST_TEXT, PEER_UNREACHABLE_INVITE_TEXT,
    PREPARING_TEXT, STALLED_TEXT, mapping_text,
};
use chervo_core::{
    ClockProposal, ClockSync, FriendRef, FriendStatus, InviteOutcome, InviteRef, Node, NodeError,
    NodeEvent, NodeEvents, PathKind, PauseReason, RouterCandidate, SasView, Side, TransferRef,
    TransferState,
};

use crate::input::{Input, tokenize};
use crate::out;
use crate::view::{human_size, percent};

/// Срок мягкой остановки передач при выходе.
const QUIT_DEADLINE: Duration = Duration::from_secs(5);
/// Как часто, ожидая ввод, смотреть события узла.
const POLL: Duration = Duration::from_millis(100);

const HELP: &[&str] = &[
    "Команды:",
    "  friends                         список друзей",
    "  invite [--lan] [--addr IP:ПОРТ]  создать приглашение (текст раскрывает ваш IP)",
    "  accept-invite                   принять приглашение (следующей строкой вставьте текст)",
    "  sas yes ИМЯ | sas no            код совпал (и как назвать друга) или не совпал",
    "  send ДРУГ ПУТЬ...               отправить файлы или папки",
    "  offers                          входящие предложения, ждущие ответа",
    "  accept N [--into ПАПКА]         принять предложение N",
    "  decline N                       отклонить предложение N",
    "  transfers                       список передач",
    "  retry N | cancel N              повторить или отменить передачу N",
    "  diag ДРУГ                       почему друг недоступен",
    "  connect ДРУГ                    соединиться сейчас",
    "  token-for ДРУГ [--lan]          текст с вашим адресом для друга",
    "  apply-token                     вставить текст с адресом друга (следующей строкой)",
    "  revoke-text                     тексты отзыва, которые нужно передать друзьям",
    "  apply-revocation                вставить отзыв от друга (следующей строкой)",
    "  rekey ДРУГ                      пересоздать ключ пары",
    "  block ДРУГ | unblock ДРУГ | remove ДРУГ",
    "  upnp find | upnp allow [--permanent] | upnp forget",
    "  clock sync | clock confirm | clock reset",
    "  quit                            выйти (конец ввода тоже выход)",
    "ДРУГ: имя или номер из friends. N: номер из transfers.",
];

pub fn run(node: Node, events: NodeEvents, lines: Receiver<Input>) {
    let mut r = Repl {
        node,
        events,
        lines,
        pending_sas: Vec::new(),
        router: None,
        proposal: None,
        eof: false,
    };
    out::line("Узел запущен. Список команд: help. Выход: quit.");
    loop {
        match r.next_input() {
            Input::Eof => break,
            Input::TooLong => out::err(INPUT_TOO_LONG_TEXT),
            Input::BadText => out::err("Строка не в кодировке UTF-8."),
            Input::Line(l) => {
                if !r.command(&l) {
                    break;
                }
            }
        }
        if r.eof {
            break;
        }
    }
    out::line("Завершаю работу: останавливаю передачи и снимаю проброс порта.");
    let Repl { node, .. } = r;
    node.shutdown(QUIT_DEADLINE);
    out::line("Узел остановлен.");
}

struct Repl {
    node: Node,
    events: NodeEvents,
    lines: Receiver<Input>,
    /// Приглашения, у которых показан код и ждётся ответ человека (старое первым).
    pending_sas: Vec<(InviteRef, SasView)>,
    router: Option<RouterCandidate>,
    proposal: Option<ClockProposal>,
    eof: bool,
}

fn fail(e: NodeError) {
    out::err(e.user_text());
}

fn is_yes(s: &str) -> bool {
    matches!(s.trim().to_lowercase().as_str(), "да" | "д" | "yes" | "y")
}

fn path_text(p: PathKind) -> &'static str {
    match p {
        PathKind::Lan => "локальная сеть",
        PathKind::Ipv6 => "IPv6",
        PathKind::PortMapped => "проброс порта",
        PathKind::SimultaneousOpen => "прямое соединение через NAT",
    }
}

fn status_text(s: FriendStatus) -> &'static str {
    match s {
        FriendStatus::Active => "активен",
        FriendStatus::Blocked => "заблокирован",
        FriendStatus::RevokedByPeer => "друг отозвал ключ",
        FriendStatus::Retired => "удалён (остался текст отзыва)",
        _ => "неизвестно",
    }
}

fn pause_text(p: PauseReason) -> &'static str {
    match p {
        PauseReason::Disconnected => DISCONNECTED_TEXT,
        PauseReason::DiskFull => DISK_FULL_TEXT,
        PauseReason::Io => "Ошибка чтения или записи; передача на паузе. Повторите: retry.",
        PauseReason::Stalled => STALLED_TEXT,
    }
}

const IP_WARNING: &str =
    "Внимание: в этом тексте ваш IP-адрес. Отправляйте его только тому, кому доверяете.";

impl Repl {
    fn next_input(&mut self) -> Input {
        loop {
            self.pump_events();
            match self.lines.recv_timeout(POLL) {
                Ok(i) => return i,
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return Input::Eof,
            }
        }
    }

    /// Следующая строка как ответ на вопрос (вставка текста, подтверждение).
    fn ask(&mut self, prompt: &str) -> Option<String> {
        out::line(prompt);
        match self.next_input() {
            Input::Line(s) => Some(s),
            Input::TooLong => {
                out::err(INPUT_TOO_LONG_TEXT);
                None
            }
            Input::BadText => {
                out::err("Строка не в кодировке UTF-8.");
                None
            }
            Input::Eof => {
                self.eof = true;
                None
            }
        }
    }

    fn name_of(&self, f: FriendRef) -> String {
        self.node
            .friends()
            .into_iter()
            .find(|v| v.friend == f)
            .map_or_else(|| "друг".to_owned(), |v| out::clean(&v.name))
    }

    fn number_of(&self, t: TransferRef) -> Option<usize> {
        self.node
            .transfers()
            .iter()
            .position(|v| v.transfer == t)
            .map(|i| i + 1)
    }

    fn friend(&self, arg: &str) -> Option<FriendRef> {
        let all = self.node.friends();
        let by_name: Vec<_> = all.iter().filter(|v| v.name == arg).collect();
        match by_name.as_slice() {
            [one] => return Some(one.friend),
            [] => {}
            _ => {
                out::err("Несколько друзей с таким именем: укажите номер из friends.");
                return None;
            }
        }
        if let Ok(n) = arg.parse::<usize>()
            && n >= 1
            && let Some(v) = all.get(n - 1)
        {
            return Some(v.friend);
        }
        out::err("Такого друга нет. Список: friends.");
        None
    }

    fn transfer(&self, arg: &str) -> Option<TransferRef> {
        if let Ok(n) = arg.parse::<usize>()
            && n >= 1
            && let Some(v) = self.node.transfers().get(n - 1)
        {
            return Some(v.transfer);
        }
        out::err("Такой передачи нет. Список: transfers.");
        None
    }

    fn pump_events(&mut self) {
        while let Ok(e) = self.events.try_recv() {
            self.on_event(e);
        }
    }

    fn on_event(&mut self, e: NodeEvent) {
        match e {
            NodeEvent::FriendOnline { friend, path } => {
                out::line(&format!(
                    "{} на связи ({}).",
                    self.name_of(friend),
                    path_text(path)
                ));
            }
            NodeEvent::FriendOffline { friend } => {
                out::line(&format!("{} не в сети.", self.name_of(friend)));
            }
            NodeEvent::InviteSas { invite, sas } => {
                out::line(&format!("Проверочный код: {}", sas.digits()));
                out::line(
                    "Сверьте код с другом по телефону или лично. Совпал: sas yes ИМЯ (имя, под \
                     которым вы будете видеть друга). Не совпал: sas no.",
                );
                self.pending_sas.push((invite, sas));
            }
            NodeEvent::InviteFinished { invite, outcome } => {
                self.pending_sas.retain(|(i, _)| *i != invite);
                out::line(match outcome {
                    InviteOutcome::Added => "Друг добавлен.",
                    InviteOutcome::Declined => "Приглашение отклонено.",
                    InviteOutcome::PeerUnreachable => PEER_UNREACHABLE_INVITE_TEXT,
                    InviteOutcome::Expired => "Срок приглашения истёк.",
                    InviteOutcome::Failed => "Не удалось завершить приглашение.",
                });
            }
            NodeEvent::FriendKeyProblem { friend } => {
                out::line(&format!("{}: {}", self.name_of(friend), KEY_LOST_TEXT));
            }
            NodeEvent::ClockSkewSuspected { friend } => {
                out::line(&format!(
                    "Возможно, часы у вас или у {} идут неверно. Проверить свои: clock sync.",
                    self.name_of(friend)
                ));
            }
            NodeEvent::Unreachable { friend, diagnosis } => {
                out::line(&format!(
                    "{} недоступен. {}",
                    self.name_of(friend),
                    diagnosis.text
                ));
            }
            NodeEvent::OwnAddressChanged => {
                out::line(
                    "Ваш адрес изменился. Если друзья не могут соединиться, отправьте им новый \
                     текст: token-for ДРУГ.",
                );
            }
            NodeEvent::MappingChanged { status } => out::line(mapping_text(status)),
            NodeEvent::OfferIncoming { transfer } => {
                let who = self
                    .node
                    .transfers()
                    .into_iter()
                    .find(|v| v.transfer == transfer)
                    .map_or_else(|| "друг".to_owned(), |v| self.name_of(v.friend));
                out::line(&format!(
                    "Входящее предложение от {who}. Посмотреть: offers. Принять: accept N. \
                     Отклонить: decline N."
                ));
            }
            NodeEvent::OfferAutoAccepted { transfer } => {
                let n = self
                    .number_of(transfer)
                    .map_or_else(String::new, |n| format!(" {n}"));
                out::line(&format!("Предложение{n} принято автоматически."));
            }
            NodeEvent::TransferFinished { transfer, result } => {
                let dest = self
                    .node
                    .transfers()
                    .into_iter()
                    .find(|v| v.transfer == transfer)
                    .and_then(|v| v.dest_root);
                let label = self
                    .number_of(transfer)
                    .map_or_else(|| "Передача".to_owned(), |n| format!("Передача {n}"));
                out::line(&format!("{label}: {}", result.user_text()));
                if let (Some(d), true) = (
                    dest,
                    matches!(result, chervo_core::TransferResult::Completed),
                ) {
                    out::line(&format!("Файлы лежат в папке: {}", out::clean(&d)));
                }
            }
            NodeEvent::Warning(w) => out::line(w.user_text()),
            NodeEvent::Internal => {
                out::line(
                    "Внутренний сбой узла. Если проблема повторяется, перезапустите программу.",
                );
            }
            NodeEvent::Lagged => {
                out::line("Часть событий потеряна. Актуальное состояние: friends, transfers.");
            }
            _ => {}
        }
    }

    /// `false`: выйти.
    fn command(&mut self, line: &str) -> bool {
        let Some(words) = tokenize(line) else {
            out::err("Не закрыта кавычка.");
            return true;
        };
        let Some((cmd, args)) = words.split_first() else {
            return true;
        };
        match cmd.as_str() {
            "quit" | "exit" => return false,
            "help" => HELP.iter().for_each(|l| out::line(l)),
            "friends" => self.cmd_friends(),
            "invite" => self.cmd_invite(args),
            "accept-invite" => self.cmd_accept_invite(),
            "sas" => self.cmd_sas(args),
            "send" => self.cmd_send(args),
            "offers" => self.cmd_offers(),
            "accept" => self.cmd_accept(args),
            "decline" => self.with_transfer(args, |n, t| n.decline(t), "Предложение отклонено."),
            "cancel" => self.with_transfer(args, |n, t| n.cancel(t), "Передача отменена."),
            "retry" => self.with_transfer(args, |n, t| n.retry(t), "Пробую продолжить."),
            "transfers" => self.cmd_transfers(),
            "diag" => self.cmd_diag(args),
            "connect" => self.with_friend(args, |n, f| n.connect_now(f), "Пробую соединиться."),
            "token-for" => self.cmd_token_for(args),
            "apply-token" => self.cmd_apply_token(),
            "revoke-text" => self.cmd_revoke_text(),
            "apply-revocation" => self.cmd_apply_revocation(),
            "rekey" => self.cmd_rekey(args),
            "block" => self.with_friend(args, |n, f| n.block(f), "Друг заблокирован."),
            "unblock" => self.with_friend(args, |n, f| n.unblock(f), "Друг разблокирован."),
            "remove" => self.cmd_remove(args),
            "upnp" => self.cmd_upnp(args),
            "clock" => self.cmd_clock(args),
            _ => out::err("Неизвестная команда. Список: help."),
        }
        true
    }

    fn with_friend(
        &self,
        args: &[String],
        act: impl FnOnce(&Node, FriendRef) -> Result<(), NodeError>,
        done: &str,
    ) {
        let [arg] = args else {
            out::err("Нужен один аргумент: имя или номер друга.");
            return;
        };
        let Some(f) = self.friend(arg) else { return };
        match act(&self.node, f) {
            Ok(()) => out::line(done),
            Err(e) => fail(e),
        }
    }

    fn with_transfer(
        &self,
        args: &[String],
        act: impl FnOnce(&Node, TransferRef) -> Result<(), NodeError>,
        done: &str,
    ) {
        let [arg] = args else {
            out::err("Нужен один аргумент: номер передачи из transfers.");
            return;
        };
        let Some(t) = self.transfer(arg) else { return };
        match act(&self.node, t) {
            Ok(()) => out::line(done),
            Err(e) => fail(e),
        }
    }

    fn cmd_friends(&self) {
        let all = self.node.friends();
        if all.is_empty() {
            out::line("Друзей пока нет. Начать: invite.");
        }
        for (i, v) in all.iter().enumerate() {
            let mut s = format!(
                "{}. {} — {}",
                i + 1,
                out::clean(&v.name),
                status_text(v.state)
            );
            if v.online {
                s.push_str(", на связи");
                if let Some(p) = v.last_path {
                    s.push_str(&format!(" ({})", path_text(p)));
                }
            }
            if v.auto_accept {
                s.push_str(", автоприём");
            }
            if v.key_problem {
                s.push_str(&format!(". {KEY_LOST_TEXT}"));
            }
            out::line(&s);
        }
    }

    fn cmd_invite(&self, args: &[String]) {
        let mut lan = false;
        let mut addr: Option<SocketAddr> = None;
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--lan" => lan = true,
                "--addr" => match it.next().map(|v| v.parse::<SocketAddr>()) {
                    Some(Ok(v)) => addr = Some(v),
                    _ => {
                        out::err("После --addr нужен адрес вида IP:ПОРТ.");
                        return;
                    }
                },
                _ => {
                    out::err("Использование: invite [--lan] [--addr IP:ПОРТ]");
                    return;
                }
            }
        }
        match self.node.create_invite(lan, addr) {
            Ok((_, token)) => {
                let minutes = self.node.settings().invite_ttl_secs / 60;
                out::line(&format!(
                    "Приглашение для друга (действует {minutes} мин). Отправьте этот текст целиком:"
                ));
                out::line(token.as_str());
                out::line(IP_WARNING);
                out::line("Когда друг его примет, здесь появится проверочный код.");
            }
            Err(e) => fail(e),
        }
    }

    fn cmd_accept_invite(&mut self) {
        let Some(text) = self.ask("Вставьте текст приглашения одной строкой:")
        else {
            return;
        };
        match self.node.accept_invite(&text) {
            Ok(_) => out::line("Приглашение принято. Ждём проверочный код."),
            Err(e) => fail(e),
        }
    }

    fn cmd_sas(&mut self, args: &[String]) {
        let Some((first, _)) = self.pending_sas.first().copied() else {
            out::err("Нет приглашения, ждущего проверки кода.");
            return;
        };
        let code = self
            .pending_sas
            .first()
            .map(|(_, s)| s.digits())
            .unwrap_or_default();
        let (yes, name) = match args {
            [v, rest @ ..] if v == "yes" => {
                let name = rest.join(" ");
                if name.trim().is_empty() {
                    out::err("Укажите имя друга: sas yes ИМЯ.");
                    return;
                }
                (true, name)
            }
            [v] if v == "no" => (false, String::new()),
            _ => {
                out::err("Использование: sas yes ИМЯ или sas no.");
                return;
            }
        };
        match self.node.confirm_sas(first, yes, &name) {
            Ok(()) => {
                self.pending_sas.retain(|(i, _)| *i != first);
                if yes {
                    out::line(&format!("Подтверждён код {code}. Ждём второго участника."));
                } else {
                    out::line("Код не совпал: приглашение отклонено.");
                }
            }
            Err(e) => fail(e),
        }
    }

    fn cmd_send(&self, args: &[String]) {
        let Some((who, paths)) = args.split_first() else {
            out::err("Использование: send ДРУГ ПУТЬ...");
            return;
        };
        if paths.is_empty() {
            out::err("Укажите хотя бы один файл или папку.");
            return;
        }
        let Some(f) = self.friend(who) else { return };
        let paths: Vec<PathBuf> = paths.iter().map(PathBuf::from).collect();
        match self.node.send(f, &paths) {
            Ok(t) => {
                let n = self
                    .number_of(t)
                    .map_or_else(String::new, |n| format!(" {n}"));
                out::line(&format!("Передача{n} создана: ждём ответа друга."));
            }
            Err(NodeError::BadName(count)) => {
                out::err(&format!(
                    "{} Таких имён: {count}.",
                    NodeError::BadName(count).user_text()
                ));
            }
            Err(e) => fail(e),
        }
    }

    fn cmd_offers(&self) {
        let waiting: Vec<_> = self
            .node
            .transfers()
            .into_iter()
            .enumerate()
            .filter(|(_, v)| v.side == Side::Receiver && v.state == TransferState::AwaitingUser)
            .collect();
        if waiting.is_empty() {
            out::line("Входящих предложений нет.");
        }
        for (i, v) in waiting {
            let offer = match self.node.offer(v.transfer) {
                Ok(o) => o,
                Err(e) => {
                    fail(e);
                    continue;
                }
            };
            out::line(&format!(
                "Предложение {} от {}: файлов {}, всего {}.",
                i + 1,
                self.name_of(offer.friend),
                offer.files.len(),
                human_size(offer.total)
            ));
            for f in &offer.files {
                let mut s = format!("  {} ({})", out::clean(&f.name), human_size(f.size));
                if f.needs_question {
                    s.push_str(" [нужен вопрос о доверии]");
                }
                if f.deceptive {
                    s.push_str(" [выглядит не тем, чем является]");
                }
                if f.name_changed {
                    s.push_str(" [имя изменено]");
                }
                out::line(&s);
            }
            for w in &offer.warnings {
                out::line(w);
            }
            if offer.space.short {
                out::line(&space_text(offer.space.needed, offer.space.available));
            }
        }
    }

    fn cmd_accept(&mut self, args: &[String]) {
        let mut n: Option<&String> = None;
        let mut into: Option<PathBuf> = None;
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if a == "--into" {
                match it.next() {
                    Some(d) => into = Some(abs(d)),
                    None => {
                        out::err("После --into нужна папка.");
                        return;
                    }
                }
            } else if n.is_none() {
                n = Some(a);
            } else {
                out::err("Использование: accept N [--into ПАПКА]");
                return;
            }
        }
        let Some(n) = n else {
            out::err("Использование: accept N [--into ПАПКА]");
            return;
        };
        let Some(t) = self.transfer(n) else { return };
        let offer = match self.node.offer(t) {
            Ok(o) => o,
            Err(e) => {
                fail(e);
                return;
            }
        };
        if offer.space.short && into.is_none() {
            out::err(&space_text(offer.space.needed, offer.space.available));
            return;
        }
        if offer.needs_question {
            for w in &offer.warnings {
                out::line(w);
            }
            out::line(ASK_FILE_TEXT);
            match self.ask("Принять? Введите «да» или «нет»:") {
                Some(a) if is_yes(&a) => {}
                _ => {
                    out::line("Не принято. Предложение ждёт вашего ответа.");
                    return;
                }
            }
        }
        let r = match &into {
            Some(d) => self.node.accept_into(t, d),
            None => self.node.accept(t),
        };
        match r {
            Ok(()) => out::line("Приём начат. Ход: transfers."),
            Err(e) => fail(e),
        }
    }

    fn cmd_transfers(&self) {
        let all = self.node.transfers();
        if all.is_empty() {
            out::line("Передач нет.");
        }
        for (i, v) in all.iter().enumerate() {
            let dir = match v.side {
                Side::Sender => "отправка",
                Side::Receiver => "приём",
            };
            let state = match (v.result, v.state) {
                (Some(r), _) => r.user_text().to_owned(),
                (None, TransferState::AwaitingAnswer) => "ждёт ответа друга".to_owned(),
                (None, TransferState::AwaitingUser) => "ждёт вашего ответа (offers)".to_owned(),
                (None, TransferState::Active) => v.preparing.map_or_else(
                    || format!("идёт, {}%", percent(v.done, v.total)),
                    |(d, t)| format!("{PREPARING_TEXT} {}%", percent(d, t)),
                ),
                (None, TransferState::Paused(p)) => pause_text(p).to_owned(),
                (None, _) => "завершена".to_owned(),
            };
            let mut s = format!(
                "{}. {} {}: {} из {}. {}",
                i + 1,
                dir,
                self.name_of(v.friend),
                human_size(v.done),
                human_size(v.total),
                state
            );
            if let (Side::Receiver, Some(d)) = (v.side, &v.dest_root) {
                s.push_str(&format!(" Папка: {}", out::clean(d)));
            }
            out::line(&s);
        }
    }

    fn cmd_diag(&self, args: &[String]) {
        let [arg] = args else {
            out::err("Использование: diag ДРУГ");
            return;
        };
        let Some(f) = self.friend(arg) else { return };
        match self.node.diagnose(f) {
            Ok(Some(d)) => out::line(d.text),
            Ok(None) => out::line("Соединение есть или причину пока определить нельзя."),
            Err(e) => fail(e),
        }
    }

    fn cmd_token_for(&self, args: &[String]) {
        let mut lan = false;
        let mut who: Option<&String> = None;
        for a in args {
            if a == "--lan" {
                lan = true;
            } else if who.is_none() {
                who = Some(a);
            } else {
                out::err("Использование: token-for ДРУГ [--lan]");
                return;
            }
        }
        let Some(who) = who else {
            out::err("Использование: token-for ДРУГ [--lan]");
            return;
        };
        let Some(f) = self.friend(who) else { return };
        match self.node.issue_addr_update_text(f, lan) {
            Ok(t) => {
                out::line("Отправьте другу этот текст целиком:");
                out::line(t.as_str());
                out::line(IP_WARNING);
            }
            Err(e) => fail(e),
        }
    }

    fn cmd_apply_token(&mut self) {
        let Some(text) = self.ask("Вставьте текст с адресом друга одной строкой:")
        else {
            return;
        };
        match self.node.apply_addr_update_text(&text) {
            Ok(f) => out::line(&format!(
                "Адрес {} обновлён, пробую соединиться.",
                self.name_of(f)
            )),
            Err(e) => fail(e),
        }
    }

    fn cmd_revoke_text(&self) {
        let retired = self.node.retired();
        if retired.is_empty() {
            out::line("Текстов отзыва для передачи нет.");
        }
        for (f, t) in retired {
            out::line(&format!(
                "Отзыв для друга {}. Отправьте этот текст ему вручную:",
                self.name_of(f)
            ));
            out::line(t.as_str());
        }
    }

    fn cmd_apply_revocation(&mut self) {
        let Some(text) = self.ask("Вставьте текст отзыва от друга одной строкой:")
        else {
            return;
        };
        match self.node.apply_revocation_text(&text) {
            Ok(Some(f)) => out::line(&format!(
                "Друг {} отозвал ключ: связь с ним закрыта.",
                self.name_of(f)
            )),
            Ok(None) => out::line("Отзыв подлинный, но никому из ваших друзей не подходит."),
            Err(e) => fail(e),
        }
    }

    fn cmd_rekey(&self, args: &[String]) {
        let [arg] = args else {
            out::err("Использование: rekey ДРУГ");
            return;
        };
        let Some(f) = self.friend(arg) else { return };
        match self.node.rekey(f) {
            Ok(t) => {
                out::line(
                    "Ключ пересоздан. Отправьте другу этот текст отзыва вручную, затем создайте \
                     для него новое приглашение (invite):",
                );
                out::line(t.as_str());
            }
            Err(e) => fail(e),
        }
    }

    fn cmd_remove(&self, args: &[String]) {
        let [arg] = args else {
            out::err("Использование: remove ДРУГ");
            return;
        };
        let Some(f) = self.friend(arg) else { return };
        match self.node.remove(f) {
            Ok(Some(t)) => {
                out::line(
                    "Друг удалён. Чтобы он узнал об этом сразу, отправьте ему текст отзыва \
                     вручную:",
                );
                out::line(t.as_str());
            }
            Ok(None) => out::line("Друг удалён."),
            Err(e) => fail(e),
        }
    }

    fn cmd_upnp(&mut self, args: &[String]) {
        match args {
            [a] if a == "find" => {
                out::line("Ищу роутер: один запрос в локальной сети.");
                match self.node.upnp_identify() {
                    Ok(r) => {
                        self.router = Some(r);
                        out::line("Роутер найден.");
                        out::line(ENABLE_ON_ROUTER_TEXT);
                        out::line("Если согласны: upnp allow.");
                    }
                    Err(e) => fail(e),
                }
            }
            [a, rest @ ..] if a == "allow" && rest.iter().all(|x| x == "--permanent") => {
                let Some(r) = self.router.clone() else {
                    out::err("Сначала найдите роутер: upnp find.");
                    return;
                };
                match self.node.upnp_allow(&r, !rest.is_empty()) {
                    Ok(()) => out::line("Роутер разрешён: проброс порта включён."),
                    Err(e) => fail(e),
                }
            }
            [a] if a == "forget" => {
                let target =
                    self.router
                        .clone()
                        .or_else(|| match self.node.settings().routers.as_slice() {
                            [one] => Some(one.router.clone()),
                            _ => None,
                        });
                let Some(r) = target else {
                    out::err("Сначала найдите роутер: upnp find.");
                    return;
                };
                match self.node.upnp_forget(&r) {
                    Ok(()) => out::line("Роутер убран из разрешённых."),
                    Err(e) => fail(e),
                }
            }
            _ => out::err("Использование: upnp find | upnp allow [--permanent] | upnp forget"),
        }
    }

    fn cmd_clock(&mut self, args: &[String]) {
        match args {
            [a] if a == "sync" => {
                out::line("Сверяю часы с серверами времени.");
                match self.node.sync_clock() {
                    Ok(ClockSync::Applied { offset_ms }) => {
                        out::line(&format!("Часы сверены, поправка {offset_ms} мс."));
                    }
                    Ok(ClockSync::NeedsConfirm(p)) => {
                        out::line(&format!(
                            "Время на этом компьютере отличается больше чем на 5 минут \
                             (поправка {} с). Если уверены, что неверны именно ваши часы: \
                             clock confirm.",
                            p.offset_ms() / 1000
                        ));
                        self.proposal = Some(p);
                    }
                    Ok(_) => {}
                    Err(e) => fail(e),
                }
            }
            [a] if a == "confirm" => match self.proposal.take() {
                Some(p) => match self.node.confirm_clock(p) {
                    Ok(()) => out::line("Поправка применена."),
                    Err(e) => fail(e),
                },
                None => out::err("Нет поправки для подтверждения. Сначала: clock sync."),
            },
            [a] if a == "reset" => {
                self.proposal = None;
                match self.node.reset_clock() {
                    Ok(()) => out::line("Поправка сброшена."),
                    Err(e) => fail(e),
                }
            }
            _ => out::err("Использование: clock sync | clock confirm | clock reset"),
        }
    }
}

fn abs(p: &str) -> PathBuf {
    std::path::absolute(p).unwrap_or_else(|_| PathBuf::from(p))
}

fn space_text(needed: u64, available: Option<u64>) -> String {
    let have = available.map_or_else(|| "неизвестно".to_owned(), human_size);
    format!(
        "Не хватает места для приёма: нужно {}, свободно {have}. {CHOOSE_OTHER_FOLDER_TEXT}",
        human_size(needed)
    )
}
