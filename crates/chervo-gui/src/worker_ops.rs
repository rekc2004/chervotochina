//! Работа фонового потока с узлом по командам главного окна (экраны 2-6) и построение снимков.
//! Как и `worker.rs`, выполняется только на фоновом потоке. Локальные номера (`Id`) нужны,
//! чтобы окно и модель не держали непрозрачные ссылки ядра.

use std::collections::HashMap;
use std::hash::Hash;

use chervo_core::{
    FriendRef, FriendsError, InviteRef, Node, NodeError, NodeEvent, Side, TransferRef,
    TransferState, TrustConfirmation,
};

use crate::model::{Command, Outcome, Snapshot};
use crate::rows::{FileRow, FriendRow, Id, OfferRow, TransferRow};

/// Таблица «ссылка ядра <-> локальный номер».
pub struct Table<T: Copy + Eq + Hash> {
    next: u32,
    by_id: HashMap<u32, T>,
    by_ref: HashMap<T, u32>,
}

impl<T: Copy + Eq + Hash> Default for Table<T> {
    fn default() -> Self {
        Self {
            next: 1,
            by_id: HashMap::new(),
            by_ref: HashMap::new(),
        }
    }
}

impl<T: Copy + Eq + Hash> Table<T> {
    pub fn id(&mut self, r: T) -> Id {
        if let Some(i) = self.by_ref.get(&r) {
            return Id(*i);
        }
        let i = self.next;
        self.next = self.next.wrapping_add(1);
        self.by_id.insert(i, r);
        self.by_ref.insert(r, i);
        Id(i)
    }

    pub fn get(&self, id: Id) -> Option<T> {
        self.by_id.get(&id.0).copied()
    }
}

#[derive(Default)]
pub struct Refs {
    pub friends: Table<FriendRef>,
    pub transfers: Table<TransferRef>,
    pub invites: Table<InviteRef>,
}

fn unknown() -> NodeError {
    NodeError::Friends(FriendsError::UnknownPair)
}

fn friend_name(node: &Node, f: FriendRef) -> String {
    node.friends()
        .into_iter()
        .find(|v| v.friend == f)
        .map(|v| v.name)
        .unwrap_or_default()
}

/// Снимок для окна: друзья, передачи и предложения, ждущие ответа.
pub fn snapshot(node: &Node, refs: &mut Refs) -> Snapshot {
    let fviews = node.friends();
    let names: HashMap<FriendRef, String> =
        fviews.iter().map(|v| (v.friend, v.name.clone())).collect();
    let friends = fviews
        .into_iter()
        .map(|v| FriendRow {
            id: refs.friends.id(v.friend),
            name: v.name,
            status: v.state,
            online: v.online,
            auto_accept: v.auto_accept,
            key_problem: v.key_problem,
            path: v.last_path,
        })
        .collect();
    let tviews = node.transfers();
    let mut transfers = Vec::new();
    let mut offers = Vec::new();
    for t in tviews {
        let id = refs.transfers.id(t.transfer);
        let friend = names.get(&t.friend).cloned().unwrap_or_default();
        if t.side == Side::Receiver
            && t.state == TransferState::AwaitingUser
            && let Ok(o) = node.offer(t.transfer)
        {
            offers.push(OfferRow {
                id,
                friend: friend.clone(),
                files: o
                    .files
                    .iter()
                    .map(|f| FileRow {
                        name: f.name.clone(),
                        size: f.size,
                        kind: f.kind,
                        needs_question: f.needs_question,
                    })
                    .collect(),
                total: o.total,
                space: o.space,
                needs_question: o.needs_question,
                warnings: o.warnings.clone(),
            });
        }
        transfers.push(TransferRow {
            id,
            friend,
            side: t.side,
            state: t.state,
            done: t.done,
            total: t.total,
            pause: t.pause,
            preparing: t.preparing,
            result: t.result,
            dest_root: t.dest_root,
        });
    }
    let active_transfers = transfers.iter().filter(|t| t.is_active()).count();
    Snapshot {
        friends,
        transfers,
        offers,
        active_transfers,
    }
}

/// Событие узла -> ответ окну. `None`: событие только повод обновить снимок.
pub fn event_outcome(refs: &mut Refs, ev: NodeEvent) -> Outcome {
    match ev {
        NodeEvent::InviteSas { invite, sas } => Outcome::InviteSas {
            invite: refs.invites.id(invite),
            digits: sas.digits(),
            spoken: sas.spoken(),
        },
        NodeEvent::InviteFinished { outcome, .. } => Outcome::InviteFinished(outcome),
        NodeEvent::OfferIncoming { .. } => Outcome::OfferIncoming,
        NodeEvent::OfferAutoAccepted { .. } => Outcome::AutoAccepted,
        other => Outcome::Event(other),
    }
}

/// Выполняет команду главного окна. Остальные команды (запуск, остановка) обрабатывает
/// `worker.rs`.
pub fn exec(node: &Node, refs: &mut Refs, cmd: Command) -> Option<Outcome> {
    let done = |r: Result<(), NodeError>| Some(Outcome::Done(r));
    match cmd {
        Command::CreateInvite {
            same_network,
            manual,
        } => {
            let r = node
                .create_invite(same_network, manual)
                .map(|(i, t)| (refs.invites.id(i), t.as_str().to_owned()));
            Some(Outcome::InviteCreated(r))
        }
        Command::AcceptInvite(text) => {
            let r = node.accept_invite(&text).map(|i| refs.invites.id(i));
            Some(Outcome::InviteAccepted(r))
        }
        Command::ConfirmSas { invite, yes, name } => {
            let r = match refs.invites.get(invite) {
                Some(i) => node.confirm_sas(i, yes, &name),
                None => Err(unknown()),
            };
            Some(Outcome::SasAnswered(r))
        }
        Command::CancelInvite(id) => done(match refs.invites.get(id) {
            Some(i) => node.cancel_invite(i),
            None => Err(unknown()),
        }),
        Command::Rename { friend, name } => done(match refs.friends.get(friend) {
            Some(f) => node.rename(f, &name),
            None => Err(unknown()),
        }),
        Command::Block(id) => done(match refs.friends.get(id) {
            Some(f) => node.block(f),
            None => Err(unknown()),
        }),
        Command::Unblock(id) => done(match refs.friends.get(id) {
            Some(f) => node.unblock(f),
            None => Err(unknown()),
        }),
        Command::Remove(id) => match refs.friends.get(id) {
            Some(f) => {
                let name = friend_name(node, f);
                let text = node.remove(f).map(|o| o.map(|t| t.as_str().to_owned()));
                Some(Outcome::Revocation {
                    friend: name,
                    text,
                    rekey: false,
                })
            }
            None => done(Err(unknown())),
        },
        Command::Rekey(id) => match refs.friends.get(id) {
            Some(f) => {
                let name = friend_name(node, f);
                let text = node.rekey(f).map(|t| Some(t.as_str().to_owned()));
                Some(Outcome::Revocation {
                    friend: name,
                    text,
                    rekey: true,
                })
            }
            None => done(Err(unknown())),
        },
        Command::RekeyAll => {
            let names: HashMap<FriendRef, String> = node
                .friends()
                .into_iter()
                .map(|v| (v.friend, v.name))
                .collect();
            let mut items = Vec::new();
            let mut failed = 0;
            for (f, r) in node.rekey_all() {
                match r {
                    Ok(t) => items.push((
                        names.get(&f).cloned().unwrap_or_default(),
                        t.as_str().to_owned(),
                    )),
                    Err(_) => failed += 1,
                }
            }
            Some(Outcome::RekeyAll { items, failed })
        }
        // вызывается только по команде, а команда рождается только после ответа «да» на вопрос
        Command::EnableAutoAccept(id) => done(match refs.friends.get(id) {
            Some(f) => node.enable_auto_accept(f, TrustConfirmation::user_confirmed_trust()),
            None => Err(unknown()),
        }),
        Command::DisableAutoAccept(id) => done(match refs.friends.get(id) {
            Some(f) => node.disable_auto_accept(f),
            None => Err(unknown()),
        }),
        Command::IssueAddrToken {
            friend,
            same_network,
        } => {
            let r = match refs.friends.get(friend) {
                Some(f) => node
                    .issue_addr_update_text(f, same_network)
                    .map(|t| t.as_str().to_owned()),
                None => Err(unknown()),
            };
            Some(Outcome::AddrToken(r))
        }
        Command::ApplyAddrToken(text) => {
            let r = node.apply_addr_update_text(&text).map(|_| ());
            Some(Outcome::AddrApplied(r))
        }
        // кнопка «Соединить»: сам узел это не делает
        Command::ConnectNow(id) => done(match refs.friends.get(id) {
            Some(f) => node.connect_now(f),
            None => Err(unknown()),
        }),
        Command::Send { friend, paths } => {
            let r = match refs.friends.get(friend) {
                Some(f) => node.send(f, &paths).map(|t| {
                    refs.transfers.id(t);
                }),
                None => Err(unknown()),
            };
            Some(Outcome::Sent(r))
        }
        Command::Accept(id) => done(match refs.transfers.get(id) {
            Some(t) => node.accept(t),
            None => Err(unknown()),
        }),
        Command::AcceptInto { transfer, root } => done(match refs.transfers.get(transfer) {
            Some(t) => node.accept_into(t, &root),
            None => Err(unknown()),
        }),
        Command::Decline(id) => done(match refs.transfers.get(id) {
            Some(t) => node.decline(t),
            None => Err(unknown()),
        }),
        Command::CancelTransfer(id) => done(match refs.transfers.get(id) {
            Some(t) => node.cancel(t),
            None => Err(unknown()),
        }),
        Command::Retry(id) => done(match refs.transfers.get(id) {
            Some(t) => node.retry(t),
            None => Err(unknown()),
        }),
        _ => None,
    }
}
