//! Работа фонового потока с узлом по командам главного окна (экраны 2-6) и построение снимков.
//! Как и `worker.rs`, выполняется только на фоновом потоке. Локальные номера (`Id`) нужны,
//! чтобы окно и модель не держали непрозрачные ссылки ядра.

use std::collections::HashMap;
use std::hash::Hash;

use chervo_core::{
    ClockProposal, ClockSync, FriendRef, FriendStatus, FriendsError, InviteRef, NoDirectPath, Node,
    NodeError, NodeEvent, PathKind, RouterCandidate, Side, TransferRef, TransferState,
    TrustConfirmation,
};

use crate::model::{ClockResult, Command, FriendEventKind, Outcome, Snapshot};
use crate::rows::{
    DiagRow, FileRow, FriendRow, Id, OfferRow, RetiredRow, RouterRow, SettingsRow, TransferRow,
};
use crate::update_worker::{UpdateJob, UpdateWorker};

/// Как долго держится построенное предложение (имена не меняются, место на диске обновляется).
const OFFER_TTL: std::time::Duration = std::time::Duration::from_secs(5);

/// Кэш построенных предложений. Метка времени ставится только при построении (`put`), попадание
/// её не продлевает: иначе при частых событиях запись не устаревала бы и строка о месте на диске
/// навсегда осталась бы прежней.
#[derive(Default)]
pub struct OfferCache {
    rows: HashMap<u32, (std::time::Instant, OfferRow)>,
}

impl OfferCache {
    pub fn get(&self, id: Id, now: std::time::Instant) -> Option<OfferRow> {
        self.rows
            .get(&id.0)
            .filter(|(built, _)| now.saturating_duration_since(*built) < OFFER_TTL)
            .map(|(_, row)| row.clone())
    }

    pub fn put(&mut self, id: Id, built: std::time::Instant, row: OfferRow) {
        self.rows.insert(id.0, (built, row));
    }

    /// Оставить только предложения, которые ещё ждут ответа.
    pub fn retain_ids(&mut self, keep: impl Fn(u32) -> bool) {
        self.rows.retain(|k, _| keep(*k));
    }
}

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

impl Refs {
    pub fn router_id(&mut self, c: &RouterCandidate) -> Id {
        let i = match self.routers.iter().position(|r| r == c) {
            Some(i) => i,
            None => {
                self.routers.push(c.clone());
                self.routers.len() - 1
            }
        };
        Id(u32::try_from(i).unwrap_or(u32::MAX))
    }

    /// Роутер по номеру, только если он и сейчас есть среди разрешённых. Иначе `None`:
    /// действие по устаревшему номеру не выполняется.
    pub fn approved_router(&self, node: &Node, id: Id) -> Option<RouterCandidate> {
        let c = self.routers.get(id.0 as usize)?;
        node.settings()
            .routers
            .iter()
            .any(|r| &r.router == c)
            .then(|| c.clone())
    }
}

#[derive(Default)]
pub struct Refs {
    pub friends: Table<FriendRef>,
    pub transfers: Table<TransferRef>,
    pub invites: Table<InviteRef>,
    /// Роутер, найденный кнопкой «Найти роутер» и ожидающий ответа «да/нет».
    pub found_router: Option<RouterCandidate>,
    /// Роутеры, которые окно видело: номер это место в этом списке, он только растёт, а сам
    /// роутер при выполнении действия ищется по равенству в текущих настройках узла.
    pub routers: Vec<RouterCandidate>,
    /// Построенные предложения: номер передачи -> (когда построено, строка).
    pub offers: OfferCache,
    /// Поправка часов больше 5 минут, ждущая подтверждения.
    pub clock_proposal: Option<ClockProposal>,
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
    let friends: Vec<FriendRow> = fviews
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
        if t.side == Side::Receiver && t.state == TransferState::AwaitingUser {
            // план приёма (имена, типы) считается узлом дорого: берём из кэша, пока он свежий
            // (место на диске при этом тоже обновляется не реже, чем раз в `OFFER_TTL`)
            let cached = refs.offers.get(id, std::time::Instant::now());
            let hit = cached.is_some();
            let row = match cached {
                Some(row) => Some(row),
                None => node.offer(t.transfer).ok().map(|o| OfferRow {
                    id,
                    friend: String::new(),
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
                }),
            };
            if let Some(mut row) = row {
                row.friend = friend.clone();
                // кэш обновляется только после нового построения, не после попадания
                if !hit {
                    refs.offers.put(id, std::time::Instant::now(), row.clone());
                }
                offers.push(row);
            }
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
    refs.offers
        .retain_ids(|k| offers.iter().any(|o: &OfferRow| o.id.0 == k));
    let active_transfers = transfers.iter().filter(|t| t.is_active()).count();
    let diagnoses = diagnoses(node, refs, &friends);
    let retired = node
        .retired()
        .into_iter()
        .map(|(f, t)| RetiredRow {
            id: refs.friends.id(f),
            friend: names.get(&f).cloned().unwrap_or_default(),
            text: t.as_str().to_owned(),
        })
        .collect();
    let sv = node.settings();
    let settings = SettingsRow {
        port: sv.port,
        receive_root: sv.receive_root,
        extra_roots: sv.extra_roots,
        min_free_percent: sv.min_free_percent,
        manual_forward: sv.manual_forward,
        routers: sv
            .routers
            .iter()
            .map(|r| RouterRow {
                id: refs.router_id(&r.router),
                permanent_ok: r.permanent_ok,
                needs_permanent: r.needs_permanent,
            })
            .collect(),
        clock_offset_ms: sv.clock_offset_ms,
        ntp_servers: sv.ntp_servers,
        key_store: sv.key_store,
        restart_needed: sv.restart_needed,
        update_consent: sv.update_consent,
    };
    Snapshot {
        friends,
        transfers,
        offers,
        active_transfers,
        settings: Some(settings),
        nat: Some(node.nat_view()),
        mapping: node.mapping_status(),
        retired,
        diagnoses,
    }
}

/// Диагноз для каждого активного друга, с которым нет соединения.
fn diagnoses(node: &Node, refs: &Refs, friends: &[FriendRow]) -> Vec<DiagRow> {
    let mut out = Vec::new();
    for f in friends {
        if f.status != FriendStatus::Active || f.key_problem || f.online {
            continue;
        }
        let Some(r) = refs.friends.get(f.id) else {
            continue;
        };
        if let Ok(Some(d)) = node.diagnose(r) {
            out.push(DiagRow {
                friend: f.id,
                text: d.text,
                could_help: d.rendezvous_could_help,
                lan_hint: lan_hint(f.path, d.reason),
            });
        }
    }
    out
}

/// Последний путь был по локальной сети, а адрес для звонка пропал или не отвечает: частные
/// адреса живут сутки (16а, Q1), нужен токен с отметкой «мы в одной сети».
pub fn lan_hint(last_path: Option<PathKind>, reason: NoDirectPath) -> bool {
    last_path == Some(PathKind::Lan)
        && matches!(
            reason,
            NoDirectPath::NoKnownAddress | NoDirectPath::NeedToken | NoDirectPath::Unknown
        )
}

/// Событие узла -> ответ окну. `None`: событие только повод обновить снимок.
pub fn event_outcome(node: Option<&Node>, refs: &mut Refs, ev: NodeEvent) -> Outcome {
    let view = |f: FriendRef| {
        node.and_then(|n| n.friends().into_iter().find(|v| v.friend == f))
            .map(|v| (v.name, v.last_path))
    };
    match ev {
        NodeEvent::FriendKeyProblem { friend } => Outcome::FriendEvent {
            name: view(friend).map(|v| v.0).unwrap_or_default(),
            kind: FriendEventKind::KeyProblem,
        },
        NodeEvent::ClockSkewSuspected { friend } => Outcome::FriendEvent {
            name: view(friend).map(|v| v.0).unwrap_or_default(),
            kind: FriendEventKind::ClockSkew,
        },
        NodeEvent::Unreachable { friend, diagnosis } => {
            let (name, path) = view(friend).unwrap_or_default();
            Outcome::FriendEvent {
                name,
                kind: FriendEventKind::Unreachable {
                    text: diagnosis.text,
                    lan_hint: lan_hint(path, diagnosis.reason),
                },
            }
        }
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

/// Один такт проверки новых версий (фон раз в час и кнопка «Проверить сейчас»). Время ядро
/// берёт само; окно и этот код времени не передают и не подставляют. Разрешение на запрос
/// выдаёт только узел и только при записанном согласии. `manual`: итог нужен окну всегда,
/// для фона `None` значит «ничего не делаем».
pub fn update_tick(node: &Node, updates: &UpdateWorker, manual: bool) -> Option<Outcome> {
    let skipped = || manual.then_some(Outcome::UpdateSkipped);
    // номер своей версии берём до разрешения: разрешение тратится только на настоящий запрос
    let Some(running) = chervo_core::update::running_version() else {
        return skipped();
    };
    match node.update_check_permit(manual) {
        Ok(Some(permit)) => {
            let job = UpdateJob::Check {
                permit,
                running,
                manual,
            };
            if updates.send(job) {
                Some(Outcome::UpdateCheckStarted { manual })
            } else {
                skipped()
            }
        }
        Ok(None) | Err(_) => skipped(),
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
        Command::SetReceiveRoot {
            root,
            confirm_shared,
        } => Some(Outcome::RootSet(
            node.set_receive_root(&root, confirm_shared),
        )),
        Command::SetMinFree(p) => done(node.set_min_free_percent(p)),
        Command::SetPort(p) => done(node.set_port(p)),
        Command::SetManualForward(p) => done(node.set_manual_forward(p)),
        // кнопка «Найти роутер»: сам узел это не делает
        Command::UpnpIdentify => {
            let r = node.upnp_identify().map(|c| {
                refs.found_router = Some(c);
            });
            Some(Outcome::UpnpFound(r))
        }
        Command::UpnpAllow { router, permanent } => {
            let candidate = match router {
                None => refs.found_router.clone(),
                Some(i) => refs.approved_router(node, i),
            };
            let r = match candidate {
                Some(c) => node.upnp_allow(&c, permanent),
                None => Err(unknown()),
            };
            if r.is_ok() && router.is_none() {
                refs.found_router = None;
            }
            done(r)
        }
        Command::UpnpForget(i) => {
            let candidate = refs.approved_router(node, i);
            done(match candidate {
                Some(c) => node.upnp_forget(&c),
                None => Err(unknown()),
            })
        }
        Command::RefreshMapping => {
            node.refresh_mapping();
            done(Ok(()))
        }
        // кнопка «Сверить часы»: автоматической сверки нет
        Command::SyncClock => {
            let r = node.sync_clock().map(|s| match s {
                ClockSync::Applied { offset_ms } => ClockResult::Applied(offset_ms),
                ClockSync::NeedsConfirm(p) => {
                    let ms = p.offset_ms();
                    refs.clock_proposal = Some(p);
                    ClockResult::NeedsConfirm(ms)
                }
                _ => ClockResult::Applied(0),
            });
            Some(Outcome::ClockSynced(r))
        }
        Command::ConfirmClock => done(match refs.clock_proposal.take() {
            Some(p) => node.confirm_clock(p),
            None => Err(unknown()),
        }),
        Command::ResetClock => done(node.reset_clock()),
        Command::ForgetRetired(id) => done(match refs.friends.get(id) {
            Some(f) => node.forget_retired(f),
            None => Err(unknown()),
        }),
        // ответ на вопрос о проверке новых версий; сам по себе ничего не отправляет
        Command::SetUpdateConsent(enabled) => Some(Outcome::UpdateConsentSet {
            enabled,
            result: node.set_update_consent(enabled),
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chervo_core::SpaceView;
    use std::time::{Duration, Instant};

    fn row() -> OfferRow {
        OfferRow {
            id: Id(1),
            friend: String::new(),
            files: Vec::new(),
            total: 0,
            space: SpaceView {
                needed: 1,
                available: Some(2),
                short: false,
            },
            needs_question: false,
            warnings: Vec::new(),
        }
    }

    #[test]
    fn cache_hit_does_not_extend_the_ttl() {
        let t0 = Instant::now();
        let mut c = OfferCache::default();
        c.put(Id(1), t0, row());
        // частые попадания внутри срока ничего не продлевают (get только читает)
        for secs in [1, 2, 3, 4] {
            assert!(c.get(Id(1), t0 + Duration::from_secs(secs)).is_some());
        }
        // срок считается от построения: на 6-й секунде запись устарела
        assert!(
            c.get(Id(1), t0 + OFFER_TTL + Duration::from_secs(1))
                .is_none()
        );
        // после нового построения срок начинается заново
        let t1 = t0 + Duration::from_secs(6);
        c.put(Id(1), t1, row());
        assert!(c.get(Id(1), t1 + Duration::from_secs(4)).is_some());
        assert!(c.get(Id(1), t1 + OFFER_TTL).is_none());
    }

    #[test]
    fn cache_drops_finished_offers() {
        let t0 = Instant::now();
        let mut c = OfferCache::default();
        c.put(Id(1), t0, row());
        c.retain_ids(|_| false);
        assert!(c.get(Id(1), t0).is_none());
    }
}
