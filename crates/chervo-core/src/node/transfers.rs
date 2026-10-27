//! Передачи, приём и настройки приёма (этап 18а, A4.1-A4.5).
//!
//! Предложение показывается человеку только по ПЛАНУ приёма (`plan_offer_for_root`): имена уже
//! санитизированы (нет bidi, нулевой ширины, `..`, зарезервированных имён), а недоверенное имя
//! (`UntrustedName`) из ядра не выходит.

use std::path::{Path, PathBuf};

use chervo_receive::{
    ACTIVE_DOC_TEXT, DECEPTIVE_TEXT, DISK_IMAGE_TEXT, EXECUTABLE_TEXT, LONG_PATH_TEXT,
    NAME_CHANGED_TEXT, SUSPICIOUS_NAME_TEXT,
};
use chervo_receive::{
    AcceptIntoError, ChooseRootError, FileClass, NameFlags, ReceiveLimits, ReceiveRoot, SpaceCheck,
    accept_into, classify, disk_space, is_known_inert, plan_offer_for_root,
};
use chervo_timesync::SyncConfig;
use chervo_transfer::{Side, TransferError, TransferState};

use super::Node;
use super::core::{TEntry, lock};
use super::error::NodeError;
use super::folder;
use super::settings::{self, Settings};
use super::views::{
    FileKind, FriendRef, IncomingOffer, NodeWarning, OfferFile, RouterCandidate, RouterView,
    SettingsView, SpaceView, TransferRef, TransferView, path_for_display,
};

fn kind_of(p: &chervo_receive::SafeRelPath) -> (FileKind, bool, bool) {
    let info = classify(p);
    let inert = is_known_inert(p);
    let kind = if inert {
        FileKind::Safe
    } else if info.class != FileClass::Ordinary {
        FileKind::ExecutableLike
    } else {
        FileKind::Unknown
    };
    (kind, info.deceptive, !inert)
}

fn flags_changed(f: NameFlags) -> bool {
    f.changed || f.suspicious || f.renamed_in_offer
}

/// Предупреждения по плану предложения: тексты этапа 15 в порядке опасности.
fn warnings_of(plan: &chervo_receive::OfferPlan) -> Vec<&'static str> {
    let has_class = |c: FileClass| plan.files.iter().any(|f| f.kind.class == c);
    let mut w = Vec::new();
    if has_class(FileClass::Executable) {
        w.push(EXECUTABLE_TEXT);
    }
    if plan.any_deceptive {
        w.push(DECEPTIVE_TEXT);
    }
    if has_class(FileClass::DiskImage) {
        w.push(DISK_IMAGE_TEXT);
    }
    if has_class(FileClass::ActiveDocument) {
        w.push(ACTIVE_DOC_TEXT);
    }
    if plan.files.iter().any(|f| f.flags.suspicious) {
        w.push(SUSPICIOUS_NAME_TEXT);
    }
    if plan
        .files
        .iter()
        .any(|f| f.flags.changed || f.flags.renamed_in_offer)
    {
        w.push(NAME_CHANGED_TEXT);
    }
    if plan.files.iter().any(|f| f.flags.long_path) {
        w.push(LONG_PATH_TEXT);
    }
    w
}

/// Лимиты для плана: недопустимые заменяются значениями по умолчанию, как в политике приёма.
fn effective_limits(l: ReceiveLimits) -> ReceiveLimits {
    if l.validate().is_ok() {
        l
    } else {
        ReceiveLimits::default()
    }
}

/// Вид предложения по плану и месту (без обращения к `Transfers`, для проверки таблицей).
pub(crate) fn offer_files(plan: &chervo_receive::OfferPlan) -> Vec<OfferFile> {
    plan.files
        .iter()
        .map(|pf| {
            let (kind, deceptive, needs_question) = kind_of(&pf.path);
            OfferFile {
                index: pf.index,
                name: pf.path.display(),
                size: pf.size,
                kind,
                deceptive,
                needs_question,
                name_changed: flags_changed(pf.flags),
            }
        })
        .collect()
}

impl Node {
    /// Отправить файлы и папки другу. Папки раскрываются здесь: ссылки не разворачиваются,
    /// имена идут относительными через `/`, глубина и число файлов ограничены.
    pub fn send(&self, friend: FriendRef, paths: &[PathBuf]) -> Result<TransferRef, NodeError> {
        let files = folder::expand(paths, ReceiveLimits::default().max_depth)?;
        let key = self.core.transfers.send(friend.inner(), files)?;
        lock(&self.core.reg).entry(key, Side::Sender);
        Ok(TransferRef::new(key))
    }

    /// Предложение, ожидающее ответа человека: только санитизированные имена.
    pub fn offer(&self, transfer: TransferRef) -> Result<IncomingOffer, NodeError> {
        let key = *transfer.inner();
        let ov = self
            .core
            .transfers
            .offer(&key)
            .ok_or(NodeError::Transfer(TransferError::NoSuchTransfer))?;
        let limits = effective_limits(self.core.rcfg.limits);
        let plan = plan_offer_for_root(&ov.files, &limits, &self.core.root)
            .map_err(|_| NodeError::Transfer(TransferError::BadName))?;
        let files = offer_files(&plan);
        let min_free = self.core.rcfg.min_free_percent;
        let space = match self.core.policy.space_check(&ov) {
            SpaceCheck::Short(s) => SpaceView {
                needed: s.needed,
                available: Some(s.available),
                short: true,
            },
            SpaceCheck::Fits => {
                let d = disk_space(self.core.root.root());
                SpaceView {
                    needed: d.map_or(plan.total, |d| d.needed(plan.total, min_free)),
                    available: d.map(|d| d.available_bytes),
                    short: false,
                }
            }
            SpaceCheck::Unknown => SpaceView {
                needed: plan.total,
                available: None,
                short: false,
            },
        };
        Ok(IncomingOffer {
            transfer,
            friend: FriendRef::new(key.pair),
            needs_question: files.iter().any(|f| f.needs_question),
            warnings: warnings_of(&plan),
            files,
            total: plan.total,
            space,
        })
    }

    /// Принять в основную папку приёма.
    pub fn accept(&self, transfer: TransferRef) -> Result<(), NodeError> {
        let key = *transfer.inner();
        lock(&self.core.reg).entry(key, Side::Receiver).dest_root =
            Some(self.core.root.root().to_path_buf());
        self.core.transfers.respond(&key, true)?;
        Ok(())
    }

    /// Принять в другую папку (когда в основной не хватает места). Папка проверяется, место на
    /// её томе тоже. После успешного приёма канонический путь запоминается в настройках
    /// (`extra_root`), чтобы после перезапуска передача нашлась; список полон: `LimitReached`
    /// ещё до приёма. Не удалось записать настройки: приём состоялся, придёт
    /// `Warning(SettingsNotSaved)`.
    pub fn accept_into(&self, transfer: TransferRef, root: &Path) -> Result<(), NodeError> {
        let key = *transfer.inner();
        let mut rc = self.core.rcfg.clone();
        rc.root = root.to_path_buf();
        rc.allow_shared_root |= lock(&self.core.settings).shared_root_confirmed;
        let target = ReceiveRoot::open(&rc).map_err(NodeError::ReceiveRoot)?;
        let target_root = target.root().to_path_buf();
        let is_primary = target.root() == self.core.root.root();
        let known =
            |s: &Settings| s.receive_root == target_root || s.extra_roots.contains(&target_root);
        if !is_primary {
            let s = lock(&self.core.settings);
            if !known(&s) && 1 + s.extra_roots.len() >= settings::MAX_ROOTS {
                return Err(NodeError::LimitReached);
            }
        }
        accept_into(&self.core.transfers, &self.core.placement, &key, target).map_err(
            |e| match e {
                AcceptIntoError::NoSuchOffer => NodeError::Transfer(TransferError::NoSuchTransfer),
                AcceptIntoError::Root(ChooseRootError::Insufficient(_)) => NodeError::NoSpace,
                AcceptIntoError::Root(ChooseRootError::Plan(_)) => {
                    NodeError::Transfer(TransferError::BadName)
                }
                AcceptIntoError::Transfer(t) => NodeError::from(t),
                _ => NodeError::Io,
            },
        )?;
        lock(&self.core.reg).entry(key, Side::Receiver).dest_root = Some(target_root.clone());
        if !is_primary {
            let saved = self.update_settings(|s| {
                if !known(s) {
                    if 1 + s.extra_roots.len() >= settings::MAX_ROOTS {
                        return Err(NodeError::LimitReached);
                    }
                    s.extra_roots.push(target_root.clone());
                }
                Ok(())
            });
            if saved.is_err() {
                self.core.warn(NodeWarning::SettingsNotSaved);
            }
        }
        Ok(())
    }

    pub fn decline(&self, transfer: TransferRef) -> Result<(), NodeError> {
        self.core.transfers.respond(transfer.inner(), false)?;
        Ok(())
    }

    pub fn cancel(&self, transfer: TransferRef) -> Result<(), NodeError> {
        self.core.transfers.cancel(transfer.inner())?;
        Ok(())
    }

    /// «Повторить» для приостановленной входящей передачи (диск, ввод-вывод, молчание
    /// отправителя) или попробовать соединение сейчас.
    pub fn retry(&self, transfer: TransferRef) -> Result<(), NodeError> {
        self.core.transfers.retry(transfer.inner())?;
        Ok(())
    }

    /// Снимок передач (по порядку появления).
    pub fn transfers(&self) -> Vec<TransferView> {
        let mut rows: Vec<(chervo_transfer::TransferKey, TEntrySnap)> = {
            let reg = lock(&self.core.reg);
            reg.transfers
                .iter()
                .map(|(k, e)| (*k, TEntrySnap::of(e)))
                .collect()
        };
        rows.sort_by_key(|(_, e)| e.seq);
        rows.into_iter()
            .map(|(key, e)| {
                let st = self.core.transfers.status(&key);
                let (state, done, total) = match st {
                    Some(s) => (s.state, s.done, s.total),
                    None => (TransferState::Finished, e.done, e.total),
                };
                TransferView {
                    transfer: TransferRef::new(key),
                    friend: FriendRef::new(key.pair),
                    side: st.map_or(e.side, |s| s.side),
                    state,
                    done,
                    total,
                    pause: match state {
                        TransferState::Paused(r) => Some(r),
                        _ => e.pause,
                    },
                    preparing: e.preparing,
                    result: e.result,
                    dest_root: e.dest_root.as_deref().map(path_for_display),
                }
            })
            .collect()
    }

    // ---------------------------------------------------------------- настройки

    pub(crate) fn update_settings(
        &self,
        f: impl FnOnce(&mut Settings) -> Result<(), NodeError>,
    ) -> Result<(), NodeError> {
        let mut g = lock(&self.core.settings);
        let mut next = g.clone();
        f(&mut next)?;
        settings::save(&self.core.dir, &next)?;
        *g = next;
        Ok(())
    }

    /// Сменить основную папку приёма (вступает в силу после перезапуска). Прежняя основная
    /// остаётся среди дополнительных. Вне профиля Windows нужно `confirm_shared_root`.
    pub fn set_receive_root(
        &self,
        root: &Path,
        confirm_shared_root: bool,
    ) -> Result<(), NodeError> {
        let mut rc = self.core.rcfg.clone();
        rc.root = root.to_path_buf();
        rc.allow_shared_root |= confirm_shared_root;
        ReceiveRoot::open(&rc).map_err(NodeError::ReceiveRoot)?;
        self.update_settings(|s| settings::replace_root(s, root, confirm_shared_root))
    }

    /// Запас свободного места после приёма, процентов объёма тома (0..=100). Вступает в силу
    /// после перезапуска.
    pub fn set_min_free_percent(&self, percent: u8) -> Result<(), NodeError> {
        if percent > 100 {
            return Err(NodeError::InvalidValue);
        }
        self.update_settings(|s| {
            s.min_free_percent = percent;
            Ok(())
        })
    }

    /// Порт UDP (1024..=65535). Вступает в силу после перезапуска.
    pub fn set_port(&self, port: u16) -> Result<(), NodeError> {
        if port < settings::MIN_USER_PORT {
            return Err(NodeError::InvalidValue);
        }
        self.update_settings(|s| {
            s.port = port;
            Ok(())
        })
    }

    /// Внешний порт ручного проброса (`None`: нет). Вступает в силу после перезапуска.
    pub fn set_manual_forward(&self, port: Option<u16>) -> Result<(), NodeError> {
        if port == Some(0) {
            return Err(NodeError::InvalidValue);
        }
        self.update_settings(|s| {
            s.manual_forward = port;
            Ok(())
        })
    }

    /// Снимок настроек.
    pub fn settings(&self) -> SettingsView {
        let s = lock(&self.core.settings).clone();
        let live = &self.core.live;
        let restart_needed = s.port != live.port_setting
            || s.receive_root != live.receive_root
            || s.min_free_percent != live.min_free_percent
            || s.manual_forward != live.manual_forward;
        let ntp_servers = if s.ntp_servers.is_empty() {
            SyncConfig::default().servers
        } else {
            s.ntp_servers.clone()
        };
        SettingsView {
            port: s.port,
            receive_root: path_for_display(&s.receive_root),
            shared_root_confirmed: s.shared_root_confirmed,
            extra_roots: s.extra_roots.iter().map(|p| path_for_display(p)).collect(),
            min_free_percent: s.min_free_percent,
            invite_ttl_secs: s.invite_ttl_secs,
            manual_forward: s.manual_forward,
            routers: s
                .routers
                .iter()
                .map(|r| RouterView {
                    router: RouterCandidate(r.id.clone()),
                    permanent_ok: r.permanent_ok,
                })
                .collect(),
            clock_offset_ms: s.clock_offset_ms,
            clock_offset_at: s.clock_offset_at,
            ntp_servers,
            key_store: self.core.store.kind(),
            restart_needed,
        }
    }
}

/// Копия полей записи для сборки вида без удержания замка.
struct TEntrySnap {
    side: Side,
    done: u64,
    total: u64,
    pause: Option<chervo_transfer::PauseReason>,
    preparing: Option<(u64, u64)>,
    result: Option<super::views::TransferResult>,
    dest_root: Option<PathBuf>,
    seq: u64,
}

impl TEntrySnap {
    fn of(e: &TEntry) -> Self {
        Self {
            side: e.side,
            done: e.done,
            total: e.total,
            pause: e.pause,
            preparing: e.preparing,
            result: e.result,
            dest_root: e.dest_root.clone(),
            seq: e.seq,
        }
    }
}
