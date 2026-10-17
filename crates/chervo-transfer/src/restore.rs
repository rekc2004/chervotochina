//! Загрузка недокачанных передач при запуске: просмотр `partial_dir`, проверка состояния.
//! С диска не доверяется ничего: состояние ограничено и проверено контрольной суммой, список
//! хэшей воспроизводит корень, пара берётся из соединения при возобновлении, а готовые блоки
//! перехэшируются перед использованием.

use std::path::Path;
use std::sync::Arc;

use crate::hash::FileRoot;
use crate::layout::{Layout, layout};
use crate::names::TransferKey;
use crate::paths::{
    list_session_dirs, read_hashes, read_state, remove_part_and_hashes, remove_session, session_dir,
};
use crate::receiver::RecvSession;
use crate::sched::{Prior, Run};
use crate::shared::Shared;
use crate::state::{FileStatus, decode_state, parse_hashes, state_dir_name};
use crate::util::{Bits, now_unix};

/// Прежний прогресс файла, если `.hashes` воспроизводит корень; иначе файл начнётся заново.
fn prior(sdir: &Path, index: u32, size: u64, l: Layout, root: FileRoot, bits: Bits) -> Run {
    let max = u64::from(l.block_count).saturating_mul(32);
    let Ok(raw) = read_hashes(sdir, index, max) else {
        return Run::Waiting(None);
    };
    // список хэшей обязан воспроизвести корень; сами хэши берутся из свежего манифеста
    match parse_hashes(&raw, size, l, &root) {
        Ok(_) => Run::Waiting(Some(Prior {
            layout: l,
            root,
            bits,
        })),
        Err(_) => Run::Waiting(None),
    }
}

/// Все годные передачи; негодные и просроченные удаляются (только наши файлы по шаблонам).
pub(crate) fn load_all(sh: &Arc<Shared>) -> Vec<Arc<RecvSession>> {
    let base = &sh.cfg.partial_dir;
    let Ok(names) = list_session_dirs(base) else {
        return Vec::new();
    };
    let now = now_unix();
    let ttl = sh.cfg.partial_ttl.as_secs();
    let mut out = Vec::new();
    for name in names {
        let sdir = session_dir(base, &name);
        let state = read_state(&sdir)
            .ok()
            .and_then(|b| decode_state(&b).ok())
            .filter(|st| state_dir_name(&st.pair, &st.id) == name)
            .filter(|st| now.saturating_sub(st.last_progress_unix) <= ttl);
        let Some(st) = state else {
            remove_session(&sdir);
            continue;
        };
        let mut runs = Vec::with_capacity(st.files.len());
        for (i, f) in st.files.iter().enumerate() {
            let index = u32::try_from(i).unwrap_or(u32::MAX);
            let run = match &f.status {
                FileStatus::Waiting => Run::Waiting(None),
                FileStatus::InProgress(p) => prior(
                    &sdir,
                    index,
                    f.size,
                    p.layout,
                    p.root,
                    Bits::from_bytes(p.layout.block_count, &p.bitmap),
                ),
                FileStatus::Verified(root) => match layout(f.size) {
                    Ok(l) => prior(&sdir, index, f.size, l, *root, Bits::ones(l.block_count)),
                    Err(_) => Run::Waiting(None),
                },
                FileStatus::Placed(root) => Run::Placed(*root),
                // ошибки файлов сбрасываются: после перезапуска файл пробуется заново
                FileStatus::Failed => {
                    remove_part_and_hashes(&sdir, index);
                    Run::Waiting(None)
                }
            };
            runs.push(run);
        }
        let files = st
            .files
            .iter()
            .map(|f| (f.name.clone(), f.size))
            .collect::<Vec<_>>();
        let key = TransferKey {
            pair: st.pair,
            id: st.id,
        };
        out.push(RecvSession::restored(
            sh.clone(),
            key,
            files,
            runs,
            st.created_unix,
            sdir,
        ));
    }
    out
}
