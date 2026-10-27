//! Загрузка недокачанных передач при запуске: просмотр `partial_dir`, проверка состояния.
//! С диска не доверяется ничего: состояние и файл имён ограничены и проверены контрольной
//! суммой (состояние привязано к трейлеру файла имён), список хэшей воспроизводит корень, пара
//! берётся из соединения при возобновлении, а готовые блоки перехэшируются перед использованием.

use std::path::Path;
use std::sync::Arc;

use crate::hash::FileRoot;
use crate::layout::{Layout, layout};
use crate::names::TransferKey;
use crate::paths::{
    list_session_dirs, read_hashes, read_names, read_state, remove_part_and_hashes, remove_session,
    session_dir,
};
use crate::receiver::RecvSession;
use crate::sched::{Prior, Run};
use crate::shared::Shared;
use crate::state::{FileStatus, decode_names, decode_state, parse_hashes, state_dir_name};
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

/// Все годные передачи из `partial_dir` и из дополнительных каталогов размещения
/// (`Placement::extra_partial_dirs`, Рев. 5 этапа 15); негодные и просроченные удаляются
/// (только наши файлы по шаблонам).
pub(crate) fn load_all(sh: &Arc<Shared>) -> Vec<Arc<RecvSession>> {
    let mut bases = vec![sh.cfg.partial_dir.clone()];
    for extra in sh.placement.extra_partial_dirs() {
        if !bases.contains(&extra) {
            bases.push(extra);
        }
    }
    let mut out = Vec::new();
    for base in &bases {
        load_dir(sh, base, &mut out);
    }
    out
}

fn load_dir(sh: &Arc<Shared>, base: &Path, out: &mut Vec<Arc<RecvSession>>) {
    let Ok(names) = list_session_dirs(base) else {
        return;
    };
    let now = now_unix();
    let ttl = sh.cfg.partial_ttl.as_secs();
    for name in names {
        let sdir = session_dir(base, &name);
        let decoded = read_state(&sdir)
            .ok()
            .and_then(|b| decode_state(&b).ok())
            .filter(|st| state_dir_name(&st.pair, &st.id) == name);
        // ключ известен, только если состояние разобрано и согласовано с именем каталога
        let known = decoded.as_ref().map(|st| TransferKey {
            pair: st.pair,
            id: st.id,
        });
        let state = decoded.filter(|st| now.saturating_sub(st.last_progress_unix) <= ttl);
        // имена: неизменяемый файл, тот самый, к которому привязано состояние
        let nf = state.as_ref().and_then(|st| {
            read_names(&sdir)
                .ok()
                .and_then(|b| decode_names(&b).ok())
                .filter(|nf| {
                    nf.pair == st.pair
                        && nf.id == st.id
                        && nf.sum == st.names_sum
                        && nf.names.len() == st.files.len()
                })
        });
        let (Some(st), Some(nf)) = (state, nf) else {
            remove_session(&sdir);
            if let Some(k) = known {
                sh.placement.forget(&k);
            }
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
                FileStatus::Placed(root) => {
                    // остатки после краха между записью `Placed` и уборкой (только имена)
                    remove_part_and_hashes(&sdir, index);
                    Run::Placed(*root)
                }
                // ошибки файлов сбрасываются: после перезапуска файл пробуется заново
                FileStatus::Failed => {
                    remove_part_and_hashes(&sdir, index);
                    Run::Waiting(None)
                }
            };
            runs.push(run);
        }
        let files = nf
            .names
            .into_iter()
            .zip(st.files.iter().map(|f| f.size))
            .collect::<Vec<_>>();
        let key = TransferKey {
            pair: st.pair,
            id: st.id,
        };
        // одна передача в двух каталогах: берётся первая, вторая остаётся нетронутой
        if out.iter().any(|x| x.key == key) {
            continue;
        }
        out.push(RecvSession::restored(
            sh.clone(),
            key,
            files,
            runs,
            st.created_unix,
            sdir,
            st.names_sum,
        ));
    }
}
