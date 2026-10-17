//! Хуки `Placement::prepare` и `Placement::forget` (этап 15, R2) и права `.part`.

use std::sync::atomic::Ordering;
use std::time::Duration;

use super::kit::*;
use crate::paths::session_dir;
use crate::{FailReason, Side, TransferEvent, TransferKey, state_dir_name};

fn narrow(c: &mut crate::TransferConfig) {
    c.streams = 2;
    c.per_stream_window = 1;
    c.recv_buffer_budget = 16 << 20;
}

async fn start_transfer(
    rig: &mut Rig,
    files: Vec<crate::SourceFile>,
) -> (TransferKey, TransferKey) {
    let key = rig.a.tr.send(&rig.pa, files).unwrap();
    let e = wait_ev(&mut rig.b.ev, 10, is_offer()).await;
    (key, key_of(&e))
}

fn count(log: &[PlaceEv], f: impl Fn(&PlaceEv) -> bool) -> usize {
    log.iter().filter(|e| f(e)).count()
}

#[tokio::test]
async fn prepare_called_once_before_first_place() {
    let mut rig = Rig::new().await;
    let src = TestDir::new();
    let files: Vec<_> = (0..3u64)
        .map(|i| write_src(src.path(), &format!("f{i}.bin"), &rand_bytes(i + 1, 3000)))
        .collect();
    let (key, kb) = start_transfer(&mut rig, files).await;
    // до принятия на диск и в `Placement` ничего не попало
    assert!(rig.b.spy.log.lock().unwrap().is_empty());
    rig.b.tr.respond(&kb, true).unwrap();
    wait_ev(&mut rig.b.ev, 60, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
    let log = rig.b.spy.log.lock().unwrap().clone();
    assert_eq!(log.first(), Some(&PlaceEv::Prepare(3)), "{log:?}");
    assert_eq!(count(&log, |e| matches!(e, PlaceEv::Prepare(_))), 1);
    assert_eq!(count(&log, |e| matches!(e, PlaceEv::Place(_))), 3);
    assert_eq!(log.last(), Some(&PlaceEv::Forget), "{log:?}");
}

#[tokio::test]
async fn prepare_called_lazily_after_restore() {
    let mut rig = Rig::with(|_| {}, narrow).await;
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "a.bin", &rand_bytes(64, 40 << 20))];
    let (key, kb) = start_transfer(&mut rig, files).await;
    let gate = gate_after_written(&rig.b.hook, 10);
    rig.b.tr.respond(&kb, true).unwrap();
    gate.wait_reached().await;
    rig.b.tr.shutdown();
    gate.release();
    rig.b.tr.wait_stopped().await;
    assert!(
        session_dir(rig.b.partial.path(), &state_dir_name(&kb.pair, &kb.id)).is_dir(),
        "session must survive the restart"
    );
    // первая жизнь: ровно один `prepare` при принятии, размещений не было
    {
        let log = rig.b.spy.log.lock().unwrap().clone();
        assert_eq!(log, vec![PlaceEv::Prepare(1)], "{log:?}");
    }
    rig.b.restart().await;
    wait_ev(&mut rig.b.ev, 60, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
    // вторая жизнь (журнал очищен при перезапуске): `prepare` лениво, один раз, до `place`
    let log = rig.b.spy.log.lock().unwrap().clone();
    assert_eq!(
        log,
        vec![PlaceEv::Prepare(1), PlaceEv::Place(0), PlaceEv::Forget],
        "{log:?}"
    );
}

#[tokio::test]
async fn prepare_error_cancels_limits_and_cleans() {
    let mut rig = Rig::new().await;
    rig.b.spy.prepare_fail.store(true, Ordering::SeqCst);
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "a.bin", &rand_bytes(5, 3000))];
    let (key, kb) = start_transfer(&mut rig, files).await;
    rig.b.tr.respond(&kb, true).unwrap();
    let e = wait_ev(&mut rig.b.ev, 20, |e| {
        matches!(e, TransferEvent::Failed { .. })
    })
    .await;
    assert!(matches!(
        e,
        TransferEvent::Failed {
            reason: FailReason::Limits,
            ..
        }
    ));
    // отправитель в фазе предложения видит CANCEL получателя как отмену с его стороны
    let e = wait_ev(&mut rig.a.ev, 20, |e| {
        matches!(e, TransferEvent::Cancelled { .. })
    })
    .await;
    assert!(matches!(
        e,
        TransferEvent::Cancelled {
            by: Side::Receiver,
            ..
        }
    ));
    assert_eq!(key_of(&e), key);
    assert!(
        rig.b.partial.list().is_empty(),
        "{:?}",
        rig.b.partial.list()
    );
    assert!(rig.b.dest.list().is_empty());
    assert!(rig.b.tr.status(&kb).is_none());
    let log = rig.b.spy.log.lock().unwrap().clone();
    assert_eq!(log, vec![PlaceEv::Prepare(1), PlaceEv::Forget], "{log:?}");
}

#[tokio::test]
async fn forget_called_on_complete_cancel_fail() {
    // завершение
    let mut rig = Rig::with(|_| {}, narrow).await;
    let src = TestDir::new();
    let files = vec![write_src(src.path(), "a.bin", &rand_bytes(7, 3000))];
    let (key, kb) = start_transfer(&mut rig, files).await;
    rig.b.tr.respond(&kb, true).unwrap();
    wait_ev(&mut rig.b.ev, 60, is_completed(kb)).await;
    wait_ev(&mut rig.a.ev, 60, is_completed(key)).await;
    let n = count(&rig.b.spy.log.lock().unwrap(), |e| *e == PlaceEv::Forget);
    assert_eq!(n, 1, "complete");

    // отмена получателем
    let files = vec![write_src(src.path(), "b.bin", &rand_bytes(8, 40 << 20))];
    let (_key, kb) = start_transfer(&mut rig, files).await;
    let gate = gate_after_written(&rig.b.hook, 5);
    rig.b.tr.respond(&kb, true).unwrap();
    gate.wait_reached().await;
    rig.b.tr.cancel(&kb).unwrap();
    gate.release();
    let e = wait_ev(&mut rig.b.ev, 20, |e| {
        matches!(e, TransferEvent::Cancelled { .. })
    })
    .await;
    assert!(matches!(
        e,
        TransferEvent::Cancelled {
            by: Side::Receiver,
            ..
        }
    ));
    let n = count(&rig.b.spy.log.lock().unwrap(), |e| *e == PlaceEv::Forget);
    assert_eq!(n, 2, "cancel");

    // сбой: отправитель «забыл» передачу
    let files = vec![write_src(src.path(), "c.bin", &rand_bytes(9, 40 << 20))];
    let (_key, kb) = start_transfer(&mut rig, files).await;
    let gate = gate_after_written(&rig.b.hook, 5);
    rig.b.tr.respond(&kb, true).unwrap();
    gate.wait_reached().await;
    let release = gate.clone();
    let restart = rig.a.restart();
    tokio::pin!(restart);
    tokio::select! {
        () = &mut restart => {}
        () = tokio::time::sleep(Duration::from_millis(100)) => {
            release.release();
            restart.await;
        }
    }
    gate.release();
    let e = wait_ev(&mut rig.b.ev, 30, |e| {
        matches!(e, TransferEvent::Failed { .. })
    })
    .await;
    assert!(matches!(
        e,
        TransferEvent::Failed {
            reason: FailReason::PeerForgot,
            ..
        }
    ));
    let n = count(&rig.b.spy.log.lock().unwrap(), |e| *e == PlaceEv::Forget);
    assert_eq!(n, 3, "fail");
}

#[cfg(unix)]
#[test]
fn part_created_0600() {
    use std::os::unix::fs::PermissionsExt;
    let d = TestDir::new();
    let f = crate::paths::create_part_new(d.path(), 0).unwrap();
    let mode = f.metadata().unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "mode {mode:o}");
    assert_eq!(mode & 0o111, 0);
}
