//! Логика проверки без сети: подписанные манифесты, перенаправления, отсутствие запросов без ключей.

use chervo_update::{KeySet, Target, UpdateError};

use super::helpers::*;
use crate::http::Response;
use crate::{
    CheckError, Fetch, MAX_MANIFEST_LEN, MAX_MINISIG_LEN, MAX_REDIRECTS, Redirecting, UpdateStatus,
    check_latest_with,
};

const TARGET: Target = Target::LinuxX86_64;

fn run(
    manifest: Vec<u8>,
    sig: Vec<u8>,
    running: chervo_update::Version,
) -> Result<UpdateStatus, CheckError> {
    let sk = test_key(7);
    let fetch = MockFetch::new(manifest, sig);
    check_latest_with(keyset(&sk), &fetch, running, Some(TARGET))
}

#[test]
fn newer_signed_shown() {
    let sk = test_key(7);
    let m = manifest_bytes(v(1, 3, 0), &[TARGET, Target::Any]);
    let sig = sign(&sk, &m);
    assert_eq!(run(m, sig, v(1, 2, 9)), Ok(UpdateStatus::Newer(v(1, 3, 0))));
}

#[test]
fn same_version_up_to_date() {
    let sk = test_key(7);
    let m = manifest_bytes(v(1, 3, 0), &[TARGET]);
    let sig = sign(&sk, &m);
    assert_eq!(run(m, sig, v(1, 3, 0)), Ok(UpdateStatus::UpToDate));
}

#[test]
fn older_signed_not_shown() {
    let sk = test_key(7);
    let m = manifest_bytes(v(0, 9, 0), &[TARGET]);
    let sig = sign(&sk, &m);
    assert_eq!(run(m, sig, v(1, 0, 0)), Ok(UpdateStatus::UpToDate));
}

#[test]
fn newer_without_current_target_not_shown() {
    let sk = test_key(7);
    // только другая ОС и строка any: для этой ОС файла нет
    let m = manifest_bytes(v(2, 0, 0), &[Target::WindowsX86_64, Target::Any]);
    let sig = sign(&sk, &m);
    assert_eq!(
        run(m.clone(), sig.clone(), v(1, 0, 0)),
        Ok(UpdateStatus::UpToDate)
    );
    // система не из списка (цели нет): тоже не показывается
    let fetch = MockFetch::new(m, sig);
    assert_eq!(
        check_latest_with(keyset(&sk), &fetch, v(1, 0, 0), None),
        Ok(UpdateStatus::UpToDate)
    );
}

#[test]
fn bad_signature_rejected() {
    let sk = test_key(7);
    let m = manifest_bytes(v(2, 0, 0), &[TARGET]);
    // чужой ключ с тем же key_id
    let sig = sign(&test_key(8), &m);
    assert_eq!(
        run(m.clone(), sig, v(1, 0, 0)),
        Err(CheckError::BadSignature)
    );
    // изменённый манифест при подписи от настоящего ключа
    let sig = sign(&sk, &m);
    let mut tampered = m.clone();
    let last = tampered.len() - 2;
    tampered[last] ^= 1;
    assert_eq!(
        run(tampered, sig.clone(), v(1, 0, 0)),
        Err(CheckError::BadSignature)
    );
    // мусор вместо подписи
    assert_eq!(
        run(m, b"garbage".to_vec(), v(1, 0, 0)),
        Err(CheckError::BadSignature)
    );
}

#[test]
fn sig_and_manifest_mismatch_rejected() {
    let sk = test_key(7);
    let old = manifest_bytes(v(1, 0, 0), &[TARGET]);
    let new = manifest_bytes(v(2, 0, 0), &[TARGET]);
    // релиз вышел между запросами: подпись от одного, манифест от другого
    let sig_old = sign(&sk, &old);
    assert_eq!(run(new, sig_old, v(0, 5, 0)), Err(CheckError::BadSignature));
}

#[test]
fn oversize_inputs_rejected() {
    let sk = test_key(7);
    let m = manifest_bytes(v(2, 0, 0), &[TARGET]);
    let sig = sign(&sk, &m);
    // фальшивый Fetch отдаёт сверх предела: отказ без паники
    let huge_m = vec![b'a'; MAX_MANIFEST_LEN + 1];
    assert!(run(huge_m, sig.clone(), v(1, 0, 0)).is_err());
    let huge_s = vec![b'a'; MAX_MINISIG_LEN + 1];
    assert!(run(m, huge_s, v(1, 0, 0)).is_err());
}

#[test]
fn no_trusted_keys_makes_no_request() {
    let sk = test_key(7);
    let m = manifest_bytes(v(2, 0, 0), &[TARGET]);
    let fetch = MockFetch::new(m.clone(), sign(&sk, &m));
    let none = KeySet::from_pubkey_files(&[]);
    assert!(matches!(none, Err(UpdateError::NoTrustedKeys)));
    assert_eq!(
        check_latest_with(none, &fetch, v(1, 0, 0), Some(TARGET)),
        Err(CheckError::NoTrustedKeys)
    );
    assert_eq!(fetch.calls(), 0, "запросов быть не должно");
    // любая ошибка набора ключей тоже без сети
    assert_eq!(
        check_latest_with(
            Err(UpdateError::KeysetInvalid),
            &fetch,
            v(1, 0, 0),
            Some(TARGET)
        ),
        Err(CheckError::NoTrustedKeys)
    );
    assert_eq!(fetch.calls(), 0);
}

#[test]
fn signature_is_requested_before_manifest() {
    let sk = test_key(7);
    let m = manifest_bytes(v(2, 0, 0), &[TARGET]);
    let fetch = MockFetch::new(m.clone(), sign(&sk, &m));
    check_latest_with(keyset(&sk), &fetch, v(1, 0, 0), Some(TARGET)).expect("ok");
    assert_eq!(fetch.calls(), 2);
}

fn redirect(to: &str) -> Result<Response, CheckError> {
    Ok(Response::Redirect(to.to_owned()))
}

#[test]
fn redirect_chain_ok() {
    let t = MockTransport::new(vec![
        redirect(
            "https://github.com/rekc2004/chervotochina/releases/download/v1.0.0/chervo-release.txt",
        ),
        redirect("https://release-assets.githubusercontent.com/x/y?sig=a%2Bb&z=1"),
        Ok(Response::Body(b"BODY".to_vec())),
    ]);
    let got = Redirecting(&t)
        .get("chervo-release.txt", 1000)
        .expect("chain");
    assert_eq!(got, b"BODY");
    let log = t.log.lock().expect("log");
    assert_eq!(log.len(), 3);
    assert_eq!(log[0].0, "github.com");
    assert_eq!(
        log[0].1,
        "/rekc2004/chervotochina/releases/latest/download/chervo-release.txt"
    );
    assert_eq!(log[1].0, "github.com");
    assert_eq!(log[2].0, "release-assets.githubusercontent.com");
    assert_eq!(log[2].1, "/x/y?sig=a%2Bb&z=1");
}

#[test]
fn redirect_limit_exceeded() {
    // ровно MAX_REDIRECTS перенаправлений допустимо, на одно больше нет
    let mk = |n: usize| {
        let mut replies: Vec<Result<Response, CheckError>> = (0..n)
            .map(|i| redirect(&format!("https://github.com/hop{i}")))
            .collect();
        replies.push(Ok(Response::Body(b"X".to_vec())));
        MockTransport::new(replies)
    };
    let t = mk(MAX_REDIRECTS);
    assert_eq!(Redirecting(&t).get("f", 1000).expect("limit ok"), b"X");
    let t = mk(MAX_REDIRECTS + 1);
    assert_eq!(Redirecting(&t).get("f", 1000), Err(CheckError::BadResponse));
    assert_eq!(t.log.lock().expect("log").len(), MAX_REDIRECTS + 1);
}

#[test]
fn redirect_to_bad_location_stops() {
    for loc in [
        "http://github.com/x",
        "https://evil.example/x",
        "/relative",
        "https://github.com:8443/x",
        "https://github.com@evil.example/x",
    ] {
        let t = MockTransport::new(vec![redirect(loc), Ok(Response::Body(b"X".to_vec()))]);
        assert_eq!(
            Redirecting(&t).get("f", 1000),
            Err(CheckError::BadResponse),
            "{loc}"
        );
        // второй запрос не отправлен
        assert_eq!(t.log.lock().expect("log").len(), 1, "{loc}");
    }
}

#[test]
fn transport_error_passes_through() {
    let t = MockTransport::new(vec![Err(CheckError::Timeout)]);
    assert_eq!(Redirecting(&t).get("f", 1000), Err(CheckError::Timeout));
}
