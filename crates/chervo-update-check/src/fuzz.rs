//! Общая точка входа фаззинга разбора ответа: libFuzzer (`fuzz/`) и stable-смоук (`src/tests`).
//! Свойства: нет паники; тело не больше предела; `Location` из списка хостов; чтение не больше
//! `MAX_HEADER_BYTES + 4 + предел + 1` байт.

use std::io::Read;

use crate::http::{Response, parse_location, read_response};
use crate::{ALLOWED_HOSTS, MAX_HEADER_BYTES, MAX_LOCATION_LEN, MAX_MANIFEST_LEN, MAX_MINISIG_LEN};

/// Читатель байтов, считающий выданное.
pub(crate) struct Counting<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) taken: usize,
}

impl Read for Counting<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.data.len().min(buf.len());
        buf[..n].copy_from_slice(&self.data[..n]);
        self.data = &self.data[n..];
        self.taken += n;
        Ok(n)
    }
}

pub(crate) fn exercise(data: &[u8]) {
    for max in [MAX_MINISIG_LEN, MAX_MANIFEST_LEN, 7] {
        let mut r = Counting { data, taken: 0 };
        match read_response(&mut r, max) {
            Ok(Response::Body(body)) => assert!(body.len() <= max),
            Ok(Response::Redirect(location)) => {
                assert!(location.len() <= MAX_LOCATION_LEN);
                if let Ok(l) = parse_location(&location) {
                    assert!(ALLOWED_HOSTS.contains(&l.host));
                }
            }
            Err(_) => {}
        }
        assert!(
            r.taken <= MAX_HEADER_BYTES + 4 + max + 1,
            "прочитано {} байт при пределе {max}",
            r.taken
        );
    }
    if let Ok(s) = std::str::from_utf8(data)
        && let Ok(l) = parse_location(s)
    {
        assert!(ALLOWED_HOSTS.contains(&l.host));
        assert!(l.path.starts_with('/') && !l.path.contains('#'));
        assert!(l.path.bytes().all(|b| (0x21..=0x7E).contains(&b)));
        assert!(s.len() <= MAX_LOCATION_LEN);
    }
}
