#![allow(clippy::print_stdout)]
//! Fuzz-смоук на stable без зависимостей: ГПСЧ xorshift64* с фиксированным зерном.
//! Свойства: ни одной паники; каждое принятое сообщение (состояние) перекодируется в те же байты.
//! Число итераций: `CHERVO_FUZZ_ITERS` (по умолчанию 20 000 в release, 2 000 в debug).

use std::time::Duration;

use chervo_identity::PairId;

use super::{MemRx, body};
use crate::hash::sha256;
use crate::state::{FileStatus, Progress, RecvState, StateFile, decode_names, encode_names};
use crate::{
    BlockErrCode, CancelReason, FileErrCode, FileRoot, MAX_FILE_SIZE, Message, OfferAssembler,
    OfferedFile, TransferId, UntrustedName, Verdict, decode_message, decode_state, encode,
    encode_state, layout, read_message,
};

struct XorShift(u64);

impl XorShift {
    fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n.max(1) as u64)) as usize
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
}

fn fuzz_iters() -> u64 {
    let default = if cfg!(debug_assertions) {
        2_000
    } else {
        20_000
    };
    std::env::var("CHERVO_FUZZ_ITERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Зерно ГПСЧ цели (этап 17, B3). Без `CHERVO_FUZZ_SEED` ровно `default`, как раньше. С ней
/// у каждой цели своё зерно (splitmix64 от `seed ^ default`), так что длинные прогоны идут по
/// новым последовательностям. Пустое значение считается незаданным; неразборное (не `u64`)
/// вызывает панику, чтобы прогон не пошёл молча по старому зерну.
fn fuzz_seed(default: u64) -> u64 {
    let Ok(raw) = std::env::var("CHERVO_FUZZ_SEED") else {
        return default;
    };
    if raw.trim().is_empty() {
        return default;
    }
    let seed: u64 = raw
        .trim()
        .parse()
        .unwrap_or_else(|_| panic!("CHERVO_FUZZ_SEED must be a u64, got {raw:?}"));
    let mut z = (seed ^ default).wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Одна случайная мутация: переворот бита, вставка, удаление, обрезка, замена байта.
fn mutate(rng: &mut XorShift, src: &[u8]) -> Vec<u8> {
    let mut v = src.to_vec();
    match rng.below(5) {
        0 if !v.is_empty() => {
            let i = rng.below(v.len());
            v[i] ^= 1 << rng.below(8);
        }
        1 => {
            let i = rng.below(v.len() + 1);
            let len = 1 + rng.below(4);
            for (k, b) in rng.bytes(len).into_iter().enumerate() {
                v.insert(i + k, b);
            }
        }
        2 if !v.is_empty() => {
            let i = rng.below(v.len());
            v.remove(i);
        }
        3 => {
            let n = rng.below(v.len() + 1);
            v.truncate(n);
        }
        _ if !v.is_empty() => {
            let i = rng.below(v.len());
            v[i] = rng.next() as u8;
        }
        _ => {}
    }
    v
}

fn name(rng: &mut XorShift) -> UntrustedName {
    let len = 1 + rng.below(40);
    let s: String = (0..len)
        .map(|_| match rng.below(4) {
            0 => 'я',
            1 => '/',
            _ => char::from(b'a' + rng.below(26) as u8),
        })
        .collect();
    UntrustedName::new(&s).unwrap()
}

fn id(rng: &mut XorShift) -> TransferId {
    let mut b = [0u8; 16];
    b.copy_from_slice(&rng.bytes(16));
    TransferId(b)
}

fn root(rng: &mut XorShift) -> FileRoot {
    let mut b = [0u8; 32];
    b.copy_from_slice(&rng.bytes(32));
    FileRoot(b)
}

/// Корпус допустимых тел по одному на тип; OFFER_FILES с несколькими записями.
fn corpus(rng: &mut XorShift) -> Vec<Vec<u8>> {
    let files: Vec<_> = (0..4)
        .map(|_| OfferedFile {
            name: name(rng),
            size: rng.next() % (MAX_FILE_SIZE + 1),
        })
        .collect();
    let msgs = vec![
        Message::OfferHead {
            id: id(rng),
            file_count: 4,
            total_size: 1 << 30,
            offer_bytes: 200,
        },
        Message::OfferFiles(files),
        Message::Decision {
            id: id(rng),
            verdict: Verdict::Busy,
        },
        Message::Cancel {
            id: id(rng),
            reason: CancelReason::Limits,
        },
        Message::FileError {
            index: 1,
            code: FileErrCode::Damaged,
        },
        Message::FileDone { index: 2 },
        Message::Done { id: id(rng) },
        Message::Resume { id: id(rng) },
        Message::ResumeOk {
            id: id(rng),
            file_count: 3,
            total_size: 99,
        },
        Message::HashProgress {
            hashed: rng.next() >> 20,
        },
        Message::Bind { id: id(rng) },
        Message::GetManifest { index: 7 },
        Message::Manifest {
            index: 7,
            block_size: 1 << 20,
            block_count: 9,
            root: root(rng),
        },
        Message::GetBlock { index: 7, block: 8 },
        Message::Block {
            index: 7,
            block: 8,
            len: 1 << 20,
        },
        Message::BlockErr {
            index: 7,
            block: 8,
            code: BlockErrCode::SourceChanged,
        },
    ];
    msgs.iter().map(body).collect()
}

#[tokio::test]
async fn fuzz_smoke_codec() {
    let n = fuzz_iters();
    let mut rng = XorShift::new(fuzz_seed(0x0123_4567_89AB_CDEF));
    let seeds = corpus(&mut rng);
    let mut buf = Vec::new();
    let (mut ok_body, mut ok_stream) = (0u64, 0u64);
    for i in 0..n {
        let b: Vec<u8> = match rng.below(5) {
            0 => {
                let len = rng.below(80);
                rng.bytes(len)
            }
            1 | 2 => {
                let s = seeds[rng.below(seeds.len())].clone();
                mutate(&mut rng, &s)
            }
            3 => {
                // Допустимый тип, случайные поля.
                let mut v = vec![rng.below(0x18) as u8];
                let len = rng.below(60);
                v.extend(rng.bytes(len));
                v
            }
            _ => {
                // Двойная мутация корпуса.
                let s = seeds[rng.below(seeds.len())].clone();
                let m = mutate(&mut rng, &s);
                mutate(&mut rng, &m)
            }
        };
        // Тело напрямую.
        let decoded = decode_message(&b);
        if let Ok(msg) = &decoded {
            ok_body += 1;
            let mut again = Vec::new();
            encode(msg, &mut again).unwrap();
            let mut want = (b.len() as u32).to_be_bytes().to_vec();
            want.extend_from_slice(&b);
            assert_eq!(again, want, "итерация {i}: принятое не каноническое");
        }
        // Тот же кадр через поток кусками разной величины: результат совпадает с прямым.
        if !b.is_empty() && b.len() <= crate::MAX_MESSAGE_LEN {
            let mut f = (b.len() as u32).to_be_bytes().to_vec();
            f.extend_from_slice(&b);
            let mut rx = MemRx::chunked(f, 1 + rng.below(9));
            let got = read_message(&mut rx, &mut buf, Duration::from_secs(5)).await;
            assert_eq!(got.is_ok(), decoded.is_ok(), "итерация {i}");
        }
        // Произвольный поток (длина в заголовке может лгать): принятое перекодируется в
        // ровно прочитанные байты.
        let mut stream = (b.len() as u32).to_be_bytes().to_vec();
        stream.extend_from_slice(&b);
        let stream = if rng.below(3) == 0 {
            mutate(&mut rng, &stream)
        } else {
            stream
        };
        let mut rx = MemRx::chunked(stream.clone(), 1 + rng.below(9));
        if let Ok(Some(msg)) = read_message(&mut rx, &mut buf, Duration::from_secs(5)).await {
            ok_stream += 1;
            let mut again = Vec::new();
            encode(&msg, &mut again).unwrap();
            assert_eq!(
                again.as_slice(),
                &stream[..again.len()],
                "итерация {i}: поток"
            );
            assert_eq!(rx.taken(), again.len(), "прочитано не больше кадра");
        }
    }
    println!(
        "fuzz_smoke_codec: iterations={n} accepted_body={ok_body} accepted_stream={ok_stream}"
    );
}

fn random_files(rng: &mut XorShift) -> Vec<OfferedFile> {
    let n = rng.below(7);
    (0..n)
        .map(|_| OfferedFile {
            name: name(rng),
            size: match rng.below(8) {
                0 => 0,
                1 => MAX_FILE_SIZE,
                2 => MAX_FILE_SIZE + 1 + rng.next() % 1000,
                3 => u64::MAX - rng.next() % 4,
                _ => rng.next() % (1 << 34),
            },
        })
        .collect()
}

#[tokio::test]
async fn fuzz_smoke_offer_assembly() {
    let n = fuzz_iters();
    let mut rng = XorShift::new(fuzz_seed(0xDEAD_BEEF_0BAD_F00D));
    let (mut finished, mut rejected) = (0u64, 0u64);
    for i in 0..n {
        let files = random_files(&mut rng);
        let valid_sizes = files.iter().all(|f| f.size <= MAX_FILE_SIZE);
        let bytes: u64 = files.iter().map(|f| 10 + f.name.len() as u64).sum();
        let sum: u128 = files.iter().map(|f| u128::from(f.size)).sum();
        let exact = (
            files.len() as u32,
            sum.min(u128::from(u64::MAX)) as u64,
            bytes as u32,
        );
        // Заголовок точный или сдвинутый.
        let (fc, ts, ob) = match rng.below(6) {
            0 => (exact.0 + 1, exact.1, exact.2),
            1 => (exact.0.saturating_sub(1), exact.1, exact.2),
            2 => (exact.0, exact.1.wrapping_add(1), exact.2),
            3 => (exact.0, exact.1, exact.2.wrapping_add(1)),
            4 => (rng.next() as u32 % 12_000, rng.next(), rng.next() as u32),
            _ => exact,
        };
        let is_exact = (fc, ts, ob) == exact;
        let head_ok = fc >= 1 && ob >= 1 && fc <= 10_000 && ts <= 1 << 44 && ob <= 2 * 1024 * 1024;
        let Ok(mut asm) = OfferAssembler::new(fc, ts, ob) else {
            assert!(!head_ok, "итерация {i}: допустимый заголовок отвергнут");
            rejected += 1;
            continue;
        };
        assert!(head_ok, "итерация {i}: недопустимый заголовок принят");
        // Записи отдаются порциями случайной величины.
        let mut rest = files.clone();
        let mut push_failed = false;
        while !rest.is_empty() {
            let take = (1 + rng.below(3)).min(rest.len());
            let chunk: Vec<_> = rest.drain(..take).collect();
            if asm.push(chunk).is_err() {
                push_failed = true;
                break;
            }
        }
        match (push_failed, asm.finish()) {
            (false, Ok(got)) => {
                finished += 1;
                // Принятое согласовано с заголовком точно.
                assert_eq!(got.len() as u32, fc, "итерация {i}");
                assert_eq!(
                    got.iter().map(|f| 10 + f.name.len() as u64).sum::<u64>(),
                    u64::from(ob)
                );
                assert_eq!(got.iter().map(|f| f.size).sum::<u64>(), ts);
                assert!(is_exact && valid_sizes, "итерация {i}: лишнее принято");
            }
            (false, Err(_)) => {
                assert!(
                    !(is_exact && valid_sizes),
                    "итерация {i}: точное отвергнуто"
                );
                rejected += 1;
            }
            (true, r) => {
                assert!(r.is_err(), "итерация {i}: после ошибки finish принял");
                assert!(
                    !(is_exact && valid_sizes),
                    "итерация {i}: точное отвергнуто"
                );
                rejected += 1;
            }
        }
    }
    println!("fuzz_smoke_offer_assembly: iterations={n} finished={finished} rejected={rejected}");
}

/// Согласованное состояние: размеры, раскладки, карты с нулевыми старшими битами.
fn random_state(rng: &mut XorShift) -> RecvState {
    const SIZES: [u64; 7] = [
        0,
        1,
        1 << 20,
        (1 << 20) + 1,
        3 * (1 << 20) + 7,
        100 << 20,
        9 << 20,
    ];
    let count = 1 + rng.below(6);
    let mut in_progress = 0;
    let files: Vec<StateFile> = (0..count)
        .map(|_| {
            let size = SIZES[rng.below(SIZES.len())];
            let status = match rng.below(5) {
                1 if in_progress < 8 => {
                    in_progress += 1;
                    let l = layout(size).unwrap();
                    let mut bitmap = rng.bytes(crate::layout::bitmap_len(l.block_count));
                    if !l.block_count.is_multiple_of(8)
                        && let Some(last) = bitmap.last_mut()
                    {
                        *last &= (1u8 << (l.block_count % 8)) - 1;
                    }
                    FileStatus::InProgress(Progress {
                        layout: l,
                        root: root(rng),
                        bitmap,
                    })
                }
                2 => FileStatus::Verified(root(rng)),
                3 => FileStatus::Placed(root(rng)),
                4 => FileStatus::Failed,
                _ => FileStatus::Waiting,
            };
            StateFile { size, status }
        })
        .collect();
    RecvState {
        pair: PairId::from_bytes(rng.bytes(16).try_into().unwrap()),
        id: id(rng),
        created_unix: rng.next(),
        last_progress_unix: rng.next(),
        total_size: files.iter().map(|f| f.size).sum(),
        names_sum: rng.bytes(32).try_into().unwrap(),
        files,
    }
}

fn reseal(mut b: Vec<u8>) -> Vec<u8> {
    if b.len() < 32 {
        return b;
    }
    let n = b.len() - 32;
    b.truncate(n);
    let sum = sha256(&[&b]);
    b.extend_from_slice(&sum);
    b
}

#[test]
fn fuzz_smoke_state() {
    let n = fuzz_iters();
    let mut rng = XorShift::new(fuzz_seed(0x005E_ED0F_57A7_E000_u64));
    let mut accepted = 0u64;
    for i in 0..n {
        let s = random_state(&mut rng);
        let good = encode_state(&s);
        // Нетронутое состояние всегда принимается и совпадает.
        let back = decode_state(&good).expect("согласованное состояние");
        assert!(back == s, "итерация {i}");
        let b = match rng.below(5) {
            0 => {
                let len = rng.below(200);
                rng.bytes(len)
            }
            1 => mutate(&mut rng, &good),
            2 => reseal(mutate(&mut rng, &good)),
            3 => {
                let once = mutate(&mut rng, &good);
                reseal(mutate(&mut rng, &once))
            }
            _ => {
                // Усечение или добавка тела с пересчитанной суммой.
                let mut v = good[..good.len() - 32].to_vec();
                if rng.below(2) == 0 {
                    let cut = rng.below(v.len() + 1);
                    v.truncate(cut);
                } else {
                    let extra = 1 + rng.below(8);
                    v.extend(rng.bytes(extra));
                }
                v.extend_from_slice(&[0u8; 32]);
                reseal(v)
            }
        };
        if let Ok(s2) = decode_state(&b) {
            accepted += 1;
            assert_eq!(encode_state(&s2), b, "итерация {i}: не каноническое");
        }
    }
    println!("fuzz_smoke_state: iterations={n} accepted={accepted}");
}

#[test]
fn fuzz_smoke_names() {
    let n = fuzz_iters();
    let mut rng = XorShift::new(fuzz_seed(0x00A3_E5F0_0D5E_ED01_u64));
    let mut accepted = 0u64;
    for i in 0..n {
        let count = 1 + rng.below(6);
        let list: Vec<UntrustedName> = (0..count).map(|_| name(&mut rng)).collect();
        let pair = PairId::from_bytes(rng.bytes(16).try_into().unwrap());
        let tid = id(&mut rng);
        let (good, sum) = encode_names(&pair, &tid, &list);
        let back = decode_names(&good).expect("согласованный файл имён");
        assert!(back.names == list && back.sum == sum, "итерация {i}");
        let b = match rng.below(5) {
            0 => {
                let len = rng.below(200);
                rng.bytes(len)
            }
            1 => mutate(&mut rng, &good),
            2 => reseal(mutate(&mut rng, &good)),
            3 => {
                let once = mutate(&mut rng, &good);
                reseal(mutate(&mut rng, &once))
            }
            _ => {
                let mut v = good[..good.len() - 32].to_vec();
                if rng.below(2) == 0 {
                    let cut = rng.below(v.len() + 1);
                    v.truncate(cut);
                } else {
                    let extra = 1 + rng.below(8);
                    v.extend(rng.bytes(extra));
                }
                v.extend_from_slice(&[0u8; 32]);
                reseal(v)
            }
        };
        if let Ok(nf) = decode_names(&b) {
            accepted += 1;
            let (again, _) = encode_names(&nf.pair, &nf.id, &nf.names);
            assert_eq!(again, b, "итерация {i}: не каноническое");
        }
    }
    println!("fuzz_smoke_names: iterations={n} accepted={accepted}");
}
