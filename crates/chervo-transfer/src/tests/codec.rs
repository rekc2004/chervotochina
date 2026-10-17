use std::time::Duration;

use super::{MemRx, body, frame};
use crate::{
    BlockErrCode, CancelReason, FileErrCode, FileRoot, MAX_FILE_SIZE, MAX_MESSAGE_LEN, Message,
    OfferAssembler, OfferedFile, ProtocolError, TransferId, UntrustedName, Verdict,
    check_block_len, check_manifest_layout, decode_message, encode, layout, read_exact,
    read_message,
};

const ID: TransferId = TransferId([7; 16]);

fn offered(name: &str, size: u64) -> OfferedFile {
    OfferedFile {
        name: UntrustedName::new(name).unwrap(),
        size,
    }
}

/// Все сообщения таблицы, по одному.
fn every_message() -> Vec<Message> {
    vec![
        Message::OfferHead {
            id: ID,
            file_count: 2,
            total_size: 30,
            offer_bytes: 29,
        },
        Message::OfferFiles(vec![offered("a.txt", 10), offered("папка/б", 20)]),
        Message::Decision {
            id: ID,
            verdict: Verdict::Accept,
        },
        Message::Decision {
            id: ID,
            verdict: Verdict::Limits,
        },
        Message::Cancel {
            id: ID,
            reason: CancelReason::Protocol,
        },
        Message::FileError {
            index: 3,
            code: FileErrCode::PlaceFailed,
        },
        Message::FileDone { index: 9 },
        Message::Done { id: ID },
        Message::Resume { id: ID },
        Message::ResumeOk {
            id: ID,
            file_count: 5,
            total_size: 1 << 33,
        },
        Message::HashProgress { hashed: 1 << 40 },
        Message::Bind { id: ID },
        Message::GetManifest { index: 1 },
        Message::Manifest {
            index: 1,
            block_size: 1 << 20,
            block_count: 4,
            root: FileRoot([9; 32]),
        },
        Message::GetBlock { index: 1, block: 2 },
        Message::Block {
            index: 1,
            block: 2,
            len: 1 << 20,
        },
        Message::BlockErr {
            index: 1,
            block: 2,
            code: BlockErrCode::ReadError,
        },
    ]
}

/// Сообщения фиксированной длины (всё, кроме OFFER_FILES).
fn fixed_messages() -> Vec<Message> {
    every_message()
        .into_iter()
        .filter(|m| !matches!(m, Message::OfferFiles(_)))
        .collect()
}

fn offer_files_body(entries: &[(u64, &[u8])]) -> Vec<u8> {
    let mut b = vec![0x02];
    b.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    for (size, name) in entries {
        b.extend_from_slice(&size.to_be_bytes());
        b.extend_from_slice(&(name.len() as u16).to_be_bytes());
        b.extend_from_slice(name);
    }
    b
}

#[test]
fn roundtrip_every_message() {
    for m in every_message() {
        let f = frame(&m);
        let len = u32::from_be_bytes(f[..4].try_into().unwrap()) as usize;
        assert_eq!(len, f.len() - 4);
        let back = decode_message(&f[4..]).unwrap();
        assert_eq!(frame(&back), f);
    }
}

#[test]
fn fixed_messages_exact_length() {
    for m in fixed_messages() {
        let b = body(&m);
        let mut short = b.clone();
        short.pop();
        assert!(
            matches!(decode_message(&short), Err(ProtocolError::Malformed)),
            "type {:#x} short",
            b[0]
        );
        let mut long = b.clone();
        long.push(0);
        assert!(
            matches!(decode_message(&long), Err(ProtocolError::Malformed)),
            "type {:#x} long",
            b[0]
        );
    }
    // Пустое тело: нет даже типа.
    assert!(matches!(decode_message(&[]), Err(ProtocolError::Malformed)));
}

#[tokio::test]
async fn frame_len_zero_rejected() {
    let mut rx = MemRx::new(vec![0, 0, 0, 0, 1, 2, 3]);
    let mut buf = Vec::new();
    let r = read_message(&mut rx, &mut buf, Duration::from_secs(1)).await;
    assert!(matches!(r, Err(ProtocolError::Malformed)));
}

#[tokio::test]
async fn frame_len_over_max_rejected_before_body() {
    for len in [MAX_MESSAGE_LEN as u32 + 1, u32::MAX] {
        let mut data = len.to_be_bytes().to_vec();
        data.extend(vec![0xAB; 70_000]);
        let mut rx = MemRx::new(data);
        let mut buf = Vec::new();
        let r = read_message(&mut rx, &mut buf, Duration::from_secs(1)).await;
        assert!(matches!(r, Err(ProtocolError::TooLong)));
        // Выдано ровно 4 байта длины: ни байта тела не прочитано, буфер не рос.
        assert_eq!(rx.taken(), 4);
        assert!(buf.is_empty());
    }
    // Ровно MAX_MESSAGE_LEN допустим по длине (тело разбирается и отвергается по типу).
    let mut data = (MAX_MESSAGE_LEN as u32).to_be_bytes().to_vec();
    data.extend(vec![0xEE; MAX_MESSAGE_LEN]);
    let mut rx = MemRx::new(data);
    let mut buf = Vec::new();
    let r = read_message(&mut rx, &mut buf, Duration::from_secs(1)).await;
    assert!(matches!(r, Err(ProtocolError::UnknownType)));
    assert_eq!(rx.taken(), 4 + MAX_MESSAGE_LEN);
    assert!(matches!(
        decode_message(&vec![0u8; MAX_MESSAGE_LEN + 1]),
        Err(ProtocolError::TooLong)
    ));
}

#[test]
fn unknown_type_rejected() {
    for t in [0x00u8, 0x0B, 0x0F, 0x16, 0x20, 0x7F, 0xFF] {
        assert!(
            matches!(decode_message(&[t]), Err(ProtocolError::UnknownType)),
            "type {t:#x}"
        );
    }
}

#[test]
fn wrong_version_rejected() {
    for m in [
        Message::OfferHead {
            id: ID,
            file_count: 1,
            total_size: 0,
            offer_bytes: 11,
        },
        Message::Resume { id: ID },
        Message::Bind { id: ID },
    ] {
        let good = body(&m);
        for v in [0u8, 2, 255] {
            let mut b = good.clone();
            b[1] = v;
            assert!(matches!(decode_message(&b), Err(ProtocolError::BadVersion)));
        }
    }
}

#[test]
fn trailing_bytes_rejected() {
    for m in every_message() {
        let mut b = body(&m);
        b.push(0);
        assert!(
            matches!(decode_message(&b), Err(ProtocolError::Malformed)),
            "type {:#x}",
            b[0]
        );
    }
}

#[test]
fn offer_name_bounds() {
    let long = vec![b'a'; 1024];
    let too_long = vec![b'a'; 1025];
    assert!(matches!(
        decode_message(&offer_files_body(&[(1, b"")])),
        Err(ProtocolError::BadName)
    ));
    assert!(decode_message(&offer_files_body(&[(1, b"a")])).is_ok());
    assert!(decode_message(&offer_files_body(&[(1, &long)])).is_ok());
    assert!(matches!(
        decode_message(&offer_files_body(&[(1, &too_long)])),
        Err(ProtocolError::BadName)
    ));
    // Конструктор имени с теми же границами.
    assert!(UntrustedName::new("").is_err());
    assert!(UntrustedName::new("a").is_ok());
    assert!(UntrustedName::new(&"a".repeat(1024)).is_ok());
    assert!(UntrustedName::new(&"a".repeat(1025)).is_err());
    // Длина в байтах, а не в символах: 513 двухбайтовых символов это 1026 байт.
    assert!(UntrustedName::new(&"я".repeat(513)).is_err());
    assert!(UntrustedName::new(&"я".repeat(512)).is_ok());
    // Кодирование не пропускает то, что декодер отверг бы: имя 1024 байта в кадре.
    let m = Message::OfferFiles(vec![offered(&"a".repeat(1024), 5)]);
    assert!(decode_message(&body(&m)).is_ok());
}

#[test]
fn offer_name_invalid_utf8_and_nul_rejected() {
    for bad in [&b"\xff"[..], b"a\xc3", b"a\0b", b"\0", b"\xed\xa0\x80"] {
        assert!(
            matches!(
                decode_message(&offer_files_body(&[(1, bad)])),
                Err(ProtocolError::BadName)
            ),
            "{bad:?}"
        );
    }
    assert!(UntrustedName::new("a\0b").is_err());
    // Всё остальное принимается как есть: смысл имён решает этап 15.
    assert!(decode_message(&offer_files_body(&[(1, b"../..\\x:y")])).is_ok());
    assert!(decode_message(&offer_files_body(&[(1, "\u{202e}x".as_bytes())])).is_ok());
}

#[test]
fn offer_entry_across_frames_rejected() {
    // Имя длиннее остатка кадра.
    let mut b = offer_files_body(&[(1, b"abcdef")]);
    b.truncate(b.len() - 2);
    assert!(matches!(decode_message(&b), Err(ProtocolError::Malformed)));
    // Заголовок записи оборван.
    let mut b = offer_files_body(&[(1, b"a")]);
    b.truncate(1 + 2 + 5);
    assert!(matches!(decode_message(&b), Err(ProtocolError::Malformed)));
    // Заявлено две записи, есть одна.
    let mut b = offer_files_body(&[(1, b"a"), (2, b"b")]);
    b[2] = 3;
    assert!(matches!(decode_message(&b), Err(ProtocolError::Malformed)));
    // Нет счётчика, счётчик 0.
    assert!(matches!(
        decode_message(&[0x02]),
        Err(ProtocolError::Malformed)
    ));
    assert!(matches!(
        decode_message(&[0x02, 0, 0]),
        Err(ProtocolError::Malformed)
    ));
}

#[test]
fn offer_totals_must_match() {
    let files = || vec![offered("a", 10), offered("bb", 20)];
    // Ровно: 2 записи, (10+1) + (10+2) = 23 байта, сумма 30.
    let mut a = OfferAssembler::new(2, 30, 23).unwrap();
    assert!(!a.push(vec![offered("a", 10)]).unwrap());
    assert!(a.push(vec![offered("bb", 20)]).unwrap());
    assert_eq!(a.finish().unwrap().len(), 2);

    // Записей меньше заявленного.
    let mut a = OfferAssembler::new(3, 30, 23).unwrap();
    a.push(files()).unwrap();
    assert!(a.finish().is_err());
    // Записей больше заявленного.
    let mut a = OfferAssembler::new(1, 30, 23).unwrap();
    assert!(a.push(files()).is_err());
    // Лишняя запись после полного набора.
    let mut a = OfferAssembler::new(2, 30, 23).unwrap();
    assert!(a.push(files()).unwrap());
    assert!(a.push(vec![offered("c", 0)]).is_err());
    // Байты записей: заявлено больше фактического, меньше фактического.
    let mut a = OfferAssembler::new(2, 30, 24).unwrap();
    a.push(files()).unwrap();
    assert!(a.finish().is_err());
    let mut a = OfferAssembler::new(2, 30, 22).unwrap();
    assert!(a.push(files()).is_err());
    // Сумма размеров: заявлено больше и меньше фактической.
    let mut a = OfferAssembler::new(2, 31, 23).unwrap();
    a.push(files()).unwrap();
    assert!(a.finish().is_err());
    let mut a = OfferAssembler::new(2, 29, 23).unwrap();
    assert!(a.push(files()).is_err());
    // После ошибки сборщик мёртв, даже если дальше всё выглядит верно.
    let mut a = OfferAssembler::new(2, 30, 23).unwrap();
    assert!(a.push(vec![offered("a", 99)]).is_err());
    assert!(a.push(vec![offered("a", 10), offered("bb", 20)]).is_err());
    assert!(a.finish().is_err());
    // Переполнение суммы: размер сверх u64 не пролезает уже по лимиту файла.
    let mut a = OfferAssembler::new(2, 1 << 44, 24).unwrap();
    assert!(matches!(
        a.push(vec![offered("a", u64::MAX)]),
        Err(ProtocolError::TooLarge)
    ));
    // Два файла по максимуму укладываются в итог 2^41.
    let mut a = OfferAssembler::new(2, 2 * MAX_FILE_SIZE, 22).unwrap();
    a.push(vec![
        offered("a", MAX_FILE_SIZE),
        offered("b", MAX_FILE_SIZE),
    ])
    .unwrap();
    assert_eq!(a.finish().unwrap().len(), 2);
    // Нулевые файлы допустимы, пустой итог тоже.
    let mut a = OfferAssembler::new(1, 0, 11).unwrap();
    a.push(vec![offered("z", 0)]).unwrap();
    assert!(a.finish().is_ok());
}

#[test]
fn offer_caps() {
    let head = |file_count: u32, total_size: u64, offer_bytes: u32| {
        decode_message(&body(&Message::OfferHead {
            id: ID,
            file_count,
            total_size,
            offer_bytes,
        }))
    };
    // Кодировщик отвергает то же, что декодер: собираем тело вручную.
    let raw = |file_count: u32, total_size: u64, offer_bytes: u32| {
        let mut b = vec![0x01, 1];
        b.extend_from_slice(&ID.0);
        b.extend_from_slice(&file_count.to_be_bytes());
        b.extend_from_slice(&total_size.to_be_bytes());
        b.extend_from_slice(&offer_bytes.to_be_bytes());
        decode_message(&b)
    };
    assert!(head(10_000, 1 << 44, 2 * 1024 * 1024).is_ok());
    assert!(matches!(raw(10_001, 0, 11), Err(ProtocolError::TooLarge)));
    assert!(matches!(
        raw(1, 0, 2 * 1024 * 1024 + 1),
        Err(ProtocolError::TooLarge)
    ));
    assert!(matches!(
        raw(1, (1 << 44) + 1, 11),
        Err(ProtocolError::TooLarge)
    ));
    assert!(matches!(raw(0, 0, 11), Err(ProtocolError::Malformed)));
    assert!(matches!(raw(1, 0, 0), Err(ProtocolError::Malformed)));
    let mut out = vec![1, 2, 3];
    let bad = Message::OfferHead {
        id: ID,
        file_count: 10_001,
        total_size: 0,
        offer_bytes: 11,
    };
    assert!(encode(&bad, &mut out).is_err());
    assert_eq!(out, [1, 2, 3], "ошибка кодирования не меняет out");
    // Размер файла 2^40 допустим, 2^40 + 1 нет.
    assert!(decode_message(&offer_files_body(&[(1 << 40, b"a")])).is_ok());
    assert!(matches!(
        decode_message(&offer_files_body(&[((1 << 40) + 1, b"a")])),
        Err(ProtocolError::TooLarge)
    ));
    let m = Message::OfferFiles(vec![offered("a", (1 << 40) + 1)]);
    assert!(encode(&m, &mut Vec::new()).is_err());
    // Кадр OFFER_FILES больше 64 КиБ не кодируется.
    let many: Vec<_> = (0..100).map(|_| offered(&"n".repeat(1000), 1)).collect();
    assert!(matches!(
        encode(&Message::OfferFiles(many), &mut Vec::new()),
        Err(ProtocolError::TooLong)
    ));
}

#[tokio::test]
async fn block_len_mismatch_rejected_before_payload() {
    let size = 3 * (1u64 << 20) + 5;
    let l = layout(size).unwrap();
    assert_eq!(l.block_count, 4);
    let payload_len = 1usize << 20;
    for (block, len) in [(0u32, (1u32 << 20) + 1), (0, (1 << 20) - 1), (3, 6), (4, 5)] {
        let mut data = frame(&Message::Block {
            index: 0,
            block,
            len,
        });
        let head_len = data.len();
        data.extend(vec![0x55; payload_len]);
        let mut rx = MemRx::new(data);
        let mut buf = Vec::new();
        let msg = read_message(&mut rx, &mut buf, Duration::from_secs(1))
            .await
            .unwrap()
            .unwrap();
        let Message::Block { block, len, .. } = msg else {
            panic!("не BLOCK");
        };
        assert!(matches!(
            check_block_len(size, l, block, len),
            Err(ProtocolError::Malformed)
        ));
        assert_eq!(rx.taken(), head_len, "тело блока не прочитано");
    }
    check_block_len(size, l, 0, 1 << 20).unwrap();
    check_block_len(size, l, 3, 5).unwrap();
}

#[test]
fn codec_nonzero_rejected() {
    let good = body(&Message::Block {
        index: 1,
        block: 2,
        len: 100,
    });
    assert!(decode_message(&good).is_ok());
    for codec in 1..=255u8 {
        let mut b = good.clone();
        b[9] = codec;
        assert!(
            matches!(decode_message(&b), Err(ProtocolError::UnsupportedCodec)),
            "codec {codec}"
        );
    }
    // Длина тела блока 0 и сверх 16 МиБ не бывает.
    let mut b = good.clone();
    b[10..14].copy_from_slice(&0u32.to_be_bytes());
    assert!(matches!(decode_message(&b), Err(ProtocolError::Malformed)));
    b[10..14].copy_from_slice(&((1u32 << 24) + 1).to_be_bytes());
    assert!(matches!(decode_message(&b), Err(ProtocolError::TooLarge)));
}

#[test]
fn manifest_layout_mismatch_rejected() {
    let size = 5 * (1u64 << 20) + 1;
    let l = check_manifest_layout(size, 1 << 20, 6).unwrap();
    assert_eq!(l.block_count, 6);
    for (bs, bc) in [(1u32 << 21, 6u32), (1 << 20, 5), (1 << 20, 7), (1 << 20, 0)] {
        assert!(matches!(
            check_manifest_layout(size, bs, bc),
            Err(ProtocolError::Malformed)
        ));
    }
    assert!(matches!(
        check_manifest_layout((1 << 40) + 1, 1 << 24, 65_536),
        Err(ProtocolError::TooLarge)
    ));
    // Нелепые поля MANIFEST отвергает уже декодер, до чтения хэшей.
    for (bs, bc) in [
        (0u32, 1u32),
        ((1 << 20) - 1, 1),
        ((1 << 24) + 1, 1),
        (1 << 20, 65_537),
    ] {
        let m = body(&Message::Manifest {
            index: 0,
            block_size: 1 << 20,
            block_count: 1,
            root: FileRoot([0; 32]),
        });
        let mut b = m;
        b[5..9].copy_from_slice(&bs.to_be_bytes());
        b[9..13].copy_from_slice(&bc.to_be_bytes());
        assert!(decode_message(&b).is_err(), "bs {bs} bc {bc}");
    }
}

#[tokio::test(start_paused = true)]
async fn read_message_deadline() {
    let f = frame(&Message::Done { id: ID });
    // Заголовок и часть тела, дальше тишина: срабатывает срок кадра.
    let mut rx = MemRx::hanging(f[..10].to_vec());
    let mut buf = Vec::new();
    let t0 = tokio::time::Instant::now();
    let r = read_message(&mut rx, &mut buf, Duration::from_secs(5)).await;
    assert!(matches!(r, Err(ProtocolError::TimedOut)));
    assert_eq!(t0.elapsed(), Duration::from_secs(5));
    // Только часть длины.
    let mut rx = MemRx::hanging(f[..2].to_vec());
    let r = read_message(&mut rx, &mut buf, Duration::from_secs(5)).await;
    assert!(matches!(r, Err(ProtocolError::TimedOut)));
    // Срок общий на кадр: по байту раз в 2 секунды не успевает за 5 секунд.
    let mut rx = MemRx::chunked(f.clone(), 1);
    let r = tokio::time::timeout(
        Duration::from_secs(60),
        read_message(&mut rx, &mut buf, Duration::from_secs(5)),
    )
    .await
    .unwrap();
    assert!(r.is_ok(), "быстрый поток укладывается в срок");
    // Ожидание самого первого байта не ограничено сроком кадра.
    let mut rx = MemRx::hanging(Vec::new());
    let outer = tokio::time::timeout(
        Duration::from_secs(3600),
        read_message(&mut rx, &mut buf, Duration::from_secs(5)),
    )
    .await;
    assert!(outer.is_err(), "ограничивает только внешний срок");
}

#[tokio::test(start_paused = true)]
async fn read_exact_stall_is_progress_based() {
    // Данные пришли целиком, затем конец потока раньше срока: Closed.
    let mut rx = MemRx::new(vec![1; 10]);
    let mut out = [0u8; 20];
    let r = read_exact(&mut rx, &mut out, Duration::from_secs(5)).await;
    assert!(matches!(r, Err(ProtocolError::Closed)));
    // Тишина дольше stall: TimedOut.
    let mut rx = MemRx::hanging(vec![1; 10]);
    let t0 = tokio::time::Instant::now();
    let r = read_exact(&mut rx, &mut out, Duration::from_secs(5)).await;
    assert!(matches!(r, Err(ProtocolError::TimedOut)));
    assert_eq!(t0.elapsed(), Duration::from_secs(5));
    // Ровно столько, сколько просили, и не больше.
    let mut rx = MemRx::chunked(vec![2; 100], 7);
    let mut out = [0u8; 50];
    read_exact(&mut rx, &mut out, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(rx.taken(), 50);
    assert!(out.iter().all(|b| *b == 2));
    // Пустой буфер не читает ничего.
    let mut rx = MemRx::new(vec![3; 4]);
    read_exact(&mut rx, &mut [], Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(rx.taken(), 0);
}

#[tokio::test]
async fn read_message_clean_eof() {
    let mut buf = Vec::new();
    let mut rx = MemRx::new(Vec::new());
    assert!(
        read_message(&mut rx, &mut buf, Duration::from_secs(1))
            .await
            .unwrap()
            .is_none()
    );
    // Два кадра подряд (по одному байту за чтение), потом чистый конец.
    let mut data = frame(&Message::GetManifest { index: 4 });
    data.extend(frame(&Message::FileDone { index: 5 }));
    let mut rx = MemRx::chunked(data, 1);
    let a = read_message(&mut rx, &mut buf, Duration::from_secs(1))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(a, Message::GetManifest { index: 4 }));
    let b = read_message(&mut rx, &mut buf, Duration::from_secs(1))
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(b, Message::FileDone { index: 5 }));
    assert!(
        read_message(&mut rx, &mut buf, Duration::from_secs(1))
            .await
            .unwrap()
            .is_none()
    );
    // Конец посреди длины и посреди тела это обрыв, не чистый конец.
    let f = frame(&Message::Done { id: ID });
    for cut in [1usize, 3, 4, 10, f.len() - 1] {
        let mut rx = MemRx::new(f[..cut].to_vec());
        let r = read_message(&mut rx, &mut buf, Duration::from_secs(1)).await;
        assert!(matches!(r, Err(ProtocolError::Closed)), "cut {cut}");
    }
}
