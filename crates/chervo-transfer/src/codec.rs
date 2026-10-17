//! Кадры протокола передачи: длина u32 (1..=64 КиБ), тип u8, поля. Числа big-endian.
//! Сообщения фиксированной длины принимаются только с точной длиной; остаток после полей
//! отвергается. Сырые данные (хэши манифеста, тело блока) идут после кадра и читаются отдельно.

use std::fmt;

use crate::hash::FileRoot;
use crate::limits::{
    ENTRY_OVERHEAD, MAX_BLOCK, MAX_BLOCKS, MAX_FILE_SIZE, MAX_FILES_PER_OFFER, MAX_MESSAGE_LEN,
    MAX_OFFER_BYTES, MAX_OFFER_TOTAL, MIN_BLOCK, PROTO_VERSION,
};
use crate::names::{OfferedFile, TransferId, UntrustedName};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProtocolError {
    TooLong,
    Malformed,
    UnknownType,
    BadVersion,
    TooLarge,
    BadName,
    UnsupportedCodec,
    Unexpected,
    TimedOut,
    Closed,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::TooLong => "message too long",
            Self::Malformed => "malformed message",
            Self::UnknownType => "unknown message type",
            Self::BadVersion => "unsupported protocol version",
            Self::TooLarge => "value over limit",
            Self::BadName => "invalid name",
            Self::UnsupportedCodec => "unsupported block codec",
            Self::Unexpected => "unexpected message",
            Self::TimedOut => "timed out",
            Self::Closed => "stream closed",
        };
        f.write_str(text)
    }
}

impl std::error::Error for ProtocolError {}

/// Ответ получателя на предложение (поле `verdict` DECISION).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Decline,
    Busy,
    Expired,
    Limits,
}

impl Verdict {
    fn to_u8(self) -> u8 {
        match self {
            Self::Accept => 1,
            Self::Decline => 2,
            Self::Busy => 3,
            Self::Expired => 4,
            Self::Limits => 5,
        }
    }

    fn from_u8(v: u8) -> Result<Self, ProtocolError> {
        Ok(match v {
            1 => Self::Accept,
            2 => Self::Decline,
            3 => Self::Busy,
            4 => Self::Expired,
            5 => Self::Limits,
            _ => return Err(ProtocolError::Malformed),
        })
    }
}

/// Причина CANCEL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelReason {
    User,
    Unknown,
    Protocol,
    Limits,
}

impl CancelReason {
    fn to_u8(self) -> u8 {
        match self {
            Self::User => 1,
            Self::Unknown => 2,
            Self::Protocol => 3,
            Self::Limits => 4,
        }
    }

    fn from_u8(v: u8) -> Result<Self, ProtocolError> {
        Ok(match v {
            1 => Self::User,
            2 => Self::Unknown,
            3 => Self::Protocol,
            4 => Self::Limits,
            _ => return Err(ProtocolError::Malformed),
        })
    }
}

/// Код FILE_ERROR: 1, 2 шлёт отправитель; 3, 4, 5 получатель (направление проверяет сессия).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileErrCode {
    SourceChanged,
    ReadError,
    Damaged,
    WriteError,
    PlaceFailed,
}

impl FileErrCode {
    fn to_u8(self) -> u8 {
        match self {
            Self::SourceChanged => 1,
            Self::ReadError => 2,
            Self::Damaged => 3,
            Self::WriteError => 4,
            Self::PlaceFailed => 5,
        }
    }

    fn from_u8(v: u8) -> Result<Self, ProtocolError> {
        Ok(match v {
            1 => Self::SourceChanged,
            2 => Self::ReadError,
            3 => Self::Damaged,
            4 => Self::WriteError,
            5 => Self::PlaceFailed,
            _ => return Err(ProtocolError::Malformed),
        })
    }
}

/// Код BLOCK_ERR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockErrCode {
    SourceChanged,
    ReadError,
}

impl BlockErrCode {
    fn to_u8(self) -> u8 {
        match self {
            Self::SourceChanged => 1,
            Self::ReadError => 2,
        }
    }

    fn from_u8(v: u8) -> Result<Self, ProtocolError> {
        Ok(match v {
            1 => Self::SourceChanged,
            2 => Self::ReadError,
            _ => return Err(ProtocolError::Malformed),
        })
    }
}

/// Без Debug: внутри бывают имена. Версия протокола в сообщении не хранится: `encode` пишет
/// `PROTO_VERSION`, `decode_message` другую версию отвергает. `Manifest` и `Block` это только
/// заголовки; сырые байты читаются и пишутся отдельно.
pub enum Message {
    OfferHead {
        id: TransferId,
        file_count: u32,
        total_size: u64,
        offer_bytes: u32,
    },
    OfferFiles(Vec<OfferedFile>),
    Decision {
        id: TransferId,
        verdict: Verdict,
    },
    Cancel {
        id: TransferId,
        reason: CancelReason,
    },
    FileError {
        index: u32,
        code: FileErrCode,
    },
    FileDone {
        index: u32,
    },
    Done {
        id: TransferId,
    },
    Resume {
        id: TransferId,
    },
    ResumeOk {
        id: TransferId,
        file_count: u32,
        total_size: u64,
    },
    Bind {
        id: TransferId,
    },
    GetManifest {
        index: u32,
    },
    Manifest {
        index: u32,
        block_size: u32,
        block_count: u32,
        root: FileRoot,
    },
    GetBlock {
        index: u32,
        block: u32,
    },
    /// Кодек всегда 0 (сырой); другой отвергается как `UnsupportedCodec`.
    Block {
        index: u32,
        block: u32,
        len: u32,
    },
    BlockErr {
        index: u32,
        block: u32,
        code: BlockErrCode,
    },
}

const T_OFFER_HEAD: u8 = 0x01;
const T_OFFER_FILES: u8 = 0x02;
const T_DECISION: u8 = 0x03;
const T_CANCEL: u8 = 0x04;
const T_FILE_ERROR: u8 = 0x05;
const T_FILE_DONE: u8 = 0x06;
const T_DONE: u8 = 0x07;
const T_RESUME: u8 = 0x08;
const T_RESUME_OK: u8 = 0x09;
const T_BIND: u8 = 0x10;
const T_GET_MANIFEST: u8 = 0x11;
const T_MANIFEST: u8 = 0x12;
const T_GET_BLOCK: u8 = 0x13;
const T_BLOCK: u8 = 0x14;
const T_BLOCK_ERR: u8 = 0x15;

/// Единственный допустимый кодек блока: сырые байты.
const CODEC_RAW: u8 = 0;

/// Читатель среза без паник: любая нехватка байт это `Malformed`.
pub(crate) struct Rd<'a>(&'a [u8]);

impl<'a> Rd<'a> {
    pub(crate) fn new(b: &'a [u8]) -> Self {
        Self(b)
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], ProtocolError> {
        let (head, rest) = self.0.split_at_checked(n).ok_or(ProtocolError::Malformed)?;
        self.0 = rest;
        Ok(head)
    }

    pub(crate) fn arr<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(ProtocolError::Malformed)?;
        self.0 = rest;
        Ok(*head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(u8::from_be_bytes(self.arr::<1>()?))
    }

    pub(crate) fn u16(&mut self) -> Result<u16, ProtocolError> {
        Ok(u16::from_be_bytes(self.arr::<2>()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, ProtocolError> {
        Ok(u32::from_be_bytes(self.arr::<4>()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_be_bytes(self.arr::<8>()?))
    }

    /// Остаток обязан быть пустым.
    pub(crate) fn end(&self) -> Result<(), ProtocolError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(ProtocolError::Malformed)
        }
    }
}

fn check_head(file_count: u32, total_size: u64, offer_bytes: u32) -> Result<(), ProtocolError> {
    if file_count == 0 || offer_bytes == 0 {
        return Err(ProtocolError::Malformed);
    }
    if file_count > MAX_FILES_PER_OFFER
        || total_size > MAX_OFFER_TOTAL
        || offer_bytes > MAX_OFFER_BYTES
    {
        return Err(ProtocolError::TooLarge);
    }
    Ok(())
}

fn check_manifest_fields(block_size: u32, block_count: u32) -> Result<(), ProtocolError> {
    if !(MIN_BLOCK..=MAX_BLOCK).contains(&block_size) {
        return Err(ProtocolError::Malformed);
    }
    if block_count > MAX_BLOCKS {
        return Err(ProtocolError::TooLarge);
    }
    Ok(())
}

fn check_block_field(len: u32) -> Result<(), ProtocolError> {
    if len == 0 {
        return Err(ProtocolError::Malformed);
    }
    if len > MAX_BLOCK {
        return Err(ProtocolError::TooLarge);
    }
    Ok(())
}

fn check_version(v: u8) -> Result<(), ProtocolError> {
    if v == PROTO_VERSION {
        Ok(())
    } else {
        Err(ProtocolError::BadVersion)
    }
}

/// Тело кадра (без 4 байт длины) в сообщение. Длина сверх `MAX_MESSAGE_LEN` даёт `TooLong`.
/// Здесь проверяются только поля самого кадра; сверка с размером файла и направлением
/// потока делается сессией.
pub fn decode_message(body: &[u8]) -> Result<Message, ProtocolError> {
    if body.len() > MAX_MESSAGE_LEN {
        return Err(ProtocolError::TooLong);
    }
    let mut r = Rd::new(body);
    let ty = r.u8()?;
    // Длина фиксированных сообщений проверяется до разбора полей: `Malformed` важнее версии.
    let fixed = |want: usize, got: usize| -> Result<(), ProtocolError> {
        if got == want {
            Ok(())
        } else {
            Err(ProtocolError::Malformed)
        }
    };
    let rest = r.len();
    let msg = match ty {
        T_OFFER_HEAD => {
            fixed(33, rest)?;
            check_version(r.u8()?)?;
            let id = TransferId(r.arr()?);
            let file_count = r.u32()?;
            let total_size = r.u64()?;
            let offer_bytes = r.u32()?;
            check_head(file_count, total_size, offer_bytes)?;
            Message::OfferHead {
                id,
                file_count,
                total_size,
                offer_bytes,
            }
        }
        T_OFFER_FILES => Message::OfferFiles(decode_entries(&mut r)?),
        T_DECISION => {
            fixed(17, rest)?;
            Message::Decision {
                id: TransferId(r.arr()?),
                verdict: Verdict::from_u8(r.u8()?)?,
            }
        }
        T_CANCEL => {
            fixed(17, rest)?;
            Message::Cancel {
                id: TransferId(r.arr()?),
                reason: CancelReason::from_u8(r.u8()?)?,
            }
        }
        T_FILE_ERROR => {
            fixed(5, rest)?;
            Message::FileError {
                index: r.u32()?,
                code: FileErrCode::from_u8(r.u8()?)?,
            }
        }
        T_FILE_DONE => {
            fixed(4, rest)?;
            Message::FileDone { index: r.u32()? }
        }
        T_DONE => {
            fixed(16, rest)?;
            Message::Done {
                id: TransferId(r.arr()?),
            }
        }
        T_RESUME => {
            fixed(17, rest)?;
            check_version(r.u8()?)?;
            Message::Resume {
                id: TransferId(r.arr()?),
            }
        }
        T_RESUME_OK => {
            fixed(28, rest)?;
            Message::ResumeOk {
                id: TransferId(r.arr()?),
                file_count: r.u32()?,
                total_size: r.u64()?,
            }
        }
        T_BIND => {
            fixed(17, rest)?;
            check_version(r.u8()?)?;
            Message::Bind {
                id: TransferId(r.arr()?),
            }
        }
        T_GET_MANIFEST => {
            fixed(4, rest)?;
            Message::GetManifest { index: r.u32()? }
        }
        T_MANIFEST => {
            fixed(44, rest)?;
            let index = r.u32()?;
            let block_size = r.u32()?;
            let block_count = r.u32()?;
            let root = FileRoot(r.arr()?);
            check_manifest_fields(block_size, block_count)?;
            Message::Manifest {
                index,
                block_size,
                block_count,
                root,
            }
        }
        T_GET_BLOCK => {
            fixed(8, rest)?;
            Message::GetBlock {
                index: r.u32()?,
                block: r.u32()?,
            }
        }
        T_BLOCK => {
            fixed(13, rest)?;
            let index = r.u32()?;
            let block = r.u32()?;
            if r.u8()? != CODEC_RAW {
                return Err(ProtocolError::UnsupportedCodec);
            }
            let len = r.u32()?;
            check_block_field(len)?;
            Message::Block { index, block, len }
        }
        T_BLOCK_ERR => {
            fixed(9, rest)?;
            Message::BlockErr {
                index: r.u32()?,
                block: r.u32()?,
                code: BlockErrCode::from_u8(r.u8()?)?,
            }
        }
        _ => return Err(ProtocolError::UnknownType),
    };
    r.end()?;
    Ok(msg)
}

/// Записи OFFER_FILES. Запись не пересекает границу кадра: нехватка байт это `Malformed`.
fn decode_entries(r: &mut Rd<'_>) -> Result<Vec<OfferedFile>, ProtocolError> {
    let count = usize::from(r.u16()?);
    if count == 0 {
        return Err(ProtocolError::Malformed);
    }
    // Каждая запись занимает не меньше 11 байт: больше записей в кадр не влезет.
    let min_entry = usize::try_from(ENTRY_OVERHEAD)
        .unwrap_or(10)
        .saturating_add(1);
    let cap = count.min(r.len() / min_entry);
    let mut files = Vec::with_capacity(cap);
    for _ in 0..count {
        let size = r.u64()?;
        let name_len = usize::from(r.u16()?);
        if name_len == 0 || name_len > crate::limits::MAX_NAME_BYTES {
            return Err(ProtocolError::BadName);
        }
        if size > MAX_FILE_SIZE {
            return Err(ProtocolError::TooLarge);
        }
        let name = UntrustedName::from_bytes(r.take(name_len)?)?;
        files.push(OfferedFile { name, size });
    }
    Ok(files)
}

fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_id(out: &mut Vec<u8>, id: &TransferId) {
    out.extend_from_slice(&id.0);
}

/// Дописывает в `out` кадр: u32 длины и тело. Значения вне границ, которые `decode_message`
/// отверг бы, кодирование тоже отвергает (`out` тогда не меняется).
pub fn encode(msg: &Message, out: &mut Vec<u8>) -> Result<(), ProtocolError> {
    let mut body: Vec<u8> = Vec::new();
    match msg {
        Message::OfferHead {
            id,
            file_count,
            total_size,
            offer_bytes,
        } => {
            check_head(*file_count, *total_size, *offer_bytes)?;
            body.push(T_OFFER_HEAD);
            body.push(PROTO_VERSION);
            put_id(&mut body, id);
            put_u32(&mut body, *file_count);
            put_u64(&mut body, *total_size);
            put_u32(&mut body, *offer_bytes);
        }
        Message::OfferFiles(files) => {
            if files.is_empty() {
                return Err(ProtocolError::Malformed);
            }
            let count = u16::try_from(files.len()).map_err(|_| ProtocolError::TooLong)?;
            body.push(T_OFFER_FILES);
            body.extend_from_slice(&count.to_be_bytes());
            for f in files {
                if f.size > MAX_FILE_SIZE {
                    return Err(ProtocolError::TooLarge);
                }
                let name = f.name.untrusted_str().as_bytes();
                let name_len = u16::try_from(name.len()).map_err(|_| ProtocolError::BadName)?;
                put_u64(&mut body, f.size);
                body.extend_from_slice(&name_len.to_be_bytes());
                body.extend_from_slice(name);
                if body.len() > MAX_MESSAGE_LEN {
                    return Err(ProtocolError::TooLong);
                }
            }
        }
        Message::Decision { id, verdict } => {
            body.push(T_DECISION);
            put_id(&mut body, id);
            body.push(verdict.to_u8());
        }
        Message::Cancel { id, reason } => {
            body.push(T_CANCEL);
            put_id(&mut body, id);
            body.push(reason.to_u8());
        }
        Message::FileError { index, code } => {
            body.push(T_FILE_ERROR);
            put_u32(&mut body, *index);
            body.push(code.to_u8());
        }
        Message::FileDone { index } => {
            body.push(T_FILE_DONE);
            put_u32(&mut body, *index);
        }
        Message::Done { id } => {
            body.push(T_DONE);
            put_id(&mut body, id);
        }
        Message::Resume { id } => {
            body.push(T_RESUME);
            body.push(PROTO_VERSION);
            put_id(&mut body, id);
        }
        Message::ResumeOk {
            id,
            file_count,
            total_size,
        } => {
            body.push(T_RESUME_OK);
            put_id(&mut body, id);
            put_u32(&mut body, *file_count);
            put_u64(&mut body, *total_size);
        }
        Message::Bind { id } => {
            body.push(T_BIND);
            body.push(PROTO_VERSION);
            put_id(&mut body, id);
        }
        Message::GetManifest { index } => {
            body.push(T_GET_MANIFEST);
            put_u32(&mut body, *index);
        }
        Message::Manifest {
            index,
            block_size,
            block_count,
            root,
        } => {
            check_manifest_fields(*block_size, *block_count)?;
            body.push(T_MANIFEST);
            put_u32(&mut body, *index);
            put_u32(&mut body, *block_size);
            put_u32(&mut body, *block_count);
            body.extend_from_slice(&root.0);
        }
        Message::GetBlock { index, block } => {
            body.push(T_GET_BLOCK);
            put_u32(&mut body, *index);
            put_u32(&mut body, *block);
        }
        Message::Block { index, block, len } => {
            check_block_field(*len)?;
            body.push(T_BLOCK);
            put_u32(&mut body, *index);
            put_u32(&mut body, *block);
            body.push(CODEC_RAW);
            put_u32(&mut body, *len);
        }
        Message::BlockErr { index, block, code } => {
            body.push(T_BLOCK_ERR);
            put_u32(&mut body, *index);
            put_u32(&mut body, *block);
            body.push(code.to_u8());
        }
    }
    if body.len() > MAX_MESSAGE_LEN {
        return Err(ProtocolError::TooLong);
    }
    let len = u32::try_from(body.len()).map_err(|_| ProtocolError::TooLong)?;
    put_u32(out, len);
    out.extend_from_slice(&body);
    Ok(())
}

/// Сборка предложения на стороне получателя. Заголовок и каждая порция записей сверяются с
/// заявленными `file_count`, `offer_bytes` и `total_size`: превышение видно сразу, равенство
/// проверяется в `finish`. После любой ошибки сборщик отвергает всё дальнейшее.
pub struct OfferAssembler {
    file_count: u32,
    total_size: u64,
    offer_bytes: u32,
    files: Vec<OfferedFile>,
    bytes: u64,
    sum: u64,
    failed: bool,
}

impl OfferAssembler {
    /// Поля OFFER_HEAD проверяются по тем же границам, что и в `decode_message`.
    pub fn new(file_count: u32, total_size: u64, offer_bytes: u32) -> Result<Self, ProtocolError> {
        check_head(file_count, total_size, offer_bytes)?;
        Ok(Self {
            file_count,
            total_size,
            offer_bytes,
            files: Vec::new(),
            bytes: 0,
            sum: 0,
            failed: false,
        })
    }

    /// Добавляет записи одного кадра OFFER_FILES. `Ok(true)`: все записи получены
    /// (`finish` ещё проверит точные суммы).
    pub fn push(&mut self, entries: Vec<OfferedFile>) -> Result<bool, ProtocolError> {
        if self.failed {
            return Err(ProtocolError::Malformed);
        }
        for e in entries {
            if let Err(err) = self.add(e) {
                self.failed = true;
                return Err(err);
            }
        }
        Ok(self.is_complete())
    }

    fn add(&mut self, e: OfferedFile) -> Result<(), ProtocolError> {
        if e.size > MAX_FILE_SIZE {
            return Err(ProtocolError::TooLarge);
        }
        let have = u32::try_from(self.files.len()).map_err(|_| ProtocolError::Malformed)?;
        if have >= self.file_count {
            return Err(ProtocolError::Malformed);
        }
        let entry_bytes = ENTRY_OVERHEAD
            .checked_add(u64::try_from(e.name.len()).map_err(|_| ProtocolError::BadName)?)
            .ok_or(ProtocolError::Malformed)?;
        let bytes = self
            .bytes
            .checked_add(entry_bytes)
            .ok_or(ProtocolError::Malformed)?;
        if bytes > u64::from(self.offer_bytes) {
            return Err(ProtocolError::Malformed);
        }
        let sum = self
            .sum
            .checked_add(e.size)
            .ok_or(ProtocolError::Malformed)?;
        if sum > self.total_size {
            return Err(ProtocolError::Malformed);
        }
        self.bytes = bytes;
        self.sum = sum;
        self.files.push(e);
        Ok(())
    }

    /// Получено ровно `file_count` записей.
    pub fn is_complete(&self) -> bool {
        u32::try_from(self.files.len()).ok() == Some(self.file_count)
    }

    /// Точные равенства: число записей, байты записей, сумма размеров.
    pub fn finish(self) -> Result<Vec<OfferedFile>, ProtocolError> {
        if self.failed
            || !self.is_complete()
            || self.bytes != u64::from(self.offer_bytes)
            || self.sum != self.total_size
        {
            return Err(ProtocolError::Malformed);
        }
        Ok(self.files)
    }
}
