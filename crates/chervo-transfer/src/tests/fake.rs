//! Поддельный отправитель: говорит по проводу напрямую (кодек крейта) и может подменять
//! ответы. Нужен, чтобы проверить получателя против враждебного или сломанного узла.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_identity::PairId;
use chervo_transport::{Connection, RecvStream, SendStream};

use super::kit::{FakeConn, FakeRx, FakeTx, recv_frame, send_frame};
use crate::{
    BlockErrCode, BlockHash, CancelReason, FileRoot, Layout, Message, OfferedFile, TransferId,
    TransferKey, UntrustedName, Verdict, block_len, file_root, layout, leaf_hash, read_message,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Req {
    Manifest(u32),
    /// Файл, блок, какой раз по счёту запрошен этот блок (с 1).
    Block(u32, u32, u32),
}

pub enum Resp {
    Normal,
    /// Не отвечать (поток молчит).
    Silent,
    /// Верные данные с одним испорченным байтом.
    Flip,
    /// Произвольное тело блока (длина верная, содержимое чужое).
    Custom(Vec<u8>),
    /// В заголовке BLOCK ложная длина; тело не отправляется.
    LieLen(u32),
    BlockErr(BlockErrCode),
    /// Закрыть поток.
    Drop,
}

type Responder = Box<dyn FnMut(&Req) -> Resp + Send>;

pub struct FakeFile {
    pub name: String,
    pub data: Vec<u8>,
    pub layout: Layout,
    pub leaves: Vec<BlockHash>,
    pub root: FileRoot,
}

impl FakeFile {
    pub fn new(name: &str, data: Vec<u8>) -> Self {
        let size = data.len() as u64;
        let l = layout(size).unwrap();
        let leaves: Vec<BlockHash> = (0..l.block_count)
            .map(|i| {
                let len = block_len(size, l, i).unwrap() as usize;
                let off = i as usize * l.block_size as usize;
                leaf_hash(i, &data[off..off + len])
            })
            .collect();
        let root = file_root(size, l, &leaves).unwrap();
        Self {
            name: name.to_owned(),
            data,
            layout: l,
            leaves,
            root,
        }
    }

    pub fn block(&self, b: u32) -> Vec<u8> {
        let size = self.data.len() as u64;
        let len = block_len(size, self.layout, b).unwrap() as usize;
        let off = b as usize * self.layout.block_size as usize;
        self.data[off..off + len].to_vec()
    }
}

#[derive(Default)]
pub struct Log {
    pub requests: Vec<Req>,
    pub ctl: Vec<String>,
    pub binds: usize,
    pub rejected_streams: usize,
}

pub struct Fake {
    pub key: TransferKey,
    pub files: Arc<Vec<FakeFile>>,
    pub log: Arc<Mutex<Log>>,
    /// Не отвечать на DONE получателя (эхо потеряно), соединение оставить живым.
    pub drop_done_echo: Arc<AtomicBool>,
    responder: Arc<Mutex<Responder>>,
    served: Arc<Mutex<HashMap<(u32, u32), u32>>>,
}

impl Fake {
    pub fn new(pair: PairId, files: Vec<FakeFile>) -> Self {
        Self {
            key: TransferKey {
                pair,
                id: TransferId::generate().unwrap(),
            },
            files: Arc::new(files),
            log: Arc::new(Mutex::new(Log::default())),
            drop_done_echo: Arc::new(AtomicBool::new(false)),
            responder: Arc::new(Mutex::new(Box::new(|_| Resp::Normal))),
            served: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn respond_with(&self, f: impl FnMut(&Req) -> Resp + Send + 'static) {
        *self.responder.lock().unwrap() = Box::new(f);
    }

    pub fn total(&self) -> u64 {
        self.files.iter().map(|f| f.data.len() as u64).sum()
    }

    /// Открывает поток управления и шлёт предложение. Возвращает потоки.
    pub async fn offer(&self, conn: &FakeConn) -> (FakeTx, FakeRx) {
        let (mut tx, rx) = conn.open_bi().await.unwrap();
        let list: Vec<OfferedFile> = self
            .files
            .iter()
            .map(|f| OfferedFile {
                name: UntrustedName::new(&f.name).unwrap(),
                size: f.data.len() as u64,
            })
            .collect();
        let bytes: u32 = list.iter().map(|f| 10 + f.name.len() as u32).sum();
        tx.write_all(&[crate::STREAM_TRANSFER_CTL]).await.unwrap();
        send_frame(
            &mut tx,
            &Message::OfferHead {
                id: self.key.id,
                file_count: list.len() as u32,
                total_size: self.total(),
                offer_bytes: bytes,
            },
        )
        .await;
        send_frame(&mut tx, &Message::OfferFiles(list)).await;
        (tx, rx)
    }

    /// Читает ответ получателя на предложение.
    pub async fn decision(rx: &mut FakeRx, secs: u64) -> Option<Verdict> {
        match recv_frame(rx, secs).await? {
            Message::Decision { verdict, .. } => Some(verdict),
            _ => None,
        }
    }

    /// Принимает потоки данных от получателя и обслуживает их, пока соединение живо.
    /// Поток управления (`ctl`) читается отдельной задачей: сначала уходит HASH_PROGRESS на весь
    /// размер предложения, события пишутся в журнал, на DONE отвечает DONE. Без `ctl` поток
    /// управления ведёт тест.
    pub fn run(&self, peer: FakeConn, ctl: Option<(FakeTx, FakeRx)>) {
        if let Some((mut tx, mut rx)) = ctl {
            let log = self.log.clone();
            let id = self.key.id;
            let drop_echo = self.drop_done_echo.clone();
            let total = self.total();
            tokio::spawn(async move {
                // как настоящий отправитель: после принятия сообщает, что всё захэшировано
                send_frame(&mut tx, &Message::HashProgress { hashed: total }).await;
                let mut buf = Vec::new();
                loop {
                    match read_message(&mut rx, &mut buf, Duration::from_secs(30)).await {
                        Ok(Some(Message::FileDone { index })) => {
                            log.lock().unwrap().ctl.push(format!("file_done {index}"));
                        }
                        Ok(Some(Message::FileError { index, code })) => {
                            log.lock()
                                .unwrap()
                                .ctl
                                .push(format!("file_error {index} {code:?}"));
                        }
                        Ok(Some(Message::Cancel { reason, .. })) => {
                            log.lock().unwrap().ctl.push(format!("cancel {reason:?}"));
                        }
                        Ok(Some(Message::Done { .. })) => {
                            log.lock().unwrap().ctl.push("done".to_owned());
                            if drop_echo.load(Ordering::SeqCst) {
                                // эхо потеряно: поток управления остаётся открытым
                                std::future::pending::<()>().await;
                            }
                            send_frame(&mut tx, &Message::Done { id }).await;
                            let _ = tx.finish();
                            break;
                        }
                        _ => break,
                    }
                }
            });
        }
        let (files, log, resp, served) = (
            self.files.clone(),
            self.log.clone(),
            self.responder.clone(),
            self.served.clone(),
        );
        let id = self.key.id;
        tokio::spawn(async move {
            while let Ok((tx, rx)) = peer.accept_bi().await {
                let (files, log, resp, served) =
                    (files.clone(), log.clone(), resp.clone(), served.clone());
                tokio::spawn(serve_stream(tx, rx, id, files, log, resp, served));
            }
        });
    }
}

async fn serve_stream(
    mut tx: FakeTx,
    mut rx: FakeRx,
    id: TransferId,
    files: Arc<Vec<FakeFile>>,
    log: Arc<Mutex<Log>>,
    resp: Arc<Mutex<Responder>>,
    served: Arc<Mutex<HashMap<(u32, u32), u32>>>,
) {
    let mut kind = [0u8; 1];
    match rx.read(&mut kind).await {
        Ok(Some(1)) if kind[0] == crate::STREAM_TRANSFER_DATA => {}
        _ => return,
    }
    let mut buf = Vec::new();
    match read_message(&mut rx, &mut buf, Duration::from_secs(10)).await {
        Ok(Some(Message::Bind { id: got })) if got == id => {
            log.lock().unwrap().binds += 1;
        }
        _ => {
            log.lock().unwrap().rejected_streams += 1;
            return;
        }
    }
    loop {
        let m = match read_message(&mut rx, &mut buf, Duration::from_secs(30)).await {
            Ok(Some(m)) => m,
            _ => return,
        };
        match m {
            Message::GetManifest { index } => {
                let req = Req::Manifest(index);
                log.lock().unwrap().requests.push(req.clone());
                let r = (resp.lock().unwrap())(&req);
                let Some(f) = files.get(index as usize) else {
                    return;
                };
                match r {
                    Resp::Silent => {}
                    Resp::Drop => return,
                    Resp::BlockErr(code) => {
                        send_frame(
                            &mut tx,
                            &Message::BlockErr {
                                index,
                                block: 0,
                                code,
                            },
                        )
                        .await;
                    }
                    _ => {
                        send_frame(
                            &mut tx,
                            &Message::Manifest {
                                index,
                                block_size: f.layout.block_size,
                                block_count: f.layout.block_count,
                                root: f.root,
                            },
                        )
                        .await;
                        let mut raw = Vec::new();
                        for l in &f.leaves {
                            raw.extend_from_slice(&l.0);
                        }
                        tx.write_all(&raw).await.unwrap();
                    }
                }
            }
            Message::GetBlock { index, block } => {
                let nth = {
                    let mut s = served.lock().unwrap();
                    let n = s.entry((index, block)).or_insert(0);
                    *n += 1;
                    *n
                };
                let req = Req::Block(index, block, nth);
                log.lock().unwrap().requests.push(req.clone());
                let r = (resp.lock().unwrap())(&req);
                let Some(f) = files.get(index as usize) else {
                    return;
                };
                let mut data = f.block(block);
                let len = data.len() as u32;
                match r {
                    Resp::Silent => {}
                    Resp::Drop => return,
                    Resp::BlockErr(code) => {
                        send_frame(&mut tx, &Message::BlockErr { index, block, code }).await;
                    }
                    Resp::LieLen(l) => {
                        send_frame(
                            &mut tx,
                            &Message::Block {
                                index,
                                block,
                                len: l,
                            },
                        )
                        .await;
                    }
                    other => {
                        match other {
                            Resp::Flip => {
                                if let Some(b) = data.first_mut() {
                                    *b ^= 0x55;
                                }
                            }
                            Resp::Custom(c) => data = c,
                            _ => {}
                        }
                        send_frame(&mut tx, &Message::Block { index, block, len }).await;
                        tx.write_all(&data).await.unwrap();
                    }
                }
            }
            _ => return,
        }
    }
}

/// Отмена от поддельного отправителя.
pub async fn cancel(tx: &mut FakeTx, id: TransferId, reason: CancelReason) {
    send_frame(tx, &Message::Cancel { id, reason }).await;
}
