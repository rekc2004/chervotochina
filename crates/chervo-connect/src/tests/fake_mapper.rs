//! Поддельный отображатель портов для тестов задачи проброса: записывает вызовы, отвечает
//! по сценарию. Сети нет.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chervo_addr::{GatewayInfo, MapReport, MapRequest, MapStatus, PortMapper};

type Script = Box<dyn Fn(usize, MapRequest) -> MapReport + Send + Sync>;

pub struct FakeMapper {
    pub calls: Mutex<Vec<MapRequest>>,
    pub releases: AtomicUsize,
    cur: AtomicUsize,
    pub max_concurrent: AtomicUsize,
    script: Script,
}

impl FakeMapper {
    /// `f(номер вызова с нуля, запрос)`. Сценарий может блокировать поток (настоящее время).
    pub fn new(f: impl Fn(usize, MapRequest) -> MapReport + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            calls: Mutex::new(Vec::new()),
            releases: AtomicUsize::new(0),
            cur: AtomicUsize::new(0),
            max_concurrent: AtomicUsize::new(0),
            script: Box::new(f),
        })
    }

    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    pub fn call(&self, i: usize) -> MapRequest {
        self.calls.lock().unwrap()[i]
    }

    pub fn release_count(&self) -> usize {
        self.releases.load(Ordering::SeqCst)
    }
}

impl PortMapper for FakeMapper {
    fn refresh(&self, req: MapRequest) -> MapReport {
        let n = {
            let mut c = self.calls.lock().unwrap();
            c.push(req);
            c.len() - 1
        };
        let cur = self.cur.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_concurrent.fetch_max(cur, Ordering::SeqCst);
        let r = (self.script)(n, req);
        self.cur.fetch_sub(1, Ordering::SeqCst);
        r
    }

    fn release(&self) {
        self.releases.fetch_add(1, Ordering::SeqCst);
    }
}

/// Подтверждённый проброс на внешний адрес `wan` и порт `ext`.
pub fn mapped(wan: &str, ext: u16, retry_secs: u64) -> MapReport {
    let ip: Ipv4Addr = wan.parse().unwrap();
    MapReport {
        status: MapStatus::Mapped,
        gateway: Some(GatewayInfo {
            wan_ip: Some(ip),
            mapping: Some(SocketAddrV4::new(ip, ext)),
        }),
        retry_after: Duration::from_secs(retry_secs),
    }
}

/// Итог без шлюза.
pub fn plain(status: MapStatus, retry_secs: u64) -> MapReport {
    MapReport {
        status,
        gateway: None,
        retry_after: Duration::from_secs(retry_secs),
    }
}

/// Явный сдвиг приостановленного времени. Пока в `spawn_blocking` идёт вызов (завис), tokio
/// не продвигает время сам: `sleep` в таком тесте не вернулся бы никогда.
pub async fn advance(d: Duration) {
    tokio::time::advance(d).await;
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
}

/// Ждёт условие, отдавая управление задачам движка; предел по настоящему времени 5 с.
pub async fn wait_until(mut f: impl FnMut() -> bool) {
    for _ in 0..5000 {
        if f() {
            return;
        }
        tokio::task::yield_now().await;
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("condition not reached");
}
