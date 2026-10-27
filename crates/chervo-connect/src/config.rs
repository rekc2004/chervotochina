//! Настройки слоя соединения. Значения по умолчанию заданы спецификацией этапа 13.

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct ConnectConfig {
    /// Внешний порт ручного проброса (настройка пользователя).
    pub manual_forward: Option<u16>,
    pub probe_interval: Duration,
    pub tick: Duration,
    pub fast_window: Duration,
    pub fast_period: Duration,
    pub dial_base: Duration,
    pub dial_cap: Duration,
    /// Минимум между установлением соединения с другом и следующим нашим набором этой пары
    /// (ревью 13, M1): друг, обрывающий каждое соединение, не может вызвать набор чаще. Равен
    /// `dial_base` (30 с); действует только после короткого соединения, так как к концу
    /// долгого срок давно прошёл. Пользовательское «соединить сейчас» его снимает.
    pub min_redial: Duration,
    pub hint_base: Duration,
    pub hint_cap: Duration,
    pub per_ip_dials: u32,
    pub per_ip_window: Duration,
    pub max_concurrent_dials: usize,
    pub max_live: usize,
    pub limiter_capacity: usize,
    pub addr_info_timeout: Duration,
    pub addr_info_in_per_min: u32,
    pub addr_info_out_interval: Duration,
    /// Потоков зарегистрированных видов (`Engine::stream_inbox`) в минуту на одно соединение,
    /// все виды вместе; сверх этого поток сбрасывается.
    pub extra_streams_in_per_min: u32,
    /// Ёмкость приёмника потоков (`Engine::stream_inbox`); переполнен: поток сбрасывается.
    pub stream_inbox_capacity: usize,
    /// Одновременных чтений байта вида на соединение; сверх этого приём потоков ждёт
    /// (обратное давление), остальные потоки друга не страдают от одного молчащего.
    pub max_pending_kind_reads: usize,
    pub invite_session: Duration,
    /// Срок приглашающего на M1 внутри сессии (ревью 13, L2): держатель токена, молчащий
    /// после соединения, освобождает приглашение через это время, а не через `invite_session`.
    pub invite_m1_deadline: Duration,
    pub expire_interval: Duration,
    pub unreachable_after_fails: u32,
    pub udp_blocked_window: Duration,
    pub udp_blocked_min_friends: usize,
    /// Не чаще одного объявления «внешний адрес изменился» (повторный стук, ADDR_INFO друзьям,
    /// событие) за этот срок. Быстрого окна и сброса ограничителя оно не вызывает.
    pub ext_announce_gap: Duration,
}

impl Default for ConnectConfig {
    fn default() -> Self {
        Self {
            manual_forward: None,
            probe_interval: Duration::from_secs(2),
            tick: Duration::from_secs(1),
            fast_window: Duration::from_secs(120),
            fast_period: Duration::from_secs(5),
            dial_base: Duration::from_secs(30),
            dial_cap: Duration::from_secs(600),
            min_redial: Duration::from_secs(30),
            hint_base: Duration::from_secs(60),
            hint_cap: Duration::from_secs(1800),
            per_ip_dials: 4,
            per_ip_window: Duration::from_secs(10),
            max_concurrent_dials: 16,
            max_live: 64,
            limiter_capacity: 4096,
            addr_info_timeout: Duration::from_secs(5),
            addr_info_in_per_min: 4,
            addr_info_out_interval: Duration::from_secs(10),
            extra_streams_in_per_min: 60,
            stream_inbox_capacity: 32,
            max_pending_kind_reads: 4,
            invite_session: Duration::from_secs(300),
            invite_m1_deadline: Duration::from_secs(20),
            expire_interval: Duration::from_secs(60),
            unreachable_after_fails: 3,
            udp_blocked_window: Duration::from_secs(600),
            udp_blocked_min_friends: 2,
            ext_announce_gap: Duration::from_secs(30),
        }
    }
}
