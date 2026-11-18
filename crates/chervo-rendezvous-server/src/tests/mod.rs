#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
//! Тесты сервера эха: логика разбора и лимиты без сети, ответы по настоящим сокетам на петле.

mod limits;
mod net;
