//! Модульные тесты (только `cfg(test)`): кодек открытого текста и файл списка.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod fuzz;
mod kit;
mod plain;
mod seq;
mod vault;
