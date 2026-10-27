//! Модульные тесты (только `cfg(test)`): всё, что требует внутренних типов или сырых клиентов.
//! Здесь нельзя печатать; печатающие тесты лежат в `tests/`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod attacks;
mod flood;
mod fuzz;
mod gate;
mod kit;
mod knock;
mod misc;
mod peers;
mod preauth;
mod race;
mod tlsx;
mod windows;
