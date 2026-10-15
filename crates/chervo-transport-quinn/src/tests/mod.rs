//! Модульные тесты (только `cfg(test)`): всё, что требует внутренних типов или сырых клиентов.
//! Здесь нельзя печатать; печатающие тесты лежат в `tests/`.

mod attacks;
mod flood;
mod gate;
mod kit;
mod misc;
mod tlsx;
