//! Консольная оболочка узла: вся работа в библиотеке крейта.

fn main() -> std::process::ExitCode {
    // Первая строка (этап 17, C07): запрет дампов памяти до чтения аргументов и любых ключей.
    let _hardening = chervo_core::harden_process();
    chervo_cli::run_cli(&_hardening, std::env::args_os().skip(1).collect())
}
