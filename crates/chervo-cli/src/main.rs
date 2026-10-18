//! Скелет CLI. Пока поддерживает только `--version`.

fn main() -> std::process::ExitCode {
    // Первая строка (этап 17, C07): запрет дампов памяти до чтения аргументов и любых ключей.
    let _hardening = chervo_core::harden_process();
    let is_version = std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg.to_str() == Some("--version"));
    if is_version {
        println!("chervo {}", chervo_core::VERSION);
        return std::process::ExitCode::SUCCESS;
    }
    eprintln!("chervo: not implemented");
    std::process::ExitCode::from(2)
}
