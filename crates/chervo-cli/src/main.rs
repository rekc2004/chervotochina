//! Скелет CLI. Пока поддерживает только `--version`.

fn main() -> std::process::ExitCode {
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
