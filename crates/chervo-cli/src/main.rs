//! CLI Червоточины: `--version`, проверка выпусков (`verify-release`, `release-keys`).

mod doctor;
mod release;

fn main() -> std::process::ExitCode {
    // Первая строка (этап 17, C07): запрет дампов памяти до чтения аргументов и любых ключей.
    let _hardening = chervo_core::harden_process();
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let command = args.first().and_then(|a| a.to_str());
    match command {
        Some("--version") => {
            println!("chervo {}", chervo_core::VERSION);
            std::process::ExitCode::SUCCESS
        }
        Some("verify-release") => std::process::ExitCode::from(release::verify_release(
            &args[1..],
            chervo_update::KeySet::embedded(),
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        )),
        Some("release-keys") => std::process::ExitCode::from(release::release_keys(
            &args[1..],
            chervo_update::KeySet::embedded(),
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        )),
        Some("doctor") => std::process::ExitCode::from(doctor::doctor(
            &args[1..],
            &mut std::io::stdout().lock(),
            &mut std::io::stderr().lock(),
        )),
        _ => {
            eprintln!("chervo: not implemented");
            std::process::ExitCode::from(2)
        }
    }
}
