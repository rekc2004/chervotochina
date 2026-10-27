//! Консольная оболочка узла: работа узла в библиотеке крейта. Здесь только команды выпусков
//! (этап 19): `verify-release`, `release-keys`, `check-update`, `doctor`.

mod check_update;
mod doctor;
mod release;

fn main() -> std::process::ExitCode {
    // Первая строка (этап 17, C07): запрет дампов памяти до чтения аргументов и любых ключей.
    let _hardening = chervo_core::harden_process();
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    let command = args.first().and_then(|a| a.to_str());
    match command {
        Some("verify-release") => std::process::ExitCode::from(release::verify_release(
            &args[1..],
            chervo_update::KeySet::embedded(),
            &mut chervo_cli::out::main_sink(),
            &mut chervo_cli::out::err_sink(),
        )),
        Some("release-keys") => std::process::ExitCode::from(release::release_keys(
            &args[1..],
            chervo_update::KeySet::embedded(),
            &mut chervo_cli::out::main_sink(),
            &mut chervo_cli::out::err_sink(),
        )),
        Some("check-update") => std::process::ExitCode::from(check_update::run(&args[1..])),
        Some("doctor") => std::process::ExitCode::from(doctor::doctor(
            &args[1..],
            &mut chervo_cli::out::main_sink(),
            &mut chervo_cli::out::err_sink(),
        )),
        _ => chervo_cli::run_cli(&_hardening, args),
    }
}
