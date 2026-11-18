//! «Открыть папку приёма» (этап 18б, Н7, решение владельца 2026-11-18): единственное место
//! программы, которое запускает другую программу. Открывается только настроенная папка приёма
//! из настроек: путь не приходит ни от друга, ни от окна, ни из пути файла, а сами файлы не
//! открываются. Проводник запускается без оболочки (`cmd /c`, `sh -c` нет) одним аргументом,
//! без склейки строк. Защиту «других вызовов `Command::new` в ядре нет» держит
//! `tests/process_guard.rs`.

use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use chervo_receive::RootError;

use super::Node;
use super::core::lock;
use super::error::NodeError;

/// Запуск системного проводника для каталога. В тестах подменяется.
pub(crate) trait FolderLauncher {
    fn launch(&self, dir: &Path) -> io::Result<()>;
}

/// Какую программу запускать: Windows `explorer.exe` из системного каталога (`SystemRoot`, а не
/// поиск по `PATH` и рядом с программой), macOS `/usr/bin/open` (абсолютный путь), прочие
/// `xdg-open` по `PATH`.
///
/// Принятое решение (ревью безопасности 18б): `SystemRoot` и `PATH` подменяет только тот, кто уже
/// управляет окружением процесса программы, то есть новых прав это не даёт. Путь через
/// `GetSystemWindowsDirectoryW` потребовал бы новой зависимости (при `unsafe_code = forbid`), так
/// что не делается.
fn system_program() -> io::Result<PathBuf> {
    if cfg!(windows) {
        let root = std::env::var_os("SystemRoot")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?;
        Ok(root.join("explorer.exe"))
    } else if cfg!(target_os = "macos") {
        Ok(PathBuf::from("/usr/bin/open"))
    } else {
        Ok(PathBuf::from("xdg-open"))
    }
}

struct SystemLauncher;

impl FolderLauncher for SystemLauncher {
    fn launch(&self, dir: &Path) -> io::Result<()> {
        let program = system_program()?;
        // единственный запуск процесса в ядре: один аргумент (абсолютный путь), без оболочки
        let mut child = Command::new(program)
            .arg(dir)
            .stdin(Stdio::null())
            .spawn()?;
        // результат не нужен (проводник Windows отвечает кодом 1 и при успехе), но процесс
        // нужно дождаться, чтобы он не остался зомби (Unix)
        let _ = std::thread::Builder::new()
            .name("chervo-open-folder".to_owned())
            .spawn(move || {
                let _ = child.wait();
            });
        Ok(())
    }
}

/// Проверки и запуск. Каталог должен быть абсолютным, существовать как каталог и не быть
/// символьной ссылкой; иначе запуска нет (`NotDir`). Ошибка запуска это `NodeError::Io`.
///
/// Остаточное окно гонки (TOCTOU): между проверкой и запуском проводника папку можно заменить
/// ссылкой. Закрыть его без открытия каталога по дескриптору нельзя; последствие ограничено
/// показом чужой папки в проводнике (файлы не открываются и не запускаются), а подменить папку
/// приёма может только тот, кто уже пишет в профиль пользователя.
pub(crate) fn open_folder_with(dir: &Path, launcher: &dyn FolderLauncher) -> Result<(), NodeError> {
    if !dir.is_absolute() {
        return Err(NodeError::ReceiveRoot(RootError::NotAbsolute));
    }
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() && !m.file_type().is_symlink() => {}
        _ => return Err(NodeError::ReceiveRoot(RootError::NotDir)),
    }
    launcher.launch(dir).map_err(|_| NodeError::Io)
}

impl Node {
    /// Кнопка «Открыть папку»: открывает в проводнике папку приёма из настроек. Ничего другого
    /// открыть нельзя: у метода нет параметров. `ReceiveRoot(NotDir)`: папка пропала или это не
    /// каталог; `Io`: проводник не запустился.
    pub fn open_receive_folder(&self) -> Result<(), NodeError> {
        let dir = lock(&self.core.settings).receive_root.clone();
        open_folder_with(&dir, &SystemLauncher)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Spy {
        calls: RefCell<Vec<PathBuf>>,
        fail: bool,
    }

    impl FolderLauncher for Spy {
        fn launch(&self, dir: &Path) -> io::Result<()> {
            self.calls.borrow_mut().push(dir.to_path_buf());
            if self.fail {
                Err(io::Error::from(io::ErrorKind::NotFound))
            } else {
                Ok(())
            }
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let p =
            std::env::temp_dir().join(format!("chervo-open-folder-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn existing_directory_is_launched_once() {
        let dir = scratch("ok");
        let spy = Spy::default();
        assert_eq!(open_folder_with(&dir, &spy), Ok(()));
        assert_eq!(*spy.calls.borrow(), vec![dir.clone()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_directory_is_an_error_and_nothing_is_launched() {
        let dir = scratch("missing");
        let gone = dir.join("нет такой");
        let spy = Spy::default();
        assert_eq!(
            open_folder_with(&gone, &spy),
            Err(NodeError::ReceiveRoot(RootError::NotDir))
        );
        assert!(spy.calls.borrow().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_file_is_not_a_directory_and_is_never_launched() {
        let dir = scratch("file");
        let file = dir.join("a.txt");
        std::fs::write(&file, b"x").unwrap();
        let spy = Spy::default();
        assert_eq!(
            open_folder_with(&file, &spy),
            Err(NodeError::ReceiveRoot(RootError::NotDir))
        );
        assert!(spy.calls.borrow().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_to_a_directory_is_refused_without_launch() {
        let dir = scratch("link");
        let target = dir.join("real");
        std::fs::create_dir_all(&target).unwrap();
        let link = dir.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let spy = Spy::default();
        assert_eq!(
            open_folder_with(&link, &spy),
            Err(NodeError::ReceiveRoot(RootError::NotDir))
        );
        assert!(spy.calls.borrow().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn relative_path_is_refused_without_launch() {
        let spy = Spy::default();
        assert_eq!(
            open_folder_with(Path::new("recv"), &spy),
            Err(NodeError::ReceiveRoot(RootError::NotAbsolute))
        );
        assert!(spy.calls.borrow().is_empty());
    }

    #[test]
    fn launch_failure_is_reported_as_io() {
        let dir = scratch("fail");
        let spy = Spy {
            fail: true,
            ..Spy::default()
        };
        assert_eq!(open_folder_with(&dir, &spy), Err(NodeError::Io));
        assert_eq!(spy.calls.borrow().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
