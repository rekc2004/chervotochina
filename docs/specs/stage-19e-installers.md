# SPEC 19е: установщики для Windows, macOS и Linux          критичность: КРИТИЧНЫЙ (19е-2, 19е-3), обычный (19е-1, 19е-4)

Редакция 1, 2026-11-15, architect (opus/high). Основа: main `b3e7315`, ветка `claude/stage-19e-installers`. Дополнение к `docs/specs/stage-19-release-signing.md` («SPEC 19») и `docs/specs/stage-19g-gui-packaging.md` («SPEC 19г»).
Запрос владельца (2026-11-15): «сделай установщики» для Windows, macOS и Linux. Ставит владелец сам, вручную; агенты ничего не устанавливают на машинах.
Метки: [П] проверено мной по файлу (путь:строка); [В] вывод или память, сверить до кода; [НП] факт о чужом инструменте, первоисточник не открыт (у меня нет веба): **сверить дирижёру по официальной документации до запуска builder** (список в разд. 10). Я ничего не собирал и не запускал.

Цель: в выпуске появляются 4 установщика (`.exe`-установщик Windows для текущего пользователя без UAC, `.dmg` для двух целей macOS, `.deb` для Linux). Каждый в манифесте и подписан владельцем. Каждый в CI ставится тихо и удаляется: установленная программа побайтно совпадает с подписанным одиночным файлом, запускается, данные пользователя после удаления на месте. Пользователь ничего не доустанавливает; новые инструменты сборки есть только в CI, закреплены по версии и хэшу.

## 0. Разбиение, исполнители, порядок

| Часть | Что | Критичность, исполнитель | Ждёт |
|---|---|---|---|
| 19е-0 | сверка фактов [НП] разд. 10, ответы владельца на разд. 12, закрепление Inno Setup (версия, URL, SHA-256, размер, подписант) | дирижёр | — |
| 19е-1 | значки (генератор, файлы), `.desktop`; в GUI `app_id` и значок окна (Q3) | обычный, builder sonnet/medium | 19е-0 |
| 19е-2 | `fetch-tool.sh` + `packaging/tools.lock` + страж скачиваний (правило 7) | **КРИТИЧНЫЙ** (цепочка поставки: чужой исполняемый файл в CI делает подписываемый артефакт), builder sonnet/**high**; ревью security opus/high | 19е-0 |
| 19е-3 | скрипты пакетов (`package-deb.sh`, `check-deb.sh`, `package-windows.sh`, `.iss`, `check-iss.sh`, `package-dmg.sh`, `check-dmg.sh`), задания `installers` и `installer-smoke` в `release.yml`, `assemble`, белый список, стражи 8 и 9 | **КРИТИЧНЫЙ** (подписываемые артефакты; код, который исполняется у пользователя при установке; права), builder sonnet/**high**; ревью security opus/high по diff; дирижёр сам открывает сводку пробного прогона | 19е-1, 19е-2 |
| 19е-4 | `docs/INSTALL.md`, текст `draft.sh`, чек-лист в конце `sign.sh` (только текст), T21 в THREAT_MODEL (дирижёр по разд. 8) | обычный, builder sonnet/medium | 19е-3 принят |

Почему 19е-3 одним куском: всё проверяется только пробным прогоном CI. У builder нет `dpkg-deb`, `hdiutil` и Inno Setup, ставить их нельзя. Одна цепочка зависимых шагов дешевле у одного исполнителя (pipeline.md).

## 1. Решения architect (кратко, с причиной)

Р19е-1. **Установщик упаковывает уже собранные байты, а не пересобирает.** Задание `installers` скачивает артефакты `bin-<цель>` из `build` и кладёт в пакет тот же файл:
- Windows: `chervotochina-<v>-windows-x86_64.exe` под именем `chervotochina.exe`;
- Linux: оба ELF;
- macOS: `.app` из `.zip` той же цели.
Поэтому главный критерий проверяется командой: после тихой установки SHA-256 установленного файла равен строке манифеста одиночного файла (на macOS: дерево `.app` из `.dmg` побайтно равно дереву из `.zip`). Экран «Обновления» и `chervo verify-release` проверяют установленный файл по хэшу без изменений в коде (сверка по хэшу [П: SPEC 19г 5.1, `verify.rs:115-120`]).

Р19е-2. **Windows: Inno Setup 6** (решение за владельцем, Q1). Причины:
- установка для текущего пользователя без прав администратора задаётся одной директивой `PrivilegesRequired=lowest` [НП]; тогда `{autopf}` = `%LOCALAPPDATA%\Programs`, `{autoprograms}` = «Пуск» пользователя, запись удаления пишется в HKCU и видна в «Приложениях» [НП];
- журнал установки `/LOG=` и `SetupLogging=yes` [НП];
- официальный русский перевод `compiler:Languages\Russian.isl` [НП];
- не нужен свой код установки: секция `[Code]` (Pascal Script) запрещена стражем.
Лицензия Inno Setup [НП]: по памяти разрешительная (свободное использование, в том числе в коммерческих целях), но условия могли измениться (просьба или требование коммерческой лицензии). Дирижёр сверяет `license.txt` версии из `tools.lock`. Если для проекта нужна оплата или условия неясны, это **стоп**, вопрос владельцу.
Отвергнуто или запасной путь:
- WiX/MSI. Нужен .NET SDK в CI (только CI, это допустимо), но MSI для одного пользователя капризен: правила ICE, ключи HKCU. WiX ставится как `dotnet tool` из NuGet, а закрепить хэш так сложнее. Условия лицензии WiX v6 (EULA, «Open Source Maintenance Fee») [НП];
- NSIS. Лицензия zlib, собирается на Linux из apt Ubuntu (плюс). Минусы: запись удаления, «Пуск» и режим одного пользователя пишутся вручную, ошибок больше; штатного журнала установки нет [В]. Это запасной путь, если Inno отпадёт по лицензии.

Р19е-3. **Windows без ресурсов в `.exe` (Q3).** `build.rs` в GUI запрещён [П: `crates/chervo-gui/tests/manifest_only_core.rs:1-4,102-104`], одиночный `.exe` не меняется. Значок появляется так:
- у ярлыка «Пуск»: `IconFilename={app}\chervotochina.ico`;
- в «Приложениях»: `UninstallDisplayIcon`;
- у самого установщика: `SetupIconFile`;
- у окна и на панели задач во время работы: `ViewportBuilder::with_icon` из сырых RGBA 64×64, вшитых `include_bytes!`. Это Q3 (а), без новых пакетов и без `build.rs`.
В «Проводнике» у самого `chervotochina.exe` значок остаётся стандартным. Встроить его можно только ресурсом: `.res` через `-C link-arg` в `build-release.sh` (Q3 б) или правкой готового PE чужим инструментом (отвергнуто: байты расходятся с подписанным одиночным файлом, лишний инструмент).

Р19е-4. **Linux: `.deb`, собранный штатным `dpkg-deb` раннера, без maintainer-скриптов.** AppImage по-прежнему отвергнут (Р19г-1, libfuse2). Flatpak и Snap отвергнуты: нужны среда выполнения и магазин, а это третья сторона. RPM: у владельца Ubuntu, не делаем.
- Нет `preinst`, `postinst`, `prerm`, `postrm`, `config`, `triggers`, `conffiles`. Кэш значков и база `.desktop` обновляются файловыми триггерами пакетов `desktop-file-utils` и `hicolor-icon-theme` [В], свой код от root не нужен.
- `Depends` выводится из `NEEDED` бинарей по закрытой таблице (разд. 3.1); на практике это `libc6 (>= X)` и, возможно, `libgcc-s1`. Неизвестная библиотека = стоп.
- Secret Service ставиться не может: `Recommends` нет (apt по умолчанию ставит рекомендуемые [В]), есть только `Suggests: gnome-keyring`. Apt его не ставит, а показывает строкой «Предлагаемые пакеты» [В]. Проверка и подсказка остаются в программе: первый экран окна (`KeyStoreLocked` [П: SPEC 19г Р19г-10]) и `chervo doctor` (Р7 SPEC 19 [П: `stage-19-release-signing.md:40`]). Postinst выполняется от root без сеанса D-Bus пользователя и не может честно проверить его хранилище (Q4).
- В пакете оба файла: `/usr/bin/chervotochina` и `/usr/bin/chervo` (Q5, для мини-ПК).

Р19е-5. **macOS: `.dmg` без подписи Apple** (U18). Внутри тот же `Chervotochina.app`, что в `.zip` (ad-hoc, Р19г-1), и ссылка `Applications -> /Applications` для переноса мышью. Удаление: перенести `.app` в Корзину, данные остаются. `.dmg` сам не подписывается (ad-hoc подпись образа ничего не даёт). Образ собирается `hdiutil` на `macos-15` для обеих целей (инструмент не зависит от архитектуры [В]). Вместе с этим `.app` получает значок (`Contents/Resources/chervotochina.icns`, `CFBundleIconFile`), поэтому байты `.zip` тоже меняются. Это новый выпуск, не подмена.

Р19е-6. **Одиночные файлы остаются** (Q6, по умолчанию да): ручное обновление «заменить файл», переносной запуск, мини-ПК без apt. В выпуске 12 артефактов вместо 8, предел 32 [П: SPEC 19г 5.1, `chervo-update/src/lib.rs:25`].

Р19е-7. **Данные пользователя при удалении не трогаются.** Каталоги данных [П: `crates/chervo-core/src/node/profile.rs:59-75`]:
- Windows: `%LOCALAPPDATA%\Chervotochina`. Это **не** каталог установки `%LOCALAPPDATA%\Programs\Chervotochina`: пути разные, `.iss` на каталог данных не ссылается (страж);
- macOS: `~/Library/Application Support/Chervotochina`;
- Linux: `$XDG_DATA_HOME/chervotochina` или `~/.local/share/chervotochina`.
Записи в Credential Manager, Keychain и Secret Service установщики не трогают. В `.iss` нет `[UninstallDelete]` и `[InstallDelete]`, в `.deb` нет `postrm`. Удаление данных вручную описано в `INSTALL.md` с предупреждением: удалить ключи = заново добавлять друзей.

Р19е-8. **`assemble` скачивает артефакты по точным именам, а не по шаблону `bin-*`** [П: сейчас `pattern: bin-*`, `release.yml:168-172`]. Причина: в задании `installers` исполняется чужая программа (Inno). Код задания может добраться до токена выполнения и выложить лишний артефакт, например `bin-zzz`. При `pattern` + `merge-multiple` такой артефакт попал бы в `dist` [В]. Белый список ловит лишние имена, но не подмену файла с тем же именем. Скачивание по 8 точным именам закрывает это дёшево (страж 9).

Р19е-9. **Воспроизводимость, честно.**
- `.deb`: упаковка детерминирована. Тот же вход, `SOURCE_DATE_EPOCH` = время коммита, `--root-owner-group`, нормализованные mtime. Две сборки в одном задании сравниваются через `cmp`, расхождение **валит** задание. Нельзя добиться (dpkg-deb так не умеет) = стоп и доклад.
- Установщик Windows и `.dmg`: собираются дважды, SHA-256 сравниваются, результат **только записывается** (Inno и UDIF несут метки времени и UUID [В]).
- Побитовая воспроизводимость самих бинарей не заявляется (Р6 SPEC 19).

Р19е-10. **Значки из одного текстового источника.** `packaging/icons/make-icons.py` рисует значок процедурно (Q2: временный, кольца «червоточины», без текста и шрифтов). Нужна только стандартная библиотека Python (`struct`, `zlib`); математика ограничена `+ - * /` и `math.sqrt` (без тригонометрии и `exp`: разные libm [В]). Скрипт пишет PNG 16…512, ICO, ICNS и RGBA 64×64. Файлы коммитятся. CI (`ci.yml`, задание `lint`, Ubuntu) запускает `python3 -I packaging/icons/make-icons.py --check packaging/icons` и сравнивает **пиксели** (PNG распаковываются), а не сжатые байты: от версии zlib проверка не зависит. Python нужен только CI и builder (если есть локально), пользователю и сборке пакетов он не нужен.

## 2. Состав выпуска (после 19е)

| # | Цель | Файл | Что |
|---|---|---|---|
| 1 | `linux-x86_64` | `chervo-<v>-linux-x86_64` | CLI (как сейчас) |
| 2 | `linux-x86_64` | `chervotochina-<v>-linux-x86_64` | окно (как сейчас) |
| 3 | `linux-x86_64` | `chervotochina-<v>-linux-x86_64.deb` | **новый**, пакет: окно + CLI + `.desktop` + значки |
| 4 | `macos-aarch64` | `chervotochina-<v>-macos-aarch64.zip` | окно (теперь со значком) |
| 5 | `macos-aarch64` | `chervotochina-<v>-macos-aarch64.dmg` | **новый** |
| 6 | `macos-x86_64` | `chervotochina-<v>-macos-x86_64.zip` | окно (со значком) |
| 7 | `macos-x86_64` | `chervotochina-<v>-macos-x86_64.dmg` | **новый** |
| 8 | `windows-x86_64` | `chervotochina-<v>-windows-x86_64.exe` | окно (как сейчас) |
| 9 | `windows-x86_64` | `chervotochina-<v>-windows-x86_64-setup.exe` | **новый**, установщик Inno |
| 10 | `any` | `chervo-<v>-sbom.cdx.json` | |
| 11 | `any` | `chervotochina-<v>-sbom.cdx.json` | |
| 12 | `any` | `chervo-<v>-third-party-licenses.txt` | |

Имена укладываются в `[A-Za-z0-9._-]` [П: SPEC 19 разд. 2, `stage-19-release-signing.md:74`]. Имя `chervotochina_<v>_amd64.deb` по обычаю Debian не используется: имена в выпуске единообразны. `sign.sh` сам включит новые файлы своей цели в `own` (отбор по цели манифеста [П: `scripts/release/sign.sh:166-174`]). Builder подтверждает чтением, что шаг подписи и загрузки `sign.sh` перебирает имена манифеста, а не закрытый список. Если закрытый, это стоп.

## 3. Форматы и содержимое (точно)

### 3.1. `.deb`
Данные (владелец `root:root`, uid и gid 0; каталоги 0755; бинари 0755; прочее 0644; без символических и жёстких ссылок, setuid, setgid и устройств):
```
./usr/bin/chervotochina                                   (= chervotochina-<v>-linux-x86_64, побайтно)
./usr/bin/chervo                                          (= chervo-<v>-linux-x86_64, побайтно; Q5)
./usr/share/applications/io.github.rekc2004.chervotochina.desktop
./usr/share/icons/hicolor/{16x16,32x32,48x48,64x64,128x128,256x256,512x512}/apps/io.github.rekc2004.chervotochina.png
./usr/share/doc/chervotochina/copyright
```
плюс промежуточные каталоги. Управляющая часть: ровно `./control` и `./md5sums`.

`control`: поля строго в этом порядке, других нет:
```
Package: chervotochina
Version: <v>
Architecture: amd64
Maintainer: <Q8; по умолчанию: Chervotochina <rekc2004@users.noreply.github.com>>
Installed-Size: <КиБ, округление вверх, по данным>
Depends: <по таблице ниже>
Suggests: gnome-keyring
Section: net
Priority: optional
Homepage: https://github.com/rekc2004/chervotochina
Description: Червоточина: прямая передача файлов между компьютерами
 Окно chervotochina и консольная программа chervo. Ключи хранятся в
 Secret Service (gnome-keyring, KWallet, KeePassXC); если его нет,
 программа скажет об этом при запуске, подробности: chervo doctor.
```
`Depends`: объединение `NEEDED` обоих ELF (`readelf -d`) по закрытой таблице. Пакет `libc6` дают `libc.so.6`, `libm.so.6`, `libpthread.so.0`, `libdl.so.2`, `librt.so.1`, `ld-linux-x86-64.so.2`; пакет `libgcc-s1` даёт `libgcc_s.so.1`. Другое имя = стоп. Версия `libc6 (>= X)`: X = наибольшая `GLIBC_a.b` из `objdump -T` обоих файлов. Итог одной строкой, `libc6` первым.
`copyright`: имя программы, адрес проекта, строка «Лицензия проекта: см. адрес проекта», строка «Лицензии сторонних компонентов: файл chervo-<v>-third-party-licenses.txt в выпуске». Лицензии у проекта сейчас нет: в корне нет `LICENSE`, в `Cargo.toml` нет поля `license` [П: поиск по корню]. Выдумывать её нельзя.

### 3.2. `.desktop` (`packaging/linux/io.github.rekc2004.chervotochina.desktop`, UTF-8, `\n`)
```
[Desktop Entry]
Type=Application
Name=Червоточина
GenericName=Передача файлов
Comment=Прямая передача файлов между компьютерами
Exec=chervotochina
Icon=io.github.rekc2004.chervotochina
Terminal=false
Categories=Network;FileTransfer;
StartupNotify=true
StartupWMClass=io.github.rekc2004.chervotochina
```
В `Exec` нет кодов полей (`%f`, `%u`): файловый менеджер ничего не передаёт программе. `desktop-file-validate` без ошибок.

### 3.3. Windows: `packaging/windows/chervotochina.iss` (UTF-8 **с BOM** [НП])
Параметры через ISCC: `/DAppVersion=<v> /DSrcDir=<каталог> /DTouchDate=<ГГГГ-ММ-ДД> /DTouchTime=<ЧЧ:ММ:СС>` (из `SOURCE_DATE_EPOCH`), `/O<outdir>`. Без `AppVersion` или `SrcDir` = `#error`. Содержание:
- `[Setup]`:
  - `AppId={{<GUID>}`: GUID генерирует builder один раз (`[guid]::NewGuid()`), записывает в `packaging/windows/APPID` и больше **никогда** не меняет (страж). От него зависит обновление поверх;
  - `AppName=Червоточина`, `AppVersion={#AppVersion}`, `AppVerName=Червоточина {#AppVersion}`, `AppPublisher=Chervotochina`, `AppPublisherURL` и `AppSupportURL` = адрес проекта;
  - `DefaultDirName={autopf}\Chervotochina`, `DisableDirPage=yes`, `DisableProgramGroupPage=yes`, `UsePreviousAppDir=yes`;
  - `PrivilegesRequired=lowest`; `PrivilegesRequiredOverridesAllowed` **нет**;
  - `OutputBaseFilename=chervotochina-{#AppVersion}-windows-x86_64-setup`;
  - `SetupIconFile={#SrcDir}\chervotochina.ico`, `UninstallDisplayIcon={app}\chervotochina.ico`, `UninstallDisplayName=Червоточина`;
  - `Compression=lzma2/max`, `SolidCompression=yes`;
  - `ArchitecturesAllowed=x64compatible`, `ArchitecturesInstallIn64BitMode=x64compatible`, `MinVersion=10.0`;
  - `WizardStyle=modern`, `ShowLanguageDialog=no`;
  - `SetupLogging=yes`, `CloseApplications=yes`, `RestartApplications=no`;
  - `TimeStampsInUTC=yes`, `TouchDate={#TouchDate}`, `TouchTime={#TouchTime}`;
  - `VersionInfoVersion={#AppVersion}.0`;
  - имена и значения директив сверить [НП].
- `[Languages]`: только `Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"`.
- `[Files]`: ровно две строки: `chervotochina.exe` и `chervotochina.ico` из `{#SrcDir}` в `{app}`, `Flags: ignoreversion`.
- `[Icons]`: ровно одна строка: `Name: "{autoprograms}\Червоточина"; Filename: "{app}\chervotochina.exe"; IconFilename: "{app}\chervotochina.ico"; WorkingDir: "{app}"`. Ярлыка на рабочем столе нет (Q7).
- `[Run]`: ровно одна строка: `Filename: "{app}\chervotochina.exe"; Description: "Запустить Червоточину"; Flags: nowait postinstall skipifsilent`.
- Других секций нет: ни `[Code]`, ни `[Registry]`, ни `[Dirs]`, ни `[INI]`, ни `[InstallDelete]`, ни `[UninstallDelete]`, ни `[UninstallRun]`, ни `[Tasks]`, ни `[Types]`, ни `[Components]`. Нет `#include` и `{userappdata}`, нет `{localappdata}` вне `{autopf}`, нет `http`, кроме двух URL проекта.

### 3.4. `.dmg`
Имя тома `Chervotochina` (ASCII [В: не-ASCII имя тома допустимо, но лишний риск]), файловая система HFS+, формат `UDZO`. Видимые элементы корня ровно такие: `Chervotochina.app` (дерево побайтно равно `.app` из `.zip` той же цели) и `Applications` (символическая ссылка, цель ровно `/Applications`). Скрытые служебные элементы, которые создаёт система (`.fseventsd` и т. п. [В]), допускаются и печатаются в сводку. Внутри `.app` нет символических ссылок.

### 3.5. Значки (`packaging/icons/`, 19е-1)
- `chervotochina-{16,32,48,64,128,256,512}.png`: RGBA 8 бит, без чередования, фильтр 0 у каждой строки;
- `chervotochina.ico`: 16, 32, 48 как 32-битный DIB с маской AND и 256 как PNG (DIB для малых размеров надёжнее у старых потребителей; Inno требует ICO [НП]);
- `chervotochina.icns`: `ic07` (128), `ic08` (256), `ic09` (512), каждый как PNG [НП: типы ICNS];
- `crates/chervo-gui/assets/icon-64.rgba`: ровно 16384 байт (только при Q3 а).
Генератор детерминирован; режим `--check <dir>` сравнивает пиксели и структуру; `--self-test` проверяет, что изменённый пиксель ловится.

## 4. Цепочка поставки: что скачивает CI и как проверяется

| Что | Где | Закреплено | Проверка |
|---|---|---|---|
| Установщик Inno Setup `<версия>` | `installers`, `windows-2025` | `packaging/tools.lock`: имя, версия, URL (https), SHA-256, размер | `fetch-tool.sh`: только https (`--proto '=https' --proto-redir '=https'`), `--max-filesize`, размер и SHA-256 **до** любого запуска; при расхождении файл удаляется, печатаются фактические SHA-256 и размер, код 1. Затем pwsh `Get-AuthenticodeSignature`: `Status` равен `Valid`, подписант совпадает с полем `signer` в `tools.lock`. Установка в новый пустой каталог `$RUNNER_TEMP\inno`: `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- /DIR=... /LOG=...` [НП]. Заголовок `ISCC.exe` содержит версию из `tools.lock` |
| `dpkg-deb`, `md5sum`, `readelf`, `objdump`, `tar` | `installers` и `installer-smoke`, Ubuntu | образ раннера по имени | версии печатаются в сводку |
| `hdiutil`, `ditto`, `codesign`, `plutil` | macOS | образ раннера | `sw_vers` и версии в сводку |
| apt: `desktop-file-utils` (плюс набор GUI из `release.yml:230` [П]) | только `installer-smoke` Linux | архив Ubuntu (подписанный apt) | только CI; в пакеты не попадает |
| `python3` (стандартная библиотека) | `ci.yml` `lint` | образ раннера | только `--check` значков; в путь сборки выпуска не входит |

Новых actions, кэшей и `cargo install` нет. Запрещены Chocolatey, winget, предустановленный на образе Inno (версия плавает), `dotnet tool`. Первое закрепление хэша Inno работает по принципу «доверие с первого раза» (TOFU). Порядок: builder пишет в `tools.lock` заглушку; пробный прогон падает и печатает фактические SHA-256, размер и подписанта, ничего не запуская. Дирижёр сверяет подписанта и хэш с официальной страницей, если хэш там опубликован [НП], и записывает в `tools.lock` и `docs/TASK.md`, откуда взяты значения.

## 5. Подэтапы

### 5.1. 19е-1: значки, `.desktop`, GUI          builder sonnet/medium
Прочитать: этот файл, разд. 1 (Р19е-3, Р19е-10), 3.2, 3.5; `crates/chervo-gui/src/main.rs:84-100`; `crates/chervo-gui/tests/manifest_only_core.rs`; `scripts/release/package-macos.sh`; `packaging/macos/Info.plist`; `.github/workflows/ci.yml` (задание `lint`).
Сделать:
1. `packaging/icons/make-icons.py` (`--out <dir>`, `--check <dir>`, `--self-test`; код 0 или 1; без сторонних модулей; запускать `python3 -I` или `python -I`). Если Python нет локально, сгенерированные файлы не коммитить и доложить (ничего не ставить).
2. Сгенерированные файлы разд. 3.5 закоммитить.
3. `ci.yml`, задание `lint`: `python3 -I packaging/icons/make-icons.py --check packaging/icons` и `--self-test`.
4. `packaging/linux/io.github.rekc2004.chervotochina.desktop` по разд. 3.2.
5. GUI (`main.rs`): константа `APP_ID = "io.github.rekc2004.chervotochina"`, `.with_app_id(APP_ID)`. При Q3 (а) ещё `.with_icon(...)` из `include_bytes!("../assets/icon-64.rgba")`, 64×64 [НП: API eframe 0.37 `with_app_id`, `with_icon`, `IconData { rgba, width, height }`]. Модульный тест в `src`: длина 16384, есть непрозрачные пиксели. `--render-check` проходит. Новых зависимостей, `build.rs`, `[dev-dependencies]` нет; `manifest_only_core` без изменений.
6. `package-macos.sh`: `Contents/Resources/chervotochina.icns` до `codesign`; в шаблоне `Info.plist` ключ `CFBundleIconFile=chervotochina`; `--self-test` проверяет ключ и наличие файла.
Критерии:
- [ ] `cargo build --locked -p chervo-gui`; `cargo test --locked -p chervo-gui` (в том числе `manifest_only_core`, новый тест значка);
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`; `cargo fmt --all -- --check`;
- [ ] `make-icons.py --check packaging/icons` код 0; `--self-test` печатает «self-test: ok»; `--check` на копии с одним изменённым байтом пикселя даёт код 1;
- [ ] CI `ci.yml` зелёный на 3 ОС, в том числе `gui-render` и `package-macos.sh --self-test` на macOS.

### 5.2. 19е-2: скачивание инструмента          КРИТИЧНЫЙ, builder sonnet/high
Прочитать: разд. 4 и 8; `scripts/check-release-guards.sh` целиком; `scripts/release/lib.sh`.
Сделать:
1. `packaging/tools.lock`: строки `tool <name> <version> <https-url> <sha256 64 hex> <size> <signer>`. В `<signer>` нет пробелов (кодировать `_`, разбирать обратно); одна строка `inno-setup`; разбор строгий (лишнее поле, `http:`, неверный hex = код 2).
2. `scripts/release/fetch-tool.sh <name> <new-empty-dir>`:
   - каталог должен не существовать или быть пустым;
   - `curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL --max-filesize <size> -o <dir>/<basename-из-url>`;
   - сверить размер и SHA-256. При расхождении удалить файл и вывести `expected/actual sha256`, `size`, код 1. Права на исполнение и запуск не делаются никогда (запуск делает следующий шаг workflow);
   - `--self-test`: функция сверки на локальных файлах (верный, неверный хэш, неверный размер, лишнее поле в `tools.lock`, `http://`); сеть не нужна.
3. Страж, правило 7 `guard_downloads`: в `.github/workflows/*.yml` и `scripts/**` нет `curl`, `wget`, `Invoke-WebRequest`, `iwr`, `Invoke-RestMethod`, `irm`, `Start-BitsTransfer`, `certutil`, `bitsadmin`, кроме `scripts/release/fetch-tool.sh`. Исключение: уже существующие законные места, которые builder перечисляет явно в страже (если такие найдутся, доложить). В `fetch-tool.sh` сверка хэша стоит до `exit 0`. Самопроверка: каждое запрещённое слово в чужом файле ловится.
Критерии:
- [ ] `bash scripts/release/fetch-tool.sh --self-test` = «self-test: ok»;
- [ ] `bash scripts/check-release-guards.sh` и `--self-test` (новые случаи правила 7 в выводе);
- [ ] `ci.yml` `lint` вызывает `fetch-tool.sh --self-test`;
- [ ] ревью security по diff `fetch-tool.sh`, `tools.lock`, правила 7: без High/Critical.

### 5.3. 19е-3: пакеты и выпуск          КРИТИЧНЫЙ, builder sonnet/high
Прочитать: этот файл целиком; SPEC 19г разд. 5; `.github/workflows/{release.yml,ci.yml}`; `scripts/release/*.sh`; `scripts/check-release-guards.sh`; `scripts/check-actions-pinned.sh`; `docs/INSTALL.md`. Больше ничего не искать.
Сделать:
1. **`scripts/release/package-deb.sh <gui-elf> <cli-elf> <ver> <outdir>`**:
   - версия по `^[0-9]+\.[0-9]+\.[0-9]+$`; оба входа обычные файлы с магией ELF;
   - `SOURCE_DATE_EPOCH` обязателен (из workflow: `git log -1 --format=%ct`);
   - сборка во **временном пустом** каталоге, `umask 022`, `touch -h -d @$SOURCE_DATE_EPOCH` всем; `md5sums` с сортировкой по пути;
   - `dpkg-deb --root-owner-group -Zxz --build <stage> <out>` [НП: флаги, учёт `SOURCE_DATE_EPOCH` в dpkg 1.21 на `ubuntu-22.04`];
   - собрать дважды в разные каталоги и сравнить `cmp`; расхождение = код 1;
   - вызвать `check-deb.sh`.
   `--self-test` (только Linux): копии `/bin/true` в роли ELF; положительный случай и отрицательные через `check-deb.sh`.
2. **`scripts/release/check-deb.sh <deb> <gui-elf> <cli-elf> <ver>`**:
   - `dpkg-deb -f`: поля и порядок ровно по 3.1; `Depends` по шаблону `^libc6 \(>= 2\.[0-9]+\)(, libgcc-s1)?$`; запрещены `Pre-Depends`, `Recommends`, `Enhances`, `Conflicts`, `Breaks`, `Provides`, `Replaces`, `Essential`;
   - `--ctrl-tarfile`: ровно `./`, `./control`, `./md5sums`;
   - `--fsys-tarfile`: точный список разд. 3.1, `root/root` 0/0, режимы по 3.1, нет ссылок, setuid, setgid и устройств;
   - бинари внутри побайтно равны входам;
   - `.desktop` внутри равен `packaging/linux/...`.
   Отрицательные случаи самопроверки (каждый даёт код 1): `postinst`, `Depends: gnome-keyring`, `Recommends: gnome-keyring`, владелец 1000, файл setuid, лишний `./etc/x`, изменённый байт бинаря, `Version` не та.
3. **`scripts/release/package-windows.sh <gui-exe> <ver> <outdir> <iscc>`**:
   - версия по шаблону;
   - каталог `src`: `chervotochina.exe` (копия входа, SHA-256 сверен со входом), `chervotochina.ico`;
   - `bash scripts/release/check-iss.sh packaging/windows/chervotochina.iss`;
   - ISCC с параметрами 3.3, дважды (два `/O`), SHA-256 обоих в сводку, «совпало/не совпало» только запись;
   - на выходе ровно `chervotochina-<v>-windows-x86_64-setup.exe`.
4. **`scripts/release/check-iss.sh <iss>`** (страж правила 8, с `--self-test`): правила разд. 3.3 по тексту:
   - разрешённые секции и число строк в `[Files]`, `[Icons]`, `[Run]`;
   - `PrivilegesRequired=lowest`; нет `PrivilegesRequiredOverridesAllowed`;
   - `AppId` равен `packaging/windows/APPID`;
   - `DefaultDirName={autopf}\Chervotochina`;
   - запрещённые секции и подстроки;
   - BOM в начале.
   Отрицательные случаи: `[Code]`, `[UninstallDelete]`, `[Registry]`, `PrivilegesRequired=admin`, `PrivilegesRequiredOverridesAllowed=dialog`, другой `AppId`, `{localappdata}\Chervotochina`, `#include`, третья строка в `[Files]`, `[Run]` с `http`.
5. **`scripts/release/package-dmg.sh <zip> <ver> <label> <outdir>`**:
   - версия и `label` (`macos-aarch64|macos-x86_64`);
   - `ditto -x -k` в новый пустой каталог; ровно один элемент `Chervotochina.app`; `codesign --verify --strict`;
   - `ln -s /Applications Applications`;
   - `hdiutil create -volname Chervotochina -srcfolder <stage> -fs HFS+ -format UDZO -ov <out>` [НП]. До 3 попыток с паузой 10 с, каждая попытка в сводку [В: известный сбой «Resource busy» на раннерах];
   - `hdiutil verify`; затем `check-dmg.sh`;
   - две сборки, сравнение только записывается.
6. **`scripts/release/check-dmg.sh <dmg> <zip>`**:
   - `hdiutil attach -readonly -nobrowse -noautoopen -mountpoint <tmp>/mnt` [НП]; `detach` в `trap` всегда;
   - корень по 3.4; цель ссылки ровно `/Applications`; в `.app` нет ссылок;
   - список файлов и `cmp` каждого против `.app` из `.zip`; `codesign --verify --strict` на смонтированном `.app`.
7. **`release.yml`**:
   - новое задание `installers` (`needs: [gate, build]`, `permissions: contents: read`, `persist-credentials: false`), матрица из 3 строк:
     - `ubuntu-22.04`: скачать `bin-linux-x86_64`; `SOURCE_DATE_EPOCH`; `package-deb.sh`; выложить `inst-linux-x86_64`;
     - `windows-2025`: скачать `bin-windows-x86_64`; `fetch-tool.sh inno-setup`; шаг pwsh с проверкой Authenticode; тихая установка Inno в `$RUNNER_TEMP\inno`; `package-windows.sh`; выложить `inst-windows-x86_64`;
     - `macos-15`: скачать `bin-macos-aarch64` и `bin-macos-x86_64`; `package-dmg.sh` для каждой; выложить `inst-macos-aarch64` и `inst-macos-x86_64`;
     - у всех `if-no-files-found: error`, `retention-days: 14`; журнал установки Inno как артефакт `tool-logs-windows` (не `bin-*` и не `inst-*`);
   - `assemble`: `needs: [gate, build, installers]`; вместо `pattern: bin-*` восемь шагов `download-artifact` по точным именам (`bin-` × 4, `inst-` × 4) в `dist` (Р19е-8);
   - `assemble.sh`: 12 строк `--artifact` по разд. 2;
   - `check-whitelist.sh`: `expected_names` ровно 12 имён разд. 2. Из списка «лишних» самопроверки убрать `chervotochina-$ver-macos-aarch64.dmg` [П: `check-whitelist.sh:58`] и добавить `chervotochina-$ver-windows-x86_64.msi`, `chervotochina-$ver-linux-x86_64.AppImage`, `chervotochina_${ver}_amd64.deb`, `chervotochina-$ver-macos-aarch64.pkg`. Пропажа каждого из 12 ловится; счётчик 12;
   - новое задание `installer-smoke` (`needs: [gate, assemble]`, `permissions: contents: read`), матрица:
     - `ubuntu-22.04`, `ubuntu-24.04`: `.deb`;
     - `windows-2025`: setup;
     - `macos-15`: `.dmg` aarch64;
     - `macos-15-intel`: `.dmg` x86_64;
     - каждое скачивает только `release-files`;
   - `draft`: `needs` дополняется `installers, installer-smoke`;
   - шаг pwsh в `smoke` (`release.yml:247` [П]): вместо `-Filter` точное имя `chervotochina-<v>-windows-x86_64.exe` из манифеста (иначе есть риск, что совпадёт и `-setup.exe`).
8. **Дымовые тесты установщиков.** У каждого первым шагом SHA-256 установщика сверяется со строкой манифеста своей цели, иначе он **не запускается** (как `smoke-gui.sh:55-60` [П]).
   - `scripts/release/smoke-deb.sh <rel>` (Linux):
     1. `apt-get install` CI-набора GUI и `desktop-file-utils`;
     2. снимок `dpkg-query -W -f='${Package}\n' | sort`; в сводку `apt-config dump | grep -i Install-`;
     3. `sudo apt-get install -y ./<deb>` (по умолчанию, с Recommends) с журналом в сводку;
     4. новый снимок: добавлен **ровно** `chervotochina`;
     5. SHA-256 `/usr/bin/chervotochina` и `/usr/bin/chervo` равны строкам манифеста одиночных файлов;
     6. `desktop-file-validate`; `/usr/bin/chervo --version` содержит `<v>`; `timeout 120 xvfb-run -a /usr/bin/chervotochina --render-check` = 0;
     7. метка `$HOME/.local/share/chervotochina/sentinel-19e`;
     8. `sudo apt-get remove -y chervotochina`, затем `sudo dpkg --purge chervotochina`;
     9. нет `/usr/bin/chervotochina`, `/usr/bin/chervo`, `.desktop` и значков; `dpkg -s` даёт ошибку; снимок пакетов равен первому; метка на месте, байты те же.
   - `scripts/release/smoke-installer-windows.ps1 <rel>` (`pwsh -NoProfile -File`):
     1. до установки нет ключа HKCU `...\Uninstall\{<AppId>}_is1` и каталога `%LOCALAPPDATA%\Programs\Chervotochina`;
     2. `Start-Process <setup> -ArgumentList '/VERYSILENT','/SUPPRESSMSGBOXES','/NORESTART','/SP-',"/LOG=<log>" -Wait -PassThru`, код 0 [НП];
     3. в каталоге установки ровно `chervotochina.exe`, `chervotochina.ico`, `unins000.exe`, `unins000.dat` [НП: имена]; SHA-256 `chervotochina.exe` равен строке одиночного `.exe`;
     4. ярлык `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Червоточина.lnk` [НП], `TargetPath` равен установленному `.exe` (COM `WScript.Shell`);
     5. ключ HKCU есть: `DisplayVersion` = `<v>`, `InstallLocation` = каталог установки;
     6. в HKLM (оба представления, 64 и 32) такого ключа нет, `%ProgramFiles%\Chervotochina` и `%ProgramFiles(x86)%\Chervotochina` нет;
     7. журнал печатается в сводку; строка о режиме без администратора [НП: точный текст] обязательна;
     8. установленный `.exe` с `--render-check` даёт код 0;
     9. метка `%LOCALAPPDATA%\Chervotochina\sentinel-19e`;
     10. удаление командой из `QuietUninstallString` плюс `/LOG=<log2>`. Ожидание до 120 с, пока не пропадут каталог и ключ: деинсталлятор Inno может вернуться раньше конца [В];
     11. нет каталога, ярлыка и ключа; метка на месте, байты те же;
     12. оба журнала выкладываются артефактом `installer-logs-windows`, в выпуск он не попадает.
   - `scripts/release/smoke-dmg.sh <rel> <label>`:
     1. `check-dmg.sh` (с `.zip` из `rel`);
     2. копия `.app` через `ditto` в `$RUNNER_TEMP/Applications` (системный `/Applications` не трогать);
     3. `codesign --verify --strict`; `--render-check` = 0; удалить копию.
9. **Стражи** (`check-release-guards.sh`, каждое правило с отрицательным случаем в `--self-test`):
   - правило 8: `check-iss.sh` вызывается из `ci.yml` `lint` и из `package-windows.sh`;
   - правило 9 `guard_assemble_exact`: в блоке `assemble` нет `pattern:`, ровно 8 `name:` у `download-artifact` из закрытого списка. Самопроверка: `pattern: bin-*` и `name: bin-zzz` ловятся;
   - правило 6 дополнить: `installer-logs` и `tool-logs` тоже не встречаются в `assemble` и `draft`.
10. `ci.yml` `lint`: `check-iss.sh --self-test`, `check-iss.sh packaging/windows/chervotochina.iss`, `package-deb.sh --self-test`. Самопроверку `check-dmg.sh` CI не делает: нужен macOS-раннер и образ. Вместо неё работает пробный прогон.
Критерии:
- [ ] `bash scripts/check-release-guards.sh` и `--self-test`; `check-whitelist.sh --self-test`; `check-iss.sh --self-test`; `package-deb.sh --self-test` (Linux); `check-actions-pinned.sh` и `--self-test`;
- [ ] CI `ci.yml` зелёный (3 ОС);
- [ ] пробный `release.yml` (`workflow_dispatch`, `skip_keys_check: true`) зелёный. В отчёте:
  - `release-files`: ровно 13 файлов, манифест целиком;
  - сводка `installers`: SHA-256, сверка подписанта Inno, повтор сборки `.deb` «совпало» (обязательно), Windows и `.dmg` «совпало/не совпало»;
  - сводка `installer-smoke` по 5 строкам матрицы: разница снимков пакетов, хэши установленных файлов против манифеста, коды `--render-check`, метка цела, хвосты журналов Inno;
  Дирижёр сам открывает сводку.
- [ ] Негатив: самопроверки п. 2, 4, 9; белый список отвергает `.msi`, `.AppImage`, `_amd64.deb`, `.pkg` и пропажу любого из 12;
- [ ] ревью security по diff `release.yml`, `.iss`, `check-iss.sh`, `package-deb.sh`, `check-deb.sh`, `smoke-*`, стражей: без High/Critical.

### 5.4. 19е-4: документы          builder sonnet/medium
1. `docs/INSTALL.md`, разд. 1-8:
   - что скачать: рекомендуется установщик, одиночный файл тоже годится;
   - проверка `minisign` и SHA-256 установщика **до** запуска;
   - Windows: SmartScreen для установщика; UAC не должен появляться (появился = не продолжать, прислать журнал); «Пуск»; удаление через «Параметры → Приложения»; журнал `%TEMP%\Setup Log *.txt` [НП]; брандмауэр снова спросит разрешение, потому что путь программы новый [В];
   - macOS: открыть `.dmg`, перенести в «Программы», Gatekeeper как сейчас; удаление в Корзину;
   - Linux: `sudo apt install ./chervotochina-<v>-linux-x86_64.deb` (apt ничего, кроме пакета, не ставит; Secret Service предлагается, но не ставится); удаление `sudo apt remove chervotochina`;
   - данные после удаления: где лежат (Р19е-7), как удалить вручную и чем это грозит;
   - обновление: проверить новый установщик на экране «Обновления», запустить поверх (Windows), заменить `.app` (macOS), `apt install ./новый.deb` (Linux).
2. `draft.sh`: строка состава с установщиками; строка «установщики: на машинах не проверено, только CI».
3. `sign.sh`, только текст чек-листа: пункты владельца разд. 9.2.
4. THREAT_MODEL T21 вносит дирижёр по разд. 8.
Критерии: `bash scripts/check-release-guards.sh`; `cargo test --locked --workspace` не затронут (без кода); дирижёр читает diff.

## 6. Недоверенный ввод
- Скачанный установщик Inno — враждебный, пока не сверены размер и SHA-256. До сверки он не исполняется и не получает права на исполнение. Файл из `tools.lock` разбирается строго.
- Артефакты `bin-*` и `inst-*` считаются недоверенными до сверки: в `installer-smoke` по манифесту, в `installers` по SHA-256 входа и копии.
- Версия и `label` в скриптах проходят шаблоны. Пути передаются аргументами и не склеиваются в команды через `eval`.
- Смонтированный `.dmg`: проверяются ссылки и состав, ничего не запускается до `codesign --verify` и сверки с `.zip`.
- `.deb` и `.iss`: состав проверяется по тексту и по готовому пакету (`check-deb.sh`, `check-iss.sh`), не на доверии.

## 7. Не делать
- Подписи Authenticode и Apple, нотаризацию (U18, Q2 SPEC 19); подпись `.dmg`.
- Установку для всех пользователей, запрос UAC, `PrivilegesRequiredOverridesAllowed`, записи в HKLM, Program Files, `/usr/local`, `/etc`.
- Maintainer-скрипты, `Recommends`, `Depends` сверх таблицы 3.1, systemd-юниты, автозапуск, трей (Q6 этапа 18), ассоциации файлов, обработчики URL.
- Удаление и изменение данных пользователя и записей хранилищ ОС при удалении или обновлении.
- Сетевые обращения установщиков; запуск браузера; `[Run]` сверх запуска программы после установки.
- Изменения `chervo-update`, формата манифеста, `verify-release`, текстов GUI (кроме `APP_ID` и значка окна, 19е-1).
- Новые actions, кэши, пакеты Rust, `cargo install`, Chocolatey, winget, `dotnet tool`, предустановленный Inno, AppImage, Flatpak, Snap, RPM, `.pkg`, MSI.
- `build.rs` в GUI и правку готовых PE чужими инструментами.
- Публикацию, теги, установку чего-либо на машины владельца или агента.
Нужен новый инструмент, пакет или возможность сверх названных = стоп.

## 8. Модель угроз: T21 «Установщики» (внести в THREAT_MODEL при закрытии)

| Атака или сбой | Мера | Остаток |
|---|---|---|
| Подменённый установщик Inno при скачивании в CI | https, размер и SHA-256 из `tools.lock` до запуска; подписант Authenticode; отдельное задание с `contents: read` | первое закрепление работает «с первого раза» (TOFU); уязвимости самой версии Inno |
| Чужой инструмент в CI выкладывает поддельный артефакт | `assemble` берёт 8 точных имён (Р19е-8), белый список, сверка по манифесту в `smoke` | код в задании может испортить собственный выход (установщик): содержимое ловится сверкой хэша установленного файла, а лишние действия заглушки установщика — нет |
| Заглушка установщика делает больше, чем копирует (вредная сборка Inno, `[Code]`) | страж `.iss`; тихая установка в CI с проверкой состава каталога, ярлыка, ключа, отсутствия записей в HKLM | скрытое действие вне проверенных мест не ловится; подпись владельца удостоверяет байты CI, а не их честность (как T19) |
| Подмена DLL рядом с установщиком в «Загрузках» | защита загрузки DLL в Inno [НП]; совет в INSTALL: запускать из чистой папки | зависит от версии Inno |
| Нечаянное повышение прав | `lowest` без переопределений; страж; строка режима в журнале CI | раннер работает от администратора [В], поэтому отсутствие UAC CI не доказывает: проверка у владельца, разд. 9.2 |
| Каталог установки Windows доступен на запись пользователю | как у одиночного `.exe` | вредонос того же пользователя заменит `.exe` (T18(a), вне модели) |
| Потеря ключей и книги друзей при удалении | нет `[UninstallDelete]` и `postrm`; данные в другом каталоге; метка в `installer-smoke` | пользователь может удалить их вручную (предупреждение в INSTALL) |
| Установщик ставит лишнее (gnome-keyring от root) | `Depends` по таблице, без `Recommends`; разница снимков пакетов в CI = ровно один | `Suggests` ставится, если у пользователя включён `APT::Install-Suggests` (его выбор) |
| Код от root при установке `.deb` | нет maintainer-скриптов (проверка управляющей части); только файлы `root:root` 0755/0644 | триггеры чужих пакетов (`desktop-file-utils`, `hicolor`) выполняются как обычно |
| Аргументы из файлового менеджера | в `Exec` нет кодов полей | — |
| Лишнее в `.dmg` (ссылка наружу, второе приложение) | состав корня, цель ссылки, `cmp` с `.zip`, `codesign` | обход Gatekeeper приучает нажимать «всё равно открыть» (U18) |
| Откат на старую версию установщиком | действие пользователя; экран «Обновления» предупреждает (Р5) | Inno и dpkg поставят старую версию поверх новой |
| Неподписанные установщики (SmartScreen, Gatekeeper) | первая установка: `minisign` и SHA-256 до запуска | как в T19-дополнении |

## 9. Ручные проверки владельца и журналы

### 9.1. Что CI не докажет
- отсутствие UAC у обычного (не административного) пользователя;
- «Пуск» и «Приложения» в реальной Windows 11;
- поведение SmartScreen;
- значок в доке и панели GNOME (Wayland, `app_id`);
- Gatekeeper на настоящем Mac (машины нет: «не проверено»).

### 9.2. Чек-лист (одним заходом с прочими ручными, OWNER_DECISIONS «Ручные проверки (2026-10-28)»)
1. Windows 11, по возможности обычная учётная запись:
   - сначала `minisign` и `Get-FileHash`;
   - запуск `chervotochina-<v>-windows-x86_64-setup.exe /LOG="%USERPROFILE%\Desktop\chervo-setup.log"`;
   - UAC не появился; в «Пуске» «Червоточина» со значком; окно открывается, значок окна и панели задач (Q3);
   - в «Параметры → Приложения» есть «Червоточина <v>»;
   - удаление оттуда; для журнала: `"%LOCALAPPDATA%\Programs\Chervotochina\unins000.exe" /LOG="%USERPROFILE%\Desktop\chervo-uninstall.log"`;
   - после удаления на месте `%LOCALAPPDATA%\Chervotochina` и записи Credential Manager.
   Сохранить: оба журнала, `%TEMP%\Setup Log *.txt`, снимок «Приложений».
2. Ubuntu 24.04 с рабочим столом:
   - `sudo apt install ./chervotochina-<v>-linux-x86_64.deb 2>&1 | tee ~/apt-install.log`;
   - apt предложил только `gnome-keyring` (Suggests) и ничего не поставил сверх пакета;
   - значок в списке программ и в доке;
   - `sudo apt remove chervotochina 2>&1 | tee ~/apt-remove.log`, данные в `~/.local/share/chervotochina` на месте.
   Сохранить: оба журнала, `dpkg -L chervotochina > ~/files.txt` (до удаления), фрагменты `/var/log/dpkg.log` и `/var/log/apt/term.log`.
3. Мини-ПК без рабочего стола (по желанию владельца): та же установка; `chervo doctor`; apt не тянет графических библиотек.
4. macOS: «не проверено». Для будущего разбора: `hdiutil attach -verbose`, `spctl --assess -vv`, `codesign -dv --verbose=4` [НП].
До этих пунктов в отчётах писать «не проверено».

## 10. Сверить дирижёру до запуска builder (первоисточники) [НП]
1. Inno Setup:
   - текущая стабильная версия 6.x, официальный URL файла версии, опубликован ли SHA-256, подписант Authenticode;
   - **`license.txt` этой версии** (коммерческая лицензия: требование или просьба);
   - `PrivilegesRequired=lowest` и значения `{autopf}`, `{autoprograms}` в режиме без администратора; запись удаления в HKCU, имя ключа `{AppId}_is1`, поле `QuietUninstallString`;
   - параметры командной строки установщика и деинсталлятора (`/VERYSILENT`, `/SUPPRESSMSGBOXES`, `/NORESTART`, `/SP-`, `/LOG=`, `/DIR=`) и коды возврата; возвращается ли деинсталлятор до конца удаления;
   - директивы `SetupLogging`, `TouchDate`/`TouchTime`, `TimeStampsInUTC`, `x64compatible`, `CloseApplications`, `WizardStyle`; требование BOM у `.iss` в UTF-8; наличие `Russian.isl`; требования к `.ico`; защита от подмены DLL;
   - строка журнала о режиме без администратора.
2. Раннер `windows-2025`: работает ли от администратора (влияет на доказательность).
3. `dpkg-deb` на `ubuntu-22.04`: версия, `--root-owner-group`, `-Zxz`, учёт `SOURCE_DATE_EPOCH`; файловые триггеры `desktop-file-utils` и `hicolor-icon-theme`; настройка `APT::Install-Recommends` на раннере; пакет с `desktop-file-validate`.
4. `hdiutil create`, `attach` и `verify`: флаги; поведение на `macos-15`; известные сбои.
5. Типы ICNS (`ic07`, `ic08`, `ic09` как PNG); PNG внутри ICO.
6. eframe 0.37: `ViewportBuilder::with_app_id`, `with_icon`, `IconData`; что становится `app_id` и WM_CLASS по умолчанию; эффект на Windows (WM_SETICON) и X11.
7. Спецификация Desktop Entry: ключи и `Categories=Network;FileTransfer;`; размеры темы hicolor.
8. Действительность адреса `rekc2004@users.noreply.github.com` (для Q8).

## 11. Стоп-условия, лимит, отчёт
Стоп, если:
- лицензия Inno не подходит или неясна;
- хэш или подписант Inno не сверены;
- `dpkg-deb` не даёт детерминированный `.deb`;
- `NEEDED` вне таблицы 3.1;
- в `ubuntu-22.04` нет `dpkg-deb`, `readelf` или `objdump`;
- на `macos-15` нет `hdiutil`;
- нужны `[Code]`, maintainer-скрипт, новый action, пакет или инструмент;
- шаг подписи в `sign.sh` перебирает закрытый список имён;
- Python для значков недоступен локально и в CI;
- API eframe не совпадает с 5.1 п. 5;
- противоречие спецификации и кода;
- критерий непроверяем.
Остановиться и доложить, не обходить.
Лимит: не более 2 кругов «правка по ревью» на часть, затем доклад владельцу.
Отчёт builder (до 25 строк): изменённые файлы; команды приёмки и последние строки их вывода; что не сделано; отклонения.

## 12. Вопросы владельцу

**Q1. Чем делать установщик Windows.** (а) Inno Setup 6; (б) WiX/MSI; (в) NSIS. **По умолчанию (а):**
- режим «для текущего пользователя без UAC», «Пуск», «Приложения» и журнал есть из коробки, своего кода установки нет;
- условие: лицензия подходит, дирижёр сверит её до начала;
- (б) тянет .NET SDK в CI, а MSI для одного пользователя капризен; (в) — запасной путь (лицензия zlib), но регистрацию удаления пришлось бы писать вручную и журнала нет.

**Q2. Картинка значка.** (а) временная процедурная (кольца), генератор в репозитории, позже заменяется; (б) ваша картинка PNG 1024×1024. **По умолчанию (а):** не блокирует этап, замена потом меняет только файлы в `packaging/icons/`.

**Q3. Значок у окна и на панели задач Windows.** (а) задаётся из программы (`with_icon`, без `build.rs` и новых пакетов), в «Проводнике» у `.exe` значок стандартный; (б) ещё и ресурс в `.exe` через ключ компоновщика (одиночный `.exe` тоже меняется; нужен `rc.exe` раннера или свой генератор `.res`); (в) только у ярлыка. **По умолчанию (а):** запрет `build.rs` не нарушается, а без этого у работающего окна будет пустой значок.

**Q4. Secret Service при установке на Linux.** (а) без скриптов в пакете: `Suggests: gnome-keyring` (apt покажет и не поставит), проверка на первом экране окна и `chervo doctor`; (б) короткий `postinst` с подсказкой по списку установленных пакетов. **По умолчанию (а):** postinst выполняется от root без вашего сеанса D-Bus и не может проверить хранилище честно (Р7 SPEC 19).

**Q5. Класть ли консольную `chervo` в `.deb`.** **По умолчанию да:** нужна мини-ПК и для `chervo doctor`; места почти не занимает.

**Q6. Оставить ли одиночные файлы рядом с установщиками.** **По умолчанию да:** ручное обновление «заменить файл», переносной запуск, машины без apt. Цена — 4 лишних файла в выпуске.

**Q7. Windows: выбор папки и ярлык на рабочем столе.** **По умолчанию:** папка фиксирована (`%LOCALAPPDATA%\Programs\Chervotochina`), ярлык только в «Пуске». Меньше вариантов, меньше ошибок.

**Q8. Поле `Maintainer` в `.deb` (обязательное, нужен адрес).** **По умолчанию:** `Chervotochina <rekc2004@users.noreply.github.com>`, по уже публичному имени на GitHub, без личной почты. Если адрес недействителен, нужен ваш вариант.

## 13. Резюме для владельца
- Будут 4 установщика: Windows (`-setup.exe`, ставится только для вас, без запроса прав администратора, в «Пуск» и «Приложения»), macOS (`.dmg` для двух процессоров, без подписи Apple), Linux (`.deb` с окном, консолью, ярлыком и значком).
- Установщик кладёт тот же файл, что уже лежит в выпуске и подписан вами. CI это проверяет: ставит тихо, сверяет хэш установленного файла с манифестом, запускает, удаляет и смотрит, что данные остались.
- При удалении ключи и книга друзей не трогаются ни на одной ОС.
- Linux-пакет ничего не делает от root, кроме копирования файлов, и ничего не тянет: gnome-keyring только «предлагается». CI проверяет, что ставится ровно один пакет.
- Новый внешний инструмент один: Inno Setup, только в CI, версия и хэш закреплены, подписант проверяется. На macOS и Linux используются штатные `hdiutil` и `dpkg-deb`.
- Ограничение то же, что у T19: подпись подтверждает «эти байты собрал CI», но не доказывает, что заглушка установщика честная. Проверяется только то, что она поставила и удалила.
- На вашей стороне ручной чек-лист разд. 9.2 и сохранение журналов. До него установщики «на машинах не проверены».
- Нужны ответы Q1–Q8. Без ответа на Q1 (и сверки лицензии Inno) этап не начинается.

## Дополнение 1. Сверка дирижёра и ответы владельца (2026-11-15)
Ответы владельца: `docs/OWNER_DECISIONS.md`, запись «Этап 19е». Они **заменяют** варианты по умолчанию разд. 12 там, где отличаются.

1. **Inno Setup 6.7.4 (Q1), закрепление без TOFU.** Факты [П]: URL `https://github.com/jrsoftware/issrc/releases/download/is-6_7_4/innosetup-6.7.4.exe` (ссылка со страницы jrsoftware.org/isdl.php; на jrsoftware.org/files/is/ файла 6.7.4 нет); размер 10604576 байт; SHA-256 `a549929319f9120716677c685535ca4671e4b937b5fdc87e2585f32d8eb30e8c` (digest в GitHub API релиза `is-6_7_4`, совпал с локальным подсчётом); Authenticode: Status `Valid`, подписант `CN=Pyrsys B.V., O=Pyrsys B.V., S=Noord-Holland, C=NL`, издатель Sectigo Public Code Signing CA R36. Эти значения builder пишет в `packaging/tools.lock` сразу; шаг «заглушка, пробный прогон печатает хэш» (разд. 4) отменяется. Проверка подписанта — по `CN=Pyrsys B.V.` и `O=Pyrsys B.V.`. Лицензия тега `is-6_7_4/license.txt`: свободное использование, в том числе коммерческое, условие — сохранять уведомления; установщик Inno не распространяется, но строка о сборке Inno — в `docs/INSTALL.md`.
2. **Удаление.** `QuietUninstallString` в Inno 6.7.4 = `"<unins>" /SILENT` (не `/VERYSILENT`) [П: Setup.Install.pas:309-310]. Smoke зовёт `unins000.exe /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /LOG=<файл>` через `Start-Process -Wait -PassThru`, код возврата 0, затем проверяет, что каталог программы и ключ удаления `<AppId>_is1` в HKCU исчезли (повтор проверки до 10 с: деинсталлятор удаляет себя с задержкой около 0,5 с). AppId короче 57 символов (иначе имя ключа укорачивается с CRC32).
3. **BOM у `.iss`** не требуется (компилятор читает UTF-8 без BOM) [П по исходнику]; оставить BOM можно. `Russian.isl` в поставке есть [П].
4. **Q7: папка программы фиксирована** (`DisableDirPage=yes`; `{autopf}` = `{localappdata}/Programs` при `PrivilegesRequired=lowest` [П]). Папку для принятых файлов установщик не задаёт и не спрашивает: её выбирает пользователь в программе (первый экран, настройки).
5. **Q2: значок — процедурная «кротовая нора»**: воронка или туннель из концентрических колец с перспективой, уходящая в тёмный центр; детерминированный генератор, без шрифтов и чужих картинок; читается на 16×16 (на малых размерах допускается упрощение до 2-3 колец).
6. **Q8: Maintainer** = `Chervotochina <161205578+rekc2004@users.noreply.github.com>` [П: формат docs.github.com для аккаунтов после 2017-07-18, id аккаунта из `gh api user`].
7. **eframe/egui 0.37.0** [П docs.rs]: `ViewportBuilder::with_icon(impl Into<Arc<IconData>>)`, `IconData { rgba: Vec<u8>, width: u32, height: u32 }`; `with_app_id` действует только на Wayland и задаёт место persistence корневого окна. Если смена app_id меняет путь сохранённых настроек eframe — **стоп-условие** (доложить, не мигрировать молча).
8. **dpkg 1.21.1 на ubuntu-22.04** [П]: `--root-owner-group`, `-Zxz`, `SOURCE_DATE_EPOCH` поддержаны.
9. [НП] до запуска в CI: работает ли job `windows-2025` от администратора (UAC на образе выключен). Поэтому доказательство «без администратора» в CI: запись удаления в HKCU, отсутствие записи в HKLM, каталог под `%LOCALAPPDATA%`; окончательно — ручная установка владельцем под обычной учётной записью.
