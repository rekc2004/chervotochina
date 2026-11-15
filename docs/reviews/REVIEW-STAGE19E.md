# Ревью этапа 19е (установщики) перед ручной установкой

Дата: 2026-11-16. Объект: ветка `claude/stage-19e-installers` на `d04cd99`, diff `origin/main...HEAD` (база `b3e7315`, 44 файла).
Рецензенты, независимые и без доступа к прошлой записи ревью 19е:
- `combine-security` (Opus, high): безопасность;
- general-purpose (Opus): корректность и соответствие спецификации.

Сводил дирижёр. Находки С2, С3 и К1 он сверил с кодом сам: `smoke-deb.sh:67`, `smoke-dmg.sh:54`, `INSTALL.md:54`.

Критичность: **Critical** и **High** не найдено. Ничего, что ломало бы установку по существу, не найдено.

## Безопасность

| № | Уровень | Где | Суть | Предложение | Статус |
|---|---|---|---|---|---|
| С1 | Medium | `release.yml`, задание `installers` | Подмена артефакта целиком: код Inno/ISCC (выполняется от администратора раннера) может через токен следующего шага `upload-artifact` перезалить `bin-*`/`inst-*` того же прогона; `collect-dist.sh` и страж 9 проверяют только имена, манифест строится из подменённых байтов | `build` публикует SHA-256 в `outputs` (свой ключ на цель матрицы), `assemble` сверяет до `collect-dist.sh`; либо `download-artifact` по `artifact-ids` | Уже в T21, остаток (1); [НП] перезапись чужого артефакта токеном |
| С2 | Medium | `scripts/release/smoke-deb.sh:42-67` | Перед `apt-get install` `.deb` сверяется только по хэшу манифеста; `check-deb.sh` (нет maintainer-скриптов, `root:root`, состав) идёт лишь в `installers`. Вместе с С1 подменённый пакет с `postinst` прошёл бы smoke | Вызвать `check-deb.sh` в smoke-deb до установки, при провале не ставить | Новое |
| С3 | Low | `scripts/release/smoke-dmg.sh:54` | При провале `check-dmg.sh` только `bad`, образ всё равно монтируется и бинарь запускается; расходится со SPEC разд. 6 | При провале сразу `exit 1` | Новое |
| С4 | Low/Info | `scripts/check-release-guards.sh`, правило 7 | Чёрный список не ловит `WebClient`/`DownloadFile`/`HttpClient`, `gh run download`/`gh release download`, `urllib`, `pip`, `git clone`; `packaging/` не сканируется | Дополнить список хотя бы `gh run download`, `WebClient` | Уже в T21, остаток (2) |
| С5 | Info | `scripts/release/check-dmg.sh:53` | Скрытые элементы корня образа принимаются под любым именем | Закрытый список: `.fseventsd`, `.Trashes`, `.DS_Store` | Новое |

Проверено и в порядке, по отчёту рецензента:
- разбор `tools.lock`, `curl` только https с ограничением размера, сверка размера и SHA-256 до запуска;
- подписант Inno сверяется точно по CN и O;
- права заданий: `contents: read`, запись только у `draft`;
- закрытый список строк `.iss`, нет `[Code]`/`[Registry]`/`[UninstallDelete]`;
- данные пользователя отделены от каталога установки;
- состав и права `.deb`;
- ссылка `.dmg` ровно на `/Applications`, побайтное сравнение с `.zip`;
- `include_bytes!` иконки без unsafe.

## Корректность

| № | Уровень | Где | Суть | Предложение |
|---|---|---|---|---|
| К1 | Важно (до ручной установки) | `docs/INSTALL.md:54`, SPEC 9.2 | Команда журнала в синтаксисе cmd. В PowerShell, который открывается по умолчанию в Windows 11: `%USERPROFILE%` не раскрывается, нет `.\`, а при OneDrive `Desktop` может отсутствовать | Две строки, cmd и PowerShell (`.\…-setup.exe /LOG="$env:TEMP\chervo-setup.log"`), журнал в `%TEMP%` |
| К2 | Важно | `packaging/linux/io.github.rekc2004.chervotochina.desktop:11` | `StartupWMClass=io.github.rekc2004.chervotochina`: на X11 winit ставит WM_CLASS по имени бинаря (`chervotochina`), и док GNOME не свяжет окно с ярлыком. На Wayland всё совпадает | `StartupWMClass=chervotochina`; та же правка в `check-deb.sh` и self-test `package-deb.sh` (сравнение побайтное) |
| К3 | Проверить вручную | `crates/chervo-gui/src/main.rs`, INSTALL.md:58 | `with_icon` ставит только `ICON_SMALL`, у панели задач Windows может остаться стандартный значок (вывод по исходнику winit) | Посмотреть при ручной установке; если подтвердится, поправить INSTALL или передавать иконку панели задач |
| К4 | Мелочь | `docs/INSTALL.md`, разд. 3 | Нет шага удаления на Windows, а SPEC 5.4 его требует | Добавить «Параметры → Приложения → Червоточина → Удалить» |
| К5 | Мелочь | `packaging/windows/chervotochina.iss` | При удалении Inno не закрывает работающую программу (`AppMutex` нет), и `.exe` может остаться. Это по памяти, не проверено | Строка в INSTALL: «закройте программу перед удалением» |

Принятые отклонения от SPEC: `Exec=/usr/bin/chervotochina` (правка ревью B7) и ожидание удаления 60 с вместо 10 с (`smoke-installer-windows.ps1:158`).

Проверено и в порядке:
- пути `.iss` и `AppId` совпадают со smoke;
- `control` и `Installed-Size` одинаковы в двух скриптах, пути hicolor 16…512;
- том `.dmg`;
- `needs` в release.yml, 8 имён артефактов совпадают во всех скриптах;
- smoke не проходит ложно при пустом хэше;
- буфер иконки 16384 байт; паники при неверном размере нет;
- `persistence` выключена, `with_app_id` путь настроек не меняет.

Команды рецензентов, все прошли:
- `bash -n` по всем скриптам;
- self-test: `check-iss`, `collect-dist`, `check-whitelist`, `package-dmg`, `package-windows`, `fetch-tool`;
- `check-release-guards.sh`;
- `cargo test -p chervo-gui window_icon`.

## Не проверено
- shellcheck (на машине нет), self-test `package-deb` и `check-dmg` (нужны dpkg-deb и macOS), запуск ISCC.
- Обновление поверх старой версии и установка при работающей программе: в CI таких шагов нет.
- Отсутствие UAC под обычной учётной записью, SmartScreen, Gatekeeper, значки на панели задач и в доке, подмена DLL рядом с установщиком [НП].
- Может ли `ACTIONS_RUNTIME_TOKEN` перезаписать артефакт другого задания [НП].
- `make-icons.py` и бинарные значки по содержимому.

## Рекомендация дирижёра
До ручной установки: К1 (иначе журнал Windows не запишется так, как описано) и К4/К5 (текст INSTALL). Дёшево и без риска: С2, С3, К2. С1 и С4 остаются остатками T21 до отдельного решения. К3 проверяется при ручной установке.
