# Ревью безопасности этапа 15 (безопасный приём)

Автор: combine-security (opus/high), 2026-10-18. Diff `d9d5671..10ae217`. Опоры: `docs/specs/stage-15-receive.md` (ред. 2), `docs/OWNER_DECISIONS.md` «Этап 15», `docs/THREAT_MODEL.md`, `docs/reviews/SECURITY-REVIEW-STAGE14.md` п.8-9. Записано дирижёром со слов ревьюера (агент только читает).

## Итог
Имя от друга само по себе не выходит из корня и не перезаписывает существующий файл (тесты и чтение кода). 1 Medium (Windows, локальный гонщик), остальное — пробелы списков типов и Low.

## Находки
- **F1 Medium (Windows, локальный гонщик).** `place.rs:134-144` + удаление `place.rs:446-452`: при неудаче `verify_placed` `remove_file(cand)`, если найденный файл той же длины. Гонщик подменяет нашу папку D на junction к V с пользовательским файлом того же имени и длины -> удаляется файл пользователя (подставной исполнитель). На Unix закрыто dev+ino. Мера: `symlink_metadata(temp)` после `mark_origin` (`place.rs:424`), сравнение `len` + `creation_time()` + `last_write_time()` (`std::os::windows::fs::MetadataExt`), либо не удалять, а `Refused`.
- **F2 Medium-Low.** Пробелы классов (`classify.rs:65-181`), такие файлы Ordinary и автоприёмны. Windows: `.appref-ms .msu .ppkg .vsto .xbap .deskthemepack .searchConnector-ms .diagcfg .diagpkg .wsb .pyz .pyzw .dqy .rqy`; активное содержимое `.svg .svgz .xht .shtml`; старый Office с макросами `.doc .dot .xls .xlt .xla .ppt .pot .pps .ppa .wbk .wll`; Access `.mdb .accdb .accde .mde .adp .ade`; OneNote `.one .onepkg`. macOS: `.fileloc .inetloc .sparseimage`; `BUNDLE_DIRS` без `.prefpane .saver .scptd .workflow .action .mpkg .wdgt .qlgenerator .mdimporter .xpc .osax`. Linux: `.flatpak`. Надёжная мера: автоприём только по списку заведомо безопасных расширений.
- **F3 Low-Medium (не проверено).** Не-ASCII расширение — Ordinary без `suspicious` (`classify.rs:184-188`); если оболочка Windows сопоставляет `ſ`->S, `ı`->I, то `x.vbſ`, `x.msı`, `x.pıf` исполняемы. Мера: классифицировать по `fold(ext)` и/или `suspicious` при любом не-ASCII в расширении.
- **F4 Low.** Потолок не общий: `policy.rs:335-338` берёт минимум лимита друга и потолка для каждого друга отдельно (N друзей = N×16 ГиБ/24 ч); соответствует решению 15 спецификации, но комментарий `root.rs:307` говорит «по всем друзьям вместе». Нужно решение владельца.
- **F5 Low (локально, класс п.8 ревью 14).** `.dirs` под SHA-256 без ключа (`journal.rs:110-149`): подделка `k=1` -> после перезапуска `walk_create` принимает существующую папку пользователя при i==0 (`place.rs:276`), новые файлы ложатся внутрь (без перезаписи). Мера: хранить идентичность папки (ino / creation_time) и сверять.
- **F6 Low.** `plan.rs:230-235`: `long_path` до суффикса ` (k)` — путь может перейти 259 символов (только удобство).
- **F7 Low (конфигурация).** `place.rs:78-86`: малый `max_name_bytes` -> бюджет 0 -> имя ` (2).ext` или длиннее предела. Использовать проверку резерва `plan.rs:96-99`.
- **F8 Сведения.** `forget`/`create_top_dirs` проверяют только последний компонент перед `remove_dir` — через junction в середине пути можно удалить пустую папку пользователя.
- **F9 Сведения (не проверено).** Значение карантина `0081` (Safari пишет `0083`); созданные папки (пакеты) без карантина.

## Проверено, верно
Санитайзер (`..`, абсолютные, диски, UNC, `\\?\`, обратная косая, управляющие отвергаются; `:`/ADS, похожие косые, bidi/невидимые -> `_`; устройства вкл. надстрочные, CONIN$, с расширением и пробелом; `~цифра`; хвостовые точки/пробелы; NFC до переписываний; `safe_push`). Корень канонический `\\?\`. Ссылки проверяются до и после по каждому звену; junction видна как ссылка; висячая ссылка -> `AlreadyExists` -> `Refused`. Журналы ограничены, с контрольной суммой, только индексы, `k<=999`. MotW до ссылки; Unix 0o600/0o700. unicode-normalization 0.1.26: `unsafe` только Hangul с верными границами; tinyvec 1.13.3 forbid(unsafe).

## Не проверено
macOS/Linux локально (в CI тесты прошли), `create_new` на висячей ссылке в Windows, FAT/SMB, следование ссылкам `create_new` в std Windows, `examples/node15.rs`, `tests/receive_net.rs`, реальное поведение Проводника для `ſ`/`ı`.
