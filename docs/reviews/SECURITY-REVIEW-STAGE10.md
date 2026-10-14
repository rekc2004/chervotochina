# Ревью безопасности реализации этапа 10 (combine-security, Opus/high)

Diff `a9d1aea..dc3710a`. Сверено с исходниками крейтов в `~/.cargo/registry`. Запущено: `cargo test -p chervo-identity --locked` (39 passed, 1 ignored; no_disk 2; doc 4), `cargo tree` по фичам. Записано дирижёром из отчёта агента без изменений по существу.

**Итог: блокирующих (High и выше) нет.** Н1-Н9 из `ARCH-REVIEW-STAGE10.md` не повторяются.

Проверено [П]: U10a-2 п.5 (`load` не пишет, store.rs:70-99; `create`/`rekey` пробрасывают ошибку `read`, store.rs:61-66,103-108; `NoEntry` в `None` только в `read`, os.rs:94-100, и в `Ok` только в `delete`, os.rs:105-110); п.1 (нет выдачи seed/blob, `from_seed` pub(crate) keys.rs:115, Debug скрыт, байты `BadEncoding`/`BadDataFormat` обнуляются os.rs:49-56); журналы keyring-core `debug!` без секрета (keyring-core lib.rs:237,282,359; zbus trace без тела, zbus-5.19.0 message/mod.rs:249-281); Linux: сессия всегда DH (zbus-store service.rs:24-26; secret-service-5.2.0 session.rs:173-181); подписи: фичи только fast+zeroize, каноничность скаляра (signature.rs:89-90,158), `verify_strict` сравнивает R (verifying.rs:384-389), `Signature::from_bytes` без ошибки (ed25519-3.0.0 lib.rs:327); обнуление `SigningKey` (signing.rs:719,726), `get_secret` сразу в `Zeroizing` (os.rs:96); `cargo tree --target all`: нет openssl/libdbus/dbus-sys/keyutils/regex, нет sample/mock.

Замечания (все Low):
- L1. secret-service-5.2.0 не обнуляет память (секрет blocking/item.rs:113, ключ AES и DH session.rs:68-78). Записать как [П] «не обнуляет» в «НЕ проверяется».
- L2. Кроме `.expect` на Mutex в zbus-store, `expect("platform RNG failed")` в secret-service session.rs:70 из `Store::new` (`OsKeyStore::open`): сбой ГСЧ = паника. Записать.
- L3. При debug/trace логах keyring-core и zbus пишут `keyring:pair-v1-<hex>@chervotochina`: виден масштаб и обращения. Требование к этапу журналов: фильтр `keyring_core`, `zbus`, `secret_service` не ниже info.
- L4. DH Secret Service: группа 1024 бит, возведение в степень с переменным временем (session.rs:219); атакующий на шине уже под тем же пользователем. В модель угроз.
- L5. `rekey` перезаписывает запись неизвестной версии (откат формата). Требование к этапу 11: при `UnsupportedKeyVersion` перед `rekey` спрашивать пользователя.
- L6. Гонка `create` между `read` и `write` (store.rs:61-66): уже в этапе 18; случайный PairId снижает риск.

Не проверено [НП]: сборка веток Windows/macOS (на момент ревью; см. CI в отчёте), supply-chain (не запускал), поведение реальных хранилищ (KWallet/KeePassXC при блокировке, запросы macOS, `Persist=Local`), данные внутри `PlatformFailure(Box<dyn Error>)` (уничтожаются без обнуления), копии ключа в стеке и временные массивы ed25519-dalek, ручной `os_store_roundtrip_manual`.
