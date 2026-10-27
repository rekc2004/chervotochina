# Приёмка этапа 10б (combine-verifier, Sonnet/low), 2026-10-15

HEAD 6561fc3, база b3bd562. Все критерии `docs/specs/stage-10b-kx.md`, проверяемые командой, выполнены фактическим запуском: сборка крейта и workspace; `cargo test -p chervo-identity` (4 + 52 [1 ignored] + 14 [1 ignored] + 2 + 2 + 10 doc), все 38 имён из перечня есть; 10 doc `compile_fail`; `cargo test --workspace`; другие крейты не тронуты; clippy `-D warnings`, fmt; `check-forbidden.sh` и `--self-test`; прямые зависимости ровно 10; фичи snow/x25519-dalek/ed25519-dalek по спецификации; `ring` отсутствует; прежние критерии этапа 10 зелёные. Дирижёр независимо перезапустил `cargo test -p chervo-identity --locked`: те же числа, exit 0.

`kk_trial_cost` (release, медиана из 50, мкс; нет совпадения / первым / последним / max:min): N=1 152/309/313/2.06; N=10 1587/1740/1776/1.12; N=50 8074/8364/8185/1.04; N=200 32131/34456/32779/1.07. При N=1 «нет совпадения» быстрее, так как msg2 не пишется (по спецификации).

`cargo tree -d --target all`: ожидаемые curve25519-dalek 4.1.3/5.0.0, getrandom 0.3.4/0.4.3; иные дубликаты крипто-крейтов (по спецификации — перечислить, не стоп): block-buffer 0.10/0.12, cipher 0.4/0.5, cpufeatures 0.2/0.3, crypto-common 0.1/0.2, digest 0.10/0.11, fiat-crypto 0.2/0.3, inout 0.1/0.2 (одна версия от snow 0.10.0, другая от dalek 5 / secret-service); прочие r-efi 5/6, syn 2/3.

Supply-chain (`cargo deny`, `cargo audit`): проверяется CI на коммите этапа. Не проверено: CI-матрица 3 ОС на момент записи, `os_store_roundtrip_manual` (ручной).
