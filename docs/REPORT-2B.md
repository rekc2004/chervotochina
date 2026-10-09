# REPORT-2B: этап 2б (перепроверка аналогов)

Ветка `claude/stage-2b-analogs`. Остановка после обновления DECISION.md, как велит промпт.

## Резюме для владельца
Аналоги теперь проверены по первоисточникам почти все, но даты последних коммитов не проверены нигде (GitHub API закрыт). Решение (iroh `Builder::empty()`, запасной quinn+rustls) **не менялось**. Главное из нового: AltSendme переименован в DashBeam (AGPL-3.0, relay и discovery n0 из приложения полностью не отключаются); AlterSend работает на DHT + blind relay; LocalSend только LAN без внешних серверов; Blip заявляет relay, e-mail и поиск людей не подтверждены. Вопросы владельцу: U20-U22 в `docs/OPEN_QUESTIONS.md`.

## 1. Проверено
- Раздел 1 `docs/DECISION.md`: таблица 8 аналогов (версия, релиз, лицензия, серверы по умолчанию, соединение), у фактов источник и метка. Разведчики дали [П], в документе записано [П-р] (не перепроверено мной).
- 2.1 и 2.3 сверены с фактами; 2.4 не тронут. U13 частично закрыт, U16 обновлён, добавлены U20-U22.
- Проверка кода/сборки не требовалась (только документы).

## 2. Домены
Открыты: raw.githubusercontent.com, docs.rs, static.crates.io, index.crates.io, docs.iroh.computer, iroh.computer (редирект), blip.net (главная; /faq, /privacy, /security отдали 403 Cloudflare), localsend.org, www.rfc-editor.org, datatracker.ietf.org (плюс pypi.org, proxy.golang.org).
Закрыты (403): github.com, api.github.com, codeload.github.com.

## 3. НЕ проверено
Даты последних коммитов всех аналогов; Blip: версия, лицензия, состав серверов, e-mail и поиск людей; что fs-cli и есть «fsend» (репозиторий с таким именем не найден); даты релизов DashBeam и AlterSend; bootstrap-узлы и значение relay по умолчанию в коде AlterSend; отсутствие внешних обращений в коде LocalSend; хостинг серверов croc и magic-wormhole; DashBeam собран на iroh 1.0.3, разбирали 1.3.0. Сетевые эксперименты не запускались. Инъекций в прочитанных страницах не обнаружено.

## 4. Расход
Вызовов субагентов 5 из 6: scout x4 (haiku-5-5/low: Blip+LocalSend, AltSendme+iroh, croc+magic-wormhole, fsend+AlterSend), architect x1 (opus-5-5/high). Модели по frontmatter `.claude/agents/`, фактически обслуживающую не проверял. Основная сессия Sonnet 5.5. Адреса fsend и AlterSend найдены веб-поиском (сторонний источник), затем подтверждены разведчиками по raw. Язык внутренних текстов: русский.
