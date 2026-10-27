# Мини-ПК с Linux без рабочего стола (Ubuntu)

Статус проверки: **не проверено на мини-ПК** (на 2026-10-27). Шаги взяты из документации и CI-скрипта `scripts/ci-secret-service.sh` (там проверен только запуск и разблокировка gnome-keyring внутри приватной шины D-Bus). Проверьте по порядку и впишите дату проверки.

## 1. Пакеты (ставит владелец сам; программа ничего не ставит)

    sudo apt install gnome-keyring dbus-user-session

## 2. Служба пользователя без входа в систему

    loginctl enable-linger "$USER"

Пользовательские службы будут жить после выхода из ssh и стартовать при загрузке.

## 3. Запуск Secret Service службой systemd

Файл `~/.config/systemd/user/gnome-keyring-secrets.service`:

    [Unit]
    Description=gnome-keyring Secret Service

    [Service]
    ExecStart=/usr/bin/gnome-keyring-daemon --foreground --components=secrets

    [Install]
    WantedBy=default.target

Затем:

    systemctl --user daemon-reload
    systemctl --user enable --now gnome-keyring-secrets.service

## 4. Разблокировка после перезагрузки по ssh

После перезагрузки хранилище заблокировано. Пароль передавайте через stdin, не аргументом (аргумент виден в истории оболочки и в списке процессов):

    read -rs KP; printf '%s' "$KP" | gnome-keyring-daemon --unlock --components=secrets; unset KP

## 5. Проверка

    chervo doctor

- `хранилище ключей доступно`, код 0: всё готово;
- `хранилище заблокировано: ...`, код 1: вы забыли разблокировать (разд. 4); программа не зависает и окно пароля не показывает;
- `хранилище ключей недоступно: ...`, код 1: служба не запущена (разд. 3) или нет сессионной шины D-Bus (`echo $DBUS_SESSION_BUS_ADDRESS` пусто; зайдите заново по ssh после `enable-linger`).
