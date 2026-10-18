#!/usr/bin/env bash
# Генератор отчёта этапа 16: docs/reports/NETTEST-<дата>.md из логов стенда stage16.sh (спецификация п. 13).
# Использование (обычный пользователь, не root):
#   bash tools/netns/report16.sh LOGDIR OUT.md     # LOGDIR = tools/netns/logs/stage16
#   bash tools/netns/report16.sh --self-test       # прогон на tools/netns/fixtures16 (положительный и отрицательные контроли)
# Читает в LOGDIR: summary16.tsv, speed16.tsv, meta16.txt, natcheck16.tsv, hostsafe16.tsv (каких-то может не быть).
# Адреса заменяются ролями (фиксированная карта, CORE=11.0.0 по умолчанию). Если в итоге остался IPv4/IPv6-адрес, путь
# /home/, /tmp/chervo, /root/, значение `hostname` или $SUDO_USER, файл НЕ пишется, код выхода 4.
#
# НЕ ЗАПУСКАЛСЯ НА LINUX СБОРЩИКОМ (not run on Linux by the builder): проверен `bash -n` и `--self-test` на машине сборки.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE="${CORE:-11.0.0}"
LD=""

# ---------------------------------------------------------------- статические сведения о строках
declare -A TITLE=() LEARN=() THEORY=()
TITLE[C01]="HA - HA2 (одна LAN)";               LEARN[C01]="приглашение с адресом LAN";            THEORY[C01]="один сегмент (mDNS не проверялся)"
TITLE[C02]="IPv6";                              LEARN[C02]="-";                                     THEORY[C02]="приём IPv6 отложен владельцем"
TITLE[C03]="WA - WB";                           LEARN[C03]="приглашение";                           THEORY[C03]="оба белые"
TITLE[C04]="FC - PR (NAT-A FC, NAT-B PR)";      LEARN[C04]="встречная связка; токен X->Y";          THEORY[C04]="EIF пускает Y, не зная Y"
TITLE[C05]="AR - AR";                           LEARN[C05]="связка; токены в обе стороны";          THEORY[C05]="оба EIM, оба адреса известны"
TITLE[C06]="PR - PR";                           LEARN[C06]="связка; токены в обе стороны";          THEORY[C06]="оба EIM, одновременное открытие"
TITLE[C07]="PR - PR без токенов";               LEARN[C07]="только связка";                         THEORY[C07]="никто не знает внешний адрес другого"
TITLE[C08]="SYM - WA, WB";                      LEARN[C08]="приглашение; затем WA убит";            THEORY[C08]="EDM виден двум наблюдателям"
TITLE[C09]="SYM - FC";                          LEARN[C09]="связка; токен Y->X";                    THEORY[C09]="SYM звонит, EIF пускает"
TITLE[C10]="SYM - AR";                          LEARN[C10]="связка; токен Y->X";                    THEORY[C10]="AR не писал на адрес SYM"
TITLE[C11]="SYM - PR";                          LEARN[C11]="связка; токен Y->X";                    THEORY[C11]="EDM против APDF"
TITLE[C12]="SYM - SYM";                         LEARN[C12]="связка; токены (ожидается отказ)";      THEORY[C12]="EDM с обеих сторон"
TITLE[C13]="HC (CGNAT) - WA";                   LEARN[C13]="приглашение; затем WA убит";            THEORY[C13]="исходящее работает, до HC никто не достаёт"
TITLE[C14]="HC - PR";                           LEARN[C14]="связка; токен Y->X";                    THEORY[C14]="HC не может опубликовать адрес"
TITLE[C15]="HC - HC2 (два CGNAT)";              LEARN[C15]="связка; токены (ожидается отказ)";      THEORY[C15]="обе стороны за CGNAT"
TITLE[C16]="HD (двойной NAT) - WA";             LEARN[C16]="приглашение";                           THEORY[C16]="двойной NAT без данных шлюза не виден (nat_view=Eim)"
TITLE[C17]="HD - PR";                           LEARN[C17]="связка; токены в обе стороны";          THEORY[C17]="оба слоя EIM с сохранением порта"
TITLE[C18]="HR (UPnP) - PR";                    LEARN[C18]="приглашение с пробросным адресом";      THEORY[C18]="проброс порта; после остановки правило снято"
TITLE[C19]="HA - WA, WB при обрыве UDP на HA";  LEARN[C19]="приглашения";                           THEORY[C19]="два белых друга молчат"
CONN_IDS=(C01 C02 C03 C04 C05 C06 C07 C08 C09 C10 C11 C12 C13 C14 C15 C16 C17 C18 C19)
declare -A VTITLE=() VTHEORY=()
VTITLE[V01]="CGNAT - PR";          VTHEORY[V01]="да (EIM с обеих сторон)"
VTITLE[V02]="CGNAT - CGNAT";       VTHEORY[V02]="зависит от того, что оба CGNAT EIM"
VTITLE[V03]="SYM - PR";            VTHEORY[V03]="нет"
VTITLE[V04]="SYM - SYM";           VTHEORY[V04]="нет"
VTITLE[V05]="PR - PR без токена";  VTHEORY[V05]="да"

# ---------------------------------------------------------------- чтение
cell() { local v="${1:-}"; v="${v//|//}"; [[ -n "$v" ]] || v="-"; printf '%s' "$v"; }
srow() { # id -> строка summary16.tsv
  [[ -f "$LD/summary16.tsv" ]] || return 0
  awk -F'\t' -v id="$1" '$1 == id { print; exit }' "$LD/summary16.tsv"
}
sf() { # id номер_поля
  local r; r="$(srow "$1")"
  [[ -n "$r" ]] || { printf '%s' "-"; return 0; }
  awk -F'\t' -v n="$2" '{ print $n }' <<<"$r"
}
meta() { # ключ
  local v=""
  [[ -f "$LD/meta16.txt" ]] && v="$(grep -m1 "^$1=" "$LD/meta16.txt" | cut -d= -f2-)"
  printf '%s' "${v:-нет данных}"
}

# ---------------------------------------------------------------- разделы
sec_header() {
  echo "# Сетевые тесты этапа 16 (стенд netns)"
  echo
  echo "Отчёт сгенерирован скриптом report16.sh. Эмуляция netns, не реальные операторы и не ТСПУ."
  echo
  echo "## 1. Заголовок"
  echo
  echo "- Дата: $(meta date)"
  echo "- Коммит: $(meta commit)"
  echo "- Ядро: $(meta kernel); ядер: $(meta nproc); процессор: $(meta cpu); виртуализация: $(meta virt)"
  echo "- Версии: $(meta nft); $(meta tc); $(meta iproute2); miniupnpd $(meta miniupnpd); rustc сборки узла: $(meta rustc)"
  echo "- Скорости измерены под nice $(meta nice) (узлы строк скорости шли с пониженным приоритетом): все числа раздела 6 помечены «под nice»."
  echo "- Повторов на конфигурацию скорости: $(meta repeats)"
}

sec_natcheck() {
  echo
  echo "## 2. NATCHECK (проверка, что правила nft изображают заявленные типы NAT)"
  echo
  if [[ ! -s "$LD/natcheck16.tsv" ]]; then
    echo "Контроль типов NAT не выполнялся или не дал данных: **типы NAT независимо не проверены.**"
  else
    echo "| Ключ (тип@узел) | Ожидали (маппинг/фильтр) | Получили | Внешний порт | Итог | Попыток |"
    echo "|---|---|---|---|---|---|"
    awk -F'\t' '{ printf "| %s | %s/%s | %s/%s | %s | %s | %s |\n", $1, $2, $3, $4, $5, $6, $7, $8 }' "$LD/natcheck16.tsv"
    if awk -F'\t' '$7 != "PASS" { f = 1 } END { exit f ? 0 : 1 }' "$LD/natcheck16.tsv"; then
      echo
      echo "Есть типы без прохода контроля: строки, где они используются, помечены INCONCLUSIVE; правила под результат не подгонялись."
    fi
  fi
  echo
  echo "Примечание: FC здесь это full cone для одного внутреннего хоста (проброс порта одному хосту), а не общий full cone."
  local r; r="$(srow NATCHECK)"
  [[ -z "$r" ]] || echo "Итог строки NATCHECK: $(sf NATCHECK 3), $(sf NATCHECK 5)."
}

sec_matrix() {
  local id r v
  echo
  echo "## 3. Матрица связности (ожидали и получили)"
  echo
  echo "| ID | Пара | Адреса узнаны через | Ожидали | Получили | Причина X (ожид. / получ.) | Причина Y (ожид. / получ.) | Путь | Время, с | Вердикт |"
  echo "|---|---|---|---|---|---|---|---|---|---|"
  for id in "${CONN_IDS[@]}"; do
    r="$(srow "$id")"
    if [[ -z "$r" ]]; then
      echo "| $id | $(cell "${TITLE[$id]}") | $(cell "${LEARN[$id]}") | - | нет данных | - | - | - | - | не запускалась |"
      continue
    fi
    echo "| $id | $(cell "${TITLE[$id]}") | $(cell "${LEARN[$id]}") | $(cell "$(sf "$id" 4)") | $(cell "$(sf "$id" 5)") | $(cell "$(sf "$id" 6)") / $(cell "$(sf "$id" 7)") | $(cell "$(sf "$id" 8)") / $(cell "$(sf "$id" 9)") | $(cell "$(sf "$id" 10)") | $(cell "$(sf "$id" 11)") | $(cell "$(sf "$id" 3)") |"
  done
  echo
  echo "Вердикты: PASS; MISMATCH (исход как ожидали, причина или путь другие: на разбор архитектору); FAIL; INCONCLUSIVE (контроль стенда или срок); NOTRUN (с причиной). Ожидания взяты из спецификации и под результат не правились."
}

sec_notconnected() {
  local id r a any=0
  echo
  echo "## 4. Какие пары не соединились и почему"
  echo
  echo "| ID | Пара | Исход | Причина X (получена) | Причина Y (получена) | Теория (почему) | Вердикт |"
  echo "|---|---|---|---|---|---|---|"
  for id in "${CONN_IDS[@]}"; do
    r="$(srow "$id")"
    [[ -n "$r" ]] || continue
    a="$(sf "$id" 5)"
    case "$a" in
      no*|*unreachable*)
        any=1
        echo "| $id | $(cell "${TITLE[$id]}") | $(cell "$a") | $(cell "$(sf "$id" 7)") | $(cell "$(sf "$id" 9)") | $(cell "${THEORY[$id]}") | $(cell "$(sf "$id" 3)") |" ;;
    esac
  done
  if [[ $any == 0 ]]; then echo "| - | в данных нет строк с исходом «нет» | - | - | - | - | - |"; fi
  echo
  echo "Причина каждой стороны — диагноз продукта только про свою сторону (последнее событие unreachable по паре, иначе последний DIAG в конце окна)."
}

sec_via() {
  local id
  echo
  echo "## 5. Через посредника (rendezvous): не запускалось"
  echo
  echo "| ID | Пара | Вердикт | Причина | Ожидание по теории |"
  echo "|---|---|---|---|---|"
  for id in V01 V02 V03 V04 V05; do
    echo "| $id | $(cell "${VTITLE[$id]}") | NOTRUN | этап 13б отложен владельцем | $(cell "${VTHEORY[$id]}") |"
  done
}

sec_speed() {
  local nice; nice="$(meta nice)"
  echo
  echo "## 6. Скорости (справочно, под nice $nice)"
  echo
  if [[ ! -s "$LD/speed16.tsv" ]]; then
    echo "Строки скорости не запускались."
  else
    echo "| Путь | Профиль | MiB/с медиана (мин-макс) | Мбит/с | Разброс | CPU отправитель, % ядра | CPU получатель, % ядра | Занято ядер | Контроли (rate/rtt/loss) | Пометки |"
    echo "|---|---|---|---|---|---|---|---|---|---|"
    awk -F'\t' '
      function med(key, col, n,   i, j, t, a, m) {
        m = 0
        for (i = 1; i <= cnt[key]; i++) { t = val[key, i, col]; if (t != "-" && t != "") a[++m] = t + 0 }
        if (m == 0) return "-"
        for (i = 2; i <= m; i++) { t = a[i]; for (j = i - 1; j >= 1 && a[j] > t; j--) a[j + 1] = a[j]; a[j + 1] = t }
        return (m % 2) ? a[(m + 1) / 2] : (a[m / 2] + a[m / 2 + 1]) / 2
      }
      {
        k = $1 "|" $2
        if (!(k in cnt)) { order[++nk] = k; cnt[k] = 0 }
        n = ++cnt[k]
        for (c = 4; c <= 14; c++) val[k, n, c] = $c
      }
      END {
        for (q = 1; q <= nk; q++) {
          k = order[q]; split(k, kp, "|")
          mn = ""; mx = ""; fin = 0; flags = ""; busy = 0; bad = 0; rate = "ok"; rtt = "ok"; loss = "ok"; hasr = 0; hasl = 0; hast = 0
          for (i = 1; i <= cnt[k]; i++) {
            v = val[k, i, 6]
            if (v != "-" && v != "") { fin++; v += 0; if (mn == "" || v < mn) mn = v; if (mx == "" || v > mx) mx = v }
            if (val[k, i, 10] + 0 > 1.5) busy = 1
            if (val[k, i, 11] != "ok") bad = 1
            if (val[k, i, 12] == "FAIL") rate = "FAIL"; else if (val[k, i, 12] == "-" && rate != "FAIL") rate = "-"
            if (val[k, i, 13] == "FAIL") rtt = "FAIL"; else if (val[k, i, 13] == "-" && rtt != "FAIL") rtt = "-"
            if (val[k, i, 14] == "FAIL") loss = "FAIL"; else if (val[k, i, 14] == "-" && loss != "FAIL") loss = "-"
          }
          m = med(k, 6)
          if (m == "-") { cell = "нет скорости"; mb = "-"; spread = "-" }
          else {
            cell = sprintf("%.2f (%.2f-%.2f)", m, mn, mx)
            mb = sprintf("%.0f", m * 8.388608)
            sp = (m > 0) ? (mx - mn) / m : 0
            spread = sprintf("%.0f %%", sp * 100)
            if (sp > 0.2) flags = flags "нестабильно (>20 %); "
          }
          if (fin < cnt[k]) flags = flags "не завершено " (cnt[k] - fin) " из " cnt[k] "; "
          if (busy) flags = flags "занятый хост (load1>1.5); "
          if (bad) flags = flags "cmp не равен; "
          if (rate == "FAIL" || rtt == "FAIL" || loss == "FAIL") flags = flags "control failed; "
          if (kp[2] == "R2-W1") flags = flags "окно 1 МиБ: ограничено окном по построению; "
          cs = med(k, 7); cr = med(k, 8); co = med(k, 9)
          if (cs != "-") cs = sprintf("%.0f", cs)
          if (cr != "-") cr = sprintf("%.0f", cr)
          if (co != "-") co = sprintf("%.1f", co)
          printf "| %s | %s | %s | %s | %s | %s | %s | %s | %s/%s/%s | %s |\n", kp[1], kp[2], cell, mb, spread, cs, cr, co, rate, rtt, loss, (flags == "" ? "-" : flags)
        }
      }' "$LD/speed16.tsv"
  fi
  echo "| IPV6 | - | NOTRUN | - | - | - | - | - | - | приём IPv6 отложен владельцем |"
  echo
  echo "Окно: в полёте не больше min(окно соединения 16 МиБ, потоки x окно x блок = 8 МиБ по умолчанию); только R2-W1 (1 МиБ) ограничен окном по построению. Скорость = байты / время получателя от начала приёма до конца проверки файла; CPU = тики процесса из /proc/self/stat; «Занято ядер» = вся машина по /proc/stat за повтор. Контроли: rate (скорость не выше 1,05 x полосы), rtt (ping в пределах 25 % и 1 мс от задержки порта), loss (доля отброшенных пакетов в [0,5P; 2P]); «-» не измерялось. Числа справочные: это эмуляция, а не реальные сети."
}

sec_g7() {
  local id r
  echo
  echo "## 7. Смена адреса и обрывы при задержке (G7, профиль D20: RTT 20 мс, 100 Мбит/с)"
  echo
  echo "| ID | Вердикт | Ожидали | Получили | Время, с | Подробности |"
  echo "|---|---|---|---|---|---|"
  for id in G7-BASE G7-CALLEE G7-LAPTOP G7-DROP15 C20; do
    r="$(srow "$id")"
    if [[ -z "$r" ]]; then echo "| $id | не запускалась | - | - | - | - |"; continue; fi
    echo "| $id | $(cell "$(sf "$id" 3)") | $(cell "$(sf "$id" 4)") | $(cell "$(sf "$id" 5)") | $(cell "$(sf "$id" 11)") | $(cell "$(sf "$id" 12)") |"
  done
  echo
  echo "connections: 1 означает миграцию соединения, 2 и больше — переподключение; max_stall_s — наибольший простой между растущими строками progress."
}

sec_extra() {
  local id r
  echo
  echo "## 8. Дополнительные строки (X01, X02)"
  echo
  echo "| ID | Вердикт | Итог | Примечание |"
  echo "|---|---|---|---|"
  for id in X01 X02; do
    r="$(srow "$id")"
    if [[ -z "$r" ]]; then echo "| $id | не запускалась | - | - |"; continue; fi
    echo "| $id | $(cell "$(sf "$id" 3)") | $(cell "$(sf "$id" 5)") | $(cell "$(sf "$id" 12)") |"
  done
}

sec_hostsafe() {
  echo
  echo "## 9. HOSTSAFE (хост умного дома не менялся)"
  echo
  local r; r="$(srow HOSTSAFE)"
  if [[ -z "$r" ]]; then echo "Данных нет."
  else echo "Итог: $(sf HOSTSAFE 3). $(sf HOSTSAFE 5). $(sf HOSTSAFE 12)."
  fi
  if [[ -s "$LD/hostsafe16.tsv" ]]; then
    echo
    echo "| Дата | Команда | Итог | Что отличалось |"
    echo "|---|---|---|---|"
    awk -F'\t' '{ printf "| %s | %s | %s | %s |\n", $1, $2, $3, $4 }' "$LD/hostsafe16.tsv"
  fi
}

sec_notverified() {
  echo
  echo "## 10. Не проверено"
  echo
  echo "Не проверено: реальные операторы, ТСПУ."
  echo
  echo "Также не проверено в этом прогоне: IPv6 (приём отложен), mDNS (13в), посредник rendezvous (13б), реальные домашние роутеры и их таймауты UDP и выбор портов, мобильные CGNAT с блоками портов, hairpin, NAT-PMP и PCP, стеки сети Windows и macOS, жёсткие диски."
}

sec_summary() {
  local total ok mm fl inc nr ids
  total=0; ok=0; mm=0; fl=0; inc=0; nr=0; ids=""
  if [[ -s "$LD/summary16.tsv" ]]; then
    total="$(awk -F'\t' '$1 != "HOSTSAFE" && $1 != "NATCHECK"' "$LD/summary16.tsv" | wc -l)"
    ok="$(awk -F'\t' '$1 != "HOSTSAFE" && $1 != "NATCHECK" && $3 == "PASS"' "$LD/summary16.tsv" | wc -l)"
    mm="$(awk -F'\t' '$3 == "MISMATCH"' "$LD/summary16.tsv" | wc -l)"
    fl="$(awk -F'\t' '$3 == "FAIL"' "$LD/summary16.tsv" | wc -l)"
    inc="$(awk -F'\t' '$3 == "INCONCLUSIVE"' "$LD/summary16.tsv" | wc -l)"
    nr="$(awk -F'\t' '$3 == "NOTRUN"' "$LD/summary16.tsv" | wc -l)"
    ids="$(awk -F'\t' '$3 == "FAIL" || $3 == "MISMATCH" { printf "%s ", $1 }' "$LD/summary16.tsv")"
  fi
  echo
  echo "## 11. Резюме для владельца (заготовка с числами; выводы допишет архитектор)"
  echo
  echo "- Строк в данных: $total; PASS: $ok; MISMATCH: $mm; FAIL: $fl; INCONCLUSIVE: $inc; NOTRUN: $nr."
  echo "- Строки FAIL и MISMATCH (каждой нужна строка разбора: дефект продукта или дефект стенда): ${ids:-нет}."
  echo "- Целостность (cmp, sha256) и охрана хоста (счётчики other, other_in): см. разделы 6, 7 и столбец Вердикт; любой FAIL там эскалируется."
  echo "- Выводы архитектора: (пишутся после разбора)."
}

render() {
  sec_header; sec_natcheck; sec_matrix; sec_notconnected; sec_via; sec_speed; sec_g7; sec_extra; sec_hostsafe
  sec_notverified; sec_summary
}

# ---------------------------------------------------------------- санитайзер
# Замена адресов стенда ролями; затем проверка, что адресов не осталось.
sanitize() {
  local c="${CORE//./\\.}" e=()
  e+=(-e "s/\\b${c}\\.254\\b/INET/g" -e "s/\\b${c}\\.100\\b/REFL/g" -e "s/\\b${c}\\.101\\b/REFL-2/g"
      -e "s/\\b${c}\\.50\\b/WA/g" -e "s/\\b${c}\\.51\\b/WB/g" -e "s/\\b${c}\\.52\\b/WB/g"
      -e "s/\\b${c}\\.10\\b/NAT-A/g" -e "s/\\b${c}\\.11\\b/NAT-A/g" -e "s/\\b${c}\\.12\\b/NAT-A2/g"
      -e "s/\\b${c}\\.20\\b/NAT-R/g" -e "s/\\b${c}\\.30\\b/NAT-B/g"
      -e "s/\\b${c}\\.40\\b/CGN-1/g" -e "s/\\b${c}\\.41\\b/CGN-2/g" -e "s/\\b${c}\\.66\\b/LIAR/g"
      -e 's/\b192\.168\.10\.2\b/HA/g' -e 's/\b192\.168\.10\.3\b/HA2/g' -e 's/\b192\.168\.12\.2\b/HA/g'
      -e 's/\b192\.168\.30\.2\b/HB/g' -e 's/\b192\.168\.20\.2\b/HR/g' -e 's/\b192\.168\.40\.2\b/HD/g'
      -e 's/\b100\.64\.0\.2\b/HC/g' -e 's/\b100\.64\.0\.3\b/NAT-D/g' -e 's/\b100\.64\.0\.1\b/CGN-1/g'
      -e 's/\b10\.99\.0\.1\b/MEET-X/g' -e 's/\b10\.99\.0\.2\b/MEET-Y/g'
      -e 's/\b192\.168\.10\.1\b/NAT-A/g' -e 's/\b192\.168\.30\.1\b/NAT-B/g' -e 's/\b192\.168\.20\.1\b/NAT-R/g'
      -e 's/\b192\.168\.12\.1\b/NAT-A2/g' -e 's/\b192\.168\.40\.1\b/NAT-D/g')
  sed -E "${e[@]}"
}

# 0 — чисто; иначе причина на stdout, код 1.
check_clean() { # файл
  local f="$1" h u
  if grep -Eq '([0-9]{1,3}\.){3}[0-9]{1,3}' "$f"; then echo "IPv4-адрес"; return 1; fi
  if grep -Eq '(^|[^0-9A-Za-z:])(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|([0-9A-Fa-f]{1,4}:){1,6}:([0-9A-Fa-f]{1,4})?|::[0-9A-Fa-f]{1,4})([^0-9A-Za-z:]|$)' "$f"; then
    echo "IPv6-адрес"; return 1
  fi
  if grep -Fq -e '/home/' -e '/tmp/chervo' -e '/root/' "$f"; then echo "путь домашнего каталога или /tmp/chervo"; return 1; fi
  h="$(hostname 2>/dev/null || true)"
  if [[ ${#h} -ge 3 ]] && tr "[:upper:]" "[:lower:]" < "$f" | grep -Fwq -- "${h,,}"; then echo "имя хоста"; return 1; fi
  u="${SUDO_USER:-}"
  if [[ -n "$u" && "$u" != root && ${#u} -ge 3 ]] && tr "[:upper:]" "[:lower:]" < "$f" | grep -Fwq -- "${u,,}"; then echo "имя пользователя"; return 1; fi
  return 0
}

generate() { # LOGDIR OUT -> код 0, 4 (отказ)
  local out="$2" tmp why
  LD="$1"
  [[ -d "$LD" ]] || { echo "report16: нет каталога $LD" >&2; return 2; }
  tmp="$(mktemp "${TMPDIR:-/tmp}/report16.XXXXXX")" || return 2
  render | sanitize > "$tmp"
  if ! why="$(check_clean "$tmp")"; then
    rm -f -- "$tmp"
    echo "report16: отказ записи отчёта: в тексте осталось: $why" >&2
    return 4
  fi
  mkdir -p -- "$(dirname -- "$out")"
  mv -- "$tmp" "$out"
  return 0
}

# ---------------------------------------------------------------- самопроверка
selftest() {
  local fx="$ROOT/fixtures16/ok" t out rc fails=0 h
  [[ -d "$fx" ]] || { echo "SELFTEST FAIL: нет $fx" >&2; return 1; }
  t="$(mktemp -d "${TMPDIR:-/tmp}/report16-test.XXXXXX")"
  out="$t/out.md"
  # положительный контроль
  generate "$fx" "$out"; rc=$?
  if [[ $rc != 0 || ! -s "$out" ]]; then echo "SELFTEST FAIL: положительный контроль, код $rc"; fails=$((fails + 1)); fi
  grep -Fxq 'Не проверено: реальные операторы, ТСПУ.' "$out" || { echo "SELFTEST FAIL: нет строки «Не проверено: реальные операторы, ТСПУ.»"; fails=$((fails + 1)); }
  grep -Fq 'Эмуляция netns, не реальные операторы и не ТСПУ' "$out" || { echo "SELFTEST FAIL: нет строки про эмуляцию"; fails=$((fails + 1)); }
  [[ "$(grep -c '^## ' "$out")" == 11 ]] || { echo "SELFTEST FAIL: разделов не 11"; fails=$((fails + 1)); }
  grep -Fq 'Какие пары не соединились и почему' "$out" || { echo "SELFTEST FAIL: нет раздела 4"; fails=$((fails + 1)); }
  grep -Fq 'под nice 10' "$out" || { echo "SELFTEST FAIL: нет пометки «под nice»"; fails=$((fails + 1)); }
  grep -Fq 'NOTRUN' "$out" || { echo "SELFTEST FAIL: нет строк NOTRUN"; fails=$((fails + 1)); }
  # замена адреса ролью: в фикстуре есть сырой адрес WA в примечании
  grep -Fq 'путь через WA' "$out" || { echo "SELFTEST FAIL: адрес не заменён ролью"; fails=$((fails + 1)); }
  # отрицательные контроли: файл не пишется, код 4
  neg() { # имя текст
    local d="$t/neg-$1"
    rm -rf -- "$d"; cp -r -- "$fx" "$d"
    printf '2026-10-18\t%s\tPASS\t-\n' "$2" >> "$d/hostsafe16.tsv"
    rm -f -- "$t/neg.md"
    generate "$d" "$t/neg.md" 2>/dev/null; rc=$?
    if [[ $rc != 4 || -e "$t/neg.md" ]]; then echo "SELFTEST FAIL: отрицательный контроль «$1»: код $rc, файл $([[ -e $t/neg.md ]] && echo есть || echo нет)"; fails=$((fails + 1)); fi
  }
  neg ipv4 "адрес 203.0.113.9 в тексте"
  neg ipv6 "адрес 2001:db8::7 в тексте"
  neg home "каталог /home/user/x"
  neg tmp "каталог /tmp/chervo-stage16.abc"
  h="$(hostname 2>/dev/null || true)"
  if [[ ${#h} -ge 3 ]]; then neg host "узел $h в тексте"; else echo "SELFTEST: имя хоста короче 3 символов, контроль имени хоста пропущен"; fi
  rm -rf -- "$t"
  if (( fails == 0 )); then echo "SELFTEST OK"; return 0; fi
  echo "SELFTEST FAIL: $fails"
  return 1
}

case "${1:-}" in
  --self-test) selftest; exit $? ;;
  ""|-h|--help) echo "использование: report16.sh LOGDIR OUT.md | --self-test" >&2; exit 2 ;;
  *)
    [[ $# -ge 2 ]] || { echo "использование: report16.sh LOGDIR OUT.md | --self-test" >&2; exit 2; }
    generate "$1" "$2"; exit $? ;;
esac
