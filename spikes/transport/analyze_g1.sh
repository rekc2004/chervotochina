#!/usr/bin/env bash
# G1: разбор захвата `tcpdump -i any` одного ns. Печатает кортежи исходящих пакетов (dst proto port),
# которых нет в разрешённом списке, и строку `VIOLATIONS <n>`.
# Использование: analyze_g1.sh <pcap> <peers,через,запятую> <шлюз> <allow_portmap 0|1>
set -euo pipefail
pcap="${1:?pcap}"; peers="${2:?peers}"; gw="${3:?gateway}"; pm="${4:?allow_portmap}"
tcpdump -nn -q -r "$pcap" 2>/dev/null | awk -v peers="$peers" -v gw="$gw" -v pm="$pm" '
BEGIN { n = split(peers, p, ","); for (i = 1; i <= n; i++) P[p[i]] = 1 }
$3 == "Out" && ($4 == "IP" || $4 == "IP6") {
  dst = $7; sub(/:$/, "", dst); proto = $8; sub(/,$/, "", proto)
  ip = dst; port = "-"
  if (proto == "UDP" || proto == "TCP" || proto == "tcp") {
    k = match(dst, /\.[0-9]+$/)
    if (k) { port = substr(dst, k + 1); ip = substr(dst, 1, k - 1) }
  }
  ok = 0
  if (ip in P) ok = 1
  else if (ip ~ /^ff02::1:ff/ || ip == "ff02::2" || ip == "ff02::16" || ip == "ff02::1") ok = 1
  else if (ip == "224.0.0.22") ok = 1
  else if (pm == 1 && ((ip == gw && port == 5351) || (ip == "239.255.255.250" && port == 1900) || \
           ((ip == "ff02::c" || ip == "ff05::c") && port == 1900))) ok = 1
  if (!ok) { c[ip " " proto " " port]++ }
}
END { v = 0; for (k in c) { print "VIOLATION " k " packets=" c[k]; v++ } print "VIOLATIONS " v }'
