#!/usr/bin/env python3
"""Помощник стенда 13в (stage13v.sh): разбор pcap и отправка пакетов с узла-наблюдателя.

НЕ ЗАПУСКАЛСЯ СБОРЩИКОМ НА LINUX (написан на Windows, проверен только `python -m py_compile`).
Только стандартная библиотека. Работает внутри ns стенда (stage13v.sh вызывает через `ip netns exec`).

Команды:
  tsv PCAP                       строки `время src dst proto sport dport длина_данных`
  count PCAP ФИЛЬТР...           число UDP-пакетов, подошедших под все `поле=значение`
                                 (поля: src dst sport dport len); печатает число
  lan3 PCAP KEYS A_IP PORT HOST  проверки LAN3 над маяками узла A (см. ниже); печатает OK или FAIL-строки
  first-time PCAP SRC            время первого маяка с адреса SRC (или `-`)
  flood OWN N                    N случайных датаграмм по 430 байт в 224.0.0.1:45817 со своего адреса
  replay PCAP OWN                повтор записанных маяков со своего адреса
  spoof PCAP SPOOF_IP OWN        повтор записанных маяков с подставленным адресом источника (raw)
"""
import os
import socket
import struct
import sys

LAN_GROUP = "224.0.0.1"
LAN_PORT = 45817
DGRAM = 430
SLOT = 26
SLOTS_AT = 14


def read_pcap(path):
    data = open(path, "rb").read()
    if len(data) < 24:
        return
    magic = struct.unpack("<I", data[:4])[0]
    if magic in (0xA1B2C3D4, 0xA1B23C4D):
        e = "<"
    else:
        e = ">"
    nano = magic in (0xA1B23C4D, 0x4D3CB2A1)
    network = struct.unpack(e + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        ts_s, ts_f, incl, _orig = struct.unpack(e + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        ip = None
        if network == 1 and pkt[12:14] == b"\x08\x00":
            ip = pkt[14:]
        elif network == 113 and pkt[14:16] == b"\x08\x00":
            ip = pkt[16:]
        elif network == 276 and pkt[0:2] == b"\x08\x00":
            ip = pkt[20:]
        elif network in (101, 228):
            ip = pkt
        if ip is None or len(ip) < 20 or ip[0] >> 4 != 4:
            continue
        ihl = (ip[0] & 15) * 4
        proto = ip[9]
        src = socket.inet_ntoa(ip[12:16])
        dst = socket.inet_ntoa(ip[16:20])
        sport = dport = 0
        payload = b""
        if proto == 17 and len(ip) >= ihl + 8:
            sport, dport, ulen = struct.unpack("!HHH", ip[ihl:ihl + 6])
            payload = ip[ihl + 8:ihl + ulen]
        ts = ts_s + ts_f / (1e9 if nano else 1e6)
        yield ts, src, dst, proto, sport, dport, payload


def beacons(path, src=None):
    for ts, s, d, proto, sp, dp, pl in read_pcap(path):
        if proto == 17 and d == LAN_GROUP and dp == LAN_PORT and (src is None or s == src):
            yield ts, s, pl


def cmd_tsv(path):
    for ts, s, d, proto, sp, dp, pl in read_pcap(path):
        print(f"{ts:.3f} {s} {d} {proto} {sp} {dp} {len(pl)}")


def cmd_count(path, filters):
    want = {}
    for f in filters:
        k, _, v = f.partition("=")
        want[k] = v
    n = 0
    for ts, s, d, proto, sp, dp, pl in read_pcap(path):
        if proto != 17:
            continue
        have = {"src": s, "dst": d, "sport": str(sp), "dport": str(dp), "len": str(len(pl))}
        if all(have.get(k) == v for k, v in want.items()):
            n += 1
    print(n)


def cmd_first_time(path, src):
    for ts, _s, _pl in beacons(path, src):
        print(f"{ts:.3f}")
        return
    print("-")


def cmd_lan3(path, keys_file, a_ip, port, host, n_friends):
    bad = []
    items = list(beacons(path, a_ip))
    if not items:
        print("FAIL: ни одного маяка от A")
        return
    payloads = [pl for _ts, _s, pl in items]
    # 1. длина
    short = [len(p) for p in payloads if len(p) != DGRAM]
    if short:
        bad.append(f"длина не 430: {sorted(set(short))}")
    # 2. открытые ключи пар
    keys = []
    try:
        for line in open(keys_file):
            line = line.strip()
            if len(line) == 64:
                keys.append(bytes.fromhex(line))
    except OSError:
        bad.append("нет файла открытых ключей (--dump-pubkeys)")
    if not keys:
        bad.append("в файле открытых ключей нет ключей: проверка пуста")
    for k in keys:
        if any(k in p for p in payloads):
            bad.append("открытый ключ пары найден в маяке")
            break
    # 3. свой адрес (4 байта) и имя компьютера
    if any(socket.inet_aton(a_ip) in p for p in payloads):
        bad.append("свой адрес в открытом виде")
    hb = host.encode()
    if len(hb) >= 4 and any(hb in p for p in payloads):
        bad.append("имя компьютера в маяке")
    # 4. порт прослушивания не на постоянном смещении
    pb = struct.pack("!H", int(port))
    if len(payloads) >= 10:
        for off in range(0, DGRAM - 1):
            if all(p[off:off + 2] == pb for p in payloads):
                bad.append(f"порт лежит на постоянном смещении {off}")
                break
    # 5. метки (первые 8 байт слота) не повторяются через окна: окно 30 с, допуск на границу
    seen = {}
    for ts, _s, p in items:
        w = int(ts // 30)
        for i in range(16):
            at = SLOTS_AT + i * SLOT
            seen.setdefault(p[at:at + 8], set()).add(w)
    for head, ws in seen.items():
        if max(ws) - min(ws) >= 2:
            bad.append("метка слота повторилась через окна")
            break
    # 5а. метки всех 16 слотов (настоящих и пустых) постоянны внутри окна: по двум датаграммам серии
    # число друзей не определить. Датаграммы раунда нумеруются по порядку; в одном окне набор меток
    # j-й датаграммы раунда один и тот же во всех раундах. Раунд, пересёкший границу окна, пропускается.
    rounds_dg = []
    cur_dg = []
    last_ts = None
    for ts, _s, p in items:
        if last_ts is not None and ts - last_ts > 1.0:
            rounds_dg.append(cur_dg)
            cur_dg = []
        cur_dg.append((ts, p))
        last_ts = ts
    rounds_dg.append(cur_dg)
    label_sets = {}
    for rd in rounds_dg:
        if not rd or int(rd[0][0] // 30) != int(rd[-1][0] // 30):
            continue
        w = int(rd[0][0] // 30)
        for j, (_ts, p) in enumerate(rd):
            heads = tuple(sorted(p[SLOTS_AT + i * SLOT:SLOTS_AT + i * SLOT + 8] for i in range(16)))
            label_sets.setdefault((w, j), set()).add(heads)
    unstable = [k for k, v in label_sets.items() if len(v) > 1]
    if unstable:
        bad.append(f"метки слотов меняются внутри окна (окно, номер датаграммы): {unstable[:3]}")
    if not any(len(v) >= 1 for v in label_sets.values()):
        bad.append("нет ни одного целого раунда внутри окна: стабильность меток не проверена")
    # 6. датаграмм в раунде: раунд это серия с промежутками меньше секунды
    want = (n_friends + 15) // 16
    rounds = []
    cur = 0
    last = None
    for ts, _s, _p in items:
        if last is not None and ts - last > 1.0:
            rounds.append(cur)
            cur = 0
        cur += 1
        last = ts
    rounds.append(cur)
    if any(r != want for r in rounds):
        bad.append(f"датаграмм в раунде {sorted(set(rounds))}, ожидалось {want}")
    if bad:
        for b in bad:
            print("FAIL: " + b)
    else:
        print(f"OK datagrams={len(items)} rounds={len(rounds)} per_round={want}")


def mcast_socket(own):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(own))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 0)
    s.bind((own, 0))
    return s


def cmd_flood(own, n):
    s = mcast_socket(own)
    for _ in range(int(n)):
        s.sendto(b"\x01\x00" + os.urandom(DGRAM - 2), (LAN_GROUP, LAN_PORT))
    print(f"sent {n}")


def cmd_replay(path, own):
    s = mcast_socket(own)
    n = 0
    for _ts, _src, pl in beacons(path):
        s.sendto(pl, (LAN_GROUP, LAN_PORT))
        n += 1
    print(f"sent {n}")


def checksum(b):
    if len(b) % 2:
        b += b"\x00"
    t = sum(struct.unpack("!%dH" % (len(b) // 2), b))
    t = (t >> 16) + (t & 0xFFFF)
    t += t >> 16
    return (~t) & 0xFFFF


def cmd_spoof(path, spoof_ip, own):
    raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    raw.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(own))
    n = 0
    for _ts, _src, pl in beacons(path):
        udp = struct.pack("!HHHH", 40000, LAN_PORT, 8 + len(pl), 0) + pl
        total = 20 + len(udp)
        hdr = struct.pack(
            "!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 1, 17, 0,
            socket.inet_aton(spoof_ip), socket.inet_aton(LAN_GROUP),
        )
        hdr = hdr[:10] + struct.pack("!H", checksum(hdr)) + hdr[12:]
        raw.sendto(hdr + udp, (LAN_GROUP, 0))
        n += 1
    print(f"sent {n}")


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    c, a = argv[1], argv[2:]
    if c == "tsv":
        cmd_tsv(a[0])
    elif c == "count":
        cmd_count(a[0], a[1:])
    elif c == "first-time":
        cmd_first_time(a[0], a[1])
    elif c == "lan3":
        cmd_lan3(a[0], a[1], a[2], a[3], a[4], int(a[5]))
    elif c == "flood":
        cmd_flood(a[0], a[1])
    elif c == "replay":
        cmd_replay(a[0], a[1])
    elif c == "spoof":
        cmd_spoof(a[0], a[1], a[2])
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
