#!/usr/bin/env python3
"""Помощник стенда 13г (stage13g.sh): разбор pcap (IPv6, UDP) и отправка датаграмм с узла-постороннего.

НЕ ЗАПУСКАЛСЯ СБОРЩИКОМ НА LINUX (написан на Windows, проверен `python -m py_compile` и на синтетическом pcap).
Только стандартная библиотека. Запускается внутри ns стенда (`ip netns exec`, `python3 -I`). Адреса в вывод не пишутся.

Команды:
  payloads PCAP PORT                       число непустых UDP-датаграмм IPv6 на порт PORT в записи
  flood6 TARGET PORT SRC N [IF]            N случайных датаграмм (длина 1..1200) и три QUIC-подобных Initial
                                           с адреса SRC на [TARGET]:PORT; затем 3 с приёма
  replay6 PCAP TARGET PORT IF SRC...       каждую записанную на порт PORT датаграмму (до 64 разных, по 3 раза)
                                           с каждого из адресов SRC; затем 3 с приёма
IF: имя интерфейса (для fe80::/10 нужен индекс интерфейса). Вывод: `sent=<n> replies=<r> icmp_err=<e>`.
Ответ = принятая датаграмма; icmp_err = ошибка сокета (ECONNREFUSED и подобные: пришёл ICMPv6 «недоступен»).
"""
import os
import socket
import struct
import sys
import time

KNOCK_MAX = 64
LISTEN_S = 3.0


def read_pcap(path):
    data = open(path, "rb").read()
    if len(data) < 24:
        return
    magic = struct.unpack("<I", data[:4])[0]
    e = "<" if magic in (0xA1B2C3D4, 0xA1B23C4D) else ">"
    network = struct.unpack(e + "I", data[20:24])[0]
    off = 24
    while off + 16 <= len(data):
        _s, _f, incl, _orig = struct.unpack(e + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl]
        off += incl
        ip = None
        if network == 1 and pkt[12:14] == b"\x86\xdd":
            ip = pkt[14:]
        elif network == 113 and pkt[14:16] == b"\x86\xdd":
            ip = pkt[16:]
        elif network == 276 and pkt[0:2] == b"\x86\xdd":
            ip = pkt[20:]
        elif network in (101, 229):
            ip = pkt
        if ip is None or len(ip) < 48 or ip[0] >> 4 != 6 or ip[6] != 17:
            continue
        sport, dport, ulen = struct.unpack("!HHH", ip[40:46])
        yield dport, ip[48:40 + ulen]


def recorded(path, port):
    seen = []
    for dport, payload in read_pcap(path):
        if dport == port and payload and payload not in seen:
            seen.append(payload)
            if len(seen) >= KNOCK_MAX:
                break
    return seen


def make_socket(target, port, src, ifname):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    scope = 0
    if src.lower().startswith("fe80") and ifname:
        scope = socket.if_nametoindex(ifname)
    s.bind((src, 0, 0, scope))
    s.connect((target, port, 0, scope))
    return s


def listen(s):
    replies = errs = 0
    s.settimeout(0.2)
    end = time.time() + LISTEN_S
    while time.time() < end:
        try:
            s.recv(65535)
            replies += 1
        except socket.timeout:
            continue
        except OSError:
            errs += 1
    return replies, errs


def send(s, data):
    try:
        s.send(data)
        return 1, 0
    except OSError:
        return 0, 1


def initial(rng_bytes):
    # QUIC-подобный Initial: длинный заголовок, версия 1, DCID 8 байт, остальное случайное, всего 1200 байт
    head = b"\xc3\x00\x00\x00\x01\x08" + rng_bytes(8) + b"\x00"
    return head + rng_bytes(1200 - len(head))


def cmd_payloads(path, port):
    print(len(recorded(path, int(port))))


def cmd_flood6(target, port, src, n, ifname=""):
    s = make_socket(target, int(port), src, ifname)
    sent = errs = 0
    for _ in range(int(n)):
        ln = 1 + int.from_bytes(os.urandom(2), "big") % 1200
        a, b = send(s, os.urandom(ln))
        sent += a
        errs += b
    for _ in range(3):
        a, b = send(s, initial(os.urandom))
        sent += a
        errs += b
    r, e = listen(s)
    print(f"sent={sent} replies={r} icmp_err={errs + e}")


def cmd_replay6(path, target, port, ifname, srcs):
    pays = recorded(path, int(port))
    sent = replies = errs = 0
    for src in srcs:
        s = make_socket(target, int(port), src, ifname)
        for p in pays:
            for _ in range(3):
                a, b = send(s, p)
                sent += a
                errs += b
        r, e = listen(s)
        replies += r
        errs += e
        s.close()
    print(f"sent={sent} replies={replies} icmp_err={errs}")


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    c = argv[1]
    if c == "payloads" and len(argv) == 4:
        cmd_payloads(argv[2], argv[3])
    elif c == "flood6" and len(argv) in (6, 7):
        cmd_flood6(*argv[2:])
    elif c == "replay6" and len(argv) >= 7:
        cmd_replay6(argv[2], argv[3], argv[4], argv[5], argv[6:])
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
