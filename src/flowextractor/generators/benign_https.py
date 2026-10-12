import requests
import random
import argparse
import time
import termcolor
from concurrent.futures import ThreadPoolExecutor

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]

PATHS = ["/", "/index.html", "/about", "/contact", "/favicon.ico", "/robots.txt"]


class BenignHTTPSGenerator:
    def __init__(self, target: str, paths: list[str], min_delay: float, max_delay: float):
        self.target = target.rstrip("/")
        self.paths = paths
        self.min_delay = min_delay
        self.max_delay = max_delay

    def _single_request(self, index: int):
        path = random.choice(self.paths)
        url = f"{self.target}{path}"
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        # jede Verbindung eine eigene Session -> eigener TLS-Handshake / Flow
        try:
            with requests.Session() as session:
                response = session.get(url, headers=headers, timeout=10)
                print(f"[{index}] {url} -> {response.status_code} ({len(response.content)} bytes)")
        except Exception as e:
            print(f"[{index}] Error requesting {url}: {e}")
        if self.max_delay > 0:
            time.sleep(random.uniform(self.min_delay, self.max_delay))

    def generate(self, requests_count: int, concurrency: int):
        print(termcolor.colored(
            f"Generating {requests_count} benign HTTPS requests to {self.target} "
            f"with concurrency {concurrency}...", "green"))
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            list(executor.map(self._single_request, range(requests_count)))


def main():
    argparser = argparse.ArgumentParser(description="Generate benign HTTPS traffic against a single server.")
    argparser.add_argument("--target", type=str, default="https://sten-heimbrodt.de", help="Target HTTPS server (base URL).")
    argparser.add_argument("--paths", type=str, nargs="+", default=PATHS, help="Paths to request on the target.")
    argparser.add_argument("--requests", type=int, default=20, help="Number of requests per burst.")
    argparser.add_argument("--concurrency", type=int, default=4, help="Number of concurrent requests (threads).")
    argparser.add_argument("--min-delay", type=float, default=0.5, help="Minimum delay (s) after each request per worker.")
    argparser.add_argument("--max-delay", type=float, default=2.0, help="Maximum delay (s) after each request per worker.")
    argparser.add_argument("--interval", type=int, default=60, help="Interval in seconds between bursts.")
    argparser.add_argument("--once", action="store_true", help="Run a single burst and exit instead of looping.")
    args = argparser.parse_args()

    generator = BenignHTTPSGenerator(args.target, args.paths, args.min_delay, args.max_delay)
    while True:
        generator.generate(args.requests, args.concurrency)
        if args.once:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
