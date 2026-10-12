import requests
import random
import argparse
import time
import termcolor

BENIGN_URLS = [
    "https://www.wikipedia.org",
    "https://www.python.org",
    "https://www.github.com",
    "https://www.debian.org",
    "https://www.kernel.org",
    "https://www.gnu.org",
    "https://news.ycombinator.com",
    "https://www.mozilla.org",
    "https://www.cloudflare.com",
    "https://example.com",
]

USER_AGENTS = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]


class BenignHTTPSGenerator:
    def __init__(self):
        self.session = requests.Session()

    def generate_benign_https_traffic(self, targets: list[str]):
        url = random.choice(targets)
        number_of_requests = random.randint(1, 10)
        print(termcolor.colored(f"Generating {number_of_requests} benign HTTPS requests to {url}...", "green"))
        for i in range(number_of_requests):
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            try:
                print(termcolor.colored(f"Requesting {url}...", "green"))
                response = self.session.get(url, headers=headers, timeout=10)
                print(f"Response from {url}: {response.status_code} ({len(response.content)} bytes)")
            except Exception as e:
                print(f"Error requesting {url}: {e}")
            time.sleep(random.randint(1, 5))


def main():
    argparser = argparse.ArgumentParser(description="Generate benign HTTPS traffic.")
    argparser.add_argument("--targets", type=str, nargs="+", default=BENIGN_URLS, help="Target HTTPS URLs to request.")
    argparser.add_argument("--interval", type=int, default=60, help="Interval in seconds between generating traffic.")
    args = argparser.parse_args()
    generator = BenignHTTPSGenerator()
    while True:
        generator.generate_benign_https_traffic(args.targets)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
