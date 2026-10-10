import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class TelegramBot:
    def __init__(self, timeout=(5, 10), retries=3):
        with open("/home/sten/FlowExtractor/.botkey", "r") as f:
            self.token = f.read().strip()
        self.base_url = f"https://api.telegram.org/bot{self.token}/"
        # (connect, read) timeout in seconds - without it requests may block forever
        self.timeout = timeout
        self.session = requests.Session()
        retry = Retry(
            total=retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["POST"],
            respect_retry_after_header=True,
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))

    def send_message(self, chat_id: int, text: str) -> bool:
        url = self.base_url + "sendMessage"
        payload = {
            "chat_id": chat_id,
            "text": text
        }
        try:
            response = self.session.post(url, json=payload, timeout=self.timeout)
        except requests.RequestException as e:
            print(f"[TelegramBot] Failed to send message: {e}")
            return False
        if response.status_code != 200:
            print(f"[TelegramBot] Failed to send message: {response.text}")
            return False
        return True
