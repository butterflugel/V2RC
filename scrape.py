import base64
import hashlib
import json
import random
import re
import time
import urllib.parse
from pathlib import Path

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

CONFIG_REGEX = re.compile(
    r"(vmess://[^\s<>\[\]\"']+|"
    r"vless://[^\s<>\[\]\"']+|"
    r"trojan://[^\s<>\[\]\"']+|"
    r"ss://[^\s<>\[\]\"']+|"
    r"hysteria2://[^\s<>\[\]\"']+|"
    r"hysteria://[^\s<>\[\]\"']+|"
    r"socks://[^\s<>\[\]\"']+)"
)

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

CHANNELS_FILE = Path("channels.json")

MAX_CONFIGS_PER_CHANNEL = 300
MAX_PAGES_PER_CHANNEL = 15
REQUEST_TIMEOUT = 15

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
]

TRAILING_CHARS = ".,);]'\"}>"

session = requests.Session()

retry = Retry(
    total=3,
    backoff_factor=1,
    status_forcelist=(429, 500, 502, 503, 504),
    allowed_methods=("GET",),
)

adapter = HTTPAdapter(max_retries=retry)

session.mount("http://", adapter)
session.mount("https://", adapter)


def fix_b64(value: str) -> str:
    return value + "=" * (-len(value) % 4)


def random_headers() -> dict:
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "*/*",
    }


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def clean_link(link: str) -> str:
    return link.strip().rstrip(TRAILING_CHARS)


def stable_json(data: dict) -> str:
    return json.dumps(data, separators=(",", ":"), sort_keys=True)


def parse_vmess(link: str) -> dict | None:
    try:
        payload = link.split("://", 1)[1]
        decoded = base64.urlsafe_b64decode(fix_b64(payload)).decode("utf-8")
        return json.loads(decoded)
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def canonical_query(query: str) -> str:
    parsed = urllib.parse.parse_qsl(query, keep_blank_values=True)
    parsed.sort()
    return urllib.parse.urlencode(parsed)


def get_config_unique_key(link: str) -> str:
    try:
        link = clean_link(link)
        parsed = urllib.parse.urlparse(link)
        scheme = parsed.scheme.lower()

        if scheme == "vmess":
            config = parse_vmess(link)

            if not config:
                return sha256(link)

            identity = stable_json(
                {
                    "scheme": "vmess",
                    "add": config.get("add"),
                    "port": config.get("port"),
                    "id": config.get("id"),
                    "net": config.get("net"),
                    "type": config.get("type"),
                    "path": config.get("path"),
                    "host": config.get("host"),
                    "tls": config.get("tls"),
                    "sni": config.get("sni"),
                    "alpn": config.get("alpn"),
                    "fp": config.get("fp"),
                }
            )

            return sha256(identity)

        if scheme in {
            "vless",
            "trojan",
            "hysteria",
            "hysteria2",
            "socks",
            "ss",
        }:
            identity = stable_json(
                {
                    "scheme": scheme,
                    "host": parsed.hostname,
                    "port": parsed.port,
                    "username": parsed.username,
                    "path": parsed.path,
                    "query": canonical_query(parsed.query),
                }
            )

            return sha256(identity)

        return sha256(link)

    except Exception:
        return sha256(link)


def normalize_config(raw_link: str, channel_name: str) -> str:
    try:
        raw_link = clean_link(raw_link)
        scheme = raw_link.split("://", 1)[0].lower()

        if scheme == "vmess":
            config = parse_vmess(raw_link)

            if not config:
                return raw_link

            config["ps"] = channel_name

            encoded = (
                base64.urlsafe_b64encode(stable_json(config).encode("utf-8"))
                .decode("utf-8")
                .rstrip("=")
            )

            return f"vmess://{encoded}"

        parsed = urllib.parse.urlparse(raw_link)

        normalized = urllib.parse.urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                canonical_query(parsed.query),
                channel_name,
            )
        )

        return normalized

    except Exception:
        return raw_link


def extract_configs(text: str) -> list[str]:
    found = CONFIG_REGEX.findall(text)

    cleaned = []

    for item in found:
        item = clean_link(item)

        if "://" not in item:
            continue

        cleaned.append(item)

    return cleaned


def atomic_write(path: Path, content: str) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def load_existing_configs(path: Path) -> tuple[list[str], set[str]]:
    if not path.exists():
        return [], set()

    lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    keys = {get_config_unique_key(line) for line in lines}

    return lines, keys


def fetch_page(url: str) -> str | None:
    try:
        response = session.get(
            url,
            headers=random_headers(),
            timeout=REQUEST_TIMEOUT,
        )

        response.raise_for_status()

        return response.text

    except requests.RequestException:
        return None


def scrape_channel(base_url: str, name: str) -> None:
    print(f"\nScraping {name}")

    outfile = DATA_DIR / f"{name}.txt"

    existing_configs, existing_keys = load_existing_configs(outfile)

    new_configs = []
    new_keys = set()

    url = base_url.rstrip("/")

    for page in range(1, MAX_PAGES_PER_CHANNEL + 1):
        print(f"  Page {page}")

        time.sleep(random.uniform(1.5, 3.5))

        html = fetch_page(url)

        if not html:
            break

        soup = BeautifulSoup(html, "html.parser")

        messages = soup.select("[data-post]")

        if not messages:
            break

        oldest_id = None

        for message in messages:
            text_node = message.select_one(".tgme_widget_message_text")

            if not text_node:
                continue

            text = text_node.get_text(" ", strip=True)

            for raw in extract_configs(text):
                normalized = normalize_config(raw, name)

                key = get_config_unique_key(normalized)

                if key in existing_keys or key in new_keys:
                    continue

                new_keys.add(key)
                new_configs.append(normalized)

            post = message.get("data-post")

            if not post or "/" not in post:
                continue

            try:
                message_id = int(post.rsplit("/", 1)[1])

                if oldest_id is None or message_id < oldest_id:
                    oldest_id = message_id

            except ValueError:
                continue

        if oldest_id is None:
            break

        url = f"{base_url}?before={oldest_id}"

    combined = []

    seen = set()

    for config in new_configs + existing_configs:
        key = get_config_unique_key(config)

        if key in seen:
            continue

        seen.add(key)
        combined.append(config)

        if len(combined) >= MAX_CONFIGS_PER_CHANNEL:
            break

    atomic_write(outfile, "\n".join(combined) + "\n")

    print(f"Saved {len(combined)} configs -> {outfile}")


def main() -> None:
    if not CHANNELS_FILE.exists():
        print("channels.json not found")
        return

    try:
        channels = json.loads(CHANNELS_FILE.read_text(encoding="utf-8"))

    except json.JSONDecodeError:
        print("Invalid channels.json")
        return

    if not isinstance(channels, dict):
        print("channels.json must contain an object")
        return

    for name, url in channels.items():
        if not isinstance(name, str) or not isinstance(url, str):
            continue

        if not url.startswith("https://t.me/s/"):
            continue

        scrape_channel(url, name)


if __name__ == "__main__":
    main()
