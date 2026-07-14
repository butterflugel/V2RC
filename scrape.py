import base64
import hashlib
import json
import os
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
DATA_DIR.mkdir(parents=True, exist_ok=True)

CHANNELS_FILE = Path("channels.json")

MAX_CONFIGS_PER_CHANNEL = 300
MAX_PAGES_PER_CHANNEL = 15
REQUEST_TIMEOUT = 30

PROXY_URL = os.environ.get("PROXY_URL", None)
PROXY_USERNAME = os.environ.get("PROXY_USERNAME", None)
PROXY_PASSWORD = os.environ.get("PROXY_PASSWORD", None)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
]

TRAILING_CHARS = ".,);]'\"}>"

def get_session():
    session = requests.Session()
    
    if PROXY_URL:
        proxies = {
            "http": PROXY_URL,
            "https": PROXY_URL,
        }
        if PROXY_USERNAME and PROXY_PASSWORD:
            proxy_parts = urllib.parse.urlparse(PROXY_URL)
            proxy_url = f"{proxy_parts.scheme}://{PROXY_USERNAME}:{PROXY_PASSWORD}@{proxy_parts.netloc}"
            proxies = {
                "http": proxy_url,
                "https": proxy_url,
            }
        session.proxies.update(proxies)
    
    retry = Retry(
        total=5,
        connect=5,
        read=5,
        backoff_factor=2,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset({"GET"}),
    )
    
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

session = get_session()

def fix_b64(value: str) -> str:
    value = value.strip()
    return value + "=" * (-len(value) % 4)


def random_headers() -> dict:
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
    }


def sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def clean_link(link: str) -> str:
    return link.strip().rstrip(TRAILING_CHARS)


def stable_json(data: dict) -> str:
    return json.dumps(
        data,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def parse_vmess(link: str) -> dict | None:
    try:
        payload = link.split("://", 1)[1]
        decoded = base64.urlsafe_b64decode(
            fix_b64(payload)
        ).decode("utf-8")
        parsed = json.loads(decoded)
        if not isinstance(parsed, dict):
            return None
        return parsed
    except Exception:
        return None


def parse_ss(link: str) -> dict | None:
    try:
        parsed = urllib.parse.urlsplit(link)
        userinfo = parsed.username or ""
        password = parsed.password
        if password is None:
            try:
                decoded = base64.urlsafe_b64decode(
                    fix_b64(userinfo)
                ).decode("utf-8")
                if ":" in decoded:
                    method, pw = decoded.split(":", 1)
                else:
                    return None
            except Exception:
                return None
        else:
            method = userinfo
            pw = password
        return {
            "method": method.lower(),
            "password": pw,
            "hostname": parsed.hostname,
            "port": parsed.port,
            "path": parsed.path,
            "query": canonical_query(parsed.query),
        }
    except Exception:
        return None


def canonical_query(query: str) -> str:
    parsed = urllib.parse.parse_qsl(
        query,
        keep_blank_values=True,
    )
    parsed.sort(key=lambda item: (item[0], item[1]))
    return urllib.parse.urlencode(parsed, doseq=True)


def get_config_identity(link: str) -> dict | None:
    try:
        link = clean_link(link)
        parsed = urllib.parse.urlsplit(link)
        scheme = parsed.scheme.lower()
        if scheme == "vmess":
            config = parse_vmess(link)
            if not config:
                return None
            return {
                "scheme": "vmess",
                "add": config.get("add"),
                "port": str(config.get("port")),
                "id": config.get("id"),
                "aid": config.get("aid"),
                "net": config.get("net"),
                "type": config.get("type"),
                "host": config.get("host"),
                "path": config.get("path"),
                "tls": config.get("tls"),
                "sni": config.get("sni"),
                "alpn": config.get("alpn"),
                "fp": config.get("fp"),
            }
        if scheme == "ss":
            config = parse_ss(link)
            if not config:
                return None
            return config
        if scheme in {"vless", "trojan", "hysteria", "hysteria2", "socks"}:
            return {
                "scheme": scheme,
                "hostname": parsed.hostname,
                "port": parsed.port,
                "username": parsed.username,
                "path": parsed.path,
                "query": canonical_query(parsed.query),
            }
        return None
    except Exception:
        return None


def get_config_unique_key(link: str) -> str:
    identity = get_config_identity(link)
    if identity is None:
        return sha256(link)
    return sha256(stable_json(identity))


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
                base64.urlsafe_b64encode(
                    stable_json(config).encode("utf-8")
                )
                .decode("utf-8")
                .rstrip("=")
            )
            return f"vmess://{encoded}"
        parsed = urllib.parse.urlsplit(raw_link)
        normalized = urllib.parse.urlunsplit(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                canonical_query(parsed.query),
                channel_name,
            )
        )
        return normalized
    except Exception:
        return raw_link


def extract_configs_from_text(text: str) -> list[str]:
    results = []
    for item in CONFIG_REGEX.findall(text):
        item = clean_link(item)
        if "://" not in item:
            continue
        results.append(item)
    return results


def atomic_write(path: Path, content: str) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def fetch_page(url: str) -> str | None:
    try:
        time.sleep(random.uniform(1, 2))
        
        response = session.get(
            url,
            headers=random_headers(),
            timeout=REQUEST_TIMEOUT,
        )
        
        if response.status_code == 403:
            print(f"  WARNING: Access forbidden (403) - likely IP blocked by Telegram")
            return None
        if response.status_code == 429:
            print(f"  WARNING: Rate limited (429) - waiting longer")
            time.sleep(60)
            return None
            
        response.raise_for_status()
        
        if not response.text.strip():
            print(f"  WARNING: Empty response")
            return None
            
        if "tgme_widget_message" not in response.text and "data-post" not in response.text:
            print(f"  WARNING: Response doesn't contain message data (possible block page)")
            debug_file = Path("debug_response.html")
            debug_file.write_text(response.text[:5000], encoding="utf-8")
            print(f"  DEBUG: Saved response sample to {debug_file}")
            return None
            
        return response.text
        
    except requests.Timeout:
        print(f"  ERROR: Request timed out for {url}")
        return None
    except requests.RequestException as e:
        print(f"  ERROR: Request failed: {str(e)[:200]}")
        return None
    except Exception as e:
        print(f"  ERROR: Unexpected error: {str(e)[:200]}")
        return None


def extract_message_id(post_attr: str) -> int | None:
    try:
        parts = post_attr.rsplit("/", 1)
        if len(parts) == 2:
            return int(parts[1])
        return None
    except (ValueError, IndexError):
        return None


def scrape_all_channels(channels: dict[str, str]) -> None:
    global_seen = set()
    all_channel_data = {}

    for name, base_url in channels.items():
        if not isinstance(name, str) or not isinstance(base_url, str):
            continue
        base_url = base_url.strip()
        if not base_url.startswith("https://t.me/s/"):
            continue

        print(f"\nScraping {name}")
        channel_configs = []
        channel_seen = set()
        next_url = base_url.rstrip("/")
        previous_oldest_id = None

        for page in range(MAX_PAGES_PER_CHANNEL):
            print(f"  Page {page + 1}")
            time.sleep(random.uniform(2.0, 4.0))
            html = fetch_page(next_url)
            if not html:
                break

            soup = BeautifulSoup(html, "lxml")

            messages = soup.select("[data-post]")
            if not messages:
                print(f"  WARNING: No messages found on page")
                break

            text_nodes = soup.select(
                ".tgme_widget_message_text, .js-message_text"
            )
            all_text = "\n".join(
                node.get_text(separator="\n", strip=True)
                for node in text_nodes
            )

            raw_configs = extract_configs_from_text(all_text)
            for raw in raw_configs:
                identity = get_config_identity(raw)
                if identity is None:
                    continue
                unique_key = sha256(stable_json(identity))

                if unique_key in global_seen:
                    continue
                if unique_key in channel_seen:
                    continue

                global_seen.add(unique_key)
                channel_seen.add(unique_key)

                normalized = normalize_config(raw, name)
                channel_configs.append(normalized)

                if len(channel_configs) >= MAX_CONFIGS_PER_CHANNEL:
                    break

            if len(channel_configs) >= MAX_CONFIGS_PER_CHANNEL:
                break

            oldest_id = None
            for message in messages:
                post = message.get("data-post")
                if not post:
                    continue
                msg_id = extract_message_id(post)
                if msg_id is None:
                    continue
                if oldest_id is None or msg_id < oldest_id:
                    oldest_id = msg_id

            if oldest_id is None:
                break

            if previous_oldest_id is not None and oldest_id >= previous_oldest_id:
                break

            previous_oldest_id = oldest_id
            next_url = f"{base_url.rstrip('/')}?before={oldest_id}"

        all_channel_data[name] = channel_configs
        print(f"  Found {len(channel_configs)} unique configs")

    for name, configs in all_channel_data.items():
        outfile = DATA_DIR / f"{name}.txt"
        atomic_write(outfile, "\n".join(configs) + "\n")
        print(f"Saved {len(configs)} configs -> {outfile}")


def main() -> None:
    if not CHANNELS_FILE.exists():
        print("channels.json not found")
        return
    try:
        channels = json.loads(
            CHANNELS_FILE.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError:
        print("Invalid channels.json")
        return
    if not isinstance(channels, dict):
        print("channels.json must contain an object")
        return
    
    if PROXY_URL:
        print(f"Using proxy: {PROXY_URL[:50]}...")
    else:
        print("No proxy configured - direct connection (may be blocked by Telegram)")
    
    scrape_all_channels(channels)


if __name__ == "__main__":
    main()
