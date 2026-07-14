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
DATA_DIR.mkdir(parents=True, exist_ok=True)

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
    connect=3,
    read=3,
    backoff_factor=1,
    status_forcelist=(429, 500, 502, 503, 504),
    allowed_methods=frozenset({"GET"}),
)

adapter = HTTPAdapter(max_retries=retry)

session.mount("http://", adapter)
session.mount("https://", adapter)


def fix_b64(value: str) -> str:
    value = value.strip()
    return value + "=" * (-len(value) % 4)


def random_headers() -> dict:
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "*/*",
        "Connection": "keep-alive",
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
        response = session.get(
            url,
            headers=random_headers(),
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        if not response.text.strip():
            return None
        return response.text
    except requests.RequestException:
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

        print(f"\nScraping {name} ({base_url})")
        channel_configs = []
        channel_seen = set()
        next_url = base_url.rstrip("/")
        previous_oldest_id = None

        for page in range(MAX_PAGES_PER_CHANNEL):
            print(f"  Page {page + 1}")
            time.sleep(random.uniform(1.5, 3.0))
            html = fetch_page(next_url)
            if not html:
                print(f"  ERROR: Failed to fetch {next_url}")
                break
            
            print(f"  DEBUG: Got {len(html)} bytes of HTML")

            soup = BeautifulSoup(html, "lxml")

            messages = soup.select("[data-post]")
            print(f"  DEBUG: Found {len(messages)} message containers")

            text_nodes = soup.select(
                ".tgme_widget_message_text, .js-message_text"
            )
            print(f"  DEBUG: Found {len(text_nodes)} text nodes")
            
            # Print sample of what text nodes contain
            if text_nodes:
                for i, node in enumerate(text_nodes[:3]):
                    sample = node.get_text(separator="\n", strip=True)[:200]
                    print(f"  DEBUG: Text node {i} sample: {sample}")
            else:
                # Try to find any text content as fallback
                print("  DEBUG: No text nodes found with standard selectors")
                print("  DEBUG: Trying alternative selectors...")
                alt_nodes = soup.select(".tgme_widget_message")
                print(f"  DEBUG: Found {len(alt_nodes)} message widgets")
                if alt_nodes:
                    sample_text = alt_nodes[0].get_text()[:200]
                    print(f"  DEBUG: First widget text: {sample_text}")

            all_text = "\n".join(
                node.get_text(separator="\n", strip=True)
                for node in text_nodes
            )
            
            print(f"  DEBUG: Combined text length: {len(all_text)}")

            raw_configs = extract_configs_from_text(all_text)
            print(f"  DEBUG: Found {len(raw_configs)} raw configs in text")
            
            for raw in raw_configs:
                identity = get_config_identity(raw)
                if identity is None:
                    print(f"  DEBUG: Skipping invalid config: {raw[:100]}")
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
                print(f"  DEBUG: Could not find oldest message ID, stopping")
                break

            if previous_oldest_id is not None and oldest_id >= previous_oldest_id:
                print(f"  DEBUG: No older messages found")
                break

            previous_oldest_id = oldest_id
            next_url = f"{base_url.rstrip('/')}?before={oldest_id}"

        all_channel_data[name] = channel_configs
        print(f"  Found {len(channel_configs)} unique configs for {name}")

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
    scrape_all_channels(channels)


if __name__ == "__main__":
    main()
