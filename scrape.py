import re
import json
from pathlib import Path
import requests
from bs4 import BeautifulSoup
import random
import time
import urllib.parse
import base64
import hashlib

CONFIG_REGEX = re.compile(
    r'(vmess://[^\s<>\[\]]+|vless://[^\s<>\[\]]+|trojan://[^\s<>\[\]]+|ss://[^\s<>\[\]]+|'
    r'hysteria2://[^\s<>\[\]]+|hysteria://[^\s<>\[\]]+|socks://[^\s<>\[\]]+)'
)

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

CHANNELS_FILE = "channels.json"
MAX_CONFIGS_PER_CHANNEL = 400
MAX_PAGES_PER_CHANNEL = 15
REQUEST_TIMEOUT = 15

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
]

def fix_b64(s: str) -> str:
    return s + "=" * (-len(s) % 4)

def get_random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "*/*",
    }

def hash_key(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def get_config_unique_key(link: str) -> str:
    try:
        parsed = urllib.parse.urlparse(link)
        scheme = parsed.scheme.lower()

        if scheme == 'vmess':
            decoded = base64.urlsafe_b64decode(fix_b64(parsed.path)).decode()
            config = json.loads(decoded)

            identity = f"{config.get('add')}:{config.get('port')}:{config.get('id')}"
            return hash_key(identity)

        elif scheme in ['vless', 'trojan', 'hysteria', 'hysteria2', 'socks']:
            identity = f"{scheme}:{parsed.hostname}:{parsed.port}:{parsed.username}"
            return hash_key(identity)

        elif scheme == 'ss':
            return hash_key(parsed.netloc or parsed.path)

        return hash_key(link)

    except:
        return hash_key(link)

def normalize_config(raw_link: str, channel_name: str) -> str:
    try:
        scheme = raw_link.split("://")[0].lower()

        if scheme == "vmess":
            b64 = raw_link.split("://")[1]
            decoded = base64.urlsafe_b64decode(fix_b64(b64)).decode()
            config = json.loads(decoded)

            # force clean remark
            config["ps"] = channel_name

            new_b64 = base64.urlsafe_b64encode(
                json.dumps(config, separators=(",", ":")).encode()
            ).decode().rstrip("=")

            return f"vmess://{new_b64}"

        else:
            parsed = urllib.parse.urlparse(raw_link)

            # remove any existing fragment
            clean_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                channel_name
            ))

            return clean_url

    except:
        return raw_link

def scrape_channel(base_url: str, name: str):
    print(f"\nScraping {name}")
    url = base_url.rstrip("/")
    page_count = 0

    outfile = DATA_DIR / f"{name}.txt"

    existing_configs = []
    existing_keys = set()

    if outfile.exists():
        existing_configs = outfile.read_text(encoding="utf-8").splitlines()
        for cfg in existing_configs:
            existing_keys.add(get_config_unique_key(cfg))

    new_configs = []
    new_keys = set()

    while page_count < MAX_PAGES_PER_CHANNEL:
        page_count += 1
        print(f"  Page {page_count}")

        try:
            time.sleep(random.uniform(2, 4))
            r = requests.get(url, headers=get_random_headers(), timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
        except Exception as e:
            print(f"  Request failed: {e}")
            break

        soup = BeautifulSoup(r.text, "html.parser")
        messages = soup.select("div.tgme_widget_message")

        if not messages:
            break

        oldest_id = None

        for msg in messages:
            text_elem = msg.select_one("div.tgme_widget_message_text")
            if not text_elem:
                continue

            text = text_elem.get_text(" ", strip=True)
            found = CONFIG_REGEX.findall(text)

            for raw in found:
                clean = normalize_config(raw, name)
                key = get_config_unique_key(clean)

                if key in existing_keys or key in new_keys:
                    continue

                new_keys.add(key)
                new_configs.append(clean)

            post = msg.get("data-post")
            if post and "/" in post:
                try:
                    mid = int(post.split("/")[-1])
                    if oldest_id is None or mid < oldest_id:
                        oldest_id = mid
                except:
                    pass

        if not oldest_id:
            break

        url = f"{base_url}?before={oldest_id}"

    combined = new_configs + existing_configs
    combined = combined[:MAX_CONFIGS_PER_CHANNEL]

    outfile.write_text("\n".join(combined) + "\n", encoding="utf-8")

    print(f"Saved {len(combined)} configs → {outfile}")

def main():
    if not Path(CHANNELS_FILE).exists():
        print("channels.json not found")
        return

    with open(CHANNELS_FILE, encoding="utf-8") as f:
        channels = json.load(f)

    for name, url in channels.items():
        if not url.startswith("https://t.me/s/"):
            continue
        scrape_channel(url, name)

if __name__ == "__main__":
    main()
