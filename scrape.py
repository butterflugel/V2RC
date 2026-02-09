import re
import json
from pathlib import Path
import requests
from bs4 import BeautifulSoup
import random
import time
import urllib.parse
import base64

CONFIG_REGEX = re.compile(
    r'(vmess://[^\s<>\[\]]+|vless://[^\s<>\[\]]+|trojan://[^\s<>\[\]]+|ss://[^\s<>\[\]]+|hysteria2://[^\s<>\[\]]+|hysteria://[^\s<>\[\]]+)'
)

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

CHANNELS_FILE = "channels.json"
MAX_CONFIGS_PER_CHANNEL = 300
MAX_PAGES_PER_CHANNEL = 15
REQUEST_TIMEOUT = 25

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

def fix_b64(s: str) -> str:
    return s + "=" * (-len(s) % 4)

def get_random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

def get_config_unique_key(link: str) -> str:
    try:
        parsed = urllib.parse.urlparse(link)
        scheme = parsed.scheme.lower()

        if scheme == 'vmess':
            decoded = base64.urlsafe_b64decode(fix_b64(parsed.path)).decode()
            config = json.loads(decoded)
            return f"vmess:{config.get('add')}:{config.get('port')}:{config.get('id')}"

        elif scheme in ['vless', 'trojan', 'hysteria', 'hysteria2']:
            return f"{scheme}:{parsed.netloc}"

        elif scheme == 'ss':
            data = parsed.netloc or parsed.path
            return f"ss:{data}"

        return link
    except:
        return link

def clean_and_normalize_config(raw_link: str, channel_name: str, index: int = 0) -> str:
    try:
        scheme = raw_link.split('://')[0].lower()

        if scheme == 'vmess':
            b64 = raw_link.split('://')[1]
            decoded = base64.urlsafe_b64decode(fix_b64(b64)).decode()
            config = json.loads(decoded)

            remark = config.get('ps', '').strip()
            if not remark:
                remark = f"{channel_name} - VMESS-{index}"

            config['ps'] = f"{channel_name} - {remark[:50]}"
            new_b64 = base64.urlsafe_b64encode(json.dumps(config).encode()).decode().rstrip("=")
            return f"vmess://{new_b64}"

        else:
            parsed = urllib.parse.urlparse(raw_link)
            remark = parsed.fragment.strip()
            if not remark:
                host = parsed.hostname or "unknown"
                remark = f"{channel_name} - {host}-{parsed.scheme.upper()}-{index}"

            new_url = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                parsed.query,
                urllib.parse.quote(remark)
            ))
            return new_url
    except:
        return raw_link

def scrape_channel(base_url: str, name: str):
    print(f"\nScraping {name} → {base_url}")
    new_configs = []
    seen_keys = set()
    url = base_url.rstrip('/')
    page_count = 0
    global_index = 0

    while page_count < MAX_PAGES_PER_CHANNEL:
        page_count += 1
        print(f"  Page {page_count} → {url}")

        try:
            time.sleep(random.uniform(2, 5))
            r = requests.get(url, headers=get_random_headers(), timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
        except Exception as e:
            print(f"  Request failed: {e}")
            break

        soup = BeautifulSoup(r.text, "html.parser")
        messages = soup.select("div.tgme_widget_message")

        if not messages:
            print("  No messages found — Telegram layout may have changed")
            break

        oldest_id = None

        for msg in messages:
            text_elem = msg.select_one("div.tgme_widget_message_text")
            if not text_elem:
                continue

            text = text_elem.get_text(" ", strip=True)
            found = CONFIG_REGEX.findall(text)

            for raw in found:
                global_index += 1
                key = get_config_unique_key(raw)
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                clean = clean_and_normalize_config(raw, name, global_index)
                new_configs.append(clean)

            post = msg.get("data-post")
            if post and "/" in post:
                try:
                    mid = int(post.split("/")[-1])
                    if oldest_id is None or mid < oldest_id:
                        oldest_id = mid
                except:
                    pass

        print(f"  Added {len(new_configs)} total configs so far")

        if not oldest_id:
            break
        url = f"{base_url}?before={oldest_id}"

    outfile = DATA_DIR / f"{name}.txt"
    old = []
    if outfile.exists():
        old = outfile.read_text(encoding="utf-8").splitlines()

    combined = list(dict.fromkeys(new_configs + old))[:MAX_CONFIGS_PER_CHANNEL]
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
            print(f"Skipping {name}: invalid URL")
            continue
        scrape_channel(url, name)

if __name__ == "__main__":
    main()
