import re
import json
from pathlib import Path
import requests
from bs4 import BeautifulSoup
import random
import time

CONFIG_REGEX = re.compile(
    r'(vmess://|vless://|trojan://|ss://|hysteria2://|hysteria://)[^ \n]+(?:#[^\n]*)?',
    re.IGNORECASE
)

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

CHANNELS_FILE = "channels.json"
MAX_CONFIGS = 200

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

def scrape_channel(url: str, name: str):
    print(f"Scraping {name} ({url}) ...")
    try:
        time.sleep(random.uniform(1.2, 3.8))  # polite delay
        r = requests.get(url, headers=HEADERS, timeout=30)
        r.raise_for_status()
    except Exception as e:
        print(f"→ Request failed: {e}")
        return

    soup = BeautifulSoup(r.text, "html.parser")
    message_elements = soup.select("div.tgme_widget_message_text")

    if not message_elements:
        print("→ No messages found (class might have changed or page empty)")
        return

    configs = []
    for elem in message_elements:
        text = elem.get_text(separator=" ", strip=True)
        found = CONFIG_REGEX.findall(text)
        configs.extend(found)

    configs = list(dict.fromkeys(configs))  # remove duplicates, preserve first occurrence order

    print(f"→ Found {len(configs)} new configs")

    # Load existing
    outfile = DATA_DIR / f"{name}.txt"
    old_configs = []
    if outfile.is_file():
        with open(outfile, encoding="utf-8") as f:
            old_configs = [line.strip() for line in f if line.strip()]

    # Combine: new ones first, then old, dedupe, limit
    combined = list(dict.fromkeys(configs + old_configs))[:MAX_CONFIGS]

    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(combined) + "\n")

    print(f"→ Saved {len(combined)} total configs → {outfile}")


def main():
    with open(CHANNELS_FILE, encoding="utf-8") as f:
        channels = json.load(f)

    for name, url in channels.items():
        scrape_channel(url, name)


if __name__ == "__main__":
    main()
