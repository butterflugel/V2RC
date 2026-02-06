import re
import json
from pathlib import Path
import requests
from bs4 import BeautifulSoup

CONFIG_REGEX = re.compile(
    r'(vmess://[^\s]+|vless://[^\s]+|trojan://[^\s]+|ss://[^\s]+|hysteria2://[^\s]+|hysteria://[^\s]+)'
)

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

CHANNELS_FILE = "channels.json"
MAX_CONFIGS = 200

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
}

def scrape_channel(url, name):
    print(f"Scraping {name}...")
    try:
        r = requests.get(url, headers=HEADERS, timeout=25)
        r.raise_for_status()
    except Exception as e:
        print(f"Request failed for {name}: {e}")
        return

    soup = BeautifulSoup(r.text, "html.parser")
    messages = soup.select("div.tgme_widget_message_text")

    configs = []
    for msg in messages:
        text = msg.get_text(separator="\n", strip=True)
        found = CONFIG_REGEX.findall(text)
        configs.extend(found)

    configs = list(dict.fromkeys(configs))  # dedupe preserve order

    # Load old
    outfile = DATA_DIR / f"{name}.txt"
    old = []
    if outfile.is_file():
        with open(outfile, encoding="utf-8") as f:
            old = [l.strip() for l in f if l.strip()]

    # Newest first
    combined = list(dict.fromkeys(configs + old))[:MAX_CONFIGS]

    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(combined) + "\n")

    print(f"Saved {len(combined)} configs → {outfile}")


def main():
    with open(CHANNELS_FILE, encoding="utf-8") as f:
        channels = json.load(f)

    for name, url in channels.items():
        scrape_channel(url, name)


if __name__ == "__main__":
    main()
