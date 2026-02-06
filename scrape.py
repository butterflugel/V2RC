import requests
import re
import json
from bs4 import BeautifulSoup
from pathlib import Path

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

# regex matches full config links directly
CONFIG_REGEX = re.compile(
    r'(vmess://[^\s]+|vless://[^\s]+|trojan://[^\s]+|ss://[^\s]+|hysteria2://[^\s]+|hysteria://[^\s]+)',
    re.IGNORECASE
)

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

CHANNELS_FILE = "channels.json"
MAX_CONFIGS = 200

with open(CHANNELS_FILE, "r", encoding="utf-8") as f:
    channels = json.load(f)

for name, url in channels.items():
    print(f"Scraping {name}...")
    try:
        r = requests.get(url, headers=HEADERS, timeout=30)
        r.raise_for_status()
    except Exception as e:
        print(f"[{name}] Error fetching page: {e}")
        continue

    soup = BeautifulSoup(r.text, "html.parser")
    texts = soup.select(".tgme_widget_message_text")

    found = []
    for t in texts:
        # apply regex directly to the full message text
        matches = CONFIG_REGEX.findall(t.get_text())
        found.extend(matches)

    # Load existing configs
    outfile = DATA_DIR / f"{name}.txt"
    old_configs = []
    if outfile.exists():
        with open(outfile, "r", encoding="utf-8") as f:
            old_configs = [line.strip() for line in f if line.strip()]

    # Merge new on top, old below, dedupe, limit MAX_CONFIGS
    combined = list(dict.fromkeys(found + old_configs))[:MAX_CONFIGS]

    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(combined))

    print(f"Saved {len(combined)} configs → {outfile}")
