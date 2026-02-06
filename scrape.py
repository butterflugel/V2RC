import requests
import re
import json
from bs4 import BeautifulSoup
from pathlib import Path

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

CONFIG_REGEX = re.compile(
    r'(vmess://[^\s]+|vless://[^\s]+|trojan://[^\s]+|ss://[^\s]+|hysteria2://[^\s]+|hysteria://[^\s]+)'
)

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

with open("channels.json", "r", encoding="utf-8") as f:
    channels = json.load(f)

for name, url in channels.items():
    print(f"Scraping {name}...")
    r = requests.get(url, headers=HEADERS, timeout=30)
    r.raise_for_status()

    soup = BeautifulSoup(r.text, "html.parser")
    texts = soup.select(".tgme_widget_message_text")

    new_found = []
    for t in texts:
        matches = CONFIG_REGEX.findall(t.get_text())
        new_found.extend(matches)

    # Deduplicate new batch while preserving order
    new_unique = list(dict.fromkeys(new_found))

    outfile = DATA_DIR / f"{name}.txt"

    # Load existing
    old = []
    if outfile.exists():
        with open(outfile, "r", encoding="utf-8") as f:
            old = [line.strip() for line in f if line.strip()]

    # Merge: new on top, old below → dedupe → keep top 200
    combined = list(dict.fromkeys(new_unique + old))[:200]

    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(combined))

    print(f"Saved {len(combined)} configs → {outfile}")
