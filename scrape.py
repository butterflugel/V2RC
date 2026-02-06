import requests
import re
import json
from bs4 import BeautifulSoup
from pathlib import Path

HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

CONFIG_REGEX = re.compile(r'(vmess://[^\s]+|vless://[^\s]+|trojan://[^\s]+)')

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

    found = []
    for t in texts:
        matches = CONFIG_REGEX.findall(t.get_text())
        found.extend(matches)

    # Deduplicate + limit
    unique = list(dict.fromkeys(found))[:200]

    outfile = DATA_DIR / f"{name}.txt"
    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(unique))

    print(f"Saved {len(unique)} configs → {outfile}")
