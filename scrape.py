import asyncio
import re
import json
from pathlib import Path
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright

# regex to match all config protocols
CONFIG_REGEX = re.compile(
    r'(vmess://[^\s,]+|vless://[^\s,]+|trojan://[^\s,]+|ss://[^\s,]+|hysteria2://[^\s,]+|hysteria://[^\s,]+)',
    re.IGNORECASE
)

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

CHANNELS_FILE = "channels.json"
MAX_CONFIGS = 200
SCROLL_PAUSE = 1.5  # seconds between scrolls

async def scrape_channel(page, url, name):
    print(f"Scraping {name}...")
    await page.goto(url, timeout=60000)
    
    previous_height = None
    collected_texts = set()
    
    while True:
        html = await page.inner_html("body")
        soup = BeautifulSoup(html, "html.parser")
        messages = soup.select(".tgme_widget_message_text")
        
        for msg in messages:
            collected_texts.add(msg.get_text())
        
        # extract configs
        matches = []
        for t in collected_texts:
            # split by space, comma, newline
            parts = re.split(r'[\s,]+', t)
            for p in parts:
                if CONFIG_REGEX.match(p):
                    matches.append(p)
        
        matches = list(dict.fromkeys(matches))  # dedupe
        
        if len(matches) >= MAX_CONFIGS:
            matches = matches[:MAX_CONFIGS]
            break
        
        # scroll down
        current_height = await page.evaluate("document.body.scrollHeight")
        if previous_height == current_height:
            break
        previous_height = current_height
        await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
        await asyncio.sleep(SCROLL_PAUSE)
    
    # Load existing configs
    outfile = DATA_DIR / f"{name}.txt"
    old_configs = []
    if outfile.exists():
        with open(outfile, "r", encoding="utf-8") as f:
            old_configs = [line.strip() for line in f if line.strip()]
    
    # Merge new on top, old below, dedupe
    combined = list(dict.fromkeys(matches + old_configs))[:MAX_CONFIGS]
    
    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(combined))
    
    print(f"Saved {len(combined)} configs → {outfile}")

async def main():
    with open(CHANNELS_FILE, "r", encoding="utf-8") as f:
        channels = json.load(f)

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        for name, url in channels.items():
            await scrape_channel(page, url, name)
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
