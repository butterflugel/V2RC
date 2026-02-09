import re
import json
from pathlib import Path
import requests
from bs4 import BeautifulSoup
import random
import time
import urllib.parse
import base64  # for vmess decoding/encoding and unique key

CONFIG_REGEX = re.compile(
    r'(vmess://[^\s<>\[\]]+|vless://[^\s<>\[\]]+|trojan://[^\s<>\[\]]+|ss://[^\s<>\[\]]+|hysteria2://[^\s<>\[\]]+|hysteria://[^\s<>\[\]]+)'
)

DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

CHANNELS_FILE = "channels.json"
MAX_CONFIGS_PER_CHANNEL = 300      # most recent 300 per channel
MAX_PAGES_PER_CHANNEL = 15         # adjust as needed (5–20)
REQUEST_TIMEOUT = 25

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
]

def get_random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

def get_config_unique_key(link: str) -> str:
    """Extract a unique key for dedup (host:port:uuid/password)"""
    try:
        parsed = urllib.parse.urlparse(link)
        scheme = parsed.scheme.lower()
        
        if scheme == 'vmess':
            padded = parsed.path + '=' * (4 - len(parsed.path) % 4)
            decoded = base64.urlsafe_b64decode(padded).decode('utf-8')
            config = json.loads(decoded)
            host = config.get('add', '')
            port = str(config.get('port', ''))
            uuid = config.get('id', '')
            return f"{scheme}:{host}:{port}:{uuid}"
        
        elif scheme in ['vless', 'trojan']:
            if '@' in parsed.netloc:
                user, addr = parsed.netloc.split('@', 1)
            else:
                user = ''
                addr = parsed.netloc
            return f"{scheme}:{user}:{addr}"
        
        elif scheme == 'ss':
            if '@' in parsed.netloc:
                auth, addr = parsed.netloc.split('@', 1)
            else:
                auth = ''
                addr = parsed.netloc
            return f"{scheme}:{auth}:{addr}"
        
        elif scheme.startswith('hysteria'):
            if '@' in parsed.netloc:
                user, addr = parsed.netloc.split('@', 1)
            else:
                user = ''
                addr = parsed.netloc
            return f"{scheme}:{user}:{addr}"
        
        return link  # fallback
    except:
        return link

def clean_and_normalize_config(raw_link: str, channel_name: str, index: int = 0) -> str:
    """Parse link and create a clean remark prefixed with channel name. Handles VMess specially."""
    try:
        scheme = raw_link.split('://')[0].lower()
        
        if scheme == 'vmess':
            # Decode base64
            base64_str = raw_link.split('://')[1]
            padded = base64_str + '=' * (4 - len(base64_str) % 4)
            decoded = base64.urlsafe_b64decode(padded).decode('utf-8')
            config = json.loads(decoded)
            
            remark = config.get('ps', '').strip()
            # Keep original chars (no strip junk)
            
            if remark and len(remark) > 4 and remark.lower() != 'none':
                if len(remark) > 50:
                    remark = remark[:47] + "..."
                final_remark = f"{channel_name} - {remark}"
            else:
                # Fallback
                host = config.get('add', 'unknown')
                port = config.get('port', '')
                port_str = f":{port}" if port else ""
                proto = 'VMESS'
                extra = ""
                if index > 0 and index % 10 == 0:
                    extra = f" #{index}"
                elif '#' in raw_link:
                    frag = raw_link.split('#')[-1][:8].strip()
                    if frag and len(frag) > 3:
                        extra = f" #{frag}"
                final_remark = f"{channel_name} - {host}{port_str} - {proto}{extra}"
            
            # Update ps
            config['ps'] = final_remark
            
            # Re-encode
            new_json = json.dumps(config)
            new_base64 = base64.urlsafe_b64encode(new_json.encode('utf-8')).decode('utf-8').rstrip('=')
            return f"vmess://{new_base64}"
        
        else:
            # Non-vmess
            parsed = urllib.parse.urlparse(raw_link)
            qs = urllib.parse.parse_qs(parsed.query)
            
            remark = qs.get('remark', [''])[0].strip()
            # Keep original
            
            if remark and len(remark) > 4 and remark.lower() != 'none':
                if len(remark) > 50:
                    remark = remark[:47] + "..."
                final_remark = f"{channel_name} - {remark}"
            else:
                host = parsed.hostname or "unknown"
                port_str = f":{parsed.port}" if parsed.port else ""
                proto = parsed.scheme.upper()
                extra = ""
                if index > 0 and index % 10 == 0:
                    extra = f" #{index}"
                elif '#' in raw_link:
                    frag = raw_link.split('#')[-1][:8].strip()
                    if frag and len(frag) > 3:
                        extra = f" #{frag}"
                final_remark = f"{channel_name} - {host}{port_str} - {proto}{extra}"
            
            # Rebuild
            new_qs = {k: v for k, v in qs.items() if k != 'remark'}
            new_qs['remark'] = [final_remark]
            new_query = urllib.parse.urlencode(new_qs, doseq=True)
            
            clean_link = urllib.parse.urlunparse((
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                parsed.params,
                new_query,
                parsed.fragment or ''
            ))
            
            return clean_link
    except Exception:
        fallback_remark = f"{channel_name} - Config-{index}" if index > 0 else f"{channel_name} - Config"
        sep = '&' if '?' in raw_link else '?'
        return f"{raw_link}{sep}remark={urllib.parse.quote(fallback_remark)}"


def scrape_channel(base_url: str, name: str):
    print(f"\nScraping {name} ({base_url}) ...")
    new_configs = []  # list to preserve order (newest first)
    seen_keys = set()  # for strict dedup by unique key
    url = base_url.rstrip('/')
    page_count = 0
    global_index = 0

    while page_count < MAX_PAGES_PER_CHANNEL:
        page_count += 1
        print(f"  Page {page_count} → {url}")
        try:
            time.sleep(random.uniform(2.0, 5.5))
            r = requests.get(url, headers=get_random_headers(), timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
        except Exception as e:
            print(f"  → Request failed: {e}")
            break

        soup = BeautifulSoup(r.text, "html.parser")
        message_wrappers = soup.select("div.tgme_widget_message[data-post]")

        if not message_wrappers:
            print("  → No messages found (end of channel or class changed)")
            break

        page_new_count = 0
        oldest_msg_id = None

        for wrapper in message_wrappers:
            text_elem = wrapper.select_one("div.tgme_widget_message_text")
            if not text_elem:
                continue

            text = text_elem.get_text(separator=" ", strip=True)
            found_links = CONFIG_REGEX.findall(text)

            for raw_link in found_links:
                global_index += 1
                unique_key = get_config_unique_key(raw_link)
                if unique_key in seen_keys:
                    continue  # skip duplicate core config
                seen_keys.add(unique_key)
                clean_link = clean_and_normalize_config(raw_link, channel_name=name, index=global_index)
                new_configs.append(clean_link)
                page_new_count += 1

            # Find oldest ID
            data_post = wrapper.get("data-post")
            if data_post:
                try:
                    _, msg_id_str = data_post.rsplit("/", 1)
                    msg_id = int(msg_id_str)
                    if oldest_msg_id is None or msg_id < oldest_msg_id:
                        oldest_msg_id = msg_id
                except:
                    pass

        print(f"  → Added {page_new_count} new unique configs (total: {len(new_configs)})")

        if oldest_msg_id is None or oldest_msg_id <= 1:
            break

        url = f"{base_url}?before={oldest_msg_id}"

    # Save: prepend new to old, dedup (though strict dedup already applied), limit to 300 most recent
    print(f"→ Total unique new configs after {page_count} pages: {len(new_configs)}")

    outfile = DATA_DIR / f"{name}.txt"
    old_configs = []
    if outfile.is_file():
        with open(outfile, encoding="utf-8") as f:
            old_configs = [line.strip() for line in f if line.strip()]

    combined = list(dict.fromkeys(new_configs + old_configs))[:MAX_CONFIGS_PER_CHANNEL]

    with open(outfile, "w", encoding="utf-8") as f:
        f.write("\n".join(combined) + "\n")

    print(f"→ Saved {len(combined)} configs (limited to {MAX_CONFIGS_PER_CHANNEL}) → {outfile}")


def main():
    if not Path(CHANNELS_FILE).is_file():
        print(f"Error: {CHANNELS_FILE} not found!")
        return

    with open(CHANNELS_FILE, encoding="utf-8") as f:
        channels = json.load(f)

    for name, url in channels.items():
        if not url.startswith("https://t.me/s/"):
            print(f"Skipping {name}: URL should start with https://t.me/s/")
            continue
        scrape_channel(url, name)


if __name__ == "__main__":
    main()
