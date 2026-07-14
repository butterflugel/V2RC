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
REQUEST_TIMEOUT = 30

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
]

TRAILING_CHARS = ".,);]'\"}>"

TELEGRAM_DOMAINS = [
    "https://t.me",
    "https://telegram.me",
    "https://telegram.org",
]


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


def fix_b64(value: str) -> str:
    value = value.strip()
    return value + "=" * (-len(value) % 4)


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


def fetch_channel_messages(channel_username: str) -> str | None:
    session = requests.Session()
    
    for domain in TELEGRAM_DOMAINS:
        url = f"{domain}/s/{channel_username}"
        
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        for attempt in range(2):
            try:
                time.sleep(random.uniform(1, 2))
                
                response = session.get(
                    url,
                    headers=headers,
                    timeout=REQUEST_TIMEOUT,
                    allow_redirects=True,
                )
                
                if response.status_code == 200:
                    if "tgme_widget_message" in response.text:
                        print(f"  Success with {domain}")
                        return response.text
                
            except requests.Timeout:
                continue
            except requests.RequestException:
                continue
            except Exception:
                continue
    
    return None


def scrape_channel(channel_username: str, channel_name: str) -> list:
    configs = []
    seen = set()
    
    html = fetch_channel_messages(channel_username)
    if not html:
        print(f"  ERROR: Could not fetch channel")
        return configs
    
    soup = BeautifulSoup(html, "lxml")
    
    text_nodes = soup.select(".tgme_widget_message_text, .js-message_text")
    all_text = "\n".join(
        node.get_text(separator="\n", strip=True)
        for node in text_nodes
    )
    
    raw_configs = extract_configs_from_text(all_text)
    
    for raw in raw_configs:
        identity = get_config_identity(raw)
        if identity is None:
            continue
        
        unique_key = sha256(stable_json(identity))
        if unique_key in seen:
            continue
        
        seen.add(unique_key)
        normalized = normalize_config(raw, channel_name)
        configs.append(normalized)
        
        if len(configs) >= MAX_CONFIGS_PER_CHANNEL:
            break
    
    return configs


def scrape_all_channels(channels: dict[str, str]) -> None:
    all_channel_data = {}
    
    for name, url in channels.items():
        if not isinstance(name, str) or not isinstance(url, str):
            continue
        
        url = url.strip()
        channel_username = url.replace("https://t.me/s/", "").replace("https://t.me/", "").replace("https://telegram.me/s/", "").replace("https://telegram.me/", "").strip("/")
        
        if not channel_username:
            continue
        
        print(f"\nScraping {name} (@{channel_username})")
        
        channel_configs = scrape_channel(channel_username, name)
        
        all_channel_data[name] = channel_configs
        print(f"  Found {len(channel_configs)} unique configs")
    
    for name, configs in all_channel_data.items():
        outfile = DATA_DIR / f"{name}.txt"
        if configs:
            atomic_write(outfile, "\n".join(configs) + "\n")
            print(f"Saved {len(configs)} configs -> {outfile}")
        else:
            print(f"No configs found for {name}")


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
