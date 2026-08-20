"""
add_default_blocklist.py — SecEoKnight Default Blocklist Seeder
===============================================================
Seeds the server's blocklist with a sensible set of enterprise default rules
covering social media, streaming, gambling, malware distribution, and adult content.

Run once after first server deployment:
    python3 scripts/add_default_blocklist.py [SERVER_IP] [PORT]

Examples:
    python3 scripts/add_default_blocklist.py
    python3 scripts/add_default_blocklist.py 192.168.1.189 5001
"""

import sys
import json
import urllib.request
import urllib.error

SERVER_IP   = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
SERVER_PORT = sys.argv[2] if len(sys.argv) > 2 else "5001"
BASE_URL    = f"http://{SERVER_IP}:{SERVER_PORT}"

# ── Default ruleset ────────────────────────────────────────────────────────────
# Format: (rule_type, rule_value, description)
DEFAULT_RULES = [

    # ── Social media / distractions ──────────────────────────────────────────
    ("host",   "facebook.com",       "Social media — Facebook"),
    ("host",   "instagram.com",      "Social media — Instagram"),
    ("host",   "tiktok.com",         "Social media — TikTok"),
    ("host",   "twitter.com",        "Social media — Twitter/X"),
    ("host",   "x.com",              "Social media — X"),
    ("host",   "reddit.com",         "Social media — Reddit"),
    ("host",   "snapchat.com",       "Social media — Snapchat"),
    ("host",   "pinterest.com",      "Social media — Pinterest"),
    ("host",   "discord.com",        "Chat — Discord"),
    ("host",   "telegram.org",       "Chat — Telegram"),
    ("host",   "whatsapp.com",       "Chat — WhatsApp"),

    # ── Streaming / media ─────────────────────────────────────────────────────
    ("prefix", "youtube.com/shorts", "YouTube Shorts"),
    ("host",   "netflix.com",        "Streaming — Netflix"),
    ("host",   "twitch.tv",          "Streaming — Twitch"),
    ("host",   "spotify.com",        "Streaming — Spotify"),
    ("host",   "soundcloud.com",     "Streaming — SoundCloud"),

    # ── Gambling ─────────────────────────────────────────────────────────────
    ("regex",  r".*\bbet(ting|365|way)\b.*",  "Gambling — bet* sites"),
    ("regex",  r".*\b(casino|poker|slots)\b.*", "Gambling — casino/poker"),

    # ── Torrent / piracy ──────────────────────────────────────────────────────
    ("regex",  r".*torrent.*",       "Piracy — torrent sites"),
    ("host",   "thepiratebay.org",   "Piracy — The Pirate Bay"),
    ("host",   "1337x.to",           "Piracy — 1337x"),
    ("host",   "rarbg.to",           "Piracy — RARBG"),

    # ── Malware / phishing infrastructure ─────────────────────────────────────
    ("regex",  r".*\.(exe|bat|cmd|scr|vbs|ps1)$", "Block direct executable downloads"),
    ("regex",  r".*paypal.*\.(xyz|tk|ml|ga|cf|gq|top).*", "Phishing — PayPal typosquats"),
    ("regex",  r".*microsoft.*\.(xyz|tk|ml|ga|cf|gq|top).*", "Phishing — Microsoft typosquats"),
    ("regex",  r".*apple.*-?secure.*\.(xyz|tk|ml|ga|cf|gq|top).*", "Phishing — Apple fakes"),

    # ── Ad / tracker networks (bandwidth & privacy) ───────────────────────────
    ("host",   "doubleclick.net",    "Ad tracker — Google DoubleClick"),
    ("host",   "adnxs.com",          "Ad tracker — AppNexus"),
    ("host",   "outbrain.com",       "Ad tracker — Outbrain"),
    ("host",   "taboola.com",        "Ad tracker — Taboola"),

    # ── Crypto mining ─────────────────────────────────────────────────────────
    ("regex",  r".*coinhive.*",      "Crypto miner — CoinHive"),
    ("regex",  r".*(cryptonight|monero-miner|minexmr).*", "Crypto miner scripts"),
]


def post_rule(rule_type: str, rule_value: str, description: str) -> bool:
    payload = json.dumps({
        "rule_type":   rule_type,
        "rule_value":  rule_value,
        "description": description,
        "added_by":    "default_seed",
    }).encode()

    req = urllib.request.Request(
        f"{BASE_URL}/api/blocklist",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status in (200, 201):
                return True
    except urllib.error.HTTPError as e:
        if e.code == 409:
            return True   # already exists — that's fine
        print(f"  HTTP {e.code} — {rule_value}")
    except Exception as e:
        print(f"  ERROR — {rule_value}: {e}")
    return False


def main():
    print(f"\nSecEoKnight Default Blocklist Seeder")
    print(f"Target: {BASE_URL}")
    print(f"Rules to add: {len(DEFAULT_RULES)}\n")

    # Verify server is up
    try:
        with urllib.request.urlopen(f"{BASE_URL}/health", timeout=5) as r:
            pass
    except Exception as e:
        print(f"ERROR: Cannot reach server at {BASE_URL} — {e}")
        print("Make sure the server is running before seeding the blocklist.")
        sys.exit(1)

    added = 0
    for rule_type, rule_value, description in DEFAULT_RULES:
        if post_rule(rule_type, rule_value, description):
            print(f"  [OK] {rule_type:8s}  {rule_value}")
            added += 1
        else:
            print(f"  [!!] {rule_type:8s}  {rule_value}  ← failed")

    print(f"\n✅  Done — {added}/{len(DEFAULT_RULES)} rules added.")
    print("Endpoints will pick up the new rules within 30 seconds.")


if __name__ == "__main__":
    main()
