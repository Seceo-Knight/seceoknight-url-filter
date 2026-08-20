"""
to-server.py  --  SecEoKnight log forwarder
Runs on each Windows endpoint.
Tails C:/url-block/logs.json and POSTs every new line to the unified server.

Run:
  python to-server.py
"""

import time
import json
import socket
import threading
import requests
from datetime import datetime

# -- Configuration -------------------------------------------------------------
SERVER_IP     = "192.168.1.63"          # <-- Change to your security server IP
SERVER_PORT   = 5001
LOGS_FILE     = r"C:\url-block\logs.json"
API_ENDPOINT  = f"http://{SERVER_IP}:{SERVER_PORT}/logs"
HEARTBEAT_ENDPOINT  = f"http://{SERVER_IP}:{SERVER_PORT}/api/heartbeat"
HEARTBEAT_INTERVAL  = 60      # seconds between heartbeats -- keep in sync with
                               # STALE_THRESHOLD_MINUTES in server/database.py
POLL_INTERVAL = 1       # seconds between file checks
RETRY_LIMIT   = 5       # max consecutive send failures before warning
# -----------------------------------------------------------------------------

_fail_count = 0


def _get_endpoint_ip():
    """Get the real LAN IP of this machine (not 127.0.0.1)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostname()


ENDPOINT_IP       = _get_endpoint_ip()
ENDPOINT_HOSTNAME = socket.gethostname()


def heartbeat_loop():
    """
    Runs forever in a background thread, independent of the log file.
    Pings the server every HEARTBEAT_INTERVAL seconds so the dashboard
    can tell "installed and healthy but idle" apart from "uninstalled
    or crashed" -- without this, an endpoint that isn't actively
    browsing would look identical to one that's been removed.
    """
    _hb_fail_count = 0
    while True:
        try:
            requests.post(
                HEARTBEAT_ENDPOINT,
                json={"ip": ENDPOINT_IP, "hostname": ENDPOINT_HOSTNAME},
                timeout=5,
            )
            _hb_fail_count = 0
        except Exception:
            _hb_fail_count += 1
            if _hb_fail_count == 1 or _hb_fail_count % RETRY_LIMIT == 0:
                print(f"[{datetime.now():%H:%M:%S}] WARNING: heartbeat failed, "
                      f"cannot reach {HEARTBEAT_ENDPOINT}")
        time.sleep(HEARTBEAT_INTERVAL)


def send_log(entry: dict):
    """POST a single log entry to the unified server."""
    global _fail_count
    try:
        resp = requests.post(API_ENDPOINT, json=entry, timeout=5)
        resp.raise_for_status()
        _fail_count = 0
        if entry.get("blocked"):
            print(f"[{datetime.now():%H:%M:%S}] BLOCKED  {entry.get('url','')[:80]}")
    except requests.exceptions.ConnectionError:
        _fail_count += 1
        if _fail_count == 1 or _fail_count % RETRY_LIMIT == 0:
            print(f"[{datetime.now():%H:%M:%S}] WARNING: Cannot reach server at {API_ENDPOINT}")
    except Exception as e:
        _fail_count += 1
        print(f"[{datetime.now():%H:%M:%S}] ERROR sending log: {e}")


def follow(fp):
    """Generator that yields new lines as they appear -- like tail -f."""
    fp.seek(0, 2)   # seek to end
    while True:
        line = fp.readline()
        if not line:
            time.sleep(POLL_INTERVAL)
            continue
        yield line


def wait_for_file(path: str, interval: int = 5):
    """Block until the log file exists."""
    while not __import__("os").path.exists(path):
        print(f"[{datetime.now():%H:%M:%S}] Waiting for log file: {path}")
        time.sleep(interval)


if __name__ == "__main__":
    print(f"[{datetime.now():%H:%M:%S}] SecEoKnight log forwarder starting...")
    print(f"[{datetime.now():%H:%M:%S}] Log file  : {LOGS_FILE}")
    print(f"[{datetime.now():%H:%M:%S}] Server    : {API_ENDPOINT}")
    print(f"[{datetime.now():%H:%M:%S}] Heartbeat : {HEARTBEAT_ENDPOINT} every {HEARTBEAT_INTERVAL}s")

    threading.Thread(target=heartbeat_loop, daemon=True).start()

    wait_for_file(LOGS_FILE)
    print(f"[{datetime.now():%H:%M:%S}] Monitoring {LOGS_FILE} ...")

    try:
        with open(LOGS_FILE, "r", encoding="utf-8") as fp:
            for line in follow(fp):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    send_log(entry)
                except json.JSONDecodeError:
                    pass   # incomplete line -- skip
    except KeyboardInterrupt:
        print(f"\n[{datetime.now():%H:%M:%S}] Stopped by user.")
    except Exception as e:
        print(f"[{datetime.now():%H:%M:%S}] Fatal error: {e}")
