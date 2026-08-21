"""
agent.py  --  SecEoKnight mitmproxy addon
Run with:
  mitmproxy --listen-port 8082 -s agent.py

Changes from original:
  - BLOCKLIST_URL now points to the unified server's /blocklist endpoint
    (same plain-text format, zero parser changes)
  - SERVER_IP is the only setting you need to change per deployment
  - LOG_PATH unchanged -- to-server.py picks up logs and forwards them
"""

from mitmproxy import http, ctx
from urllib.parse import urlparse, parse_qs
import time
import os
import re
import json
import socket
import urllib.request
import urllib.error
import threading


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

# -- Configuration -------------------------------------------------------------
SERVER_IP    = "192.168.1.63"          # <-- Change to your security server IP
SERVER_PORT  = 5001
BLOCKLIST_URL = f"http://{SERVER_IP}:{SERVER_PORT}/blocklist"

# API key -- optional while the server is in its auth "grace period"
# (SECEOKNIGHT_REQUIRE_API_KEY=false), required once it's flipped to true.
# Get this value from server/.env on the server (printed at the end of
# install.sh), and set it here.
API_KEY = "c587daf8474f912561f01c3b960fe080f84497271f4e6efe23854ccdefe1f193"

LOG_PATH     = r"C:\url-block\logs.json"
REQUEST_TIMEOUT  = 10
DEBUG            = True
RELOAD_INTERVAL  = 30       # seconds between blocklist refreshes
MAX_RETRIES      = 2
RETRY_BACKOFF    = 1.5

SUSPICIOUS_CDN_HOSTS = ("googlevideo.com", "ytimg.com")
MAX_LOG_BYTES = 20 * 1024 * 1024   # rotate (truncate) LOG_PATH before it grows past this
# -----------------------------------------------------------------------------


def make_response(status: int, body: bytes, headers: dict):
    factory = getattr(http, "Response", None) or getattr(http, "HTTPResponse", None)
    if not factory:
        raise RuntimeError("mitmproxy http.Response factory not found")
    if hasattr(factory, "make"):
        return factory.make(status, body, headers)
    return factory(status, body, headers)


class VideoBlockerSafe:
    def __init__(self):
        self.block_vids     = set()
        self.block_prefixes = []
        self.block_hosts    = set()
        self._last_modified_header = None
        self.counters = {
            "blocked_watch": 0, "blocked_cdn_referer": 0, "blocked_api": 0,
            "blocked_host": 0,  "blocked_prefix": 0,      "blocked_regex": 0,
            "allowed": 0,
        }
        self._lock           = threading.Lock()
        self._last_load_time = 0

        try:
            self._load_blocklist(force=True)
        except Exception:
            ctx.log.warn("agent: initial blocklist load failed -- continuing")

    # -- Blocklist loader ------------------------------------------------------

    def _load_blocklist(self, force=False):
        now = time.time()
        if not force and (now - self._last_load_time) < RELOAD_INTERVAL:
            return
        self._last_load_time = now

        for attempt in range(1, MAX_RETRIES + 2):
            try:
                req_headers = {"User-Agent": "SecEoKnight-Agent/1.0"}
                if API_KEY:
                    req_headers["X-API-Key"] = API_KEY
                req = urllib.request.Request(
                    BLOCKLIST_URL,
                    headers=req_headers,
                )
                if self._last_modified_header:
                    req.add_header("If-Modified-Since", self._last_modified_header)

                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                ctx.log.debug(f"agent: fetching blocklist attempt {attempt}")

                with opener.open(req, timeout=REQUEST_TIMEOUT) as resp:
                    lm = resp.headers.get("Last-Modified")
                    if lm:
                        self._last_modified_header = lm
                    content = resp.read().decode("utf-8", errors="ignore")

                new_vids, new_prefixes, new_hosts = set(), [], set()
                for raw in content.splitlines():
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("vid:"):
                        vid = line.split(":", 1)[1].strip()
                        if vid:
                            new_vids.add(vid)
                    elif line.startswith("re:"):
                        try:
                            cre = re.compile(line.split(":", 1)[1].strip())
                            new_prefixes.append(("__regex__", cre))
                        except re.error:
                            ctx.log.warn(f"agent: invalid regex: {line}")
                    elif "/" in line:
                        host_part, path_part = line.split("/", 1)
                        new_prefixes.append((host_part.strip(), "/" + path_part.strip()))
                    else:
                        new_hosts.add(line.strip())

                with self._lock:
                    self.block_vids     = new_vids
                    self.block_prefixes = new_prefixes
                    self.block_hosts    = new_hosts

                ctx.log.info(
                    f"agent: blocklist loaded -- vids={len(new_vids)} "
                    f"prefixes={len(new_prefixes)} hosts={len(new_hosts)}"
                )
                return

            except urllib.error.HTTPError as e:
                if e.code == 304:
                    return   # not modified
                ctx.log.warn(f"agent: HTTPError {e.code} fetching blocklist")
            except urllib.error.URLError as e:
                ctx.log.warn(f"agent: URLError fetching blocklist: {e.reason}")
            except Exception as e:
                ctx.log.warn(f"agent: unexpected error: {e}")

            if attempt <= MAX_RETRIES:
                time.sleep(RETRY_BACKOFF ** attempt)

        ctx.log.warn("agent: blocklist fetch exhausted -- keeping previous rules")

    # -- Logging ---------------------------------------------------------------

    def _get_log_path(self):
        return LOG_PATH if os.path.isabs(LOG_PATH) else os.path.join(
            os.path.dirname(__file__), LOG_PATH
        )

    def _write_log(self, payload: dict):
        path = self._get_log_path()
        parent = os.path.dirname(path)
        try:
            if parent:
                os.makedirs(parent, exist_ok=True)
        except Exception:
            pass
        try:
            with self._lock:
                # Rotate before this grows unbounded (it's appended to on every
                # request with no cleanup otherwise). Truncate in place rather
                # than rename/delete -- to-server.py has this file open for
                # tailing in a separate process, and Windows won't let another
                # process rename or delete a file that's currently open.
                # to-server.py detects the truncation (file got smaller than
                # its read position) and re-seeks to the start on its own.
                try:
                    if os.path.exists(path) and os.path.getsize(path) >= MAX_LOG_BYTES:
                        open(path, "w", encoding="utf-8").close()
                except Exception:
                    pass
                with open(path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(payload, ensure_ascii=False) + "\n")
        except Exception as e:
            ctx.log.warn(f"agent: log write failed: {e}")

    def _emit_log(self, flow, event_type: str, blocked=False, extra: dict = None):
        if extra is None:
            extra = {}
        req    = flow.request
        parsed = urlparse(req.pretty_url) if req else None
        ip, port = self._client_addr(flow)
        headers  = {}
        try:
            headers = dict(req.headers) if req and req.headers else {}
        except Exception:
            pass

        payload = {
            "timestamp":       time.time(),
            "timestamp_iso":   time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "event":           event_type,
            "endpoint_ip":     ENDPOINT_IP,
            "endpoint_hostname": ENDPOINT_HOSTNAME,
            "client_ip":       ip,
            "client_port":     port,
            "host":          parsed.hostname if parsed else (req.host if req else None),
            "url":           req.pretty_url if req else None,
            "method":        req.method if req else None,
            "path":          parsed.path if parsed else None,
            "query":         parse_qs(parsed.query) if parsed else {},
            "user_agent":    req.headers.get("user-agent") if req else None,
            "referer":       req.headers.get("referer") if req else None,
            "blocked":       bool(blocked),
            "counters_snapshot": dict(self.counters),
        }
        payload.update(extra)
        self._write_log(payload)

    def _client_addr(self, flow):
        try:
            addr = flow.client_conn.address
            if isinstance(addr, (list, tuple)) and len(addr) >= 2:
                return addr[0], addr[1]
        except Exception:
            pass
        try:
            peer = getattr(flow.client_conn, "peername", None)
            if isinstance(peer, (list, tuple)) and len(peer) >= 2:
                return peer[0], peer[1]
        except Exception:
            pass
        return None, None

    # -- Block response --------------------------------------------------------

    def _blocked_response(self, flow, reason="blocked"):
        accept = flow.request.headers.get("accept", "")
        if "application/json" in accept:
            body    = json.dumps({"error": "blocked", "reason": reason}).encode()
            headers = {"Content-Type": "application/json"}
        else:
            body    = (
                f"<html><body><h1>Blocked by SecEoKnight</h1>"
                f"<p>{reason}</p></body></html>"
            ).encode()
            headers = {"Content-Type": "text/html; charset=utf-8"}
        flow.response = make_response(403, body, headers)

    # -- Watch path helper -----------------------------------------------------

    def _is_watch_path(self, path: str):
        return path == "/watch" or path.startswith("/watch/") or path.startswith("/watch?")

    # -- Main request handler --------------------------------------------------

    def request(self, flow: http.HTTPFlow):
        self._load_blocklist()   # no-op if cache is fresh

        req    = flow.request
        if not req:
            return
        parsed = urlparse(req.pretty_url)
        host   = (parsed.hostname or "").lower()
        path   = parsed.path or "/"
        query  = parse_qs(parsed.query or "")

        # 0) Trusted update infrastructure -- always allowed, before any
        # blocklist rule gets a chance to match. Without this, the default
        # regex rule that blocks script/executable downloads (.ps1, .exe,
        # .bat, etc. -- see scripts/add_default_blocklist.py) also blocks
        # setup.ps1 itself and the endpoint's own update files once mitmproxy
        # is active and protecting the machine, since they're served from
        # these same domains. That's a real bootstrapping trap: a machine
        # this tool protects can no longer fetch its own updates. Confirmed
        # in production 2026-08-21 -- Invoke-WebRequest for setup.ps1 got
        # blocked with "Regex rule matched" on an already-protected machine.
        UPDATE_SOURCE_HOSTS = (
            "raw.githubusercontent.com",
            "github.com",
            "codeload.github.com",
            "objects.githubusercontent.com",
        )
        if any(host == h or host.endswith("." + h) for h in UPDATE_SOURCE_HOSTS):
            with self._lock:
                self.counters["allowed"] += 1
            return

        # 1) YouTube watch page -- block by video ID
        if self._is_watch_path(path):
            vlist = query.get("v", [])
            if vlist and vlist[0] in self.block_vids:
                vid = vlist[0]
                with self._lock:
                    self.counters["blocked_watch"] += 1
                self._emit_log(flow, "blocked_watch", blocked=True,
                               extra={"block_type": "watch", "matched_vid": vid})
                self._blocked_response(flow, reason=f"Video {vid} is blocked")
                return

        # 2) YouTube internal API -- block by video ID in request body
        if host.endswith("youtube.com") and (
            "/youtubei/v1/player" in path or "/youtubei/v1/next" in path
        ):
            try:
                if req.content:
                    body      = req.content.decode("utf-8", errors="ignore")
                    found_vid = None
                    ctype     = req.headers.get("content-type", "")
                    if "application/json" in ctype:
                        try:
                            obj   = json.loads(body)
                            stack = [obj]
                            while stack and not found_vid:
                                node = stack.pop()
                                if isinstance(node, dict):
                                    for k, v in node.items():
                                        if k == "videoId" and isinstance(v, str) \
                                                and v in self.block_vids:
                                            found_vid = v
                                            break
                                        stack.append(v)
                                elif isinstance(node, list):
                                    stack.extend(node)
                        except Exception:
                            pass
                    if not found_vid:
                        for vid in self.block_vids:
                            if f'"videoId":"{vid}"' in body or \
                               f'"videoId": "{vid}"' in body:
                                found_vid = vid
                                break
                    if found_vid:
                        with self._lock:
                            self.counters["blocked_api"] += 1
                        self._emit_log(flow, "blocked_api", blocked=True,
                                       extra={"block_type": "youtube_api",
                                              "matched_vid": found_vid})
                        self._blocked_response(flow, reason=f"API call for {found_vid} blocked")
                        return
            except Exception as e:
                ctx.log.debug(f"agent: API parse failed: {e}")

        # 3) CDN hosts -- only block when referer contains a blocked video
        if any(host.endswith(p) for p in SUSPICIOUS_CDN_HOSTS):
            referer = req.headers.get("referer", "")
            if referer:
                try:
                    rps   = urlparse(referer)
                    rq    = parse_qs(rps.query or "")
                    rv    = rq.get("v", [])
                    if rv and rv[0] in self.block_vids:
                        vid = rv[0]
                        with self._lock:
                            self.counters["blocked_cdn_referer"] += 1
                        self._emit_log(flow, "blocked_cdn_referer", blocked=True,
                                       extra={"block_type": "cdn_referer",
                                              "matched_vid": vid, "referer": referer})
                        self._blocked_response(flow, reason=f"CDN for video {vid} blocked")
                        return
                except Exception:
                    pass
            with self._lock:
                self.counters["allowed"] += 1
            self._emit_log(flow, "allowed_cdn", blocked=False,
                           extra={"note": "cdn allowed -- no blocked referer"})
            return

        # 4) Host-only rules
        for bh in list(self.block_hosts):
            if host == bh or host.endswith("." + bh):
                with self._lock:
                    self.counters["blocked_host"] += 1
                self._emit_log(flow, "blocked_host", blocked=True,
                               extra={"block_type": "host", "block_rule": bh})
                self._blocked_response(flow, reason=f"Host {host} is blocked")
                return

        # 5) Prefix and regex rules
        for entry in list(self.block_prefixes):
            if entry[0] == "__regex__":
                cre = entry[1]
                try:
                    if cre.search(req.pretty_url):
                        with self._lock:
                            self.counters["blocked_regex"] += 1
                        self._emit_log(flow, "blocked_regex", blocked=True,
                                       extra={"block_type": "regex",
                                              "block_rule": cre.pattern})
                        self._blocked_response(flow, reason="Regex rule matched")
                        return
                except re.error:
                    pass
            else:
                host_part, path_prefix = entry
                if (host == host_part or host.endswith("." + host_part)) \
                        and path.startswith(path_prefix):
                    with self._lock:
                        self.counters["blocked_prefix"] += 1
                    rule = f"{host_part}{path_prefix}"
                    self._emit_log(flow, "blocked_prefix", blocked=True,
                                   extra={"block_type": "prefix", "block_rule": rule})
                    self._blocked_response(flow, reason=f"Prefix rule {rule} matched")
                    return

        # Default -- allowed
        with self._lock:
            self.counters["allowed"] += 1
        self._emit_log(flow, "allowed", blocked=False)

    # -- Stats endpoint --------------------------------------------------------

    def response(self, flow: http.HTTPFlow):
        parsed = urlparse(flow.request.pretty_url)
        if parsed.path == "/__blocker_stats":
            stats = {"counts": self.counters,
                     "blocked_vids": sorted(list(self.block_vids))}
            flow.response = make_response(
                200, json.dumps(stats, indent=2).encode(),
                {"Content-Type": "application/json"}
            )


addons = [VideoBlockerSafe()]
