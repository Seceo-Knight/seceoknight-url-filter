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
from urllib.parse import urlparse, parse_qs, quote as _urlquote
import time
import os
import re
import json
import socket
import urllib.request
import urllib.error
import threading
import hashlib


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
BLOCKLIST_URL       = f"http://{SERVER_IP}:{SERVER_PORT}/blocklist"
AGENT_CONFIG_URL    = f"http://{SERVER_IP}:{SERVER_PORT}/api/agents/config"
AGENT_UPDATE_HASH_URL     = f"http://{SERVER_IP}:{SERVER_PORT}/agent-update/hash"
AGENT_UPDATE_DOWNLOAD_URL = f"http://{SERVER_IP}:{SERVER_PORT}/agent-update/download"
AUTO_UPDATE_ENABLED = True   # set False on a machine to pin its current agent.py version

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
HANDLE_CACHE_CAP = 500   # bounded LRU-ish cap for the passively-learned @handle -> UC id map

# Injected into youtube.com HTML pages (see _maybe_inject_overlay). YouTube is
# a single-page app: clicking a blocked video from search results, the
# homepage, or a related-videos sidebar updates the address bar via
# history.pushState() WITHOUT sending a fresh request to /watch -- the actual
# blocking happens on the background youtubei API call instead, which the
# user never sees a 403 page for (it's not a navigation, it's a fetch()).
# Without this, a user just sees a broken/half-loaded player with no
# explanation. This script polls a short-lived cookie that _blocked_response
# sets on every block (including background API blocks) and shows a real
# block screen the instant it appears, regardless of how the block happened.
OVERLAY_SCRIPT = """
<script>(function(){
  function getCookie(name){
    var pairs=document.cookie.split(";");
    for (var i=0;i<pairs.length;i++){
      var p=pairs[i].trim();
      if (p.indexOf(name+"=")===0) return decodeURIComponent(p.substring(name.length+1));
    }
    return null;
  }
  function clearCookie(name){
    document.cookie=name+"=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT";
  }
  function showOverlay(msg){
    if (document.getElementById("__seb_overlay")) return;
    var el=document.createElement("div");
    el.id="__seb_overlay";
    el.style.cssText="position:fixed;inset:0;z-index:2147483647;background:#0b0f14;color:#fff;"
      +"display:flex;flex-direction:column;align-items:center;justify-content:center;"
      +"font-family:-apple-system,Segoe UI,Roboto,sans-serif;text-align:center;padding:24px;";
    el.innerHTML="<div style='font-size:40px;margin-bottom:12px;'>&#128737;</div>"
      +"<h1 style='margin:0 0 8px;font-size:22px;'>Blocked by SecEoKnight</h1>"
      +"<p style='margin:0;opacity:.75;font-size:14px;max-width:480px;'>"+msg+"</p>";
    (document.documentElement||document.body).appendChild(el);
  }
  function poll(){
    var v=getCookie("__seb_block");
    if (v){ showOverlay(v); clearCookie("__seb_block"); }
  }
  setInterval(poll,200);
  poll();
})();</script>
"""
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
            "blocked_channel": 0,
            "allowed": 0,
        }
        self.block_channels = set()   # UC ids and/or "@handle" strings, from `channel:` rules
        self.handle_to_uc   = {}      # passively learned "@handle" -> "UC..." (see _learn_handle_from_browse)
        self._lock           = threading.Lock()
        self._last_load_time = 0

        # enforce (default, block+log) / monitor (log-only, don't actually
        # block) / disabled (pure passthrough, don't even log as blocked).
        # Set per-machine from the dashboard; polled every RELOAD_INTERVAL
        # alongside the blocklist so a change takes effect within ~30s.
        self.agent_mode              = "enforce"
        self._last_config_load_time  = 0
        self._last_update_check_time = 0

        try:
            self._load_blocklist(force=True)
        except Exception:
            ctx.log.warn("agent: initial blocklist load failed -- continuing")
        try:
            self._load_agent_config(force=True)
        except Exception:
            ctx.log.warn("agent: initial agent-config load failed -- defaulting to enforce")

    # -- Per-agent mode (enforce / monitor / disabled) --------------------------

    def _load_agent_config(self, force=False):
        now = time.time()
        if not force and (now - self._last_config_load_time) < RELOAD_INTERVAL:
            return
        self._last_config_load_time = now
        try:
            req_headers = {"User-Agent": "SecEoKnight-Agent/1.0"}
            if API_KEY:
                req_headers["X-API-Key"] = API_KEY
            url = f"{AGENT_CONFIG_URL}?hostname={ENDPOINT_HOSTNAME}"
            req = urllib.request.Request(url, headers=req_headers)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=REQUEST_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            mode = data.get("mode", "enforce")
            if mode not in ("enforce", "monitor", "disabled"):
                mode = "enforce"
            with self._lock:
                self.agent_mode = mode
        except Exception as e:
            ctx.log.debug(f"agent: config fetch failed, keeping mode={self.agent_mode}: {e}")

    # -- Self-update -------------------------------------------------------------
    # Solves the "manual machine-by-machine PowerShell rollout" problem: this
    # machine's own agent.py checks its SHA-256 against the server's copy
    # every RELOAD_INTERVAL, and if they differ, downloads and overwrites
    # itself, then exits. NSSM (AppRestartDelay, set up by setup.ps1) brings
    # the mitmdump service back up automatically, loading the new file --
    # no PowerShell or manual action needed on the endpoint.

    def _check_for_update(self, force=False):
        if not AUTO_UPDATE_ENABLED:
            return
        now = time.time()
        if not force and (now - self._last_update_check_time) < RELOAD_INTERVAL:
            return
        self._last_update_check_time = now
        try:
            req_headers = {"User-Agent": "SecEoKnight-Agent/1.0"}
            if API_KEY:
                req_headers["X-API-Key"] = API_KEY
            req = urllib.request.Request(AGENT_UPDATE_HASH_URL, headers=req_headers)
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=REQUEST_TIMEOUT) as resp:
                remote = json.loads(resp.read().decode("utf-8", errors="ignore"))
            remote_hash = remote.get("sha256", "")

            with open(__file__, "rb") as f:
                local_content = f.read()
            local_hash = hashlib.sha256(local_content).hexdigest()

            if not remote_hash or remote_hash == local_hash:
                return   # up to date

            ctx.log.info(f"agent: update available (local {local_hash[:8]} -> remote {remote_hash[:8]}), downloading")
            dl_req = urllib.request.Request(AGENT_UPDATE_DOWNLOAD_URL, headers=req_headers)
            with opener.open(dl_req, timeout=REQUEST_TIMEOUT) as resp:
                new_content = resp.read()

            if not new_content or len(new_content) < 1000:
                ctx.log.warn("agent: downloaded update looks truncated -- refusing to install")
                return
            try:
                compile(new_content, "agent.py", "exec")   # sanity check it's valid Python before installing
            except SyntaxError as e:
                ctx.log.warn(f"agent: downloaded update failed to compile -- refusing to install: {e}")
                return

            with open(__file__, "wb") as f:
                f.write(new_content)
            ctx.log.info("agent: update installed, restarting to load it (NSSM will bring the service back up)")
            os._exit(0)
        except Exception as e:
            ctx.log.debug(f"agent: update check failed: {e}")

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

                new_vids, new_prefixes, new_hosts, new_channels = set(), [], set(), set()
                for raw in content.splitlines():
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("vid:"):
                        vid = line.split(":", 1)[1].strip()
                        if vid:
                            new_vids.add(vid)
                    elif line.startswith("channel:"):
                        chan = line.split(":", 1)[1].strip()
                        if chan:
                            new_channels.add(chan)
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
                    self.block_channels = new_channels

                ctx.log.info(
                    f"agent: blocklist loaded -- vids={len(new_vids)} "
                    f"prefixes={len(new_prefixes)} hosts={len(new_hosts)} "
                    f"channels={len(new_channels)}"
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
        # Surface this to the dashboard through the normal log pipeline
        # (to-server.py tails LOG_PATH and ships it same as any other event)
        # rather than a separate channel -- an agent silently running a
        # stale blocklist is worth an admin noticing.
        self._write_log({
            "timestamp":       time.time(),
            "timestamp_iso":   time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "event":           "blocklist_fetch_failed",
            "endpoint_ip":     ENDPOINT_IP,
            "endpoint_hostname": ENDPOINT_HOSTNAME,
            "blocked":         False,
            "note":            f"exhausted {MAX_RETRIES} retries fetching {BLOCKLIST_URL}",
        })

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
        # monitor mode: every call site above this already incremented the
        # blocked_* counter and emitted a blocked=True log entry -- that's
        # exactly the "log it as if it were blocked" behavior monitor mode
        # wants. The only thing monitor mode changes is this: don't actually
        # set flow.response, so the real request still goes through.
        if self.agent_mode == "monitor":
            return
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
        # Short-lived JS-readable cookie so the overlay script injected by
        # _maybe_inject_overlay can detect this block even when it happened
        # on a background API call the user never directly sees (see the
        # OVERLAY_SCRIPT comment above for why that matters on YouTube).
        headers["Set-Cookie"] = f"__seb_block={_urlquote(reason)[:200]}; Path=/; Max-Age=10; SameSite=Lax"
        flow.response = make_response(403, body, headers)

    # -- Watch path helper -----------------------------------------------------

    def _is_watch_path(self, path: str):
        return path == "/watch" or path.startswith("/watch/") or path.startswith("/watch?")

    # -- Channel blocking helper -------------------------------------------------
    # `value` can be a UC channel id (as seen in a youtubei API body's
    # "channelId" field, or in a /channel/UC... URL) or an "@handle" (as seen
    # in a /@handle URL). A channel: rule is written as either form -- match
    # directly first, then fall back to the passively-learned handle -> UC
    # mapping so a `channel:@handle` rule still catches API calls that only
    # carry the UC id (which is what YouTube's internal API almost always
    # uses, regardless of what the user typed in the address bar).

    def _is_channel_blocked(self, value: str) -> bool:
        if not value:
            return False
        if value in self.block_channels:
            return True
        if value.startswith("UC"):
            for handle, uc in list(self.handle_to_uc.items()):
                if uc == value and handle in self.block_channels:
                    return True
        return False

    # -- Main request handler --------------------------------------------------

    def request(self, flow: http.HTTPFlow):
        self._load_blocklist()      # no-op if cache is fresh
        self._load_agent_config()   # no-op if cache is fresh
        self._check_for_update()    # no-op if cache is fresh or already up to date

        # disabled mode: pure passthrough -- don't block, don't even log as
        # blocked (agent still counts it as "allowed" so traffic totals stay
        # sane). Checked before parsing the URL since there's nothing else to
        # do in this mode.
        if self.agent_mode == "disabled":
            with self._lock:
                self.counters["allowed"] += 1
            return

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

        # 1b) YouTube channel page -- block by channel ID or @handle
        if host.endswith("youtube.com") and (path.startswith("/@") or path.startswith("/channel/")):
            channel_key = None
            if path.startswith("/@"):
                # path is like /@mkbhd or /@mkbhd/videos -- take just the handle
                channel_key = "@" + path[2:].split("/", 1)[0]
            else:
                channel_key = path[len("/channel/"):].split("/", 1)[0]
            if channel_key and self._is_channel_blocked(channel_key):
                with self._lock:
                    self.counters["blocked_channel"] += 1
                self._emit_log(flow, "blocked_channel", blocked=True,
                               extra={"block_type": "channel", "matched_channel": channel_key})
                self._blocked_response(flow, reason=f"Channel {channel_key} is blocked")
                return

        # 2) YouTube internal API -- block by video ID or channel ID in request body
        if host.endswith("youtube.com") and (
            "/youtubei/v1/player" in path or "/youtubei/v1/next" in path
        ):
            try:
                if req.content:
                    body          = req.content.decode("utf-8", errors="ignore")
                    found_vid     = None
                    found_channel = None
                    ctype         = req.headers.get("content-type", "")
                    if "application/json" in ctype:
                        try:
                            obj   = json.loads(body)
                            stack = [obj]
                            while stack and not found_vid and not found_channel:
                                node = stack.pop()
                                if isinstance(node, dict):
                                    for k, v in node.items():
                                        if k == "videoId" and isinstance(v, str) \
                                                and v in self.block_vids:
                                            found_vid = v
                                            break
                                        if k == "channelId" and isinstance(v, str) \
                                                and self._is_channel_blocked(v):
                                            found_channel = v
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
                    if not found_vid and not found_channel:
                        for chan in self.block_channels:
                            if chan.startswith("UC") and (
                                f'"channelId":"{chan}"' in body or
                                f'"channelId": "{chan}"' in body
                            ):
                                found_channel = chan
                                break
                    if found_vid:
                        with self._lock:
                            self.counters["blocked_api"] += 1
                        self._emit_log(flow, "blocked_api", blocked=True,
                                       extra={"block_type": "youtube_api",
                                              "matched_vid": found_vid})
                        self._blocked_response(flow, reason=f"API call for {found_vid} blocked")
                        return
                    if found_channel:
                        with self._lock:
                            self.counters["blocked_channel"] += 1
                        self._emit_log(flow, "blocked_channel", blocked=True,
                                       extra={"block_type": "channel_api",
                                              "matched_channel": found_channel})
                        self._blocked_response(flow, reason=f"Channel {found_channel} is blocked")
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
                     "blocked_vids": sorted(list(self.block_vids)),
                     "blocked_channels": sorted(list(self.block_channels))}
            flow.response = make_response(
                200, json.dumps(stats, indent=2).encode(),
                {"Content-Type": "application/json"}
            )
            return

        try:
            self._maybe_inject_overlay(flow, parsed)
        except Exception as e:
            ctx.log.debug(f"agent: overlay injection failed: {e}")

        # Passively learn @handle -> UC channel-id mappings from YouTube's
        # /browse API responses (fired when a channel page loads). This is
        # what lets a `channel:@handle` rule catch blocking via the
        # youtubei API body, which carries the UC id, not the handle --
        # YouTube's internal API works in UC ids almost everywhere.
        try:
            host = (parsed.hostname or "").lower()
            if host.endswith("youtube.com") and "/youtubei/v1/browse" in parsed.path \
                    and flow.response is not None and flow.response.content:
                self._learn_handle_from_browse(flow)
        except Exception as e:
            ctx.log.debug(f"agent: handle-learning failed: {e}")

    def _learn_handle_from_browse(self, flow):
        if len(self.handle_to_uc) >= HANDLE_CACHE_CAP:
            return
        try:
            body = flow.response.content.decode("utf-8", errors="ignore")
            obj  = json.loads(body)
        except Exception:
            return

        uc_id, handle = None, None
        stack = [obj]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                cmr = node.get("channelMetadataRenderer")
                if isinstance(cmr, dict):
                    uc_id = cmr.get("externalId") or uc_id
                    vanity = cmr.get("vanityChannelUrl") or ""
                    if "/@" in vanity:
                        handle = "@" + vanity.split("/@", 1)[1].strip("/")
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)

        if uc_id and handle:
            with self._lock:
                self.handle_to_uc[handle] = uc_id
            ctx.log.debug(f"agent: learned channel mapping {handle} -> {uc_id}")

    def _maybe_inject_overlay(self, flow, parsed):
        """Inject OVERLAY_SCRIPT into youtube.com HTML pages so an in-app
        block (a background API call the user never sees a 403 for) still
        shows a real block screen instead of silently failing. Skipped
        entirely in monitor/disabled mode -- there's nothing to react to
        since those modes never set the block cookie."""
        if self.agent_mode != "enforce":
            return
        host = (parsed.hostname or "").lower()
        if not host.endswith("youtube.com"):
            return
        resp = flow.response
        if not resp or not resp.content:
            return
        ctype = resp.headers.get("content-type", "")
        if "text/html" not in ctype:
            return
        try:
            html = resp.text
        except Exception:
            return
        if "__seb_overlay" in html:
            return   # already injected -- avoid double-injecting on retried flows
        if "</body>" in html:
            resp.text = html.replace("</body>", OVERLAY_SCRIPT + "</body>", 1)
        elif "</html>" in html:
            resp.text = html.replace("</html>", OVERLAY_SCRIPT + "</html>", 1)


addons = [VideoBlockerSafe()]
