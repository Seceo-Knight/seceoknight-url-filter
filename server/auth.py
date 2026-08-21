"""
auth.py
API key authentication for the SecEoKnight unified server.

Rollout is grace-period based on purpose -- this server already has ~50 live
endpoints, a Chrome extension, and the SIEM dashboard talking to it. Flipping
hard authentication on instantly would break all of them until every single
one is manually updated, which is exactly the kind of self-inflicted outage
this deployment has already hit twice with install.sh. Instead:

  SECEOKNIGHT_API_KEY unset
    -> Auth fully disabled. This is the default on a fresh install before
       the admin has generated/configured a key -- nothing is enforced.

  SECEOKNIGHT_API_KEY set, SECEOKNIGHT_REQUIRE_API_KEY unset/false (default)
    -> "Grace period." The key is accepted if sent, but a request without it
       (or with the wrong one) is still let through -- just logged as a
       warning. This is the state to deploy in FIRST, so you can update
       every agent/extension/dashboard on your own schedule and watch the
       warnings disappear from the logs as each one starts sending the key.

  SECEOKNIGHT_REQUIRE_API_KEY=true
    -> Enforced. Requests without the correct key are rejected with 401.
       Only flip this once you've confirmed (via the logs, or simply by
       giving it a few days with no more grace-period warnings) that every
       client has been updated.
"""

import os
import time
from fastapi import Header, HTTPException, Request

API_KEY = os.environ.get("SECEOKNIGHT_API_KEY", "")
REQUIRE_API_KEY = os.environ.get("SECEOKNIGHT_REQUIRE_API_KEY", "false").strip().lower() == "true"

# Throttled PER SOURCE (client IP + path), not globally -- a single global
# throttle collapsed every offender into one generic message, making it
# impossible to tell which machine (or the dashboard) was still missing the
# key. Keyed per source so each distinct offender surfaces on its own,
# still capped to once per 5 minutes each so a busy source doesn't flood
# the journal.
_last_warn_by_source: dict[str, float] = {}
_WARN_INTERVAL_SEC = 300


def _grace_period_warn(source: str):
    now = time.time()
    last = _last_warn_by_source.get(source, 0.0)
    if now - last > _WARN_INTERVAL_SEC:
        print(
            f"[AUTH] WARNING: request without a valid X-API-Key header from {source}. "
            "Currently ALLOWED (grace period). Update that source to send the key, then "
            "set SECEOKNIGHT_REQUIRE_API_KEY=true in the server's .env once no more of "
            "these warnings appear."
        )
        _last_warn_by_source[source] = now


def verify_api_key(request: Request, x_api_key: str = Header(default="", alias="X-API-Key")) -> bool:
    """FastAPI dependency -- add `_auth: bool = Depends(verify_api_key)` to any route."""
    if not API_KEY:
        return True  # no key configured yet -- nothing to enforce
    if x_api_key == API_KEY:
        return True
    if REQUIRE_API_KEY:
        raise HTTPException(status_code=401, detail="Missing or invalid X-API-Key header")
    client_ip = request.client.host if request.client else "unknown"
    _grace_period_warn(f"{client_ip} -> {request.method} {request.url.path}")
    return True


def check_ws_api_key(supplied_key: str, client_ip: str = "unknown") -> bool:
    """Same logic as verify_api_key, for the /ws/alerts WebSocket route, which
    can't use a header-based FastAPI dependency the same way -- the key is
    passed as a ?api_key= query parameter on the connection URL instead."""
    if not API_KEY:
        return True
    if supplied_key == API_KEY:
        return True
    if REQUIRE_API_KEY:
        return False
    _grace_period_warn(f"{client_ip} -> WS /ws/alerts")
    return True
