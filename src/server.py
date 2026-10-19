"""HTTP server: serves the SPA + small JSON API for the listener."""
from __future__ import annotations
import atexit
import ipaddress
import os
import signal
import socket
import urllib.parse
import webbrowser
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from . import store, notify
from .listener import Hit, Listener


REPO_ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = REPO_ROOT / "web"

# Server is bound to loopback. Anything outside loopback is rejected at the
# middleware level — defense in depth in case a future change accidentally
# binds to 0.0.0.0.
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
ALLOWED_CLIENTS = {"127.0.0.1", "::1"}

# Optional remote access over Tailscale, opt-in via env:
#   PING_TAILSCALE_BIND=<this machine's Tailscale IP>   also listen there
#   PING_TAILSCALE_CLIENTS=<ip>[,<ip>...]               peers allowed to connect
# Only Tailscale CGNAT addresses (100.64.0.0/10) are accepted, so this can never
# expose the page on the LAN or 0.0.0.0. There is no login, so keep the client
# list to your own devices.
TAILSCALE_NET = ipaddress.ip_network("100.64.0.0/10")


def _tailscale_ips(raw: str) -> list[str]:
    out = []
    for part in raw.replace(",", " ").split():
        try:
            if ipaddress.ip_address(part) in TAILSCALE_NET:
                out.append(part)
        except ValueError:
            pass
    return out


TAILSCALE_BIND = next(iter(_tailscale_ips(os.environ.get("PING_TAILSCALE_BIND", ""))), "")
if TAILSCALE_BIND:
    ALLOWED_HOSTS.add(TAILSCALE_BIND)
    ALLOWED_CLIENTS.update(_tailscale_ips(os.environ.get("PING_TAILSCALE_CLIENTS", "")))

app = FastAPI(title="ping-me-when", docs_url=None, redoc_url=None)

_listener: Optional[Listener] = None


@app.middleware("http")
async def csrf_and_host_guard(request: Request, call_next):
    """Lightweight CSRF + host-pinning protection.

    1. Reject anything where the Host header isn't a loopback name. This stops
       DNS-rebinding attacks where a malicious site tricks the browser into
       sending requests to our server.
    2. For state-changing methods, require a JSON Content-Type. Stops naive
       cross-origin <form> POSTs (which use application/x-www-form-urlencoded).
    """
    client = request.client.host if request.client else ""
    if client not in ALLOWED_CLIENTS:
        return JSONResponse({"detail": "client not allowed"}, status_code=403)
    host = (request.headers.get("host") or "").split(":")[0].lower()
    if host not in ALLOWED_HOSTS:
        return JSONResponse({"detail": "host not allowed"}, status_code=400)
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        ct = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
        # Allow empty body POSTs (start/stop/test-notify) too.
        cl = request.headers.get("content-length") or "0"
        if cl != "0" and ct != "application/json":
            return JSONResponse({"detail": "json required"}, status_code=415)
    return await call_next(request)


def _on_hit(h: Hit) -> None:
    cfg = store.load()
    # `label` (if set) acts as the channel's display alias; otherwise fall back
    # to the live channel name, then to a short ID suffix.
    where = h.sub.label or (f"#{h.channel_name}" if h.channel_name else f"#{h.channel_id[-6:]}")
    title = f"{h.author} in {where}"
    body = h.content.strip() or "(image / embed only)"
    # Route via the profile that matched this hit, falling back to the first
    # profile if for some reason the name no longer resolves (e.g. renamed mid-run).
    profile = cfg.profile_by_name(h.profile_name) or (cfg.profiles[0] if cfg.profiles else None)
    if profile is None:
        return
    n = profile.notify
    notify.dispatch(
        title=f"📨 {title}",
        message=body,
        mac=n.mac,
        webhook_url=n.webhook_url or None,
        telegram_bot_token=n.telegram_bot_token or None,
        telegram_chat_id=n.telegram_chat_id or None,
        open_url=h.discord_url(),
    )


# ---------- API ----------

class SubscriptionIn(BaseModel):
    channel_id: str = Field(min_length=1, max_length=32)
    # 30 usernames per channel is more than enough for any realistic use.
    usernames: list[str] = Field(default_factory=list, max_length=30)
    label: str = Field(default="", max_length=120)
    enabled: bool = True
    require_digit: bool = False
    include_any: list[str] = Field(default_factory=list, max_length=50)
    exclude_any: list[str] = Field(default_factory=list, max_length=50)
    regex: str = Field(default="", max_length=200)

    @field_validator("channel_id")
    @classmethod
    def _channel_digits(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit():
            raise ValueError("channel_id must be a numeric Discord snowflake")
        return v

    @field_validator("usernames")
    @classmethod
    def _validate_usernames(cls, v: list[str]) -> list[str]:
        cleaned = []
        for u in v:
            u = (u or "").strip()
            if not u:
                continue
            if len(u) > 64:
                raise ValueError(f"username too long: {u[:20]}…")
            cleaned.append(u)
        if not cleaned:
            raise ValueError("at least one username required")
        return cleaned

    @field_validator("include_any", "exclude_any")
    @classmethod
    def _clean_words(cls, v: list[str]) -> list[str]:
        out = []
        for w in v or []:
            w = (w or "").strip()
            if w and len(w) <= 100:
                out.append(w)
        return out

    @field_validator("regex")
    @classmethod
    def _validate_regex(cls, v: str) -> str:
        import re as _re
        v = (v or "").strip()
        if not v:
            return ""
        try:
            _re.compile(v)
        except _re.error as e:
            raise ValueError(f"invalid regex: {e}")
        return v


class NotifyIn(BaseModel):
    mac: bool = True
    webhook_url: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    @field_validator("webhook_url")
    @classmethod
    def _validate_webhook(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            return ""
        try:
            parsed = urllib.parse.urlparse(v)
        except Exception:
            raise ValueError("invalid URL")
        if parsed.scheme != "https":
            raise ValueError("webhook URL must be https://")
        # Discord-only — narrow surface, easy to verify. Accept both the modern
        # discord.com and the legacy discordapp.com host that Discord still serves.
        host = parsed.netloc.lower()
        allowed = ("discord.com", "discordapp.com")
        if not (host in allowed or any(host.endswith("." + d) for d in allowed)):
            raise ValueError("only discord.com webhooks are allowed")
        return v

    @field_validator("telegram_bot_token", "telegram_chat_id")
    @classmethod
    def _trim(cls, v: str) -> str:
        return (v or "").strip()


class ProfileIn(BaseModel):
    name: str = Field(default="Default", max_length=60)
    # 50 subscriptions per profile keeps the cap roughly where it was overall.
    subscriptions: list[SubscriptionIn] = Field(default_factory=list, max_length=50)
    notify: NotifyIn = Field(default_factory=NotifyIn)

    @field_validator("name")
    @classmethod
    def _clean_name(cls, v: str) -> str:
        v = (v or "").strip() or "Default"
        return v


class ConfigIn(BaseModel):
    token: str = Field(default="", max_length=200)
    # 20 profiles is plenty; cap stops accidental DoS via the API.
    profiles: list[ProfileIn] = Field(default_factory=list, max_length=20)


@app.get("/api/config")
def get_config():
    cfg = store.load()
    return {
        "token_set": bool(cfg.token),
        "profiles": [
            {
                "name": p.name,
                "subscriptions": [s.__dict__ for s in p.subscriptions],
                "notify": p.notify.__dict__,
            }
            for p in cfg.profiles
        ],
    }


@app.post("/api/config")
def post_config(payload: ConfigIn):
    existing = store.load()
    # Empty token in the payload means "don't touch the saved one" — so users
    # don't have to re-paste their token every time they edit subscriptions.
    new_token = payload.token.strip() or existing.token
    # Deduplicate profile names so the picker stays unambiguous.
    seen: dict[str, int] = {}
    profiles: list[store.Profile] = []
    for pin in payload.profiles:
        name = pin.name
        if name in seen:
            seen[name] += 1
            name = f"{name} ({seen[name]})"
        else:
            seen[name] = 1
        profiles.append(store.Profile(
            name=name,
            subscriptions=[store.Subscription(**s.model_dump()) for s in pin.subscriptions],
            notify=store.Notify(**pin.notify.model_dump()),
        ))
    if not profiles:
        profiles = [store.Profile()]
    cfg = store.Config(token=new_token, profiles=profiles)
    store.save(cfg)
    if _listener:
        _listener.update_config(cfg)
    return {"ok": True}


@app.post("/api/start")
def start():
    global _listener
    cfg = store.load()
    if _listener and _listener._thread and _listener._thread.is_alive():
        return {"ok": True, "already_running": True}
    _listener = Listener(cfg, on_hit=_on_hit)
    _listener.start()
    return {"ok": True}


@app.post("/api/stop")
def stop():
    if _listener:
        _listener.stop()
    return {"ok": True}


@app.get("/api/status")
def status():
    if not _listener:
        return {"running": False, "connected": False, "last_error": "", "hits": []}
    s = _listener.status
    return {
        "running": _listener._thread is not None and _listener._thread.is_alive(),
        "connected": s.connected,
        "last_error": s.last_error,
        "started_at": s.started_at,
        "hits": [
            {
                "label": h.sub.label or h.author,
                "author": h.author,
                "channel_id": h.channel_id,
                "channel_name": h.channel_name,
                "content": h.content,
                "timestamp": h.timestamp,
                "message_id": h.message_id,
                "url": h.discord_url(),
                "profile": h.profile_name,
            } for h in reversed(s.hits[-50:])  # newest first, last 50
        ],
    }


@app.post("/api/test-notify")
def test_notify(profile: Optional[str] = None):
    """Send a test notification.

    Without `profile`, fires once per profile so each tab can be verified at
    once. With `?profile=Name`, targets only that profile.
    """
    cfg = store.load()
    targets = [cfg.profile_by_name(profile)] if profile else cfg.profiles
    targets = [p for p in targets if p is not None]
    if not targets:
        raise HTTPException(404, "profile not found")
    results = []
    for p in targets:
        res = notify.dispatch(
            title=f"ping-me-when test [{p.name}]",
            message="If you see this, notifications are working.",
            mac=p.notify.mac,
            webhook_url=p.notify.webhook_url or None,
            telegram_bot_token=p.notify.telegram_bot_token or None,
            telegram_chat_id=p.notify.telegram_chat_id or None,
        )
        results.append({"profile": p.name, **res})
    return {"ok": True, "results": results}


# ---------- static UI ----------

if WEB_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
def root():
    f = WEB_DIR / "index.html"
    if not f.exists():
        raise HTTPException(500, "web/index.html missing")
    return f.read_text(encoding="utf-8")


def _shutdown():
    """Stop the listener cleanly so we don't leak the WebSocket on exit."""
    global _listener
    if _listener:
        try:
            _listener.stop(join_timeout=2)
        except Exception:
            pass
        _listener = None


@app.on_event("shutdown")
async def _on_shutdown():
    _shutdown()


@app.on_event("startup")
async def _on_startup():
    if os.environ.get("PING_AUTOSTART", "") == "1":
        global _listener
        if not (_listener and _listener._thread and _listener._thread.is_alive()):
            _listener = Listener(store.load(), on_hit=_on_hit)
            _listener.start()


def main():
    """Entry point for `python -m src.server`. Opens a browser tab and serves."""
    import uvicorn
    host = os.environ.get("PING_HOST", "127.0.0.1")
    port = int(os.environ.get("PING_PORT", "8765"))
    # Hard-pin to loopback. No env override here — prevents accidental exposure.
    if host not in ALLOWED_HOSTS:
        host = "127.0.0.1"
    if os.environ.get("PING_NO_BROWSER", "") != "1":
        try:
            webbrowser.open(f"http://{host}:{port}/")
        except Exception:
            pass
    # Belt + suspenders: also catch SIGTERM/SIGINT so the listener gets a chance
    # to close cleanly even if FastAPI's shutdown event doesn't fire.
    atexit.register(_shutdown)
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, lambda *_: _shutdown())
        except (ValueError, OSError):
            # Can fail if not on the main thread (e.g. inside tests).
            pass
    if not TAILSCALE_BIND:
        uvicorn.run(app, host=host, port=port, log_level="info")
        return
    # Serve on loopback and the Tailscale address at once (uvicorn binds one host,
    # so hand it pre-bound sockets).
    sockets = []
    for addr in (host, TAILSCALE_BIND):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((addr, port))
        sockets.append(s)
    uvicorn.Server(uvicorn.Config(app, log_level="info")).run(sockets=sockets)


if __name__ == "__main__":
    main()
