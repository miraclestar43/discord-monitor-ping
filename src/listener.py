"""Discord Gateway listener. One thread per process.

Connects to wss://gateway.discord.gg, identifies as a user with the given token,
heartbeats every 41250ms (or whatever the server tells us), and routes any
MESSAGE_CREATE event whose channel + author matches a configured subscription
to the notification layer.

Scope is intentionally tiny — see README for what we deliberately don't do.
"""
from __future__ import annotations
import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

import websocket  # websocket-client

from .store import Config, Subscription


_DIGIT_RE = re.compile(r"\d")


def _passes_filters(sub: Subscription, content: str) -> bool:
    """Apply per-subscription content filters with OR semantics.

    - exclude_any is always a veto: if any excluded word appears, suppress.
    - require_digit / include_any / regex are positive filters combined with OR:
      if any of them is configured, the message must match at least one.
      If none are configured, all messages pass.
    """
    text = content or ""
    low = text.lower()

    exc = [w.lower() for w in (getattr(sub, "exclude_any", []) or []) if w]
    if exc and any(w in low for w in exc):
        return False

    positive_configured = False
    matched = False

    if getattr(sub, "require_digit", False):
        positive_configured = True
        if _DIGIT_RE.search(text):
            matched = True

    inc = [w.lower() for w in (getattr(sub, "include_any", []) or []) if w]
    if inc:
        positive_configured = True
        if any(w in low for w in inc):
            matched = True

    pat = (getattr(sub, "regex", "") or "").strip()
    if pat:
        positive_configured = True
        try:
            if re.search(pat, text, re.IGNORECASE):
                matched = True
        except re.error:
            # Bad regex: treat as not configured so we don't silently drop everything.
            positive_configured = False

    if not positive_configured:
        return True
    return matched


GATEWAY_URL = "wss://gateway.discord.gg/?v=10&encoding=json"
# Gateway close codes where reconnecting can't succeed: 4004 auth failed,
# 4010-4014 invalid shard / sharding required / invalid or disallowed intents.
FATAL_CLOSE_CODES = {4004, 4010, 4011, 4012, 4013, 4014}
INTENT_GUILD_MESSAGES = 1 << 9
INTENT_MESSAGE_CONTENT = 1 << 15  # only relevant if you ever switch to bot tokens
DEFAULT_INTENTS = INTENT_GUILD_MESSAGES | INTENT_MESSAGE_CONTENT


@dataclass
class Hit:
    """One matched message worth notifying about."""
    sub: Subscription
    author: str
    content: str
    message_id: str
    channel_id: str
    timestamp: str = ""
    channel_name: str = ""  # populated from GUILD_CREATE if known
    guild_id: str = ""
    guild_name: str = ""  # populated from GUILD_CREATE if known
    profile_name: str = ""  # which profile (tab) matched this message

    def discord_url(self) -> str:
        if self.guild_id:
            return f"https://discord.com/channels/{self.guild_id}/{self.channel_id}/{self.message_id}"
        # DM fallback (no guild)
        return f"https://discord.com/channels/@me/{self.channel_id}/{self.message_id}"


@dataclass
class Status:
    connected: bool = False
    last_error: str = ""
    last_hit: Optional[Hit] = None
    hits: list[Hit] = field(default_factory=list)
    started_at: float = 0.0


class Listener:
    """Owns the websocket loop. Public surface: start(), stop(), status."""

    MAX_HISTORY = 200

    def __init__(self, cfg: Config, on_hit: Callable[[Hit], None] | None = None):
        self.cfg = cfg
        self.on_hit = on_hit or (lambda h: None)
        self.status = Status()
        self._ws: Optional[websocket.WebSocketApp] = None
        self._thread: Optional[threading.Thread] = None
        self._heartbeat_thread: Optional[threading.Thread] = None
        self._heartbeat_interval_ms = 41250
        self._last_seq: Optional[int] = None
        self._heartbeat_acked = True
        self._backoff = 1
        self._stop = threading.Event()
        # channel_id -> {"name": str, "guild_id": str}
        # Populated lazily from GUILD_CREATE events.
        self._channel_meta: dict[str, dict] = {}

    # ---- public ----

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        # Reject obvious garbage tokens (empty / pure-whitespace / way-too-short).
        token = (self.cfg.token or "").strip()
        if len(token) < 30:
            raise ValueError("token looks invalid (too short)")
        if not any(p.subscriptions for p in self.cfg.profiles):
            raise ValueError("no subscriptions configured")
        # Reset the stop flag — important for restarts after INVALID_SESSION.
        self._stop = threading.Event()
        self._last_seq = None
        self.status = Status(started_at=time.time())
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self, join_timeout: float = 5.0) -> None:
        """Signal the listener to stop and wait briefly for it to do so."""
        self._stop.set()
        if self._ws:
            try:
                self._ws.close()
            except Exception:
                pass
        self.status.connected = False
        # Best-effort wait — we don't want to hang the caller (server shutdown).
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=join_timeout)
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            self._heartbeat_thread.join(timeout=1.0)

    def update_config(self, cfg: Config) -> None:
        """Hot-swap subscriptions. Token change requires a restart."""
        self.cfg = cfg

    # ---- internals ----

    def _run(self) -> None:
        # Outer loop: reconnect on any disconnection until the user explicitly stops
        # or Discord closes with a fatal code (see FATAL_CLOSE_CODES).
        self._backoff = 1
        while not self._stop.is_set():
            try:
                self._ws = websocket.WebSocketApp(
                    GATEWAY_URL,
                    on_open=self._on_open,
                    on_message=self._on_message,
                    on_error=self._on_error,
                    on_close=self._on_close,
                )
                self._ws.run_forever(ping_interval=None)  # we manage our own heartbeat
            except Exception as e:
                self.status.last_error = f"socket: {e}"
            # Mark connection down so the heartbeat thread exits before we open a new one.
            self.status.connected = False
            if self._stop.is_set():
                break
            # Wait for the previous heartbeat thread to finish so we don't
            # accumulate one per reconnect attempt.
            if self._heartbeat_thread and self._heartbeat_thread.is_alive():
                self._heartbeat_thread.join(timeout=2)
            # Reconnect backoff: 1, 2, 4, 8, 16, max 60. Reset on READY.
            # Interruptible so stop() doesn't have to wait out a long sleep.
            self._stop.wait(min(self._backoff, 60))
            self._backoff = min(self._backoff * 2, 60)

    def _on_open(self, _ws):
        self.status.connected = True
        self.status.last_error = ""

    def _on_close(self, _ws, code, reason):
        self.status.connected = False
        if code or reason:
            self._handle_close_code(code, reason)

    def _on_error(self, _ws, err):
        # websocket-client hands a server close frame to on_error (and then calls
        # on_close without the code), so decode the close code from the frame here.
        if isinstance(err, websocket.ABNF):
            if err.opcode == websocket.ABNF.OPCODE_CLOSE and len(err.data) >= 2:
                code = int.from_bytes(err.data[:2], "big")
                self._handle_close_code(code, err.data[2:].decode("utf-8", "replace"))
            return
        self.status.last_error = f"error: {err}"

    def _handle_close_code(self, code, reason) -> None:
        # Keep a more specific message (e.g. "invalid session") over a plain normal close.
        if code != 1000 or not self.status.last_error:
            self.status.last_error = f"closed: {code} {reason or ''}".strip()
        if code in FATAL_CLOSE_CODES:
            # Bad token / bad intents: retrying can't help, stop until the user fixes config.
            self._stop.set()

    def _on_message(self, ws, raw):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return
        op = payload.get("op")
        seq = payload.get("s")
        if seq is not None:
            self._last_seq = seq

        if op == 10:  # HELLO
            self._heartbeat_interval_ms = payload["d"]["heartbeat_interval"]
            self._send_identify(ws)
            self._start_heartbeat(ws)
        elif op == 0:
            t = payload.get("t")
            if t == "MESSAGE_CREATE":
                self._handle_message(payload["d"])
            elif t in ("GUILD_CREATE", "GUILD_UPDATE", "READY"):
                if t == "READY":
                    self._backoff = 1
                self._learn_channel_names(payload["d"])
            elif t in ("CHANNEL_CREATE", "CHANNEL_UPDATE"):
                self._learn_one_channel(payload["d"])
        elif op == 11:  # HEARTBEAT_ACK
            self._heartbeat_acked = True
        elif op == 7:  # RECONNECT — Discord asks us to drop and reconnect
            ws.close()
        elif op == 9:
            # INVALID_SESSION is routine (expired session, identify rate limit,
            # e.g. right after a network outage) — reconnect via the backoff loop.
            # A genuinely bad token gets close code 4004 instead (FATAL_CLOSE_CODES).
            self.status.last_error = "invalid session — reconnecting"
            ws.close()

    def _learn_channel_names(self, data: dict) -> None:
        """Cache channel id -> {name, guild_id, guild_name} from a GUILD_CREATE-shaped payload."""
        guild_id = str(data.get("id", "") or data.get("guild_id", "") or "")
        guild_name = str(data.get("name", "") or "")
        for ch in data.get("channels", []) or []:
            cid = str(ch.get("id", ""))
            if cid:
                self._channel_meta[cid] = {
                    "name": ch.get("name", "") or "",
                    "guild_id": guild_id,
                    "guild_name": guild_name,
                }
        # READY also includes private_channels (DMs); ignore those for guild_id.
        for dm in data.get("private_channels", []) or []:
            cid = str(dm.get("id", ""))
            if cid:
                self._channel_meta[cid] = {"name": dm.get("name") or "DM", "guild_id": "", "guild_name": ""}

    def _learn_one_channel(self, ch: dict) -> None:
        cid = str(ch.get("id", ""))
        if cid:
            self._channel_meta[cid] = {
                "name": ch.get("name", "") or "",
                "guild_id": str(ch.get("guild_id", "") or ""),
            }

    def _send_identify(self, ws):
        ws.send(json.dumps({
            "op": 2,
            "d": {
                "token": self.cfg.token,
                "intents": DEFAULT_INTENTS,
                "properties": {"$os": "linux", "$browser": "ping-me-when", "$device": "ping-me-when"},
            },
        }))

    def _start_heartbeat(self, ws):
        if self._heartbeat_thread and self._heartbeat_thread.is_alive():
            return
        self._heartbeat_acked = True

        def beat():
            interval = self._heartbeat_interval_ms / 1000.0
            while not self._stop.is_set() and self.status.connected:
                if not self._heartbeat_acked:
                    # No ACK since the last beat: zombie connection (e.g. the
                    # network dropped without a TCP close). Force a reconnect.
                    self.status.last_error = "heartbeat not acknowledged — reconnecting"
                    try:
                        ws.close()
                    except Exception:
                        pass
                    return
                self._heartbeat_acked = False
                try:
                    ws.send(json.dumps({"op": 1, "d": self._last_seq}))
                except Exception:
                    return
                time.sleep(interval)
        self._heartbeat_thread = threading.Thread(target=beat, daemon=True)
        self._heartbeat_thread.start()

    def _handle_message(self, msg: dict) -> None:
        channel_id = str(msg.get("channel_id", ""))
        author = msg.get("author", {}) or {}
        author_name = (author.get("username") or "").lower()
        author_id = str(author.get("id", "") or "")
        if not channel_id or not (author_name or author_id):
            return

        meta = self._channel_meta.get(channel_id, {})
        for profile in self.cfg.profiles:
            for sub in profile.subscriptions:
                if not getattr(sub, "enabled", True) or sub.channel_id != channel_id:
                    continue
                allowed_names = {u.lower() for u in (sub.usernames or []) if u and not str(u).isdigit()}
                allowed_ids = {str(u) for u in (sub.usernames or []) if str(u).isdigit()}
                if author_name not in allowed_names and author_id not in allowed_ids:
                    continue
                content = msg.get("content", "") or ""
                if not _passes_filters(sub, content):
                    continue
                hit = Hit(
                    sub=sub,
                    author=author.get("username", ""),
                    content=content,
                    message_id=str(msg.get("id", "")),
                    channel_id=channel_id,
                    timestamp=msg.get("timestamp", ""),
                    channel_name=meta.get("name", ""),
                    guild_id=meta.get("guild_id", ""),
                    guild_name=meta.get("guild_name", ""),
                    profile_name=profile.name,
                )
                self.status.last_hit = hit
                self.status.hits.append(hit)
                if len(self.status.hits) > self.MAX_HISTORY:
                    self.status.hits = self.status.hits[-self.MAX_HISTORY:]
                try:
                    self.on_hit(hit)
                except Exception as e:
                    self.status.last_error = f"on_hit: {e}"
                return  # one match per message is enough, even across profiles
