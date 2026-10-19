"""Local JSON config store. Single file, atomic writes."""
from __future__ import annotations
import json
import os
import tempfile
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional


CONFIG_PATH = Path(os.environ.get("PING_ME_CONFIG", "config.json"))


@dataclass
class Subscription:
    channel_id: str
    # Comma-or-space-separated list of Discord usernames to match.
    # Stored as a list internally; case-insensitive when matched.
    usernames: list[str] = field(default_factory=list)
    label: str = ""  # user-facing reminder text, e.g. "Alice's market calls"
    # If true, only notify when the message body contains at least one digit (0-9).
    require_digit: bool = False
    # If non-empty, notify only when ANY of these substrings appears (case-insensitive).
    include_any: list[str] = field(default_factory=list)
    # If non-empty, suppress notification when ANY of these substrings appears.
    exclude_any: list[str] = field(default_factory=list)
    # Optional custom regex (Python syntax, case-insensitive). Empty = ignored.
    regex: str = ""
    # Unchecked = kept in config but ignored by the listener (pause without deleting).
    enabled: bool = True

    @classmethod
    def _from_legacy(cls, data: dict) -> "Subscription":
        """Migrate old single-`username` field to `usernames`."""
        if "username" in data and "usernames" not in data:
            data = dict(data)
            u = data.pop("username")
            data["usernames"] = [u] if u else []
        # Drop unknown keys so older configs with extras don't crash.
        allowed = {"channel_id", "usernames", "label", "require_digit",
                   "include_any", "exclude_any", "regex", "enabled"}
        data = {k: v for k, v in data.items() if k in allowed}
        return cls(**data)


@dataclass
class Notify:
    mac: bool = True
    webhook_url: str = ""  # if set, also POST {"content": "..."} to this URL
    telegram_bot_token: str = ""  # if set with chat_id, sends via Telegram bot
    telegram_chat_id: str = ""

    @classmethod
    def _from_dict(cls, data: dict) -> "Notify":
        allowed = {"mac", "webhook_url", "telegram_bot_token", "telegram_chat_id"}
        return cls(**{k: v for k, v in (data or {}).items() if k in allowed})


@dataclass
class Profile:
    """A named group of subscriptions sharing one notify destination.

    Lets the user split monitoring into independent buckets — e.g. one tab for
    market calls (routed to one webhook), another for gym chat (routed elsewhere).
    """
    name: str = "Default"
    subscriptions: list[Subscription] = field(default_factory=list)
    notify: Notify = field(default_factory=Notify)

    @classmethod
    def _from_dict(cls, data: dict) -> "Profile":
        return cls(
            name=str(data.get("name", "") or "Default"),
            subscriptions=[Subscription._from_legacy(s) for s in data.get("subscriptions", [])],
            notify=Notify._from_dict(data.get("notify", {})),
        )


@dataclass
class Config:
    token: str = ""
    profiles: list[Profile] = field(default_factory=lambda: [Profile()])

    @property
    def subscriptions(self) -> list[Subscription]:
        """Flattened view across all profiles. Read-only convenience."""
        return [s for p in self.profiles for s in p.subscriptions]

    @property
    def notify(self) -> Notify:
        """First profile's notify, for legacy single-profile callers."""
        return self.profiles[0].notify if self.profiles else Notify()

    def profile_by_name(self, name: str) -> Optional[Profile]:
        for p in self.profiles:
            if p.name == name:
                return p
        return None

    def to_dict(self) -> dict:
        return {
            "token": self.token,
            "profiles": [
                {
                    "name": p.name,
                    "subscriptions": [asdict(s) for s in p.subscriptions],
                    "notify": asdict(p.notify),
                }
                for p in self.profiles
            ],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "Config":
        # Legacy shape: top-level `subscriptions` + `notify` → wrap into a single profile.
        if "profiles" not in data and ("subscriptions" in data or "notify" in data):
            legacy_profile = {
                "name": "Default",
                "subscriptions": data.get("subscriptions", []),
                "notify": data.get("notify", {}),
            }
            data = {"token": data.get("token", ""), "profiles": [legacy_profile]}
        profiles = [Profile._from_dict(p) for p in data.get("profiles", [])]
        if not profiles:
            profiles = [Profile()]
        return cls(token=data.get("token", ""), profiles=profiles)


def load(path: Optional[Path] = None) -> Config:
    p = path or CONFIG_PATH
    if not p.exists():
        return Config()
    return Config.from_dict(json.loads(p.read_text(encoding="utf-8")))


def save(cfg: Config, path: Optional[Path] = None) -> None:
    p = path or CONFIG_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    # Atomic write: temp file + rename, so a crash mid-write can't corrupt.
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".config-", suffix=".tmp")
    try:
        # File contains the Discord token — restrict to owner read/write only.
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(cfg.to_dict(), f, indent=2, ensure_ascii=False)
        os.replace(tmp, p)
    except Exception:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
