#!/usr/bin/env python3
"""Inspect, send, or delete Telegram widgets in an owned private chat."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request
import zlib
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = Path.home() / ".config/widget-sandbox/telegram-live-test.env"
DEFAULT_RECEIPT = Path.home() / ".config/widget-sandbox/telegram-live-test-last.json"
API_HOST = "api.telegram.org"
MAX_HTML = 32_768
MAX_ZLIB = 4_096


class DeliveryError(RuntimeError):
    pass


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def outside_package(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve()
    try:
        resolved.relative_to(ROOT)
    except ValueError:
        return resolved
    raise DeliveryError(f"{label} must be outside the extracted package: {resolved}")


def parse_config(path: Path) -> dict[str, str]:
    path = outside_package(path, "config")
    try:
        mode = path.stat().st_mode & 0o777
    except FileNotFoundError as exc:
        raise DeliveryError(f"config not found: {path}; create it with mode 0600") from exc
    if mode & 0o077:
        raise DeliveryError(f"config permissions must be 0600, got {mode:04o}: {path}")

    values: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise DeliveryError(f"invalid config line {number}: expected NAME=value")
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def credentials(path: Path, *, require_chat: bool = True) -> tuple[str, int | None]:
    cfg = parse_config(path)
    token = cfg.get("TG_BOT_TOKEN", "")
    chat_text = cfg.get("TG_BOT_CHAT_ID", "")
    if not re.fullmatch(r"[0-9]{5,}:[A-Za-z0-9_-]{20,}", token):
        raise DeliveryError("TG_BOT_TOKEN is missing or malformed")
    if not chat_text:
        if require_chat:
            raise DeliveryError("TG_BOT_CHAT_ID is missing")
        return token, None
    if not re.fullmatch(r"[1-9][0-9]*", chat_text):
        raise DeliveryError("TG_BOT_CHAT_ID must be a numeric private-user chat ID")
    return token, int(chat_text)


class BotApi:
    def __init__(self, token: str):
        self._token = token

    def call(self, method: str, params: dict[str, Any] | None = None) -> Any:
        body = json.dumps(params or {}, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            f"https://{API_HOST}/bot{self._token}/{method}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                decoded = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read().decode("utf-8")).get(
                    "description", "HTTP error"
                )
            except Exception:
                detail = f"HTTP {exc.code}"
            raise DeliveryError(f"Bot API {method} failed: {detail}") from None
        except urllib.error.URLError as exc:
            raise DeliveryError(f"Bot API {method} transport failure: {exc.reason}") from None
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise DeliveryError(f"Bot API {method} returned invalid JSON") from None
        if not decoded.get("ok"):
            raise DeliveryError(
                f"Bot API {method} failed: {decoded.get('description', 'unknown error')}"
            )
        return decoded.get("result")


def marker() -> str:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"TG-PROBE-{stamp}"


def probe_html(test_marker: str) -> str:
    marker_json = json.dumps(test_marker, ensure_ascii=False)
    return (
        '<!doctype html><meta charset=utf-8><body><pre id=p></pre><script>'
        f'const marker={marker_json};'
        "document.getElementById('p').textContent='TG-WIDGET-PROBE\\n'+marker;"
        "console.log('TG-WIDGET-PROBE '+marker);</script>"
    )


def file_html(path: Path) -> str:
    resolved = path.expanduser().resolve()
    try:
        return resolved.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise DeliveryError(f"HTML must be UTF-8: {resolved}") from exc


def inspect_html(html: str) -> dict[str, Any]:
    raw = html.encode("utf-8")
    packed = zlib.compress(raw, level=9)
    if b"\x00" in raw:
        raise DeliveryError("HTML contains a NUL byte")
    if len(raw) > MAX_HTML:
        raise DeliveryError(f"HTML is {len(raw)} bytes; limit is {MAX_HTML}")
    if len(packed) > MAX_ZLIB:
        raise DeliveryError(f"zlib-9 payload is {len(packed)} bytes; limit is {MAX_ZLIB}")
    return {"html_bytes": len(raw), "zlib9_bytes": len(packed), "html_sha256": sha256(raw)}


def private_chat(api: BotApi, chat_id: int) -> dict[str, Any]:
    chat = api.call("getChat", {"chat_id": chat_id})
    if not isinstance(chat, dict) or chat.get("type") != "private":
        raise DeliveryError(f"refusing delivery: configured target {chat_id} is not private")
    if int(chat.get("id", 0)) != chat_id:
        raise DeliveryError("refusing delivery: getChat returned a different chat ID")
    return chat


def bot_identity(api: BotApi) -> dict[str, Any]:
    me = api.call("getMe")
    if not isinstance(me, dict) or not me.get("is_bot"):
        raise DeliveryError("configured token did not resolve to a bot")
    return {"id": me.get("id"), "username": me.get("username"), "is_bot": True}


def write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    path = outside_package(path, "receipt")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def read_receipt(path: Path) -> dict[str, Any]:
    path = outside_package(path, "receipt")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DeliveryError(f"receipt not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise DeliveryError(f"invalid receipt: {path}") from exc


def save_chat_id(path: Path, chat_id: int) -> None:
    path = outside_package(path, "config")
    lines = path.read_text(encoding="utf-8").splitlines()
    updated: list[str] = []
    replaced = False
    for line in lines:
        stripped = line.strip()
        prefix = "export " if stripped.startswith("export ") else ""
        candidate = stripped[7:].lstrip() if prefix else stripped
        if candidate.startswith("TG_BOT_CHAT_ID="):
            updated.append(f"{prefix}TG_BOT_CHAT_ID={chat_id}")
            replaced = True
        else:
            updated.append(line)
    if not replaced:
        updated.append(f"TG_BOT_CHAT_ID={chat_id}")
    path.write_text("\n".join(updated) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def discover(api: BotApi) -> list[dict[str, Any]]:
    updates = api.call("getUpdates", {"limit": 100, "timeout": 0})
    found: dict[int, dict[str, Any]] = {}
    for update in updates if isinstance(updates, list) else []:
        message = update.get("message") or update.get("edited_message") or {}
        chat = message.get("chat") or {}
        if chat.get("type") != "private" or not isinstance(chat.get("id"), int):
            continue
        found[chat["id"]] = {
            "chat_id": chat["id"],
            "type": "private",
            "first_name": chat.get("first_name"),
            "username": chat.get("username"),
        }
    return list(found.values())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--receipt", type=Path, default=DEFAULT_RECEIPT)
    sub = parser.add_subparsers(dest="command", required=True)
    inspect_parser = sub.add_parser("inspect", help="validate an HTML widget without credentials")
    inspect_parser.add_argument("--html", type=Path, help="HTML file; defaults to a benign inline probe")
    sub.add_parser("check", help="authenticate and verify the configured private chat")
    discover_parser = sub.add_parser("discover", help="list private chats in bot updates")
    discover_parser.add_argument("--save-single", action="store_true")
    probe_parser = sub.add_parser("probe", help="send the bundled benign widget marker")
    probe_parser.add_argument("--confirm-own-private-chat", action="store_true")
    send_parser = sub.add_parser("send", help="send a supplied HTML widget to the owned private chat")
    send_parser.add_argument("--html", type=Path, required=True)
    send_parser.add_argument("--caption", default="Authorized owned-device widget test")
    send_parser.add_argument("--height", type=int, default=640)
    send_parser.add_argument("--confirm-own-private-chat", action="store_true")
    delete_parser = sub.add_parser("delete", help="delete the last delivered test widget")
    delete_parser.add_argument("--message-id", type=int)
    args = parser.parse_args()

    if args.command == "inspect":
        if args.html:
            html = file_html(args.html)
            result = {"source": str(args.html.expanduser().resolve()), **inspect_html(html)}
        else:
            test_marker = "TG-PROBE-DRY-RUN"
            result = {"marker": test_marker, **inspect_html(probe_html(test_marker))}
        print(json.dumps(result, sort_keys=True))
        return 0

    token, chat_id = credentials(args.config, require_chat=args.command != "discover")
    api = BotApi(token)
    if args.command == "discover":
        chats = discover(api)
        if args.save_single:
            if len(chats) != 1:
                raise DeliveryError(
                    f"refusing to save: expected exactly one private chat, found {len(chats)}"
                )
            save_chat_id(args.config, int(chats[0]["chat_id"]))
        print(json.dumps({"bot": bot_identity(api), "private_chats": chats}, ensure_ascii=False))
        return 0

    assert chat_id is not None
    if args.command == "check":
        chat = private_chat(api, chat_id)
        print(json.dumps({"bot": bot_identity(api), "target": {"id": chat["id"], "type": chat["type"]}, "ready": True}, ensure_ascii=False))
        return 0

    if args.command == "probe":
        if not args.confirm_own_private_chat:
            raise DeliveryError("probe delivery requires --confirm-own-private-chat")
        test_marker = marker()
        html = probe_html(test_marker)
        size = inspect_html(html)
        chat = private_chat(api, chat_id)
        me = bot_identity(api)
        result = api.call(
            "sendWidget",
            {
                "chat_id": chat_id,
                "html": html,
                "height": 180,
                "disable_notification": True,
                "protect_content": True,
                "caption": f"Authorized own-account widget test: {test_marker}",
            },
        )
        if not isinstance(result, dict) or not isinstance(result.get("message_id"), int):
            raise DeliveryError("sendWidget returned no message ID")
        receipt = {
            "schema": 1,
            "sent_at": utc_now(),
            "kind": "probe",
            "marker": test_marker,
            "chat_id": chat["id"],
            "chat_type": chat["type"],
            "message_id": result["message_id"],
            "bot_id": me["id"],
            "bot_username": me["username"],
            "protect_content_requested": True,
            **size,
        }
        write_receipt(args.receipt, receipt)
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
        return 0

    if args.command == "send":
        if not args.confirm_own_private_chat:
            raise DeliveryError("custom delivery requires --confirm-own-private-chat")
        if not 64 <= args.height <= 1024:
            raise DeliveryError("--height must be between 64 and 1024")
        html = file_html(args.html)
        size = inspect_html(html)
        chat = private_chat(api, chat_id)
        me = bot_identity(api)
        result = api.call(
            "sendWidget",
            {
                "chat_id": chat_id,
                "html": html,
                "height": args.height,
                "disable_notification": True,
                "protect_content": True,
                "caption": args.caption,
            },
        )
        if not isinstance(result, dict) or not isinstance(result.get("message_id"), int):
            raise DeliveryError("sendWidget returned no message ID")
        receipt = {
            "schema": 1,
            "sent_at": utc_now(),
            "kind": "custom",
            "source_name": args.html.name,
            "marker": f"TG-CUSTOM-{size['html_sha256'][:12]}",
            "chat_id": chat["id"],
            "chat_type": chat["type"],
            "message_id": result["message_id"],
            "bot_id": me["id"],
            "bot_username": me["username"],
            "height": args.height,
            "protect_content_requested": True,
            **size,
        }
        write_receipt(args.receipt, receipt)
        print(json.dumps(receipt, ensure_ascii=False, sort_keys=True))
        return 0

    if args.command == "delete":
        receipt = read_receipt(args.receipt)
        if int(receipt.get("chat_id", 0)) != chat_id:
            raise DeliveryError("receipt chat does not match configured private chat")
        message_id = args.message_id or int(receipt.get("message_id", 0))
        if message_id <= 0:
            raise DeliveryError("no valid message ID was supplied or recorded")
        private_chat(api, chat_id)
        deleted = api.call("deleteMessage", {"chat_id": chat_id, "message_id": message_id})
        receipt["deleted_at"] = utc_now()
        receipt["delete_result"] = bool(deleted)
        write_receipt(args.receipt, receipt)
        print(json.dumps({"chat_id": chat_id, "message_id": message_id, "deleted": bool(deleted)}))
        return 0

    raise DeliveryError(f"unknown command: {args.command}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (DeliveryError, OSError) as exc:
        print(json.dumps({"event": "error", "error": str(exc)}), file=sys.stderr)
        raise SystemExit(1)
