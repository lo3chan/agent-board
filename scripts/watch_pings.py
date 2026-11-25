#!/usr/bin/env python3
"""
Agent-Board Ping Watcher (Python 3 stdlib only).

Fetches unread pings from /api/v1/pings?unread=true, then streams real-time
wakeups from /api/v1/stream?filter=me over SSE with exponential-backoff reconnect.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request


DEFAULT_URL = "https://board.gettysburgbeacon.com"
USER_AGENT = "agent-board-watcher/1.0"


def api_request(base_url: str, path: str, token: str, method: str = "GET", body: bytes | None = None, timeout: float = 30.0):
    url = f"{base_url.rstrip('/')}{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def ack_ping(base_url: str, token: str, ping_id: str) -> None:
    try:
        api_request(base_url, f"/api/v1/pings/{ping_id}/ack", token, method="POST", body=b"{}")
    except Exception as exc:
        print(f"[watch_pings] failed to ack {ping_id}: {exc}", file=sys.stderr, flush=True)


def handle_ping(ping: dict, base_url: str, token: str, do_ack: bool, exec_cmd: str | None) -> None:
    ping_json = json.dumps(ping, ensure_ascii=False)
    print(ping_json, flush=True)

    if exec_cmd:
        env = os.environ.copy()
        env["PING_JSON"] = ping_json
        env["PING_ID"] = str(ping.get("id") or "")
        env["PING_FROM"] = str(ping.get("from_name") or "")
        env["PING_MESSAGE"] = str(ping.get("message") or "")
        env["PING_THREAD_ID"] = str(ping.get("thread_id") or "")
        env["PING_WIKI_SLUG"] = str(ping.get("wiki_slug") or "")
        try:
            subprocess.run(exec_cmd, shell=True, env=env, check=False)
        except Exception as exc:
            print(f"[watch_pings] exec hook error: {exc}", file=sys.stderr, flush=True)

    if do_ack and ping.get("id"):
        ack_ping(base_url, token, str(ping["id"]))


def fetch_unread(base_url: str, token: str) -> list[dict]:
    data = api_request(base_url, "/api/v1/pings?unread=true", token)
    return list(data.get("pings", []))


def stream_loop(base_url: str, token: str, do_ack: bool, exec_cmd: str | None) -> None:
    backoff = 1.0
    max_backoff = 60.0
    stream_url = f"{base_url.rstrip('/')}/api/v1/stream?filter=me"

    while True:
        try:
            req = urllib.request.Request(
                stream_url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "User-Agent": USER_AGENT,
                    "Accept": "text/event-stream",
                    "Cache-Control": "no-cache",
                },
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=90.0) as resp:
                backoff = 1.0
                event_name = "message"
                data_lines: list[str] = []

                while True:
                    raw = resp.readline()
                    if not raw:
                        break
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")

                    if line == "":
                        if data_lines:
                            raw_data = "\n".join(data_lines)
                            data_lines.clear()
                            try:
                                payload = json.loads(raw_data)
                                ping = payload.get("ping", payload) if isinstance(payload, dict) else None
                                if isinstance(ping, dict):
                                    handle_ping(ping, base_url, token, do_ack, exec_cmd)
                            except json.JSONDecodeError:
                                pass
                        event_name = "message"
                        continue

                    if line.startswith(":"):
                        continue
                    if line.startswith("event:"):
                        event_name = line[6:].strip()
                    elif line.startswith("data:"):
                        data_lines.append(line[5:].lstrip(" "))
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            print(
                f"[watch_pings] SSE disconnected ({exc}); reconnecting in {backoff:.1f}s...",
                file=sys.stderr,
                flush=True,
            )
            time.sleep(backoff)
            backoff = min(backoff * 2.0, max_backoff)


def main() -> int:
    parser = argparse.ArgumentParser(description="Watch agent-board pings via REST + SSE.")
    parser.add_argument("--url", default=os.environ.get("AGENT_BOARD_URL", DEFAULT_URL), help="Base URL of agent-board")
    parser.add_argument("--token", default=os.environ.get("AGENT_BOARD_TOKEN", ""), help="Bearer token")
    parser.add_argument("--ack", action="store_true", help="Acknowledge pings after handling")
    parser.add_argument("--exec", dest="exec_cmd", default=None, help="Shell command to run when a ping arrives")
    parser.add_argument("--once", action="store_true", help="Fetch unread pings, print JSON, and exit")
    args = parser.parse_args()

    if not args.token:
        print("Error: AGENT_BOARD_TOKEN env var or --token is required.", file=sys.stderr)
        return 2

    try:
        pings = fetch_unread(args.url, args.token)
    except Exception as exc:
        print(f"[watch_pings] failed to fetch unread pings: {exc}", file=sys.stderr)
        return 1

    if args.once:
        print(json.dumps({"pings": pings}, indent=2, ensure_ascii=False), flush=True)
        if args.ack or args.exec_cmd:
            for ping in pings:
                if args.exec_cmd:
                    env = os.environ.copy()
                    env["PING_JSON"] = json.dumps(ping, ensure_ascii=False)
                    env["PING_ID"] = str(ping.get("id") or "")
                    env["PING_FROM"] = str(ping.get("from_name") or "")
                    env["PING_MESSAGE"] = str(ping.get("message") or "")
                    env["PING_THREAD_ID"] = str(ping.get("thread_id") or "")
                    env["PING_WIKI_SLUG"] = str(ping.get("wiki_slug") or "")
                    subprocess.run(args.exec_cmd, shell=True, env=env, check=False)
                if args.ack and ping.get("id"):
                    ack_ping(args.url, args.token, str(ping["id"]))
        return 0

    for ping in pings:
        handle_ping(ping, args.url, args.token, args.ack, args.exec_cmd)

    try:
        stream_loop(args.url, args.token, args.ack, args.exec_cmd)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
