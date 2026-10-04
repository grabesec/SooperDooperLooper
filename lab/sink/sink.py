"""A stand-in log concentrator for the SDL lab.

Accepts what SDL's forwarders send, prints one line per event and shows the
latest ones at http://127.0.0.1:8900/ (JSON at /events):

  syslog   RFC 5424 over TCP (octet-counting or newline framing) and UDP, port 514
  graylog  GELF over HTTP, POST http://sink:12201/gelf
  splunk   HTTP Event Collector, POST http://sink:8088/services/collector/event

Standard library only, so the lab needs no image of its own for it.
"""

from __future__ import annotations

import html
import json
import os
import re
import socketserver
import threading
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

HEC_TOKEN = os.environ.get("SPLUNK_HEC_TOKEN", "")
EVENTS: deque[dict[str, Any]] = deque(maxlen=1000)
COUNTS = {"syslog": 0, "graylog": 0, "splunk": 0}
LOCK = threading.Lock()


def record(via: str, event: dict[str, Any]) -> None:
    entry = {
        "received": time.strftime("%H:%M:%S"),
        "via": via,
        "ts": event.get("ts", ""),
        "action": event.get("action", ""),
        "outcome": event.get("outcome", ""),
        "actor": event.get("actor", ""),
        "target": event.get("target") or "",
        "message": event.get("message", ""),
    }
    with LOCK:
        EVENTS.append(entry)
        COUNTS[via] += 1
    print(
        f"{via:<8} {entry['action']:<28} {entry['outcome']:<8} "
        f"{entry['target']:<8} {entry['actor']}: {entry['message']}",
        flush=True,
    )


def actor_name(actor: Any) -> str:
    if isinstance(actor, dict):
        return f"{actor.get('type', '')}:{actor.get('id', '')}"
    return str(actor or "")


# --- syslog -----------------------------------------------------------------

SYSLOG = re.compile(rb"^<\d+>1 \S+ \S+ \S+ \S+ \S+ (?:-|\[.*?[^\\]\])+ ?(.*)$", re.S)


def syslog_message(raw: bytes) -> None:
    match = SYSLOG.match(raw.strip())
    body = match.group(1) if match else raw
    try:
        event = json.loads(body)
    except ValueError:
        record("syslog", {"message": body.decode(errors="replace")})
        return
    record("syslog", {**event, "actor": actor_name(event.get("actor"))})


class SyslogTcp(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        while True:
            first = self.rfile.read(1)
            if not first:
                return
            if first.isdigit():  # octet-counting: "<length> <message>"
                length = first
                while (c := self.rfile.read(1)) not in (b" ", b""):
                    length += c
                syslog_message(self.rfile.read(int(length)))
            else:  # newline framing
                syslog_message(first + self.rfile.readline())


class SyslogUdp(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        syslog_message(self.request[0])


# --- HTTP: GELF, Splunk HEC and the page ------------------------------------


class Http(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: Any) -> None:
        pass

    def reply(self, code: int, body: bytes, kind: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        port = self.server.server_address[1]
        if port == 12201 and self.path == "/gelf":
            gelf = json.loads(body)
            record(
                "graylog",
                {
                    "ts": gelf.get("_sdl_ts", ""),
                    "action": gelf.get("_sdl_action", ""),
                    "outcome": gelf.get("_sdl_outcome", ""),
                    "actor": f"{gelf.get('_sdl_actor_type', '')}:{gelf.get('_sdl_actor', '')}",
                    "target": gelf.get("_sdl_target", ""),
                    "message": gelf.get("full_message") or gelf.get("short_message", ""),
                },
            )
            self.reply(202, b"")
        elif port == 8088 and self.path == "/services/collector/event":
            if self.headers.get("Authorization") != f"Splunk {HEC_TOKEN}":
                self.reply(401, b'{"text":"Invalid token","code":4}')
                return
            decoder, text, pos = json.JSONDecoder(), body.decode(), 0
            while pos < len(text):
                entry, end = decoder.raw_decode(text, pos)
                event = entry["event"]
                record("splunk", {**event, "actor": actor_name(event.get("actor"))})
                pos = end
                while pos < len(text) and text[pos].isspace():
                    pos += 1
            self.reply(200, b'{"text":"Success","code":0}')
        else:
            self.reply(404, b"{}")

    def do_GET(self) -> None:
        with LOCK:
            events = list(EVENTS)
            counts = dict(COUNTS)
        if self.path.startswith("/events"):
            self.reply(200, json.dumps({"counts": counts, "events": events}).encode())
            return
        rows = "".join(
            "<tr>"
            + "".join(
                f"<td>{html.escape(str(e[k]))}</td>"
                for k in ("received", "via", "action", "outcome", "target", "actor", "message")
            )
            + "</tr>"
            for e in reversed(events[-300:])
        )
        page = f"""<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="3">
<title>SDL lab log sink</title>
<style>body{{font:14px system-ui;margin:16px}}table{{border-collapse:collapse;width:100%}}
td,th{{border-bottom:1px solid #ddd;padding:3px 6px;text-align:left;vertical-align:top}}</style>
<h1>SDL lab log sink</h1>
<p>Received: syslog {counts["syslog"]}, Graylog (GELF) {counts["graylog"]},
Splunk (HEC) {counts["splunk"]}. Newest first; refreshes every 3 seconds.</p>
<table><tr><th>Received</th><th>Via</th><th>Action</th><th>Outcome</th><th>System</th>
<th>Actor</th><th>Message</th></tr>{rows}</table>"""
        self.reply(200, page.encode(), "text/html; charset=utf-8")


def serve(server: socketserver.BaseServer) -> None:
    threading.Thread(target=server.serve_forever, daemon=True).start()


def main() -> None:
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    socketserver.ThreadingTCPServer.daemon_threads = True
    serve(socketserver.ThreadingTCPServer(("0.0.0.0", 514), SyslogTcp))
    serve(socketserver.ThreadingUDPServer(("0.0.0.0", 514), SyslogUdp))
    serve(ThreadingHTTPServer(("0.0.0.0", 12201), Http))
    serve(ThreadingHTTPServer(("0.0.0.0", 8088), Http))
    print("sink: syslog tcp+udp 514, GELF http 12201, Splunk HEC 8088, page 8900", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8900), Http).serve_forever()


if __name__ == "__main__":
    main()
