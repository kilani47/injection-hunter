"""
collaborator/collaborator.py: The Seiyaku Arc's out-of-band (OOB)
collaborator service.

Purpose: a stand-in for the classic "attacker-controlled listener" used to
teach OOB SQL injection (notes §7). Something inside the docker-compose
network, a challenge's Flask route acting on data pulled out of the DB,
makes a real outbound network call (HTTP request or DNS lookup) to this
service's hostname (`collaborator`, the compose service name). That call
carries exfiltrated data as a header/path/subdomain, and this service is
the only place that data becomes observable, since the challenge's own
HTTP response never shows it. A later task (the portal) polls `/captures`
to display "data has arrived out-of-band" in the UI.

Single process, stdlib only:
  - A threaded HTTP server on port 80 logging every request (method, path,
    query string, headers, body, client IP, timestamp) into an in-memory
    capture list. `GET /captures` is special-cased: it does NOT get logged
    as a capture itself (that would just be UI-polling noise) and instead
    returns the current capture list as JSON.
  - A UDP DNS server on port 53 that parses just enough of RFC 1035 to log
    the queried name + type, then answers every query with a synthesized
    NOERROR response: an A record pointing at 127.0.0.1 for A queries,
    an empty-answer NOERROR for anything else (AAAA, TXT, ...). See the
    docstring on `handle_dns_query` for why NOERROR was chosen over
    NXDOMAIN: it's what keeps resolvers from retrying/falling back to
    other nameservers and slowing the round trip down, which matters
    because this is a lab and the point is to observe the query land
    quickly, not to model authoritative DNS correctly.

No persistence, no auth: this only runs on the internal compose network
and is wiped on every container restart. That's fine for a lab.
"""

from __future__ import annotations

import json
import struct
import threading
import time
from collections import deque
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import ThreadingUDPServer, BaseRequestHandler
from urllib.parse import urlsplit, parse_qs

HTTP_PORT = 80
DNS_PORT = 53
MAX_CAPTURES = 500

# Shared, thread-safe capture buffer. A deque with maxlen bounds memory
# use automatically (oldest captures just fall off); the lock guards the
# read-modify-write in /captures (which returns a *sorted copy*, newest
# first) against concurrent appends from the HTTP and DNS threads.
_captures: deque = deque(maxlen=MAX_CAPTURES)
_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _record(entry: dict) -> None:
    entry.setdefault("timestamp", _now())
    with _lock:
        _captures.append(entry)


def _captures_snapshot() -> list:
    with _lock:
        items = list(_captures)
    # Newest first.
    items.sort(key=lambda e: e["timestamp"], reverse=True)
    return items


# ---------------------------------------------------------------------------
# HTTP capture server
# ---------------------------------------------------------------------------

class CaptureHTTPHandler(BaseHTTPRequestHandler):
    server_version = "collaborator/1.0"

    # Silence the default per-request stderr logging; we keep our own
    # structured captures instead.
    def log_message(self, fmt, *args):  # noqa: D401 - matches base signature
        return

    def _handle(self) -> None:
        parsed = urlsplit(self.path)

        # GET /captures is the portal's polling endpoint, not something we
        # want cluttering the very capture list it's asking about.
        if self.command == "GET" and parsed.path == "/captures":
            self._serve_captures()
            return

        length = int(self.headers.get("Content-Length", 0) or 0)
        body_bytes = self.rfile.read(length) if length else b""
        try:
            body = body_bytes.decode("utf-8", errors="replace")
        except Exception:
            body = repr(body_bytes)

        entry = {
            "type": "http",
            "timestamp": _now(),
            "method": self.command,
            "path": parsed.path,
            "query": parse_qs(parsed.query),
            "raw_query": parsed.query,
            "headers": dict(self.headers.items()),
            "body": body,
            "client_ip": self.client_address[0],
        }
        _record(entry)

        payload = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _serve_captures(self) -> None:
        body = json.dumps(_captures_snapshot()).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # Accept every method a challenge might plausibly emit (GET for a
    # DNS-style/blind "beacon" hit modeled as an HTTP GET, POST for an
    # exfil payload carried in a body, etc).
    def do_GET(self):
        self._handle()

    def do_POST(self):
        self._handle()

    def do_PUT(self):
        self._handle()

    def do_PATCH(self):
        self._handle()

    def do_DELETE(self):
        self._handle()

    def do_HEAD(self):
        self._handle()

    def do_OPTIONS(self):
        self._handle()


# ---------------------------------------------------------------------------
# Minimal DNS capture server (RFC 1035, just enough to log a query)
# ---------------------------------------------------------------------------

_QTYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}


def _parse_qname(data: bytes, offset: int) -> tuple[str, int]:
    """Parse a (non-compressed) DNS name starting at `offset`.

    Incoming *queries* from a resolver don't use label compression in the
    question section (compression only ever points at earlier bytes, and
    the question is always the first thing after the 12-byte header), so
    a straightforward length-prefixed-label walk is sufficient here.
    """
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels), offset


def _build_dns_response(query: bytes, qname: str, qtype: int) -> bytes:
    """Build a synthesized NOERROR response.

    For an A query: answers with a single A record, 127.0.0.1, TTL 60,
    a real, resolvable answer so a client-side resolver making a genuine
    `gethostbyname()`-style call doesn't stall or fall back to another
    resolver waiting for a reply that never comes. For anything else (AAAA,
    TXT, ...): NOERROR with zero answers, still a prompt, well-formed
    reply, just with nothing to add. Query capture already happened before
    this is ever called; the *reply* only exists to keep the round trip
    fast, not because anything downstream is expected to use the answer.
    """
    txn_id = query[0:2]
    flags = struct.pack(">H", 0x8180)  # standard query response, no error
    qdcount = struct.pack(">H", 1)

    question_end = query.index(b"\x00", 12) + 1 + 4  # name + qtype(2) + qclass(2)
    question_section = query[12:question_end]

    if qtype == 1:  # A
        ancount = struct.pack(">H", 1)
        answer = (
            b"\xc0\x0c"  # pointer to name at offset 12
            + struct.pack(">HHIH", 1, 1, 60, 4)  # TYPE=A, CLASS=IN, TTL=60, RDLENGTH=4
            + bytes([127, 0, 0, 1])
        )
    else:
        ancount = struct.pack(">H", 0)
        answer = b""

    header = txn_id + flags + qdcount + ancount + struct.pack(">HH", 0, 0)
    return header + question_section + answer


class DNSHandler(BaseRequestHandler):
    def handle(self) -> None:
        data, sock = self.request
        client_ip = self.client_address[0]
        try:
            qdcount = struct.unpack(">H", data[4:6])[0]
            if qdcount < 1:
                return
            qname, offset = _parse_qname(data, 12)
            qtype, qclass = struct.unpack(">HH", data[offset:offset + 4])
        except Exception as exc:
            _record({
                "type": "dns",
                "timestamp": _now(),
                "error": f"unparseable query: {exc!r}",
                "client_ip": client_ip,
            })
            return

        _record({
            "type": "dns",
            "timestamp": _now(),
            "qname": qname,
            "qtype": _QTYPE_NAMES.get(qtype, str(qtype)),
            "client_ip": client_ip,
        })

        try:
            response = _build_dns_response(data, qname, qtype)
            sock.sendto(response, self.client_address)
        except Exception:
            # Logging the query is the whole point; a reply failure is
            # not fatal to the teaching mechanism.
            pass


def main() -> None:
    dns_server = ThreadingUDPServer(("0.0.0.0", DNS_PORT), DNSHandler)
    dns_thread = threading.Thread(target=dns_server.serve_forever, daemon=True)
    dns_thread.start()

    http_server = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), CaptureHTTPHandler)
    print(f"[collaborator] HTTP capture on :{HTTP_PORT}, DNS capture on :{DNS_PORT}/udp", flush=True)
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        http_server.shutdown()
        dns_server.shutdown()


if __name__ == "__main__":
    main()
