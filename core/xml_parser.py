"""
core/xml_parser.py — the one shared XML parser configuration for Phase 5's
XML-based floors (p5_2 tag injection, p5_3 XXE).

VULN (shared, intentional, notes §11): a hardened lxml parser disables DTD
processing and external-entity resolution entirely — this app explicitly
configures the *unsafe* legacy posture instead: `load_dtd=True` and
`resolve_entities=True`. Every route across Phase 5 that touches
user-supplied XML calls `parse()` here rather than building its own
`etree.XMLParser`, so this one function is the whole phase's real XML
attack surface, in a single place, rather than duplicated per route.

p5_2 doesn't actually need DTD/entity support to be exploitable — its bug
is pure tag-structure injection at the string-building stage, upstream of
this parser entirely. It still parses through this same unsafe
configuration, though, for the same reason a hardened app would apply one
safe parser configuration everywhere rather than deciding per-route which
inputs "need" hardening: p5_3 is the floor where this exact posture turns
into a genuine external-entity file read.
"""

from __future__ import annotations

from lxml import etree


def parse(xml_bytes: bytes) -> "etree._Element":
    """Parse `xml_bytes` with DTD processing and entity resolution enabled.

    Raises `etree.XMLSyntaxError` on malformed XML — callers should let
    that surface as a rejected request, not swallow it silently, since a
    parser exception on a metacharacter is itself part of how a caller
    fingerprints weak validation (notes §11).
    """
    parser = etree.XMLParser(
        resolve_entities=True,
        load_dtd=True,
        no_network=False,
        huge_tree=False,
    )
    return etree.fromstring(xml_bytes, parser=parser)
