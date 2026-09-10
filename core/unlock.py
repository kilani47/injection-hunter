"""
core/unlock.py — single source of truth for challenge ordering, flags, and
progressive unlock state.

The Seiyaku Arc is one linear chain of 18 nodes (5 phases + finals). Clearing
node N unlocks node N+1. Progress lives in the Flask session under the
"cleared" key: a list of node ids the player has solved, in the order they
were solved.

This module has zero Flask import dependency beyond the `session`-like
mapping it is handed — any dict-like object with __getitem__/get/__setitem__
works, which keeps it trivially unit-testable outside a request context.
"""

from __future__ import annotations

from typing import Any, MutableMapping, Optional

# ---------------------------------------------------------------------------
# Flags — the single canonical source. Every flag string here must match the
# one embedded in its challenge's DEBRIEF.md / solver exactly (SEIYAKU{...}).
# ---------------------------------------------------------------------------
FLAGS: dict[str, str] = {
    "p1_1": "SEIYAKU{the_vow_was_never_sealed}",
    "p1_2": "SEIYAKU{100_type_error_leak}",
    "p1_3": "SEIYAKU{append_your_own_select}",
    "p1_4": "SEIYAKU{yes_or_no_is_enough}",
    "p1_5": "SEIYAKU{time_tells_all}",
    "p2_1": "SEIYAKU{sqlmap_walks_the_floors}",
    "p2_2": "SEIYAKU{an_old_forgotten_door}",
    "p2_3": "SEIYAKU{the_header_was_the_door}",
    "p3_1": "SEIYAKU{word_left_the_island}",
    "p3_2": "SEIYAKU{dormant_until_played}",
    "p4_1": "SEIYAKU{operators_not_strings}",
    "p4_2": "SEIYAKU{ne_null_walks_in}",
    "p4_3": "SEIYAKU{star_closes_the_filter}",
    "p5_1": "SEIYAKU{orm_is_not_armor}",
    "p5_2": "SEIYAKU{inject_a_new_tag}",
    "p5_3": "SEIYAKU{external_entity_unsealed}",
    "f1": "SEIYAKU{all_four_styles_descend}",
    "f2": "SEIYAKU{chairman_of_the_loopholes}",
}

# Per-phase Nen accent colours (see spec §6 / plan Global Constraints).
PHASE_META: dict[str, dict[str, str]] = {
    "1": {"label": "The Written Exam", "nen": "Enhancement", "color": "#e5484d", "css_class": "nen-p1"},
    "2": {"label": "Trick Tower", "nen": "Transmutation", "color": "#8b5cf6", "css_class": "nen-p2"},
    "3": {"label": "Greed Island", "nen": "Specialization", "color": "#f5c518", "css_class": "nen-p3"},
    "4": {"label": "Hunter Association HQ", "nen": "Manipulation", "color": "#22c55e", "css_class": "nen-p4"},
    "5": {"label": "Chimera Ant Palace", "nen": "Conjuration", "color": "#6366f1", "css_class": "nen-p5"},
    "finals": {"label": "The Exam Finals", "nen": "Emission", "color": "#22d3ee", "css_class": "nen-finals"},
}

# ---------------------------------------------------------------------------
# NODES — ordered list of every challenge in the lab. `built` is False until
# the challenge's Task lands its real blueprint route; the hub uses it to
# render an "under construction" state distinct from "locked".
# ---------------------------------------------------------------------------
NODES: list[dict[str, Any]] = [
    {"id": "p1_1", "phase": "1", "name": "Gate of Trust",
     "path": "/p1/gate", "flag": FLAGS["p1_1"], "built": True},
    {"id": "p1_2", "phase": "1", "name": "Netero's Recipe Vault",
     "path": "/p1/recipe", "flag": FLAGS["p1_2"], "built": True},
    {"id": "p1_3", "phase": "1", "name": "Exam Results Board",
     "path": "/p1/results", "flag": FLAGS["p1_3"], "built": True},
    {"id": "p1_4", "phase": "1", "name": "Trick Tower — Silent Room",
     "path": "/p1/silent", "flag": FLAGS["p1_4"], "built": True},
    {"id": "p1_5", "phase": "1", "name": "Zevil Island Medical Bay",
     "path": "/p1/medbay", "flag": FLAGS["p1_5"], "built": True},

    {"id": "p2_1", "phase": "2", "name": "Automated Floor Skip",
     "path": "/p2/floors", "flag": FLAGS["p2_1"], "built": True},
    {"id": "p2_2", "phase": "2", "name": "A Sealed Floor",
     "path": "/p2/sealed", "flag": FLAGS["p2_2"], "built": True},
    {"id": "p2_3", "phase": "2", "name": "The Disguised Examiner",
     "path": "/p2/examiner", "flag": FLAGS["p2_3"], "built": True},

    {"id": "p3_1", "phase": "3", "name": "The Spell Card",
     "path": "/p3/spellcard", "flag": FLAGS["p3_1"], "built": True},
    {"id": "p3_2", "phase": "3", "name": "The Cursed Card",
     "path": "/p3/cursedcard", "flag": FLAGS["p3_2"], "built": True},

    {"id": "p4_1", "phase": "4", "name": "Basic Records Room",
     "path": "/p4/records", "flag": FLAGS["p4_1"], "built": True},
    {"id": "p4_2", "phase": "4", "name": "Bypassing the Archive Guardian",
     "path": "/p4/guardian", "flag": FLAGS["p4_2"], "built": True},
    {"id": "p4_3", "phase": "4", "name": "Zodiac Twelve Directory Breach",
     "path": "/p4/zodiac", "flag": FLAGS["p4_3"], "built": True},

    {"id": "p5_1", "phase": "5", "name": "Manipulator's Firewall",
     "path": "/p5/firewall", "flag": FLAGS["p5_1"], "built": True},
    {"id": "p5_2", "phase": "5", "name": "Palace Blueprint Tampering",
     "path": "/p5/blueprint", "flag": FLAGS["p5_2"], "built": True},
    {"id": "p5_3", "phase": "5", "name": "The King's Sealed Archives",
     "path": "/p5/archives", "flag": FLAGS["p5_3"], "built": False},

    {"id": "f1", "phase": "finals", "name": "Trick Tower Final Exam",
     "path": "/f/bookhaven", "flag": FLAGS["f1"], "built": False},
    {"id": "f2", "phase": "finals", "name": "Chairman Election Infiltration",
     "path": "/f/omnigrid", "flag": FLAGS["f2"], "built": False},
]

_ORDER: list[str] = [n["id"] for n in NODES]
_BY_ID: dict[str, dict[str, Any]] = {n["id"]: n for n in NODES}


def _cleared(session: MutableMapping[str, Any]) -> list[str]:
    return list(session.get("cleared", []))


def is_unlocked(session: MutableMapping[str, Any], node_id: str) -> bool:
    """A node is unlocked if it's the very first node in the chain, or the
    node immediately before it in NODES order has been cleared."""
    if node_id not in _BY_ID:
        return False
    idx = _ORDER.index(node_id)
    if idx == 0:
        return True
    cleared = _cleared(session)
    return _ORDER[idx - 1] in cleared


def submit_flag(session: MutableMapping[str, Any], flag: str) -> Optional[dict[str, Any]]:
    """Validate a submitted flag against the currently-unlocked node.

    Returns the node dict on success (and records it as cleared in the
    session), or None if the flag doesn't match any unlocked, not-yet-cleared
    node. Matching is restricted to unlocked nodes so a flag can't be used to
    skip ahead out of order.
    """
    flag = (flag or "").strip()
    if not flag:
        return None

    cleared = _cleared(session)
    for node in NODES:
        if node["id"] in cleared:
            continue
        if not is_unlocked(session, node["id"]):
            continue
        if node["flag"] == flag:
            cleared.append(node["id"])
            session["cleared"] = cleared
            return node
    return None


def progress(session: MutableMapping[str, Any]) -> dict[str, Any]:
    """Full progress snapshot for rendering the hub."""
    cleared = _cleared(session)
    cleared_set = set(cleared)
    nodes = []
    next_node_id = None
    for node in NODES:
        unlocked = is_unlocked(session, node["id"])
        is_cleared = node["id"] in cleared_set
        if unlocked and not is_cleared and next_node_id is None:
            next_node_id = node["id"]
        nodes.append({
            **node,
            "unlocked": unlocked,
            "cleared": is_cleared,
            "phase_meta": PHASE_META.get(node["phase"], {}),
        })
    return {
        "cleared": cleared,
        "total": len(NODES),
        "cleared_count": len(cleared),
        "next": next_node_id,
        "nodes": nodes,
        "phases": PHASE_META,
    }


def reset(session: MutableMapping[str, Any]) -> None:
    """Wipe progress back to a fresh start."""
    session["cleared"] = []
