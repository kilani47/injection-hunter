"""
core/unlock.py: single source of truth for challenge ordering, flags, and
progressive unlock state.

The Seiyaku Arc is one linear chain of 18 nodes (5 phases + finals). Clearing
node N unlocks node N+1. Progress lives in the Flask session under the
"cleared" key: a list of node ids the player has solved, in the order they
were solved.

This module has zero Flask import dependency beyond the `session`-like
mapping it is handed: any dict-like object with __getitem__/get/__setitem__
works, which keeps it trivially unit-testable outside a request context.
"""

from __future__ import annotations

from typing import Any, MutableMapping, Optional

# ---------------------------------------------------------------------------
# Flags: the single canonical source. Every flag string here must match the
# one embedded in its challenge's DEBRIEF.md / solver exactly (SEIYAKU{...}).
# ---------------------------------------------------------------------------
FLAGS: dict[str, str] = {
    "p1_1": "SEIYAKU{the_vow_was_never_sealed}",
    "p1_2": "SEIYAKU{100_type_error_leak}",
    "p1_3": "SEIYAKU{append_your_own_select}",
    "p1_4": "SEIYAKU{yes_or_no_is_enough}",
    "p1_5": "SEIYAKU{time_tells_all}",
    "p2_2": "SEIYAKU{an_old_forgotten_door}",
    "p2_3": "SEIYAKU{the_header_was_the_door}",
    "p2_4": "SEIYAKU{replay_the_signed_request}",
    "p2_5": "SEIYAKU{define_your_own_oracle}",
    "p2_6": "SEIYAKU{tamper_past_the_ward}",
    "p2_7": "SEIYAKU{targeted_beats_dump_all}",
    "p2_8": "SEIYAKU{file_privilege_has_no_walls}",
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
# `order` fixes the phase sequence for the hub overview; `engine` and
# `topic` feed the phase-page hero. Key-art splash images aren't tracked
# here: phase.html checks has_hero('phase' ~ phase.id) against the actual
# file on disk (static/img/phase<id>.png), the same convention every
# challenge template uses, so a missing file always falls back gracefully
# instead of depending on a config flag staying in sync with reality.
PHASE_META: dict[str, dict[str, Any]] = {
    "1": {"label": "The Written Exam", "nen": "Enhancement", "color": "#e5484d",
          "css_class": "nen-p1", "order": 1, "engine": "MariaDB",
          "topic": "SQLi fundamentals + the four core techniques"},
    "2": {"label": "Trick Tower", "nen": "Transmutation", "color": "#8b5cf6",
          "css_class": "nen-p2", "order": 2, "engine": "MariaDB",
          "topic": "Testing methodology, SQLMap, header & CVE injection"},
    "3": {"label": "Greed Island", "nen": "Specialization", "color": "#f5c518",
          "css_class": "nen-p3", "order": 3, "engine": "MariaDB + collaborator",
          "topic": "Out-of-band and second-order SQLi"},
    "4": {"label": "Hunter Association HQ", "nen": "Manipulation", "color": "#22c55e",
          "css_class": "nen-p4", "order": 4, "engine": "MongoDB + OpenLDAP",
          "topic": "NoSQL and LDAP injection"},
    "5": {"label": "Chimera Ant Palace", "nen": "Conjuration", "color": "#6366f1",
          "css_class": "nen-p5", "order": 5, "engine": "SQLAlchemy + lxml",
          "topic": "ORM injection and XML / XXE"},
    "finals": {"label": "The Exam Finals", "nen": "Emission", "color": "#22d3ee",
               "css_class": "nen-finals", "order": 6,
               "engine": "every engine at once",
               "topic": "Two chained, multi-vuln final trials"},
}

# Short, spoiler-free hooks per node: one line describing the floor's
# premise without giving away its technique. Used on the phase pages.
BLURBS: dict[str, str] = {
    "p1_1": "The applicant gate takes your name on trust. Trust is a rule, and rules can be misread.",
    "p1_2": "Netero's recipe vault answers the wrong questions loudly. Read what it says when it breaks.",
    "p1_3": "The results board prints whatever matches. Ask it to match something it was never meant to show.",
    "p1_4": "A sealed door that only ever whispers pass or fail. One bit at a time is still enough.",
    "p1_5": "The medical bay never tells you anything, but it can be made to take its time about it.",
    "p2_2": "An ancient, forgotten floor with a weakness catalogued long ago. Look it up; walk in.",
    "p2_3": "The examiner isn't watching the door you'd expect. The threat rides in the header instead.",
    "p2_4": "The warden's ledger won't look at a cell for a stranger. Sign in, then bring your tools past the gate.",
    "p2_5": "The chamber only ever says resonate or silence, buried in noise. Teach your tool what a yes sounds like.",
    "p2_6": "The ward doesn't watch closely, it only flares at a name it knows and a phrase it's been carved to reject.",
    "p2_7": "Hundreds of records, one that matters. Read the whole hall by hand, or ask exactly where to look.",
    "p2_8": "Nothing in this database is worth stealing. The account reading it can reach past the database entirely.",
    "p3_1": "A spell card carries word off the island, through a channel the game master never watches.",
    "p3_2": "A card that lies dormant when inscribed and only wakes when someone else plays it back.",
    "p4_1": "The archive answers only match or no match, but its questions aren't strings anymore.",
    "p4_2": "The archive guardian checks that you supplied a name and a key, never what kind of thing they are.",
    "p4_3": "The Zodiac Twelve's directory is rigid by design. Rewrite the question it's rigid about.",
    "p5_1": "A firewall built on a real ORM, and one raw seam its own safety was never applied to.",
    "p5_2": "The badge press prints exactly what its blueprint says. Add a line to the blueprint.",
    "p5_3": "The archive desk reads your request back to you, including wherever you point it to look.",
    "f1": "The tower's final locked floor demands every SQLi style at once, in order, to descend.",
    "f2": "Four factions, four systems, four fragments. Seize the Chairman's seat by breaching them all.",
}

# ---------------------------------------------------------------------------
# NODES: ordered list of every challenge in the lab. `built` is False until
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
    {"id": "p1_4", "phase": "1", "name": "Trick Tower: Silent Room",
     "path": "/p1/silent", "flag": FLAGS["p1_4"], "built": True},
    {"id": "p1_5", "phase": "1", "name": "Zevil Island Medical Bay",
     "path": "/p1/medbay", "flag": FLAGS["p1_5"], "built": True},

    {"id": "p2_2", "phase": "2", "name": "A Sealed Floor",
     "path": "/p2/sealed", "flag": FLAGS["p2_2"], "built": True},
    {"id": "p2_3", "phase": "2", "name": "The Disguised Examiner",
     "path": "/p2/examiner", "flag": FLAGS["p2_3"], "built": True},
    {"id": "p2_4", "phase": "2", "name": "The Warden's Ledger",
     "path": "/p2/ledger", "flag": FLAGS["p2_4"], "built": True},
    {"id": "p2_5", "phase": "2", "name": "The Echo Chamber",
     "path": "/p2/echo", "flag": FLAGS["p2_5"], "built": True},
    {"id": "p2_6", "phase": "2", "name": "The Warded Door",
     "path": "/p2/warded", "flag": FLAGS["p2_6"], "built": True},
    {"id": "p2_7", "phase": "2", "name": "The Hall of Cells",
     "path": "/p2/hall", "flag": FLAGS["p2_7"], "built": True},
    {"id": "p2_8", "phase": "2", "name": "The Groundskeeper's Keys",
     "path": "/p2/keys", "flag": FLAGS["p2_8"], "built": True},

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
     "path": "/p5/archives", "flag": FLAGS["p5_3"], "built": True},

    {"id": "f1", "phase": "finals", "name": "Trick Tower Final Exam",
     "path": "/f/bookhaven", "flag": FLAGS["f1"], "built": True},
    {"id": "f2", "phase": "finals", "name": "Chairman Election Infiltration",
     "path": "/f/omnigrid", "flag": FLAGS["f2"], "built": True},
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
            "blurb": BLURBS.get(node["id"], ""),
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


def phase_progress(session: MutableMapping[str, Any]) -> list[dict[str, Any]]:
    """Per-phase aggregate for the hub overview, in phase order. Each entry
    carries the phase's meta, its cleared/total counts, whether the phase is
    unlocked (its first node is reachable) or fully cleared, and the id of
    the first not-yet-cleared node in it (for a 'continue here' link)."""
    snapshot = progress(session)
    by_phase: dict[str, list[dict[str, Any]]] = {}
    for node in snapshot["nodes"]:
        by_phase.setdefault(node["phase"], []).append(node)

    phases = []
    for phase_id, meta in sorted(PHASE_META.items(), key=lambda kv: kv[1]["order"]):
        nodes = by_phase.get(phase_id, [])
        cleared = sum(1 for n in nodes if n["cleared"])
        unlocked = any(n["unlocked"] for n in nodes)
        resume = next((n["id"] for n in nodes if n["unlocked"] and not n["cleared"]), None)
        phases.append({
            "id": phase_id,
            **meta,
            "count": len(nodes),
            "cleared_count": cleared,
            "unlocked": unlocked,
            "fully_cleared": bool(nodes) and cleared == len(nodes),
            "resume": resume,
        })
    return phases


def phase_view(session: MutableMapping[str, Any], phase_id: str) -> Optional[dict[str, Any]]:
    """Everything a single phase page needs: the phase meta plus its nodes
    with unlock/clear state. Returns None for an unknown phase id."""
    if phase_id not in PHASE_META:
        return None
    snapshot = progress(session)
    nodes = [n for n in snapshot["nodes"] if n["phase"] == phase_id]
    cleared = sum(1 for n in nodes if n["cleared"])
    return {
        "id": phase_id,
        **PHASE_META[phase_id],
        "nodes": nodes,
        "count": len(nodes),
        "cleared_count": cleared,
        "unlocked": any(n["unlocked"] for n in nodes),
        "fully_cleared": bool(nodes) and cleared == len(nodes),
    }


def reset(session: MutableMapping[str, Any]) -> None:
    """Wipe progress back to a fresh start."""
    session["cleared"] = []
