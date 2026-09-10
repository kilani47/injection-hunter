"""
app.py — The Seiyaku Arc Flask portal.

Serves the hub, the progressive-unlock flag flow, and the victory takeover.
Challenge blueprints (challenges/phase1.py ... challenges/finals.py) register
themselves here defensively: this scaffold task ships before any of them
exist, so app.py must boot cleanly with zero challenge modules present.
"""

from __future__ import annotations

import os

from flask import Flask, redirect, render_template, request, session, url_for

from core import unlock

APP_ROOT = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)

# Lab constant secret key. This is a deliberately-vulnerable, local-only CTF
# lab (see NOTICE / README ethics banner) — session integrity here only
# needs to survive a container restart, not resist a determined attacker,
# so a hardcoded key (vs. a per-deploy secret) is an intentional simplicity
# choice, not an oversight.
app.secret_key = "seiyaku-arc-hunter-license-nen-000001"


def _gif_path(node_id: str) -> str:
    return os.path.join(APP_ROOT, "static", "img", "victory", f"{node_id}.gif")


def render_victory(node: dict) -> str:
    """Render the full-screen victory takeover for a just-cleared node.

    Looks for an author-supplied static/img/victory/<id>.gif; falls back to
    the original CSS Nen-burst animation (templates/victory.html) when
    absent, per the legal pack's no-gif-by-default policy.
    """
    prog = unlock.progress(session)
    next_node = next(
        (n for n in prog["nodes"] if n["unlocked"] and not n["cleared"]), None
    )
    return render_template(
        "victory.html",
        node=node,
        phase_meta=unlock.PHASE_META.get(node["phase"], {}),
        gif_exists=os.path.isfile(_gif_path(node["id"])),
        next_node=next_node,
        progress=prog,
    )


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/hub")
def hub():
    prog = unlock.progress(session)
    phases = unlock.phase_progress(session)
    return render_template("hub.html", progress=prog, phases=phases)


@app.route("/phase/<phase_id>")
def phase(phase_id):
    view = unlock.phase_view(session, phase_id)
    if view is None:
        return redirect(url_for("hub"))
    return render_template("phase.html", phase=view)


@app.route("/flag", methods=["POST"])
def flag():
    submitted = request.form.get("flag", "")
    node = unlock.submit_flag(session, submitted)
    if node is None:
        prog = unlock.progress(session)
        return render_template(
            "hub.html",
            progress=prog,
            error="vow not fulfilled — that flag doesn't match the next locked floor.",
        ), 400
    return render_victory(node)


@app.route("/reset")
def reset():
    unlock.reset(session)
    return redirect(url_for("hub"))


# --- phase blueprints -------------------------------------------------
# Registered defensively: each challenges/phaseN.py module is added by a
# later task and is expected to expose a Blueprint named "<phase>_bp".
# Until then, this loop is a no-op and the app boots with just hub/victory.
for _module_name, _bp_name in (
    ("challenges.phase1", "phase1_bp"),
    ("challenges.phase2", "phase2_bp"),
    ("challenges.phase3", "phase3_bp"),
    ("challenges.phase4", "phase4_bp"),
    ("challenges.phase5", "phase5_bp"),
    ("challenges.finals", "finals_bp"),
):
    try:
        _mod = __import__(_module_name, fromlist=[_bp_name])
        app.register_blueprint(getattr(_mod, _bp_name))
    except (ImportError, AttributeError):
        pass


if __name__ == "__main__":
    # Debug/reloader off by default — the app is deliberately vulnerable on
    # purpose via its own challenge routes; the Werkzeug interactive
    # debugger is a separate, out-of-scope attack surface we don't want to
    # expose incidentally. Set FLASK_DEBUG=1 for local development only.
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=8000, debug=debug)
