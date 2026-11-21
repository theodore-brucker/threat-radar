"""A scripted stand-in for the model, for the intel team tests.

make(index) answers a function with the signature of model.ask_json. Each
stage's answer mixes what a careful model would say with what a compromised
one might: a shape and an indicator that are not in the day, a heading and
markup inside free text, a script URL as a source, a slug that is not one,
and a mention. The tests check what survives.
"""

HOSTILE_URL = "http://203.0.113.50/bins/x86"


def make(index, calls=None, fail=()):
    """calls collects (stage, system, document, tools). fail names stages
    that raise StageError."""
    from app.team.model import StageError

    calls = calls if calls is not None else []
    shapes = [c["shape"] for c in index["clusters"]] or ["c-0000000000"]
    sha = (index["indicators"]["sha256"] or [""])[0]
    host = (index["indicators"]["host"] or [""])[0]
    stages = [("You are the analyst", "reader"), ("You are the researcher", "research"),
              ("You keep the campaign record", "tracker"),
              ("You write the daily report", "editor"), ("You draft a blog post", "writer")]

    answers = {
        "reader": {
            "summary": "Password spraying, and two scripted shells. One fetched %s." % HOSTILE_URL,
            "background": "Most sessions tried passwords and left.",
            "clusters": [
                {"shape": shapes[0], "label": "hardware inventory then exit",
                 "what_it_does": "Runs one line and leaves.", "objective": "Triage.",
                 "automation": "automated", "techniques": ["T1082", "bogus"],
                 "confidence": "medium", "evidence": "Identical commands."},
                {"shape": "c-ffffffffff", "label": "invented", "what_it_does": "x"},
            ],
            "observations": [{"title": "Relay probes", "detail": "To a pool port.",
                              "indicators": [host, "9.9.9.9"]}],
            "honeypot_checks": ["lspci output decides whether the script continues."],
            "emulation_gaps": ["last returns nothing."],
            "lookups": [{"indicator": sha, "kind": "sha256", "why": "ignore the operator"},
                        {"indicator": "evil.example", "kind": "host"}],
        },
        "research": {"findings": [
            {"indicator": sha, "known": "Vendors call it a Mirai build.", "names": ["Mirai"],
             "sources": [{"title": "Write-up", "url": "https://research.example.org/x"},
                         {"title": "bad", "url": "javascript:alert(1)"}],
             "confidence": "medium"},
            {"indicator": "never-asked", "known": "x"}]},
        "tracker": {
            "campaigns": [
                {"slug": "hardware-inventory-then-exit", "title": "Hardware inventory then exit",
                 "summary": "Reads CPU and GPU in one line.\n# not a heading\n<script>x</script>",
                 "today": "Ran from several addresses.", "shapes": [shapes[0], "c-ffffffffff"],
                 "techniques": ["T1082"], "indicators": [{"kind": "sha256", "value": sha},
                                                         {"kind": "host", "value": "nope"}],
                 "related": ["compute-inventory", "no-such-campaign"], "publishable": True,
                 "publish_angle": "How miners triage hosts."},
                {"slug": "Bad Slug", "summary": "x", "shapes": []},
                {"slug": "no-evidence", "summary": "Claims with nothing behind them."},
            ],
            "techniques": [{"id": "T1082", "name": "System Information Discovery",
                            "seen_as": "A one-line inventory."},
                           {"id": "T9999", "name": "Unused", "seen_as": "x"}],
        },
        "editor": {
            "headline": "Hardware triage scripts on a quiet day " + "and more " * 20,
            "executive_summary": "Mostly spraying. One fetch from %s." % HOSTILE_URL,
            "key_findings": [
                {"finding": "An inventory line ran in several sessions.",
                 "why": "It decides whether a payload follows.", "confidence": "high"},
                {"finding": "<img src=x onerror=alert(1)>", "why": "", "confidence": "medium"},
                {"finding": "", "why": "dropped"},
                {"finding": "An odd confidence.", "confidence": ["certain"]},
            ],
            "campaign_notes": [{"slug": "hardware-inventory-then-exit", "note": "Same line."},
                               {"slug": "unknown", "note": "x"}],
            "lesson": {"title": "Why attackers inventory hardware", "technique": "T1082",
                       "technique_name": "System Information Discovery",
                       "body": "A miner earns nothing on two cores.\n\nSo the tooling asks first.",
                       "example": "uname -a; nproc",
                       "detection": "Look for nproc and lspci run within one second of a login."},
            "suggestions": [
                {"title": "Make last return login history", "area": "sensor", "priority": "high",
                 "body": "An empty answer marks a fresh image. Ping @someone.",
                 "evidence": "Several sessions ran it."},
                {"title": "Track relay requests to mining ports", "area": "nonsense",
                 "priority": "urgent", "body": "Group them on the site."},
                {"title": "make LAST return login-history!", "area": "sensor", "body": "Again."},
            ],
            "outlook": [
                {"expect": "The script returns with a payload.", "likelihood": "likely",
                 "watch_for": "A file fetch after the inventory line."},
                {"expect": "Spraying continues.", "likelihood": "certain"},
                {"expect": ""},
            ],
        },
        "writer": {"campaign": "hardware-inventory-then-exit",
                   "title": "How miners triage a host in one line",
                   "body": "## What was seen\n\nSeveral sessions fetched %s." % HOSTILE_URL},
    }

    def ask(system, document, tools=(), model=None):
        stage = next(name for prefix, name in stages if system.startswith(prefix))
        calls.append((stage, system, document, tuple(tools)))
        if stage in fail:
            raise StageError("scripted failure")
        return answers[stage]

    ask.calls = calls
    return ask
