"""One API surface for the whole site.

Every response uses the same envelope:

    {"ok": true, "generated_at": "...", "window_days": 30, "data": {...}}

Page routes return the same shell; the client router picks the view. Nothing
here writes to the database, and nothing here scans raw_events for a list
view. Detail endpoints for a single hash or address may touch raw_events
because they are bounded by an indexed equality.
"""


import logging

from fastapi import APIRouter, HTTPException, Query

from app.analytics import asn as asnmod
from app.analytics import credentials as credmod
from app.analytics import cards as cardmod
from app.analytics import contributions as contribmod
from app.analytics import db
from app.analytics import entities as entmod
from app.analytics import escalation
from app.analytics import families as fammod
from app.analytics import lookup as lookupmod
from app.analytics import exec_view
from app.analytics import fingerprints
from app.analytics import funnel as funnelmod
from app.analytics import overview as overviewmod
from app.analytics import payloads as payloadmod
from app.analytics import sessions as sessmod
from app.analytics import spikes as spikemod
from app.analytics import tunnels as tunnelmod

router = APIRouter()
log = logging.getLogger("radar.site")


def _con():
    try:
        return db.connect_ro()
    except Exception as exc:
        # The reason goes to the service log, not the response: the exception
        # text carries the database path, which a caller has no use for.
        log.warning("database unavailable: %s", exc)
        raise HTTPException(status_code=503, detail="database unavailable") from exc


def ok(data, days=None):
    body = {"ok": True, "generated_at": db.utcnow(), "data": data}
    if days is not None:
        body["window_days"] = days
    return body


# --------------------------------------------------------------------------
# meta
# --------------------------------------------------------------------------

@router.get("/api/v1/meta")
def meta():
    con = _con()
    try:
        state = {
            k: db.get_state(con, k)
            for k in ("last_run", "last_run_seconds", "facts_built_at",
                      "sessions_built_at", "payloads_built_at",
                      "credentials_built_at", "spikes_built_at",
                      "intel_built_at", "stage_built_at", "fingerprints_built_at",
                      "submissions_built_at", "entities_built_at",
                      "families_built_at", "bazaar_built_at")
        }
        coverage = db.qone(
            con, "SELECT MIN(day) first_day, MAX(day) last_day FROM asn_ip_daily"
        ) or {}
        return ok({"worker": state, "coverage": coverage, "version": "3.7.0"})
    finally:
        con.close()


# --------------------------------------------------------------------------
# entities
# --------------------------------------------------------------------------

@router.post("/api/v1/cards")
def cards(body: dict):
    """Batch hover-card summaries. POST because a page sends a few hundred
    entities at once, which does not belong in a query string."""
    con = _con()
    try:
        return ok(cardmod.batch(con, (body or {}).get("items")))
    finally:
        con.close()


@router.get("/api/v1/lookup")
def lookup(q: str = Query("", max_length=128)):
    con = _con()
    try:
        return ok(lookupmod.search(con, q))
    finally:
        con.close()


@router.get("/api/v1/entity/{etype}/{value}")
def entity(etype: str, value: str, days: int = Query(30, ge=1, le=3650)):
    if etype not in entmod.HANDLERS:
        raise HTTPException(status_code=404, detail="unknown entity type")
    con = _con()
    try:
        try:
            data = entmod.lookup(con, etype, value, days)
        except entmod.BadEntity as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if data is None:
            raise HTTPException(status_code=404, detail="entity not seen")
        return ok(data, days)
    finally:
        con.close()


# --------------------------------------------------------------------------
# overview
# --------------------------------------------------------------------------

@router.get("/api/v1/overview")
def overview(days: int = Query(30, ge=1, le=3650),
             min_stage: int = Query(0, ge=0, le=4),
             points: int = Query(60, ge=5, le=500)):
    con = _con()
    try:
        return ok(
            {
                "headline": overviewmod.headline(con, days),
                "rail": escalation.rail(con, days),
                "activity": overviewmod.activity(con, min(days * 2, 120)),
                "notable": overviewmod.notable_sessions(con, days),
                "map": {
                    "points": escalation.map_points(con, days, points, min_stage),
                    "legend": escalation.stage_totals(con, days),
                },
                # executive framing: a comparison, a direction, a sentence
                "trends": exec_view.trends(con, days),
                "odds": exec_view.odds(con, days),
                "concentration": exec_view.concentration(con, days),
                "goals": exec_view.goals(con, days),
                "health": exec_view.health(con),
            },
            days,
        )
    finally:
        con.close()


@router.get("/api/v1/health")
def health():
    con = _con()
    try:
        return ok(exec_view.health(con))
    finally:
        con.close()


@router.get("/api/v1/rail")
def rail(days: int = Query(30, ge=1, le=3650)):
    con = _con()
    try:
        return ok(escalation.rail(con, days), days)
    finally:
        con.close()


@router.get("/api/v1/spikes")
def spikes(days: int = Query(90, ge=7, le=3650)):
    con = _con()
    try:
        return ok(spikemod.timeline(con, days), days)
    finally:
        con.close()


# --------------------------------------------------------------------------
# sources
# --------------------------------------------------------------------------

@router.get("/api/v1/sources")
def sources(days: int = Query(30, ge=1, le=3650),
            min_stage: int = Query(0, ge=0, le=4),
            limit: int = Query(100, ge=1, le=1000),
            offset: int = Query(0, ge=0)):
    con = _con()
    try:
        sc = db.source_columns(con)
        countries = []
        if sc["country"] and sc["ip"]:
            cols = sc["columns"]
            evt = "event_count" if "event_count" in cols else None
            name = "country" if "country" in cols else sc["country"]
            countries = db.qall(
                con,
                f"SELECT {name} AS country, {sc['country']} AS code, COUNT(*) sources"
                + (f", SUM({evt}) events" if evt else ", 0 events")
                + f" FROM sources WHERE {sc['country']} IS NOT NULL"
                f" GROUP BY {sc['country']} ORDER BY events DESC, sources DESC LIMIT 12",
            )
        return ok(
            {
                "sources": escalation.sources(con, days, min_stage, limit, offset),
                "stage_totals": escalation.stage_totals(con, days),
                "asn_abuse": asnmod.abuse_scores(con, days, 20),
                "countries": countries,
                "fingerprints": fingerprints.overview(con, days, 20),
            },
            days,
        )
    finally:
        con.close()


@router.get("/api/v1/sources/{ip}")
def source_detail(ip: str):
    con = _con()
    try:
        data = escalation.source_detail(con, ip)
        if not data.get("source"):
            raise HTTPException(status_code=404, detail="source not seen")
        return ok(data)
    finally:
        con.close()


# --------------------------------------------------------------------------
# credentials
# --------------------------------------------------------------------------

@router.get("/api/v1/credentials")
def credentials(days: int = Query(30, ge=1, le=3650),
                limit: int = Query(40, ge=1, le=200)):
    con = _con()
    try:
        tiers = []
        if db.table_exists(con, "v_cred_attempts"):
            try:
                tiers = db.qall(
                    con,
                    "SELECT cred_tier, COUNT(*) attempts, COUNT(DISTINCT src_ip) ips,"
                    " SUM(succeeded) succeeded FROM v_cred_attempts GROUP BY cred_tier",
                )
            except Exception:
                tiers = []
        top = credmod.top_pairs(con, days, 25)
        return ok(
            {
                "campaigns": credmod.campaigns(con, days, limit),
                "top_pairs": top,
                "tiers": tiers,
            },
            days,
        )
    finally:
        con.close()


@router.get("/api/v1/credentials/{tag}")
def credential_campaign(tag: str, days: int = Query(30, ge=1, le=3650),
                        limit: int = Query(100, ge=1, le=1000)):
    con = _con()
    try:
        return ok(credmod.campaign_detail(con, tag, days, limit), days)
    finally:
        con.close()


# --------------------------------------------------------------------------
# payloads
# --------------------------------------------------------------------------

@router.get("/api/v1/payloads")
def payloads(days: int = Query(30, ge=1, le=3650),
             limit: int = Query(200, ge=1, le=1000)):
    con = _con()
    try:
        return ok(
            {
                "summary": payloadmod.summary(con, days),
                "payloads": payloadmod.list_payloads(con, days, None, limit),
                "hosts": payloadmod.hosts(con, days, 40),
                "families": fammod.overview(con, days, 20),
                "contributions": {
                    "summary": contribmod.summary(con, days),
                    "items": contribmod.contributions(con, 50),
                },
            },
            days,
        )
    finally:
        con.close()


@router.get("/api/v1/contributions")
def contributions(limit: int = Query(200, ge=1, le=1000)):
    """Samples this sensor uploaded upstream, with capture context, detection
    trajectory and first-submitter attribution. Lifetime, not windowed: a
    contribution does not stop being one when it ages out of the window."""
    con = _con()
    try:
        return ok({"summary": contribmod.summary(con),
                   "contributions": contribmod.contributions(con, limit)})
    finally:
        con.close()


@router.get("/api/v1/payloads/{shasum}")
def payload_detail(shasum: str):
    con = _con()
    try:
        return ok(payloadmod.payload_detail(con, shasum))
    finally:
        con.close()


# --------------------------------------------------------------------------
# sessions and samples
# --------------------------------------------------------------------------
@router.get("/api/v1/sessions")
def sessions(days: int = Query(30, ge=1, le=3650),
             limit: int = Query(200, ge=1, le=1000)):
    con = _con()
    try:
        return ok(sessmod.sessions_with_files(con, days=days, limit=limit), days)
    finally:
        con.close()


@router.get("/api/v1/sessions/{session}")
def session_detail(session: str):
    con = _con()
    try:
        data = sessmod.session_detail(con, session)
        if "error" in data:
            raise HTTPException(status_code=404, detail=data["error"])
        return ok(data)
    finally:
        con.close()


@router.get("/api/v1/samples/{shasum}")
def sample_detail(shasum: str):
    con = _con()
    try:
        data = sessmod.sample_detail(con, shasum)
        if "error" in data:
            raise HTTPException(status_code=400, detail=data["error"])
        return ok(data)
    finally:
        con.close()


# --------------------------------------------------------------------------
# tunnels and funnel
# --------------------------------------------------------------------------

@router.get("/api/v1/tunnels")
def tunnels(days: int = Query(30, ge=1, le=3650)):
    con = _con()
    try:
        return ok(tunnelmod.overview(con, days, 50), days)
    finally:
        con.close()


@router.get("/api/v1/funnel")
def funnel(days: int = Query(30, ge=1, le=3650)):
    con = _con()
    try:
        data = funnelmod.funnel(con, days)
        data["silent"] = funnelmod.silent_sessions(con, days, 50)
        return ok(data, days)
    finally:
        con.close()
