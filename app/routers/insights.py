"""Insights API.

Mounted by app/main.py. Every handler opens its own read-only connection and
closes it, matching the existing dashboard convention. Nothing here writes to
the database; the intel worker owns the write path.
"""

import os

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import FileResponse

from app.analytics import asn as asnmod
from app.analytics import credentials as credmod
from app.analytics import db
from app.analytics import funnel as funnelmod
from app.analytics import payloads as payloadmod
from app.analytics import spikes as spikemod
from app.analytics import tunnels as tunnelmod

router = APIRouter(tags=["insights"])

STATIC_PAGE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "insights.html"
)


def _con():
    try:
        return db.connect_ro()
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"database unavailable: {exc}")


@router.get("/insights", include_in_schema=False)
def insights_page():
    if not os.path.exists(STATIC_PAGE):
        raise HTTPException(status_code=404, detail="insights page not installed")
    return FileResponse(STATIC_PAGE)


@router.get("/api/insights/status")
def status():
    con = _con()
    try:
        keys = [
            "last_run",
            "last_run_seconds",
            "facts_built_at",
            "sessions_built_at",
            "tunnels_built_at",
            "payloads_built_at",
            "credentials_built_at",
            "spikes_built_at",
            "intel_built_at",
        ]
        state = {k: db.get_state(con, k) for k in keys}
        tables = {
            t: db.table_exists(con, t)
            for t in (
                "asn_ip_daily",
                "session_facts",
                "tunnel_targets",
                "payloads",
                "payload_intel",
                "cred_pairs",
                "spike_annotations",
            )
        }
        return {"version": "2.0.0", "state": state, "tables": tables}
    finally:
        con.close()


# --- payloads --------------------------------------------------------------

@router.get("/api/insights/payloads")
def payloads(
    days: int = Query(30, ge=1, le=365),
    direction: str = Query(None, pattern="^(download|upload)$"),
    limit: int = Query(200, ge=1, le=1000),
):
    con = _con()
    try:
        out = payloadmod.list_payloads(con, days, direction, limit)
        out["summary"] = payloadmod.summary(con, days)
        return out
    finally:
        con.close()


@router.get("/api/insights/payloads/hosts")
def payload_hosts(days: int = Query(30, ge=1, le=365), limit: int = Query(50, ge=1, le=500)):
    con = _con()
    try:
        return payloadmod.hosts(con, days, limit)
    finally:
        con.close()


@router.get("/api/insights/payloads/{shasum}")
def payload_detail(shasum: str):
    con = _con()
    try:
        return payloadmod.payload_detail(con, shasum)
    finally:
        con.close()


# --- credentials -----------------------------------------------------------

@router.get("/api/insights/credentials/campaigns")
def cred_campaigns(days: int = Query(30, ge=1, le=365), limit: int = Query(40, ge=1, le=200)):
    con = _con()
    try:
        return credmod.campaigns(con, days, limit)
    finally:
        con.close()


@router.get("/api/insights/credentials/campaigns/{tag}")
def cred_campaign(tag: str, limit: int = Query(100, ge=1, le=1000)):
    con = _con()
    try:
        return credmod.campaign_detail(con, tag, limit)
    finally:
        con.close()


# --- ASN -------------------------------------------------------------------

@router.get("/api/insights/asn/abuse")
def asn_abuse(days: int = Query(30, ge=1, le=365), limit: int = Query(25, ge=1, le=200)):
    con = _con()
    try:
        return asnmod.abuse_scores(con, days, limit)
    finally:
        con.close()


@router.get("/api/insights/asn/{asn}")
def asn_detail(asn: str, days: int = Query(30, ge=1, le=365)):
    con = _con()
    try:
        return asnmod.asn_detail(con, asn, days)
    finally:
        con.close()


# --- funnel ----------------------------------------------------------------

@router.get("/api/insights/funnel")
def funnel(days: int = Query(30, ge=1, le=365)):
    con = _con()
    try:
        out = funnelmod.funnel(con, days)
        out["commands"] = funnelmod.command_gap(con, days)
        return out
    finally:
        con.close()


@router.get("/api/insights/funnel/silent-sessions")
def silent_sessions(
    days: int = Query(30, ge=1, le=365),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    con = _con()
    try:
        return funnelmod.silent_sessions(con, days, limit, offset)
    finally:
        con.close()


# --- tunnels ---------------------------------------------------------------

@router.get("/api/insights/tunnels")
def tunnels(days: int = Query(30, ge=1, le=365), limit: int = Query(50, ge=1, le=500)):
    con = _con()
    try:
        return tunnelmod.overview(con, days, limit)
    finally:
        con.close()


# --- spikes ----------------------------------------------------------------

@router.get("/api/insights/spikes")
def spikes(days: int = Query(90, ge=7, le=365)):
    con = _con()
    try:
        return spikemod.timeline(con, days)
    finally:
        con.close()
