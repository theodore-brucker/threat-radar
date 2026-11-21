"""Incident trends API, under /api/v1/trends/ with the site's envelope.

Read-only: every request opens the database with db.connect_ro. A database
without the trends tables answers built=false, so the page can say the
worker has not run yet. The figures cover every week on record, so these
routes take no days parameter; the one the page's fetch helper appends is
ignored.
"""

import logging

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse, PlainTextResponse

from app.analytics import clock
from app.analytics import db
from app.trends import export as texport
from app.trends import read

router = APIRouter()
log = logging.getLogger("radar.trends")


def _con():
    try:
        return db.connect_ro()
    except Exception as exc:
        log.warning("database unavailable: %s", exc)
        raise HTTPException(status_code=503, detail="database unavailable") from exc


def ok(data):
    return {"ok": True, "generated_at": clock.iso(clock.now()), "data": clock.localize(data)}


@router.get("/api/v1/trends/summary")
def summary():
    con = _con()
    try:
        if not read.built(con):
            return ok({"built": False})
        return ok(dict(read.summary(con), built=True))
    finally:
        con.close()


@router.get("/api/v1/trends/rows")
def rows(ids: str = Query("", max_length=4000)):
    con = _con()
    try:
        if not read.built(con):
            return ok({"rows": []})
        try:
            return ok({"rows": read.rows(con, read.parse_ids(ids))})
        except read.BadValue as exc:
            raise HTTPException(status_code=400, detail=str(exc))
    finally:
        con.close()


@router.get("/api/v1/trends/{etype}/{value}")
def entity(etype: str, value: str):
    if etype not in read.HANDLERS:
        raise HTTPException(status_code=404, detail="unknown record type")
    con = _con()
    try:
        if not read.built(con):
            raise HTTPException(status_code=404, detail="the trends worker has not run yet")
        try:
            data = read.lookup(con, etype, value)
        except read.BadValue as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if data is None:
            raise HTTPException(status_code=404, detail=f"no {etype} with that name")
        return ok(data)
    finally:
        con.close()


@router.get("/api/v1/trends/export/{etype}/{value}")
def export(etype: str, value: str,
           format: str = Query("json", pattern="^(json|md)$"),
           brief: int = Query(1, ge=0, le=1),
           download: int = Query(0, ge=0, le=1)):
    if etype not in texport.TYPES:
        raise HTTPException(status_code=404, detail="unknown record type")
    con = _con()
    try:
        if not read.built(con):
            raise HTTPException(status_code=404, detail="the trends worker has not run yet")
        try:
            bundle = texport.build(con, etype, value)
        except read.BadValue as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if bundle is None:
            raise HTTPException(status_code=404, detail=f"no {etype} with that name")
    finally:
        con.close()
    headers = {"Cache-Control": "no-store"}
    if download:
        headers["Content-Disposition"] = 'attachment; filename="%s"' % texport.filename(
            bundle, "md" if format == "md" else "json")
    if format == "md":
        return PlainTextResponse(texport.to_markdown(bundle, brief=bool(brief)),
                                 media_type="text/markdown; charset=utf-8", headers=headers)
    return JSONResponse(ok(bundle), headers=headers)
