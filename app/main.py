#!/usr/bin/env python3
"""Threat Radar.

One FastAPI app serving one site. All JSON lives under /api/v1 with a single
envelope; all pages return the same shell and are routed client side.

Attacker-controlled strings leave this API as JSON values only. The frontend
renders exclusively through textContent and never innerHTML, so hostile
usernames, commands and filenames stay inert. The response headers set below
are the second half of that: a content security policy that excludes inline
script means an injection that somehow reached the DOM still could not run.
"""

import os
import sys

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

BASE = os.environ.get("TR_BASE", "/opt/threat-radar")
sys.path.insert(0, BASE)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

app = FastAPI(title="Threat Radar", docs_url=None, redoc_url=None)

from app.shell import router as shell_router, SECURITY_HEADERS, not_found  # noqa: E402
from app.routers.site import router as site_router  # noqa: E402


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    for key, value in SECURITY_HEADERS.items():
        response.headers.setdefault(key, value)
    return response


# The shell router first: it re-registers the page paths so they render the
# prefix-aware HTML instead of the raw file. Everything else in site.py is
# untouched and still owns the whole /api/v1 surface.
app.include_router(shell_router)
app.include_router(site_router)

# Unknown page paths render the shell with a 404 status; the client shows the
# not-found page. API and static misses are untouched.
app.add_exception_handler(StarletteHTTPException, not_found)

# Static last: a mount would otherwise shadow every route registered after it.
app.mount("/static", StaticFiles(directory=STATIC), name="static")
