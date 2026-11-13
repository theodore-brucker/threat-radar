"""Page shell rendering and the content security policy that goes with it.

It does two things so the site can be published under a path on
theobrucker.us as well as served at the root of the Pi.

1.  Mount prefix. Every asset link and the boot script carry a __TR_BASE__
    placeholder that is replaced with TR_URL_PREFIX at request time. The
    client resolves the same prefix independently from its own module URL, so
    the router, the API calls and the entity links all agree without a build
    step. The default is the empty string, which serves the site at the root
    as the LAN deployment does.

2.  Content security policy. The shell carries one inline script, the
    pre-paint theme resolver, and its sha256 is computed from the file itself
    at import time, so script-src can exclude 'unsafe-inline' and the policy
    stays correct when the shell is edited.

These routes are registered ahead of the ones in routers/site.py, which keeps
the change to a single import in main.py and leaves the API surface alone.

3.  Not found. A path that is not a page, not under /api and not a static
    file gets the same shell with status 404, so a crawler or link checker
    sees the truth while a reader gets the site's own not-found page around
    it. API and static misses keep their plain responses.
"""

import base64
import hashlib
import os
import re

from fastapi import APIRouter
from fastapi.responses import HTMLResponse, JSONResponse

router = APIRouter()

STATIC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
SHELL_FILE = os.path.join(STATIC, "index.html")

# "" serves at the root. "/radar" serves under theobrucker.us/radar with nginx
# stripping the prefix before it proxies. A trailing slash is always dropped.
PREFIX = os.environ.get("TR_URL_PREFIX", "").rstrip("/")

_INLINE = re.compile(r"<script(?![^>]*\ssrc=)[^>]*>(.*?)</script>", re.DOTALL)


def _render():
    with open(SHELL_FILE, "r", encoding="utf-8") as fh:
        html = fh.read()
    return html.replace("__TR_BASE__", PREFIX)


def _csp(html):
    hashes = []
    for body in _INLINE.findall(html):
        digest = hashlib.sha256(body.encode("utf-8")).digest()
        hashes.append("'sha256-%s'" % base64.b64encode(digest).decode("ascii"))
    script_src = " ".join(["'self'"] + hashes)
    return "; ".join([
        "default-src 'self'",
        "script-src %s" % script_src,
        # Inline style attributes carry bar widths and stage colours, which are
        # computed per row. They are set through setAttribute on values this
        # app produces, never on attacker text.
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self'",
        "connect-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "base-uri 'none'",
        "object-src 'none'",
    ])


# Rendered once at import. The shell is static; only the prefix is injected.
SHELL_HTML = _render()
CSP = _csp(SHELL_HTML)

SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "same-origin",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=(), interest-cohort=()",
}


@router.get("/", include_in_schema=False)
@router.get("/sources", include_in_schema=False)
@router.get("/credentials", include_in_schema=False)
@router.get("/payloads", include_in_schema=False)
@router.get("/tunnels", include_in_schema=False)
@router.get("/method", include_in_schema=False)
@router.get("/sessions", include_in_schema=False)
@router.get("/session/{session}", include_in_schema=False)
@router.get("/sample/{shasum}", include_in_schema=False)
@router.get("/ip/{value}", include_in_schema=False)
@router.get("/asn/{value}", include_in_schema=False)
@router.get("/credential/{value}", include_in_schema=False)
@router.get("/hassh/{value}", include_in_schema=False)
@router.get("/url/{value}", include_in_schema=False)
@router.get("/day/{value}", include_in_schema=False)
def shell():
    return HTMLResponse(SHELL_HTML, headers={"Cache-Control": "no-cache"})


def _is_page_path(path):
    """True for a path a reader could have typed or followed as a page link."""
    rel = path[len(PREFIX):] if PREFIX and path.startswith(PREFIX) else path
    return not (rel.startswith("/api/") or rel.startswith("/static/") or rel == "/api")


async def not_found(request, exc):
    """404 handler: the shell for page paths, JSON for everything else.

    Registered for HTTPException in main.py. Any status other than 404 keeps
    the framework's own JSON shape, which is what the API contract tests and
    the front end's error messages expect.
    """
    status = getattr(exc, "status_code", 500)
    detail = getattr(exc, "detail", None)
    headers = getattr(exc, "headers", None)
    if status == 404 and request.method in ("GET", "HEAD") and _is_page_path(request.url.path):
        return HTMLResponse(SHELL_HTML, status_code=404, headers={"Cache-Control": "no-cache"})
    return JSONResponse({"detail": detail}, status_code=status, headers=headers)
