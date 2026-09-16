"""Page shell rendering and the content security policy that goes with it.

Two jobs, both of which exist so the site can be published under a path on
theobrucker.us rather than only served at the root of the Pi.

1.  Mount prefix. Every asset link and the boot script carry a __TR_BASE__
    placeholder that is replaced with TR_URL_PREFIX at request time. The
    client resolves the same prefix independently from its own module URL, so
    the router, the API calls and the entity links all agree without a build
    step. Default is the empty string, which is exactly what the LAN
    deployment already serves.

2.  Content security policy. The shell carries one inline script, the
    pre-paint theme resolver, and its sha256 is computed from the file itself
    at import time. That means script-src can exclude 'unsafe-inline' without
    the policy going stale the next time the shell is edited.

These routes are registered ahead of the ones in routers/site.py, which keeps
the change to a single import in main.py and leaves the API surface alone.
"""

import base64
import hashlib
import os
import re

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

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
