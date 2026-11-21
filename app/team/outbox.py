"""The handoff between the two accounts.

The worker writes one directory per day and the publisher reads it:

  outbox/<day>/manifest.json   what is in the directory, with a hash per file
  outbox/<day>/report.json     the report, as report.assemble() built it
  outbox/<day>/kb/...          files for the knowledge base, at their paths

The worker has spent the morning reading text attackers wrote, so the
publisher does not take its word for anything. check() accepts a file only
when its path matches ALLOWED, it is a regular file inside the outbox, it is
within the size for its type, its content is what its name says, and its
hash matches the manifest. Paths the operator owns (feedback.md, context/)
and the publisher's own state are not in ALLOWED, so nothing a model wrote
can replace them.

write() builds the directory beside its final name and renames it into
place, with the manifest written last, so the publisher never reads a
half-written day.
"""

import hashlib
import json
import os
import re
import shutil
import stat

SCHEMA = "threat-radar.team-outbox/1"

_SLUG = r"[a-z0-9][a-z0-9-]{2,59}"
_DAY = r"\d{4}-\d{2}-\d{2}"
ALLOWED = [re.compile(p) for p in (
    r"INDEX\.md",
    r"campaigns/%s\.md" % _SLUG,
    r"techniques/T\d{4}(\.\d{3})?\.md",
    r"daily/\d{4}/%s\.md" % _DAY,
    r"drafts/\d{4}-W\d{2}\.md",
    r"charts/%s/(volume|hours|networks)\.png" % _DAY,
    r"charts/campaigns/%s\.png" % _SLUG,
    r"charts/overview\.png",
    r"state/(campaigns|lessons)\.json",
)]
MAX_BYTES = {".md": 256 * 1024, ".png": 2 * 1024 * 1024, ".json": 4 * 1024 * 1024}
MAX_FILES = 400
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


class OutboxError(ValueError):
    """The outbox is missing, incomplete, or holds something it should not."""


def directory(state_dir, day):
    return os.path.join(state_dir, "outbox", day)


def allowed(rel):
    # fullmatch, because `$` also matches before a trailing newline.
    return any(p.fullmatch(rel) for p in ALLOWED)


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def write(state_dir, day, report, files):
    """Leave a day in the outbox. files maps a knowledge base path to its
    content, text or bytes."""
    final = directory(state_dir, day)
    building = final + ".building"
    shutil.rmtree(building, ignore_errors=True)
    os.makedirs(os.path.join(building, "kb"))
    listed = {}
    for rel, content in sorted(files.items()):
        if not allowed(rel):
            raise OutboxError("refusing to stage a path the publisher would reject: %s" % rel)
        data = content if isinstance(content, bytes) else content.encode("utf-8")
        path = os.path.join(building, "kb", rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(data)
        listed[rel] = _sha256(data)
    body = json.dumps(report, indent=1, sort_keys=True).encode("utf-8")
    with open(os.path.join(building, "report.json"), "wb") as fh:
        fh.write(body)
    manifest = {"schema": SCHEMA, "day": day, "report": _sha256(body), "files": listed}
    with open(os.path.join(building, "manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=1, sort_keys=True)
    shutil.rmtree(final, ignore_errors=True)
    os.rename(building, final)
    return final


def _read_regular(root, path, limit):
    """The bytes of a regular file that sits inside root, or an error. A
    symlink, a device or a path that climbs out is refused before any read."""
    real_root = os.path.realpath(root)
    if not os.path.realpath(path).startswith(real_root + os.sep):
        raise OutboxError("path leaves the outbox: %s" % path)
    try:
        info = os.lstat(path)
    except OSError:
        raise OutboxError("listed file is missing: %s" % path)
    if not stat.S_ISREG(info.st_mode):
        raise OutboxError("not a regular file: %s" % path)
    if info.st_size > limit:
        raise OutboxError("file is larger than its limit: %s" % path)
    with open(path, "rb") as fh:
        return fh.read(limit + 1)


def _load_json(data, what):
    try:
        return json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise OutboxError("%s is not JSON" % what)


def check(state_dir, day):
    """(report dict, {knowledge base path: bytes}) for a day, or OutboxError."""
    root = directory(state_dir, day)
    if not os.path.isdir(root):
        raise OutboxError("no outbox for %s" % day)
    manifest = _load_json(_read_regular(root, os.path.join(root, "manifest.json"),
                                        MAX_BYTES[".json"]), "the manifest")
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA \
            or manifest.get("day") != day or not isinstance(manifest.get("files"), dict):
        raise OutboxError("the manifest is not one this version wrote for %s" % day)
    if len(manifest["files"]) > MAX_FILES:
        raise OutboxError("the manifest lists more than %d files" % MAX_FILES)

    body = _read_regular(root, os.path.join(root, "report.json"), MAX_BYTES[".json"])
    if _sha256(body) != manifest.get("report"):
        raise OutboxError("report.json does not match the manifest")
    report = _load_json(body, "report.json")

    files = {}
    for rel, digest in manifest["files"].items():
        if not isinstance(rel, str) or not allowed(rel):
            raise OutboxError("path is not one the knowledge base accepts: %r" % rel)
        suffix = os.path.splitext(rel)[1]
        data = _read_regular(root, os.path.join(root, "kb", rel), MAX_BYTES[suffix])
        if _sha256(data) != digest:
            raise OutboxError("file does not match the manifest: %s" % rel)
        if suffix == ".png" and not data.startswith(PNG_MAGIC):
            raise OutboxError("not a PNG: %s" % rel)
        if suffix == ".json":
            _load_json(data, rel)
        if suffix == ".md":
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                raise OutboxError("not UTF-8 text: %s" % rel)
        files[rel] = data
    return report, files
