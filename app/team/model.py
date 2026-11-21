"""One model call, through the claude CLI, with the tools named by the caller.

Every stage reads text that began with an attacker or with a web page, so a
stage gets no tools unless it asks for one by name, and the only tool any
stage asks for is WebSearch. The CLI runs in an empty temporary directory,
loads no MCP servers and no slash commands, keeps no session on disk, and has
its system prompt replaced by the stage's own instructions.

The answer comes back as text. ask_json() takes the JSON object out of it and
returns a dict, and the stage that called it checks every field before any of
it is used.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time

BIN = os.environ.get("TR_CLAUDE_BIN", "claude")
MODEL = os.environ.get("TR_TEAM_MODEL", "opus")
TIMEOUT = int(os.environ.get("TR_TEAM_STAGE_TIMEOUT", "900"))
RETRIES = 1


class StageError(RuntimeError):
    """A stage produced nothing usable. The message is short enough to mail."""


def available():
    return bool(shutil.which(BIN))


def command(system, tools=(), model=None):
    cmd = [BIN, "-p", "--model", model or MODEL, "--output-format", "json",
           "--tools", ",".join(tools),
           "--strict-mcp-config", "--no-session-persistence",
           "--disable-slash-commands", "--system-prompt", system]
    if tools:
        # Print mode refuses a tool nobody approved, so the one tool a stage
        # may use is approved here.
        cmd += ["--allowedTools", ",".join(tools)]
    return cmd


def ask(system, document, tools=(), model=None, run=subprocess.run):
    """Send one document under one system prompt and return the answer text."""
    with tempfile.TemporaryDirectory(prefix="team-llm-") as cwd:
        try:
            proc = run(command(system, tools, model), input=document,
                       capture_output=True, text=True, timeout=TIMEOUT, cwd=cwd)
        except subprocess.TimeoutExpired:
            raise StageError("the model did not answer within %d seconds" % TIMEOUT)
        except OSError as exc:
            raise StageError("could not run %s: %s" % (BIN, exc))
    try:
        envelope = json.loads(proc.stdout)
    except ValueError:
        envelope = None
    result = envelope.get("result") if isinstance(envelope, dict) else None
    # A failed API call can exit 0 or 1. Either way the envelope's result
    # field holds the reason, and is_error is set.
    if isinstance(result, str) and (envelope.get("is_error") or proc.returncode != 0):
        raise StageError("the model call failed: %s" % result[:300])
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "").strip()[-300:]
        raise StageError("claude exited %d: %s" % (proc.returncode, tail))
    if not isinstance(result, str):
        raise StageError("claude printed something other than its JSON envelope")
    return result


def parse_object(text):
    """The JSON object in an answer, whether or not prose or a code fence
    surrounds it."""
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise StageError("the answer held no JSON object")
    try:
        obj = json.loads(text[start:end + 1])
    except ValueError as exc:
        raise StageError("the answer was not valid JSON: %s" % exc)
    if not isinstance(obj, dict):
        raise StageError("the answer was JSON but not an object")
    return obj


def ask_json(system, document, tools=(), model=None, run=subprocess.run,
             sleep=time.sleep):
    """ask() and parse_object(), tried once more after a failure, since most
    failures are a busy API or one malformed answer."""
    for attempt in range(RETRIES + 1):
        try:
            return parse_object(ask(system, document, tools, model, run))
        except StageError:
            if attempt == RETRIES:
                raise
            sleep(20)
