#!/usr/bin/env python3
"""Run commands in the shell the sensor presents, without the sensor.

    python tools/sensor_shell.py 'echo $((2+3))' 'grep -ci root /etc/passwd'
    python tools/sensor_shell.py < commands.txt
    python tools/sensor_shell.py --unpatched 'echo $((2+3))'

The script copies the installed Cowrie package to a temporary directory,
applies every patch in sensor/patches to the copy and feeds each command to
Cowrie's emulated shell. Each argument, or each line of standard input, is one
command typed into the same session. It prints what an attacker's terminal
would show.

It needs the Cowrie release the sensor runs in the current environment:

    python -m pip install --require-hashes -r requirements-cowrie.txt

The filesystem and command output come from the files Cowrie ships. The sensor
serves its own persona files instead, so the script answers questions about
the shell and not about the persona's content. `--honeyfs DIR`, `--txtcmds
DIR` and `--fs PICKLE` point it at a persona's files when that matters.

Nothing here opens a network connection, and the commands never reach a real
shell: Cowrie's emulation interprets them.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PATCHES = ROOT / "sensor" / "patches"
PROMPT = "root@unitTest:~# "


def installed_cowrie() -> Path | None:
    """Where the Cowrie package lives, or None when it is not installed."""
    spec = importlib.util.find_spec("cowrie")
    if spec is None or not spec.submodule_search_locations:
        return None
    return Path(next(iter(spec.submodule_search_locations)))


def build(dest: Path, patches: Path | None = PATCHES) -> Path:
    """Copy the installed Cowrie into `dest` and apply the patches in name
    order, the order the sensor applies them in. Returns the directory to put
    on the import path."""
    package = installed_cowrie()
    if package is None:
        raise RuntimeError("Cowrie is not installed in this environment")
    shutil.copytree(package, dest / "src" / "cowrie",
                    ignore=shutil.ignore_patterns("__pycache__"))
    files = sorted(patches.glob("*.patch")) if patches else []
    if files:
        # The patches name paths from the top of Cowrie's repository, which
        # is why the copy sits under src/.
        subprocess.run(["git", "apply", *map(str, files)], cwd=dest, check=True)
    return dest / "src"


def run_script(tree: Path, script: Path, stdin: str = "",
               honeyfs: Path | None = None, txtcmds: Path | None = None,
               arguments: tuple[str, ...] = (),
               filesystem: Path | None = None) -> object:
    """Run a Python file with the copy in `tree` as its Cowrie, in an empty
    working directory, and return the JSON on the last line it prints.
    Cowrie reads its settings from the environment, so nothing here depends on
    a cowrie.cfg."""
    data = tree / "cowrie" / "data"
    scratch = Path(tempfile.mkdtemp(prefix="sensor-shell-"))
    env = {
        "PATH": os.environ.get("PATH", ""),
        "PYTHONPATH": str(tree),
        "COWRIE_HONEYPOT_DATA_PATH": str(data),
        "COWRIE_HONEYPOT_CONTENTS_PATH": str(honeyfs or data),
        "COWRIE_HONEYPOT_TXTCMDS_PATH": str(txtcmds or data / "txtcmds"),
        "COWRIE_HONEYPOT_DOWNLOAD_PATH": str(scratch / "downloads"),
        "COWRIE_HONEYPOT_STATE_PATH": str(scratch / "state"),
        "COWRIE_SHELL_FILESYSTEM": str(filesystem or data / "fs.pickle"),
    }
    (scratch / "downloads").mkdir()
    (scratch / "state").mkdir()
    try:
        done = subprocess.run(
            [sys.executable, str(script.resolve()), *arguments], input=stdin,
            capture_output=True, text=True, env=env, cwd=scratch, check=False,
            timeout=300)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    if done.returncode != 0:
        raise RuntimeError(f"{script.name} failed:\n{done.stderr[-3000:]}")
    # Cowrie logs to standard output, so the answer is the last line.
    return json.loads(done.stdout.rsplit("\n", 1)[-1])


def run(tree: Path, sessions: list[list[str]], honeyfs: Path | None = None,
        txtcmds: Path | None = None,
        filesystem: Path | None = None) -> list[list[str]]:
    """Run each session's commands in a new emulated shell. Returns, for each
    session, what each command printed, with the prompts removed."""
    return run_script(tree, Path(__file__), json.dumps(sessions), honeyfs,
                      txtcmds, ("--child",), filesystem)


def child() -> None:
    """Inside the copy: drive Cowrie's shell with its own test doubles."""
    from cowrie.shell.protocol import HoneyPotInteractiveProtocol
    from cowrie.test.fake_server import FakeAvatar, FakeServer
    from cowrie.test.fake_transport import FakeTransport

    transcripts = []
    for commands in json.load(sys.stdin):
        protocol = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
        transport = FakeTransport("", "31337")
        protocol.makeConnection(transport)
        outputs = []
        for command in commands:
            transport.clear()
            protocol.lineReceived(command.encode() + b"\n")
            text = transport.value().decode("utf-8", "replace")
            outputs.append(text.replace(PROMPT, ""))
        transcripts.append(outputs)
        protocol.connectionLost()
    sys.stdout.write("\n" + json.dumps(transcripts))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("commands", nargs="*", help="commands for one session")
    parser.add_argument("--unpatched", action="store_true",
                        help="run the release as shipped, without the patches")
    parser.add_argument("--honeyfs", type=Path, help="a persona's honeyfs directory")
    parser.add_argument("--txtcmds", type=Path, help="a persona's txtcmds directory")
    parser.add_argument("--fs", type=Path, help="a persona's fs.pickle")
    parser.add_argument("--child", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.child:
        child()
        return 0
    commands = args.commands or [line.rstrip("\n") for line in sys.stdin if line.strip()]
    if installed_cowrie() is None:
        print("Cowrie is not installed here. See the top of this file.",
              file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="sensor-tree-") as tmp:
        tree = build(Path(tmp), None if args.unpatched else PATCHES)
        paths = [path and path.resolve() for path in (args.honeyfs, args.txtcmds, args.fs)]
        outputs = run(tree, [commands], *paths)[0]
        for command, output in zip(commands, outputs, strict=True):
            print(f"$ {command}\n{output}", end="" if output.endswith("\n") else "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
