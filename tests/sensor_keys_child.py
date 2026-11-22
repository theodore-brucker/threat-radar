"""Exercise the implanted-key patch inside a patched copy of Cowrie.

tests/test_sensor_patches.py runs this file with the copy on the import path
and reads the JSON it prints. It is not collected as a test because it needs
Cowrie and Twisted, which the main test environment does not install.
"""
from __future__ import annotations

import json
import os
import sys

from cowrie.core import implanted_keys
from cowrie.core.checkers import HoneypotPublicKeyChecker
from cowrie.insults.insults import LoggingServerProtocol
from cowrie.shell.protocol import HoneyPotInteractiveProtocol
from cowrie.test.eventcapture import capture_eventlog
from cowrie.test.fake_server import FakeAvatar, FakeServer
from cowrie.test.fake_transport import FakeTransport
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from twisted.conch.ssh import keys
from twisted.cred.credentials import SSHPrivateKey
from twisted.python.failure import Failure

events, seen = capture_eventlog(protocol="ssh")
checker = HoneypotPublicKeyChecker()
results: dict[str, object] = {}


def new_key(kind: str = "ed25519") -> keys.Key:
    if kind == "rsa":
        return keys.Key(rsa.generate_private_key(65537, 2048))
    return keys.Key(ed25519.Ed25519PrivateKey.generate())


def attempt(user: bytes, key: keys.Key, signer: keys.Key | None = None) -> list[str]:
    """One authentication request. Returns the outcome and the event ids."""
    data = b"what the client signs"
    request = SSHPrivateKey(user, key.sshType(), key.public().blob(),
                            data if signer else None,
                            signer.sign(data) if signer else None)
    request.events = events
    seen.clear()
    outcome = checker.requestAvatarId(request)
    ids = [event["eventid"] for event in seen]
    if isinstance(outcome, Failure):
        return [type(outcome.value).__name__, *ids]
    fired: list[object] = []
    outcome.addBoth(fired.append)
    return [fired[0].decode() if isinstance(fired[0], bytes) else repr(fired[0]), *ids]


operator, stranger, second = new_key(), new_key(), new_key("rsa")
public = operator.public().toString("openssh").decode()

# A session implants the key the way the mdrfckr script does, and the close
# of the session is what records it.
shell = HoneyPotInteractiveProtocol(FakeAvatar(FakeServer()))
transport = FakeTransport("", "31337")
shell.makeConnection(transport)
shell.lineReceived(
    f'cd ~ && rm -rf .ssh && mkdir .ssh && echo "{public} mdrfckr">>.ssh/authorized_keys'
    " && chmod -R go= ~/.ssh && cd ~\n".encode())
results["before close"] = attempt(b"root", operator, operator)
closing = LoggingServerProtocol(lambda: None)
closing.terminalProtocol = None
closing.events = events
closing.redirFiles = set(shell.terminal.redirFiles)
closing.connectionLost()
results["redirect targets"] = sorted(virtual for _, virtual in closing.redirFiles) or \
    sorted(virtual for _, virtual in shell.terminal.redirFiles)

results["asks first"] = attempt(b"root", operator)
results["signed"] = attempt(b"root", operator, operator)
results["success event"] = {key: value for key, value in seen[-1].items()
                            if key in ("eventid", "username", "type", "implanted")}
results["wrong signature"] = attempt(b"root", operator, stranger)
results["other account"] = attempt(b"ubuntu", operator, operator)
results["unknown key"] = attempt(b"root", stranger, stranger)

# Hostile content: options before the key, junk, a broken key, random bytes.
hostile = (b"# comment\nssh-rsa AAAA!!!\n"
           b'command="/bin/x",no-pty ' + second.public().toString("openssh") + b" later\n"
           b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIbroken\n" + os.urandom(300))
results["hostile added"] = implanted_keys.record("/home/ubuntu/.ssh/authorized_keys", hostile)
results["hostile again"] = implanted_keys.record("/home/ubuntu/.ssh/authorized_keys", hostile)
results["rsa signed"] = attempt(b"ubuntu", second, second)
results["not a key file"] = [
    implanted_keys.record(path, hostile)
    for path in ("/tmp/authorized_keys", "/home/../root/.ssh/authorized_keys",
                 "/home/a b/.ssh/authorized_keys", "/root/.ssh/authorized_keys.bak")]

# The store is capped, and a damaged store refuses a key without raising.
implanted_keys.MAX_KEPT = 5
for _ in range(8):
    implanted_keys.record("/root/.ssh/authorized_keys",
                          new_key().public().toString("openssh"))
with open(implanted_keys.store_path(), encoding="ascii") as store:
    results["kept"] = len(store.read().splitlines())
with open(implanted_keys.store_path(), "wb") as store:
    store.write(os.urandom(4096) + b"\nroot not-a-fingerprint 1\n")
results["damaged store"] = attempt(b"root", operator, operator)
os.remove(implanted_keys.store_path())
os.rmdir(os.environ["COWRIE_HONEYPOT_STATE_PATH"])
results["no state directory"] = [
    implanted_keys.record("/root/.ssh/authorized_keys", hostile),
    *attempt(b"root", operator, operator)]

# Switched off, nothing is recorded and nothing is accepted.
os.makedirs(os.environ["COWRIE_HONEYPOT_STATE_PATH"])
implanted_keys.record("/root/.ssh/authorized_keys", public.encode())
results["on"] = attempt(b"root", operator, operator)[0]
os.environ["COWRIE_SSH_AUTH_PUBLICKEY_IMPLANTED"] = "false"
results["off"] = [attempt(b"root", operator, operator)[0],
                  implanted_keys.record("/root/.ssh/authorized_keys", hostile)]

sys.stdout.write("\n" + json.dumps(results))
