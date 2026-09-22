"""The pieces of the pipeline the end-to-end tests do not reach on their own.

Enrichment runs against a stand-in for the MaxMind readers, because checking
MaxMind's test databases in would bring their licence with them; what matters
here is the handling around the lookups, not the lookups. Pruning is checked
for what it must never delete. Spike scoring is checked against the claim the
method page makes about it.
"""

import datetime as dt
import importlib.util
import os
import time
import types
from unittest import mock

import geoip2.errors

from tests.support import DBTestCase, ROOT
from app.analytics import spikes


def load(name, path, **env):
    with mock.patch.dict(os.environ, env):
        spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, path))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
    return mod


class FakeReaders:
    """Answers like geoip2 for known addresses and raises like it for the rest."""

    def __init__(self, known):
        self.known = known

    def city(self, ip):
        if ip not in self.known:
            raise geoip2.errors.AddressNotFoundError("not found", ip, 0)
        return types.SimpleNamespace(
            country=types.SimpleNamespace(name="Testland", iso_code="TL"),
            city=types.SimpleNamespace(name="Example City"),
            location=types.SimpleNamespace(latitude=1.5, longitude=2.5))

    def asn(self, ip):
        if ip not in self.known:
            raise ValueError("not an address it knows")
        return types.SimpleNamespace(autonomous_system_number=64496,
                                     autonomous_system_organization="Example Net")


class EnrichTests(DBTestCase):
    def setUp(self):
        super().setUp()
        self.enrich = load("enrich_under_test", "enrich.py")
        for ip in ("192.0.2.10", "198.51.100.20", "not-an-address"):
            self.con.execute("INSERT INTO sources(ip, first_seen, last_seen, event_count)"
                             " VALUES(?, '2026-09-21', '2026-09-21', 1)", (ip,))
        self.con.commit()

    def test_known_addresses_are_tagged_and_unknown_ones_still_complete(self):
        readers = FakeReaders({"192.0.2.10"})
        self.assertEqual(self.enrich.enrich_batch(self.con, readers, readers), 3)
        rows = {r["ip"]: r for r in self.con.execute("SELECT * FROM sources")}
        self.assertEqual((rows["192.0.2.10"]["country_code"], rows["192.0.2.10"]["asn"]), ("TL", 64496))
        # An address the databases do not know is marked done, not retried forever.
        self.assertIsNotNone(rows["198.51.100.20"]["enriched_at"])
        self.assertIsNone(rows["198.51.100.20"]["asn"])
        self.assertIsNotNone(rows["not-an-address"]["enriched_at"])

    def test_a_second_pass_has_nothing_left_to_do(self):
        readers = FakeReaders(set())
        self.enrich.enrich_batch(self.con, readers, readers)
        self.assertEqual(self.enrich.enrich_batch(self.con, readers, readers), 0)


class PruneTests(DBTestCase):
    def setUp(self):
        super().setUp()
        self.spool = os.path.join(self.tmp, "spool")
        os.makedirs(self.spool)
        self.prune = load("prune_parts", "prune.py", TR_RETAIN_DAYS="30",
                          TR_SPOOL_RETAIN_DAYS="8", TR_ROLLUP_RETAIN_DAYS="36500")
        self.prune.SPOOL = self.spool
        self.prune.log = lambda *_: None

    def spool_file(self, name, days_old):
        path = os.path.join(self.spool, name)
        with open(path, "w") as fh:
            fh.write("{}\n")
        t = time.time() - days_old * 86400
        os.utime(path, (t, t))
        self.con.execute("INSERT OR REPLACE INTO ingest_state(filename, byte_offset) VALUES(?, 3)", (name,))
        self.con.commit()

    def test_old_rotated_files_go_but_the_live_file_never_does(self):
        self.spool_file("cowrie.json", 40)
        self.spool_file("cowrie.json.2026-08-01", 40)
        self.spool_file("cowrie.json.2026-09-20", 1)
        self.assertEqual(self.prune.prune_spool(self.con), 1)
        self.assertEqual(sorted(os.listdir(self.spool)), ["cowrie.json", "cowrie.json.2026-09-20"])
        left = {r[0] for r in self.con.execute("SELECT filename FROM ingest_state")}
        self.assertEqual(left, {"cowrie.json", "cowrie.json.2026-09-20"})

    def test_heartbeats_and_other_files_are_left_alone(self):
        for name in (".pulled", "notes.txt"):
            path = os.path.join(self.spool, name)
            open(path, "w").close()
            os.utime(path, (0, 0))
        self.prune.prune_spool(self.con)
        self.assertEqual(sorted(os.listdir(self.spool)), [".pulled", "notes.txt"])

    def test_rollups_are_kept_at_the_configured_horizon(self):
        old = (dt.date.today() - dt.timedelta(days=400)).isoformat()
        self.con.execute("INSERT INTO eventid_daily(day, eventid, events) VALUES(?, 'x', 5)", (old,))
        self.con.commit()
        self.prune.prune_rollups(self.con)
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM eventid_daily").fetchone()[0], 1,
                         "a rollup older than a year was pruned under an indefinite horizon")

    def test_sources_with_surviving_events_are_kept(self):
        old = "2026-01-01T00:00:00+00:00"
        for ip in ("192.0.2.1", "192.0.2.2"):
            self.con.execute("INSERT INTO sources(ip, first_seen, last_seen, event_count)"
                             " VALUES(?, ?, ?, 1)", (ip, old, old))
        self.add_event("cowrie.session.connect", "s", "192.0.2.1", "2026-09-21T00:00:00Z")
        self.prune.prune_sources(self.con)
        self.assertEqual([r[0] for r in self.con.execute("SELECT ip FROM sources")], ["192.0.2.1"])


class SpikeScoringTests(DBTestCase):
    def series(self, values):
        start = dt.date(2026, 8, 1)
        return [{"day": (start + dt.timedelta(days=i)).isoformat(), "events": v}
                for i, v in enumerate(values)]

    def test_a_single_day_surge_is_flagged(self):
        scored = spikes.score_series(self.series([1000] * 20 + [9000]))
        self.assertTrue(scored[-1]["spike"])
        self.assertFalse(any(r["spike"] for r in scored[:-1]))

    def test_a_multi_day_surge_does_not_hide_itself(self):
        # The method page's claim: a surge lasting days would inflate a mean
        # and standard deviation enough to hide its own later days. The median
        # and MAD baseline must still flag the third day of one.
        values = [1000 + (i % 3) * 20 for i in range(20)] + [9000, 9500, 9800]
        scored = spikes.score_series(self.series(values))
        self.assertTrue(scored[-1]["spike"], scored[-1])

    def test_too_little_history_is_never_a_spike(self):
        scored = spikes.score_series(self.series([10, 10000]))
        self.assertFalse(any(r["spike"] for r in scored))
        self.assertIsNone(scored[-1]["z"])

    def test_small_numbers_are_not_spikes(self):
        scored = spikes.score_series(self.series([2] * 20 + [40]))
        self.assertFalse(scored[-1]["spike"], "a jump from 2 to 40 events is noise, not a spike")
