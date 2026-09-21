"""Every read path opens the database so that it cannot write, twice over.

mode=ro in the URI refuses writes at open time, and query_only refuses them
per statement, so a future change that passes the wrong path or flags still
cannot turn the dashboard into something that modifies the evidence.
"""

import sqlite3

from tests.support import DBTestCase
from app.analytics import db


class ReadOnlyTests(DBTestCase):
    def test_read_connections_refuse_every_kind_of_write(self):
        ro = db.connect_ro(self.db_path)
        self.addCleanup(ro.close)
        for stmt in ("CREATE TABLE x(a)", "DELETE FROM raw_events",
                     "INSERT INTO insights_state(key,value,updated_at) VALUES('k','v','t')"):
            with self.assertRaises(sqlite3.OperationalError, msg=stmt):
                ro.execute(stmt)

    def test_query_only_is_set(self):
        ro = db.connect_ro(self.db_path)
        self.addCleanup(ro.close)
        self.assertEqual(ro.execute("PRAGMA query_only").fetchone()[0], 1)
