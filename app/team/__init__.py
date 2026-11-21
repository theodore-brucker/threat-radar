"""The threat intel team: a daily review of what the sensor recorded.

One run covers one Eastern day and has five parts, each in its own module:

  bundle.py   gathers the day's facts from the collector database, read-only
  stages.py   four model stages turn the facts into analysis:
                reader    reads the recorded activity and describes it
                research  looks up a short list of indicators on the web
                tracker   files the day's activity under campaigns
                editor    writes the report
  kb.py       turns the tracker's answer into knowledge base files
  charts.py   draws the day's charts as PNG files
  report.py   renders the report as an email and as a Markdown page

bin/team_worker.py runs those as the radar-team account and leaves the result
in an outbox. bin/team_publish.py runs as a second account, radar-team-pub,
which holds the credentials: it checks the outbox, commits the knowledge base,
files suggestions as issues and sends the email. docs/TEAM.md describes the
trust boundaries between them.
"""

import os

# Where the worker keeps its own state: stage outputs for review and the
# outbox the publisher reads.
STATE_DIR = os.environ.get("TR_TEAM_STATE", "/var/lib/radar-team")
# The publisher's clone of the private knowledge base. The worker only reads it.
KB_DIR = os.environ.get("TR_TEAM_KB", "/var/lib/radar-team-pub/kb")

KEEP_DAYS = 14          # days of stage outputs and outboxes kept on disk

AREAS = ("persona", "sensor", "classification", "site", "pipeline")
