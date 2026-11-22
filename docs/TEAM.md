# The intel team

Each morning a set of model stages reviews the previous Eastern day of sensor
activity. The run leaves three things: a report mailed to the operator, an
updated knowledge base of campaigns and techniques in a private repository,
and an issue for each change it suggests to the sensor or the pipeline.

The dashboard shows what happened. The team is for the reading a person
would otherwise do by hand each day: which scripts ran, whether they have
been seen before, what the attacker was after, and what the sensor failed to
capture.

## The run

```
05:20  radar-team-sync      refresh the knowledge base clone       radar-team-pub
       radar-team           one day, database to outbox            radar-team
         bundle             the day's facts, read-only
         reader             describes the recorded activity        no tools
         research           looks up a few indicators              WebSearch only
         tracker            files the activity under campaigns     no tools
         editor             writes the report                      no tools
         writer             Sunday only: drafts a blog post        no tools
         charts, pages      PNG charts and Markdown pages
06:30  radar-team-publish   outbox to knowledge base, issues, mail radar-team-pub
```

`app/team/bundle.py` gathers the day from the per-day tables and from that
day's raw command events. It groups shell sessions into clusters by the shape
of what they typed: the command sequence with addresses, URLs and long
numbers removed, hashed. A shape is how the knowledge base recognises a
script on a later day, whatever address it comes from.

Two tables come straight from the day's raw events. Relay requests are listed
by source, one row for each destination a source asked the sensor to reach,
because the per-day totals show the destinations and hide who walked the
list. A destination is somebody's target, so it is never offered to the
research stage as an indicator. Logins made with a key an earlier session
installed (see `sensor/README.md`) are listed with their key, and those
sessions are expanded before any cluster's example.

Each count is compared with its median over the earlier days of the current
persona, 14 at most, and never across a persona change or a cutover. A
comparison with fewer than three days behind it is reported as having no
baseline.

A stage that fails costs its own contribution. Without the reader the report
carries the numbers and says the analysis is missing. Without the tracker, a
shape the knowledge base already files under a campaign is still counted for
that campaign. The mail goes out in every case, and when the worker left
nothing at all the publisher mails a notice saying so.

## The report

The report has the same parts in the same order every day. The order and the
parts come from how established threat intelligence teams publish, so a
reader who knows those reports can skim this one.

| Part | What it holds | Where the practice comes from |
|------|---------------|-------------------------------|
| Executive summary | One paragraph of 60 to 90 words that stands alone | Recorded Future's Insikt Group and CISA advisories open with one. GreyNoise's weekly brief opens with a lede of about 50 words |
| The day in numbers | Five counts, each against the median of earlier comparable days | GreyNoise's "By The Numbers", which pairs each figure with its change on the week |
| Key findings | Three to five facts, each with its number, why it matters, and a confidence | Insikt Group's "Key Findings", and Cisco Talos's "Why do I care?" under its main story |
| Campaigns | A table ranked by sessions, each row marked new, returning, up, down or steady | Red Canary's monthly top ten, which marks each threat's movement against the month before |
| Technique of the day | One piece of tradecraft taught from the record, with how to detect it | Red Canary pairs each threat with detection guidance. Talos follows its story with "So now what?" |
| ATT&CK techniques seen | Technique, name, and the campaigns that showed it | CISA advisories map observed activity to ATT&CK in tables |
| Indicators | Defanged, with what each is tied to, file hashes first and addresses last | CISA and Talos list indicators with each report. Ordering by how costly an indicator is to change follows Lenny Zeltser's report template |
| Recommended actions | Up to three changes with a priority, each filed as an issue | The mitigations section of a CISA advisory, and GreyNoise's recommended actions |
| Outlook | What is expected next, with a likelihood and what would confirm it | Insikt Group's "Outlook" |
| Collection notes | What was cut, what failed, and what the confidence words mean | The methodology and gaps section of an intelligence report |

Confidence and likelihood are kept apart, as the US intelligence community's
analytic standard has it and as Sophos and Mandiant apply it. Confidence is
high, moderate or low, and is stated for a judgment about what was recorded.
Likelihood appears only in the outlook, on what has not happened yet. The
report carries a TLP mark, AMBER unless `TR_TEAM_TLP` says otherwise.

The editor stage writes the headline, the executive summary, the key
findings, the technique, the actions and the outlook, under the rules in
`app/team/prompts/editor.md`. Code builds the numbers, the campaign ranking,
the technique table, the indicators and the charts from the day's record and
the tracker's checked answer, so those parts do not depend on how a model
chose to phrase anything.

## Trust boundaries

Everything typed into a session was written by an attacker, and the team's
job is to read it with a model. A session can therefore be written to steer
that model. The design assumes this will be tried and limits what a steered
stage could do.

**The reader has no tools.** It is the only stage shown recorded text. It
runs in an empty directory with every built-in tool removed, no MCP servers
and no slash commands. The recorded text sits inside a fence whose tag is
generated for that document, as in an export. The worst a steered reader can
do is write a misleading answer.

**A stage keeps only names the code already holds.** Each answer is checked
field by field in `app/team/stages.py`. A command shape, an indicator or a
campaign slug is kept only when it is in the day's index or the knowledge
base. A technique id must have the form of one. Free text is cut to a length
and stays text. An item that fails is dropped.

**The web stage sees no free text.** The researcher is the only stage with a
tool, WebSearch. It is handed indicators the reader named and the day
contains, with the collector's own lookup results, and none of the reader's
words. A steered reader has no way to pass a sentence to the stage that can
reach the internet, and the private description of the sensor is not given to
that stage either.

**The account that reads attacker text holds no credential but the model
token.** The worker runs as `radar-team`. It can read the database, the
samples and the knowledge base clone. It can write only its own state
directory.

**The account that holds credentials reads no attacker text.** The publisher
runs as `radar-team-pub` with the GitHub token and the mail password, loaded
by systemd from root-owned files that no other unit is given. It runs no
model. It accepts a file from the outbox only when the path is in the allowed
set in `app/team/outbox.py`, the file is a regular file inside the outbox,
its size and content match its type, and its hash matches the manifest. The
operator's own files (`feedback.md`, `context/`) are not in the allowed set,
so nothing a model wrote can replace the instructions the next run reads.

**Model text is never markup.** The publisher renders the mail from the
report's fields and escapes each one. Pages in the knowledge base pass through
`kb.md_text()`, which stops text from opening a heading, closing the front
matter, embedding an image or carrying HTML. URLs and IPv4 addresses are
defanged in both, because a mail client and a Markdown page turn a bare URL
into a link. Issue text has `@` replaced so it cannot notify anyone.

What remains: a steered stage can still write something false into a report
or a campaign page. The knowledge base is a git repository, so a bad day can
be read in the diff and reverted, and the report states the evidence each
claim rests on. Read the report as analysis to check, as you would a junior
analyst's.

## What leaves the collector

The team adds three recipients to the list in `DATA.md`:

- The model API receives the day's record: source addresses, credential
  pairs, commands, defanged sample text, and the private description of the
  sensor in `context/persona.md`. Strings listed in `TR_EXPORT_REDACT` are
  replaced first, as in an export.
- Web search receives the indicators the researcher looks up: file hashes,
  hosting addresses, network numbers, malware family names.
- GitHub and the mail provider receive the report and the knowledge base
  pages, which quote commands and list indicators.

The knowledge base repository must be private. It holds detail about the
persona that this public repository leaves out.

## The knowledge base

| Path | Holds | Written by |
|------|-------|------------|
| `INDEX.md` | The front page: campaigns by status, techniques, the activity chart | the team |
| `campaigns/<slug>.md` | One page per campaign: summary, timeline, indicators, techniques | the team |
| `techniques/<id>.md` | One page per ATT&CK technique seen, with each day it showed up | the team |
| `daily/<year>/<day>.md` | The day's report | the team |
| `charts/` | PNG charts for the reports and the campaign pages | the team |
| `drafts/<year>-W<week>.md` | The weekly blog draft | the team |
| `state/campaigns.json` | Which shape belongs to which campaign, and sessions per day | the team |
| `state/lessons.json` | Lessons already given, so they are not repeated | the team |
| `state/suggestions.json` | Suggestions already raised, with their issue numbers | the publisher |
| `feedback.md` | Standing corrections to the team | the operator |
| `context/persona.md` | What the sensor presents and what counts as interesting | the operator |
| `context/watch.txt` | Strings to call out when a command contains one, such as decoy paths | the operator |

A campaign is `active` on the day it is seen and the day after, `quiet` for
two weeks, then `dormant`. A `historical` campaign was recorded under an
earlier persona. The team never adds to one. Activity that resembles it
opens a current campaign that links back.

To steer the team, edit `feedback.md` in the repository. Every run reads it
before any stage writes. To stop a suggestion coming back, close its issue
and add a line to `feedback.md`. A suggestion already in
`state/suggestions.json` is not raised twice.

## Setup on the collector

These steps assume the collector is running as `SETUP.md` describes and has
this version deployed (`sudo /opt/threat-radar/deploy/update.sh --config`,
which also installs the team's units). They also assume the `claude` CLI is
installed at `/usr/local/bin/claude`, and that the private knowledge base
repository exists with at least one commit.

1. Create the two accounts. Neither has a shell or a home directory.

   ```bash
   sudo useradd --system --user-group --shell /usr/sbin/nologin --no-create-home radar-team
   sudo useradd --system --user-group --shell /usr/sbin/nologin --no-create-home radar-team-pub
   ```

2. Create the worker's Python environment and install its lock.

   ```bash
   sudo python3 -m venv /opt/threat-radar/venv-team
   sudo /opt/threat-radar/venv-team/bin/pip install --no-cache-dir --require-hashes \
     -r /opt/threat-radar/requirements-team.txt
   ```

3. Give the worker a model token. Run `claude setup-token` as your own user,
   then put the token it prints in a root-only file. `TR_EXPORT_REDACT` is
   optional and takes the same comma-separated strings as `web.env`.

   ```bash
   sudo install -m 600 -o root -g root /dev/null /etc/threat-radar/team.env
   sudoedit /etc/threat-radar/team.env
   ```

   ```
   CLAUDE_CODE_OAUTH_TOKEN=<the token>
   ```

4. Create a fine-grained GitHub token limited to the knowledge base
   repository, with read and write on Contents and Issues and nothing else.
   Store it and the mail account's app password where only root can read
   them. Each file holds the secret on one line with no spaces.

   ```bash
   sudo install -d -m 700 -o root -g root /etc/threat-radar/team-pub
   sudo install -m 600 -o root -g root /dev/null /etc/threat-radar/team-pub/github-token
   sudo install -m 600 -o root -g root /dev/null /etc/threat-radar/team-pub/smtp-password
   sudoedit /etc/threat-radar/team-pub/github-token
   sudoedit /etc/threat-radar/team-pub/smtp-password
   ```

5. Tell the publisher which repository and which addresses.

   ```bash
   sudo install -m 644 -o root -g root /dev/null /etc/threat-radar/team-pub.env
   sudoedit /etc/threat-radar/team-pub.env
   ```

   ```
   TR_TEAM_KB_REPO=<owner>/<knowledge base repository>
   TR_TEAM_MAIL_FROM=<the sending address>
   TR_TEAM_MAIL_TO=<where the report goes>
   ```

6. Clone the knowledge base.

   ```bash
   sudo systemctl start radar-team-sync; systemctl status radar-team-sync --no-pager -n 5
   ```

7. Run one day by hand. The log names each stage as it finishes. The worker
   reads the database through the `radar` group, which works while
   `radar-ingest` has the database open.

   ```bash
   sudo systemctl start radar-team; journalctl -u radar-team -n 20 --no-pager
   ```

8. Send that day. This pushes to the knowledge base, files any suggestions
   as issues, and mails the report.

   ```bash
   sudo systemctl start radar-team-publish; journalctl -u radar-team-publish -n 20 --no-pager
   ```

9. Enable the timers once the mail has arrived and reads correctly.

   ```bash
   sudo systemctl enable --now radar-team.timer radar-team-publish.timer
   ```

## Running it

| To | Run |
|----|-----|
| See what the reader would be shown for a day | `team_worker.py --day 2026-11-21 --show-document` |
| Check the model call the stages make | `team_worker.py --check`, which prints `ready` |
| Read a day's mail without sending it | `team_publish.py preview --day 2026-11-21 <directory>` |
| Rebuild a day's outbox | `team_worker.py --day 2026-11-21`, as `radar-team` |
| Rebuild it without the model | add `--no-model` |
| Send a day again | remove `/var/lib/radar-team-pub/sent/<day>.sent`, then `team_publish.py publish --day <day>` |
| Read each stage's checked answer | `/var/lib/radar-team/work/<day>/` |

A day is mailed once. The publisher records the send in a marker file, so a
unit that is retried after a failure does only the missing work. Stage
outputs and outboxes are kept for 14 days.

The worker exits non-zero when a stage failed, so `systemctl status
radar-team` shows it, and the report for that day lists the failure at its
foot.

## Settings

| Variable | File | Default | Meaning |
|----------|------|---------|---------|
| `CLAUDE_CODE_OAUTH_TOKEN` | `team.env` | none | The model token |
| `TR_CLAUDE_BIN` | `team.env` | `claude` | Path to the CLI |
| `TR_TEAM_MODEL` | `team.env` | `opus` | Model for the reader, tracker, editor and writer |
| `TR_TEAM_RESEARCH_MODEL` | `team.env` | `sonnet` | Model for the researcher |
| `TR_TEAM_STAGE_TIMEOUT` | `team.env` | `900` | Seconds one stage may take |
| `TR_EXPORT_REDACT` | `team.env` | empty | Strings withheld from the model |
| `TR_TEAM_TLP` | `team.env` | `AMBER` | The sharing mark shown on the report |
| `TR_TEAM_KB_REPO` | `team-pub.env` | none | `owner/name` of the knowledge base |
| `TR_TEAM_MAIL_FROM`, `TR_TEAM_MAIL_TO` | `team-pub.env` | none | Sender and recipient |
| `TR_TEAM_SMTP_HOST`, `TR_TEAM_SMTP_PORT`, `TR_TEAM_SMTP_USER` | `team-pub.env` | `smtp.gmail.com`, `587`, the sender | Mail server |
