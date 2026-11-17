# Incident trend sources

Checked on 2026-11-17. Four sources are in use. The status page API and a news
feed are listed with the reason each is left out.

| Source | URL | Format | Auth | Rate limit | Terms | Fields used |
|---|---|---|---|---|---|---|
| CISA KEV catalog | https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | JSON, one file holding the whole catalog | None | None published. Polled every 6 hours with If-None-Match, so an unchanged file costs one 304. | US government work, public domain. | cveID, vendorProject, product, dateAdded, knownRansomwareCampaignUse |
| CISA advisories | https://www.cisa.gov/cybersecurity-advisories/all.xml | RSS 2.0 | None | None published. Polled every 6 hours. | US government work, public domain. | title, link, pubDate, CVE IDs matched in the title |
| ransomware.live | https://api-pro.ransomware.live | JSON | Personal token from my.ransomware.live, stored as TR_RANSOMWARE_LIVE_TOKEN in /etc/threat-radar.env | 500,000 calls a month under fair use. The service caches for 30 minutes, so polling is hourly at most. | Free for non-commercial use with a linked "Source: Ransomware.live" credit on every page that uses it. Republishing the raw data, re-serving it as an API or feed, and commercial use all need the owner's written approval. The legacy api.ransomware.live/v2 is for personal use only and is not used. | Group, victim name, country, discovery date and post link for US victims. Field names to be confirmed against the API docs at build time. |
| DysruptionHub | https://dysruptionhub.com/feed/ | RSS 2.0 from Ghost, 15 most recent posts | None | None published. Polled every 2 hours with ETag. | No terms page found. robots.txt allows /feed/ and /incidents/ for all agents and disallows /incidents/feeds/, which the collector never requests. Posts carry paid content, so only metadata is stored. | title, link, pubDate, category |
| Vendor status pages | https://status.optimizely.com/api/v2/incidents.json | Statuspage v2 JSON | None | Not checked | Not used. Optimizely's robots.txt disallows this path for automated fetchers. Other vendors were not checked. | None |
| News feed | None chosen | | | | Not used. The Record has no RSS feed of its own; reader services build one by scraping the home page. The search limit was reached before another outlet's terms were confirmed. | None |

## Consequences for the pages

- ransomware.live rows are used for matching and counts. Pages show the group
  name and a link to the ransomware.live post, with the credit line, and do
  not list the raw victim records. The export does the same.
- DysruptionHub rows keep the headline, link, date and categories. The post
  body is never fetched or stored.
- Vendor fan-out events come from the seed rows and from DysruptionHub
  headlines until a status source is approved.
