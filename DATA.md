# Data handling

This page describes what the project collects, how long each kind of data is
kept, what leaves the system and where it goes, and what the dashboard shows.

## What is collected

The sensor records what an SSH client does when it connects to the honeypot:

- the source address and port, the client version string, and the key
  exchange offer, from which a HASSH fingerprint is derived
- every username and password tried, and whether the sensor accepted it
- every command typed into the emulated shell
- files downloaded onto the decoy or pushed to it, which are captured and
  kept by their sha256
- port-forwarding requests, including the destinations asked for and a
  fingerprint of any HTTP sent through them. These are recorded but never
  carried out: the sensor does not proxy traffic for anyone.

The credentials that appear on the site are ones attackers tried against the
honeypot. They are not the credentials of any real account, and a successful
login means the sensor chose to accept it, not that anything was breached.

## Whose data this is

Most source addresses belong to rented servers, proxies, or machines that
have themselves been compromised. An address in this data identifies
infrastructure that sent the traffic, which may belong to someone who is
unaware of it, and it is not evidence of who operated it. The same caution
applies to the geolocation and network ownership attached to each address.

Addresses the operator uses for testing are excluded from analysis. They are
configured outside this repository, and the events themselves are kept but
never counted.

## Retention

| Data | Where | Kept for |
|------|-------|----------|
| Raw Cowrie logs | sensor | 7 days |
| Log copies awaiting ingestion | collector spool | 8 days |
| Raw events, one row per log line | collector database | 30 days |
| Per-day rollups and lifetime tables | collector database | indefinitely |
| Captured samples | sensor and collector | indefinitely |
| Reputation lookups | collector database | refreshed on a TTL, kept |

The rollups keep counts, first and last seen dates, and the addresses that
contributed to them, so addresses remain in the long-term record after the
raw events describing them are gone. Captured samples are malware at rest on
both hosts. They are readable only by the accounts that collect them, and no
part of the system serves them.

## What leaves the system

- Sample hashes are looked up on VirusTotal and URLhaus, and download URLs
  and hosts on URLhaus.
- A sample VirusTotal has never seen is uploaded to VirusTotal, where it is
  available to its community.
- A sample captured in the last ten days that at least one engine flags is
  uploaded to MalwareBazaar under a named account, where it is public.

Nothing else is sent anywhere. The sensor's own address, the operator's
addresses, and the persona are never submitted.

## What the dashboard shows

The dashboard is served on a private network behind authentication. It shows
aggregates, source addresses and their networks, credential pairs, commands,
session narratives, and sample analysis: text samples defanged and binaries
described by metadata and strings. It offers no download of any sample.

## The sensor's behaviour toward others

The honeypot is passive. It answers connections made to it and does nothing
in response: no scanning back, no interference with the sources. Its outbound
traffic is limited to name resolution, time, and web requests, which is how it
fetches the files attackers ask it to download, and it cannot reach private,
link-local or tailnet addresses, so it cannot be turned against a network
behind it.
