# siem-splunk-lab

![ci](https://github.com/dancemonk/siem-splunk-lab/actions/workflows/ci.yml/badge.svg)
![cases](https://img.shields.io/badge/cases-0%20of%203-lightgrey)

SOC investigations in Splunk on the Boss of the SOC (BOTS) v1, v2 and v3 datasets,
with the SPL detections that came out of them.
Built by Vlad Guliakin, from November 2026.

Each case starts with an alert and ends with a verdict, a ticket, a shift handover
note and one detection rule. Splunk runs on my lab laptop; the datasets are linked,
not copied.

## Progress

| Weekend | Dates | Focus | Status |
|---|---|---|---|
| 1 | 2026-11-10 | Lab check: Splunk 10.6, BOTS v1 data and fields | Done |
| 2 | 2026-11-21 to 11-22 | SPL for investigation (`stats`, `eval`, `rex`), BOTS v1 web attack | Not started |
| 3 | 2026-11-28 to 11-29 | Case 01 finished (BOTS v1), first detections | Not started |
| 4 | 2026-12-05 to 12-06 | BOTS v2, data models and `tstats` (Case 02) | Not started |
| 5 | 2026-12-12 to 12-13 | BOTS v3, cloud logs (Case 03) | Not started |
| 6 | 2026-12-19 to 12-20 | Detection pack, scheduled alerts, release | Not started |

Every resource used is listed in [TRACKER.md](TRACKER.md).

## Layout

| Folder | What is in it |
|---|---|
| [`cases/`](cases/) | Investigations, one folder per case |
| [`detections/`](detections/) | SPL rules from the cases, with tests |
| [`notes/`](notes/) | Lab and course notes, in my own words |

## Rules this repo follows

- No datasets, malware, keys, passwords or public IPs of my own. Data sources are linked, not copied.
- Every indicator is defanged: `hxxp://`, `1.2.3[.]4`
- Unfinished parts are marked `[TODO]`. No invented results or screenshots.

## Assistance

I use Claude (Anthropic) as a mentor and reviewer. It helped set up the repo structure, CI and templates, and it reviews my notes. The investigations, verdicts and SPL are my own work.

## License

[MIT](LICENSE)
