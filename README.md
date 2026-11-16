# siem-splunk-lab

![ci](https://github.com/dancemonk/siem-splunk-lab/actions/workflows/ci.yml/badge.svg)
![cases](https://img.shields.io/badge/cases-1%20of%203-blue)

SOC investigations in Splunk on the Boss of the SOC (BOTS) v1, v2 and v3 datasets,
with the SPL detections that came out of them.
Built by Vlad Guliakin, from November 2026.

Each case starts with an alert and ends with a verdict, a ticket, a shift handover
note and one detection rule. Splunk runs on my lab laptop; the datasets are linked,
not copied.

## Featured: Case 01, website defacement (BOTS v1)

A Joomla website on an IIS server was defaced. I traced the attack across web traffic, Sysmon,
Windows Security and firewall logs: a vulnerability scan, a brute force of the admin login,
a web shell upload, a Metasploit reverse shell that the firewall allowed, and the image swap
that defaced the site. The case has a 23-row timeline with a screenshot for every step, a
verdict, a ticket and a shift handover note.

- Case report: [`cases/01-bots-v1/`](cases/01-bots-v1/)
- Investigation notes, 32 searches: [`worklog.md`](cases/01-bots-v1/worklog.md)
- Detection from the case: [D01, web server starts a command shell](detections/d01-web-server-starts-shell.md)

## Progress

| Weekend | Dates | Focus | Status |
|---|---|---|---|
| 1 | 2026-11-10 | Lab check: Splunk 10.6, BOTS v1 data and fields | Done |
| 2 | 2026-11-11 to 11-15 | SPL for investigation (`stats`, `rex`, `bin`), BOTS v1 web attack | Done (investigation) |
| 3 | 2026-11-28 to 11-29 | Case 01 finished (BOTS v1), first detections | Started early: web attack report and D01 done |
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

I use Claude (an AI by Anthropic) as a mentor. It set up the repo structure, CI and templates, suggested some of the searches, and helped me write up parts of the worklog and timeline from my findings. I ran every search in my own Splunk lab.

## License

[MIT](LICENSE)
