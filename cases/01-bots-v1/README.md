# Case 01: Website attack and ransomware (Splunk, BOTS v1)

| | |
|---|---|
| Data source | [Splunk Boss of the SOC v1](https://github.com/splunk/botsv1), attack-only version (CC0-1.0). Not copied here. |
| Data dates | 2016-08-10 03:28:51 to 2016-08-24 18:27:44 UTC | 
| Platform | Splunk Enterprise 10.6.1.1, Trial license, on the lab ThinkPad (Fedora 44). Splunk Web and the management port listen on 127.0.0.1 only. |
| Tools | Splunk ([TODO] OSINT sites used) |
| ATT&CK | [TODO] |
| Hours | [TODO] |
| Status | [TODO] |

## 0. Data check (2026-11-10)

Done before the investigation, so that "0 results" can be trusted.

- 955,807 events in 22 sourcetypes (inventory with `tstats`). Exhibit: [`exhibits/data-check/dc1-tstats-inventory-2x.png`](exhibits/data-check/dc1-tstats-inventory-2x.png)
- Attack-only dataset: most normal traffic is missing, so the attack is easier to see than in a real SOC.
- Add-ons: only the Sysmon add-on (`Splunk_TA_microsoft_sysmon`). The other add-ons in the BOTS v1 README are not installed. The fields below work without them.
- The BOTS v1 data is from 2016. The time picker must be "All time" (or `earliest=0`).
- The Sysmon add-on renames the sourcetype at search time: `tstats` shows the original name, normal search shows `XmlWinEventLog`.

| Log | Search with | Key fields (checked) |
|---|---|---|
| Sysmon | `sourcetype=XmlWinEventLog` | `EventCode`, `Image`, `CommandLine`, `ParentImage` |
| Windows Security | `sourcetype=WinEventLog:Security` | `EventCode` |
| Web traffic (Splunk Stream) | `sourcetype=stream:http` | `src_ip`, `dest_ip` |
| Web server | `sourcetype=iis` | `c_ip`, `s_ip` |
| IDS | `sourcetype=suricata` | `src_ip`, `dest_ip` |
| Firewall UTM | `sourcetype=fgt_utm` | `srcip`, `dstip` |

## 1. Alert

The website shows a defacement page: imreallynotbatman[.]com

## 2. Hypotheses

**H1 - A developer or admin changed the page.**
- **Supports:** the change comes from an internal IP, with no scanning or attack attempts before it.
- **Rules out:** the change comes from an external IP, or follows attack attempts such as a vulnerability scan.
- **Where to look:** `iis` (web server log), `stream:http` (every web request), `suricata` (IDS alerts).

**H2 - An outsider got in, through stolen access (for example phishing) or a web application flaw.**
- **Supports:** attempts to get into the system from an external IP before the page changed, then a request that succeeds.
- **Rules out:** no attack attempts at all, and the change comes from an internal IP.
- **Where to look:** the same logs. Also check the server's answer to the attack requests: an error (404, 500) or success (200).

## 3. Exhibits

[TODO]

## 4. Timeline

| Time (UTC) | Host / IP | What happened | Exhibit |
|---|---|---|---|
| [TODO] | | | |

## 5. Verdict

[TODO]

## 6. Ticket

[TODO]

## 7. Shift handover note

[TODO]

## 8. Detection

[TODO]

## 9. Takeaway

[TODO]

## 10. Hindsight

[TODO]

---
Indicators are defanged: `hxxp://`, `1.2.3[.]4`.
