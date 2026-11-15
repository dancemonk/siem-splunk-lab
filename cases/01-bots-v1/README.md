# Case 01: Website attack and ransomware (Splunk, BOTS v1)

| | |
|---|---|
| Data source | [Splunk Boss of the SOC v1](https://github.com/splunk/botsv1), attack-only version (CC0-1.0). Not copied here. |
| Data dates | 2016-08-10 03:28:51 to 2016-08-24 18:27:44 UTC | 
| Platform | Splunk Enterprise 10.6.1.1, Trial license, on the lab ThinkPad (Fedora 44). Splunk Web and the management port listen on 127.0.0.1 only. |
| Tools | Splunk, VirusTotal (hash lookup only), Fortinet docs |
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

**H1: a developer or admin changed the page.**
- Supports: the change comes from an internal IP, with no scanning or attack attempts before it.
- Rules out: the change comes from an external IP, or follows attack attempts such as a vulnerability scan.
- Where to look: `iis` (web server log), `stream:http` (every web request), `suricata` (IDS alerts).

**H2: an outsider got in, through stolen access (for example phishing) or a web application flaw.**
- Supports: attempts to get into the system from an external IP before the page changed, then a request that succeeds.
- Rules out: no attack attempts at all, and the change comes from an internal IP.
- Where to look: the same logs. Also check the server's answer to the attack requests: an error (404, 500) or success (200).

## 3. Exhibits

[TODO]

## 4. Timeline

| Time (UTC) | Host / IP | What happened | Exhibit |
|---|---|---|---|
| 21:36:45 | `40.80.148[.]42` to website | Acunetix web scan of the website (17,483 requests in total) | |
| 21:45:21 | `23.22.63[.]114` to website | Python script starts a brute force on the Joomla admin login (`username=admin`, 412 passwords) | [w04](exhibits/w04-python-login-page-hl.png), [w05](exhibits/w05-bruteforce-passwords-hl.png) |
| 21:46:33 | `23.22.63[.]114` to website | Script tries the password `batman` | [w07](exhibits/w07-batman-time-order-hl.png) |
| 21:48:05 | `40.80.148[.]42` to website | Browser (Internet Explorer 11) sends `batman`; the admin login works | [w07](exhibits/w07-batman-time-order-hl.png) |
| 21:50:31 | `40.80.148[.]42` to website | Web shell `agent.php` uploaded through the Joomla Extension Installer (most likely failed) | [w09b](exhibits/w09b-upload-agent-php-hl.png), [w09c](exhibits/w09c-upload-form-headers-2x.png) |
| 21:51:32 | `40.80.148[.]42` to website | Admin file manager eXtplorer opened | [w08b](exhibits/w08b-admin-session-extplorer-hl.png) |
| 21:52:45 | Firewall (FortiGate) | Firewall detects `W32/Swrort.C!tr` in `3791.exe`, but only monitors (`action=monitored`) | [w17](exhibits/w17-firewall-alert-and-upload-hl.png) |
| 21:52:47 | `40.80.148[.]42` to website | `3791.exe` and `agent.php` uploaded through eXtplorer ("Upload successful") | [w17](exhibits/w17-firewall-alert-and-upload-hl.png) |
| 21:55:22 | `23.22.63[.]114` to `agent.php` | Web shell used for the first time (test command `echo 24365`) | [w10](exhibits/w10-webshell-used-hl.png), [w12](exhibits/w12-webshell-commands-hl.png) |
| 21:56:18 | `we1149srv` (`192.168.250.70`) | Web shell runs `3791.exe` (trojanized `ab.exe`, VirusTotal 63/68) | [w14a](exhibits/w14a-3791-process-starts-hl.png), [w14b](exhibits/w14b-3791-sha256-hl.png), [w14c](exhibits/w14c-3791-virustotal-hl.png) |
| 21:56:19 | `192.168.250.70` to `23.22.63[.]114:3791` | Reverse shell to the attacker; the firewall allows it | [w15](exhibits/w15-reverse-shell-hl.png), [w23](exhibits/w23-firewall-reverse-shell-hl.png) |
| 22:05:42 | `23.22.63[.]114` to `agent.php` | New web shell session (test command `echo 63059`) | [w22b](exhibits/w22b-webshell-first-requests-hl.png) |
| 22:06:21 | `192.168.250.70` to `23.22.63[.]114:1337` | Web shell makes the server download `poisonivy-is-coming-for-you-batman.jpeg` | [w19](exhibits/w19-server-outbound-http-hl.png), [w20](exhibits/w20-downloaded-file-hl.png), [w21](exhibits/w21-download-process-hl.png), [w22a](exhibits/w22a-webshell-per-minute-hl.png) |
| 22:13:46 | `192.168.250.70` to `23.22.63[.]114:1337` | Second download of the same image | [w20](exhibits/w20-downloaded-file-hl.png), [w21](exhibits/w21-download-process-hl.png) |
| 22:19:11 | `192.168.250.70` to `23.22.63[.]114:1337` | Third `php-cgi.exe` connection; no HTTP download seen [OPEN] | [w21](exhibits/w21-download-process-hl.png) |
| 22:20:10 | `we1149srv` (`192.168.250.70`) | `move ..\1.jpeg 2.jpeg`: the image is moved into the website folder | [w12](exhibits/w12-webshell-commands-hl.png) |
| 22:20:33 | `we1149srv` (`192.168.250.70`) | `move 2.jpeg imnotbatman.jpg`: the website's image is replaced (defacement) | [w12](exhibits/w12-webshell-commands-hl.png) |
| 22:21:34 | `23.22.63[.]114` to `agent.php` | Last web shell commands (`exit`) | [w12](exhibits/w12-webshell-commands-hl.png) |
| 22:21:58 | `we1149srv` (`192.168.250.70`) | `3791.exe` ends | [w24](exhibits/w24-3791-ended-hl.png) |
| 22:22:03 | Firewall (FortiGate) | Firewall logs the reverse shell closed (open 1545 s, about 1.4 MB moved) | [w23](exhibits/w23-firewall-reverse-shell-hl.png) |

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
