# Case 01: Website attack and ransomware (Splunk, BOTS v1)

| | |
|---|---|
| Data source | [Splunk Boss of the SOC v1](https://github.com/splunk/botsv1), attack-only version (CC0-1.0). Not copied here. |
| Data dates | 2016-08-10 03:28:51 to 2016-08-24 18:27:44 UTC | 
| Platform | Splunk Enterprise 10.6.1.1, Trial license, on the lab ThinkPad (Fedora 44). Splunk Web and the management port listen on 127.0.0.1 only. |
| Tools | Splunk, VirusTotal (hash lookup only), Fortinet docs |
| ATT&CK | Web attack: T1595.002 Vulnerability Scanning, T1110.001 Password Guessing, T1078 Valid Accounts, T1505.003 Web Shell, T1027 Obfuscated Files or Information, T1059.003 Windows Command Shell, T1033 System Owner/User Discovery, T1087.001 Local Account Discovery, T1135 Network Share Discovery, T1049 System Network Connections Discovery, T1018 Remote System Discovery, T1057 Process Discovery, T1571 Non-Standard Port, T1105 Ingress Tool Transfer, T1491.002 External Defacement |
| Hours | About 8-10 |
| Status | Web attack: done. Ransomware part not started. |

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

All screenshots are in [`exhibits/`](exhibits/). File names start with the worklog entry they belong to (`w12-...` is entry 12), and every row in the timeline below links to its screenshots. Highlights mark the rows that matter.

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
| 21:58:28 | `we1149srv` (`192.168.250.70`) | In the reverse shell: `whoami`, `net user`, `net share`, `net session`, `net view /domain` (looking around, no new account) | [w28](exhibits/w28-accounts-attack-window-hl.png), [w29](exhibits/w29-reverse-shell-commands-hl.png) |
| 22:05:42 | `23.22.63[.]114` to `agent.php` | New web shell session (test command `echo 63059`) | [w22b](exhibits/w22b-webshell-first-requests-hl.png) |
| 22:06:21 | `192.168.250.70` to `23.22.63[.]114:1337` | Web shell makes the server request `poisonivy-is-coming-for-you-batman.jpeg`; the try fails (212 bytes back) | [w27](exhibits/w27-port-1337-firewall-hl.png), [w19](exhibits/w19-server-outbound-http-hl.png), [w20](exhibits/w20-downloaded-file-hl.png), [w21](exhibits/w21-download-process-hl.png), [w22a](exhibits/w22a-webshell-per-minute-hl.png) |
| 22:11:06 | `we1149srv` (`192.168.250.70`) | `ping` and `nslookup` for the attacker's own server, after the first download failed | [w29](exhibits/w29-reverse-shell-commands-hl.png) |
| 22:13:46 | `192.168.250.70` to `23.22.63[.]114:1337` | Second try, fails the same way | [w27](exhibits/w27-port-1337-firewall-hl.png), [w20](exhibits/w20-downloaded-file-hl.png), [w21](exhibits/w21-download-process-hl.png) |
| 22:19:11 | `192.168.250.70` to `23.22.63[.]114:1337` | Third try works: the server gets 569,600 bytes, the image | [w27](exhibits/w27-port-1337-firewall-hl.png), [w21](exhibits/w21-download-process-hl.png), [w32b](exhibits/w32b-third-download-stream-hl.png) |
| 22:20:10 | `we1149srv` (`192.168.250.70`) | `move ..\1.jpeg 2.jpeg`: the image is moved into the website folder | [w12](exhibits/w12-webshell-commands-hl.png) |
| 22:20:33 | `we1149srv` (`192.168.250.70`) | `move 2.jpeg imnotbatman.jpg`: the website's image is replaced (defacement) | [w12](exhibits/w12-webshell-commands-hl.png) |
| 22:21:19 | `40.80.148[.]42` to website | Attacker loads the defaced image `imnotbatman.jpg` (status 200) | [w30](exhibits/w30-imnotbatman-iis-hl.png) |
| 22:21:34 | `23.22.63[.]114` to `agent.php` | Last web shell commands (`exit`) | [w12](exhibits/w12-webshell-commands-hl.png) |
| 22:21:58 | `we1149srv` (`192.168.250.70`) | `3791.exe` exits normally (exit code `0x0`), no kill command found | [w24](exhibits/w24-3791-ended-hl.png), [w25](exhibits/w25-no-kill-process-hl.png), [w26](exhibits/w26-3791-exit-status-hl.png) |
| 22:22:03 | Firewall (FortiGate) | Firewall logs the reverse shell closed (open 1545 s, about 1.4 MB moved) | [w23](exhibits/w23-firewall-reverse-shell-hl.png), [w31](exhibits/w31-ip-conn-row-hl.png) |

## 5. Verdict

**True positive, H2: an outsider got in. Confidence: high.**

One attacker used two IPs and two tools. `23.22.63[.]114` brute-forced the Joomla admin login and found the password `batman` ([w06b](exhibits/w06b-password-reused-hl.png), [w07](exhibits/w07-batman-time-order-hl.png)). `40.80.148[.]42` logged in with it, opened eXtplorer and uploaded the web shell `agent.php` and the malware `3791.exe` ([w08b](exhibits/w08b-admin-session-extplorer-hl.png), [w17](exhibits/w17-firewall-alert-and-upload-hl.png)). Then `23.22.63[.]114` used the web shell to run commands on the web server, including the two `move` commands that replaced the website image ([w11](exhibits/w11-process-chain-hl.png), [w12](exhibits/w12-webshell-commands-hl.png)). This rules out H1: an external IP changed the page through a web shell, not an admin.

The proof comes from three separate log sources (web traffic, Sysmon and the firewall), and their times match within one or two seconds.

The attacker stayed at the rights of `IUSR`, the IIS account for anonymous visitors: no administrator rights and no new account ([w28](exhibits/w28-accounts-attack-window-hl.png), [w29](exhibits/w29-reverse-shell-commands-hl.png)). No open questions are left for the web attack.

## 6. Ticket

| Field | Value |
|---|---|
| Ticket | INC-01 (lab) |
| Title | Web server `we1149srv` compromised, website imreallynotbatman[.]com defaced |
| Severity | Critical |
| Status | Escalated to Tier 2 / incident response |
| Asset | `we1149srv` (`192.168.250.70`), Windows with IIS and Joomla |
| Attack window | 2016-08-10, 21:36:45 to 22:22:03 UTC |
| Attacker | `40.80.148[.]42` and `23.22.63[.]114` (also `prankglassinebracket.jumpingcrab[.]com`) |
| Malware | `agent.php` (PHP web shell), `3791.exe` (SHA256 `EC78C938D8453739CA2A370B9C275971EC46CAF6E479DE2B2D04E97CC47FA45D`) |
| Recommended actions | 1. Isolate `we1149srv` from the network. 2. Block both attacker IPs at the firewall. 3. Reset the Joomla admin password. 4. Save the evidence, then remove `agent.php` and `3791.exe`. |

## 7. Shift handover note

Ticket INC-01 is escalated to Tier 2 / IR as Critical. The web server `we1149srv` was taken over through the Joomla admin account: the password `batman` was found by brute force. The attacker uploaded a web shell and a Metasploit payload, had a reverse shell for about 26 minutes and replaced the website image. The last attacker activity I found was at 22:22:03 UTC.

First thing to do: change the firewall profile `Honeypot-Access` from monitor to block. It detected `W32/Swrort.C!tr` in `3791.exe` at 21:52:45 but let the file through (`action=monitored`), so the same upload would still work.

Also still to do: isolate the server, block `40.80.148[.]42` and `23.22.63[.]114`, reset the admin password, and remove `agent.php` and `3791.exe` after the evidence is saved.

The attacker stayed at `IUSR` rights and did not create an account (worklog 28 and 29). They ran discovery commands in the reverse shell (`whoami`, `net user`, `net share`). No open questions are left.

## 8. Detection

[D01: Web server starts a command shell](../../detections/d01-web-server-starts-shell.md). It looks for IIS (`w3wp.exe`) or PHP (`php-cgi.exe`) starting `cmd.exe` or `powershell.exe`. On BOTS v1 it finds all 17 web shell commands as one alert for `we1149srv`, and nothing before the attack.

## 9. Takeaway

An event with empty fields is invisible to a field search. In entry 20 I searched for the downloads by `src_ip` and `dest_ip` and found two. The third download, the one that worked, was in `stream:http` too, but without IPs or a URL, so my search missed it. A plain keyword search (`1337`) found it (entry 32). Before I write "it is not in the logs", I now also search for a plain keyword.

## 10. Hindsight

What the company should change:

- Switch the firewall profile `Honeypot-Access` from monitor to block. It detected `W32/Swrort.C!tr` in `3791.exe` and still let the file through.
- Protect the Joomla admin login with a strong, unique password and MFA, and lock the account after repeated failed logins. `batman` is in common password lists, and the script tried 412 passwords without being stopped.
- Add egress filtering. The web server should not open connections to the internet on ports like 3791 and 1337.
- Remove the `777` permissions from the website folders, so the IIS account cannot write files there.

What I would do differently: start with a plain keyword search, then narrow down with fields. Field searches are faster, but they miss events where the fields are empty (entries 20 and 32).

---
Indicators are defanged: `hxxp://`, `1.2.3[.]4`.
