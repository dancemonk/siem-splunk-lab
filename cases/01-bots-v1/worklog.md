# Case 01 worklog

Working notes during the investigation. Newest at the bottom. My mentor suggested searches 1-3, 6, 7, 9, 13, 14 and 16-27 while I was learning SPL; I wrote the others.

## 2026-11-10

**1. Which logs mention the website?**
- Search: 
    - `index=botsv1 earliest=0 imreallynotbatman.com | stats count by sourcetype | sort - count`
- Result: `suricata` (about 30,000 events), `iis`, `fgt_utm`, `stream:http`.
- Meaning: many events mention the website, all from network and web server logs.

**2. Who sent the most requests to the website?**
- Search: 
    - `index=botsv1 earliest=0 sourcetype=stream:http imreallynotbatman.com | stats count by src_ip | sort - count`
- Result: `40.80.148[.]42` 17,483 requests (first at 21:36:45), `23.22.63[.]114` 1,235 requests.
- Meaning: a scanner makes many more requests than other sources, so `40.80.148[.]42` stands out.

**3. What user agent does each IP send?**
- Search: 
    - `index=botsv1 earliest=0 sourcetype=stream:http imreallynotbatman.com | stats count by src_ip, http_user_agent | sort - count`
- Result: `40.80.148[.]42` says it is Chrome in most requests, but many requests carry attack test strings (SQL injection, XSS, command injection) with the marker `acunetix_wvs_security_test`: the Acunetix scanner. `23.22.63[.]114` sends `Python-urllib/2.7`: a Python script.
- Meaning: a user agent can be faked. This shows a scan, but it does not prove the site was hacked: I still need to see how the server answered.
- Thought: the scan could be an authorized pentest. To check: is there an approved test? A pentest would not explain the defacement.

## 2026-11-11

**4. What did the Python script (`23.22.63[.]114`) request?**
- Search: 
    - `index=botsv1 earliest=0 sourcetype=stream:http imreallynotbatman.com src_ip=23.22.63[.]114 | stats count by http_method, uri_path | sort - count`
- Result: all 1,235 requests went to one page, `/joomla/administrator/index.php` (the Joomla admin login page): 823 GET, 412 POST.
- Meaning: this is a **brute force** attack on the admin login. A script from an external IP submitted the login form 412 times. It fits H2 and rules out H1. Not proven yet: whether any password worked.

**5. What did the script send in its 412 POSTs?**
- Search: 
    - `index=botsv1 earliest=0 sourcetype=stream:http imreallynotbatman.com src_ip=23.22.63[.]114 http_method=POST | table _time form_data | sort _time`
- Result: every attempt uses `username=admin`. The passwords come from a list of common passwords (`12345678`, `letmein`, `qwerty`...), about 14 per second, starting 2016-08-10 21:45:21 UTC.
- Meaning: brute force with a wordlist against the `admin` account.

**6. Was any password used more than once?**
- Search: 
    - `index=botsv1 earliest=0 sourcetype=stream:http imreallynotbatman.com http_method=POST | rex field=form_data "passwd=(?<password>[^&]+)" | stats count, values(src_ip) AS ips by password | where count > 1`
- Result: the script tried 412 different passwords, each once. Across all 14,238 POSTs, only `batman` was sent twice: by `23.22.63[.]114` and by `40.80.148[.]42`.
- Meaning: the two IPs are very likely the same attacker, using different tools.

**7. Who sent `batman` first?**
- Search: 
    - `index=botsv1 earliest=0 sourcetype=stream:http imreallynotbatman.com http_method=POST | rex field=form_data "passwd=(?<password>[^&]+)" | where password="batman" | table _time, src_ip, http_user_agent, status | sort _time`
- Result: 21:46:33 `23.22.63[.]114` (`Python-urllib/2.7`), then 21:48:05 `40.80.148[.]42` (Internet Explorer 11), 1 min 32 s later. Status 303 for both.
- Meaning: the script found the password, then the attacker used it from a browser. Status 303 alone does not show success.

**8. What did the browser do after the login?**
- Search: 
    - `index=botsv1 earliest=0 sourcetype=stream:http imreallynotbatman.com src_ip=40.80.148[.]42 http_user_agent="*Trident*" | table _time http_method uri_path status | sort _time`
- Result: admin pages load after the login. From 21:51:32 the admin file manager eXtplorer (`com_extplorer`) opens and lists files. 21:52:49: an `.exe` file icon. POSTs inside the admin area at 22:16-22:21.
- Meaning: the same IP that tried to get into the admin site got in with `batman`. Only a logged-in admin can open the file manager.

**9. Did the attacker upload a file?**
- Search: 
    - `index=botsv1 earliest=0 sourcetype=stream:http src_ip=40.80.148[.]42 http_method=POST part_filename=* | table _time, uri_path, part_filename | sort _time`
- Result: one upload, `agent.php`, at 21:50:31.
- Meaning: `agent.php` is an obfuscated PHP web shell (T1505.003, obfuscation T1027), uploaded through Joomla's Extension Installer (`com_installer`) with install folder `C:\inetpub\wwwroot\joomla\tmp`. The web server runs Windows / IIS. The code is not copied here (malware).

**10. Did the attacker use the web shell?**
- Search:
    - `index=botsv1 earliest=0 sourcetype=stream:http agent.php | stats count by src_ip, http_method, uri_path _time | sort _time`
- Result: from 21:55:22, `23.22.63[.]114` sends many GET requests to `/joomla/agent.php`, a few per second. In one request (22:21:34): a strange `Accept-Language` (`it-CH,pa;q=0.5,ps;q=0.7,pa;q=0.8`), a fake Google `Referer`, and a fake Safari user agent. The reply is `<34819d7b>...</34819d7b>`: the same key as in the `agent.php` code (`$kh` + `$kf`).
- Meaning: the web shell was used about 5 minutes after the upload, by the brute force IP. The commands hide in the `Referer` and `Accept-Language` headers, and the reply is encoded. The website's public IP is `71.39.18[.]126`; the web server's internal IP is `192.168.250.70`.
- Next: what the commands did on `192.168.250.70` (Sysmon).

## 2026-11-12

**11. Which programs did the web server start? (Sysmon)**
- Search:
    - `index=botsv1 earliest=0 sourcetype=XmlWinEventLog EventCode=1 (ParentImage="*w3wp.exe" OR ParentImage="*php-cgi.exe") | stats count by host, ParentImage, Image`
- Result: on host `we1149srv` (the web server, `192.168.250.70`): `w3wp.exe` (IIS) started `php-cgi.exe` 33 times, and `php-cgi.exe` started `cmd.exe` 17 times.
- Meaning: IIS starting PHP is normal. PHP starting a command prompt is not: this is the web shell running commands on the server.

**12. Which commands did the web shell run?**
- Search:
    - `index=botsv1 earliest=0 sourcetype=XmlWinEventLog EventCode=1 Image="*cmd.exe" ParentImage="*php-cgi.exe" | table _time CommandLine | sort _time`
- Result: 17 commands from 21:55:22 to 22:21:34. First `echo 24365` (a test), then `dir`, `ls`, `ifconfig`; 21:56:18 `3791.exe`; more `dir`; 22:20:10 `move ..\1.jpeg 2.jpeg`; 22:20:33 `move 2.jpeg imnotbatman.jpg`; then `exit`. (`2&gt;&amp;1` is `2>&1` in HTML escaping: show errors too.)
- Meaning: the first command runs in the same second as the first `agent.php` request, so the network and host logs match. `ls` and `ifconfig` are Linux commands that fail on Windows: the attacker or the tool did not check the operating system first. The two `move` commands most likely made the defacement: an image file gets the name the website uses (`imnotbatman.jpg`), so the page shows the picture of the attacker.
- Open: where `1.jpeg` came from; whether visitors really got the new image after 22:20:33.

## 2026-11-14

**13. What does Sysmon record about `3791.exe`?**
- Search:
    - `index=botsv1 earliest=0 sourcetype=XmlWinEventLog 3791.exe | stats count by EventCode | sort - count`
- Result: EventCode 1 (process created) 5, 3 (network connection) 1, 5 (process ended) 1, 7 (DLL loaded) 62. No EventCode 11 (file created).
- Meaning: most events are normal DLL loads. Sysmon did not record how the file got onto the disk.

**14. Who started `3791.exe`, and what is its hash?**
- Search:
    - `index=botsv1 earliest=0 sourcetype=XmlWinEventLog 3791.exe EventCode=1 | search Image="*3791.exe" | rex field=Hashes "SHA256=(?<sha256>[^,]+)" | table _time, Image, sha256`
- Result: 21:56:18, `php-cgi.exe` started `cmd.exe /c "3791.exe 2>&1"`, which started `C:\inetpub\wwwroot\joomla\3791.exe` (in the website folder). SHA256 `EC78C938D8453739CA2A370B9C275971EC46CAF6E479DE2B2D04E97CC47FA45D`. `3791.exe` then started `cmd.exe` at 21:58:23 and 22:08:13.
- VirusTotal (hash search only, checked 2026-11-14): 63 of 68 vendors say malicious. First known as `ab.exe`, a trojanized ApacheBench (the default template of Metasploit msfvenom). Family label `swrort`; categories trojan, hacktool.
- Meaning: known malware, very likely a Metasploit payload that gives the attacker a command shell. Note: in EventCode 7 rows the hash belongs to the loaded DLL, not to `3791.exe`.

**15. Where did `3791.exe` connect?**
- Search:
    - `index=botsv1 earliest=0 sourcetype=XmlWinEventLog 3791.exe EventCode=3 | table _time SourceIp DestinationIp DestinationPort Image`
- Result: 21:56:19, `192.168.250.70` to `23.22.63[.]114`, port 3791, one second after the start.
- Meaning: a reverse shell. The web server connected OUT to the attacker: the same IP as the brute force and the web shell. The port is the same as the file name.
- Open: where `3791.exe` came from; does the firewall log (`fgt_traffic`) show this connection?

## 2026-11-15

**16. Which logs mention `3791.exe`?**
- Search:
    - `index=botsv1 earliest=0 3791.exe | stats count by sourcetype | sort - count`
- Result: `XmlWinEventLog` 69, `WinEventLog:Security` 3, `stream:http` 2, `fgt_utm` 1, `suricata` 1.
- Meaning: the file travelled over the network. The web traffic, the firewall and the IDS all saw it.

**17. How did `3791.exe` get onto the server?**
- Search:
    - `index=botsv1 earliest=0 3791.exe sourcetype IN ("stream:http", "fgt_utm", "suricata") | sort _time`
- Result:
    - 21:52:45 `fgt_utm`: "File is infected.", virus `W32/Swrort.C!tr`, file `3791.exe`, from `40.80.148[.]42` to the web server. Its checksum is the same SHA256 as in entry 14. `action=monitored`, level critical, profile `Honeypot-Access`.
    - 21:52:47 `stream:http`: one eXtplorer upload (POST) with two files, `3791.exe` and `agent.php`. Server answer: "Upload successful!".
    - 21:52:47 `suricata`: a `fileinfo` event for `3791.exe` (logged, no alert).
    - 21:52:47 `stream:http`: eXtplorer lists `/joomla`: `3791.exe` (72.07 KB) and `agent.php` (1.47 KB) are there. Every folder has permissions `777` (anyone can write).
- Meaning: `40.80.148[.]42` uploaded both files with eXtplorer at 21:52:47. The firewall recognised the malware but only logged it (monitor mode), so the file got through. An analyst had about 3.5 minutes to act on that critical alert before the reverse shell (21:56:18). The first `agent.php` upload through the Joomla installer (21:50:31) most likely failed (no success message); the working copy came through eXtplorer. Permissions `777` made the upload easy.
- Note: the same second shows as 21:52:47 UTC in Splunk, 15:52:47 in the firewall and IDS (UTC-6) and 14:52 in the file list (web server, UTC-7). The timeline uses UTC.

**18. Which logs mention `1.jpeg`?**
- Search:
    - `index=botsv1 earliest=0 "1.jpeg" | stats count by sourcetype`
- Result: `XmlWinEventLog` 2, `WinEventLog:Security` 1. No network log.
- Meaning: only Windows knows the name `1.jpeg`. The file probably had a different name on the network and got the new name when it was saved.

**19. Did the web server download anything?**
- Search:
    - `index=botsv1 earliest=0 sourcetype=stream:http src_ip=192.168.250.70 | stats count by dest_ip, http_method, site | sort - count`
- Result: two destinations. `update.joomla.org` (`108.161.187[.]134`) 5 GET; `23.22.63[.]114` (`prankglassinebracket.jumpingcrab[.]com:1337`) 2 GET.
- Meaning: Joomla checking for updates is normal. A GET to the attacker IP on port 1337 is not. Here the server is the client: the file was pulled (downloaded by the server), not pushed (uploaded). 1337 means "leet" in hacker slang and is not a normal web port.

**20. What did the server download?**
- Search:
    - `index=botsv1 earliest=0 sourcetype=stream:http src_ip=192.168.250.70 dest_ip=23.22.63[.]114 | table _time, http_method, site, uri_path, status, http_user_agent | sort _time`
- Result: 22:06:21 and 22:13:46, GET `/poisonivy-is-coming-for-you-batman.jpeg`. Status and user agent are empty.
- Meaning: both downloads are before `move ..\1.jpeg 2.jpeg` (22:20:10), so the order fits: downloaded, most likely saved as `1.jpeg`, then renamed. The empty user agent means the program did not introduce itself, so it was not a browser. An empty user agent in traffic going out from a server is a detection idea.
- Update (entry 27): these two tries failed. The server got only 212 bytes back each time. The image came with a third connection at 22:19:11.

**21. Which program made the download?**
- Search:
    - `index=botsv1 earliest=0 sourcetype=XmlWinEventLog EventCode=3 DestinationPort=1337 | table _time, Image, SourceIp, DestinationIp, DestinationPort | sort _time`
- Result: `php-cgi.exe` connected from `192.168.250.70` to `23.22.63[.]114:1337` three times: 22:06:22, 22:13:48, 22:19:11.
- Meaning: PHP itself made the download, not `cmd.exe`. That is why there is no download command among the 17 `cmd.exe` commands (entry 12): the web shell ran it as PHP code. A search for `cmd.exe` alone would miss this download.
- Open: Sysmon shows 3 connections, `stream:http` only 2 downloads. Maybe the third was not HTTP, or it failed or was not captured. Answered in entry 27.

**22. Was the web shell used at the download times?**
- Search:
    - `index=botsv1 earliest="08/10/2016:22:05:00" latest="08/10/2016:22:20:00" sourcetype=stream:http uri_path="/joomla/agent.php" | bin _time span=1m | stats count by _time`
- Result: 96 requests from `23.22.63[.]114`. Per minute: 22:05 10, 22:06 14, 22:08 1, 22:13 14, 22:15 7, 22:16 7, 22:19 43.
- Meaning: the bursts at 22:06, 22:13 and 22:19 are in the same minute as the three `php-cgi.exe` connections. `23.22.63[.]114` used the web shell to make the server pull the image from its own server on port 1337. The 22:05 burst starts with `echo 63059` at 22:05:42, like `echo 24365` at 21:55:22: a test that tells the attacker the web shell still works, so each new session starts with one.
- SPL lesson: `head` before `sort` cut 10 events and hid the 22:05 burst. Sort first, or count per minute with `bin`.

**23. Did the firewall allow the reverse shell?**
- Search:
    - `index=botsv1 earliest=0 sourcetype=fgt_traffic 23.22.63[.]114 dstport=3791 | table _time, srcip, dstip, dstport, action, sentbyte, rcvdbyte, duration | sort _time`
- Result: two rows at 22:22:03, both `192.168.250.70` to `23.22.63[.]114`, port 3791.
    - Row 1: `action=close`, `sentbyte` 112,524, `rcvdbyte` 1,336,289 (about 1.3 MB), `duration` 1545 seconds.
    - Row 2: `action=ip-conn`, no bytes.
- Meaning: a blocked connection cannot move 1.4 MB, so the firewall allowed the reverse shell and the attacker had a working shell. FortiGate writes a traffic log when a connection ends: 22:22:03 minus 1545 seconds (25 min 45 s) is 21:56:18, one second from the Sysmon connection in entry 15 (21:56:19). So it is the same connection, and it stayed open for almost 26 minutes while the attacker worked on the server. There was no egress filtering: the web server could open a connection to the internet on an unusual port.
- `ip-conn` (I looked this up in Fortinet's docs): traffic allowed, but the session closed because the FortiGate got no reply packet. Row 2 is probably a second connection attempt that got no answer, maybe because the attacker's listener was already gone. [OPEN]
- Source: [Fortinet: ip-conn traffic action in logs](https://community.fortinet.com/fortigate-3/technical-tip-ip-conn-traffic-action-in-logs-99859)
- Field names: FortiGate calls the source IP `srcip`, Sysmon calls it `SourceIp` and `stream:http` calls it `src_ip`. I check the names before I search one sourcetype.

**24. Why did the reverse shell end?**
- Search:
    - `index=botsv1 earliest=0 sourcetype=XmlWinEventLog 3791.exe EventCode=5 | table _time, Image`
- Result: 22:21:58, `C:\inetpub\wwwroot\joomla\3791.exe` ended (Sysmon EventCode 5, process ended).
- Meaning: the program ended at 22:21:58 and the firewall logged the connection close at 22:22:03, 5 seconds later, so the reverse shell ended because `3791.exe` stopped. This was about 30 seconds after the last web shell commands (`exit`, 22:21:31 and 22:21:34) and 1.5 minutes after the defacement (22:20:33). It looks like the attacker finished and closed everything. The `exit` commands went through the web shell (`php-cgi` to `cmd.exe`), not through the reverse shell, so they did not close it directly.
- Open: what stopped `3791.exe` (the attacker from their side, or something on the server). Answered in entries 25 and 26.

**25. Did anything on the server kill `3791.exe`?**
- Search:
    - `index=botsv1 earliest="08/10/2016:21:56:00" latest="08/10/2016:22:23:00" sourcetype=XmlWinEventLog EventCode=1 host=we1149srv | table _time, ParentImage, Image, CommandLine | search CommandLine="*kill*" OR ParentImage="*3791.exe*" | sort _time`
- Result: 2 events, the two `cmd.exe` started by `3791.exe` at 21:58:23 and 22:08:13 (`C:\Windows\SysWOW64\cmd.exe`). No process with "kill" in its command line.
- Meaning: no program was started on the server to stop `3791.exe`. SysWOW64 holds the 32-bit Windows programs, so `3791.exe` is a 32-bit program.

**26. How did `3791.exe` end?**
- Search:
    - `index=botsv1 earliest=0 sourcetype=WinEventLog:Security 3791.exe | table _time, EventCode, Exit_Status, Process_Name, Account_Name | sort _time`
- Result: 21:56:18, two events 4688 (process created), accounts `IUSR` and `joomla`. 22:21:58, event 4689 (process exited) for `C:\inetpub\wwwroot\joomla\3791.exe`, `Exit_Status` `0x0`, account `IUSR`.
- Meaning: `3791.exe` exited normally (`0x0`), in the same second Sysmon logged in entry 24. With entry 25 (no kill command), the most likely reason is that the attacker closed the reverse shell from their side. It ran as `IUSR`, the IIS account for anonymous visitors, which is not an administrator.
- Open: I did not check whether the attacker got more rights than `IUSR`. [OPEN]

**27. What did the three connections to port 1337 carry?**
- Search:
    - `index=botsv1 earliest=0 sourcetype=fgt_traffic dstip=23.22.63[.]114 dstport=1337 | table _time, srcip, dstport, action, sentbyte, rcvdbyte, duration | sort _time`
- Result: three rows from `192.168.250.70`, all `action=close`. The firewall logs a connection when it ends, so start = `_time` minus `duration`.
    - 22:10:21, sent 318 bytes, received 212, 240 seconds: started 22:06:21.
    - 22:17:46, sent 318, received 212, 240 seconds: started 22:13:46.
    - 22:19:12, sent 8,038, received 569,600, 2 seconds: started 22:19:10.
- Meaning: the start times match the three `php-cgi.exe` connections in entry 21 within one or two seconds. The first two tries got only 212 bytes and waited 240 seconds before closing, so they failed. That fits the empty status in entry 20. The third try got 569,600 bytes (about 556 KB) in 2 seconds: this is the image. The `move ..\1.jpeg 2.jpeg` at 22:20:10 came about one minute later. It also explains the burst of 43 web shell requests at 22:19 (entry 22). `stream:http` did not record this third download, and I do not know why.
