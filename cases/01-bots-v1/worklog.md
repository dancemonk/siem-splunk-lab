# Case 01 worklog

Working notes during the investigation. Newest at the bottom. Searches 1-3, 6, 7, 9, 13 and 14 were given step by step while I learned SPL; the others I wrote myself.

## 2026-11-10

**1. Which logs mention the website?**
- Search: 
    - `index=botsv1 earliest=0 imreallynotbatman.com | stats count by sourcetype | sort - count`
- Result: `suricata` (about 30,000 events), `iis`, `fgt_utm`, `stream:http`.
- Meaning: many events mention the website, all from network and web server logs.

**2. Who sent the most requests to the website?**
- Search: 
    - `index=botsv1 earliest=0 sourcetype=stream:http imreallynotbatman.com | stats count by src_ip | sort - count`
- Result: `40.80.148[.]42` 17,483 requests, `23.22.63[.]114` 1,235 requests.
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

**13. What does Sysmon record about `3791.exe`?** (given)
- Search:
    - `index=botsv1 earliest=0 sourcetype=XmlWinEventLog 3791.exe | stats count by EventCode | sort - count`
- Result: EventCode 1 (process created) 5, 3 (network connection) 1, 5 (process ended) 1, 7 (DLL loaded) 62. No EventCode 11 (file created).
- Meaning: most events are normal DLL loads. Sysmon did not record how the file got onto the disk.

**14. Who started `3791.exe`, and what is its hash?** (given)
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
