# Case 01 worklog

Working notes during the investigation. Newest at the bottom. Searches 1-3 were given step by step while I learned SPL; from search 4, I write them myself.

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
- Meaning: the two IPs are related: the same attacker with different tools.

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
- Meaning: [TODO]