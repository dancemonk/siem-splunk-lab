# Case 01 worklog

Working notes during the investigation. Newest at the bottom. Searches 1-3 were given step by step while I learned SPL; from search 4, I write them myself.

## 2026-11-10

**1. Which logs mention the website?**
- Search: `index=botsv1 earliest=0 imreallynotbatman.com | stats count by sourcetype | sort - count`
- Result: `suricata` (about 30,000 events), `iis`, `fgt_utm`, `stream:http`.
- Meaning: many events mention the website, all from network and web server logs.

**2. Who sent the most requests to the website?**
- Search: `index=botsv1 earliest=0 sourcetype=stream:http imreallynotbatman.com | stats count by src_ip | sort - count`
- Result: `40.80.148[.]42` 17,483 requests, `23.22.63[.]114` 1,235 requests.
- Meaning: a scanner makes many more requests than other sources, so `40.80.148[.]42` stands out.

**3. What user agent does each IP send?**
- Search: `index=botsv1 earliest=0 sourcetype=stream:http imreallynotbatman.com | stats count by src_ip, http_user_agent | sort - count`
- Result: `40.80.148[.]42` says it is Chrome in most requests, but many requests carry attack test strings (SQL injection, XSS, command injection) with the marker `acunetix_wvs_security_test`: the Acunetix scanner. `23.22.63[.]114` sends `Python-urllib/2.7`: a Python script.
- Meaning: a user agent can be faked. This shows a scan, but it does not prove the site was hacked: I still need to see how the server answered.
- Thought: the scan could be an authorized pentest. To check: is there an approved test? A pentest would not explain the defacement.

**Open questions**
- What did `23.22.63[.]114` (the Python script) do?
- Did the server answer any attack request with success?