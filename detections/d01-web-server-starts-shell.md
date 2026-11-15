# D01: Web server starts a command shell

From [Case 01](../cases/01-bots-v1/) (worklog entries 11 and 12).

| | |
|---|---|
| ATT&CK | T1505.003 Web Shell, T1059.003 Windows Command Shell |
| Data | Sysmon process creation (EventCode 1), `sourcetype=XmlWinEventLog` |
| Severity | High |
| Status | Tested on BOTS v1. Scheduling comes in weekend 6. |

## Why

On a normal web server, IIS (`w3wp.exe`) and PHP (`php-cgi.exe`) serve pages. They should not start `cmd.exe` or `powershell.exe`. When they do, someone is most likely running commands through a web shell. In Case 01 this was the core of the attack: `php-cgi.exe` started `cmd.exe` 17 times.

## Search: alert version

One row per server, so one attack gives one alert.

```spl
index=botsv1 sourcetype=XmlWinEventLog EventCode=1
    ParentImage IN ("*\\w3wp.exe", "*\\php-cgi.exe")
    Image IN ("*\\cmd.exe", "*\\powershell.exe")
| stats count, min(_time) AS first_seen, max(_time) AS last_seen, values(User) AS user, values(CommandLine) AS commands by host, ParentImage
| convert ctime(first_seen) ctime(last_seen)
```

## Search: detail version

One row per command, for the investigation after the alert.

```spl
index=botsv1 sourcetype=XmlWinEventLog EventCode=1
    ParentImage IN ("*\\w3wp.exe", "*\\php-cgi.exe")
    Image IN ("*\\cmd.exe", "*\\powershell.exe")
| table _time, host, User, ParentImage, Image, CommandLine
| sort _time
```

## Tests

For the tests I added a time range after `index=botsv1`.

| Test | Time range | Expected | Result |
|---|---|---|---|
| Should fire | `earliest=0` (all of BOTS v1) | The web shell session | 17 events, 21:55:22 to 22:21:34 UTC, all `php-cgi.exe` to `cmd.exe` as `NT AUTHORITY\IUSR` on `we1149srv` ([screenshot](exhibits/d01-fire-test-2x.png)) |
| Should not fire | `earliest=0 latest="08/10/2016:21:50:00"` (before the attack) | 0 | 0 events |
| Alert version | `earliest=0` | One row per server | 1 row: `we1149srv`, `php-cgi.exe`, count 17, first 21:55:22, last 22:21:34, 9 different commands ([screenshot](exhibits/d01-alert-version-2x.png)) |

## When it fires

1. Read `commands`. A test like `echo <number>` at the start is a typical web shell sign.
2. Find the web page that was called at `first_seen` (`stream:http` or `iis`). That file is most likely the web shell.
3. Escalate as a likely web shell and ask for the server to be isolated.

## Limits

- BOTS v1 is the attack-only dataset, with little normal traffic. The "should not fire" test is only a first check. Before using the rule in production, I would run it for a week and note any admin tools or plugins that start a shell on purpose.
- It only sees new processes. A web shell that runs code inside PHP does not start a shell. In Case 01 the image download was done that way (worklog entry 21), and this rule does not see it.
- A renamed copy of `cmd.exe` would not match the file name.
