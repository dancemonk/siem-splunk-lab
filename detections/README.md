# detections

SPL rules. Each rule comes from a case and links back to it.

Each rule will have: the search, its ATT&CK technique, the data it needs, one test search
that should fire and one that should not, and the result counts from my lab.

| Rule | What it finds | ATT&CK | From |
|---|---|---|---|
| [D01](d01-web-server-starts-shell.md) | IIS or PHP starts `cmd.exe` or `powershell.exe` | T1505.003, T1059.003 | Case 01 |
