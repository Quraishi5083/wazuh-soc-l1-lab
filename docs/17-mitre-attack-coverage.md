# 17. MITRE ATT&CK Coverage

Coverage is graded honestly: **Detection** means a custom rule was written and tested; **Telemetry** means the events were observed and investigated but no custom rule exists; **Reasoning** means it was only analysed in a scenario.

| **Tactic** | **Technique** | **Lab activity** | **Coverage** |
|---|---|---|---|
| Execution | T1059.001 PowerShell | PowerShell hunts, parent-child alerts, encoded commands (Phases 2 to 4) | Detection (rule 100101, built-in 92027) and telemetry |
| Execution | T1059.003 Windows Command Shell | cmd.exe launching PowerShell, process tree (Phase 4) | Detection (rule 100101) |
| Persistence | T1053.005 Scheduled Task | `schtasks /Create` test (Phase 3); the persisting task reviewed in Phase 9 | Detection (rule 100102, tagged in the rule); alert investigated, execution evidence gap |
| Persistence | T1547.001 Startup Folder | A harmless text file added to the monitored Startup folder (Phase 10); it does not execute | Detection by built-in FIM rule 554 (level 5); no custom rule |
| Defense Evasion | T1070.004 File Deletion | Deletion of the test file detected (Phase 10) | Telemetry (built-in FIM deletion alert, level 7) |
| Defense Evasion | T1027 Obfuscated Files or Information (encoded commands) | `-EncodedCommand` hunt, decoded to `Get-Date` (Phase 4) | Telemetry and reasoning, no dedicated rule |
| Command and Control | T1071.004 DNS | Event 22 queries correlated by ProcessGuid (Phases 4, 6); an Event 3 to 8.8.8.8:53 reviewed and deliberately not mapped (Phase 7) | Telemetry |
| Command and Control | T1071.001 Web Protocols | `curl.exe` HTTPS request (Phase 6) | Telemetry, rule 100103 unresolved |
| Credential Access | T1110 Brute Force | Failed-then-successful logon timeline (Phase 5) | Telemetry and reasoning, no rule; the test itself was benign |
| Initial Access / Persistence | T1078 Valid Accounts | Reading a 4624 success in context (Phase 5) | Reasoning |
| Discovery | T1046 Network Service Discovery | Internal scanning scenario (Phase 6, hypothetical) | Reasoning only |

A MITRE tag describes a technique. It does not prove that the technique was used maliciously.

Phase 11 adds no technique row on purpose: a CVE finding is an exposure, not observed attacker behaviour, and no exploitation was seen.
