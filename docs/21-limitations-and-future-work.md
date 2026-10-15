# 21. Limitations and Future Work

-   Phases 1 and 2 are documented from the lab notes and stored alerts rather than from live captures.
-   The Nmap reconnaissance detection experiment was postponed because the lab hardware cannot comfortably run Kali, Windows and Wazuh at the same time.
-   Phase 6 left items unresolved: rule 100103 never produced an alert, and the final state of temporary JSON archiving was not verified (Section 8.12).
-   Phase 7 showed that searches for rules 61605 (level 0) and 100103 (PowerShell and TCP only) cannot fail or pass on an Opera UDP event. Rule 100103 still has to be tested with a PowerShell TCP Event 3. The 2 h 11 min delay between event time and archive time is explained only by a hypothesis (Section 10.5).
-   Phase 9 could not corroborate that the scheduled task's action executed: no Sysmon record of `cmd.exe /c echo DAY03-PERSISTENCE-TEST-4` was found in the evidence reviewed. The verdict is "likely benign, not fully corroborated".
-   Phase 10: the older FIM alert on the SYSTEM account stayed inconclusive (no path or change type was available), the SHA-256 of the modified file rests on Wazuh alone, and the process that changed the test file was not identified. Only the Startup folder is monitored in real time; other paths are checked every 12 hours.
-   Phase 11: the cause of the stale inventory record is not established (connection errors in the agent log are only a hypothesis), and the other 90 vulnerability findings were not triaged.
-   Phase 8 found that the live rule file differs from earlier documentation (looser patterns for 100101, lowercase `commandline` and a stray period in 100102, a sample outer group name). The differences are recorded in Section 10.8 and a retest of the field spelling is planned.
-   The Phase 6 Event Viewer screenshots are dated 8 October, while the Wazuh archive records described in the text are dated 9 October.

## 21.1 Known limitations and open items

| **#** | **Open item** | **Where** | **Next step** |
|---|---|---|---|
| 1 | Rule 100103 never produced an alert | Sections 8.7, 10.12 | Test `if_sid` 61605, replay archived JSON through logtest |
| 2 | 100102 field spelling (`commandline` live, `commandLine` documented) | Section 10.8 | Controlled retest of both spellings |
| 3 | Current value of `logall_json` | Section 10.12 | `grep -n logall /var/ossec/etc/ossec.conf`, restore, restart |
| 4 | Cause of the 2 h 11 min archive delay | Sections 9.2, 10.5 | Check agent and manager logs for that period |
| 5 | Execution of the task action `Wazuh-Day03-Test-4` not corroborated | Section 11.9 | Sysmon log and Task Scheduler history search |
| 6 | Older FIM alert on the SYSTEM account (219 bytes) is inconclusive: no path or change type | Section 12.8 | Retrieve the full alert from Discover and read `syscheck.path` and `syscheck.event` |
| 7 | SHA-256 of the modified test file confirmed only by Wazuh | Section 12.6 | Repeat the test and capture `Get-FileHash` after the change |
| 8 | Process that created and changed the FIM test file not identified | Section 12.9 | Check Sysmon Event 11 for the file around 19:20:19 local, or enable who-data |
| 9 | Cause of the stale 7-Zip inventory record (connection loss is a hypothesis; no timestamps tie the errors to the update) | Section 13.7 | Repeat with another package update, note times, compare agent log and Wazuh inventory time |
| 10 | Remaining 90 vulnerability findings not triaged | Sections 13.3, 13.10 | Triage the High findings by package and exposure |

## 21.2 Future work

| **Priority** | **Planned work** | **Why it matters** |
|---|---|---|
| 1 | Resolve rule 100103 with a PowerShell TCP Event 3 (try `if_sid` 61605, field check, logtest on the archived JSON, review issue #38097), retest the 100102 field spelling, deploy the hardened rules from Section 14.2 | Closes the one open technical problem |
| 2 | Atomic Red Team tests for T1053.005, T1059.001 and T1110, each with the rule that fired and a written verdict | Tests detections against a recognised simulation set instead of hand-made tests |
| 3 | Linux endpoint with SSH brute-force detection and Wazuh active response (block source) | Adds a second platform and a response action |
| 4 | Triage of the remaining vulnerability findings and who-data attribution for FIM alerts (FIM and vulnerability detection were covered in Phases 10 and 11) | Covers more of Wazuh than log analysis and closes the attribution gap |
| 5 | Frequency rule for repeated 4625 events and a dashboard of lab alerts | Moves from single events to patterns |
