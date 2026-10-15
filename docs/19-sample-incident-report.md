# 19. Sample Incident Report (Lab Exercise)

This report applies the investigation workflow to the real Phase 5 evidence. A second, longer case (the scheduled task from Phase 3) is written up in Section 11. It is written as an analyst would write it, and the incident is a controlled test, not a real intrusion.

| **Field** | **Value** |
|---|---|
| Report type | Authentication alert triage (lab exercise) |
| Host / agent | `WIN10-SOC-LAB` (Agent 001) |
| Account | `lab-user` (local) |
| Detection | Wazuh rules 60122 (three times) then 60118 |
| Final verdict | **Benign, controlled authentication testing** |

**Summary.** Three failed logons were followed by one successful logon for the same account within about 19 seconds.

**Timeline (times as displayed in the dashboard).**

| **Time** | **Event** |
|---|---|
| 15:16:35.903 | 4625 failed logon, bad password |
| 15:16:40.118 | 4625 failed logon, bad password |
| 15:16:45.748 | 4625 failed logon, bad password |
| 15:16:54.506 | 4624 successful logon, logon type 2 |

**Evidence.** Same account, logon type 2 (interactive), source 127.0.0.1, same caller process (`svchost.exe`, PID 0x984), failure status 0xC000006D / 0xC000006A, elevated token on success.

**Analysis.** Failures about 5 seconds apart from the local console, no remote source, one account, then success. Remote logon types (3 or 10), many accounts or an external source address would have raised the priority.

**Not checked / unknown.** Post-login process activity was not reviewed for this window, because the test was known to be controlled.

**Recommendation.** No action. In a real environment, review process creation, scheduled tasks and network connections after the 4624 before closing, and confirm the user recognises the activity.
