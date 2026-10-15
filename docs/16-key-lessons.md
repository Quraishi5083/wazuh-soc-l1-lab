# 16. Key Lessons

-   EncodedCommand is not malware, and PowerShell is not malware.
-   A temp file is not malware, and file creation (Event 11) is not execution.
-   A DNS query (Event 22) is not malicious DNS, and a network event (Event 3) is not proof of attack.
-   A MITRE mapping is not a compromise, and a high rule level is not a confirmed malicious verdict.
-   The reverse also holds: several suspicious indicators, plus supporting evidence, plus a clear timeline raise confidence.
-   Detections must be built from the real telemetry, not assumptions about it.
-   An event in the archive is not an alert, a valid configuration is not a working detection, and an unresolved problem must be recorded as unresolved, not as a fix.
-   Document the live configuration, not the one you remember; where they differ, record the difference.
-   A FIM alert proves a change, not intent and not which process made it; correlate it with process telemetry.
-   Verify tool output with an independent check (for example a hash computed by PowerShell) and say what was not independently verified.
-   A vulnerability finding is a weakness, not an incident; confirm the installed version with an independent source before and after the fix.
-   A stale SIEM record is not the same as an unfixed host: check the inventory, then the agent, then the connection, and do not call a log error the cause without matching times.
-   A silent rule is not always a broken rule: read the rule's own conditions (level, process, protocol) before calling a detection failed.
-   A failed logon is not an attack and a successful logon is not proof of legitimacy: read the sequence, the logon type and what happens after.
