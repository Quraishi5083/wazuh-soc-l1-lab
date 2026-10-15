# 4. Phase 2: Windows, Sysmon and PowerShell Investigation

## 4.1 Windows Security events used

| **Event ID**       | **Meaning**                                |
|--------------------|--------------------------------------------|
| 4624               | Successful logon                           |
| 4625               | Failed logon                               |
| 4634               | Logoff                                     |
| 4648               | Explicit credential use                    |
| 4672               | Special privileges assigned                |
| 4688 / 4689        | Process creation / termination             |
| 4698 / 4699 / 4702 | Scheduled task created / deleted / updated |
| 4720 / 4726        | User created / deleted                     |
| 4732               | Member added to local group                |
| 7045               | Service installed                          |

## 4.2 Sysmon events used

| **Event ID** | **Meaning**                    |
|--------------|--------------------------------|
| 1            | Process creation               |
| 3            | Network connection             |
| 5            | Process terminated             |
| 7            | Image loaded                   |
| 8            | CreateRemoteThread             |
| 10           | Process access                 |
| 11           | File create                    |
| 12 / 13      | Registry object / value events |
| 22           | DNS query                      |
| 23           | File delete                    |
| 24           | Clipboard change               |
| 25           | Process tampering              |

The four that mattered most in this lab: **1 (process), 3 (network), 11 (file), 22 (DNS).**

## 4.3 PowerShell in context

PowerShell is legitimate, powerful and widely used by administrators, but also frequently abused by attackers. PowerShell itself is not malicious, so the context decides. Evidence to collect: parent and child process, command line, user, integrity level, PID, ProcessGuid, file creation, DNS, network connections, script content and encoded commands.

## 4.4 Investigation: PowerShell temporary script file (Sysmon Event 11)

PowerShell created a file named like `__PSScriptPolicyTest_....ps1` in the user's `AppData\Local\Temp` folder. Wazuh raised a high-level alert (Rule 8288, Level 15) describing an executable file dropped in a location commonly used by malware.

The conclusion was **not** "temp file means malware." The questions asked instead: what created it, why, was it executed, what did it contain, and what happened afterwards? **File creation does not prove execution.**

## 4.5 Investigation: encoded PowerShell commands

`-EncodedCommand` is a suspicious indicator, not proof of malicious activity. The approach: decode the command, understand the real behaviour, then investigate the surrounding evidence.

## 4.6 DNS and network telemetry

-   **Event 22** records a DNS query. `example.com` resolved to two addresses.
-   **Event 3** records a network connection attributed to a process (here PowerShell connecting to a destination on port 443).

Event 3 is process-centric telemetry, not a packet capture.

## 4.7 Process correlation

Events are correlated using PID, ProcessGuid, timestamp, Image, ParentImage and CommandLine:

    PowerShell Event 1 -> same ProcessGuid -> DNS Event 22 -> same process -> network Event 3

Events that merely happen at about the same time must not be assumed to be related.
