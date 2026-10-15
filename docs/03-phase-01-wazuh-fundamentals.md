# 3. Phase 1: Wazuh Fundamentals and SOC Investigation Foundation

## 3.1 What Wazuh does

Wazuh is a security monitoring / XDR platform used for log collection, threat detection, File Integrity Monitoring, vulnerability detection, Security Configuration Assessment, MITRE ATT&CK mapping, endpoint monitoring and incident investigation. From a SOC view: it collects telemetry from endpoints, analyses it with decoders and rules, generates alerts, and gives the analyst a place to investigate them.

## 3.2 Architecture

-   **Agent:** runs on the endpoint and collects Windows, Sysmon, file, security and process events.
-   **Manager:** the central analysis component. Receives agent data, decodes it, matches rules, generates alerts and manages agents and configuration.
-   **Decoder:** understands and structures the incoming event.
-   **Rule:** decides whether the decoded event is interesting enough to alert on.
-   **Alert:** produced when an event satisfies a rule.

    Event -> Decoder -> Rule -> Alert

The starting point for every phase is a connected agent. The Wazuh dashboard lists the Windows endpoint as active:

![Figure 3.1](../screenshots/phase-01/01-agent-active.png)

*Figure 3.1: Dashboard agent panel: `WIN10-SOC-LAB (001)`, group `default`, version v4.14.7, Microsoft Windows 10 Pro 10.0.19045.7291, status **active**. Captured on 13 October 2026, at the end of the lab.*

## 3.3 Key distinctions

-   **Event is not Alert.** Windows Event ID 4625 is an event (a failed logon). It only becomes an alert if a Wazuh rule matches it.
-   **Alert is not malware.** An alert only means "something matched this detection condition."
-   **Rule ID vs Rule Level.** The ID identifies the rule (for example 92027). The level (for example 4) is the severity assigned by the rule author. Level is not the final verdict: a level 10 alert can be legitimate and a level 4 alert can deserve investigation.

## 3.4 Investigation methodology

1.  What actually triggered the alert?
2.  What process or event caused it?
3.  Who performed it?
4.  What was the command line?
5.  What was the parent process?
6.  What happened before?
7.  What happened after?
8.  Are there related events?
9.  Is there a legitimate explanation?
10. What is my evidence-based verdict?

Possible verdicts: Benign, False positive, Suspicious, Needs investigation, Malicious, Confirmed compromise.

## 3.5 Investigation 1: McAfee updater spawning cmd.exe

**Alert:** Windows command prompt started by an abnormal process (Rule 92052, Level 4).

**Sysmon Event 1 evidence:**

-   Command: `cmd.exe /c DEL "C:\Program Files\McAfee\WebAdvisor\*.tmp"`
-   Parent: `updater.exe` inside the McAfee WebAdvisor folder
-   User: SYSTEM

**Analysis:** An updater launching cmd.exe looks suspicious at first glance. In context, the parent is the McAfee updater, the command only deletes temporary files, and it runs as SYSTEM, which matches normal software maintenance.

**Verdict:** Preliminary benign. A suspicious-looking process chain must be judged in context.

## 3.6 Investigation 2: failed logon (Event ID 4625)

A failed login was generated deliberately in the lab.

| **Field**          | **Value**               |
|--------------------|-------------------------|
| Event ID           | 4625                    |
| Logon type         | 2 (interactive)         |
| Source             | 127.0.0.1               |
| Status / Substatus | 0xC000006D / 0xC000006A |
| Rule               | 60122, Level 5          |

**Verdict:** Benign, intentional lab activity. One failed login is not brute force; it could be a typo or a test. A very different picture would be 20+ failures from one source in a short time across multiple accounts, followed by a successful login (see Phase 3 validation exercises).
