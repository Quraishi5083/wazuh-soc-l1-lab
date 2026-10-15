# 2. Lab Environment

| **Component**         | **Role**                                                             |
|------------------------------------|------------------------------------|
| Windows 10 endpoint   | Monitored host running Sysmon and the Wazuh agent                    |
| Sysmon                | Detailed process, network, file and DNS telemetry                    |
| Wazuh agent           | Collects and forwards events from the endpoint                       |
| Wazuh manager (Linux, `wazuh-server`) | Decodes events, matches rules, generates alerts, hosts the dashboard |
| Wazuh agent name | `WIN10-SOC-LAB` (Agent ID 001) |

| **Item** | **Value** |
|---|---|
| Wazuh | 4.14.7 (manager and agent) |
| Windows | Windows 10 Pro, OS build 10.0.19045.7291 (Wazuh agent panel, Figure 13.7); file versions in Sysmon events in earlier phases carry the 19041 number |
| Sysmon | Event schema version 5 (from archived records); the program version was not recorded |
| Virtualisation | The Wazuh manager runs in a VirtualBox virtual machine |
| Agent to manager link | TCP 1514 to the manager (IP address redacted; Section 2.2) |
| Vulnerability detection | Wazuh Vulnerability Detection module with Syscollector inventory (hourly, also on agent start); 91 findings at the time of Phase 11 |
| File integrity monitoring | Enabled on the agent (syscheck): 12-hour scans, Startup folder monitored in real time (Phase 10) |

## 2.1 Conventions used in this document

| **Topic** | **Convention** |
|---|---|
| Time zone | Sysmon `UtcTime` and archive timestamps are UTC. The Wazuh dashboard and Event Viewer show local time, UTC+5. Tables state which one they use |
| Redaction | User, host and folder names are blacked out in screenshots and replaced by placeholders in text before publication |
| Verdicts | Benign, suspicious, needs further investigation, confirmed malicious. Nothing in this lab is confirmed malicious |
| Honesty labels | *Hypothetical* (training scenario), *unresolved* (open problem), *hypothesis* (unconfirmed explanation) |
| Figure numbers | Figure N.M belongs to section N |

![Figure 2.1](../images/architecture.png)

*Figure 2.1: Lab architecture: endpoint telemetry (Sysmon and the Windows Security log) travels through the Wazuh agent to the manager, where decoders and rules produce alerts for the analyst.*

**Reading process IDs in this document.** Process IDs (PIDs) are reassigned by Windows every time a process starts, so the same program shows a different PID in every test. For example, PowerShell had PID 1460 as a parent in Phase 3 and PID 1084 in Phases 4 and 6: these are different PowerShell sessions, not an inconsistency. Sysmon records PIDs in decimal. The Windows Security events in Phase 5 record the caller process in hexadecimal (`0x984` is PID 2436 in decimal). Because PIDs can be reused, correlation in this project relies on **ProcessGuid first, and uses PID, image, user and time only as supporting evidence.**

## 2.2 How events travel from the agent to the manager

Every detection in this report depends on one thing: the endpoint's events reaching the manager. This section describes that path. Items marked *observed* were seen in this lab; the rest describes Wazuh's documented default design and was not separately tested here.

![Figure 2.2](../images/agent-manager-comm.png)

*Figure 2.2: Path of an event from the Windows endpoint to the analyst. The bold arrow is the agent-to-manager channel seen in this lab (TCP 1514); dashed arrows are parts of the default Wazuh design that were not tested separately.*

| **Channel** | **Protocol and port** | **Purpose** | **Status** |
|---|---|---|---|
| Agent to manager (events) | TCP 1514 | The agent sends collected events (Windows and Sysmon event channels, file integrity data, software inventory) and periodic keepalive messages, and receives configuration and commands | **Observed**: the agent log names `<manager-ip>:1514/tcp`, the manager listens on 1514 and `Test-NetConnection` succeeded (Section 13.7) |
| Agent enrollment | TCP 1515 | One-time registration: the manager issues the agent ID and a key that the agent then uses to protect its messages | Default design; agent 001 is enrolled and active (Figure 3.1) |
| Manager to indexer | HTTPS 9200 | Filebeat ships alerts to the Wazuh indexer, which the dashboard queries | Default design |

**The journey of one event.**

1.  The event is created on the endpoint: Sysmon writes to its operational log and Windows writes the Security log.
2.  The agent's log collector reads those event channels (the same events the manager later decodes with the `windows_eventchannel` decoder, Phase 8). File integrity and inventory modules feed the same agent.
3.  The agent places events in a send queue (the `client_buffer` setting seen in Phase 10, 5000 events) and sends them to the manager over the TCP connection to port 1514. Messages are compressed and encrypted with the key issued to that agent.
4.  On the manager, `wazuh-remoted` receives and decrypts the messages and passes them to `wazuh-analysisd`.
5.  `wazuh-analysisd` decodes each event and evaluates the rules. A match produces an alert in `alerts.json`; if archiving is enabled, every event is also written to `archives.json` (Sections 8.5 and 10.5).
6.  Filebeat ships the alerts to the indexer and the dashboard displays them, which is where the analyst investigates.

**Why this matters to an analyst.** If the agent cannot reach port 1514, nothing arrives: no alerts, no file integrity events and no inventory updates. That is exactly what the connection errors in Phase 11 showed ("Lost connection with manager", "Process locked due to agent is offline"), and it is why an *active* agent status (Figure 3.1) is the first thing to check when a detection is silent. Events held in the agent's queue while it is disconnected can reach the manager late; this is one candidate, not a proven cause, for the delay between event time and archive time discussed in Section 9.2.
