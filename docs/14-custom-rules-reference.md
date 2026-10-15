# 14. Custom Rules Reference

## 14.1 Live configuration (captured 11 October 2026)

This is the content of `/var/ossec/etc/rules/local_rules.xml` as shown in Figures 10.4 and 10.5, transcribed without changes. The sample rule 100001 that ships with Wazuh is omitted.

    <group name="local,syslog,sshd,">

      <rule id="100101" level="10">
        <if_sid>61603</if_sid>
        <field name="win.eventdata.parentImage" type="pcre2">(?i)cmd.exe</field>
        <field name="win.eventdata.image" type="pcre2">(?i)powershell.exe</field>
        <description>PowerShell spawned by cmd.exe</description>
        <group>sysmon,powershell,process_creation,</group>
      </rule>

      <rule id="100102" level="10">
        <if_sid>61603</if_sid>
        <field name="win.eventdata.image" type="pcre2">(?i)\\schtasks\.exe$</field>
        <field name="win.eventdata.commandline" type="pcre2">(?i)\s/create(\s|$)</field>
        <description>Scheduled task created using schtasks.exe</description>
        <mitre>
          <id>T1053.005</id>
        </mitre>
        <group>sysmon,persistence,scheduled_task.</group>
      </rule>

      <rule id="100103" level="8">
        <if_group>sysmon_event3</if_group>
        <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe$</field>
        <field name="win.eventdata.protocol">^tcp$</field>
        <description>powershell initiated a TCP network connection to $(win.eventdata.destinationIp):$(win.eventdata.destinationPort)</description>
        <group>sysmon_event3,powershell,network_connection,</group>
      </rule>

    </group>

| **Rule** | **Level** | **Purpose** | **Status** |
|---|---|---|---|
| 100101 | 10 | PowerShell spawned by `cmd.exe` | Confirmed working by the author |
| 100102 | 10 | Scheduled task created with `schtasks.exe /create` (T1053.005) | Confirmed working by the author |
| 100103 | 8 | PowerShell initiated a TCP connection | **Unresolved**: no matching alert verified. See Sections 8.7 and 10.12 |

## 14.2 Proposed hardened versions (not deployed, not tested)

These are the changes suggested by the Phase 8 review (Section 10.8). They must be validated with `wazuh-analysisd -t` and a controlled test before they replace the live rules.

    <group name="lab_custom_detections,">

      <rule id="100101" level="10">
        <if_sid>61603</if_sid>
        <field name="win.eventdata.parentImage" type="pcre2">(?i)\\cmd\.exe$</field>
        <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe$</field>
        <description>PowerShell spawned by cmd.exe</description>
        <group>sysmon,powershell,process_creation,</group>
      </rule>

      <rule id="100102" level="10">
        <if_sid>61603</if_sid>
        <field name="win.eventdata.image" type="pcre2">(?i)\\schtasks\.exe$</field>
        <field name="win.eventdata.commandLine" type="pcre2">(?i)\s/create(\s|$)</field>
        <description>Scheduled task created using schtasks.exe</description>
        <mitre>
          <id>T1053.005</id>
        </mitre>
        <group>sysmon,persistence,scheduled_task,</group>
      </rule>

    </group>

Changes: anchored and escaped patterns for 100101, the field spelled as the decoder writes it (`commandLine`) for 100102, the stray period in the group tag replaced by a comma, and a meaningful outer group name. Which spelling of the field name is required is still to be confirmed by the retest in Section 10.12.
