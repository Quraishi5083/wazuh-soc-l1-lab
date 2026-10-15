# 15. Commands Reference

| **Purpose**          | **Command**                                                                                           |
|------------------------------------|------------------------------------|
| Hunting test         | `powershell.exe -NoProfile -Command "Get-Date"`                                                       |
| Persistence test     | `schtasks /Create /TN "Wazuh-Day03-Test" /TR "cmd.exe /c echo DAY03-PERSISTENCE-TEST" /SC ONLOGON /F` |
| Correlation test     | `powershell.exe -NoProfile -Command "Resolve-DnsName example.com; curl.exe https://example.com"`      |
| Validate Wazuh rules | `sudo /var/ossec/bin/wazuh-analysisd -t`                                                              |
| Look for an alert by rule ID | `grep '"id":"100103"' /var/ossec/logs/alerts/alerts.json` |
| DNS test (Phase 6) | `nslookup example.com` |
| HTTPS test (Phase 6) | `curl.exe https://example.com` |
| Find an archived Sysmon Event 3 (Phase 7) | `grep '"eventID":"3"' /var/ossec/logs/archives/archives.json \| grep -m 1 '"destinationIp":"8.8.8.8"'` |
| Search alerts for rule 61605 (Phase 7) | `grep '"id":"61605"' /var/ossec/logs/alerts/alerts.json` |
| Review FIM settings (Phase 10) | `Select-String -Path "C:\Program Files (x86)\ossec-agent\ossec.conf" -Pattern "<syscheck>","<directories","<frequency>"` |
| Hash a file (Phase 10) | `Get-FileHash $path -Algorithm SHA256` |
| FIM test: modify and delete (Phase 10) | `Add-Content -Path $path -Value "..."`, `Remove-Item -LiteralPath $path`, then `Test-Path $path` |
| Installed version of a package (Phase 11) | `Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' \| Where-Object { $_.DisplayName -like '*7-Zip*' } \| Select-Object DisplayName, DisplayVersion, InstallLocation` |
| Search the agent log for inventory messages (Phase 11) | `Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 500 \| Select-String 'syscollector\|inventory'` |
| Test the path to the manager (Phase 11) | `Test-NetConnection <manager-ip> -Port 1514` |
| Manager service and port (Phase 11) | `sudo systemctl status wazuh-manager --no-pager -l`, `sudo ss -lntp \| grep ':1514'` |
| List connected agents (Phase 11) | `sudo /var/ossec/bin/agent_control -lc` |
