# SOC-Automation-Lab


## Objective


The SOC Automation Lab project aimed to build a fully automated SOC workflow using Wazuh, Shuffle and TheHive in a controlled environment by detecting suspicious activity (Mimikatz) in a windows machine, sending the telemetry to Wazuh for alerting and forwarding the alert from Wazuh to Shuffle (SOAR) for automation. Shuffle being used to enrich indicator of compromise via Virustotal and lastly using an alert/case in TheHive for incident management that automatically sends an email to an analyst with details so that they can respond. 


### Skills Learned


- Detecting suspicious activity using Sysmon and Wazuh
- Configuring Wazuh to generate alerts from telemetry
- Using Shuffle to automate workflows
- Enriching alerts using Virustotal
- Creating a case and tracking incidents in TheHive
- Integration of security tools by connecting Wazuh -> Shuffle -> The Hive -> Email notifcation

### Tools Used


- Security Information and Event Management (SIEM) system for log ingestion and analysis. (Wazuh)
- Security Orchestration, Automation and Response (Shuffle)
- Incident Management tool (The Hive)
- Sysmon (collected telemetry from endpoint device)

## Steps

<a href="https://medium.com/@uju.woo243/soc-automation-lab-00014b9028e7">SOC Automation Lab</a>
