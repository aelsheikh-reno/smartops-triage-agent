"""Vendor and product names that must not appear in bank logic.

Matched case-insensitively on word boundaries. Platform names that describe what is
monitored (Windows, Linux, Active Directory, Kerberos) are allowed; names of products
and companies that could be used to answer a question are not.
"""
import re

NAMES = [
    # SIEM, log and data platforms
    "Splunk", "Microsoft Sentinel", "Azure Sentinel", "QRadar", "ArcSight", "LogRhythm", "Exabeam", "Securonix",
    "Sumo Logic", "Elastic Security", "Elastic Defend", "Elastic Agent", "Elasticsearch", "Kibana", "Chronicle",
    "Google SecOps", "Datadog", "Graylog", "Cribl", "Devo", "Rapid7", "InsightIDR", "Panther",
    # endpoint, AV and EDR
    "Microsoft Defender", "Windows Defender", "Defender", "Defender for Endpoint", "Defender for Cloud", "Defender for Office",
    "Defender for Identity", "Defender XDR", "CrowdStrike", "Falcon", "SentinelOne", "Carbon Black", "VMware Carbon Black",
    "Cortex XDR", "Trend Micro", "Kaspersky", "Sophos", "ESET", "Symantec", "Broadcom", "McAfee", "Trellix", "FireEye",
    "Mandiant", "Cylance", "Bitdefender", "Malwarebytes", "Webroot", "Cybereason", "Tanium", "Sysmon", "Sysinternals",
    # network, firewall, IDS and web
    "Palo Alto", "PAN-OS", "Prisma", "Fortinet", "FortiGate", "FortiWeb", "Check Point", "Cisco", "Firepower", "Meraki",
    "Umbrella", "Juniper", "SonicWall", "WatchGuard", "Barracuda", "Zscaler", "Netskope", "Forcepoint", "Bluecoat",
    "Blue Coat", "Squid", "Imperva", "F5", "BIG-IP", "Akamai", "Cloudflare", "Suricata", "Snort", "Zeek", "Corelight",
    "Darktrace", "ExtraHop", "Vectra", "Infoblox", "Arista", "Citrix", "NetScaler",
    # email
    "Proofpoint", "Mimecast", "Abnormal Security", "Agari", "IronPort", "Exchange Online Protection",
    # identity and PAM
    "Okta", "Ping Identity", "PingFederate", "PingOne", "Duo", "CyberArk", "BeyondTrust", "Delinea", "Thycotic",
    "SailPoint", "OneLogin", "Auth0", "Entra ID Protection", "Silverfort",
    # vulnerability and exposure
    "Tenable", "Nessus", "Qualys", "InsightVM", "Nexpose", "OpenVAS", "Censys", "Shodan",
    # cloud security products
    "GuardDuty", "Security Hub", "CloudTrail", "Macie", "Wiz", "Orca", "Lacework", "Prisma Cloud",
    # ITSM and ticketing
    "ServiceNow", "Jira", "Remedy", "BMC", "Freshservice", "Zendesk", "ManageEngine",
    # deployment, backup and RMM products
    "SCCM", "MECM", "Intune", "PDQ", "Ansible", "Veeam", "Commvault", "Datto", "Rubrik", "Cohesity",
    "AnyDesk", "TeamViewer", "ScreenConnect", "ConnectWise", "LogMeIn", "Kaseya", "NinjaOne", "Atera",
    # threat intel and reputation services
    "VirusTotal", "AbuseIPDB", "GreyNoise", "Recorded Future", "ThreatConnect", "MISP", "AlienVault",
    # misc products seen in sources
    "VMware", "Webex", "Steam", "Visual Studio Code", "VS Code",
]
PATTERN = re.compile(r"(?<![A-Za-z0-9])(" + "|".join(re.escape(n) for n in sorted(NAMES, key=len, reverse=True)) + r")(?![A-Za-z0-9])", re.I)


# Names of public source projects. Allowed in source and reference fields, never in question text
# (question text says what to check, not where).
SOURCE_PROJECTS = ["LOLDrivers", "LOLBAS", "GTFOBins", "SigmaHQ", "Sigma", "MITRE", "attack_data", "security_content"]
SOURCE_PATTERN = re.compile(r"(?<![A-Za-z0-9])(" + "|".join(re.escape(n) for n in SOURCE_PROJECTS) + r")(?![A-Za-z0-9])", re.I)
# Phrases that say where or with which tool an answer comes from.
WHERE_PATTERN = re.compile(r"\b(in|from|via|using|with|query|search(ing)?|look(ing)? up in)\s+(the\s+|a\s+|an\s+)?"
                           r"(siem|edr|xdr|av console|cmdb|itsm|ticketing system|ticket system|log(s)?|console|portal|database|"
                           r"data model|index|tool|sandbox|threat intel(ligence)? (feed|platform)|vault)\b", re.I)


def find(text):
    m = PATTERN.search(text)
    return m.group(0) if m else None


def where_phrase(text):
    m = SOURCE_PATTERN.search(text) or WHERE_PATTERN.search(text)
    return m.group(0) if m else None
