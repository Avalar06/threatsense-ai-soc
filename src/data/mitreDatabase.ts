export interface MitreTechniqueDefinition {
  id: string;
  name: string;
  tactic?: string;
  subtechnique?: string;
  description: string;
  detection?: string;
  detectionCheck?: string;
  mitigation: string;
  url?: string;
}

export interface MitreMatrixTactic {
  id: string;
  name: string;
  shortName: string;
  description: string;
  techniques: MitreTechniqueDefinition[];
}

export const MITRE_TACTICS: MitreMatrixTactic[] = [
  {
    id: "TA0001",
    name: "Initial Access",
    shortName: "initial-access",
    description: "Techniques adversaries use to gain an entry point into a network.",
    techniques: [
      {
        id: "T1190",
        name: "Exploit Public-Facing Application",
        description: "Adversaries may attempt to exploit vulnerabilities in Internet-facing programs.",
        detection: "Monitor web application firewall logs for SQLi, XSS, and unusual HTTP POST payloads.",
        mitigation: "Application isolation, continuous patch management, and strict input sanitization.",
      },
      {
        id: "T1566",
        name: "Phishing",
        subtechnique: "T1566.001 Spearphishing Attachment",
        description: "Adversaries send phishing messages with malicious attachments or links.",
        detection: "Inspect email gateway logs, SPF/DKIM/DMARC failures, and anomalous sender domains.",
        mitigation: "Anti-spoofing policies, secure email gateways, and multi-factor authentication.",
      },
      {
        id: "T1078",
        name: "Valid Accounts",
        description: "Adversaries may obtain and abuse credentials of existing accounts.",
        detection: "Look for logins from unusual geolocations, off-hours access, or simultaneous IP logins.",
        mitigation: "Enforce MFA, conditional access policies, and least privilege.",
      },
    ],
  },
  {
    id: "TA0002",
    name: "Execution",
    shortName: "execution",
    description: "Techniques resulting in adversary-controlled code running on a local or remote system.",
    techniques: [
      {
        id: "T1059.001",
        name: "Command and Scripting Interpreter: PowerShell",
        description: "Adversaries abuse PowerShell to execute commands, download payloads, and manipulate systems.",
        detection: "Enable PowerShell Script Block Logging (Event ID 4104) and monitor for -EncodedCommand / IEX.",
        mitigation: "Constrained Language Mode, Execution Policy restrictions, and AMSI enforcement.",
      },
      {
        id: "T1059.004",
        name: "Unix Shell",
        description: "Adversaries abuse Unix shell interpreters (bash, sh, zsh) for command execution.",
        detection: "Monitor auditd logs, bash_history modifications, and execution of curl | bash.",
        mitigation: "Disable shell access for non-interactive service accounts.",
      },
      {
        id: "T1204",
        name: "User Execution",
        description: "An adversary relies on a user to execute malicious code via attachment or script.",
        detection: "Monitor parent-child process relationships (e.g., outlook.exe spawning powershell.exe).",
        mitigation: "Block execution of executable file types via email attachments.",
      },
    ],
  },
  {
    id: "TA0003",
    name: "Persistence",
    shortName: "persistence",
    description: "Techniques adversaries use to maintain their foothold across restarts or credentials changes.",
    techniques: [
      {
        id: "T1543.003",
        name: "Create or Modify System Process: Windows Service",
        description: "Adversaries create or modify Windows services to execute malicious commands repeatedly.",
        detection: "Monitor Windows Event ID 7045 (A new service was installed in the system).",
        mitigation: "Audit service creation privileges and restrict write access to service binaries.",
      },
      {
        id: "T1053.003",
        name: "Scheduled Task/Job: Cron",
        description: "Adversaries abuse cron jobs to run scripts on a regular schedule in Linux environments.",
        detection: "Monitor /etc/cron*, /var/spool/cron/crontabs, and auditd system calls.",
        mitigation: "Restrict access to /etc/crontab and audit cron configuration files.",
      },
      {
        id: "T1136",
        name: "Create Account",
        description: "Adversaries create local or domain accounts to maintain access.",
        detection: "Monitor Event ID 4720 (A user account was created) and /etc/passwd modifications.",
        mitigation: "Alert on unauthorized account creation and strictly control account provisioning.",
      },
    ],
  },
  {
    id: "TA0004",
    name: "Privilege Escalation",
    shortName: "privilege-escalation",
    description: "Techniques used to gain higher-level permissions on a system or network.",
    techniques: [
      {
        id: "T1548.003",
        name: "Abuse Elevation Control Mechanism: Sudo and Sudoers",
        description: "Adversaries abuse sudoers configurations or exploit sudo vulnerabilities to gain root.",
        detection: "Monitor sudo log entries (/var/log/auth.log) for unauthorized commands or sudo su invocations.",
        mitigation: "Restrict sudo commands strictly using explicit binaries without wildcard arguments.",
      },
      {
        id: "T1068",
        name: "Exploitation for Privilege Escalation",
        description: "Adversaries exploit software vulnerabilities to escalate privileges.",
        detection: "Monitor system crash logs, kernel panic indicators, and anomalous process tokens.",
        mitigation: "Regular OS patching and kernel hardening.",
      },
      {
        id: "T1078.002",
        name: "Valid Accounts: Domain Accounts",
        description: "Adversaries obtain domain administrator credentials or elevate via group membership.",
        detection: "Monitor Windows Event ID 4728 (A member was added to a security-enabled global group).",
        mitigation: "Tiered administration architecture (Tier 0/1/2 separation).",
      },
    ],
  },
  {
    id: "TA0005",
    name: "Defense Evasion",
    shortName: "defense-evasion",
    description: "Techniques adversaries use to avoid detection throughout their compromise.",
    techniques: [
      {
        id: "T1070.004",
        name: "Indicator Removal on Host: File Deletion",
        description: "Adversaries delete logs, malware binaries, or scripts to conceal intrusion traces.",
        detection: "Monitor Event ID 1102 (The audit log was cleared) and rm -rf commands targeting log paths.",
        mitigation: "Forward logs in real-time to a tamper-proof SIEM/centralized log collector.",
      },
      {
        id: "T1027",
        name: "Obfuscated Files or Information",
        description: "Adversaries encrypt, encode, or obfuscate scripts and binaries to bypass static inspection.",
        detection: "Inspect command-line strings for high entropy, Base64 strings, or XOR routines.",
        mitigation: "AMSI behavioral monitoring and dynamic sandbox execution.",
      },
      {
        id: "T1562.001",
        name: "Impair Defenses: Disable or Modify Tools",
        description: "Adversaries disable antivirus, EDR agents, or Windows Defender services.",
        detection: "Monitor Event ID 7036 (service state changes) and sc stop / Stop-Service commands.",
        mitigation: "Enable tamper protection on endpoint agents.",
      },
    ],
  },
  {
    id: "TA0006",
    name: "Credential Access",
    shortName: "credential-access",
    description: "Techniques for stealing credentials like passwords, hashes, and session tokens.",
    techniques: [
      {
        id: "T1110",
        name: "Brute Force",
        subtechnique: "T1110.001 Password Guessing / Spraying",
        description: "Adversaries attempt systematic password guessing against exposed authentication endpoints.",
        detection: "Trigger alerts on >5 failed logins from a single IP within a 5-minute window.",
        mitigation: "Account lockout policies, CAPTCHA, IP rate-limiting, and MFA.",
      },
      {
        id: "T1003.001",
        name: "OS Credential Dumping: LSASS Memory",
        description: "Adversaries extract plain-text passwords and NTLM hashes from the LSASS process (Mimikatz).",
        detection: "Monitor Sysmon Event ID 10 (ProcessAccess requesting PROCESS_VM_READ on lsass.exe).",
        mitigation: "Enable LSA Protection (RunAsPPL) and Credential Guard.",
      },
      {
        id: "T1555",
        name: "Credentials from Password Stores",
        description: "Adversaries search local browsers, vaults, or config files for plaintext credentials.",
        detection: "Monitor file access to Chrome User Data / Login Data or KeePass databases.",
        mitigation: "Use enterprise password management solutions with hardware-backed keys.",
      },
    ],
  },
  {
    id: "TA0007",
    name: "Discovery",
    shortName: "discovery",
    description: "Techniques an adversary may use to observe the environment and orient themselves.",
    techniques: [
      {
        id: "T1046",
        name: "Network Service Scanning",
        description: "Adversaries attempt to enumerate services and open ports on networked hosts.",
        detection: "Monitor firewall and IDS alerts for SYN scans or connections to multiple sequential ports.",
        mitigation: "Internal network segmentation, IDS/IPS alerting, and host firewall rules.",
      },
      {
        id: "T1087",
        name: "Account Discovery",
        description: "Adversaries enumerate local or domain accounts to identify high-privilege targets.",
        detection: "Monitor execution of net user, whoami, id, and ldapsearch queries.",
        mitigation: "Restrict LDAP search permissions for standard user accounts.",
      },
      {
        id: "T1082",
        name: "System Information Discovery",
        description: "Adversaries gather detailed system information such as OS version, patch level, and architecture.",
        detection: "Monitor systeminfo, uname -a, and hostname commands from interactive shells.",
        mitigation: "Baseline normal administrative command execution.",
      },
    ],
  },
  {
    id: "TA0011",
    name: "Command and Control",
    shortName: "command-and-control",
    description: "Techniques adversaries use to communicate with systems under their control.",
    techniques: [
      {
        id: "T1071.001",
        name: "Application Layer Protocol: Web Protocols",
        description: "Adversaries communicate with external C2 servers using HTTP/HTTPS to blend in with normal traffic.",
        detection: "Analyze proxy/firewall logs for periodic beaconing intervals, abnormal User-Agents, or dynamic DNS.",
        mitigation: "SSL/TLS inspection, outbound proxy filtering, and threat-intel domain blacklists.",
      },
      {
        id: "T1573",
        name: "Encrypted Channel",
        description: "Adversaries use symmetric or asymmetric encryption to conceal command-and-control communications.",
        detection: "Inspect certificates for self-signed or recently registered domains.",
        mitigation: "Network traffic inspection and DNS filtering.",
      },
    ],
  },
  {
    id: "TA0010",
    name: "Exfiltration",
    shortName: "exfiltration",
    description: "Techniques adversaries use to steal data from your network.",
    techniques: [
      {
        id: "T1048",
        name: "Exfiltration Over Alternative Protocol",
        description: "Adversaries steal sensitive data using protocols like DNS tunneling, ICMP, or SSH.",
        detection: "Monitor DNS query lengths, high volumes of TXT record queries, and abnormal outbound data volume.",
        mitigation: "Enforce strict egress filtering and inspect DNS requests through an internal recursive resolver.",
      },
    ],
  },
];
