from __future__ import annotations

import re

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
VULN_RISK_FLOOR = {"critical": 10, "high": 8, "medium": 6}

SERVICES: dict[int, tuple[str, str, int, str, list[str]]] = {
    21: ("FTP", "cleartext", 6, "FTP sends credentials and data in clear text.",
         ["Replace FTP with SFTP or FTPS.", "If FTP is required, restrict it by firewall and disable anonymous login."]),
    22: ("SSH", "remote_admin", 3, "SSH is exposed; brute-force attempts are common.",
         ["Disable password authentication (PasswordAuthentication no) and use keys.", "Disable root login, restrict with AllowUsers, add fail2ban or equivalent."]),
    23: ("Telnet", "cleartext", 9, "Telnet is unencrypted and a classic target for botnets.",
         ["Disable the telnet service and use SSH instead.", "Block TCP/23 at the firewall."]),
    25: ("SMTP", "mail", 4, "Mail server exposed; open relay or user enumeration is possible if misconfigured.",
         ["Disable open relay and require authentication.", "Enforce STARTTLS, SPF, DKIM and DMARC."]),
    53: ("DNS", "infra", 3, "DNS exposed; recursion/zone transfers may be abusable.",
         ["Disable open recursion for external clients.", "Restrict zone transfers (AXFR) to secondary servers."]),
    80: ("HTTP", "web", 3, "Unencrypted web traffic.",
         ["Redirect HTTP to HTTPS and enable HSTS.", "Hide server version banners and keep the web server patched."]),
    110: ("POP3", "cleartext", 5, "POP3 transmits credentials in clear text.",
          ["Use POP3S (995) or disable POP3.", "Require TLS for all mail retrieval."]),
    111: ("rpcbind", "infra", 5, "rpcbind exposes RPC service information.",
          ["Disable rpcbind if NFS/NIS is not needed.", "Restrict access to trusted hosts only."]),
    135: ("MS-RPC", "infra", 6, "Windows RPC endpoint mapper should not be reachable from untrusted networks.",
          ["Block TCP/135 at the perimeter and between segments.", "Keep Windows fully patched."]),
    139: ("NetBIOS", "file_sharing", 6, "NetBIOS session service exposes Windows sharing information.",
          ["Disable NetBIOS over TCP/IP if unused.", "Block TCP/139 from untrusted networks."]),
    143: ("IMAP", "cleartext", 4, "IMAP may allow clear-text authentication.",
          ["Use IMAPS (993) or enforce STARTTLS.", "Disable plain-text login."]),
    443: ("HTTPS", "web", 1, "HTTPS exposed (expected for web services).",
          ["Use TLS 1.2+ only and disable weak ciphers.", "Renew certificates and keep the server patched."]),
    445: ("SMB", "file_sharing", 7, "SMB is a frequent ransomware and worm propagation vector.",
          ["Disable SMBv1 and require SMB signing.", "Block TCP/445 from untrusted networks; apply the latest Windows/Samba patches."]),
    465: ("SMTPS", "mail", 1, "Encrypted SMTP submission.", ["Keep TLS configuration current."]),
    587: ("SMTP-Submission", "mail", 2, "Mail submission port.", ["Require authentication and STARTTLS."]),
    993: ("IMAPS", "mail", 1, "Encrypted IMAP.", ["Keep TLS configuration current."]),
    995: ("POP3S", "mail", 1, "Encrypted POP3.", ["Keep TLS configuration current."]),
    1433: ("MSSQL", "database", 7, "Database engine reachable over the network.",
           ["Do not expose databases directly: bind to localhost or a private VLAN.", "Use strong credentials, disable 'sa' and enforce encryption."]),
    1521: ("Oracle DB", "database", 7, "Database listener reachable over the network.",
           ["Restrict the listener with valid-node checking.", "Do not expose it to untrusted networks."]),
    2049: ("NFS", "file_sharing", 6, "NFS shares may be mountable by unauthorised hosts.",
           ["Restrict exports to specific hosts in /etc/exports.", "Use root_squash and firewall TCP/2049."]),
    2375: ("Docker API", "exposed_api", 10, "Unauthenticated Docker API gives full control of the host (remote root).",
           ["Never expose the Docker socket over plain TCP.", "Use TLS client authentication (port 2376) or an SSH tunnel."]),
    3306: ("MySQL", "database", 7, "Database engine reachable over the network.",
           ["Set bind-address=127.0.0.1 or use a private network.", "Remove anonymous/remote root accounts and enforce TLS."]),
    3389: ("RDP", "remote_admin", 7, "RDP exposure is a leading cause of ransomware incidents.",
           ["Place RDP behind a VPN or gateway; never expose it directly.", "Enable NLA and MFA, and keep Windows patched."]),
    5432: ("PostgreSQL", "database", 6, "Database engine reachable over the network.",
           ["Restrict listen_addresses and pg_hba.conf to trusted hosts.", "Use scram-sha-256 and TLS."]),
    5900: ("VNC", "remote_admin", 7, "VNC often has weak or no authentication and no encryption.",
           ["Tunnel VNC through SSH or a VPN.", "Set a strong password or disable the service."]),
    5984: ("CouchDB", "database", 6, "CouchDB reachable over the network.",
           ["Enable authentication and bind to localhost.", "Make sure no admin account is left with a default or empty password."]),
    6379: ("Redis", "database", 8, "Redis is frequently exposed with no authentication, allowing data theft and takeover.",
           ["Bind to 127.0.0.1 and keep protected-mode enabled.", "Set requirepass / ACLs and firewall TCP/6379."]),
    8000: ("HTTP-alt", "web", 3, "Alternate HTTP port, often a development server.",
           ["Do not expose development servers.", "Put the service behind a reverse proxy with TLS."]),
    8080: ("HTTP-proxy/alt", "web", 3, "Alternate HTTP port, often admin consoles or proxies.",
           ["Restrict admin consoles to management networks.", "Put the service behind a reverse proxy with TLS."]),
    8443: ("HTTPS-alt", "web", 2, "Alternate HTTPS port.", ["Verify the application is patched and the TLS config is strong."]),
    9200: ("Elasticsearch", "database", 7, "Elasticsearch is often exposed without authentication, leaking data.",
           ["Enable security features (auth + TLS).", "Bind to a private interface and firewall TCP/9200."]),
    11211: ("Memcached", "database", 7, "Memcached exposure enables data leaks and DDoS amplification.",
            ["Bind to localhost and disable UDP.", "Firewall TCP/UDP 11211."]),
    27017: ("MongoDB", "database", 7, "MongoDB is often exposed without authentication.",
            ["Enable authentication and bind to a private interface.", "Firewall TCP/27017."]),
}

UNKNOWN_SERVICE = (
    "Unknown", "other", 3, "Unrecognised service exposed.",
    ["Identify the owning process (ss -tulpn / lsof -i).",
     "Close the port or restrict it by firewall if it is not required."],
)

VERSION_RULES = [
    (r"vsFTPd 2\.3\.4", "critical", "vsftpd 2.3.4 backdoor", "CVE-2011-2523",
     "This release shipped with a malicious backdoor granting a remote shell.",
     "Remove it immediately and install a trusted, current vsftpd package."),
    (r"ProFTPD 1\.3\.5(?![\w.])", "high", "ProFTPD mod_copy arbitrary file copy", "CVE-2015-3306",
     "Unauthenticated file copy can lead to remote code execution.",
     "Upgrade ProFTPD to a patched release or disable mod_copy."),
    (r"OpenSSH[_ ](?:[1-6]\.|7\.[0-6])", "medium", "Outdated OpenSSH (user enumeration)", "CVE-2018-15473",
     "Releases before 7.7 allow username enumeration and lack modern hardening.",
     "Upgrade OpenSSH through your distribution's security updates."),
    (r"Apache/2\.4\.(?:49|50)(?!\d)", "critical", "Apache path traversal / RCE", "CVE-2021-41773 / CVE-2021-42013",
     "Specific 2.4.49/2.4.50 builds allow path traversal and possible remote code execution.",
     "Upgrade Apache httpd to 2.4.51 or later."),
    (r"Apache/2\.2\.", "high", "End-of-life Apache 2.2", None,
     "Apache 2.2 no longer receives security fixes.", "Migrate to a supported Apache 2.4.x release."),
    (r"Microsoft-IIS/[1-7]\.", "high", "End-of-life Microsoft IIS", None,
     "This IIS version is unsupported and has known vulnerabilities.",
     "Upgrade to a supported Windows Server / IIS version."),
    (r"nginx/1\.(?:[0-9]|1[0-7])\.", "medium", "Outdated nginx", None,
     "This nginx branch is no longer maintained.", "Upgrade to a supported stable nginx release."),
    (r"(?:Werkzeug|SimpleHTTP|BaseHTTP)", "medium", "Development web server exposed", None,
     "A development server (Flask / Python http.server) is reachable; it is not hardened for production.",
     "Run behind a production WSGI/ASGI server and a reverse proxy."),
]


def identify_service(port: int, banner: str | None) -> dict:
    name, category, risk, issue, fixes = SERVICES.get(port, UNKNOWN_SERVICE)
    b = banner or ""
    if name == "Unknown":
        if b.startswith("SSH-"):
            name, category = "SSH", "remote_admin"
        elif b.startswith("HTTP/"):
            name, category = "HTTP", "web"
        elif b.startswith("RFB "):
            name, category, risk = "VNC", "remote_admin", 7
    return {"service": name, "category": category, "risk": risk, "issue": issue, "remediation": fixes}


def match_versions(banner: str | None) -> list[dict]:
    if not banner:
        return []
    out = []
    for pattern, sev, title, cve, desc, fix in VERSION_RULES:
        if re.search(pattern, banner, re.IGNORECASE):
            out.append({"severity": sev, "title": title, "cve": cve,
                        "description": desc, "remediation": [fix]})
    return out
