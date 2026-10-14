"""
core/port_services.py

Small, hand-maintained lookup table mapping well-known ports (and ICMP
types) to human-friendly service names, purely to make notification popups
and the rules manager easier to read at a glance -- e.g. showing
"Port 445 -- SMB (Windows File Sharing)" instead of just "445".

Deliberately not exhaustive (IANA's full list has thousands of entries) --
just the ones relevant to a typical home/self-hosting setup: file sharing,
web, mail, common dev services, remote access, media/gaming, and discovery
protocols. Easy to extend -- just add entries to COMMON_TCP_PORTS /
COMMON_UDP_PORTS.
"""

from __future__ import annotations

COMMON_TCP_PORTS: dict[int, str] = {
    20: "FTP (Data)",
    21: "FTP (Control)",
    22: "SSH",
    23: "Telnet",
    25: "SMTP (Email)",
    80: "HTTP (Web)",
    110: "POP3 (Email)",
    135: "RPC (Windows)",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session (SMB)",
    143: "IMAP (Email)",
    389: "LDAP",
    443: "HTTPS (Web)",
    445: "SMB (Windows File Sharing)",
    465: "SMTPS (Email, encrypted)",
    514: "Syslog",
    587: "SMTP (Email, submission)",
    631: "IPP (Printing)",
    993: "IMAPS (Email, encrypted)",
    995: "POP3S (Email, encrypted)",
    1433: "Microsoft SQL Server",
    1723: "PPTP (VPN)",
    3000: "Common Dev Server (e.g. Node/Grafana)",
    3306: "MySQL / MariaDB",
    3389: "RDP (Remote Desktop)",
    5000: "Common Dev Server (e.g. Flask/.NET)",
    5432: "PostgreSQL",
    5900: "VNC (Remote Desktop)",
    6379: "Redis",
    7860: "Gradio (Local AI UI)",
    8000: "Common Dev/HTTP Server",
    8080: "HTTP (Alt / Proxy)",
    8081: "HTTP (Alt)",
    8443: "HTTPS (Alt)",
    8096: "Jellyfin (Media Server)",
    8123: "Home Assistant",
    8443: "HTTPS (Alt / Portainer)",
    9000: "Portainer / Common Dev",
    9090: "Prometheus / Common Dev",
    11434: "Ollama (Local AI)",
    27017: "MongoDB",
    32400: "Plex Media Server",
    51820: "WireGuard (VPN, usually UDP)",
}

COMMON_UDP_PORTS: dict[int, str] = {
    53: "DNS",
    67: "DHCP (Server)",
    68: "DHCP (Client)",
    69: "TFTP",
    123: "NTP (Time Sync)",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram",
    161: "SNMP",
    427: "SLP (Service Location)",
    500: "IPSec / IKE (VPN)",
    514: "Syslog",
    1900: "SSDP (UPnP Discovery)",
    3478: "STUN/TURN (Voice/Video/NAT)",
    3702: "WS-Discovery",
    4500: "IPSec NAT-T (VPN)",
    5353: "mDNS (Multicast DNS / Bonjour)",
    5355: "LLMNR (Windows Name Resolution)",
    51820: "WireGuard (VPN)",
}

# ICMP "port" field in WFP events is actually the ICMP Type. Common ones:
ICMP_TYPES: dict[int, str] = {
    0: "Echo Reply (ping response)",
    3: "Destination Unreachable",
    5: "Redirect",
    8: "Echo Request (ping)",
    11: "Time Exceeded (traceroute)",
    13: "Timestamp Request",
}


def describe_port(protocol_name: str, port: str | int | None) -> str:
    """
    Returns a human-friendly label for a given protocol + port/type, or an
    empty string if unrecognized. `protocol_name` should be 'TCP', 'UDP',
    or 'ICMP' (matches ConnectionEvent.protocol_name from connection_monitor).
    """
    if port is None:
        return ""
    try:
        port_int = int(port)
    except (TypeError, ValueError):
        return ""

    protocol_name = (protocol_name or "").upper()
    if protocol_name == "TCP":
        return COMMON_TCP_PORTS.get(port_int, "")
    if protocol_name == "UDP":
        return COMMON_UDP_PORTS.get(port_int, "")
    if protocol_name == "ICMP":
        return ICMP_TYPES.get(port_int, "")
    return ""
