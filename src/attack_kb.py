"""
Curated MITRE ATT&CK (Enterprise) knowledge base subset.

HONESTY NOTE: attack.mitre.org and the official STIX/TAXII feed (and the
GitHub mirror of the ATT&CK dataset) are not reachable from this sandbox, so
this is a hand-curated subset (not a live pull) covering the ~30 techniques
relevant to the attack families this prototype detects: reconnaissance,
credential access, impact/DoS, exfiltration, and lateral movement. Technique
IDs, names, tactics and mitigation IDs are from the public ATT&CK framework
as of my training data and are stable/versioned identifiers, but this file
should be replaced with a live pull (e.g. via the `mitreattack-python`
library against the official TAXII server, or the cached STIX JSON from
github.com/mitre-attack/attack-stix-data) before any real deployment, to
stay current as ATT&CK is revised.

Each technique carries a `signal_features` list: the raw behavioral features
(from generate_dataset.FEATURE_COLUMNS) that would typically be elevated if
that technique were in play. The attribution agent uses this as the
"retrieval" step of a retrieve-then-generate pipeline: it matches an
anomaly's top contributing features against this list to find candidate
techniques, then (optionally) uses an LLM to turn the top candidates into a
readable analyst narrative.
"""

ATTACK_KB = [
    # --- Reconnaissance / Discovery (-> port_scan) ---
    {
        "id": "T1595", "tactic": "Reconnaissance", "name": "Active Scanning",
        "description": "Adversaries actively probe target infrastructure to gather information "
                        "prior to exploitation, e.g. IP block and open-port scanning.",
        "signal_features": ["unique_dst_ports", "unique_dst_ips", "conn_rate_per_min", "avg_packet_size", "novel_peer_ratio"],
        "data_sources": ["Network Traffic: Network Traffic Flow", "Network Traffic: Network Connection Creation"],
        "mitigations": ["M1056 Pre-compromise (limit exposed attack surface)"],
    },
    {
        "id": "T1046", "tactic": "Discovery", "name": "Network Service Discovery",
        "description": "Adversaries enumerate services running on remote hosts, including port "
                        "scans and vulnerability scans, to plan lateral movement or exploitation.",
        "signal_features": ["unique_dst_ports", "unique_dst_ips", "duration_s", "avg_packet_size", "novel_peer_ratio"],
        "data_sources": ["Network Traffic: Network Traffic Flow", "Cloud Service: Cloud Service Discovery"],
        "mitigations": ["M1031 Network Intrusion Prevention", "M1030 Network Segmentation"],
    },
    {
        "id": "T1018", "tactic": "Discovery", "name": "Remote System Discovery",
        "description": "Adversaries enumerate remote systems on a network, often using native "
                        "admin tools (ping sweeps, ARP, net view) prior to lateral movement.",
        "signal_features": ["unique_dst_ips", "internal_dst_ratio", "conn_rate_per_min", "novel_peer_ratio"],
        "data_sources": ["Command: Command Execution", "Network Traffic: Network Traffic Flow"],
        "mitigations": ["M1030 Network Segmentation"],
    },

    # --- Credential Access (-> brute_force) ---
    {
        "id": "T1110", "tactic": "Credential Access", "name": "Brute Force",
        "description": "Adversaries attempt to gain access to accounts via repeated, systematic "
                        "guessing of credentials against a login service.",
        "signal_features": ["failed_auth_count", "admin_proto_ratio", "unique_dst_ports"],
        "data_sources": ["User Account: User Account Authentication", "Application Log: Application Log Content"],
        "mitigations": ["M1032 Multi-factor Authentication", "M1036 Account Use Policies (lockout/throttle)"],
    },
    {
        "id": "T1110.001", "tactic": "Credential Access", "name": "Brute Force: Password Guessing",
        "description": "Systematic guessing of a single account's password against a service, "
                        "typically visible as many failed auths against the same destination.",
        "signal_features": ["failed_auth_count", "conn_rate_per_min"],
        "data_sources": ["User Account: User Account Authentication"],
        "mitigations": ["M1032 Multi-factor Authentication"],
    },
    {
        "id": "T1110.003", "tactic": "Credential Access", "name": "Brute Force: Password Spraying",
        "description": "A small number of commonly-used passwords tried across many accounts, "
                        "to evade per-account lockout thresholds.",
        "signal_features": ["failed_auth_count", "unique_dst_ips", "off_hours_flag"],
        "data_sources": ["User Account: User Account Authentication"],
        "mitigations": ["M1032 Multi-factor Authentication", "M1027 Password Policies"],
    },
    {
        "id": "T1078", "tactic": "Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        "name": "Valid Accounts",
        "description": "Adversaries use compromised legitimate credentials, often following a "
                        "successful brute-force or credential-theft step, to blend in with "
                        "normal activity and evade detection based on unusual process/tooling.",
        "signal_features": ["off_hours_flag", "admin_proto_ratio", "internal_dst_ratio"],
        "data_sources": ["Logon Session: Logon Session Creation", "User Account: User Account Authentication"],
        "mitigations": ["M1032 Multi-factor Authentication", "M1018 User Account Management"],
    },

    # --- Impact / Denial of Service (-> dos) ---
    {
        "id": "T1498", "tactic": "Impact", "name": "Network Denial of Service",
        "description": "Adversaries degrade or block availability of target resources by "
                        "exhausting network bandwidth or connection capacity.",
        "signal_features": ["conn_rate_per_min", "packet_count", "src_bytes"],
        "data_sources": ["Network Traffic: Network Traffic Volume"],
        "mitigations": ["M1037 Filter Network Traffic", "M1035 Limit Access to Resource Over Network"],
    },
    {
        "id": "T1499", "tactic": "Impact", "name": "Endpoint Denial of Service",
        "description": "Adversaries exhaust system resources (CPU, memory, connection tables) "
                        "on a specific endpoint or service to degrade or deny its availability.",
        "signal_features": ["conn_rate_per_min", "packet_count", "duration_s"],
        "data_sources": ["Network Traffic: Network Traffic Volume", "Sensor Health: Host Status"],
        "mitigations": ["M1037 Filter Network Traffic"],
    },

    # --- Exfiltration ---
    {
        "id": "T1041", "tactic": "Exfiltration", "name": "Exfiltration Over C2 Channel",
        "description": "Adversaries steal data by sending it over the same channel used for "
                        "command and control, often as sustained outbound transfer to a single "
                        "external endpoint.",
        "signal_features": ["src_bytes", "unique_dst_ips", "duration_s", "internal_dst_ratio"],
        "data_sources": ["Network Traffic: Network Traffic Flow", "Network Traffic: Network Traffic Content"],
        "mitigations": ["M1057 Data Loss Prevention", "M1031 Network Intrusion Prevention"],
    },
    {
        "id": "T1567", "tactic": "Exfiltration", "name": "Exfiltration Over Web Service",
        "description": "Adversaries use legitimate external web/cloud storage services to "
                        "exfiltrate data, which can blend into normal outbound HTTPS traffic.",
        "signal_features": ["src_bytes", "off_hours_flag", "internal_dst_ratio"],
        "data_sources": ["Network Traffic: Network Traffic Flow"],
        "mitigations": ["M1057 Data Loss Prevention", "M1021 Restrict Web-Based Content"],
    },
    {
        "id": "T1030", "tactic": "Exfiltration", "name": "Data Transfer Size Limits",
        "description": "Adversaries break exfiltrated data into smaller chunks below common "
                        "detection thresholds to evade volume-based alerting -- a stealthy variant "
                        "that produces a longer sustained transfer at lower per-window volume.",
        "signal_features": ["src_bytes", "duration_s", "conn_rate_per_min"],
        "data_sources": ["Network Traffic: Network Traffic Flow"],
        "mitigations": ["M1057 Data Loss Prevention"],
    },

    # --- Lateral Movement ---
    {
        "id": "T1021", "tactic": "Lateral Movement", "name": "Remote Services",
        "description": "Adversaries use valid accounts to log into internal services (RDP, SMB, "
                        "SSH, WinRM) to move laterally through the environment.",
        "signal_features": ["internal_dst_ratio", "unique_dst_ips", "admin_proto_ratio", "novel_peer_ratio"],
        "data_sources": ["Logon Session: Logon Session Creation", "Network Traffic: Network Traffic Flow"],
        "mitigations": ["M1030 Network Segmentation", "M1032 Multi-factor Authentication"],
    },
    {
        "id": "T1021.001", "tactic": "Lateral Movement", "name": "Remote Services: RDP",
        "description": "Lateral movement via Remote Desktop Protocol using valid or hijacked "
                        "credentials.",
        "signal_features": ["admin_proto_ratio", "internal_dst_ratio", "off_hours_flag", "novel_peer_ratio"],
        "data_sources": ["Logon Session: Logon Session Creation"],
        "mitigations": ["M1042 Disable or Remove Feature or Program"],
    },
    {
        "id": "T1021.002", "tactic": "Lateral Movement", "name": "Remote Services: SMB/Windows Admin Shares",
        "description": "Lateral movement using SMB and administrative file shares, often paired "
                        "with tool transfer to additional hosts.",
        "signal_features": ["admin_proto_ratio", "unique_dst_ips", "internal_dst_ratio", "novel_peer_ratio"],
        "data_sources": ["Network Share: Network Share Access"],
        "mitigations": ["M1030 Network Segmentation"],
    },
    {
        "id": "T1570", "tactic": "Lateral Movement", "name": "Lateral Tool Transfer",
        "description": "Adversaries copy tools between systems within a compromised environment "
                        "to support further activity, generating internal-to-internal transfers.",
        "signal_features": ["internal_dst_ratio", "unique_dst_ips", "src_bytes", "novel_peer_ratio"],
        "data_sources": ["File: File Creation", "Network Traffic: Network Traffic Flow"],
        "mitigations": ["M1030 Network Segmentation"],
    },

    # --- Command and Control (context for several attack types) ---
    {
        "id": "T1071", "tactic": "Command and Control", "name": "Application Layer Protocol",
        "description": "Adversaries blend C2 traffic into common application protocols (HTTP/S, "
                        "DNS) to avoid detection, often showing as periodic, low-volume, "
                        "off-hours connections to a small set of external hosts.",
        "signal_features": ["off_hours_flag", "unique_dst_ips", "conn_rate_per_min"],
        "data_sources": ["Network Traffic: Network Traffic Content"],
        "mitigations": ["M1031 Network Intrusion Prevention"],
    },
    {
        "id": "T1105", "tactic": "Command and Control", "name": "Ingress Tool Transfer",
        "description": "Adversaries transfer tools/malware into the environment from an external "
                        "system, visible as inbound transfer immediately preceding other activity.",
        "signal_features": ["dst_bytes", "unique_dst_ips", "duration_s"],
        "data_sources": ["Network Traffic: Network Traffic Flow", "File: File Creation"],
        "mitigations": ["M1037 Filter Network Traffic"],
    },
]


def techniques_by_feature(feature_name: str):
    return [t for t in ATTACK_KB if feature_name in t["signal_features"]]


if __name__ == "__main__":
    print(f"{len(ATTACK_KB)} curated ATT&CK techniques loaded")
    tactics = sorted({t["tactic"] for t in ATTACK_KB})
    for t in tactics:
        print(" -", t)
