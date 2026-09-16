# Enterprise Active Directory Security & Hardening Lab
A defensive security engineering lab simulating enterprise infrastructure, attack-surface reduction via PowerShell automation, and detection telemetry.

## Why this exists

Junior Security Engineering and SOC roles require practical familiarity with enterprise identity architecture, threat surface reduction, endpoint visibility, and defense-in-depth controls. Rather than conceptual knowledge, this lab demonstrates the end-to-end engineering lifecycle: **standing up core Active Directory infrastructure, enforcing security baselines through automated code, instrumenting deep endpoint telemetry, and validating defenses against simulated adversary techniques.**

## The Architecture & Threat Model

The lab simulates an enterprise domain (`corp.me-lab.local`) deployed on isolated virtual infrastructure. Active Directory serves as the primary identity provider and the target attack surface. The lab focuses on hardening against common initial compromise and lateral movement vectors (e.g., LLMNR spoofing, NBT-NS poisoning, Kerberoasting, and living-off-the-land command execution).

## Tech Stack

- **Hypervisor & Networking:** Hyper-V (Isolated internal switch, NAT routing gateway)
- **Identity & Directory Services:** Windows Server 2022 (AD DS, DNS, Group Policy)
- **Automation & Hardening:** PowerShell (CIS-aligned system configuration, legacy protocol deprecation)
- **Endpoint Visibility & Telemetry:** Microsoft Sysmon (SwiftOnSecurity baseline configuration), Windows Event Auditing
- **SIEM & Centralized Logging:** Wazuh / Elastic (Planned)
- **Adversary Emulation:** Atomic Red Team / MITRE ATT&CK validation (Planned)

## Project Roadmap

| Phase | Focus | Status | Details |
|---|---|---|---|
| **Phase 1** | Enterprise AD Architecture & RBAC | Complete | Deployed DC01, Domain Services, DNS, structured OUs, and tiered GPO baseline |
| **Phase 2** | Security Hardening via Automation | Complete | PowerShell automation disabling legacy protocols (SMBv1, LLMNR, NetBIOS) & enabling granular audit policies |
| **Phase 3** | Deep Endpoint Telemetry (Sysmon) | In Progress | Instrumenting endpoints with Sysmon to capture process injection, hash verification, and network connections |
| **Phase 4** | Centralized Logging & Detection Pipeline | Planned | Deploying Wazuh SIEM agent-manager architecture to ingest Event ID 4688 and Sysmon telemetry |
| **Phase 5** | Adversary Emulation & Detection Validation | Planned | Executing MITRE ATT&CK techniques (Atomic Red Team) and validating SIEM alerts against telemetry |

## Security Controls Implemented

### 1. Protocol Remediation & Poisoning Mitigation
- **SMBv1 Deprecation:** Disabled to eliminate legacy SMB exploits and pass-the-hash vectors.
- **NBT-NS & LLMNR Elimination:** Enforced registry and adapter configurations disabling multicast resolution, neutralizing local network credential interception attacks (e.g., Responder).

### 2. Threat Detection Auditing
- **Process Creation (Event ID 4688):** Instrumented granular tracking for every process execution.
- **CLI Parameter Logging:** Enabled full command-line argument logging in process creation events to reveal hidden flags, script parameters, and living-off-the-land binaries (LOLBins).
- **Kerberos & Credential Tracking:** Enabled auditing for Kerberos Ticket Granting Service (TGS/TGT) requests and logon events to establish telemetry for Kerberoasting and brute-force detection.

## Repo Structure

```text
├── docs/               # Technical implementation write-ups and architecture diagrams
│   └── phase1-active-directory.md
├── scripts/          # Hardening-as-Code PowerShell automation
│   ├── Disable-LegacyProtocols.ps1
│   └── Enable-SecurityAuditing.ps1
├── telemetry/          # Sysmon configs, audit configurations, and rule mappings
└── screenshots/        # Architecture diagrams, test execution logs, and event proofs
