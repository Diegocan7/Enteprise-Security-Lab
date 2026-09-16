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
- **Endpoint Visibility & Telemetry:** Microsoft Sysmon (SwiftOnSecurity baseline schema), Windows Event Auditing
- **SIEM & Centralized Logging:** Wazuh / Elastic (Planned)
- **Adversary Emulation:** Atomic Red Team / MITRE ATT&CK validation (Planned)

## Project Roadmap

| Phase | Focus | Status | Details |
|---|---|---|---|
| **Phase 1** | Enterprise AD Architecture & RBAC | Complete | Deployed DC01, Domain Services, DNS, structured OUs, and tiered GPO baseline — [Write-up](docs/phase1-active-directory.md) |
| **Phase 2** | Security Hardening via Automation | Complete | PowerShell automation disabling legacy protocols (SMBv1, LLMNR, NetBIOS) & enabling granular audit policies — [Write-up](docs/phase2-security-hardening.md) |
| **Phase 3** | Deep Endpoint Telemetry (Sysmon) | Complete | Sysmon deployed with SwiftOnSecurity schema; verified Event ID 1 process hashing & parent correlation — [Write-up](docs/phase3-sysmon.md) |
| **Phase 4** | Centralized Logging & Detection Pipeline | In Progress | Deploying Wazuh SIEM agent-manager architecture to ingest Event ID 4688 and Sysmon telemetry |
| **Phase 5** | Adversary Emulation & Detection Validation | Planned | Executing MITRE ATT&CK techniques (Atomic Red Team) and validating SIEM alerts against telemetry |

## Security Controls Implemented

### 1. Protocol Remediation & Poisoning Mitigation
- **SMBv1 Deprecation:** Disabled to eliminate legacy SMB exploits and pass-the-hash vectors.
- **NBT-NS & LLMNR Elimination:** Enforced registry and adapter configurations disabling multicast resolution, neutralizing local network credential interception attacks (e.g., Responder).

### 2. Threat Detection Auditing & Endpoint Telemetry
- **Process Creation (Event ID 4688):** Instrumented granular tracking for every process execution.
- **CLI Parameter Logging:** Enabled full command-line argument logging in process creation events to reveal hidden flags, script parameters, and living-off-the-land binaries (LOLBins).
- **Cryptographic File Hashing (Sysmon Event ID 1):** Configured real-time generation of MD5, SHA256, and IMPHASH values for every executed binary to enable automated threat intelligence lookups.
- **Parent Process Corroboration:** Tracked execution lineages via GUID-based parent/child correlation to defeat PID-reuse evasions.
- **Kerberos & Credential Tracking:** Enabled auditing for Kerberos Ticket Granting Service (TGS/TGT) requests and logon events to establish telemetry for Kerberoasting and brute-force detection.

## Repo Structure

```text
├── docs/                      # Technical implementation write-ups and architecture diagrams
│   ├── phase1-active-directory.md
│   ├── phase2-security-hardening.md
│   └── phase3-sysmon.md
├── scripts/                   # Hardening-as-Code PowerShell automation
│   ├── Disable-LegacyProtocols.ps1
│   └── Enable-SecurityAuditing.ps1
├── telemetry/                 # Sysmon configs, audit configurations, and rule mappings
│   └── sysmonconfig.xml
└── screenshots/               # Architecture diagrams, test execution logs, and event proofs
    ├── phase1-ad/
    ├── phase2-hardening/
    │   └── verification-controls.png
    └── phase3-telemetry/
        └── sysmon-event1-validation.png
