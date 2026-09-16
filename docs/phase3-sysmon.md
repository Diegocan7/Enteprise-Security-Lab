# Phase 3 — Deep Endpoint Visibility & Telemetry Instrumentation (Sysmon)

## Goal

Deploy and configure Microsoft Sysmon (System Monitor) on the domain controller (`DC01`) to instrument high-fidelity defensive telemetry beyond standard Windows event logging.

Establish persistent detection capabilities for:

* Process execution hierarchies
* Cryptographic file hashes
* Remote network connections
* Code injection attacks

using an enterprise-standard configuration schema.

## Detection Engineering Rationale

Standard Windows Security Event logs provide foundational auditing, such as Event ID `4688`, but lack critical telemetry needed for modern threat detection and incident response.

| Capability                        | Standard Windows Event Logging        | Microsoft Sysmon + SwiftOnSecurity                                 |
| --------------------------------- | ------------------------------------- | ------------------------------------------------------------------ |
| **Binary Hashing**                | None (requires external manual tools) | Real-time hashing (MD5, SHA256, IMPHASH)                           |
| **Process Lineage**               | Basic Parent PID tracking             | GUID-based parent/child correlation resistant to PID reuse         |
| **Living-off-the-Land (LOLBins)** | Basic execution tracking              | Filtered monitoring of system utilities invoked maliciously        |
| **Memory Access & Injection**     | Generic handle access audits          | Explicit detection of LSASS access and remote thread injection     |
| **Network Correlation**           | Firewall logs disconnected from PIDs  | Network connections (Event ID 3) directly linked to executing PIDs |

## Implementation Details

### 1. Telemetry Schema Selection

Adopted the industry-standard **SwiftOnSecurity** Sysmon configuration template (`sysmonconfig-export.xml`).

This schema applies curated inclusion and exclusion filters to eliminate routine operating system noise while maintaining high-fidelity capture of adversary techniques mapped to the MITRE ATT&CK framework.

### 2. Service Deployment

Staged the Sysmon binary and XML configuration into:

```text
C:\Tools\Sysmon\
```

on `DC01` and installed the service using elevated PowerShell privileges:

```powershell
Set-Location C:\Tools\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

The installer registered the core service (`Sysmon64`) and attached the kernel-mode minifilter driver (`SysmonDrv`), directing event streams to the dedicated event log channel:

```text
Microsoft-Windows-Sysmon/Operational
```

## Verification & Telemetry Validation

To validate that the minifilter driver and user-mode service actively log process creation with full cryptographic hashes, an administrative reconnaissance command (`whoami /all`) was executed and the operational channel was queried for **Event ID 1**.

```powershell
whoami /all

Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 |
    Format-List
```

![Sysmon Event ID 1 Telemetry Validation](../screenshots/phase3-telemetry/sysmon-event1-validation.png)

### Telemetry Artifact Breakdown

Example Event ID `1` output:

```text
TimeCreated  : 9/16/2026 10:26:45 AM
ProviderName : Microsoft-Windows-Sysmon
Id           : 1 (Process Create)
Message      : Process Create:
               UtcTime: 2026-09-16 17:26:45.817
               ProcessGuid: {bce44f9c-d155-6aaa-9c01-000000000400}
               ProcessId: 4352
               Image: C:\Windows\SysWOW64\whoami.exe
               CommandLine: "C:\Windows\system32\whoami.exe" /all
               CurrentDirectory: C:\Tools\Sysmon\
               User: CORP\Administrator
               LogonGuid: {bce44f9c-c829-6aaa-a88c-050000000000}
               IntegrityLevel: High
               Hashes: MD5=54A7DCA405C6B9055CA032D330BB6BC5,
                       SHA256=DE913B2FFE3DA61013CEE91B21D1CE3091579401299DFAACE9016577A1B15A0E,
                       IMPHASH=505871A09E1EEB12F301671252C611BE
               ParentProcessGuid: {bce44f9c-d128-6aaa-9101-000000000400}
               ParentProcessId: 2664
               ParentImage: C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe
               ParentCommandLine: "C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe"
```

### Key Detection Signals Confirmed

* **Cryptographic Integrity:** The binary hash (`SHA256=DE913B2FFE...`) enables automated threat intelligence lookups against VirusTotal and known malicious indicators.
* **Process Lineage Correlation:** The `ParentProcessGuid` links the child execution directly to the calling `powershell.exe` instance, preserving process context even if the parent process terminates immediately after execution.
* **Contextual Audit:** The execution was flagged with `IntegrityLevel: High` and bound to the domain administrative security principal (`CORP\Administrator`).

## Engineering Takeaways

* **Sysmon Complements Windows Auditing:** While Event ID `4688` confirms execution arguments, Sysmon provides the necessary hash telemetry and file metadata required for incident response and SIEM threat correlation.
* **Minifilter Overhead:** Utilizing a well-curated schema like SwiftOnSecurity helps prevent log churn and disk exhaustion on domain controllers while maintaining comprehensive visibility over common credential dumping and reconnaissance binaries.
