# Phase 1 — Enterprise AD Identity Architecture & Access Controls

## Goal

Deploy a secure, isolated Active Directory Domain Services (AD DS) environment to establish the centralized identity plane and primary attack surface for defensive hardening. Implement role-based access control (RBAC), enforce least-privilege boundary separations, and validate group policy delivery across endpoints.

## Environment Architecture

| Node | Role | OS | Specs | Network Config |
|---|---|---|---|---|
| **DC01** | Primary Domain Controller & DNS | Windows Server 2022 Standard | 4 GB RAM (Dynamic), 60 GB VHDX | Static `192.168.50.10` / DNS `127.0.0.1` |
| **CLIENT01** | Domain-Joined Workstation | Windows 11 Pro | 4 GB RAM (Dynamic), 60 GB VHDX | Static `192.168.50.20` / DNS `192.168.50.10` |

- **Hypervisor:** Hyper-V (Windows 11 Pro host)
- **Virtual Network:** Internal Virtual Switch (`LabSwitch`) configured with NAT routing (`LabNAT`)
- **Domain Forest FQDN:** `corp.me-lab.local`

## Implementation Details

### 1. Identity Infrastructure Deployment
Promoted `DC01` as the root Domain Controller for forest `corp.me-lab.local`. Integrated Active Directory-Integrated DNS to manage zone resolution and Kerberos SRV records securely across the lab subnet.

### 2. Tiered Organizational Unit (OU) Hierarchy
Structured OUs directly under the domain root to enforce administrative boundaries and target policy deployment, avoiding object pollution in default containers:

- `Employees`: Standard user principals and unprivileged workstation objects.
- `Contractors`: Restricted identity accounts subject to tight session boundaries.
- `IT`: Administrative workstations, privileged user objects, and delegated operational security groups.

![Active Directory OU Structure](../screenshots/phase1-ad/ou-structure.webp)

### 3. Least-Privilege & Delegated Administration
To mitigate credential theft and pass-the-hash attacks, domain administration was structured around tiered access:
- Created a dedicated administrative user principal for daily operations, deprecating the use of the default root `Administrator` account.
- Implemented a scoped security group (`Help Desk Security`) in the `IT` OU to support delegated rights over user password resets and workstation management without granting global `Domain Admins` privileges.

![Help Desk Security Group Members](../screenshots/phase1-ad/help-desk-security-members.webp)

### 4. Workstation Domain Join & Kerberos Validation
Provisioned `CLIENT01` with static IP assignment pointing to `DC01` for secure SRV lookup. Enrolled the workstation into `corp.me-lab.local`, establishing a machine account password trust with the domain controller and enabling Kerberos mutual authentication.

![CLIENT01 Domain Sign-in Screen](../screenshots/phase1-ad/signin-screen.webp)

### 5. Defensive Baseline Group Policy Delivery
Authored and linked `Baseline-Employee-Policy` to the `Employees` OU. Enforced an interactive logon inactivity limit (5 minutes) to protect against unauthorized physical and console session hijacking, mapping directly to CIS Benchmarks and standard framework controls (SOC 2 CC6.1 / ISO 27001 A.9).

## Verification

Moved `CLIENT01`'s computer object from the default `Computers` container into `OU=Employees,DC=corp,DC=me-lab,DC=local` and executed `gpresult /r` in an elevated terminal to verify GPO delivery:

![gpresult Output Confirming Baseline Policy Applied](../screenshots/phase1-ad/gpresult-verification.jpg)

```text
COMPUTER SETTINGS
------------------
    CN=CLIENT01,OU=Employees,DC=corp,DC=me-lab,DC=local
    Last time Group Policy was applied: 8/22/2026 at 5:51:03 AM
    Group Policy was applied from:      DC01.corp.me-lab.local
    Domain Name:                        CORP
    Domain Type:                        Windows 2008 or later

    Applied Group Policy Objects
    -----------------------------
        Baseline-Employee-Policy
        Default Domain Policy
```
The output validates end-to-end policy propagation from the root domain controller down to the domain-joined client.
Engineering Notes & Hardening Takeaways

# Engineering Notes & Hardening Takeaways

- Container vs. OU Policy Traversal: Computer-level GPOs linked to OUs will not evaluate against objects residing in the default CN=Computers container; machine objects must be explicitly migrated into an targeted OU structure.

- Protected AD Objects: Default domain administrative groups and the built-in Domain Controllers container are protected against accidental deletion by default. Custom OUs must follow equivalent structural protections before administrative delegation occurs.

- Client Provisioning Controls: Fresh Windows 11 client deployments on isolated subnets require offline provisioning workarounds (oobe\bypassnro) and virtual TPM 2.0 enablement before establishing domain trust.


