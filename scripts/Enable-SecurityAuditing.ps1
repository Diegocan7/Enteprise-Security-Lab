<#
.SYNOPSIS
    Configures advanced audit policies and command-line logging on Windows Server.

.DESCRIPTION
    Enables granular logging required for threat detection and SIEM telemetry:
    - Process Creation (Event ID 4688): Audits process execution events.
    - Process Command Line Inclusion: Captures full CLI flags, arguments, and script parameters.
    - Kerberos Authentication Service: Captures TGT requests (detects AS-REP Roasting).
    - Credential Validation: Tracks authentication attempts (detects brute-force / password spraying).
    - User Account Management: Audits persistence and privilege escalation attempts.

.NOTES
    Author: Diego
    Lab: Enterprise Security Lab
#>

[CmdletBinding()]
param()

Write-Host "[*] Configuring advanced security audit policies..." -ForegroundColor Cyan

# 1. Enable Process Creation Auditing
Write-Host "[*] Enabling Process Creation auditing..." -ForegroundColor Yellow
auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable | Out-Null

# 2. Enable Command-Line Logging in Event ID 4688
Write-Host "[*] Enabling command-line argument logging in process creation events..." -ForegroundColor Yellow
try {
    $auditPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit"
    if (-not (Test-Path $auditPath)) {
        New-Item -Path $auditPath -Force | Out-Null
    }
    Set-ItemProperty -Path $auditPath -Name "ProcessCreationIncludeCmdLine_Enabled" -Value 1 -Type DWord -Force
    Write-Host "[+] Command-line auditing enabled (Registry updated)." -ForegroundColor Green
} catch {
    Write-Warning "Failed to enable command-line logging: $_"
}

# 3. Enable Kerberos and Account Auditing for Identity Threat Detection
Write-Host "[*] Enabling authentication and account management audit subcategories..." -ForegroundColor Yellow
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"Credential Validation" /success:enable /failure:enable | Out-Null
auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable | Out-Null

Write-Host "`n[+] Advanced audit policy configuration applied successfully." -ForegroundColor Green
