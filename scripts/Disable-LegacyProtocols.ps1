<#
.SYNOPSIS
    Hardens Windows Server / Active Directory by disabling insecure legacy protocols.

.DESCRIPTION
    Mitigates common network poisoning and legacy exploit vectors:
    - SMBv1: Mitigates legacy SMB vulnerabilities (e.g., EternalBlue).
    - NetBIOS over TCP/IP: Mitigates NBT-NS broadcast spoofing and relay attacks.
    - LLMNR: Disables Link-Local Multicast Name Resolution to prevent credential hash
      interception via tools like Responder.

.NOTES
    Author: Diego
    Lab: Enterprise Security Lab
#>

[CmdletBinding()]
param()

Write-Host "[*] Starting legacy protocol remediation..." -ForegroundColor Cyan

# 1. Disable SMBv1
Write-Host "[*] Disabling SMBv1 Protocol..." -ForegroundColor Yellow
try {
    Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -ErrorAction SilentlyContinue | Out-Null
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
    Write-Host "[+] SMBv1 successfully disabled." -ForegroundColor Green
} catch {
    Write-Warning "Failed to disable SMBv1: $_"
}

# 2. Disable NetBIOS over TCP/IP across all active network adapters
Write-Host "[*] Disabling NetBIOS over TCP/IP..." -ForegroundColor Yellow
try {
    $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True"
    foreach ($adapter in $adapters) {
        # 2 = Disable NetBIOS over TCP/IP
        Invoke-CimMethod -InputObject $adapter -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = 2} | Out-Null
    }
    Write-Host "[+] NetBIOS disabled on all active interfaces." -ForegroundColor Green
} catch {
    Write-Warning "Failed to disable NetBIOS: $_"
}

# 3. Disable LLMNR via Local Policy Registry
Write-Host "[*] Disabling LLMNR (Link-Local Multicast Name Resolution)..." -ForegroundColor Yellow
try {
    $llmnrPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
    if (-not (Test-Path $llmnrPath)) {
        New-Item -Path $llmnrPath -Force | Out-Null
    }
    Set-ItemProperty -Path $llmnrPath -Name "EnableMulticast" -Value 0 -Type DWord -Force
    Write-Host "[+] LLMNR successfully disabled via registry policy." -ForegroundColor Green
} catch {
    Write-Warning "Failed to disable LLMNR: $_"
}

Write-Host "`n[+] Protocol hardening complete. Attack surface reduced." -ForegroundColor Green
