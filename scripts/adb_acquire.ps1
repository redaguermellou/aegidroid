# =========================================================================================
# AegisDroid: Real-World Android Forensic Logical Acquisition Script (PowerShell Edition)
# =========================================================================================
# Usage:
#   1. Enable "USB Debugging" under "Developer Options" on the target Android device.
#   2. Connect the device via USB to this workstation.
#   3. Open PowerShell as Administrator in this folder.
#   4. Execute: .\adb_acquire.ps1
#
# Description:
#   This script automates the logical extraction of system data, package details, process snapshots,
#   network sockets, and if the device is rooted, copies SMS/contacts SQLite databases.
#   It hashes all extracted artifacts (SHA-256) to maintain forensic integrity and creates an 
#   Acquisition Receipt log.
# =========================================================================================

$ErrorActionPreference = "Stop"

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "     AEGISDROID: MOBILE ACQUISITION ENGINE - FORENSIC UTILITY" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

# 1. Check if ADB is in Path
Write-Host "[*] Checking for Android Debug Bridge (ADB)..." -ForegroundColor Yellow
$adbPath = Get-Command adb -ErrorAction SilentlyContinue
if (-not $adbPath) {
    Write-Host "[!] ERROR: 'adb' not found in System Path." -ForegroundColor Red
    Write-Host "[i] Please install Android SDK Platform Tools or add adb.exe's directory to your PATH variables." -ForegroundColor Yellow
    Write-Host "[i] Exiting..." -ForegroundColor Red
    Exit
}
Write-Host "[+] ADB located at: $($adbPath.Source)" -ForegroundColor Green

# 2. Check for Connected Devices
Write-Host "[*] Starting ADB Server and checking connected devices..." -ForegroundColor Yellow
$devices = & adb devices | Select-String -Pattern "\bdevice\b"
if ($devices.Count -eq 0) {
    Write-Host "[!] ERROR: No authorized Android devices connected." -ForegroundColor Red
    Write-Host "[i] Ensure USB Debugging is enabled and you approved the fingerprint prompt on the device screen." -ForegroundColor Yellow
    Write-Host "[i] Exiting..." -ForegroundColor Red
    Exit
}

$selectedDevice = $devices[0].ToString().Split("`t")[0]
Write-Host "[+] Target device connected: $selectedDevice" -ForegroundColor Green

# 3. Create Extraction Directory
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$extractionFolder = "aegisdroid_extract_$($selectedDevice)_$timestamp"
$absoluteFolderPath = Join-Path $PSScriptRoot $extractionFolder
New-Item -ItemType Directory -Path $absoluteFolderPath | Out-Null
Write-Host "[+] Created secure acquisition directory: $absoluteFolderPath" -ForegroundColor Green
Write-Host ""

# Start Acquisition Log
$logPath = Join-Path $absoluteFolderPath "acquisition_receipt.log"
$logHeader = @"
======================================================================
                  AEGISDROID ACQUISITION RECEIPT
======================================================================
Workstation:      $env:COMPUTERNAME
Operator:         $env:USERNAME
Extraction Date:  $(Get-Date -Format "yyyy-MM-dd HH:mm:ss UTCzzz")
Device Identifier:$selectedDevice
Target Folder:    $absoluteFolderPath
======================================================================
"@
$logHeader | Out-File -FilePath $logPath -Encoding utf8

# Helper function to acquire file/data
function Acquire-Data {
    param(
        [string]$Description,
        [string]$Command,
        [string]$OutFile,
        [bool]$IsShell = $true
    )

    Write-Host "[*] Extracting $Description..." -ForegroundColor Yellow
    $destination = Join-Path $absoluteFolderPath $OutFile
    
    try {
        if ($IsShell) {
            & adb -s $selectedDevice shell $Command > $destination
        } else {
            & adb -s $selectedDevice $Command $destination
        }
        
        # Calculate hash
        if (Test-Path $destination) {
            $hash = (Get-FileHash -Path $destination -Algorithm SHA256).Hash
            $logEntry = "[ACQUIRED] $Description -> File: $OutFile | SHA-256: $hash"
            $logEntry | Out-File -FilePath $logPath -Append -Encoding utf8
            Write-Host "[+] Successfully extracted. SHA-256: $hash" -ForegroundColor Green
        } else {
            throw "File not created"
        }
    }
    catch {
        $logEntry = "[FAILED] $Description -> Error during acquisition."
        $logEntry | Out-File -FilePath $logPath -Append -Encoding utf8
        Write-Host "[!] FAILED: Unable to extract $Description." -ForegroundColor Red
    }
}

# 4. Logical Extraction Sequence
Acquire-Data -Description "System Build Properties" -Command "getprop" -OutFile "build.prop"
Acquire-Data -Description "Installed Package Listings" -Command "pm list packages -f -u" -OutFile "packages.txt"
Acquire-Data -Description "Active Operating Processes" -Command "ps -A" -OutFile "processes.txt"
Acquire-Data -Description "Active Network Connections" -Command "netstat -antp" -OutFile "network_sockets.txt"
Acquire-Data -Description "Dumpsys Battery Integrity Log" -Command "dumpsys battery" -OutFile "battery_integrity.txt"
Acquire-Data -Description "Dumpsys Wifi & Settings Info" -Command "dumpsys wifi" -OutFile "wifi_network.txt"

# 5. Check Root Status & Attempt Protected SQLite Pulls
Write-Host "[*] Auditing device system authorization (Root check)..." -ForegroundColor Yellow
$suCheck = & adb -s $selectedDevice shell "su -c 'id'" -ErrorAction SilentlyContinue 2>$null
$isRooted = $false
if ($suCheck -and $suCheck.ToString().Contains("uid=0")) {
    $isRooted = $true
    Write-Host "[+] Root access detected (SuperUser Available)." -ForegroundColor Green
    "[ROOT DETECTED] Superuser binaries available. Initiating protected database extraction..." | Out-File -FilePath $logPath -Append -Encoding utf8
} else {
    Write-Host "[i] No SuperUser permission. Operating in standard Logical extraction mode." -ForegroundColor Gray
    "[LOGICAL ONLY] Standard security sandbox active. Direct read-protected folder pulling bypassed." | Out-File -FilePath $logPath -Append -Encoding utf8
}

if ($isRooted) {
    # Pull Messaging database
    Write-Host "[*] Extracting mmssms.db (SMS/MMS Database)..." -ForegroundColor Yellow
    $smsDestination = Join-Path $absoluteFolderPath "mmssms.db"
    & adb -s $selectedDevice shell "su -c 'cat /data/data/com.android.providers.telephony/databases/mmssms.db'" > $smsDestination
    if (Test-Path $smsDestination -and (Get-Item $smsDestination).Length -gt 0) {
        $hash = (Get-FileHash -Path $smsDestination -Algorithm SHA256).Hash
        "[ACQUIRED] SMS/MMS Database -> File: mmssms.db | SHA-256: $hash" | Out-File -FilePath $logPath -Append -Encoding utf8
        Write-Host "[+] Extracted mmssms.db | SHA-256: $hash" -ForegroundColor Green
    } else {
        Write-Host "[!] Failed to exfiltrate mmssms.db copy." -ForegroundColor Red
    }

    # Pull Contacts & Call History database
    Write-Host "[*] Extracting contacts2.db (Contacts & Calls Database)..." -ForegroundColor Yellow
    $contactsDestination = Join-Path $absoluteFolderPath "contacts2.db"
    & adb -s $selectedDevice shell "su -c 'cat /data/data/com.android.providers.contacts/databases/contacts2.db'" > $contactsDestination
    if (Test-Path $contactsDestination -and (Get-Item $contactsDestination).Length -gt 0) {
        $hash = (Get-FileHash -Path $contactsDestination -Algorithm SHA256).Hash
        "[ACQUIRED] Contacts/Calls Database -> File: contacts2.db | SHA-256: $hash" | Out-File -FilePath $logPath -Append -Encoding utf8
        Write-Host "[+] Extracted contacts2.db | SHA-256: $hash" -ForegroundColor Green
    } else {
        Write-Host "[!] Failed to exfiltrate contacts2.db copy." -ForegroundColor Red
    }
} else {
    Write-Host "[i] Dynamic bypass recommendation: Run an adb backup or content provider queries to fetch logical logs." -ForegroundColor Gray
    Write-Host "[*] Executing content provider read for SMS history backup..." -ForegroundColor Yellow
    $smsContentDest = Join-Path $absoluteFolderPath "content_sms.txt"
    & adb -s $selectedDevice shell "content query --uri content://sms" > $smsContentDest 2>$null
    if (Test-Path $smsContentDest -and (Get-Item $smsContentDest).Length -gt 0) {
        $hash = (Get-FileHash -Path $smsContentDest -Algorithm SHA256).Hash
        "[ACQUIRED] SMS Provider Content Export -> File: content_sms.txt | SHA-256: $hash" | Out-File -FilePath $logPath -Append -Encoding utf8
        Write-Host "[+] Extracted content://sms data dump | SHA-256: $hash" -ForegroundColor Green
    } else {
        Write-Host "[!] Standard sandbox blocked direct Provider querying. Exfil bypassed." -ForegroundColor Gray
    }
}

# 6. Finalizing
Write-Host ""
Write-Host "======================================================================" -ForegroundColor Green
Write-Host "     ACQUISITION COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
Write-Host "[i] Forensic folder: $absoluteFolderPath" -ForegroundColor Yellow
Write-Host "[i] Receipt Log: $logPath" -ForegroundColor Yellow
Write-Host "[i] You can now import pulled SQLite databases into the AegisDroid dashboard!" -ForegroundColor Green
Write-Host "======================================================================" -ForegroundColor Green
