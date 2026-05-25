#!/usr/bin/env bash
# =========================================================================================
# AegisDroid: Real-World Android Forensic Logical Acquisition Script (Bash Edition)
# =========================================================================================
# Usage:
#   1. Enable "USB Debugging" under "Developer Options" on the target Android device.
#   2. Connect the device via USB to this workstation.
#   3. Open Terminal, make the script executable, and run:
#      chmod +x adb_acquire.sh
#      ./adb_acquire.sh
# =========================================================================================

set -euo pipefail

# ANSI color codes
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}======================================================================${NC}"
echo -e "${CYAN}     AEGISDROID: MOBILE ACQUISITION ENGINE - FORENSIC UTILITY${NC}"
echo -e "${CYAN}======================================================================${NC}"
echo ""

# 1. Check if ADB is in Path
echo -e "${YELLOW}[*] Checking for Android Debug Bridge (ADB)...${NC}"
if ! command -v adb &> /dev/null; then
    echo -e "${RED}[!] ERROR: 'adb' command not found in your PATH.${NC}"
    echo -e "${YELLOW}[i] Please install Android SDK Platform Tools (e.g., 'apt install adb' or 'brew install android-platform-tools').${NC}"
    exit 1
fi
echo -e "${GREEN}[+] ADB located at: $(which adb)${NC}"

# 2. Check for Connected Devices
echo -e "${YELLOW}[*] Starting ADB Server and checking connected devices...${NC}"
adb_devices=$(adb devices | grep -E "\bdevice\b" || true)
if [ -z "$adb_devices" ]; then
    echo -e "${RED}[!] ERROR: No authorized Android devices connected.${NC}"
    echo -e "${YELLOW}[i] Ensure USB Debugging is enabled and you approved the fingerprint prompt on the device screen.${NC}"
    exit 1
fi

selected_device=$(echo "$adb_devices" | head -n1 | awk '{print $1}')
echo -e "${GREEN}[+] Target device connected: $selected_device${NC}"

# 3. Create Extraction Directory
timestamp=$(date +"%Y%m%d_%H%M%S")
extraction_folder="aegisdroid_extract_${selected_device}_${timestamp}"
mkdir -p "$extraction_folder"
echo -e "${GREEN}[+] Created secure acquisition directory: $(pwd)/$extraction_folder${NC}"
echo ""

# Start Acquisition Log
log_path="${extraction_folder}/acquisition_receipt.log"
cat << EOF > "$log_path"
======================================================================
                  AEGISDROID ACQUISITION RECEIPT
======================================================================
Workstation:      $(hostname)
Operator:         $USER
Extraction Date:  $(date -u +"%Y-%m-%d %H:%M:%S UTC")
Device Identifier:$selected_device
Target Folder:    $(pwd)/$extraction_folder
======================================================================
EOF

# Helper function to acquire file/data
acquire_data() {
    local description="$1"
    local command="$2"
    local outfile="$3"
    
    echo -e "${YELLOW}[*] Extracting $description...${NC}"
    local destination="${extraction_folder}/${outfile}"
    
    if adb -s "$selected_device" shell "$command" > "$destination" 2>/dev/null; then
        # Calculate SHA-256 hash (handling mac vs linux shasum differences)
        local hash=""
        if command -v sha256sum &> /dev/null; then
            hash=$(sha256sum "$destination" | awk '{print $1}')
        elif command -v shasum &> /dev/null; then
            hash=$(shasum -a 256 "$destination" | awk '{print $1}')
        else
            hash="HASH_ENGINE_UNAVAILABLE"
        fi
        
        echo "[ACQUIRED] $description -> File: $outfile | SHA-256: $hash" >> "$log_path"
        echo -e "${GREEN}[+] Successfully extracted. SHA-256: $hash${NC}"
    else
        echo "[FAILED] $description -> Error during acquisition." >> "$log_path"
        echo -e "${RED}[!] FAILED: Unable to extract $description.${NC}"
    fi
}

# 4. Logical Extraction Sequence
acquire_data "System Build Properties" "getprop" "build.prop"
acquire_data "Installed Package Listings" "pm list packages -f -u" "packages.txt"
acquire_data "Active Operating Processes" "ps -A" "processes.txt"
acquire_data "Active Network Connections" "netstat -antp" "network_sockets.txt"
acquire_data "Dumpsys Battery Integrity Log" "dumpsys battery" "battery_integrity.txt"
acquire_data "Dumpsys Wifi & Settings Info" "dumpsys wifi" "wifi_network.txt"

# 5. Check Root Status & Attempt Protected SQLite Pulls
echo -e "${YELLOW}[*] Auditing device system authorization (Root check)...${NC}"
is_rooted=false
if adb -s "$selected_device" shell "su -c 'id'" &>/dev/null; then
    is_rooted=true
    echo -e "${GREEN}[+] Root access detected (SuperUser Available).${NC}"
    echo "[ROOT DETECTED] Superuser binaries available. Initiating protected database extraction..." >> "$log_path"
else
    echo -e "${YELLOW}[i] No SuperUser permission. Operating in standard Logical extraction mode.${NC}"
    echo "[LOGICAL ONLY] Standard security sandbox active. Direct read-protected folder pulling bypassed." >> "$log_path"
fi

if [ "$is_rooted" = true ]; then
    # Pull Messaging database
    echo -e "${YELLOW}[*] Extracting mmssms.db (SMS/MMS Database)...${NC}"
    sms_dest="${extraction_folder}/mmssms.db"
    if adb -s "$selected_device" shell "su -c 'cat /data/data/com.android.providers.telephony/databases/mmssms.db'" > "$sms_dest" 2>/dev/null && [ -s "$sms_dest" ]; then
        hash=$(sha256sum "$sms_dest" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$sms_dest" 2>/dev/null | awk '{print $1}' || echo "UNKNOWN")
        echo "[ACQUIRED] SMS/MMS Database -> File: mmssms.db | SHA-256: $hash" >> "$log_path"
        echo -e "${GREEN}[+] Extracted mmssms.db | SHA-256: $hash${NC}"
    else
        echo -e "${RED}[!] Failed to exfiltrate mmssms.db copy.${NC}"
    fi

    # Pull Contacts database
    echo -e "${YELLOW}[*] Extracting contacts2.db (Contacts & Calls Database)...${NC}"
    contacts_dest="${extraction_folder}/contacts2.db"
    if adb -s "$selected_device" shell "su -c 'cat /data/data/com.android.providers.contacts/databases/contacts2.db'" > "$contacts_dest" 2>/dev/null && [ -s "$contacts_dest" ]; then
        hash=$(sha256sum "$contacts_dest" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$contacts_dest" 2>/dev/null | awk '{print $1}' || echo "UNKNOWN")
        echo "[ACQUIRED] Contacts/Calls Database -> File: contacts2.db | SHA-256: $hash" >> "$log_path"
        echo -e "${GREEN}[+] Extracted contacts2.db | SHA-256: $hash${NC}"
    else
        echo -e "${RED}[!] Failed to exfiltrate contacts2.db copy.${NC}"
    fi
else
    # Non-rooted fallback
    echo -e "${YELLOW}[*] Executing content provider read for SMS history backup...${NC}"
    sms_content_dest="${extraction_folder}/content_sms.txt"
    if adb -s "$selected_device" shell "content query --uri content://sms" > "$sms_content_dest" 2>/dev/null && [ -s "$sms_content_dest" ]; then
        hash=$(sha256sum "$sms_content_dest" 2>/dev/null | awk '{print $1}' || shasum -a 256 "$sms_content_dest" 2>/dev/null | awk '{print $1}' || echo "UNKNOWN")
        echo "[ACQUIRED] SMS Provider Content Export -> File: content_sms.txt | SHA-256: $hash" >> "$log_path"
        echo -e "${GREEN}[+] Extracted content://sms data dump | SHA-256: $hash${NC}"
    else
        echo -e "${YELLOW}[i] Standard sandbox blocked direct Provider querying. Exfil bypassed.${NC}"
    fi
fi

# 6. Finalizing
echo ""
echo -e "${GREEN}======================================================================${NC}"
echo -e "${GREEN}     ACQUISITION COMPLETED SUCCESSFULLY!${NC}"
echo -e "${GREEN}======================================================================${NC}"
echo -e "${YELLOW}[i] Forensic folder: $(pwd)/$extraction_folder${NC}"
echo -e "${YELLOW}[i] Receipt Log: $(pwd)/$log_path${NC}"
echo -e "${GREEN}[i] You can now import pulled SQLite databases into the AegisDroid dashboard!${NC}"
echo -e "${GREEN}======================================================================${NC}"
