/**
 * AegisDroid Handbook - Android Forensic Knowledge Base
 * Rich structured content detailing Android incident response, SQLite structures, and ADB workflows.
 */

const ANDROID_FORENSIC_DOCUMENTATION = {
  partitions: [
    { name: "/boot", content: "Kernel, RAM disk, boot image.", access: "Read-only", forensicImportance: "Low in typical user investigations, but critical in detecting custom root-kits or modified bootloaders." },
    { name: "/recovery", content: "Alternative boot partition containing recovery interface (TWRP, stock recovery).", access: "Read-only", forensicImportance: "Allows flashing custom recovery to perform block-level physical extraction without booting the primary OS." },
    { name: "/system", content: "The core Android Operating System. System apps, libraries, system binaries, frameworks.", access: "Read-only (unless rooted/unlocked)", forensicImportance: "High for root-kit detection, system binaries integrity verification, and pre-installed system bloatware analysis." },
    { name: "/cache", content: "Temporary storage, OTA update cache, temporary application caches.", access: "Read-write", forensicImportance: "Contains active cache logs, temporary downloaded APKs, recovery logs, and remnants of aborted system operations." },
    { name: "/data", content: "The USERDATA partition. User-installed applications, local configurations, chats, databases, call logs, media, contacts.", access: "Protected (Root Required)", forensicImportance: "THE PRIMARY SOURCE OF FORENSIC EVIDENCE. Houses SQLite databases containing all messaging history, call logs, contacts, account tokens, and malware payloads." }
  ],
  databases: [
    {
      path: "/data/data/com.android.providers.telephony/databases/mmssms.db",
      description: "SMS and MMS messages (body, sender, recipient, timestamp, read status).",
      tables: "sms (individual text records), pdus (MMS headers), parts (MMS attachments).",
      keyFields: "address (phone number), body (message body), date (Unix Epoch in ms), type (1 = incoming, 2 = outgoing)."
    },
    {
      path: "/data/data/com.android.providers.contacts/databases/contacts2.db",
      description: "Contacts records, call history, dial records, email directories.",
      tables: "calls (call history log), contacts (unified contacts), raw_contacts (account-separated lists).",
      keyFields: "number (phone number), date (Epoch timestamp), duration (call duration in seconds), type (1 = incoming, 2 = outgoing, 3 = missed, 5 = rejected)."
    },
    {
      path: "/data/data/com.android.providers.telephony/databases/telephony.db",
      description: "Cell towers connected to, SIM card identification numbers (IMSI/ICCID), cellular config.",
      tables: "siminfo (SIM active profiles), carriers (APN internet routes).",
      keyFields: "imsi, iccid, carrier_name, apn."
    },
    {
      path: "/data/data/com.android.chrome/app_chrome/Default/History",
      description: "Google Chrome browser history, search history, download queues.",
      tables: "urls (browsed links), visits (timestamped logs of site entries), downloads (file download paths).",
      keyFields: "url, title, visit_count, last_visit_time (Chrome/WebKit epoch in microseconds)."
    },
    {
      path: "/data/system/packages.list",
      description: "Plain-text database listing all installed applications, their user IDs, paths, and groups.",
      tables: "Non-SQL flat file. Contains space-separated records of packages.",
      keyFields: "package_name, user_id, debug_flag, data_directory_path, se_linux_category."
    },
    {
      path: "/data/system/packages.xml",
      description: "XML file mapping package signatures, dangerous permissions declared, and requested permissions.",
      tables: "XML Structure.",
      keyFields: "<package>, <perms>, <sigs> blocks mapping app attributes."
    }
  ],
  adbCommands: [
    { cmd: "adb devices", desc: "Lists all connected Android Emulators or physical devices with USB Debugging enabled." },
    { cmd: "adb shell getprop", desc: "Queries all system build parameters. Crucial for detecting custom firmware, unlocked loaders, root tags, and SELinux configurations." },
    { cmd: "adb shell pm list packages -f", desc: "Lists all installed packages, their logical app names, and physical APK installation paths on `/data` or `/system`." },
    { cmd: "adb shell ps -A", desc: "Displays a snapshot of all active processes, system daemons, PID list, and execution users." },
    { cmd: "adb shell netstat -antp", desc: "Retrieves active TCP/UDP socket connections, routing states, and the corresponding PIDs running the connection." },
    { cmd: "adb pull <remote_path> <local_path>", desc: "Forensically copies a database or file from the Android file system onto the examiner's computer." },
    { cmd: "adb backup -apk -shared -all -f full_backup.ab", desc: "Extracts a full logical backup of the device, including app resources and shared memory." }
  ],
  workflows: [
    {
      step: "1. Device Isolation & Preparation",
      details: "Immediately place the device in **Airplane Mode** or inside a Faraday bag to block remote wipe commands (e.g., via Find My Device). Keep the phone charged and examine if USB Debugging (`Developer Options`) is toggled. If locked, analyze bypass scenarios (custom recoveries, bootloader exploits, bypass tools)."
    },
    {
      step: "2. Evidence Acquisition",
      details: "Determine the extraction method:\n- **Logical**: Run `adb backup` or invoke standard ADB commands to copy databases (`mmssms.db`, etc.) which are accessible. Safe but limited to userland data.\n- **Physical**: Create a raw sector-by-sector image of partitions (like `/data`). Requires root privileges, dynamic bootloader exploits (e.g., MTK Client, Qualcomm EDL mode), or physical chip-off desoldering."
    },
    {
      step: "3. Integrity Verification (Hashing)",
      details: "Instantly calculate cryptographic hashes (SHA-256 / MD5) of the pulled files/dumps. This creates a baseline mathematical identity of the evidence, ensuring no modification occurred during processing. Any changes will invalidate the forensic chain of custody."
    },
    {
      step: "4. SQLite Parsing & Keyword Hunting",
      details: "Load the database files into specialized tools (such as Autopsy, SQLite Analyzer, or AegisDroid's SQL module). Write custom queries to filter records, extract deleted data from SQLite write-ahead logs (WAL) or rollback journals, and search for indicators of compromise (IOCs) such as suspicious URLs, international commands, and automated malware spam."
    },
    {
      step: "5. Timeline & Link Analysis",
      details: "Construct a chronological timeline combining all activity logs. Match incoming malicious messages to browser download requests, file install updates, process executions, and exfiltration network requests. This reconstructs the complete attack chain."
    },
    {
      step: "6. Formal Reporting",
      details: "Compile a forensic report detailing: Executive summary, device specs, file hashing, step-by-step evidence discovery, MITRE ATT&CK mapping, and mitigation steps. This report must be immutable and verifiable in a legal court or corporate audit."
    }
  ]
};

// If executing in Node environments
if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
  module.exports = ANDROID_FORENSIC_DOCUMENTATION;
}
