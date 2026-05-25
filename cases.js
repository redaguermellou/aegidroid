/**
 * AegisDroid Case Studies - Forensic Datasets
 * Contains curated evidence files representing compromised Android systems.
 */

const ANDROID_FORENSIC_CASES = [
  {
    id: "hydraspy",
    name: "Operation HydraSpy (Targeted Spyware)",
    description: "A targeted espionage campaign resembling Pegasus or Predator. The malware hides as a core system service, silently intercepts communications, records audio, and tracks device location to a remote command-and-control server.",
    targetDevice: "Google Pixel 6 Pro (Android 12, Build SQ3A.220705.004)",
    extractionDate: "2026-05-24 14:32:10 UTC",
    examiner: "Lead Digital Forensic Investigator",
    hash: "8f7b2e617d91e604f32b13da87cf91c0b395029a1b9f71cde2f821639d67efca",
    riskScore: 94,
    compromised: true,
    mitreAttack: [
      { id: "T1430", name: "Access Audio Receiver (Microphone)", status: "Active Abuse" },
      { id: "T1406", name: "Device Location Tracking", status: "Active Tracking" },
      { id: "T1412", name: "Capture SMS Messages", status: "Active Sniffing" },
      { id: "T1426", name: "System Information Discovery", status: "Executed" },
      { id: "T1624", name: "Event Triggered Execution (Boot Complete)", status: "Persistence" }
    ],
    buildProp: {
      "ro.product.model": "Pixel 6 Pro",
      "ro.product.brand": "google",
      "ro.build.version.release": "12",
      "ro.build.version.security_patch": "2022-07-05",
      "ro.build.tags": "test-keys (Suspicious - Custom Signed ROM)",
      "ro.secure": "0 (CRITICAL: Kernel integrity security check disabled)",
      "ro.debuggable": "1 (CRITICAL: ADB Shell Root permissions enabled)",
      "sys.usb.config": "mtp,adb (USB Debugging is Active)"
    },
    sms: [
      {
        id: "s1",
        sender: "+33 6 45 82 91 03",
        receiver: "Me",
        date: "2026-05-23 09:15:30",
        type: "incoming",
        body: "URGENT - Chronopost: Votre colis a rencontré une anomalie lors de sa livraison. Veuillez confirmer votre adresse de livraison sous 24h sur : https://chronopost-securise-suivi.com/telecharger-app.php pour recevoir votre colis.",
        forensicTag: "Phishing Link / Delivery Vector",
        severity: "high",
        analystNotes: "Initial entry vector. Phishing SMS spoofing Chronopost. The URL hosted a malicious Android Application Package (APK) masquerading as 'Chronopost Delivery Helper'."
      },
      {
        id: "s2",
        sender: "Me",
        receiver: "+33 6 45 82 91 03",
        date: "2026-05-23 09:17:02",
        type: "outgoing",
        body: "D'accord, je télécharge l'application tout de suite.",
        forensicTag: "User Interaction",
        severity: "low",
        analystNotes: "Investigator note: User confirmed they downloaded and executed the malicious package."
      },
      {
        id: "s3",
        sender: "+1 202 555 0143",
        receiver: "Me",
        date: "2026-05-23 09:18:15",
        type: "incoming",
        body: "PING:HYDRA_ACTIVATE_REQ_9882718",
        forensicTag: "C2 SMS Command",
        severity: "high",
        analystNotes: "Command and Control SMS trigger. This binary or plaintext SMS triggers the internal spyware components to start exfiltrating databases without standard notification overlays."
      },
      {
        id: "s4",
        sender: "Me",
        receiver: "+1 202 555 0143",
        date: "2026-05-23 09:18:20",
        type: "outgoing",
        body: "PONG:HYDRA_ACK_OK_PIXEL6",
        forensicTag: "C2 SMS Acknowledge",
        severity: "high",
        analystNotes: "Automatic response sent silently by the malware. Confirming receipt of command and active connection."
      },
      {
        id: "s5",
        sender: "+33 6 12 34 56 78",
        receiver: "Me",
        date: "2026-05-24 11:20:00",
        type: "incoming",
        body: "Salut, on mange où ce midi ? Dispo vers 13h ?",
        forensicTag: "Benign/Normal Message",
        severity: "none",
        analystNotes: ""
      }
    ],
    calls: [
      {
        id: "c1",
        number: "+1 202 555 0143",
        name: "Unknown (C2 Origin)",
        date: "2026-05-23 09:19:00",
        duration: "0s (Missed)",
        type: "incoming",
        forensicTag: "Trigger / Data Connection Call",
        severity: "medium",
        analystNotes: "A zero-second call used by HydraSpy to trigger network connections and audio recording routines."
      },
      {
        id: "c2",
        number: "+33 6 12 34 56 78",
        name: "Sophie",
        date: "2026-05-23 12:45:00",
        duration: "182s",
        type: "outgoing",
        forensicTag: "Normal Call",
        severity: "none",
        analystNotes: "Audio recording of this call was captured in the temporary cache directory of the spyware, demonstrating active espionage."
      },
      {
        id: "c3",
        number: "+44 7911 123456",
        name: "Unknown (London)",
        date: "2026-05-24 02:14:05",
        duration: "24s",
        type: "incoming",
        forensicTag: "Suspicious Call",
        severity: "medium",
        analystNotes: "Unidentified inbound call at 2:14 AM. Corresponds to active CPU wake locks."
      }
    ],
    browser: [
      {
        id: "b1",
        url: "https://chronopost-securise-suivi.com/telecharger-app.php",
        title: "Chronopost - Suivi de Colis Securisé",
        date: "2026-05-23 09:16:10",
        visits: 2,
        forensicTag: "Malware Download URL",
        severity: "high",
        analystNotes: "Phishing site hosting 'chronopost_assistant.apk'. Exfiltrated browser SQLite database indicates this domain was bookmarked right after the incoming SMS."
      },
      {
        id: "b2",
        url: "https://google.com/search?q=pourquoi+mon+telephone+chauffe",
        title: "pourquoi mon telephone chauffe - Google Search",
        date: "2026-05-23 22:30:12",
        visits: 1,
        forensicTag: "User Activity",
        severity: "none",
        analystNotes: "Victim searched for why their phone is overheating. This is a common side effect of spyware constant wake-locks, audio capture, and background encryption."
      },
      {
        id: "b3",
        url: "http://185.220.101.4/hydra/c2/register",
        title: "404 Not Found",
        date: "2026-05-23 09:17:45",
        visits: 15,
        forensicTag: "Direct C2 Endpoint Visit",
        severity: "high",
        analystNotes: "Direct browser visit. The malware used the system WebView to communicate with the control portal. The IP 185.220.101.4 is a known Tor exit node used in malops infrastructure."
      }
    ],
    packages: [
      {
        id: "p1",
        packageName: "com.android.system.service.helper",
        appName: "Android Core System Helper",
        version: "1.0.4 (Mimicked System Component)",
        installDate: "2026-05-23 09:16:55",
        path: "/data/app/~~G3k1p_x==/com.android.system.service.helper-K_3sa98d2a/",
        signature: "SHA-256: 7f2c83d6a9e142dbf9e917d21c0b395029a1b9f71cde2f821639d67efca09d82 (UNVERIFIED)",
        forensicTag: "Active Malware Implant",
        severity: "high",
        riskReason: "Uses a package name mimicking Android core, but is signed with a generic, unverified debug certificate instead of Google's Platform keys.",
        permissions: [
          { name: "android.permission.RECEIVE_BOOT_COMPLETED", status: "abused", desc: "Allows starting the spyware automatically as soon as the phone boots up." },
          { name: "android.permission.ACCESS_FINE_LOCATION", status: "abused", desc: "Silently tracks victim coordinates and uploads them every 5 minutes." },
          { name: "android.permission.RECORD_AUDIO", status: "abused", desc: "Records background microphone audio during calls and ambient sound when idle." },
          { name: "android.permission.READ_SMS", status: "abused", desc: "Intercepts all incoming SMS messages, including 2FA codes and private chats." },
          { name: "android.permission.WRITE_SMS", status: "abused", desc: "Allows sending command feedback SMS messages and deleting traces." },
          { name: "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS", status: "abused", desc: "Prevents Android from putting the app to sleep, enabling constant surveillance." }
        ]
      },
      {
        id: "p2",
        packageName: "com.whatsapp",
        appName: "WhatsApp",
        version: "2.23.10.75",
        installDate: "2024-11-12 18:22:00",
        path: "/data/app/~~WhatsApp_Base/com.whatsapp-21d120a1/",
        signature: "SHA-256: 3c5970c67e103ab682fa0ff9a72d73c7b399228d447d91e604f32b13da87cf91",
        forensicTag: "Targeted Database",
        severity: "medium",
        riskReason: "Legitimate application. However, local databases (`msgstore.db`) are flagged as actively scraped by the malicious service helper.",
        permissions: []
      }
    ],
    sockets: [
      {
        id: "k1",
        localIp: "10.0.2.15",
        localPort: 49281,
        foreignIp: "185.220.101.4",
        foreignPort: 443,
        state: "ESTABLISHED",
        process: "com.android.system.service.helper (PID: 1204)",
        forensicTag: "Active Exfiltration Tunnel",
        severity: "high",
        riskReason: "Active encrypted HTTPS tunnel from the device to a Tor node IP address. Triggered by a background thread running audio recording upload loops."
      },
      {
        id: "k2",
        localIp: "10.0.2.15",
        localPort: 38291,
        foreignIp: "142.250.179.142",
        foreignPort: 443,
        state: "ESTABLISHED",
        process: "com.google.android.gms (PID: 840)",
        forensicTag: "Legitimate Service",
        severity: "none",
        riskReason: "Standard Google Play Services sync tunnel."
      }
    ]
  },
  {
    id: "golddigger",
    name: "GoldDigger Mobile (Banking Trojan)",
    description: "A highly sophisticated financial malware targeting online banking users. It abuses the Android Accessibility Service to intercept keyboard entries, inject overlay windows mimicking banking portals, capture OTP codes, and drain accounts.",
    targetDevice: "Xiaomi Redmi Note 10 (Android 11, Build RKQ1.200826.002)",
    extractionDate: "2026-05-22 18:11:45 UTC",
    examiner: "Incident Response Engineer",
    hash: "f4a1c5d9e830b2c1d3f9e917d21c0b395029a1b9f71cde2f821639d67efca09d8",
    riskScore: 89,
    compromised: true,
    mitreAttack: [
      { id: "T1417", name: "Input Capture (Keylogging / Accessibility Abuse)", status: "Active Exploitation" },
      { id: "T1411", name: "Adversary-in-the-Middle (Overlay Injections)", status: "Active Phishing" },
      { id: "T1636", name: "Credentials from Web Browsers / WebViews", status: "Active Stealing" },
      { id: "T1409", name: "Access Database Files (SMS Intercept)", status: "Active Reading" },
      { id: "T1458", name: "Prevent App Uninstallation", status: "Active Block" }
    ],
    buildProp: {
      "ro.product.model": "Redmi Note 10",
      "ro.product.brand": "xiaomi",
      "ro.build.version.release": "11",
      "ro.build.version.security_patch": "2021-12-01 (Outdated - Vulnerable to Accessibility Exploit)",
      "ro.secure": "1 (Kernel enforcement secure)",
      "ro.debuggable": "0 (ADB Shell running in standard non-root mode)",
      "sys.usb.config": "none (USB Debugging turned off, but malware activated dynamic ADB via shell payload)"
    },
    sms: [
      {
        id: "g_s1",
        sender: "Societe Generale",
        receiver: "Me",
        date: "2026-05-21 16:42:00",
        type: "incoming",
        body: "SG SECURITE: Votre code d'activation de mobile est 783921. Si vous n'etes pas à l'origine de cette demande, contactez immediatement le 3933.",
        forensicTag: "Intercepted OTP SMS",
        severity: "high",
        analystNotes: "This SMS was intercepted by the malware package. Investigation of the SQLite read timestamps shows the database was queried by the banking trojan within 400 milliseconds of reception."
      },
      {
        id: "g_s2",
        sender: "Me",
        receiver: "+33 6 88 12 34 56",
        date: "2026-05-21 16:45:10",
        type: "outgoing",
        body: "Hey! Installe ce super outil pour calculer tes impots plus vite, c'est génial : http://calculator-tax-free.fr/dl/calc.apk",
        forensicTag: "Worm Propagation / SMS Spamming",
        severity: "high",
        analystNotes: "Outbound SMS sent autonomously by the Trojan to contacts. Spreading the infection link further."
      },
      {
        id: "g_s3",
        sender: "SG ALERTE",
        receiver: "Me",
        date: "2026-05-21 17:05:00",
        type: "incoming",
        body: "ALERTE: Changement de RIB bénéficiaire effectué. Si ce n'est pas vous, connectez-vous immédiatement sur votre espace client.",
        forensicTag: "Incident Confirmation SMS",
        severity: "high",
        analystNotes: "Bank warning indicating a new transfer recipient has been registered. This confirms unauthorized funds transfer."
      }
    ],
    calls: [
      {
        id: "g_c1",
        number: "3933",
        name: "Societe Generale Helpline",
        date: "2026-05-21 17:06:12",
        duration: "0s (Blocked)",
        type: "outgoing",
        forensicTag: "Blocked Security Call",
        severity: "high",
        analystNotes: "Outbound call to the bank's fraud helpline was intercepted and immediately disconnected by the malware's call receiver service to prevent the victim from blocking their accounts."
      }
    ],
    browser: [
      {
        id: "g_b1",
        url: "http://calculator-tax-free.fr/dl/calc.apk",
        title: "Calculateur d'Impôts Gratuit - APK",
        date: "2026-05-21 15:30:00",
        visits: 1,
        forensicTag: "Initial APK Vector",
        severity: "high",
        analystNotes: "Downloaded via third-party web page link. The calculator app requested Accessibility Service immediately on startup."
      },
      {
        id: "g_b2",
        url: "https://m.societegenerale.fr.fake-portal-secure.net/auth",
        title: "Societe Generale - Espace Personnel",
        date: "2026-05-21 16:41:15",
        visits: 3,
        forensicTag: "HTML Injection / Overlay WebView",
        severity: "high",
        analystNotes: "The phishing overlay screen injected on top of the legitimate Societe Generale app redirected web requests through this server to capture credentials."
      }
    ],
    packages: [
      {
        id: "g_p1",
        packageName: "com.utility.calculator.pro",
        appName: "Calculator Plus Pro",
        version: "4.8.1 (Infected Calculator Utilities)",
        installDate: "2026-05-21 15:32:00",
        path: "/data/app/~~Cal_Utility_Pro/com.utility.calculator.pro-M39sd/",
        signature: "SHA-256: d8f39c28e9a22d30e9d1a8c08efca09d82f71cde2f821639d67efca09d82120e",
        forensicTag: "Banking Trojan",
        severity: "high",
        riskReason: "Malicious APK which asks for system-critical overlays and accessibility services. Utilizes keylogging to steal online banking logs.",
        permissions: [
          { name: "android.permission.BIND_ACCESSIBILITY_SERVICE", status: "abused", desc: "CRITICAL: Grants the app full reading access to the screen layout, gestures, keystrokes, and buttons. Used to capture inputs on external bank screens." },
          { name: "android.permission.SYSTEM_ALERT_WINDOW", status: "abused", desc: "Allows displaying invisible or full-screen overlay overlays on top of official apps to steal passwords." },
          { name: "android.permission.READ_SMS", status: "abused", desc: "Intercepts banking OTP notifications." },
          { name: "android.permission.CALL_PHONE", status: "abused", desc: "Allows dropping outbound calls to bank helpdesks to delay fraud detection." },
          { name: "android.permission.QUERY_ALL_PACKAGES", status: "abused", desc: "Scans the phone for financial, banking, or cryptocurrency wallet apps to coordinate target overlays." }
        ]
      }
    ],
    sockets: [
      {
        id: "g_k1",
        localIp: "192.168.1.34",
        localPort: 52194,
        foreignIp: "91.242.229.15",
        foreignPort: 8080,
        state: "ESTABLISHED",
        process: "com.utility.calculator.pro (PID: 3901)",
        forensicTag: "Exfiltration of Credentials",
        severity: "high",
        riskReason: "Active connection to 91.242.229.15 (Russian IP associated with banking credential collection portals)."
      }
    ]
  }
];

// If executing in Node environments
if (typeof module !== 'undefined' && typeof module.exports !== 'undefined') {
  module.exports = ANDROID_FORENSIC_CASES;
}
