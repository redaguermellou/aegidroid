# AegisDroid: Plateforme Professionnelle d'Investigation Numérique pour Smartphones Android Compromis

**AegisDroid** est une suite d'investigation numérique et de réponse aux incidents (DFIR) dédiée à la détection, à l'analyse et à la documentation de cas de compromission sur les terminaux Android. Elle permet d'identifier de manière structurée les menaces et indicateurs d'attaque (IOCs) associés à des implants malveillants complexes (spywares, chevaux de Troie bancaires).

La plateforme intègre le cycle complet de l'investigation forensique mobile : **l'Acquisition d'artéfacts, l'Analyse des bases de données de stockage, la corrélation chronologique (Timeline) et la Production automatique de Rapports Certifiés**.

---

## 1. Capacités de la Suite (DFIR Capabilities)

- **Digital Forensics Mobile** : Gestion complète de la préservation de la preuve, de l'acquisition logique automatisée, de la vérification d'intégrité cryptographique (hachage SHA-256) et du suivi de la chaîne de custodie.
- **Analyse d'Artéfacts Android** : Cartographie des partitions de stockage flash (`/system`, `/data`) et exploration ciblée des tables des fournisseurs de données d'Android (journaux de messages, appels, contacts, historique d'applications et de navigation web).
- **Incident Response & Chasse aux Menaces (Threat Hunting)** : Détection proactive d'indicateurs de compromission (IOCs), identification d'abus d'autorisations critiques (API d'Accessibilité, overlays de fenêtres, super-utilisateur `su`), surveillance des sockets réseau établis et mappage au framework industriel **MITRE ATT&CK Mobile**.

---

## 2. Structure du Projet

```
aegisdroid/
├── index.html                 # Interface utilisateur et dashboard central (Glassmorphic Dark Theme)
├── styles.css                 # Charte graphique premium, terminal interactif et styles de rapports
├── app.js                     # Logique d'application, simulateur de requêtes SQL et parseur
├── cases.js                   # Études de cas intégrées (Spyware HydraSpy & Trojan Bancaire GoldDigger)
├── documentation.js           # Manuel théorique (Partitions, DBs clés, commandes ADB)
├── scripts/
│   ├── adb_acquire.ps1        # Script d'acquisition logique automatisée pour Windows (PowerShell)
│   └── adb_acquire.sh         # Script d'acquisition logique automatisée pour Linux/macOS (Bash)
└── README.md                  # Documentation technique du projet
```

---

## 3. Guide de Démarrage Rapide

La plateforme AegisDroid est entièrement conçue avec des technologies web standards (HTML5, Vanilla CSS3 et JavaScript ES6). Elle fonctionne de manière autonome en local.

### Option A : Lancement Instantané
Double-cliquez simplement sur le fichier `index.html` pour ouvrir la console dans votre navigateur web habituel.

### Option B : Serveur de Développement Local (Recommandé)
Pour une fluidité optimale et éviter les limitations CORS strictes des fichiers locaux (`file://`) lors du téléversement de bases SQLite personnalisées, lancez un serveur HTTP local.

**Avec Python :**
```bash
# Dans le dossier aegisdroid/
python -m http.server 8000
```
Puis, visitez `http://localhost:8000` dans votre navigateur.

**Avec Node.js (via npx) :**
```bash
npx http-server -p 8000
```

---

## 4. Scénarios de Compromission Intégrés

### Étude de cas 1 : "Operation HydraSpy" (Logiciel Espion Ciblé)
- **Vecteur d'Infection** : Hameçonnage par SMS (Smishing) usurpant l'identité d'un service de livraison (Chronopost) menant au téléchargement d'une application malveillante masqueradée sous le nom de *Core System Helper*.
- **Indicateurs à analyser** :
  - SMS d'activation réseau C2 (`PING:HYDRA_ACTIVATE...`).
  - Permissions abusives (enregistrement micro `RECORD_AUDIO`, traçage GPS `ACCESS_FINE_LOCATION`).
  - Sockets réseau actifs vers un serveur C2 hébergé derrière un nœud de sortie Tor (`185.220.101.4`).
  - Variables système suspectes (`ro.build.tags=test-keys` et `ro.secure=0` indiquant un système rooté).

### Étude de cas 2 : "GoldDigger Mobile" (Trojan Bancaire)
- **Vecteur d'Infection** : Outil utilitaire de calcul fiscal tiers (`calc.apk`).
- **Indicateurs à analyser** :
  - Interception silencieuse des SMS contenant des codes de double authentification (2FA) bancaires.
  - Abus de l'API d'Accessibilité Android (`BIND_ACCESSIBILITY_SERVICE`) pour journaliser les frappes de clavier (Keylogger).
  - Écrans d'injection HTML (Overlays) usurpant les applications officielles de banques françaises.
  - Tentatives d'interception d'appels téléphoniques sortants vers les centres de fraude bancaire (`3933`) afin de bloquer le signalement de la victime.

---

## 5. Guide d'Acquisition sur Téléphone Réel

La plateforme fournit deux outils d'acquisition réels dans le sous-dossier `scripts/`. Ces scripts automatisent la phase de collecte.

### Prérequis sur le Smartphone Cible :
1. Allez dans **Paramètres > À Propos du Téléphone** et tapotez 7 fois sur **Numéro de Version** pour activer les *Options de Développement*.
2. Ouvrez les **Options de Développement** et cochez **Débogage USB**.
3. Reliez le smartphone à votre ordinateur via un câble USB de transfert de données.
4. Sur l'écran du téléphone, autorisez le débogage USB depuis l'ordinateur connecté.

### Exécution du Script sous Windows (PowerShell) :
1. Ouvrez une invite PowerShell en tant qu'administrateur.
2. Autorisez l'exécution locale des scripts :
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
   ```
3. Naviguez vers le dossier `scripts/` et exécutez :
   ```powershell
   .\adb_acquire.ps1
   ```
Le script va créer un dossier d'extraction horodaté contenant les variables de configuration de l'appareil (`build.prop`), la table de processus (`processes.txt`), les sockets réseau (`network_sockets.txt`), la liste des applications (`packages.txt`) et, si le périphérique est rooté, effectuera une copie physique intègre de la base de messages (`mmssms.db`) et des contacts (`contacts2.db`), tout en calculant instantanément leurs signatures SHA-256.

---

## 6. Bonnes Pratiques en DFIR Mobile

Lors de la gestion d'un incident impliquant un appareil Android potentiellement compromis :
1. **Isolation Immédiate** : Activez le mode Avion et isolez le smartphone dans une cage de Faraday pour bloquer tout signal d'effacement à distance (Remote Wipe).
2. **Préservation de la preuve** : Ne modifiez jamais les fichiers originaux. Travaillez toujours sur des copies forensiques logiques ou physiques en validant leur intégrité via des empreintes numériques (SHA-256).
3. **Audit de l'API d'Accessibilité** : C'est le vecteur privilégié des chevaux de Troie modernes pour contourner les mécanismes de sécurité internes d'Android.
