# <img src="https://raw.githubusercontent.com/nick-rift/Servnix/main/assets/logo.svg" width="40" height="40" alt="Servnix Logo"> Servnix - Enterprise Server Security & Auto-Updates

> 🛡️ Professionelles automatisiertes Server-Management mit kontinuierlichen Sicherheits-Updates, Firewall-Monitoring, Vulnerability-Scanning und vollständiger Security-Compliance.

**Kein Kundenservice. Kein Support-Bullshit. Nur pure Sicherheit und Automation.**

---

## 🎯 Was ist Servnix?

Servnix ist ein **Enterprise-Grade Automation-Framework**, das deinen Server:
- 🔄 **Kontinuierlich updatet** (Dependencies, Patches, Security-Fixes)
- 🔒 **Rundum überwacht** (Firewall, SSL/TLS, Ports, Vulnerabilities)
- 🚨 **Proaktiv schützt** (DDoS-Detection, Web-Attack-Prevention, Intrusion-Detection)
- 📊 **Transparent dokumentiert** (Reports, Audit-Logs, Security-Dashboards)
- 👥 **Community-Driven entwickelt** (Open-Source, alle können mitwirken)

---

## ⚡ Kernfeatures

### 🤖 Automatisierung
| Feature | Beschreibung | Frequenz |
|---------|-------------|----------|
| **Dependency Updates** | npm, pip, Docker, Cargo, Go Modules | Täglich |
| **Security Patches** | OS, Runtime, Libraries | Sofort bei Verfügbarkeit |
| **Auto-Testing** | Unit, Integration, Security Tests | Vor jedem Update |
| **Auto-Merge** | Sichere Updates automatisch mergen | Wenn Tests pass |
| **Changelog Generation** | Automatische Release Notes | Bei jedem Deploy |

### 🔒 Sicherheits-Scanning

#### Network & Infrastructure
- ✅ **Firewall Rules Check** - UFW/iptables Validierung
- ✅ **Open Ports Scan** - Unerwünschte Services detektieren
- ✅ **SSL/TLS Audit** - Zertifikat-Gültigkeit, Cipher-Stärke
- ✅ **DDoS Protection** - Rate-Limiting, Fail2Ban Status
- ✅ **IPv4/IPv6 Security** - Routing & Spoofing-Detection

#### Application & Dependencies
- ✅ **npm Audit** - Node.js Package Vulnerabilities
- ✅ **pip Audit** - Python Package Vulnerabilities
- ✅ **Docker Scan** - Container Image Security
- ✅ **Cargo Audit** - Rust Dependencies
- ✅ **SAST Analysis** - Code-Level Security Issues
- ✅ **SCA Scanning** - Supply Chain Security

#### Web & API Security
- ✅ **OWASP Top 10 Scan** - SQL Injection, XSS, CSRF, etc.
- ✅ **SSL/TLS Grade** - A+ Rating Standard
- ✅ **HTTP Security Headers** - CSP, X-Frame, HSTS
- ✅ **API Endpoint Security** - Rate-Limit, Auth-Check
- ✅ **Cookie Security** - Secure, HttpOnly, SameSite
- ✅ **CMS Vulnerability Scan** - WordPress, Drupal, etc.

#### System & OS Security
- ✅ **Kernel Vulnerability Scan** - CVE Database Matching
- ✅ **System Package Updates** - apt, yum, pacman, brew
- ✅ **User & Permission Audit** - Unauthorized Accounts
- ✅ **File Integrity Monitoring** - AIDE/Tripwire
- ✅ **Log Analysis** - Suspicious Activities
- ✅ **Compliance Check** - CIS Benchmarks, HIPAA, GDPR

#### Monitoring & Alerts
- ✅ **Real-time Alerts** - Instant Notification bei kritischen Issues
- ✅ **Automated Reports** - Tägliche/Wöchentliche Security Briefs
- ✅ **Metrics Dashboard** - Unified Monitoring Interface
- ✅ **Audit Trails** - Vollständige Change-Logs
- ✅ **Threat Intelligence** - External Threat Feeds

### 👥 Community & Collaboration
- 📋 **Issue Templates** - Bug Reports, Security Reports, Feature Requests
- 📝 **PR Templates** - Standardisierte Pull Requests
- 🤝 **Contributing Guidelines** - Klare Mitwirkungs-Regeln
- 📚 **Full Documentation** - API-Docs, Setup Guides, Best Practices
- 🔄 **Peer Review** - Alle Changes werden reviewed

### 📊 Reporting & Analytics
- 📈 **Daily Security Reports** - Automated Email/Slack
- 🎯 **Compliance Reports** - GDPR, HIPAA, PCI-DSS
- 📉 **Trend Analysis** - Vulnerability Evolution
- 🔍 **Detailed Audit Logs** - Wer, Was, Wann, Wo, Warum
- 📸 **Point-in-Time Snapshots** - State Versioning

---

## 🚀 Installation & Setup

### Schritt 1: Repository klonen
```bash
git clone https://github.com/nick-rift/Servnix.git
cd Servnix
chmod +x scripts/*.sh
```

### Schritt 2: Abhängigkeiten installieren
```bash
# Linux/macOS
./scripts/install-dependencies.sh

# Oder manuell:
npm install
pip install -r requirements.txt
```

### Schritt 3: System validieren
```bash
# Überprüft alle Voraussetzungen
./scripts/validate-system.sh
```

**Output sollte sein:**
```
✅ Node.js v18+ installed
✅ Python 3.9+ installed
✅ Docker installed and running
✅ Git configured
✅ GitHub CLI authenticated
✅ All system checks passed!
```

### Schritt 4: Umgebung konfigurieren
```bash
cp .env.example .env
nano .env
```

**Erforderliche Variablen:**
```env
# GitHub
GITHUB_TOKEN=ghp_xxxxxxxxxxxx
GITHUB_OWNER=nick-rift
GITHUB_REPO=Servnix

# Security
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
ALERT_EMAIL=admin@example.com

# Scanning
ENABLE_FIREWALL_SCAN=true
ENABLE_SSL_AUDIT=true
ENABLE_OWASP_SCAN=true
ENABLE_KERNEL_SCAN=true

# Update Behavior
AUTO_MERGE_MINOR=true
AUTO_MERGE_PATCH=true
AUTO_MERGE_MAJOR=false
```

### Schritt 5: GitHub Actions aktivieren
1. Gehe zu `Settings → Actions`
2. Aktiviere "Allow all actions and reusable workflows"
3. Gehe zu `Secrets and variables → Actions`
4. Füge hinzu:
   - `GITHUB_TOKEN`
   - `SLACK_WEBHOOK_URL`
   - `ALERT_EMAIL`

### Schritt 6: Erste Sicherheitsprüfung ausführen
```bash
./scripts/security-scan.sh
```

**Output Beispiel:**
```
🔍 Starting Security Audit...

[Network Security]
✅ Firewall: Enabled (UFW)
✅ Open Ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)
✅ SSL/TLS Grade: A+
✅ DDoS Protection: Enabled

[Application Security]
✅ npm audit: 0 vulnerabilities
✅ Docker scan: 0 HIGH, 2 MEDIUM
✅ SAST Analysis: 0 critical issues

[System Security]
✅ Kernel CVEs: 0 open
✅ File Integrity: OK
✅ Unauthorized Users: 0

[Compliance]
✅ CIS Benchmark: Level 2
✅ GDPR Compliance: 95%

📊 Overall Security Score: 9.2/10
```

---

## 📋 Automatisierte Workflows

### Daily Routine (2:00 AM UTC)
```
1. Dependency Audit
   → npm, pip, Docker, Cargo, Go
   → Vulnerability Scanning
   → Compatibility Check

2. Security Scan
   → Firewall Rules
   → Open Ports
   → SSL/TLS Certificates
   → DDoS Protection Status

3. Testing
   → Unit Tests
   → Integration Tests
   → Security Tests
   → Build Verification

4. Reporting
   → Generate Report
   → Send Slack/Email Alert
   → Update Dashboard
```

### Weekly Deep Scan (Every Monday, 3:00 AM UTC)
```
1. Full System Audit
   → OS Vulnerabilities
   → Kernel CVEs
   → System Packages
   → User Accounts

2. Web Security
   → OWASP Top 10
   → API Endpoints
   → HTTP Headers
   → Cookie Security

3. Compliance Check
   → GDPR Requirements
   → HIPAA Standards
   → PCI-DSS Rules
   → CIS Benchmarks

4. Report & Archive
   → Create detailed report
   → Archive findings
   → Generate trends
   → Update metrics
```

### On-Demand Scan
```bash
# Critical Security Scan (bei Verdacht)
./scripts/emergency-security-scan.sh

# Specific Vulnerability Scan
./scripts/scan-vulnerability.sh <CVE_ID>

# Firewall Audit
./scripts/audit-firewall.sh

# Full Compliance Check
./scripts/check-compliance.sh
```

---

## 📁 Projektstruktur

```
Servnix/
├── 📄 README.md                          # Diese Datei
├── 📄 LICENSE                            # LGPL 2.1
├── 📄 .env.example                       # Umgebungs-Template
├── 📄 package.json                       # Node Dependencies
├── 📄 requirements.txt                   # Python Dependencies
│
├── 🔧 .github/
│   ├── workflows/
│   │   ├── 01-daily-updates.yml          # Tägliche Dependency Updates
│   │   ├── 02-daily-security-scan.yml    # Tägliche Security Audits
│   │   ├── 03-weekly-full-audit.yml      # Wöchentliche Deep Scan
│   │   ├── 04-on-push-ci.yml             # CI bei jedem Push
│   │   └── 05-auto-merge.yml             # Automatisches Merging
│   │
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md                 # Bug Report Template
│   │   ├── feature_request.md            # Feature Request Template
│   │   ├── security_report.md            # Security Report Template
│   │   └── config.yml                    # Template Config
│   │
│   └── pull_request_template.md          # PR Template
│
├── 📚 scripts/
│   ├── install-dependencies.sh           # Dependency Installation
│   ├── validate-system.sh                # System Validation
│   ├── security-scan.sh                  # Umfassender Security Scan
│   ├── emergency-security-scan.sh        # Notfall-Scan
│   ├── scan-vulnerability.sh             # CVE-spezifischer Scan
│   ├── audit-firewall.sh                 # Firewall Audit
│   ├── check-compliance.sh               # Compliance Check
│   ├── update-dependencies.js            # Dependency Update Logic
│   ├── generate-report.js                # Report Generator
│   └── health-check.js                   # System Health Monitor
│
├── 📖 docs/
│   ├── INSTALLATION.md                   # Detaillierte Installationsanleitung
│   ├── CONTRIBUTING.md                   # Contribution Guidelines
│   ├── SECURITY.md                       # Security Policy
│   ├── API.md                            # API Documentation
│   ├── MAINTENANCE.md                    # Wartungs-Guide
│   ├── TROUBLESHOOTING.md               # Fehlersuche
│   ├── COMPLIANCE.md                     # Compliance Info
│   └── FAQ.md                            # Häufig gestellte Fragen
│
├── 🎨 assets/
│   ├── logo.svg                          # Servnix Logo
│   ├── logo-dark.svg                     # Dark Mode Logo
│   ├── icon.png                          # Favicon
│   └── banner.png                        # GitHub Banner
│
└── 📊 config/
    ├── security-rules.json               # Security Scan Config
    ├── firewall-rules.json               # Firewall Rules
    ├── compliance-standards.json         # Compliance Configs
    └── alert-settings.json               # Alert Configuration
```

---

## 🔐 Security Best Practices

### ✅ DO's
- ✅ Führe regelmäßig `./scripts/security-scan.sh` aus
- ✅ Überprüfe tägliche Security Reports
- ✅ Teste Updates auf Staging zuerst
- ✅ Archiviere alte Security Reports
- ✅ Halte Dokumentation aktuell
- ✅ Nutze 2FA für alle Accounts
- ✅ Rotiere API Keys regelmäßig

### ❌ DON'Ts
- ❌ Commitiere `.env` oder Secrets
- ❌ Ignoriere Security Alerts
- ❌ Nutze schwache Passwörter
- ❌ Deaktiviere automatische Updates
- ❌ Merke Credentials im Code
- ❌ Öffne unnötige Ports
- ❌ Nutze veraltete TLS Versionen

---

## 📊 Monitoring Dashboard

Nach der Installation erreichst du das Dashboard unter:
```
http://localhost:3000/dashboard
```

**Verfügbare Metriken:**
- Real-time Security Score
- Vulnerability Trends
- Update Status
- Firewall Activity
- SSL/TLS Status
- Compliance Scorecard
- Alert History
- Audit Trails

---

## 🎓 Dokumentation

Alle Details findest du in den **docs/** Dateien:

| Datei | Inhalt |
|-------|--------|
| [INSTALLATION.md](docs/INSTALLATION.md) | Step-by-Step Setup Guide |
| [CONTRIBUTING.md](docs/CONTRIBUTING.md) | Wie man mithelfen kann |
| [SECURITY.md](docs/SECURITY.md) | Security Policies & Disclosures |
| [API.md](docs/API.md) | API Dokumentation |
| [COMPLIANCE.md](docs/COMPLIANCE.md) | GDPR, HIPAA, PCI-DSS Info |
| [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) | Häufige Fehler & Lösungen |
| [FAQ.md](docs/FAQ.md) | Häufig gestellte Fragen |

---

## 🤝 Contributing

Contributions sind willkommen! Siehe [CONTRIBUTING.md](docs/CONTRIBUTING.md) für Details.

**Quick Contribute:**
```bash
1. Fork the repository
2. Create feature branch: git checkout -b feature/amazing-feature
3. Commit changes: git commit -m 'Add amazing feature'
4. Push to branch: git push origin feature/amazing-feature
5. Open a Pull Request
```

---

## 📜 Lizenz

Dieses Projekt ist unter der [LGPL 2.1 Lizenz](LICENSE) lizenziert.
Du darfst es nutzen, modifizieren und vertreiben - mit oder ohne Änderungen.

---

## 📈 Status & Metrics

| System | Status | Letzte Prüfung |
|--------|--------|---|
| **Dependencies** | ✅ Up-to-date | Täglich |
| **Security Scan** | ✅ Passed | Täglich |
| **Firewall** | ✅ Secure | Kontinuierlich |
| **SSL/TLS** | ✅ Grade A+ | Wöchentlich |
| **Compliance** | ✅ 95%+ | Wöchentlich |
| **System Health** | ✅ Optimal | Kontinuierlich |

---

## 📱 Follow Us

Folge uns auf den sozialen Medien für Updates & News:

- **TikTok**: [@nick.rift](https://www.tiktok.com/@nick.rift) 🎬
- **Instagram**: [@nick.rift](https://www.instagram.com/nick.rift) 📸

---

## 🚀 Getting Help

**Probleme?** Schau zuerst in die [Troubleshooting Guide](docs/TROUBLESHOOTING.md).

**Ideen?** Erstelle ein [GitHub Issue](https://github.com/nick-rift/Servnix/issues).

**Code-Beitrag?** Siehe [CONTRIBUTING.md](docs/CONTRIBUTING.md).

---

**Made with 🛡️ for Server Security & Automation**

*Kein Support. Keine Mitleid. Nur Sicherheit.*
