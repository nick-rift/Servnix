<div align="center">

<img src="https://raw.githubusercontent.com/nick-rift/Servnix/main/assets/logo.svg" width="120" height="120" alt="Servnix Logo">

# ⚡ SERVNIX ⚡

### Self-hosted Linux server security dashboard — real firewall, real scans, real data

**Kein Kundenservice. Kein Support-Bullshit. Nur Code, der wirklich läuft.**

[![License](https://img.shields.io/badge/License-LGPL_2.1-blue?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](#-installation--setup)
[![Node.js](https://img.shields.io/badge/Node.js-18+-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)](#-installation--setup)
[![Stars](https://img.shields.io/github/stars/nick-rift/Servnix?style=for-the-badge&color=FFD700)](https://github.com/nick-rift/Servnix/stargazers)

[![TikTok](https://img.shields.io/badge/TikTok-@nick.rift-000000?style=for-the-badge&logo=tiktok&logoColor=white)](https://www.tiktok.com/@nick.rift)
[![Instagram](https://img.shields.io/badge/Instagram-@nick.rift-E4405F?style=for-the-badge&logo=instagram&logoColor=white)](https://www.instagram.com/nick.rift)

<img src="assets/dashboard.png" alt="Servnix Dashboard – Security-Score, Firewall-Status und Blockliste" width="100%">

</div>

---

## ⚡ In 30 Sekunden

```bash
git clone https://github.com/nick-rift/Servnix.git && cd Servnix
./scripts/install-dependencies.sh && cp .env.example .env
npm install && npm start
```

Dashboard läuft danach auf `http://127.0.0.1:3000` – **nur lokal**, Zugriff per SSH-Tunnel. Ausführlich: [Installation & Setup](#-installation--setup).

---

## 📖 Inhalt

| | |
|---|---|
| [🎯 Was ist Servnix wirklich?](#-was-ist-servnix-wirklich) | Der ehrliche Überblick |
| [⚡ Was tatsächlich funktioniert](#-was-tatsächlich-funktioniert) | Jeder Check und das Werkzeug dahinter |
| [🧱 Die Servnix-Firewall](#-die-servnix-firewall-eigenständig-ohne-opnsense) | nftables, Default-Deny, Rate-Limiting |
| [🛡️ Servnix Guard](#️-servnix-guard--automatische-angriffserkennung--ip-sperrung) | Automatische IP-Sperrung |
| [🌐 Website-Schutz](#-website-schutz-webserverwebanwendungen-härten) | Web-Scan und Angriffserkennung |
| [🔐 Dashboard-Härtung](#-dashboard-härtung-schutz-der-app-selbst) | Die App schützt sich selbst |
| [🔗 OPNsense-Anbindung](#-opnsense-anbindung-optional) | Optional, per REST-API |
| [🚀 Installation & Setup](#-installation--setup) | Schritt für Schritt |
| [📋 API-Endpunkte](#-api-endpunkte) | Vollständige Referenz |

---
