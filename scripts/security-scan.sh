#!/bin/bash
###############################################################################
# Servnix - Security Scan Wrapper
# Fuehrt den echten Node-basierten Security-Scan aus (server/cli-scan.js)
# und speichert das Ergebnis zusaetzlich als JSON in reports/ ab.
# Usage: ./scripts/security-scan.sh
###############################################################################

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

if ! command -v node &> /dev/null; then
    echo "❌ Node.js ist nicht installiert. Siehe: ./scripts/install-dependencies.sh"
    exit 1
fi

if [ ! -d node_modules ]; then
    echo "ℹ️  node_modules fehlt - installiere Abhaengigkeiten..."
    npm install
fi

mkdir -p reports
REPORT_FILE="reports/security-scan-$(date +%Y%m%d-%H%M%S).json"

node server/cli-scan.js

# Zusaetzlich als JSON archivieren, damit Trends nachvollziehbar bleiben.
node -e "
require('dotenv').config();
require('./server/lib/runScan').runFullScan().then(r => {
  require('fs').writeFileSync('$REPORT_FILE', JSON.stringify(r, null, 2));
  console.log('\n📄 Report gespeichert: $REPORT_FILE');
});
"
