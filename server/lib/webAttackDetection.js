'use strict';

/**
 * webAttackDetection.js - regelbasierte Erkennung von Angriffsmustern gegen
 * Webserver/Webseiten (nginx/apache), analog zu intrusionDetection.js fuer
 * SSH/Portscan. Liest ECHTE Access-Logs aus - keine erfundene "KI-Erkennung".
 *
 * Erkannt werden Anfragen, die typisch fuer automatisierte Angriffs-Tools
 * und Schwachstellen-Scanner sind:
 *   - Exploit-Sondierung bekannter sensibler Pfade (.env, .git, wp-login.php,
 *     phpMyAdmin, Backup-Dateien, ...)
 *   - SQL-Injection-Muster in der Request-Zeile (UNION SELECT, ' OR '1'='1, ...)
 *   - Cross-Site-Scripting-Muster (<script>, javascript:, onerror=, ...)
 *   - Path-Traversal-Muster (../, ..%2f, /etc/passwd, ...)
 *   - bekannte Scanner-/Exploit-Tool User-Agents (sqlmap, nikto, nmap, ...)
 *
 * Jede IP, die innerhalb eines Zeitfensters mehrere solcher Treffer erzeugt,
 * wird als Bedrohung gemeldet. Gesperrt wird sie (wie bei SSH/Portscan) von
 * guard.js ueber blocklist.js - identischer Wirkmechanismus, nur eine andere
 * Datenquelle.
 */

const fs = require('fs');

function getEnvInt(name, fallback) {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

function getAllowlist() {
  return (process.env.GUARD_ALLOWLIST || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

// Bekannte Exploit-Sondierungspfade, die reale Angriffs-Tools routinemaessig abklappern.
const SUSPICIOUS_PATH_PATTERNS = [
  /\.env(?:$|[?#])/i,
  /\.git\/(config|HEAD)/i,
  /wp-login\.php/i,
  /wp-admin\/setup-config\.php/i,
  /phpmyadmin/i,
  /\.sql(?:\.gz)?(?:$|[?#])/i,
  /\.bak(?:$|[?#])/i,
  /\/\.ssh\//i,
  /id_rsa/i,
  /\/(?:etc\/passwd|proc\/self\/environ)/i,
  /xmlrpc\.php/i,
  /\/vendor\/phpunit/i,
  /\/\.aws\/credentials/i,
];

// SQL-Injection- und XSS-Muster in Query/Request - bewusst konservativ gehalten,
// um Fehlalarme bei normalen Nutzeranfragen gering zu halten.
const SQLI_PATTERNS = [
  /union(\s|%20)+select/i,
  /'\s*or\s*'?1'?\s*=\s*'?1/i,
  /;\s*drop\s+table/i,
  /sleep\(\d+\)/i,
  /information_schema/i,
];
const XSS_PATTERNS = [
  /<script[\s>]/i,
  /javascript:/i,
  /onerror\s*=/i,
  /onload\s*=/i,
];
const TRAVERSAL_PATTERNS = [
  /\.\.\/\.\.\//,
  /\.\.%2f/i,
  /%2e%2e%2f/i,
];

// Bekannte Scanner-/Exploit-Tool User-Agents.
const SCANNER_UA_PATTERNS = [
  /sqlmap/i,
  /nikto/i,
  /nmap/i,
  /acunetix/i,
  /nessus/i,
  /masscan/i,
  /dirbuster/i,
  /wpscan/i,
];

// Standard-"Combined Log Format" von nginx/apache:
// IP - - [zeit] "METHODE /pfad HTTP/1.1" status size "referer" "user-agent"
const COMBINED_LOG_LINE = /^(\S+) \S+ \S+ \[[^\]]+\] "(\S+) (\S+) [^"]*" (\d{3}) \S+ "[^"]*" "([^"]*)"/;

function classifyLine(line) {
  const m = line.match(COMBINED_LOG_LINE);
  if (!m) return null;
  const [, ip, , path, , userAgent] = m;

  const reasons = [];
  if (SUSPICIOUS_PATH_PATTERNS.some((p) => p.test(path))) reasons.push('Exploit-Sondierung sensibler Pfad');
  if (SQLI_PATTERNS.some((p) => p.test(path))) reasons.push('SQL-Injection-Muster');
  if (XSS_PATTERNS.some((p) => p.test(path))) reasons.push('XSS-Muster');
  if (TRAVERSAL_PATTERNS.some((p) => p.test(path))) reasons.push('Path-Traversal-Muster');
  if (SCANNER_UA_PATTERNS.some((p) => p.test(userAgent))) reasons.push('bekannter Scanner-User-Agent');

  if (reasons.length === 0) return null;
  return { ip, reasons };
}

/** Liest die letzten Zeilen einer (potenziell grossen) Logdatei effizient ein. */
function readTailLines(filePath, maxLines = 5000) {
  if (!filePath || !fs.existsSync(filePath)) return [];
  try {
    const stat = fs.statSync(filePath);
    const chunkSize = Math.min(stat.size, 2 * 1024 * 1024); // max. letzte 2MB lesen
    const buf = Buffer.alloc(chunkSize);
    const fd = fs.openSync(filePath, 'r');
    fs.readSync(fd, buf, 0, chunkSize, stat.size - chunkSize);
    fs.closeSync(fd);
    const lines = buf.toString('utf8').split('\n');
    return lines.slice(-maxLines);
  } catch {
    return [];
  }
}

/**
 * Liest die konfigurierten Access-Logs aus (mehrere, komma-getrennt moeglich,
 * z.B. nginx + apache parallel) und zaehlt Angriffsmuster-Treffer pro IP.
 */
function readRecentWebAttacks() {
  const logPaths = (process.env.WEBGUARD_ACCESS_LOGS || '/var/log/nginx/access.log,/var/log/apache2/access.log')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  const ipHits = {};
  const ipReasons = {};

  for (const logPath of logPaths) {
    for (const line of readTailLines(logPath)) {
      if (!line) continue;
      const hit = classifyLine(line);
      if (!hit) continue;
      ipHits[hit.ip] = (ipHits[hit.ip] || 0) + 1;
      ipReasons[hit.ip] = ipReasons[hit.ip] || new Set();
      hit.reasons.forEach((r) => ipReasons[hit.ip].add(r));
    }
  }

  return Object.fromEntries(
    Object.entries(ipHits).map(([ip, count]) => [ip, { count, reasons: Array.from(ipReasons[ip]) }]),
  );
}

/**
 * Fuehrt einen Erkennungsdurchlauf aus (Aufruf durch guard.js). Gibt Bedrohungen
 * zurueck, sperrt aber selbst nichts - Sperrung passiert wie bei den anderen
 * Guard-Modulen zentral in blocklist.js.
 */
function detectWebThreats() {
  const threshold = getEnvInt('WEBGUARD_MAX_HITS', 3);
  const allowlist = getAllowlist();
  const attacks = readRecentWebAttacks();

  const threats = [];
  for (const [ip, info] of Object.entries(attacks)) {
    if (allowlist.includes(ip)) continue;
    if (info.count >= threshold) {
      threats.push({
        ip,
        reason: `Web-Angriffsmuster: ${info.reasons.join(', ')} (${info.count}x)`,
        source: 'guard-web',
      });
    }
  }
  return threats;
}

module.exports = { detectWebThreats, readRecentWebAttacks, classifyLine };
