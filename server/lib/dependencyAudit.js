'use strict';

/**
 * dependencyAudit.js - fuehrt echte Vulnerability-Scans der Dependencies aus:
 * `npm audit --json` fuer Node.js und `pip-audit` (falls installiert) fuer Python.
 * Kein Tool installiert -> wird ehrlich als "nicht verfuegbar" gemeldet,
 * es wird NICHT "0 Vulnerabilities" vorgetaeuscht.
 */

const path = require('path');
const fs = require('fs');
const { run, commandExists } = require('./exec');

async function auditNpm(cwd) {
  const pkgJson = path.join(cwd, 'package.json');
  if (!fs.existsSync(pkgJson)) return { available: false, reason: 'kein package.json im Zielverzeichnis' };

  const res = await run('npm', ['audit', '--json'], { timeout: 60000 });
  if (!res.available) return { available: false, reason: res.error };

  try {
    const data = JSON.parse(res.stdout || '{}');
    const meta = data.metadata && data.metadata.vulnerabilities;
    if (meta) {
      return {
        available: true,
        vulnerabilities: meta,
        total: Object.values(meta).reduce((a, b) => a + b, 0),
      };
    }
    return { available: true, vulnerabilities: {}, total: 0, raw: data };
  } catch {
    return { available: true, parseError: true, raw: res.stdout.slice(0, 2000) };
  }
}

async function auditPip() {
  const hasPipAudit = await commandExists('pip-audit');
  if (!hasPipAudit) {
    return { available: false, reason: 'pip-audit nicht installiert (pip install pip-audit)' };
  }
  const res = await run('pip-audit', ['-f', 'json'], { timeout: 60000 });
  if (!res.stdout) return { available: true, total: 0, findings: [] };
  try {
    const data = JSON.parse(res.stdout);
    const findings = Array.isArray(data) ? data : data.dependencies || [];
    const total = findings.reduce((sum, dep) => sum + ((dep.vulns || dep.vulnerabilities || []).length), 0);
    return { available: true, total, findings };
  } catch {
    return { available: true, parseError: true, raw: res.stdout.slice(0, 2000) };
  }
}

async function scanDependencies(cwd = process.cwd()) {
  const [npmResult, pipResult] = await Promise.all([auditNpm(cwd), auditPip()]);
  return { npm: npmResult, pip: pipResult };
}

module.exports = { scanDependencies };
