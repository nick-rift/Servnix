'use strict';

/**
 * ssl.js - echte SSL/TLS-Pruefung per openssl s_client. Liest das
 * tatsaechlich servierte Zertifikat und das ausgehandelte Protokoll aus,
 * statt eine Bewertung zu erfinden.
 */

const tls = require('tls');

function checkTlsConnection(host, port = 443) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host,
        port,
        servername: host,
        rejectUnauthorized: false,
        timeout: 8000,
      },
      () => {
        const cert = socket.getPeerCertificate();
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        const now = Date.now();
        const validTo = cert && cert.valid_to ? new Date(cert.valid_to).getTime() : null;
        const daysRemaining = validTo ? Math.round((validTo - now) / 86400000) : null;

        resolve({
          reachable: true,
          protocol,
          cipher: cipher ? cipher.name : null,
          issuer: cert && cert.issuer ? cert.issuer.O || cert.issuer.CN : null,
          subject: cert && cert.subject ? cert.subject.CN : null,
          validFrom: cert ? cert.valid_from : null,
          validTo: cert ? cert.valid_to : null,
          daysRemaining,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError,
        });
        socket.end();
      },
    );
    socket.on('error', (err) => {
      resolve({ reachable: false, error: err.message });
    });
    socket.on('timeout', () => {
      socket.destroy();
      resolve({ reachable: false, error: 'Timeout' });
    });
  });
}

/** Vergibt eine ehrliche Bewertung nach nachvollziehbaren Kriterien (keine erfundene "A+"-Note). */
function gradeTls(result) {
  if (!result.reachable) return { grade: 'N/A', reasons: ['Server nicht erreichbar auf diesem Port'] };

  const reasons = [];
  let score = 100;

  const weakProtocols = ['TLSv1', 'TLSv1.1', 'SSLv3'];
  if (weakProtocols.includes(result.protocol)) {
    score -= 40;
    reasons.push(`Veraltetes Protokoll aktiv: ${result.protocol}`);
  } else if (result.protocol === 'TLSv1.2') {
    score -= 5;
    reasons.push('TLSv1.2 aktiv, TLSv1.3 wird empfohlen');
  }

  if (result.daysRemaining !== null) {
    if (result.daysRemaining < 0) {
      score -= 60;
      reasons.push('Zertifikat ist abgelaufen');
    } else if (result.daysRemaining < 14) {
      score -= 20;
      reasons.push(`Zertifikat laeuft in ${result.daysRemaining} Tagen ab`);
    }
  }

  if (result.authorizationError && result.authorizationError !== 'DEPTH_ZERO_SELF_SIGNED_CERT') {
    score -= 15;
    reasons.push(`Zertifikatsproblem: ${result.authorizationError}`);
  }
  if (result.authorizationError === 'DEPTH_ZERO_SELF_SIGNED_CERT') {
    reasons.push('Selbstsigniertes Zertifikat (fuer produktive Domains eine CA wie Let\'s Encrypt nutzen)');
  }

  score = Math.max(0, Math.min(100, score));
  let grade = 'F';
  if (score >= 95) grade = 'A+';
  else if (score >= 85) grade = 'A';
  else if (score >= 70) grade = 'B';
  else if (score >= 50) grade = 'C';
  else if (score >= 30) grade = 'D';

  if (reasons.length === 0) reasons.push('Keine Auffaelligkeiten gefunden');
  return { grade, score, reasons };
}

async function scanSsl(host, port = 443) {
  const result = await checkTlsConnection(host, port);
  const grading = gradeTls(result);
  return { host, port, ...result, ...grading };
}

module.exports = { scanSsl, checkTlsConnection, gradeTls };
