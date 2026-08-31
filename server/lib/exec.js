'use strict';

/**
 * exec.js - kleine Helper, um Shell-Kommandos sicher (ohne shell:true, ohne
 * String-Interpolation von Nutzereingaben) auszufuehren und das Ergebnis
 * einheitlich zurueckzugeben. Wird von allen Scannern benutzt.
 */

const { execFile } = require('child_process');

/**
 * Fuehrt ein Kommando aus und gibt niemals einen Fehler, sondern immer ein
 * Ergebnisobjekt zurueck - damit ein fehlendes Tool den Scan nicht abbrechen
 * laesst, sondern als "nicht verfuegbar" reported wird.
 */
function run(cmd, args = [], opts = {}) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout: opts.timeout || 15000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err && err.code === 'ENOENT') {
        resolve({ ok: false, available: false, error: `${cmd} ist nicht installiert`, stdout: '', stderr: '' });
        return;
      }
      resolve({
        ok: !err,
        available: true,
        code: err ? err.code : 0,
        stdout: (stdout || '').toString(),
        stderr: (stderr || '').toString(),
        error: err ? err.message : null,
      });
    });
  });
}

function commandExists(cmd) {
  return new Promise((resolve) => {
    execFile('which', [cmd], (err, stdout) => {
      resolve(!err && stdout.trim().length > 0);
    });
  });
}

module.exports = { run, commandExists };
