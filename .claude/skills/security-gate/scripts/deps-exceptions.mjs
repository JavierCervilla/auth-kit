#!/usr/bin/env node
// T-229 · Excepciones de dependencias del security-gate, aplicadas a `npm audit`.
//
// La fuente única es `osv-scanner.toml` del proyecto (`[[IgnoredVulns]]`, el formato que osv-scanner ya lee):
//   id = "GHSA-…"   ignoreUntil = AAAA-MM-DD   reason = "…"
// Una excepción solo vale con `reason` y con `ignoreUntil` futuro. Las demás se devuelven como inválidas y el gate
// las cuenta como hallazgo: osv-scanner aceptaría para siempre una sin fecha, y eso es un agujero, no un ratchet.
//
// Uso: deps-exceptions.mjs <npm-audit.json|-> <dir-del-proyecto> [--today AAAA-MM-DD]   («-»: solo valida el TOML)
// Salida (stdout, JSON): { recognized, blocking: [aviso], excepted: [aviso+until+reason], invalid: [{id, problem}] }
// Aviso = { id, pkg, severity, title }. Solo cuenta high/critical, el umbral del peldaño.
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const BLOCKING = new Set(['high', 'critical']);

/**
 * `[[IgnoredVulns]]` del TOML de osv-scanner, por LISTA BLANCA: solo comentarios, líneas vacías, cabeceras
 * `[[IgnoredVulns]]` y `clave = "cadena"` / `'cadena'` / valor suelto dentro de una de ellas. Cualquier otra cosa (otra
 * tabla como `[[PackageOverrides]]`, una clave suelta, un array en línea, una cabecera entre comillas o en minúsculas,
 * una cadena multilínea) hace el fichero ILEGIBLE: `unreadable` lleva el motivo y el gate bloquea, porque osv-scanner
 * sí podría estar aplicando una excepción que aquí no se ha validado.
 */
export function parseIgnoredVulns(text) {
  const entries = [];
  let current = null;
  let unreadable = null;
  text.split('\n').forEach((raw, index) => {
    if (unreadable) return;
    if (raw.includes('"""') || raw.includes("'''")) {
      unreadable = `cadena multilínea en la línea ${index + 1}`;
      return;
    }
    const line = raw.trim();
    if (line === '' || line.startsWith('#')) return;
    if (line.startsWith('[')) {
      if (!/^\[\[\s*IgnoredVulns\s*\]\]\s*(#.*)?$/.test(line)) {
        unreadable = `tabla no soportada en la línea ${index + 1} (solo [[IgnoredVulns]])`;
        return;
      }
      current = {};
      entries.push(current);
      return;
    }
    if (!current) {
      unreadable = `clave fuera de [[IgnoredVulns]] en la línea ${index + 1}`;
      return;
    }
    const match = /^([A-Za-z_]\w*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s#]+))\s*(#.*)?$/.exec(line);
    if (!match) {
      unreadable = `línea ${index + 1} no es «clave = valor»`;
      return;
    }
    current[match[1]] = (match[2] ?? match[3] ?? match[4]).trim();
  });
  return { entries, unreadable };
}

/** Valida cada excepción; devuelve las vigentes por id y las inválidas con su motivo. */
export function validExceptions(entries, today) {
  const valid = new Map();
  const invalid = [];
  for (const entry of entries) {
    const id = entry.id ?? '(sin id)';
    if (!entry.id) invalid.push({ id, problem: 'sin id' });
    else if (!entry.reason) invalid.push({ id, problem: 'sin reason' });
    else if (!/^\d{4}-\d{2}-\d{2}/.test(entry.ignoreUntil ?? '')) invalid.push({ id, problem: 'sin ignoreUntil' });
    else if (entry.ignoreUntil.slice(0, 10) <= today) invalid.push({ id, problem: `caducada el ${entry.ignoreUntil.slice(0, 10)}` });
    else valid.set(entry.id, { until: entry.ignoreUntil.slice(0, 10), reason: entry.reason });
  }
  return { valid, invalid };
}

/** Avisos high/critical de `npm audit --json`, uno por id (GHSA del url, o el `source` numérico de npm). */
export function blockingAdvisories(audit) {
  const byId = new Map();
  for (const [pkg, vuln] of Object.entries(audit.vulnerabilities ?? {})) {
    for (const via of vuln.via ?? []) {
      if (typeof via !== 'object' || !BLOCKING.has(via.severity)) continue;
      const id = /GHSA-[\w-]+/.exec(via.url ?? '')?.[0] ?? `npm-${via.source}`;
      if (!byId.has(id)) byId.set(id, { id, pkg: via.name ?? pkg, severity: via.severity, title: via.title ?? '' });
    }
  }
  return [...byId.values()];
}

/**
 * `recognized` = avisos high/critical que el filtro ha sabido leer. Si es 0 y npm dice que hay alguno (otro formato,
 * p. ej. npm 6 con `advisories`), el gate cuenta todo: una excepción solo puede restar lo que ella misma nombra.
 */
export function classify(audit, tomlText, today) {
  const { entries, unreadable } = parseIgnoredVulns(tomlText);
  const { valid, invalid } = unreadable
    ? { valid: new Map(), invalid: [{ id: 'osv-scanner.toml', problem: `ilegible (${unreadable})` }] }
    : validExceptions(entries, today);
  const advisories = blockingAdvisories(audit);
  const blocking = [];
  const excepted = [];
  for (const advisory of advisories) {
    const exception = valid.get(advisory.id);
    if (exception) excepted.push({ ...advisory, ...exception });
    else blocking.push(advisory);
  }
  return { recognized: advisories.length, blocking, excepted, invalid };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const [auditPath, dir, flag, todayArg] = process.argv.slice(2);
  const today = flag === '--today' && todayArg ? todayArg : new Date().toISOString().slice(0, 10);
  const tomlPath = join(dir ?? '.', 'osv-scanner.toml');
  const tomlText = existsSync(tomlPath) ? readFileSync(tomlPath, 'utf8') : '';
  const audit = auditPath === '-' ? {} : JSON.parse(readFileSync(auditPath, 'utf8') || '{}');
  process.stdout.write(`${JSON.stringify(classify(audit, tomlText, today))}\n`);
}
