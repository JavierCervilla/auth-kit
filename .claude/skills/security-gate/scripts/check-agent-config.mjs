#!/usr/bin/env node
// =============================================================================
// check-agent-config.mjs — escáner determinista de la CONFIG DEL AGENTE (T-167, skill security-gate).
//
// Audita la superficie de configuración de `.claude/` (permisos, hooks, servidores MCP) como lo que
// es: superficie de ataque EJECUTABLE y de máxima confianza. Complementa a T-166
// (check-unicode-safety.mjs, que caza lo INVISIBLE): esto caza lo PELIGROSO a plena luz —
// bypassPermissions colado en un PR, una allow-list Bash(*), un hook que hace curl|bash, un MCP
// npx sin pinnear. Node puro: solo stdlib, cero deps npm, cero red. Veredicto reproducible offline.
//
// HAZARD self-referential (design §HAZARD, lección viva de T-166): este scanner y sus tests están
// FUERA de la superficie por defecto (exclusión por path). Las reglas llevan los patrones peligrosos
// como strings de detección; los tests GENERAN el material peligroso en runtime (nunca commiteado);
// la doc DESCRIBE, no reproduce. Invariante: el repo real pasa el scanner en verde.
//
// SEPARACIÓN POR CONFIANZA = eje del Aroma. Solo las clases de firma SINTÁCTICA (A permisos, B hooks,
// C MCP) son GATE DURO. La prompt-injection en prosa es borrosa → ADVISORY opt-in (--advisory), nunca
// bloquea salvo --strict. Reglas afiladas > catálogo ruidoso: un gate que grita en verde se ignora.
//
// USO:
//   check-agent-config.mjs [--advisory] [--strict] [--exclude <glob-o-substring>]... [paths...]
//
//   (sin paths)  Escanea la superficie por defecto (settings, hooks, mcp.json).
//   --advisory   Incluye el reporte de prompt-injection en prosa (agents/SKILL.md/commands).
//   --strict     Hace que los hallazgos advisory cuenten para el exit code (bloquean).
//   --exclude    Excluye rutas por substring o glob (doble-estrella, estrella, ?). Repetible.
//
// EXCEPCIONES:  .claude/security/config-scan-exceptions.json — match exacto (rule, path). Una
//   excepción CADUCADA o MALFORMADA se trata como INEXISTENTE → el hallazgo re-bloquea. Una viva y
//   bien formada degrada el hallazgo a nota `excepted` (no afecta al exit code).
//
// REPORTE:  fichero:línea — regla (clase)  detalle
// EXIT:     0 limpio · 1 hallazgo A/B/C no exceptuado (o advisory con --strict) · 2 error de uso
// =============================================================================

import { readFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, sep, basename, extname } from "node:path";

// --- Exclusiones de path (HAZARD capa 1 + ruido de terceros/binarios) --------------------------
// El propio scanner y sus tests FUERA de la superficie por defecto: audita config, no su código.
const ALWAYS_EXCLUDE_SEG = new Set(["node_modules", ".git", "assets"]);
const ALWAYS_EXCLUDE_SUB = [
  ".claude/skills/security-gate/scripts/",
  ".claude/skills/security-gate/tests/",
  // Tests de hooks: banco de pruebas, NO hooks ejecutables. Su helper assert() usa `eval "$2"` y algún
  // fixture escribe a .claude/settings.json → fuera de la superficie de Clase B, igual que los tests del
  // propio scanner (design §HAZARD; enmienda T-167-B).
  ".claude/hooks/tests/",
];

// --- Utilidades de reporte ---------------------------------------------------------------------
function mk(file, line, rule, cls, msg) {
  return { file: norm(file), line, rule, cls, msg };
}
function norm(p) {
  return p.split(sep).join("/").replace(/^\.\//, "");
}
// Línea (1-based) de la primera aparición de `needle` en el fuente crudo (para reportar hallazgos de
// JSON, donde JSON.parse no da posiciones). Sin coincidencia → línea 1.
function lineOf(raw, needle) {
  if (!needle) return 1;
  const idx = raw.indexOf(needle);
  if (idx < 0) return 1;
  return raw.slice(0, idx).split("\n").length;
}

// =============================================================================================
// CLASE A — Permisos peligrosos (settings.json / settings.local.json)
// Cada regla es una entrada independiente: quitarla pone SU test en rojo (ojo mutante).
// =============================================================================================
const CATCHALL_BASH = /^Bash\(\s*(\*|:\*|\*:\*)\s*\)$/; // Bash(*) / Bash(:*) / Bash(*:*) — NO Bash(curl:*)
const CATCHALL_MCP = /^mcp__\*(__|$)/; // mcp__* (servidor comodín) — NO mcp__server / mcp__server__tool

const RULES_A = [
  {
    id: "perm-bypass-mode",
    run(obj, raw, file) {
      const out = [];
      if (obj?.permissions?.defaultMode === "bypassPermissions")
        out.push(mk(file, lineOf(raw, "bypassPermissions"), "perm-bypass-mode", "A", "permissions.defaultMode = bypassPermissions"));
      if (obj?.dangerouslySkipPermissions === true)
        out.push(mk(file, lineOf(raw, "dangerouslySkipPermissions"), "perm-bypass-mode", "A", "dangerouslySkipPermissions: true (legacy)"));
      return out;
    },
  },
  {
    id: "perm-allow-catchall",
    run(obj, raw, file) {
      const allow = obj?.permissions?.allow;
      if (!Array.isArray(allow)) return [];
      const out = [];
      for (const entry of allow) {
        if (typeof entry === "string" && CATCHALL_BASH.test(entry.trim()))
          out.push(mk(file, lineOf(raw, entry), "perm-allow-catchall", "A", `allow ${entry} concede ejecución de comando arbitraria`));
      }
      return out;
    },
  },
  {
    id: "perm-mcp-catchall",
    run(obj, raw, file) {
      const allow = obj?.permissions?.allow;
      if (!Array.isArray(allow)) return [];
      const out = [];
      for (const entry of allow) {
        if (typeof entry === "string" && CATCHALL_MCP.test(entry.trim()))
          out.push(mk(file, lineOf(raw, entry), "perm-mcp-catchall", "A", `allow ${entry} confía en cualquier tool de cualquier MCP`));
      }
      return out;
    },
  },
];

// =============================================================================================
// CLASE C — MCP over-trust (.mcp.json, mcp.json de raíz, y bloque mcpServers de settings)
// =============================================================================================
function isNpx(cmd) {
  return typeof cmd === "string" && /(^|\/)npx$/.test(cmd.trim());
}
// Pinneado = algún arg lleva @<dígito> (@1.2.3). @latest/@next NO son pin (no fijan versión).
function npxPinned(args) {
  return Array.isArray(args) && args.some((a) => typeof a === "string" && /@\d/.test(a));
}
function dangerousMcpFlag(args) {
  if (!Array.isArray(args)) return null;
  for (const a of args) {
    if (typeof a !== "string") continue;
    // Boundary (fin-de-cadena o `=`), no ancla `$`: `--yolo`, `--yolo=true`, `--yolo=1` disparan;
    // `--yolonot` NO (enmienda T-167-C, forma `--flag=valor`). `--danger*` sigue siendo prefijo.
    if (/^--danger/i.test(a) || /^--yolo(=|$)/i.test(a) || /^--allow-all(=|$)/i.test(a) || /^--skip-[\w-]*check(=|$)/i.test(a)) return a;
  }
  return null;
}
// Plaintext REMOTO: http:// (no https) a un host que NO es loopback ni un nombre de una sola etiqueta
// (servicio interno tipo `opensre-mcp`). El riesgo (MITM del canal) es de tránsito por red no confiable
// = remoto; loopback/servicio-interno quedan fuera por diseño (la regla se llama *-remote).
function plaintextRemoteUrl(cfg) {
  const urls = [];
  if (typeof cfg?.url === "string") urls.push(cfg.url);
  for (const u of urls) {
    const m = u.match(/http:\/\/([^/\s"'}:]+)/i);
    if (!m) continue;
    const host = m[1].toLowerCase();
    if (host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "0.0.0.0") continue;
    if (!host.includes(".")) continue; // nombre de una etiqueta → servicio interno, no remoto
    return u;
  }
  return null;
}

function scanMcpServers(servers, raw, file) {
  if (!servers || typeof servers !== "object") return [];
  const out = [];
  for (const [name, cfg] of Object.entries(servers)) {
    if (!cfg || typeof cfg !== "object") continue;
    const at = lineOf(raw, `"${name}"`);
    if (isNpx(cfg.command) && !npxPinned(cfg.args))
      out.push(mk(file, at, "mcp-unpinned-npx", "C", `servidor ${name}: command npx sin versión fijada (dependency-confusion)`));
    const flag = dangerousMcpFlag(cfg.args);
    if (flag) out.push(mk(file, at, "mcp-dangerous-flag", "C", `servidor ${name}: arg ${flag} desarma las salvaguardas`));
    const url = plaintextRemoteUrl(cfg);
    if (url) out.push(mk(file, at, "mcp-plaintext-remote", "C", `servidor ${name}: transporte http:// en claro a host remoto`));
  }
  return out;
}

// =============================================================================================
// CLASE B — Command-injection / egress en hooks (.claude/hooks/**, contenido shell)
// Se analiza el shell REALMENTE ejecutado: los comentarios y la prosa dentro de echo/printf NO se
// ejecutan → no disparan (así el `echo "...curl | bash"` de session-start.sh no es un falso positivo).
// =============================================================================================
function isComment(line) {
  return /^\s*#/.test(line);
}
function isEchoLine(line) {
  return /^\s*(echo|printf)\b/.test(line);
}
// Elimina el CONTENIDO de las cadenas entrecomilladas (mantiene el resto): `echo "curl | bash"` →
// `echo `. Se usa SOLO para download-exec (un `curl|bash` real va sin comillas); NO para eval, donde
// la sustitución `$(...)` se ejecuta aunque esté entre comillas dobles.
function stripQuoted(line) {
  return line.replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/'(?:[^'\\]|\\.)*'/g, "''");
}

// Marcador sensible LITERAL, INDEPENDIENTE DEL ANCLA (~/$HOME/$root//home/...): la write-op dispara si
// su línea contiene el segmento/basename sensible, con o sin prefijo. Antes exigíamos `~`/`$HOME` delante,
// lo que dejaba pasar la grafía más natural del ataque (en el contenedor HOME=/root): `>> /root/.ssh/
// authorized_keys`, `cp … /root/.aws/credentials`, `tee -a /root/.bashrc`, `> /home/user/.ssh/...` —
// todos exit 0 (bypass reproducido por el verificador, enmienda T-167-B). `authorized_keys` sin prefijo
// también cubre la indirección por variable (`> $D/authorized_keys`) cuando el basename queda literal.
// GAP CONOCIDO Y ACEPTADO (límite de un escáner por-línea, no un descuido): un target ÍNTEGRAMENTE en
// variables sin ningún marcador literal en la misma línea (`F=$D/authorized_keys` en una línea, `> $F` en
// otra) queda fuera; requeriría dataflow multi-línea, fuera del alcance v1.
const SENSITIVE_WRITE_TARGET =
  /(authorized_keys|\/\.ssh\/|\/\.aws\/credentials|\/\.bashrc|\/\.zshrc|\/\.bash_profile|\/\.profile(?![A-Za-z0-9_])|\/\.claude\/settings)/;
const WRITE_OP = /(>>?|(\bcp\b|\bmv\b|\btee\b|\binstall\b))|writeFileSync|writeFile\b/;

// Intérpretes que ejecutan un payload descargado: no solo shells (enmienda T-167-C, gap A1). RCE por
// python/node/perl/ruby/php/pwsh es el MISMO ataque que `curl … | bash`. python3/nodejs antes que sus
// prefijos para que el `\b` case la variante con dígito/sufijo.
const INTERP = "bash|sh|zsh|dash|ksh|python3|python|nodejs|node|perl|ruby|php|pwsh";
const PIPE_TO_INTERP = new RegExp(`(curl|wget)\\b[^|]*\\|\\s*(sudo\\s+)?(${INTERP})\\b`);
const PROCSUB_INTERP = new RegExp(`\\b(${INTERP})\\b[^\\n]*<\\(\\s*(curl|wget)\\b`);
// `source <(curl …)` / `. <(curl …)` ejecutan el payload en el shell ACTUAL (gap A2): no son bash/sh/zsh.
const PROCSUB_SOURCE = /(^|[^\w])(source|\.)\s+<\(\s*(curl|wget)\b/;
// `$(curl …)` / backtick-curl usados como comando ejecutan la salida descargada (gap A3, incl.
// `bash -c "$(curl …)"`). Se mira la línea CRUDA: `$()` dentro de comillas dobles SÍ se ejecuta.
const CMDSUB_DOWNLOAD = /(\$\(|`)\s*(curl|wget)\b/;
// Fichero de pinta secreta subido por curl/wget (gap A6): clave SSH, credenciales, .env, .pem, .claude/…
const SECRET_UPLOAD_PATH = /(id_rsa|id_ed25519|\.ssh\/|\.aws\/credentials|\.env\b|\.pem\b|\.key\b|\/credentials\b|\.claude\/)/;

const RULES_B = [
  {
    id: "hook-download-exec",
    run(line) {
      if (isComment(line) || isEchoLine(line)) return null;
      const code = stripQuoted(line);
      // curl|wget canalizado a CUALQUIER intérprete, o process-substitution `bash|source|. <(curl …)`.
      if (PIPE_TO_INTERP.test(code)) return "descarga canalizada a intérprete (curl … | bash|python|node|…)";
      if (PROCSUB_INTERP.test(code) || PROCSUB_SOURCE.test(code)) return "process-substitution de descarga (bash|source|. <(curl …))";
      // Sustitución de comando con descarga: `$(curl …)`/backticks, incl. `bash -c "$(curl …)"`. Sobre la
      // línea CRUDA (el `$()` entre comillas dobles se ejecuta), no sobre `code`.
      if (CMDSUB_DOWNLOAD.test(line)) return "sustitución de comando con descarga ($(curl …) / `curl …` como comando)";
      // descarga-a-fichero y ejecución encadenada.
      if (/(curl|wget)\b[^\n]*&&[^\n]*(chmod\s+\+x|\.\/|\b(bash|sh)\s)/.test(code)) return "descarga y ejecución encadenada (curl … && ejecutar)";
      return null;
    },
  },
  {
    id: "hook-eval-dynamic",
    run(line) {
      if (isComment(line) || isEchoLine(line)) return null;
      // eval de contenido NO literal construido/inyectado en runtime: sustitución de comando `$(…)`,
      // backticks, o variable/posicional (`$VAR`, `${VAR}`, `$1`-`$9`, `$@`, `$*`). El design (§Clase B)
      // pedía «eval $VAR con contenido no literal»; la regex antigua solo cazaba `$(…)`/backticks
      // (enmienda T-167-B). El único `eval "$2"` legítimo del repo es el helper assert() de los tests de
      // hooks, excluido por path (.claude/hooks/tests/**). `eval "cmd literal"` NO dispara (correcto).
      if (/\beval\b[^\n]*(`|\$(\(|\{?[A-Za-z_]|[1-9@*]))/.test(line))
        return "eval de contenido no literal (sustitución de comando o variable/posicional en runtime)";
      return null;
    },
  },
  {
    id: "hook-secret-egress",
    run(line) {
      if (isComment(line) || isEchoLine(line)) return null;
      if (!/(curl|wget)\b/.test(line)) return null;
      if (!/https?:\/\//.test(line)) return null;
      if (/\$\{?[A-Za-z_]*(KEY|TOKEN)\b/.test(line) || /\$\{?CLAUDE/.test(line) || /transcript/i.test(line))
        return "posible egress de secreto/transcript a URL externa";
      // Exfil de un FICHERO de pinta secreta subido por el mismo curl→URL externa (gap A6): `--data @path`,
      // `-d @path`, `--data-binary @path`, `-T path`, `--upload-file path`. Solo dispara si el path parece
      // secreto (id_rsa, .ssh/, .aws/credentials, .env, .pem, .claude/…) — un `@archivo` cualquiera NO.
      const up = line.match(/(?:--data-binary|--data-raw|--data|-d)\s+@(\S+)/);
      if (up && SECRET_UPLOAD_PATH.test(up[1])) return "egress de fichero secreto a URL externa (--data @<path-secreto>)";
      const upf = line.match(/(?:--upload-file|-T)\s+(\S+)/);
      if (upf && SECRET_UPLOAD_PATH.test(upf[1])) return "egress de fichero secreto a URL externa (upload de <path-secreto>)";
      return null;
    },
  },
  {
    id: "hook-sensitive-write",
    run(line) {
      if (isComment(line)) return null;
      if (WRITE_OP.test(line) && SENSITIVE_WRITE_TARGET.test(line))
        return "escritura a fichero sensible del HOME (persistencia / config-poisoning)";
      return null;
    },
  },
];

// Una línea termina en continuación de shell si tiene un número IMPAR de `\` finales (una `\` real, no
// `\\` escapada). Fix general T-167-C (gap A5): el escáner es por-línea, así que `eval \`+`\n"$PAYLOAD"`
// evadía TODA la Clase B; pre-unir las continuaciones lo cierra para todas las reglas B a la vez.
function endsWithContinuation(s) {
  const m = s.match(/\\+$/);
  return m ? m[0].length % 2 === 1 : false;
}
// Colapsa las líneas continuadas por `\` en una sola línea lógica. Devuelve { text, line } con `line` =
// nº físico (1-based) de inicio del bloque, para reportar en la primera línea (granularidad por-línea).
function joinContinuations(lines) {
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const start = i;
    let buf = lines[i];
    while (endsWithContinuation(buf) && i + 1 < lines.length) {
      buf = buf.slice(0, -1) + " " + lines[i + 1];
      i++;
    }
    out.push({ text: buf, line: start + 1 });
  }
  return out;
}

function scanHook(file) {
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    return [];
  }
  const out = [];
  for (const { text: logical, line } of joinContinuations(text.split("\n"))) {
    for (const rule of RULES_B) {
      const detail = rule.run(logical);
      if (detail) out.push(mk(file, line, rule.id, "B", detail));
    }
  }
  return out;
}

// =============================================================================================
// ADVISORY — Prompt-injection en prosa (agents/**/*.md, skills/**/SKILL.md, commands/**)
// Set ESTRECHO de known-bad. No bloquea salvo --strict. Excluye los docs de seguridad (que DESCRIBEN
// estos ataques) para no enrojecer con su propia documentación.
// =============================================================================================
const PI_OVERRIDE = /\b(ignore|disregard|forget)\s+(all\s+|any\s+)?(previous|prior|above)\s+instructions?/i;
const PI_EXFIL = /\bsend\b[^\n]*\b(env|secret|token|api[\s_-]?key|credential)s?\b[^\n]*https?:\/\//i;

function isSecurityDoc(file) {
  const p = norm(file).toLowerCase();
  return p.includes("security") || p.includes("seguridad") || p.includes("threat") || p.includes("guardrail");
}
function scanAdvisory(file) {
  if (isSecurityDoc(file)) return [];
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    return [];
  }
  const out = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    if (PI_OVERRIDE.test(lines[i])) out.push({ ...mk(file, i + 1, "pi-override", "advisory", "instrucción de override de prompt"), sev: "advisory" });
    if (PI_EXFIL.test(lines[i])) out.push({ ...mk(file, i + 1, "pi-exfil", "advisory", "instrucción de exfiltración a URL externa"), sev: "advisory" });
  }
  return out;
}

// =============================================================================================
// COBERTURA HONESTA — un settings/mcp que NO parsea es un HALLAZGO, no un skip silencioso.
// =============================================================================================
function parseJsonOr(file, raw) {
  try {
    return { obj: JSON.parse(raw), finding: null };
  } catch (e) {
    return { obj: null, finding: mk(file, 1, "config-unparseable", "coverage", `JSON inválido: no se puede auditar (${e.message})`) };
  }
}

// --- Clasificación de un fichero → qué analizadores le aplican ---------------------------------
function isSettingsFile(file) {
  const b = basename(file);
  return b === "settings.json" || b === "settings.local.json";
}
function isMcpFile(file) {
  const b = basename(file);
  return b === ".mcp.json" || b === "mcp.json";
}
function isHookFile(file) {
  return norm(file).includes(".claude/hooks/");
}
function isAdvisoryFile(file) {
  const p = norm(file);
  if (p.includes(".claude/agents/") && p.endsWith(".md")) return true;
  if (p.includes(".claude/skills/") && basename(file) === "SKILL.md") return true;
  if (p.includes(".claude/commands/")) return true;
  return false;
}

function scanFile(file, opts) {
  const out = [];
  let raw = null;
  const readRaw = () => {
    if (raw === null) {
      try {
        raw = readFileSync(file, "utf8");
      } catch {
        raw = "";
      }
    }
    return raw;
  };

  if (isSettingsFile(file)) {
    const { obj, finding } = parseJsonOr(file, readRaw());
    if (finding) return { findings: [finding], scanned: true };
    for (const rule of RULES_A) out.push(...rule.run(obj, readRaw(), file));
    out.push(...scanMcpServers(obj?.mcpServers, readRaw(), file));
    return { findings: out, scanned: true };
  }
  if (isMcpFile(file)) {
    const { obj, finding } = parseJsonOr(file, readRaw());
    if (finding) return { findings: [finding], scanned: true };
    out.push(...scanMcpServers(obj?.mcpServers, readRaw(), file));
    return { findings: out, scanned: true };
  }
  if (isHookFile(file)) {
    return { findings: scanHook(file), scanned: true };
  }
  if (opts.advisory && isAdvisoryFile(file)) {
    return { findings: scanAdvisory(file), scanned: true };
  }
  return { findings: [], scanned: false }; // fuera de scope
}

// --- Recolección de la superficie por defecto --------------------------------------------------
function walk(dir, isExcluded, out) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    const full = join(dir, ent.name);
    if (ALWAYS_EXCLUDE_SEG.has(ent.name)) continue;
    if (isExcluded(full)) continue;
    if (ent.isDirectory()) walk(full, isExcluded, out);
    else if (ent.isFile()) out.add(norm(full));
  }
}
function collectDefault(isExcluded, opts) {
  const out = new Set();
  for (const f of [".claude/settings.json", ".claude/settings.local.json", ".mcp.json", "mcp.json"]) {
    if (existsSync(f) && !isExcluded(f)) out.add(norm(f));
  }
  if (existsSync(".claude/hooks")) walk(".claude/hooks", isExcluded, out);
  if (opts.advisory) {
    for (const d of [".claude/agents", ".claude/skills", ".claude/commands"]) {
      if (existsSync(d)) walk(d, isExcluded, out);
    }
  }
  return [...out].filter((f) => {
    // En modo advisory solo dejamos pasar a los ficheros que algún analizador toca.
    return isSettingsFile(f) || isMcpFile(f) || isHookFile(f) || (opts.advisory && isAdvisoryFile(f));
  });
}
function collectExplicit(paths, isExcluded) {
  const out = new Set();
  const outOfScope = [];
  for (const p of paths) {
    let st;
    try {
      st = statSync(p);
    } catch {
      err(`path inexistente: ${p}`);
      process.exit(2);
    }
    if (st.isDirectory()) walk(p, isExcluded, out);
    else if (!isExcluded(p)) out.add(norm(p));
  }
  return { files: [...out], outOfScope };
}

// --- Excludes (substring o glob simple) --------------------------------------------------------
function globToRegExp(token) {
  const chars = Array.from(token);
  let re = "";
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i];
    if (ch === "*") {
      if (chars[i + 1] === "*") {
        re += ".*";
        i++;
      } else re += "[^/]*";
    } else if (ch === "?") re += "[^/]";
    else re += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(re);
}
function makeExcluder(tokens) {
  const all = [...tokens];
  const globs = all.filter((t) => /[*?]/.test(t)).map(globToRegExp);
  const subs = all.filter((t) => !/[*?]/.test(t));
  return (p) => {
    const n = norm(p);
    if (n.split("/").some((seg) => ALWAYS_EXCLUDE_SEG.has(seg))) return true;
    if (ALWAYS_EXCLUDE_SUB.some((s) => n.includes(s))) return true;
    if (subs.some((s) => n.includes(s))) return true;
    if (globs.some((g) => g.test(n))) return true;
    return false;
  };
}

// --- Excepciones (el diferenciador): ciclo de vida con expiry ----------------------------------
const EXCEPTIONS_FILE = ".claude/security/config-scan-exceptions.json";
function todayUTC() {
  return new Date().toISOString().slice(0, 10);
}
function daysUntil(iso) {
  const [y, m, d] = iso.split("-").map(Number);
  const exp = Date.UTC(y, m - 1, d);
  const now = new Date();
  const today = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return Math.round((exp - today) / 86400000);
}
// "malformed" | "expired" | "ok". Malformada/caducada = inexistente (no aplica → el hallazgo se queda).
function validateException(e) {
  if (!e || typeof e !== "object") return { status: "malformed" };
  for (const k of ["rule", "path", "owner", "ticket", "reason", "expires"]) {
    if (typeof e[k] !== "string" || e[k].trim() === "") return { status: "malformed" };
  }
  if (!/^\d{4}-\d{2}-\d{2}$/.test(e.expires)) return { status: "malformed" };
  const dt = new Date(e.expires + "T00:00:00Z");
  if (Number.isNaN(dt.getTime())) return { status: "malformed" };
  const days = daysUntil(e.expires);
  if (days < 0) return { status: "expired", days };
  return { status: "ok", days };
}
function loadExceptions() {
  if (!existsSync(EXCEPTIONS_FILE)) return [];
  let obj;
  try {
    obj = JSON.parse(readFileSync(EXCEPTIONS_FILE, "utf8"));
  } catch {
    process.stderr.write(`AVISO: ${EXCEPTIONS_FILE} no es JSON válido → se ignora (fail-closed: nada se exceptúa).\n`);
    return [];
  }
  return Array.isArray(obj?.exceptions) ? obj.exceptions : [];
}
// Empareja un hallazgo con una excepción VIVA y bien formada (match exacto rule+path). Devuelve la
// excepción aplicable o null. Recoge en `warnings` las que caducan en <30 días (higiene).
function findException(finding, exceptions, warnings) {
  for (const e of exceptions) {
    const v = validateException(e);
    if (v.status !== "ok") continue; // malformada/caducada = inexistente
    if (e.rule === finding.rule && norm(e.path) === finding.file) {
      if (v.days < 30) warnings.push(`${e.rule} @ ${e.path} caduca en ${v.days} día(s) (${e.expires})`);
      return e;
    }
  }
  return null;
}

// --- CLI ---------------------------------------------------------------------------------------
function err(msg) {
  process.stderr.write(`check-agent-config: ${msg}\n`);
}
function printUsage(stream) {
  stream.write(
    "uso: check-agent-config.mjs [--advisory] [--strict] [--exclude <glob-o-substring>]... [paths...]\n" +
      "  sin paths escanea la superficie por defecto (.claude/settings*.json, .claude/hooks/**, .mcp.json)\n" +
      "  --advisory  incluye prompt-injection en prosa (agents/SKILL.md/commands), no bloqueante\n" +
      "  --strict    hace que los hallazgos advisory cuenten para el exit code\n" +
      "  --exclude   excluye por substring o glob (repetible); node_modules/.git/assets y el propio scanner siempre excluidos\n" +
      "  excepciones: .claude/security/config-scan-exceptions.json (match exacto rule+path; caducada/malformada re-bloquea)\n" +
      "  exit: 0 limpio · 1 hallazgo A/B/C (o advisory con --strict) · 2 error de uso\n"
  );
}

function main(argv) {
  const opts = { advisory: false, strict: false };
  const excludes = [];
  const paths = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--advisory") opts.advisory = true;
    else if (a === "--strict") opts.strict = true;
    else if (a === "--exclude") {
      const v = argv[++i];
      if (v === undefined) {
        err("--exclude requiere un valor");
        return 2;
      }
      excludes.push(v);
    } else if (a === "-h" || a === "--help") {
      printUsage(process.stdout);
      return 0;
    } else if (a.startsWith("-")) {
      err(`opción desconocida: ${a}`);
      printUsage(process.stderr);
      return 2;
    } else paths.push(a);
  }
  if (opts.strict) opts.advisory = true; // --strict implica correr el advisory

  const isExcluded = makeExcluder(excludes);
  let files;
  let outOfScope = [];
  if (paths.length > 0) {
    const r = collectExplicit(paths, isExcluded);
    files = r.files;
    outOfScope = r.files.filter((f) => scanFile(f, opts).scanned === false);
    files = r.files.filter((f) => !outOfScope.includes(f));
  } else {
    files = collectDefault(isExcluded, opts);
  }

  const exceptions = loadExceptions();
  const warnings = [];
  let gateFindings = [];
  let advisoryFindings = [];
  const excepted = [];
  let scanned = 0;

  for (const f of files.sort()) {
    const r = scanFile(f, opts);
    if (!r.scanned) continue;
    scanned++;
    for (const finding of r.findings) {
      const isAdvisory = finding.cls === "advisory";
      if (isAdvisory) {
        advisoryFindings.push(finding);
        continue;
      }
      const exc = findException(finding, exceptions, warnings);
      if (exc) excepted.push({ ...finding, expires: exc.expires });
      else gateFindings.push(finding);
    }
  }

  // --- Reporte -------------------------------------------------------------------------------
  for (const f of gateFindings) process.stdout.write(`${f.file}:${f.line} — ${f.rule} (${f.cls})  ${f.msg}\n`);
  for (const f of excepted) process.stdout.write(`${f.file}:${f.line} — ${f.rule} [excepted expires ${f.expires}]\n`);
  if (opts.advisory) for (const f of advisoryFindings) process.stdout.write(`${f.file}:${f.line} — ${f.rule} (advisory)  ${f.msg}\n`);
  for (const w of warnings) process.stderr.write(`AVISO higiene: ${w}\n`);
  if (outOfScope.length > 0) process.stderr.write(`Fuera de scope (no escaneados): ${outOfScope.join(", ")}\n`);

  const advisoryBlocks = opts.strict && advisoryFindings.length > 0;
  if (gateFindings.length === 0 && !advisoryBlocks) {
    const adv = opts.advisory ? `; ${advisoryFindings.length} advisory (no bloquea)` : "";
    const exc = excepted.length > 0 ? `; ${excepted.length} exceptuado(s)` : "";
    process.stdout.write(`OK: config del agente sin hallazgos bloqueantes en ${scanned} fichero(s)${exc}${adv}.\n`);
    return 0;
  }

  const nBlock = gateFindings.length + (advisoryBlocks ? advisoryFindings.length : 0);
  process.stderr.write(
    `\nBLOQUEANTE: ${nBlock} hallazgo(s) de config peligrosa` +
      (advisoryBlocks ? " (incluye advisory por --strict)" : "") +
      ".\nRevisa el permiso/hook/MCP, o añade una excepción trazada (owner+ticket+expires) en " +
      `${EXCEPTIONS_FILE}.\n`
  );
  return 1;
}

process.exit(main(process.argv.slice(2)));
