#!/usr/bin/env node
// =============================================================================
// check-unicode-safety.mjs — gate anti-tag-smuggling Unicode (T-166, skill security-gate).
//
// Escanea la SUPERFICIE DE INSTRUCCIÓN DEL AGENTE (vault, skills, agents, hooks, CLAUDE.md,
// *.md de la raíz, workflows) en busca de codepoints Unicode invisibles o de "smuggling"
// (zero-width, bidi override, y sobre todo el bloque Tag U+E0000-U+E007F) que un modelo LEE
// pero un humano en el diff NO VE. Node puro: solo stdlib, cero deps npm, cero red.
//
// CRÍTICO (design 4): los rangos peligrosos se llevan como HEX (0xE0000...), NUNCA como
// caracteres literales -- si no, el propio scanner se bloquearía a sí mismo en CI. Por lo mismo,
// sus tests GENERAN las cadenas peligrosas en runtime (String.fromCodePoint) sobre un temporal.
//
// USO:
//   check-unicode-safety.mjs [--fix] [--exclude <glob-o-substring>]... [paths...]
//
//   (sin paths)  Escanea la superficie por defecto (ver DEFAULT_SOURCES).
//   --fix        Reescribe cada fichero ELIMINANDO solo los codepoints peligrosos (preserva el
//                resto byte a byte, UTF-8). Respeta [unicode-allow].
//   --exclude    Excluye rutas por substring o glob (doble-estrella, estrella, ?). Repetible.
//                Siempre se excluyen node_modules/, .git/ y assets/.
//
// ESCAPES:
//   - [unicode-allow: U+XXXX <motivo>]  en la MISMA línea -> permite ESE codepoint en ESA línea.
//   - [skip-unicode]  en el ASUNTO (primera línea) de un commit del rango -> salta el run entero
//                     (mismo criterio que [skip-adv]/[skip-traj]: en el cuerpo NO cuenta).
//
// REPORTE:  fichero:linea:col — U+XXXX (clase)
// EXIT:     0 limpio · 1 hallazgos · 2 error de uso
// =============================================================================

import { readFileSync, writeFileSync, readdirSync, statSync, existsSync } from "node:fs";
import { join, sep, extname } from "node:path";
import { execFileSync } from "node:child_process";

// --- Las 8 clases de codepoints peligrosos (design "Codepoints peligrosos" + Enmienda T-166-B) --
// Rangos como HEX. Cada clase es independiente: quitar una debe poner SU test en rojo (ojo mutante).
const CLASSES = [
  // zero-width incluye el soft hyphen U+00AD (A3): invisible salvo en salto de línea, parte-tokens.
  { name: "zero-width", match: (cp) => cp === 0xad || cp === 0x200b || cp === 0x200c || cp === 0x200d || cp === 0x2060 || cp === 0xfeff },
  { name: "bidi", match: (cp) => (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069) },
  { name: "tag", match: (cp) => cp >= 0xe0000 && cp <= 0xe007f },
  { name: "mongolian-vs", match: (cp) => cp === 0x180e },
  { name: "filler", match: (cp) => cp === 0x115f || cp === 0x1160 || cp === 0x3164 || cp === 0xffa0 },
  { name: "invisible-math", match: (cp) => cp >= 0x2061 && cp <= 0x2064 },
  { name: "interlinear", match: (cp) => cp >= 0xfff9 && cp <= 0xfffb },
  // variation selectors invisibles (A1+A2): VS1-VS15 (FE00-FE0E) y VS17-VS256 suplementarios
  // (E0100-E01EF). NO incluye U+FE0F (VS16 emoji, exento en isEmojiish, ubicuo y legítimo).
  { name: "variation-selector", match: (cp) => (cp >= 0xfe00 && cp <= 0xfe0e) || (cp >= 0xe0100 && cp <= 0xe01ef) },
];

// \t \n \r y espacios normales NO son peligrosos -- no aparecen en ninguna clase de arriba.
function classify(cp) {
  for (const c of CLASSES) if (c.match(cp)) return c.name;
  return null;
}

// Emoji-ish: rangos pictográficos + selector de variación + modificadores de tono. Se usa SOLO para
// la exención del ZERO WIDTH JOINER (U+200D): un ZWJ que une dos emoji es un emoji normal (design
// "no marques emojis normales"), p.ej. 👨‍🍳 o 👨‍👩‍👧. Fuera de ese caso, el ZWJ SÍ es peligroso.
function isEmojiish(cp) {
  if (cp === undefined) return false;
  return (
    (cp >= 0x1f000 && cp <= 0x1faff) || // planos de emoji (incl. modificadores de tono 1F3FB-1F3FF)
    (cp >= 0x2600 && cp <= 0x27bf) || // símbolos misceláneos + dingbats
    (cp >= 0x2b00 && cp <= 0x2bff) ||
    cp === 0xfe0f || // selector de variación emoji
    cp === 0x20e3 // combining enclosing keycap
  );
}

// Devuelve las posiciones peligrosas de una línea (col 1-based en codepoints), aplicando la exención
// del ZWJ de emoji. NO aplica [unicode-allow]: eso lo decide cada llamante (reportar vs. eliminar).
function dangerousInLine(line) {
  const cps = Array.from(line);
  const out = [];
  for (let i = 0; i < cps.length; i++) {
    const cp = cps[i].codePointAt(0);
    const cls = classify(cp);
    if (!cls) continue;
    if (cp === 0x200d) {
      const prev = i > 0 ? cps[i - 1].codePointAt(0) : undefined;
      const next = i < cps.length - 1 ? cps[i + 1].codePointAt(0) : undefined;
      if (isEmojiish(prev) && isEmojiish(next)) continue; // ZWJ de emoji -> legítimo
    }
    out.push({ col: i + 1, cp, cls });
  }
  return out;
}

// Directorios/segmentos siempre excluidos (design "Alcance del escaneo").
const ALWAYS_EXCLUDE = new Set(["node_modules", ".git", "assets"]);

// --- Politica de binarios (Enmienda T-166, design "evasion por encoding") -----------------------
// Extensiones LEGITIMAMENTE binarias: se saltan en SILENCIO (las fonts del repo no son un ataque),
// pero NO se cuentan como "escaneadas" -> se reportan aparte como aviso de cobertura.
// Los medios (audio y vídeo) entran en T-301: el vault guarda los de las trayectorias de vídeo, y con --strict un binario
// de extensión desconocida es hallazgo.
const BINARY_EXTS = new Set([
  ".woff2", ".ttf", ".otf", ".eot", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf",
  ".mp3", ".mp4", ".m4a", ".wav", ".webm", ".mov", ".ogg",
]);
// Formats the Read tool DECODES before the model sees them, so the bytes this scanner reads are not what the model gets.
// Under --strict (vault-push) they are a finding instead of being scanned or skipped (T-315, the human's decision
// «Rechazarlos»): a PDF's text layer can carry tag smuggling or invisible text, and a pure-ASCII notebook can carry Tag
// characters as JSON escapes that Read decodes (guardian R1, ADV-T315-1). These are the formats Read transforms besides
// images, which reach the model as images. By extension, as Read decides: renamed to .md, either is read as raw text,
// and the text-surface checks below already cover it.
const READ_DECODED_FORMATS = new Map([
  [".pdf", "pdf-text-layer"],
  [".ipynb", "notebook-decoded-by-read"],
]);
// Extensiones de TEXTO que el modelo lee como instruccion: un NUL / contenido binario aqui es
// ANOMALO y se marca como HALLAZGO (cierra el bypass por prefijo-NUL). Ademas, los ficheros SIN
// extension de .claude/hooks/ (scripts con shebang) tambien son superficie de texto.
const TEXT_EXTS = new Set([".md", ".mjs", ".js", ".yml", ".yaml", ".json", ".sh"]);

function isTextSurface(file) {
  const ext = extname(file).toLowerCase();
  if (ext !== "") return TEXT_EXTS.has(ext);
  // Sin extension: solo cuenta como texto si vive bajo .claude/hooks/.
  return file.split(sep).join("/").includes(".claude/hooks/");
}
function isBinaryExt(file) {
  return BINARY_EXTS.has(extname(file).toLowerCase());
}

// Superficie por defecto: la config del agente que el modelo lee. Relativa a cwd.
const DEFAULT_SOURCES = [
  { kind: "file", path: "CLAUDE.md" },
  { kind: "rootGlob", ext: ".md" }, // ficheros .md de la raíz
  { kind: "dir", path: "Contexto_Base_SRE", accept: (p) => p.endsWith(".md") },
  { kind: "shallowGlob", dir: ".claude", ext: ".md" }, // .claude/*.md de PRIMER nivel (no recursivo; skills/agents/hooks van aparte)
  { kind: "dir", path: ".claude/skills", accept: () => true },
  { kind: "dir", path: ".claude/agents", accept: () => true },
  { kind: "dir", path: ".claude/hooks", accept: () => true },
  { kind: "dir", path: ".claude/commands", accept: () => true }, // slash-commands que el modelo lee como instrucción (A4)
  { kind: "dir", path: ".github", accept: (p) => p.endsWith(".yml") || p.endsWith(".yaml") },
];

// --- Excludes: substring O glob simple (doble-estrella, estrella, ?) ----------------------------
// Construye el regex del glob en UNA pasada, sin sentinelas no-imprimibles (nada de \x00 embebido:
// el propio scanner es superficie de instruccion y debe quedar texto revisable y auto-escaneable).
// doble-estrella -> cualquier cosa; estrella -> cualquier cosa menos "/"; ? -> un char no-"/".
function globToRegExp(token) {
  const chars = Array.from(token);
  let re = "";
  for (let i = 0; i < chars.length; i++) {
    const ch = chars[i];
    if (ch === "*") {
      if (chars[i + 1] === "*") {
        re += ".*";
        i++; // consume la segunda estrella del par
      } else {
        re += "[^/]*";
      }
    } else if (ch === "?") {
      re += "[^/]";
    } else {
      re += ch.replace(/[.+^${}()|[\]\\]/g, "\\$&");
    }
  }
  return new RegExp(re);
}
function makeExcluder(tokens) {
  const globs = tokens.filter((t) => /[*?]/.test(t)).map(globToRegExp);
  const subs = tokens.filter((t) => !/[*?]/.test(t));
  return (relPath) => {
    const norm = relPath.split(sep).join("/");
    if (norm.split("/").some((seg) => ALWAYS_EXCLUDE.has(seg))) return true;
    if (subs.some((s) => norm.includes(s))) return true;
    if (globs.some((g) => g.test(norm))) return true;
    return false;
  };
}

// --- Recolección de ficheros ------------------------------------------------------------------
function walkDir(dir, accept, isExcluded, out) {
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    const full = join(dir, ent.name);
    if (isExcluded(full)) continue;
    if (ent.isDirectory()) {
      if (ALWAYS_EXCLUDE.has(ent.name)) continue;
      walkDir(full, accept, isExcluded, out);
    } else if (ent.isFile()) {
      if (accept(full)) out.add(full);
    }
  }
}

function collectDefault(isExcluded) {
  const out = new Set();
  for (const src of DEFAULT_SOURCES) {
    if (src.kind === "file") {
      if (existsSync(src.path) && !isExcluded(src.path)) out.add(src.path);
    } else if (src.kind === "rootGlob") {
      let entries = [];
      try {
        entries = readdirSync(".", { withFileTypes: true });
      } catch {
        entries = [];
      }
      for (const ent of entries) {
        if (ent.isFile() && ent.name.endsWith(src.ext) && !isExcluded(ent.name)) out.add(ent.name);
      }
    } else if (src.kind === "shallowGlob") {
      // Solo los ficheros directos de src.dir con la extensión (NO recursivo). Dir inexistente -> nada.
      let entries = [];
      try {
        entries = readdirSync(src.dir, { withFileTypes: true });
      } catch {
        entries = [];
      }
      for (const ent of entries) {
        if (!ent.isFile() || !ent.name.endsWith(src.ext)) continue;
        const rel = join(src.dir, ent.name);
        if (!isExcluded(rel)) out.add(rel);
      }
    } else if (src.kind === "dir") {
      if (existsSync(src.path)) walkDir(src.path, src.accept, isExcluded, out);
    }
  }
  return [...out];
}

function collectExplicit(paths, isExcluded) {
  const out = new Set();
  for (const p of paths) {
    let st;
    try {
      st = statSync(p);
    } catch {
      err(`path inexistente: ${p}`);
      process.exit(2);
    }
    // Con --strict, un fichero nombrado se escanea siempre: ALWAYS_EXCLUDE (assets/, node_modules/) y --exclude son
    // para recorrer carpetas, no para descartar en silencio lo que el llamante pide mirar (adversario de T-301, R6).
    if (st.isDirectory()) walkDir(p, () => true, isExcluded, out);
    else if (STRICT || !isExcluded(p)) out.add(p);
  }
  return [...out];
}

// --- Lectura de texto (salta binarios: NUL en el primer chunk) ---------------------------------
// La usa SOLO --fix: sobre binarios devuelve null y --fix no los toca. El ESCANEO no pasa por aqui:
// necesita distinguir "binario legitimo" de "NUL en superficie de texto" (ver scanFile).
function readText(file) {
  let buf;
  try {
    buf = readFileSync(file);
  } catch {
    return null;
  }
  const probe = buf.subarray(0, Math.min(buf.length, 8192));
  if (probe.includes(0)) return null; // binario
  return buf.toString("utf8");
}

// Posicion (linea:col, 1-based, en bytes) del primer NUL de un buffer -> reporte del hallazgo.
function nulPosition(buf) {
  const idx = buf.indexOf(0);
  let line = 1;
  let col = 1;
  for (let i = 0; i < idx; i++) {
    if (buf[i] === 0x0a) {
      line++;
      col = 1;
    } else {
      col++;
    }
  }
  return { line, col };
}

// --- Parse de [unicode-allow: U+XXXX ...] en una línea -> Set de codepoints permitidos ----------
// Con --strict no hay escapes: quien publica sin revisión humana (vault-push, T-301) no puede dejar que el propio
// contenido, o un commit del repo desde el que se lanza, decida que no se mire. Tampoco se descarta ni se salta nada
// de lo que se le nombra (ver collectExplicit y el bucle de main).
let STRICT = false;
function allowedOnLine(line) {
  const allowed = new Set();
  if (STRICT) return allowed;
  const re = /\[unicode-allow:\s*U\+([0-9A-Fa-f]{2,6})\b/g;
  let m;
  while ((m = re.exec(line)) !== null) allowed.add(parseInt(m[1], 16));
  return allowed;
}

// --- Escaneo de un fichero -> { findings, status } ---------------------------------------------
// status: "scanned" (se leyo como texto, cuenta como escaneado) · "skipped-binary" (extension
// legitimamente binaria, se salta en silencio, NO cuenta como escaneado) · "skipped-unknown"
// (binario de extension no reconocida: aviso de cobertura) · "error" (no se pudo leer).
// Un fichero de TEXTO (isTextSurface) con NUL/contenido binario NO se salta: es HALLAZGO (F2).
function scanFile(file) {
  const decodedBy = STRICT && READ_DECODED_FORMATS.get(extname(file).toLowerCase());
  if (decodedBy) return { findings: [{ file, line: 1, col: 1, cp: 0, cls: decodedBy }], status: "scanned" };
  let buf;
  try {
    buf = readFileSync(file);
  } catch {
    return { findings: [], status: "error" };
  }
  const probe = buf.subarray(0, Math.min(buf.length, 8192));
  if (probe.includes(0)) {
    // Contenido binario. En superficie de texto es anomalo -> hallazgo U+0000 (cierra el bypass).
    if (isTextSurface(file)) {
      const { line, col } = nulPosition(buf);
      return { findings: [{ file, line, col, cp: 0, cls: "nul-en-texto" }], status: "scanned" };
    }
    return { findings: [], status: isBinaryExt(file) ? "skipped-binary" : "skipped-unknown" };
  }
  // Con --strict, lo que no es UTF-8 no se puede comprobar, porque el escáner decodifica como UTF-8 (adversario de T-301,
  // R7). Un UTF-16LE con BOM y sin ASCII no tiene un solo NUL: aquí no veía nada y la herramienta Read, que decodifica
  // por el BOM, entregaba los Tag al modelo. Los binarios de extensión conocida (BINARY_EXTS) quedan fuera, como siempre.
  if (STRICT && !isBinaryExt(file)) {
    if ((buf[0] === 0xff && buf[1] === 0xfe) || (buf[0] === 0xfe && buf[1] === 0xff)) {
      return { findings: [{ file, line: 1, col: 1, cp: 0xfeff, cls: "codificacion-utf16" }], status: "scanned" };
    }
    try {
      new TextDecoder("utf-8", { fatal: true }).decode(buf);
    } catch {
      return { findings: [{ file, line: 1, col: 1, cp: 0, cls: "utf8-invalido" }], status: "scanned" };
    }
  }
  const text = buf.toString("utf8");
  const findings = [];
  const lines = text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const allowed = allowedOnLine(line);
    for (const d of dangerousInLine(line)) {
      if (!allowed.has(d.cp)) findings.push({ file, line: i + 1, col: d.col, cp: d.cp, cls: d.cls });
    }
  }
  return { findings, status: "scanned" };
}

// --- --fix: reescribe eliminando TODOS los peligrosos no permitidos (incluidos los tag-chars de una
// bandera de subdivisión: no hay excepción para el bloque Tag en ningún camino, ni classify ni --fix).
// NUNCA borra en silencio (A5): REPORTA cada codepoint que elimina (fichero:linea:col — U+XXXX
// eliminado) por stdout. Invariante: tras --fix, el mismo fichero pasa el escaneo (exit 0).
function fixFile(file) {
  const text = readText(file);
  if (text === null) return 0;
  let removed = 0;
  const lines = text.split("\n");
  const outLines = lines.map((line, lineIdx) => {
    const allowed = allowedOnLine(line);
    const cps = Array.from(line);
    // Índices (en codepoints) a eliminar: todos los peligrosos no permitidos por [unicode-allow].
    const drop = new Set(
      dangerousInLine(line)
        .filter((d) => !allowed.has(d.cp))
        .map((d) => d.col - 1)
    );
    if (drop.size === 0) return line;
    let out = "";
    for (let i = 0; i < cps.length; i++) {
      if (drop.has(i)) {
        const hex = cps[i].codePointAt(0).toString(16).toUpperCase().padStart(4, "0");
        process.stdout.write(`${file}:${lineIdx + 1}:${i + 1} — U+${hex} eliminado\n`);
        removed++;
        continue; // se elimina
      }
      out += cps[i];
    }
    return out;
  });
  if (removed > 0) writeFileSync(file, outLines.join("\n"));
  return removed;
}

// --- [skip-unicode] en el asunto de un commit del rango ----------------------------------------
function subjectsInRange() {
  const base = process.env.GITHUB_BASE_REF ? `origin/${process.env.GITHUB_BASE_REF}` : "origin/main";
  try {
    execFileSync("git", ["rev-parse", "--verify", "--quiet", base], { stdio: "ignore" });
    // %s = SOLO el asunto (primera línea), nunca el cuerpo (mismo criterio que [skip-adv]).
    return execFileSync("git", ["log", "--format=%s", `${base}...HEAD`], { encoding: "utf8" });
  } catch {
    // Sin base resoluble: conservador -- solo el asunto de HEAD (no saltamos por un cuerpo).
    try {
      return execFileSync("git", ["log", "-1", "--format=%s"], { encoding: "utf8" });
    } catch {
      return "";
    }
  }
}
function skipRequested() {
  return subjectsInRange()
    .split("\n")
    .some((s) => s.includes("[skip-unicode]"));
}

// --- CLI --------------------------------------------------------------------------------------
function err(msg) {
  process.stderr.write(`check-unicode-safety: ${msg}\n`);
}
function printUsage(stream) {
  stream.write(
    "uso: check-unicode-safety.mjs [--fix] [--strict] [--exclude <glob-o-substring>]... [paths...]\n" +
      "  sin paths escanea la superficie por defecto (vault, skills, agents, hooks, CLAUDE.md, *.md raiz, .github workflows)\n" +
      "  --fix     elimina solo los codepoints peligrosos (preserva el resto UTF-8)\n" +
      "  --exclude excluye por substring o glob (repetible); node_modules/.git/assets siempre excluidos\n" +
      "  escapes: [unicode-allow: U+XXXX motivo] (por linea) - [skip-unicode] en el asunto del commit (run entero)\n" +
      "  --strict  sin escapes: ignora [unicode-allow] y [skip-unicode]; escanea todo fichero nombrado (sin exclusiones)\n" +
      "            y cuenta como hallazgo lo que no puede leer, es binario de extension desconocida o no es UTF-8\n" +
      "  exit: 0 limpio - 1 hallazgos - 2 error de uso\n"
  );
}

function main(argv) {
  let fix = false;
  const excludes = [];
  const paths = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--fix") fix = true;
    else if (a === "--strict") STRICT = true;
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
      err(`opcion desconocida: ${a}`);
      printUsage(process.stderr);
      return 2;
    } else {
      paths.push(a);
    }
  }

  const isExcluded = makeExcluder(excludes);

  if (!STRICT && skipRequested()) {
    process.stdout.write("[skip-unicode] en el asunto de un commit del rango -> escaneo Unicode saltado a proposito.\n");
    return 0;
  }

  const files = paths.length > 0 ? collectExplicit(paths, isExcluded) : collectDefault(isExcluded);

  if (fix) {
    let total = 0;
    for (const f of files.sort()) {
      const n = fixFile(f);
      if (n > 0) {
        total += n;
        process.stdout.write(`fixed ${n} codepoint(s) peligroso(s) en ${f}\n`);
      }
    }
    process.stdout.write(total > 0 ? `--fix: eliminados ${total} codepoint(s) en total.\n` : "--fix: nada que limpiar.\n");
    return 0;
  }

  let findings = [];
  let scanned = 0;
  let skippedBinary = 0;
  let skippedUnknown = 0;
  for (const f of files.sort()) {
    const r = scanFile(f);
    if (r.status === "skipped-binary") {
      skippedBinary++;
      continue;
    }
    // Con --strict nada se salta en silencio: un binario de extensión desconocida (un .canvas con un NUL delante) o un
    // fichero ilegible no se puede comprobar, y eso es un hallazgo, no cobertura de menos.
    if (r.status === "skipped-unknown") {
      if (STRICT) findings.push({ file: f, line: 1, col: 1, cp: 0, cls: "binario-sin-escanear" });
      else skippedUnknown++;
      continue;
    }
    if (r.status === "error") {
      if (STRICT) findings.push({ file: f, line: 1, col: 1, cp: 0, cls: "ilegible" });
      continue;
    }
    scanned++;
    findings = findings.concat(r.findings);
  }

  // Aviso de cobertura HONESTA: los saltados por binario NO se cuentan como escaneados (Enmienda T-166).
  const skipped = skippedBinary + skippedUnknown;
  const coverage =
    skipped > 0
      ? ` (saltados ${skipped} por binario: ${skippedBinary} extension binaria legitima, ${skippedUnknown} desconocido/s)`
      : "";

  if (findings.length === 0) {
    process.stdout.write(`OK: sin codepoints peligrosos en ${scanned} fichero(s) escaneado(s)${coverage}.\n`);
    return 0;
  }

  for (const f of findings) {
    const hex = f.cp.toString(16).toUpperCase().padStart(4, "0");
    process.stdout.write(`${f.file}:${f.line}:${f.col} — U+${hex} (${f.cls})\n`);
  }
  process.stderr.write(
    `\nBLOQUEANTE: ${findings.length} codepoint(s) Unicode peligroso(s) en ${new Set(findings.map((x) => x.file)).size} fichero(s).\n` +
      "Corrige con: node .claude/skills/security-gate/scripts/check-unicode-safety.mjs --fix <fichero>\n" +
      "O, si el codepoint es legitimo (raro), anade en su linea: [unicode-allow: U+XXXX <motivo>]\n"
  );
  return 1;
}

process.exit(main(process.argv.slice(2)));
