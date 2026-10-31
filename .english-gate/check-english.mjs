#!/usr/bin/env node
// =============================================================================
// check-english.mjs — the English gate (T-359, epic T-324).
//
// Doctrine: everything technical is written in English (code, identifiers, comments, tests, commit messages,
// PR titles and bodies, technical docs, config, prompts); only what a person reads is in Spanish (the UI,
// notifications, reports). This script finds Spanish where it does not belong.
//
// What it reads: comments (C-family `//` and `/* */`, `#`-family, Python docstrings), Markdown prose outside
// fenced blocks, and commit or PR messages. String literals are UI most of the time, so they are only read by the
// `--literals` warning pass. Identifiers are only read by the `--identifiers` warning pass.
//
// "Looks Spanish" (SENTINEL's rule, SENT-12): an accented letter, `ñ`, `¿` or `¡`, or at least two distinct Spanish
// function words. Quoted text between «», backticks or double quotes is removed first, so English text can cite
// the Spanish UI: `// The card says «Todo correcto» when nothing is broken`.
//
// One file, no dependencies: the installer copies it as-is into each repo (see ../scripts/install.sh).
//
// Usage: node check-english.mjs [mode...] [options]
//   (no mode)          every tracked file under the root
//   --added <base>     only lines added in `git diff <base>...HEAD`
//   --staged           only lines added in the index
//   --commits <base>   commit messages in <base>..HEAD
//   --text <file|->    a message (commit message, PR title or body); repeatable
//   --identifiers      warn about Spanish words in identifiers and file names (never fails)
//   --literals         warn about Spanish string literals outside interface files (never fails)
//   --summary          counts per directory instead of one line per finding
//   --warn             report, but exit 0
//   --local            warn or block as `local` says in the config (the commit-msg layer)
//   --pr-created <iso> warn only when the PR was opened before `blockingSince`
//   --root <dir>       repo root (default: the git top level of the cwd)
//   --config <file>    config file (default: <root>/.english-gate/config.json)
//   --self-test        run the built-in cases
// Exit: 0 clean (or warning only), 1 findings, 2 usage or config error.
// =============================================================================

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readdirSync, realpathSync, statSync } from "node:fs";
import { basename, extname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// ---------------------------------------------------------------- detection

// Spanish function words. Two distinct ones are needed. Words that also read as English in code are left out on
// purpose: no, es, si, un, todo (TODO), era, sea, van, han. `de`, `solo`, `son` and `uno` read as English too, but they
// are in: Sentinel's gate counted them, and they flag 0 more lines on 142,466 lines of English comments (SENT-24).
export const FUNCTION_WORDS = new Set(
  ("que los las el la del de se para una uno unos unas por pero como esta este esto estos estas eso ese esa esos esas " +
    "cuando cada hay porque desde donde sin con sobre entre hasta ya aqui asi muy mas toda todos todas nada otro " +
    "otra otros otras ser estar hace hacer puede pueden debe deben tiene tienen lo al su sus nos cual cuales quien " +
    "aunque mientras luego antes ahora siempre nunca tambien pues segun tras hacia ademas mismo misma vez fue solo son").split(/\s+/),
);
const ACCENT = /[áéíóúüñÁÉÍÓÚÜÑ¿¡]/u;
const WORD_EDGE = "[\\p{L}\\p{N}_]";

function escapeRe(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// Removes what is quoted (cited UI text, code, paths) and the configured proper nouns.
export function stripQuoted(text, properNouns = []) {
  let s = String(text).normalize("NFC");
  s = s.replace(/«[^»]*»/g, " ").replace(/`[^`]*`/g, " ").replace(/"[^"\n]*"/g, " ").replace(/“[^”]*”/g, " ");
  // URLs go after the quotes: `\S+` would swallow a closing quote, and the prose up to the next quote would go with it.
  s = s.replace(/https?:\/\/\S+/g, " ");
  // Author and copyright lines carry people's names, which may be accented. After URLs, so a URL that says copyright
  // (a COPYRIGHT file) does not cut the rest of the line.
  s = s.replace(/(@author\b|\bcopyright\b|©).*$/gim, " ");
  for (const noun of properNouns) {
    s = s.replace(new RegExp(`(?<!${WORD_EDGE})${escapeRe(noun.normalize("NFC"))}(?!${WORD_EDGE})`, "giu"), " ");
  }
  return s;
}

export function looksSpanish(text, opts = {}) {
  const s = stripQuoted(text, opts.properNouns);
  if (ACCENT.test(s)) return true;
  const hits = new Set();
  for (const token of s.split(/[^\p{L}\p{N}_]+/u)) {
    // A token with a digit or an underscore is an identifier (es2022, que_los), not a word.
    if (!token || /[\p{N}_]/u.test(token)) continue;
    const word = token.toLowerCase();
    if (FUNCTION_WORDS.has(word)) hits.add(word);
  }
  return hits.size >= 2;
}

// ---------------------------------------------------------------- file kinds

const C_FAMILY = new Set(
  ".js .mjs .cjs .jsx .ts .mts .cts .tsx .go .rs .java .kt .kts .swift .c .h .cc .cpp .hpp .cs .dart .scala .groovy .gradle .css .scss .less".split(" "),
);
const HASH_FAMILY = new Set(".yml .yaml .toml .ini .cfg .conf .rb .pl .r .tf .properties".split(" "));
const HASH_NAMES = new Set(["Dockerfile", "Makefile", "makefile", "GNUmakefile", "Procfile", "Gemfile", "Rakefile"]);

// Decides how a file is read from its name, and from its shebang when it has no extension.
export function kindOf(path, head = "") {
  const ext = extname(path).toLowerCase();
  const name = basename(path);
  if (C_FAMILY.has(ext)) return "c";
  if ([".sh", ".bash", ".zsh"].includes(ext)) return "shell";
  if (ext === ".py") return "python";
  if (ext === ".md" || ext === ".mdx") return "markdown";
  if (HASH_FAMILY.has(ext) || HASH_NAMES.has(name) || name.startsWith("Dockerfile") || ext === ".dockerfile") return "hash";
  if (/^\.[\w-]*ignore$/.test(name) || name === ".gitattributes" || name === ".editorconfig" || /^\.env\./.test(name)) return "hash";
  if (!ext && head.startsWith("#!")) {
    if (/\b(ba|z|da)?sh\b/.test(head.split("\n")[0])) return "shell";
    if (/python/.test(head.split("\n")[0])) return "python";
    if (/\bnode\b/.test(head.split("\n")[0])) return "c";
  }
  return null;
}

// ---------------------------------------------------------------- lexers
// Every lexer returns segments { type, line, text } with type comment | string | code | prose. Multi-line
// comments and strings come back one segment per line, so a finding points at its own line.

function pushLines(out, type, startLine, text) {
  text.split("\n").forEach((t, k) => {
    if (t.trim()) out.push({ type, line: startLine + k, text: t });
  });
}
const newlines = (s) => (s.match(/\n/g) || []).length;

const REGEX_AFTER = new Set(["", "(", ",", "=", ":", "[", "!", "&", "|", "?", "{", "}", ";", "+", "-", "*", "%", "<", ">", "~", "^"]);
const REGEX_KEYWORDS = new Set(["return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw", "yield", "await", "instanceof"]);

// C-family: strings, template literals (with nested `${}`), regex literals decided by the previous token, comments.
// A '...' or "..." string never runs past its line, so a Rust lifetime or a stray quote cannot swallow the file.
function lexC(src) {
  const out = [];
  const n = src.length;
  let i = 0;
  let line = 1;
  let prev = "";
  let depth = 0;
  const templates = [];
  let code = "";
  const flushCode = () => {
    if (code.trim()) out.push({ type: "code", line, text: code });
    code = "";
  };
  const advance = (text) => {
    if (newlines(text)) flushCode();
    line += newlines(text);
  };
  const readTemplate = () => {
    const start = i;
    while (i < n) {
      if (src[i] === "\\") {
        i += 2;
        continue;
      }
      if (src[i] === "`" || (src[i] === "$" && src[i + 1] === "{")) break;
      i++;
    }
    const chunk = src.slice(start, i);
    pushLines(out, "string", line, chunk);
    advance(chunk);
    if (src[i] === "`") {
      i++;
      prev = "id";
    } else if (i < n) {
      i += 2;
      templates.push(depth);
      depth++;
      prev = "{";
    }
  };
  const readRegex = () => {
    let j = i + 1;
    let inClass = false;
    while (j < n && src[j] !== "\n") {
      const c = src[j];
      if (c === "\\") {
        j += 2;
        continue;
      }
      if (c === "[") inClass = true;
      else if (c === "]") inClass = false;
      else if (c === "/" && !inClass) {
        j++;
        while (j < n && /[a-z]/i.test(src[j])) j++;
        return j;
      }
      j++;
    }
    return -1;
  };

  while (i < n) {
    const ch = src[i];
    const next = src[i + 1];
    if (ch === "\n") {
      flushCode();
      line++;
      i++;
    } else if (ch === "/" && next === "/") {
      const end = src.indexOf("\n", i);
      const stop = end === -1 ? n : end;
      out.push({ type: "comment", line, text: src.slice(i + 2, stop) });
      i = stop;
    } else if (ch === "/" && next === "*") {
      const end = src.indexOf("*/", i + 2);
      const stop = end === -1 ? n : end + 2;
      pushLines(out, "comment", line, src.slice(i + 2, end === -1 ? n : end));
      advance(src.slice(i, stop));
      i = stop;
    } else if (ch === '"' || ch === "'") {
      let j = i + 1;
      while (j < n && src[j] !== ch && src[j] !== "\n") j += src[j] === "\\" && src[j + 1] !== "\n" ? 2 : 1;
      out.push({ type: "string", line, text: src.slice(i + 1, j) });
      i = src[j] === ch ? j + 1 : j;
      prev = "id";
    } else if (ch === "`") {
      i++;
      readTemplate();
    } else if (ch === "/" && REGEX_AFTER.has(prev) && readRegex() !== -1) {
      i = readRegex();
      prev = "id";
    } else if (ch === "}" && templates.length && depth - 1 === templates[templates.length - 1]) {
      depth--;
      templates.pop();
      i++;
      readTemplate();
    } else if (/[\p{L}_$]/u.test(ch)) {
      let j = i;
      while (j < n && /[\p{L}\p{N}_$]/u.test(src[j])) j++;
      const word = src.slice(i, j);
      code += word;
      prev = REGEX_KEYWORDS.has(word) ? "(" : "id";
      i = j;
    } else if (/\s/.test(ch)) {
      code += ch;
      i++;
    } else {
      if (ch === "{") depth++;
      if (ch === "}") depth--;
      code += ch;
      prev = /[0-9.)\]]/.test(ch) ? "id" : ch;
      i++;
    }
  }
  flushCode();
  return out;
}

const HEREDOC = /(?<!<)<<(-?)\s*(['"]?)([A-Za-z_][A-Za-z0-9_]*)\2(?![\w])/;

// `#`-family. Shell quotes can span lines and heredoc bodies are literals; elsewhere a quote only opens a string at
// the start of a value (so an apostrophe in a YAML plain scalar does not hide the comment after it). Python
// triple-quoted strings are docstrings and read like comments.
function lexHash(src, { shell = false, python = false } = {}) {
  const out = [];
  const rows = src.split("\n");
  let quote = null;
  let triple = null;
  let heredoc = null;
  rows.forEach((row, k) => {
    const lineNo = k + 1;
    if (heredoc) {
      if ((heredoc.strip ? row.replace(/^\t+/, "") : row) === heredoc.tag) heredoc = null;
      else if (row.trim()) out.push({ type: "string", line: lineNo, text: row });
      return;
    }
    if (k === 0 && row.startsWith("#!")) return;
    let code = "";
    let tagged = "";
    let buf = "";
    let j = 0;
    while (j < row.length) {
      const c = row[j];
      if (triple) {
        const end = row.indexOf(triple, j);
        buf += row.slice(j, end === -1 ? row.length : end);
        j = end === -1 ? row.length : end + 3;
        if (end !== -1) {
          if (buf.trim()) out.push({ type: "comment", line: lineNo, text: buf });
          buf = "";
          triple = null;
        }
        continue;
      }
      if (quote) {
        if (c === "\\" && quote === '"') {
          buf += row.slice(j, j + 2);
          j += 2;
          continue;
        }
        if (c === quote) {
          out.push({ type: "string", line: lineNo, text: buf });
          tagged += /^\w+$/.test(buf) ? `'${buf}'` : "''";
          buf = "";
          quote = null;
        } else buf += c;
        j++;
        continue;
      }
      if (python && (row.startsWith('"""', j) || row.startsWith("'''", j))) {
        triple = row.slice(j, j + 3);
        j += 3;
        continue;
      }
      const opensString = shell || python || j === 0 || /[\s:=[,(]/.test(row[j - 1]);
      if ((c === '"' || c === "'") && opensString) {
        quote = c;
        j++;
        continue;
      }
      if (c === "#" && (j === 0 || /\s/.test(row[j - 1]))) {
        out.push({ type: "comment", line: lineNo, text: row.slice(j + 1) });
        break;
      }
      code += c;
      tagged += c;
      j++;
    }
    if (buf.trim()) out.push({ type: triple ? "comment" : "string", line: lineNo, text: buf });
    if (!shell && !python) quote = null;
    if (code.trim()) out.push({ type: "code", line: lineNo, text: code });
    const m = shell && !quote ? HEREDOC.exec(tagged) : null;
    if (m) heredoc = { tag: m[3], strip: m[1] === "-" };
  });
  return out;
}

// Markdown: every line outside fenced code blocks. A fence closes with the same character, at least as long.
function lexMarkdown(src) {
  const out = [];
  let fence = null;
  src.split("\n").forEach((row, k) => {
    const m = /^ {0,3}(`{3,}|~{3,})/.exec(row);
    if (fence) {
      if (m && m[1][0] === fence[0] && m[1].length >= fence.length && !row.slice(m[0].length).trim()) fence = null;
      return;
    }
    if (m) {
      fence = m[1];
      return;
    }
    if (row.trim()) out.push({ type: "prose", line: k + 1, text: row });
  });
  return out;
}

export function extractText(src, kind) {
  if (kind === "c") return lexC(src);
  if (kind === "shell") return lexHash(src, { shell: true });
  if (kind === "python") return lexHash(src, { python: true });
  if (kind === "hash") return lexHash(src);
  if (kind === "markdown") return lexMarkdown(src);
  return [];
}

// A message (commit, PR title or body): Markdown rules, minus git trailers whose names are not prose
// (Co-Authored-By:, Claude-Session:, Signed-off-by:). As in git, trailers only live in the last paragraph and the
// subject is never one, so a one-line `fix: ...` is read. Only known trailer keys are dropped: a last paragraph such as
// `Nota: ...` is prose.
const TRAILER_KEYS = new Set(["claude-session", "change-id", "cc", "fixes", "closes", "resolves", "refs", "see-also", "link", "bug", "plan", "story"]);

function isTrailer(row) {
  const m = /^([A-Za-z][A-Za-z0-9-]*):\s/.exec(row);
  return Boolean(m) && (/-by$/i.test(m[1]) || TRAILER_KEYS.has(m[1].toLowerCase()));
}

export function messageLines(text) {
  const rows = String(text).replace(/\s+$/, "").split("\n");
  let lastBlank = -1;
  for (let k = rows.length - 1; k >= 0; k--) {
    if (!rows[k].trim()) {
      lastBlank = k;
      break;
    }
  }
  const hasBody = rows.slice(0, Math.max(lastBlank, 0)).some((r) => r.trim());
  const kept = rows.map((row, k) => (hasBody && k > lastBlank && isTrailer(row) ? "" : row));
  return lexMarkdown(kept.join("\n"));
}

// ---------------------------------------------------------------- config

const DEFAULT_EXCLUDE = ["**/node_modules/**", "**/.git/**", "**/dist/**", "**/build/**", "**/.next/**", "**/coverage/**", "**/vendor/**", ".english-gate/**", "**/*.min.js"];
const CONFIG_KEYS = { exclude: "list", interface: "list", vendored: "list", properNouns: "list", blockingSince: "date", local: "mode" };

export class ConfigError extends Error {}

export function loadConfig(file) {
  const config = { exclude: [], interface: [], vendored: [], properNouns: [], blockingSince: null, local: "warn" };
  if (!existsSync(file)) return config;
  let raw;
  try {
    raw = JSON.parse(readFileSync(file, "utf8"));
  } catch (e) {
    throw new ConfigError(`${file} is not valid JSON (${e.message})`);
  }
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new ConfigError(`${file} must hold a JSON object`);
  for (const [key, value] of Object.entries(raw)) {
    const type = CONFIG_KEYS[key];
    // A misspelt key would silently weaken the gate, so it is an error.
    if (!type) throw new ConfigError(`${file}: unknown key "${key}" (known: ${Object.keys(CONFIG_KEYS).join(", ")})`);
    if (type === "list" && !(Array.isArray(value) && value.every((v) => typeof v === "string"))) throw new ConfigError(`${file}: "${key}" must be a list of strings`);
    if (type === "date" && (typeof value !== "string" || Number.isNaN(Date.parse(value)))) throw new ConfigError(`${file}: "${key}" must be an ISO date`);
    if (type === "mode" && !["warn", "block"].includes(value)) throw new ConfigError(`${file}: "${key}" must be "warn" or "block"`);
    config[key] = value;
  }
  return config;
}

// Globs: `**` crosses directories (and `**/` may match nothing), `*` and `?` stay inside one segment.
export function matchGlob(glob, path) {
  let re = "";
  for (let k = 0; k < glob.length; k++) {
    const c = glob[k];
    if (c === "*" && glob[k + 1] === "*") {
      if (glob[k + 2] === "/") {
        re += "(?:.*/)?";
        k += 2;
      } else {
        re += ".*";
        k += 1;
      }
    } else if (c === "*") re += "[^/]*";
    else if (c === "?") re += "[^/]";
    else re += escapeRe(c);
  }
  return new RegExp(`^${re}$`).test(path);
}
const matchesAny = (globs, path) => globs.some((g) => matchGlob(g, path));

// ---------------------------------------------------------------- git and files

function git(root, args) {
  return execFileSync("git", ["-C", root, ...args], { encoding: "utf8", maxBuffer: 256 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
}

function trackedFiles(root) {
  try {
    return git(root, ["ls-files", "-z"]).split("\0").filter(Boolean);
  } catch {
    const found = [];
    const walk = (dir) => {
      for (const name of readdirSync(join(root, dir))) {
        const rel = dir ? `${dir}/${name}` : name;
        if (matchesAny(DEFAULT_EXCLUDE, rel) || matchesAny(DEFAULT_EXCLUDE, `${rel}/`)) continue;
        if (statSync(join(root, rel)).isDirectory()) walk(rel);
        else found.push(rel);
      }
    };
    walk("");
    return found;
  }
}

// Added line numbers per file, from the hunk headers of a zero-context diff. A renamed file is diffed together with
// its old path, so git pairs them and a pure `git mv` adds no lines.
function addedLines(root, diffArgs) {
  const fields = git(root, ["diff", "--name-status", "-z", "-M", "--diff-filter=AMR", ...diffArgs]).split("\0");
  const result = new Map();
  for (let k = 0; k < fields.length - 1; ) {
    const status = fields[k];
    const paths = status.startsWith("R") ? [fields[k + 1], fields[k + 2]] : [fields[k + 1]];
    k += 1 + paths.length;
    const file = paths[paths.length - 1];
    const set = new Set();
    const diff = git(root, ["diff", "--no-color", "--no-ext-diff", "-U0", "-M", ...diffArgs, "--", ...paths]);
    for (const m of diff.matchAll(/^@@ -\S+ \+(\d+)(?:,(\d+))? @@/gm)) {
      const start = Number(m[1]);
      const count = m[2] === undefined ? 1 : Number(m[2]);
      for (let l = start; l < start + count; l++) set.add(l);
    }
    if (set.size) result.set(file, set);
  }
  return result;
}

function readSource(root, file, rev) {
  try {
    const buf = rev === null ? readFileSync(join(root, file)) : execFileSync("git", ["-C", root, "show", `${rev}:${file}`], { maxBuffer: 64 * 1024 * 1024, stdio: ["ignore", "pipe", "ignore"] });
    if (buf.length > 2 * 1024 * 1024 || buf.subarray(0, 8192).includes(0)) return null;
    return buf.toString("utf8");
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------- warning passes

const IDENTIFIER_WORDS = new Set(
  ("pendiente pendientes escritorio borrar borrado equipo equipos crear leer guardar fichero ficheros carpeta carpetas " +
    "ruta rutas aviso avisos avisar informe informes cierre cerrar rama ramas lienzo trayectoria trayectorias sentinela " +
    "retome comprobar comprueba rechaza rechazar motivo motivos mensaje mensajes usuario usuarios clave claves tarea " +
    "tareas estado estados hecho nombre nombres fecha fechas valor valores lista listas salida entrada raiz ayuda buscar " +
    "obtener actualizar enviar recibir mostrar ocultar abrir cargar nuevo nueva viejo antiguo cuenta cuentas correo " +
    "sesion sesiones pagina paginas enlace enlaces boton botones tarjeta tarjetas tabla fila filas columna columnas " +
    "oficina planta plantas torre personaje personajes partida jugador jugadores puntos ronda rondas hallazgo hallazgos " +
    "veredicto prueba pruebas ejemplo ejemplos caso casos paso pasos cambio cambios registro registros resumen coste " +
    "costes gasto gastos precio precios pedido pedidos cliente clientes proyecto proyectos tablero hito hitos alcance " +
    "presencia almacen limpiar limpio ejecutar ejecucion despliegue desplegar copia respaldo bloqueo bloquear bloqueado " +
    "permitir permiso permisos comodin comodines rojo verde amarillo falta faltan primero segundo ultimo siguiente anterior").split(/\s+/),
);

function spanishWordsIn(identifier, properNouns) {
  if (properNouns.some((p) => p.toLowerCase() === identifier.toLowerCase())) return [];
  const words = identifier.replace(/([a-z0-9])([A-Z])/g, "$1 $2").split(/[\s_$\-./]+/).map((w) => w.toLowerCase()).filter(Boolean);
  const nouns = new Set(properNouns.map((p) => p.toLowerCase()));
  return words.filter((w) => !nouns.has(w) && (IDENTIFIER_WORDS.has(w) || ACCENT.test(w)));
}

// ---------------------------------------------------------------- scanning

function scanFile(ctx, file, src, onlyLines) {
  const kind = kindOf(file, src.slice(0, 200));
  if (!kind) return;
  const isInterface = matchesAny(ctx.config.interface, file);
  const take = (seg) => !onlyLines || onlyLines.has(seg.line);
  const opts = { properNouns: ctx.config.properNouns };
  for (const seg of extractText(src, kind)) {
    if (!take(seg)) continue;
    const prose = seg.type === "comment" || (seg.type === "prose" && !isInterface);
    if (prose && looksSpanish(seg.text, opts)) ctx.findings.push({ where: `${file}:${seg.line}`, area: areaOf(file), text: seg.text });
    if (ctx.literals && seg.type === "string" && !isInterface && looksSpanish(seg.text, opts)) {
      ctx.warnings.push(`${file}:${seg.line}: string "${clip(seg.text)}"`);
    }
    if (ctx.identifiers && seg.type === "code") {
      for (const id of seg.text.match(/[\p{L}_$][\p{L}\p{N}_$]*/gu) || []) {
        const words = spanishWordsIn(id, ctx.config.properNouns);
        const key = `${file}\0${id}`;
        if (words.length && !ctx.seen.has(key)) {
          ctx.seen.add(key);
          ctx.warnings.push(`${file}:${seg.line}: identifier ${id} (${words.join(", ")})`);
        }
      }
    }
  }
  if (ctx.identifiers && !ctx.seen.has(file)) {
    ctx.seen.add(file);
    const words = spanishWordsIn(file.replace(/\.[^./]+$/, ""), ctx.config.properNouns);
    if (words.length) ctx.warnings.push(`${file}: file name (${words.join(", ")})`);
  }
}

function inScope(ctx, file) {
  return !matchesAny(DEFAULT_EXCLUDE, file) && !matchesAny(ctx.config.exclude, file) && !matchesAny(ctx.config.vendored, file);
}

function areaOf(file) {
  const parts = file.split("/");
  return parts.length <= 2 ? parts.slice(0, parts.length - 1).join("/") || "." : `${parts[0]}/${parts[1]}`;
}

const clip = (s) => {
  const t = s.trim();
  return t.length > 160 ? `${t.slice(0, 157)}...` : t;
};

function scanMessage(ctx, label, text) {
  for (const seg of messageLines(text)) {
    if (looksSpanish(seg.text, { properNouns: ctx.config.properNouns })) ctx.findings.push({ where: `${label}:${seg.line}`, area: label.split(" ")[0], text: seg.text });
  }
}

// ---------------------------------------------------------------- self-test

const SELF_TEST = [
  ["detect", "Calcula el número total", true],
  ["detect", "Devuelve los pasos para cerrar", true],
  ["detect", "Returns the list para by name", false],
  ["detect", "TODO: el is the root node", false],
  ["detect", "The card says «Todo está correcto» when nothing is broken", false],
  ["detect", "Prints `algo que no está` on failure", false],
  ["detect", "target es2022 with que_los and para_el", false],
  ["detect", "See https://example.com/año for details", false],
  ["c", 'const u = "https://x.y/a"; // la ruta del fichero\n', [1]],
  ["c", "const r = /\\/\\/ x/g; const s = '/* y';\n", []],
  ["c", "const t = `a ${ `b${ {k: 1}.k }` } c`; // la línea del caso\n", [1]],
  ["shell", 'echo "# no" # sí\necho ${x#y} $#\n', [1]],
  ["shell", "cat <<'EOF'\n# Título\nEOF\n# después\n", [4]],
  ["python", 'def f():\n    """Devuelve el total de la cesta."""\n', [2]],
  ["markdown", "Texto para los demás\n```\nla salida del comando\n```\n", [1]],
];

function selfTest() {
  const failures = [];
  for (const [kind, input, expected] of SELF_TEST) {
    let got;
    if (kind === "detect") got = looksSpanish(input);
    else got = extractText(input, kind).filter((s) => (s.type === "comment" || s.type === "prose") && looksSpanish(s.text)).map((s) => s.line);
    if (JSON.stringify(got) !== JSON.stringify(expected)) failures.push(`${kind} ${JSON.stringify(input)}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(got)}`);
  }
  if (failures.length) {
    process.stdout.write(`self-test FAILED (${failures.length} of ${SELF_TEST.length}):\n${failures.map((f) => `  ${f}\n`).join("")}`);
    return 1;
  }
  process.stdout.write(`self-test: ${SELF_TEST.length} cases ok\n`);
  return 0;
}

// ---------------------------------------------------------------- CLI

const USAGE = "usage: check-english.mjs [--added <base>] [--staged] [--commits <base>] [--text <file|->] [--identifiers] [--literals] [--summary] [--warn] [--local] [--pr-created <iso>] [--root <dir>] [--config <file>] [--self-test]\n";

function parseArgs(argv) {
  const args = { texts: [] };
  const valued = { "--added": "added", "--commits": "commits", "--root": "root", "--config": "config", "--pr-created": "prCreated" };
  const flags = { "--staged": "staged", "--identifiers": "identifiers", "--literals": "literals", "--summary": "summary", "--warn": "warn", "--local": "local", "--self-test": "selfTest", "--help": "help", "-h": "help" };
  for (let k = 0; k < argv.length; k++) {
    const a = argv[k];
    if (a === "--text") {
      if (argv[k + 1] === undefined) throw new ConfigError("--text needs a file or -");
      args.texts.push(argv[++k]);
    } else if (valued[a]) {
      if (argv[k + 1] === undefined) throw new ConfigError(`${a} needs a value`);
      args[valued[a]] = argv[++k];
    } else if (flags[a]) args[flags[a]] = true;
    else throw new ConfigError(`unknown option ${a}`);
  }
  if (args.prCreated && Number.isNaN(Date.parse(args.prCreated))) throw new ConfigError("--pr-created must be an ISO date");
  return args;
}

function findRoot(cwd) {
  try {
    return execFileSync("git", ["-C", cwd, "rev-parse", "--show-toplevel"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
  } catch {
    return cwd;
  }
}

function warnReason(args, config) {
  if (args.warn) return "--warn";
  if (args.local && config.local !== "block") return 'local mode is "warn" in the config';
  if (args.prCreated && config.blockingSince && Date.parse(args.prCreated) < Date.parse(config.blockingSince)) {
    return `the PR was opened before blockingSince ${config.blockingSince}`;
  }
  return null;
}

function report(ctx, args, reason) {
  const out = [];
  for (const w of ctx.warnings) out.push(`warning: ${w}`);
  if (args.summary) {
    const counts = new Map();
    for (const f of ctx.findings) counts.set(f.area, (counts.get(f.area) || 0) + 1);
    for (const [area, count] of [...counts].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))) out.push(`${String(count).padStart(6)}  ${area}`);
  } else {
    for (const f of ctx.findings) out.push(`${f.where}: ${clip(f.text)}`);
  }
  if (ctx.findings.length) {
    out.push("", `${ctx.findings.length} line(s) look Spanish outside the UI.`, "Write them in English; quote Spanish UI text between «» (the gate ignores it).");
    if (reason) out.push(`english-gate: warning only (${reason}); this does not fail.`);
  }
  if (out.length) process.stdout.write(`${out.join("\n")}\n`);
}

export function main(argv, cwd = process.cwd()) {
  let args;
  let config;
  try {
    args = parseArgs(argv);
    if (args.help) {
      process.stdout.write(USAGE);
      return 0;
    }
    if (args.selfTest) return selfTest();
    args.root = args.root ? resolve(cwd, args.root) : findRoot(cwd);
    config = loadConfig(args.config ? resolve(cwd, args.config) : join(args.root, ".english-gate", "config.json"));
  } catch (e) {
    if (!(e instanceof ConfigError)) throw e;
    process.stderr.write(`check-english: ${e.message}\n${USAGE}`);
    return 2;
  }
  const ctx = { config, findings: [], warnings: [], seen: new Set(), identifiers: args.identifiers, literals: args.literals };
  try {
    const diff = args.added ? { args: [`${args.added}...HEAD`], rev: "HEAD" } : args.staged ? { args: ["--cached"], rev: "" } : null;
    if (diff) {
      for (const [file, lines] of addedLines(args.root, diff.args)) {
        if (!inScope(ctx, file)) continue;
        const src = readSource(args.root, file, diff.rev);
        if (src !== null) scanFile(ctx, file, src, lines);
      }
    }
    if (args.commits) {
      for (const entry of git(args.root, ["log", "--format=%H%x00%B%x1e", `${args.commits}..HEAD`]).split("\x1e")) {
        const [sha, body] = entry.replace(/^\s+/, "").split("\0");
        if (sha) scanMessage(ctx, `commit ${sha.slice(0, 7)}`, body || "");
      }
    }
    for (const t of args.texts) scanMessage(ctx, t === "-" ? "stdin" : t, readFileSync(t === "-" ? 0 : resolve(cwd, t), "utf8"));
    if (!diff && !args.commits && !args.texts.length) {
      for (const file of trackedFiles(args.root)) {
        if (!inScope(ctx, file)) continue;
        const src = readSource(args.root, file, null);
        if (src !== null) scanFile(ctx, file, src, null);
      }
    }
  } catch (e) {
    process.stderr.write(`check-english: ${e.stderr ? String(e.stderr).trim() : e.message}\n`);
    return 2;
  }
  const reason = warnReason(args, config);
  report(ctx, args, reason);
  return ctx.findings.length && !reason ? 1 : 0;
}

// Run as a CLI only when executed directly, not when imported by the tests.
if (process.argv[1] && realpathSync(resolve(process.argv[1])) === realpathSync(fileURLToPath(import.meta.url))) {
  process.exitCode = main(process.argv.slice(2));
}
