#!/usr/bin/env node
// T-326 · Runtimes parcheados: sub-paso del peldaño (3) del security-gate.
//
// La fuente única es `presets/runtimes.json` (mínimo por rama soportada). Se mira lo que CORRE, no lo que se declara:
//   - `FROM node:<tag>` de los Dockerfile: solo vale una versión exacta ≥ el mínimo de su rama. Una etiqueta flotante
//     (`22-alpine`, `lts`, sin tag) deja la versión en manos de la caché de capas del host que construye.
//   - `.nvmrc` / `.node-version` / la línea `nodejs`/`node` de `.tool-versions`: una rama soportada sola vale (nvm
//     instala la última); una exacta, si llega al mínimo.
//   - `node-version` de `actions/setup-node` (workflows y acciones compuestas de `.github/`), en estilo bloque o flujo y
//     con la clave entre comillas o sin ellas: una rama sola solo con `check-latest: true` en el mismo paso (instala
//     siempre la última); sin él, un runner de GitHub usa la de la caché de su imagen. `node-version-file` igual, salvo
//     que el fichero fije una versión exacta.
// Los Dockerfile se reconocen por el nombre en todas sus formas (`Dockerfile`, `Dockerfile-prod`, `Dockerfile_prod`,
// `prod.Dockerfile`, `Containerfile`…) y la imagen oficial también cuando la sirve otro registro (mirror.gcr.io,
// public.ecr.aws/docker/library…).
// Escape trazado: `runtime-gate: allow <motivo>` en la línea. Sin motivo no vale.
//
// Uso: check-runtimes.mjs <dir> [--table <runtimes.json>]
// Salida (stdout, JSON): { checked: [ruta], findings: [{file, line, found, problem}], allowed: [{file, line, found, reason}],
//                         unreadable: [ruta] }
// `unreadable` (T-353): directorios o candidatos que no se han podido leer (EACCES…). Se saltan con aviso por stderr en vez
// de tumbar el script, y quedan contados para que security-gate.sh dé el sub-paso por NO COMPROBADO, nunca por limpio.
// Exit 2 si el directorio no existe o la tabla no se puede leer: nunca un JSON vacío que pase por limpio.
import { existsSync, readdirSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { basename, dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const DEFAULT_TABLE = fileURLToPath(new URL('../presets/runtimes.json', import.meta.url));
const SKIP_DIRS = new Set(['node_modules', '.git']);
// La imagen oficial de Node con el registro quitado: `node`, `library/node` (Docker Hub, mirror.gcr.io) o
// `docker/library/node` (la réplica de public.ecr.aws). Lo de otro autor (`ghcr.io/alguien/node`) no es la oficial.
const NODE_IMAGES = new Set(['node', 'library/node', 'docker/library/node']);
const ALLOW = /runtime-gate:\s*allow\b(.*)$/;

function fail(message) {
  process.stderr.write(`check-runtimes: ${message}\n`);
  process.exit(2);
}

function loadMinimums(path) {
  let table;
  try {
    table = JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    fail(`no se puede leer la tabla ${path}: ${error.message}`);
  }
  const minimos = table?.node?.minimos;
  if (!minimos || typeof minimos !== 'object' || Object.keys(minimos).length === 0) {
    fail(`la tabla ${path} no trae node.minimos`);
  }
  return minimos;
}

// Los enlaces simbólicos se siguen: nvm, setup-node y Docker leen el fichero al que apuntan. Cada directorio real se
// recorre una vez, así que un enlace que forma un ciclo no hace daño; un enlace roto se ignora. Un enlace que sale de la
// raíz no se sigue (T-342): juzgar lo que el repo no versiona no es la promesa, y un enlace a `/` lo recorría entero.
// La raíz es la del repo (el primer directorio hacia arriba con `.git`, carpeta o fichero de worktree), no la del
// directorio escaneado: el gate se corre por subdirectorio y un `packages/web/.nvmrc -> ../../.nvmrc` es del repo. Sin
// repo, el propio directorio.
function repoRoot(dir) {
  const start = realpathSync(dir);
  for (let at = start; ; at = dirname(at)) {
    if (existsSync(join(at, '.git'))) return at;
    if (dirname(at) === at) return start;
  }
}

function walk(dir, found = [], seen = new Set(), root = repoRoot(dir), unreadable = []) {
  const real = realpathSync(dir);
  if (seen.has(real)) return found;
  seen.add(real);
  let entries;
  try {
    entries = readdirSync(dir, { withFileTypes: true });
  } catch (error) {
    process.stderr.write(`check-runtimes: no se puede leer ${dir} (${error.code ?? error.message}): se salta y queda sin comprobar\n`);
    unreadable.push(dir);
    return found;
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const path = join(dir, entry.name);
    let kind = entry;
    if (entry.isSymbolicLink()) {
      let target;
      try {
        target = realpathSync(path);
        kind = statSync(target);
      } catch {
        continue;
      }
      if (target !== root && !target.startsWith(root + sep)) {
        process.stderr.write(`check-runtimes: ${path} enlaza fuera del repo (${target}): no se sigue\n`);
        continue;
      }
    }
    if (kind.isDirectory()) walk(path, found, seen, root, unreadable);
    else if (kind.isFile()) found.push(path);
  }
  return found;
}

function kindOf(rel) {
  const name = basename(rel);
  const inGithub = `${sep}${rel}`.includes(`${sep}.github${sep}`);
  if (/^(docker|container)file([._-].*)?$/i.test(name) || /[._-](docker|container)file$/i.test(name)) return 'dockerfile';
  if (name === '.nvmrc') return 'nvmrc';
  if (name === '.node-version') return 'version-file';
  if (name === '.tool-versions') return 'tool-versions';
  if (/\.ya?ml$/.test(name) && `${sep}${rel}`.includes(`${sep}.github${sep}workflows${sep}`)) return 'workflow';
  if ((inGithub || rel === name) && /^action\.ya?ml$/.test(name)) return 'workflow';
  return null;
}

// Nombre de la imagen sin el registro: el primer segmento es un registro si lleva punto, dos puntos, es localhost o sale de
// una variable (`${REGISTRY}/node:20` sigue siendo la imagen de Node, venga del registro que venga).
function imageName(nameAndTag) {
  const parts = nameAndTag.toLowerCase().split('/');
  if (parts.length > 1 && (/[.:$]/.test(parts[0]) || parts[0] === 'localhost')) parts.shift();
  return parts.join('/');
}

const compare = (a, b) => {
  const [x, y] = [a, b].map((v) => v.split('.').map(Number));
  for (let i = 0; i < 3; i += 1) if (x[i] !== y[i]) return x[i] - y[i];
  return 0;
};

/**
 * Juicio de una versión: { exact, major, partial } o null si no es numérica. `partial` es rama.minor (`22.20`): instala la
 * última de ese minor, que puede quedar por debajo del mínimo, así que no vale como «la rama sola» (`22`, `22.x`).
 */
function parseVersion(text) {
  const exact = /^v?(\d+)\.(\d+)\.(\d+)(?:-|$)/.exec(text);
  if (exact) return { exact: `${exact[1]}.${exact[2]}.${exact[3]}`, major: exact[1], partial: false };
  const partial = /^v?(\d+)\.(\d+)(?:\.x)?(?:-|$)/.exec(text);
  if (partial) return { exact: null, major: partial[1], partial: true };
  const branch = /^v?(\d+)(?:\.x){0,2}(?:-|$)/.exec(text);
  if (branch) return { exact: null, major: branch[1], partial: false };
  return null;
}

const partialProblem = (value, minimos, major) =>
  `versión parcial «${value}»: instala la última de ese minor, que puede quedar por debajo del mínimo ${minimos[major] ?? ''}; ` +
  'usa la rama sola o la versión exacta';

/** Problema de una versión exacta o de una rama, o null si cumple. */
function judgeExact(version, minimos) {
  const minimum = minimos[version.major];
  if (!minimum) return `rama ${version.major} sin soporte (las soportadas: ${Object.keys(minimos).join(', ')})`;
  if (compare(version.exact, minimum) < 0) return `${version.exact} está por debajo del mínimo ${minimum}`;
  return null;
}

function unsupported(major, minimos) {
  return minimos[major] ? null : `rama ${major} sin soporte (las soportadas: ${Object.keys(minimos).join(', ')})`;
}

// Una referencia de imagen de Node → su problema, o null si cumple. undefined si no es la imagen oficial de Node.
function judgeImageRef(ref, minimos) {
  const [nameAndTag, digest] = ref.split('@');
  const colon = nameAndTag.lastIndexOf(':');
  const hasTag = colon > nameAndTag.lastIndexOf('/');
  const name = imageName(hasTag ? nameAndTag.slice(0, colon) : nameAndTag);
  // Un nombre que sigue siendo una variable (un ARG sin valor por defecto) puede ser Node: sin valor no se puede juzgar.
  if (name.includes('$')) return `imagen de una variable sin valor por defecto (${ref}): no se puede saber cuál es`;
  if (!NODE_IMAGES.has(name)) return undefined;
  const tag = hasTag ? nameAndTag.slice(colon + 1) : '';
  if (ref.includes('$')) return `imagen de una expresión (${ref}): no se puede saber qué versión es`;
  if (!tag && digest) return 'node@sha256 sin etiqueta: no se puede saber qué versión es; añade la etiqueta exacta';
  const version = parseVersion(tag);
  if (version?.exact) return judgeExact(version, minimos);
  const minimum = minimos[version?.major] ?? minimos[Object.keys(minimos)[0]];
  const variant = /-(.+)$/.exec(tag)?.[1];
  return (version && unsupported(version.major, minimos))
    ?? `etiqueta flotante «${tag || '(sin tag)'}»: fija la versión exacta (p. ej. node:${minimum}${variant ? `-${variant}` : ''})`;
}

// Carácter de escape del Dockerfile: `\\` salvo que la directiva `# escape=` lo cambie. Las directivas solo cuentan
// en las primeras líneas, antes de cualquier instrucción, comentario, línea vacía o directiva que BuildKit no conoce
// (parser/directives.go): un `# escape=` después de `# app=api` ya es un comentario.
const DIRECTIVES = new Set(['syntax', 'escape', 'check']);
function escapeChar(lines) {
  for (const raw of lines) {
    const directive = /^\s*#\s*([a-z]+)\s*=\s*(\S+)\s*$/i.exec(raw);
    if (!directive || !DIRECTIVES.has(directive[1].toLowerCase())) break;
    if (directive[1].toLowerCase() === 'escape' && (directive[2] === '`' || directive[2] === '\\')) return directive[2];
  }
  return '\\';
}

// Instrucciones lógicas del Dockerfile: une las líneas partidas con el carácter de escape y recuerda la línea donde
// empieza cada una. Dentro de una continuación, Docker se salta los comentarios y las líneas vacías sin cortarla.
function logicalLines(lines) {
  const esc = escapeChar(lines);
  const trailing = new RegExp(`${esc === '`' ? '`' : '\\\\'}\\s*$`);
  const out = [];
  let buf = null;
  lines.forEach((raw, index) => {
    const comment = /^\s*#/.test(raw);
    if (buf && (comment || raw.trim() === '')) return;
    const text = buf ? `${buf.text} ${raw.trim()}` : raw;
    const start = buf ? buf.start : index;
    if (trailing.test(raw) && !comment) buf = { text: text.replace(trailing, ''), start };
    else {
      out.push({ text, start });
      buf = null;
    }
  });
  if (buf) out.push(buf);
  return out;
}

// Palabras de una instrucción como las parte Docker (parseWords): por espacios, salvo dentro de comillas, que se quitan, o
// tras el carácter de escape (fuera de comillas simples), que mete el carácter siguiente en la palabra.
function words(text, esc = '\\') {
  const out = [];
  let word = null;
  let quote = null;
  let escaped = false;
  for (const ch of text) {
    if (escaped) {
      word = (word ?? '') + ch;
      escaped = false;
    } else if (ch === esc && quote !== "'") {
      escaped = true;
      word ??= '';
    } else if (quote) {
      if (ch === quote) quote = null;
      else word += ch;
    } else if (ch === '"' || ch === "'") {
      quote = ch;
      word ??= '';
    } else if (/\s/.test(ch)) {
      if (word !== null) out.push(word);
      word = null;
    } else word = (word ?? '') + ch;
  }
  if (escaped) word += esc;
  if (word !== null) out.push(word);
  return out;
}

// `ARG A=1 B="x y"` → [['A', '1'], ['B', 'x y']]; sin `=`, el valor es undefined.
function argDefs(text, esc) {
  const m = /^\s*ARG\s+(.*)$/i.exec(text);
  if (!m) return [];
  return words(m[1], esc).map((pair) => {
    const eq = pair.indexOf('=');
    return eq < 0 ? [pair, undefined] : [pair.slice(0, eq), pair.slice(eq + 1)];
  });
}

// Sustituye `$X`, `${X}` y `${X:-def}` por su valor; lo que no tiene valor se queda como está y judgeImageRef lo juzga.
// `${X:-def}` toma def si X no tiene valor o está vacía; `${X-def}`, solo si no tiene valor (shell/lex.go de BuildKit).
function expandArgs(ref, args) {
  return ref.replace(/\$\{(\w+)(?:(:?)-([^}]*))?\}|\$(\w+)/g, (whole, braced, colon, fallback, bare) => {
    const value = args.get(braced ?? bare);
    const useFallback = fallback !== undefined && (value === undefined || (colon === ':' && value === ''));
    if (useFallback) return fallback;
    return value ?? whole;
  });
}

// Imágenes que mete cada instrucción: la del FROM, la de `COPY --from=` y las de `RUN --mount=…from=`. Un nombre de
// etapa (`--from=deps`) no es la imagen de Node, así que judgeImageRef lo ignora.
function imageRefs(text) {
  const from = /^\s*FROM\s+(?:--\S+\s+)*(\S+)/i.exec(text);
  if (from) return [from[1]];
  const refs = [];
  if (/^\s*COPY\s/i.test(text)) for (const m of text.matchAll(/--from=(\S+)/gi)) refs.push(m[1]);
  if (/^\s*RUN\s/i.test(text)) for (const m of text.matchAll(/--mount=\S*?\bfrom=([^,\s]+)/gi)) refs.push(m[1]);
  return refs;
}

// Los ARG de antes del primer FROM son los que ve un FROM; los de dentro de una etapa, el resto de la etapa (un `ARG X`
// sin valor dentro de la etapa recoge el valor global). Se juzga el valor por defecto: `--build-arg` no se ve desde aquí.
function checkDockerfile(lines, minimos) {
  const out = [];
  const global = new Map();
  let stage = null;
  const esc = escapeChar(lines);
  for (const { text, start } of logicalLines(lines)) {
    for (const [name, value] of argDefs(text, esc)) {
      if (stage) stage.set(name, value ?? global.get(name));
      else global.set(name, value);
    }
    const isFrom = /^\s*FROM\s/i.test(text);
    for (const ref of imageRefs(text)) {
      const problem = judgeImageRef(expandArgs(ref, isFrom ? global : stage ?? global), minimos);
      if (problem) out.push({ line: start + 1, found: lines[start].trim(), problem });
    }
    if (isFrom) stage = new Map();
  }
  return out;
}

function judgeFileValue(value, minimos) {
  const version = parseVersion(value);
  if (!version) return `«${value}» no es una versión que se pueda juzgar`;
  if (version.exact) return judgeExact(version, minimos);
  return unsupported(version.major, minimos) ?? (version.partial ? partialProblem(value, minimos, version.major) : null);
}

function checkVersionFile(lines, minimos) {
  const index = lines.findIndex((l) => l.trim() !== '');
  if (index < 0) return [];
  const value = lines[index].trim();
  const problem = judgeFileValue(value, minimos);
  return problem ? [{ line: index + 1, found: value, problem }] : [];
}

// `.tool-versions` de asdf/mise: la línea `nodejs <versión>` (o `node`, en mise); manda la primera versión de la línea.
// T-353 (ADV-16): nvm ≥ 0.40 admite comentarios en `.nvmrc` (`24 # LTS`, o líneas enteras de comentario): lo que va
// desde `#` no es la versión. Solo en `.nvmrc`: setup-node (node-version-file) y los demás gestores no los quitan.
function checkNvmrc(lines, minimos) {
  return checkVersionFile(lines.map((l) => l.replace(/#.*$/, '')), minimos);
}

function checkToolVersions(lines, minimos) {
  const out = [];
  lines.forEach((raw, index) => {
    const m = /^\s*(?:nodejs|node)\s+(\S+)/.exec(raw);
    if (!m) return;
    const problem = judgeFileValue(m[1], minimos);
    if (problem) out.push({ line: index + 1, found: raw.trim(), problem });
  });
  return out;
}

const indentOf = (line) => line.length - line.trimStart().length;
const isItem = (line) => /^\s*-(\s|$)/.test(line);

/** Líneas [inicio, fin) del elemento de lista YAML (el paso) que contiene la línea `at`. */
function stepAround(lines, at) {
  let start = at;
  if (!isItem(lines[at])) {
    const own = indentOf(lines[at]);
    while (start > 0 && !(isItem(lines[start]) && indentOf(lines[start]) < own)) start -= 1;
  }
  const dash = indentOf(lines[start]);
  let end = start + 1;
  while (end < lines.length && (lines[end].trim() === '' || indentOf(lines[end]) > dash)) end += 1;
  return [start, end];
}

// Un valor YAML de una clave, en estilo bloque o flujo y con la clave entre comillas o sin ellas. `(?![\w-])` evita que
// `node-version` case con `node-version-file`.
const keyValue = (key) => new RegExp(`(?:^|[\\s{,])["']?${key}["']?(?![\\w-])\\s*:\\s*("[^"]*"|'[^']*'|[^,}\\s#]+)`);
const unquote = (v) => v.replace(/^['"]|['"]$/g, '');

// La línea con el contenido de sus cadenas entre comillas tapado (`_`), mismas posiciones: una clave o un ` #` que caen
// dentro de una cadena no son una clave ni un comentario (T-342, ADV-6/7). Una comilla solo abre cadena al empezar un
// valor (tras inicio, espacio, `:`, `[`, `{` o `,`); un apóstrofo dentro de una palabra no. Una cadena seguida de `:` es
// una clave entre comillas (`"node-version": 20`) y se deja a la vista.
function maskQuoted(text) {
  const chars = text.split('');
  let open = -1;
  let quote = null;
  for (let i = 0; i < chars.length; i += 1) {
    const ch = chars[i];
    if (!quote) {
      if ((ch === '"' || ch === "'") && (i === 0 || /[\s:[{,]/.test(chars[i - 1]))) [quote, open] = [ch, i];
    } else if ((quote === '"' && ch === '\\') || (quote === "'" && ch === "'" && chars[i + 1] === "'")) i += 1;
    else if (ch === quote) {
      quote = null;
      let next = i + 1;
      while (next < chars.length && /\s/.test(chars[next])) next += 1;
      if (chars[next] !== ':') for (let j = open + 1; j < i; j += 1) chars[j] = '_';
    }
  }
  if (quote) for (let j = open + 1; j < chars.length; j += 1) chars[j] = '_';
  return chars.join('');
}

/** La línea sin su comentario: ` #` fuera de comillas. */
function stripComment(text) {
  const at = maskQuoted(text).search(/\s#/);
  return at < 0 ? text : text.slice(0, at);
}

function findKey(stepLines, key) {
  const re = keyValue(key);
  for (let i = 0; i < stepLines.length; i += 1) {
    const line = stripComment(stepLines[i]);
    const at = re.exec(maskQuoted(line))?.index;
    if (at !== undefined) return { offset: i, value: unquote(re.exec(line.slice(at))[1]) };
  }
  return null;
}

function judgeNodeVersion(value, checkLatest, minimos) {
  if (value.includes('${{')) return `node-version de una expresión (${value}): no se puede juzgar; usa una rama con check-latest o una versión exacta`;
  const version = parseVersion(value);
  if (!version) return `node-version «${value}» no se puede juzgar (rango o alias): usa la rama sola con check-latest o una versión exacta`;
  if (version.exact) return judgeExact(version, minimos);
  if (unsupported(version.major, minimos)) return unsupported(version.major, minimos);
  if (version.partial) return partialProblem(value, minimos, version.major);
  if (!checkLatest) return `node-version «${value}» sin check-latest: true usa la versión que haya en la caché del runner`;
  return null;
}

// node-version-file: con check-latest siempre vale (el fichero se juzga aparte); sin él, solo si el fichero fija una versión
// exacta (una rama la resuelve la caché del runner).
function judgeVersionFile(file, checkLatest, root) {
  if (checkLatest) return null;
  const path = join(root, file);
  const first = existsSync(path) ? readFileSync(path, 'utf8').split('\n').find((l) => l.trim() !== '')?.trim() : null;
  if (first && parseVersion(first)?.exact) return null;
  return `node-version-file «${file}» sin check-latest: true usa la versión que haya en la caché del runner (salvo que el fichero fije una versión exacta)`;
}

// Las líneas del paso que pueden llevar inputs de la acción: fuera quedan `name:`, `run:`, `if:` e `id:` (texto libre) y el
// bloque `env:` (variables de entorno, no inputs), con su bloque de varias líneas si lo tienen (`run: |`, `env:`). Las
// líneas quitadas se dejan vacías para no mover los desplazamientos.
// ¿Cierra esta línea una cadena YAML abierta con `quote`? En `"…"` la comilla escapada es `\\"`; en `'…'`, `''`.
function closesQuote(text, quote) {
  const rest = quote === '"' ? text.replace(/\\./g, '') : text.replace(/''/g, '');
  return rest.includes(quote);
}

function inputLines(step) {
  let skipBelow = null;
  let openQuote = null;
  return step.map((raw) => {
    // Dentro de una cadena entre comillas que sigue en otra línea: nada de lo que haya ahí es una clave.
    if (openQuote) {
      if (closesQuote(raw, openQuote)) openQuote = null;
      return '';
    }
    const indent = indentOf(raw);
    if (skipBelow !== null && raw.trim() !== '' && indent <= skipBelow) skipBelow = null;
    if (skipBelow !== null) return '';
    const key = /^\s*(?:-\s+)?["']?([\w-]+)["']?\s*:\s*(.*)$/.exec(raw);
    if (!key) return raw;
    const value = stripComment(key[2]).trim();
    const ignored = /^(name|run|if|id|env)$/.test(key[1]);
    // El bloque `|`/`>` de cualquier clave es texto, no claves; y lo que cuelga de name/run/if/id/env (el mapa de env:)
    // no son inputs de setup-node.
    if (/^[|>][-+0-9]*$/.test(value) || (ignored && value === '')) skipBelow = indent + (/^\s*-\s/.test(raw) ? 2 : 0);
    else if (/^["']/.test(value) && !closesQuote(value.slice(1), value[0])) openQuote = value[0];
    return ignored ? '' : raw;
  });
}

function checkWorkflow(lines, minimos, root) {
  const out = [];
  const seen = new Set();
  lines.forEach((raw, index) => {
    if (!/uses["']?\s*:\s*["']?actions\/setup-node@/i.test(raw)) return;
    const [start, end] = stepAround(lines, index);
    if (seen.has(start)) return;
    seen.add(start);
    const step = inputLines(lines.slice(start, end));
    // setup-node lo lee con core.getBooleanInput, que acepta true | True | TRUE (T-353, ADV-15).
    const checkLatest = ['true', 'True', 'TRUE'].includes(findKey(step, 'check-latest')?.value);
    const nodeVersion = findKey(step, 'node-version');
    const versionFile = findKey(step, 'node-version-file');
    let found = null;
    let problem = null;
    if (nodeVersion) {
      found = nodeVersion;
      problem = judgeNodeVersion(nodeVersion.value, checkLatest, minimos);
    } else if (versionFile) {
      found = versionFile;
      problem = judgeVersionFile(versionFile.value, checkLatest, root);
    } else {
      // Ni node-version ni node-version-file legibles: un alias YAML (`with: *w`), una merge key (`<<: *w`) o ningún
      // input, y entonces el Node es el que traiga el runner. No se puede juzgar, así que no pasa (como en R2).
      found = { offset: index - start };
      problem = 'setup-node sin node-version legible (alias YAML, merge key o ninguno, que deja el Node del runner): ' +
        'pon node-version con la rama sola y check-latest, o una versión exacta';
    }
    if (problem) out.push({ line: start + found.offset + 1, found: lines[start + found.offset].trim(), problem });
  });
  return out;
}

const CHECKS = {
  dockerfile: checkDockerfile,
  'version-file': checkVersionFile,
  nvmrc: checkNvmrc,
  'tool-versions': checkToolVersions,
  workflow: checkWorkflow,
};

function main(argv) {
  const args = [...argv];
  let tablePath = DEFAULT_TABLE;
  const t = args.indexOf('--table');
  if (t >= 0) {
    tablePath = args[t + 1];
    if (!tablePath) fail('--table necesita una ruta');
    args.splice(t, 2);
  }
  const [dir] = args;
  if (!dir || args.length !== 1) fail('uso: check-runtimes.mjs <dir> [--table <runtimes.json>]');
  if (!existsSync(dir) || !statSync(dir).isDirectory()) fail(`no es un directorio: ${dir}`);
  const minimos = loadMinimums(tablePath);

  const result = { checked: [], findings: [], allowed: [], unreadable: [] };
  const unreadable = [];
  for (const path of walk(dir, [], new Set(), repoRoot(dir), unreadable)) {
    const rel = relative(dir, path);
    const kind = kindOf(rel);
    if (!kind) continue;
    let lines;
    try {
      lines = readFileSync(path, 'utf8').split('\n');
    } catch (error) {
      process.stderr.write(`check-runtimes: no se puede leer ${path} (${error.code ?? error.message}): queda sin comprobar\n`);
      unreadable.push(path);
      continue;
    }
    result.checked.push(rel);
    for (const finding of CHECKS[kind](lines, minimos, dir)) {
      const allow = ALLOW.exec(lines[finding.line - 1]);
      const reason = allow?.[1].trim();
      if (reason) {
        result.allowed.push({ file: rel, line: finding.line, found: finding.found, reason });
        continue;
      }
      const problem = allow ? `${finding.problem} (el escape runtime-gate: allow necesita un motivo)` : finding.problem;
      result.findings.push({ file: rel, ...finding, problem });
    }
  }
  result.unreadable = unreadable.map((path) => relative(dir, path));
  process.stdout.write(`${JSON.stringify(result)}\n`);
}

main(process.argv.slice(2));
