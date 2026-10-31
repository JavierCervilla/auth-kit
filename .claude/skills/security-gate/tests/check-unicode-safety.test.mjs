// =============================================================================
// Tests del gate anti-tag-smuggling Unicode (T-166). Node PURO (node:test + node:assert), sin deps.
//
// CRÍTICO (design §4): NINGÚN carácter peligroso se commitea literal. Todas las cadenas peligrosas se
// GENERAN en runtime con String.fromCodePoint(0x...) y se escriben a un TEMPORAL (os.tmpdir). Si un
// literal peligroso viviera en este fichero, el propio gate lo cazaría en CI (el scanner escanea
// .claude/skills/**), que es justo lo que queremos.
//
// Correr:  node --test .claude/skills/security-gate/tests/check-unicode-safety.test.mjs
// =============================================================================

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const SCANNER = fileURLToPath(new URL("../scripts/check-unicode-safety.mjs", import.meta.url));

// cwd por defecto = tmpdir (NO es un repo git) → skipRequested() no interfiere en los tests de fichero.
function run(args, cwd) {
  const r = spawnSync(process.execPath, [SCANNER, ...args], { cwd: cwd ?? tmpdir(), encoding: "utf8" });
  return { code: r.status, out: r.stdout ?? "", err: r.stderr ?? "" };
}
function tmpFile(name, content) {
  const dir = mkdtempSync(join(tmpdir(), "uni-"));
  const p = join(dir, name);
  writeFileSync(p, content);
  return { dir, p };
}

// --- Una entrada por clase: si se quita esa clase del scanner, SU test se pone rojo (ojo mutante). --
const CLASSES = [
  { cp: 0x200b, hex: "200B", cls: "zero-width" },
  { cp: 0x202e, hex: "202E", cls: "bidi" },
  { cp: 0xe0001, hex: "E0001", cls: "tag" },
  { cp: 0x180e, hex: "180E", cls: "mongolian-vs" },
  { cp: 0x3164, hex: "3164", cls: "filler" },
  { cp: 0x2062, hex: "2062", cls: "invisible-math" },
  { cp: 0xfff9, hex: "FFF9", cls: "interlinear" },
];
for (const c of CLASSES) {
  test(`detecta la clase ${c.cls} (U+${c.hex})`, () => {
    const { p } = tmpFile("f.md", `antes${String.fromCodePoint(c.cp)}despues\n`);
    const r = run([p]);
    assert.equal(r.code, 1, r.out + r.err);
    assert.match(r.out, new RegExp(`U\\+${c.hex} \\(${c.cls}\\)`), r.out);
  });
}

test("--fix limpia y deja el texto legítimo intacto (tab + emoji ZWJ + acentos)", () => {
  const legit = "\tHola café 👨‍🍳 mundo\n"; // el 👨‍🍳 lleva un ZWJ legítimo que NO debe tocarse
  const zwsp = String.fromCodePoint(0x200b);
  const { p } = tmpFile("f.md", "\tHola café 👨‍🍳 mundo" + zwsp + "\n");
  const r = run(["--fix", p]);
  assert.equal(r.code, 0, r.out + r.err);
  assert.equal(readFileSync(p, "utf8"), legit);
});

test("[unicode-allow: U+E0001] deja pasar SOLO ese codepoint en esa línea (y NO otro)", () => {
  const tag1 = String.fromCodePoint(0xe0001);
  const tag2 = String.fromCodePoint(0xe0002);
  const content =
    `A${tag1}B [unicode-allow: U+E0001 ilustra el ataque en docs]\n` +
    `C${tag2}D [unicode-allow: U+E0001 este marcador NO cubre E0002]\n`;
  const { p } = tmpFile("f.md", content);
  const r = run([p]);
  assert.equal(r.code, 1, r.out + r.err);
  assert.match(r.out, /U\+E0002 \(tag\)/); // el no permitido SÍ se reporta
  assert.doesNotMatch(r.out, /U\+E0001/); // el permitido NO
});

test("[skip-unicode] en el asunto del commit salta el run entero", () => {
  const dir = mkdtempSync(join(tmpdir(), "unigit-"));
  const git = (...a) => spawnSync("git", a, { cwd: dir, encoding: "utf8" });
  git("init", "-q");
  git("config", "user.email", "t@t.t");
  git("config", "user.name", "t");
  writeFileSync(join(dir, "dirty.md"), `x${String.fromCodePoint(0x200b)}y\n`);
  git("add", ".");
  git("commit", "-q", "-m", "chore: prueba [skip-unicode]");
  const skipped = run(["dirty.md"], dir);
  assert.equal(skipped.code, 0, skipped.out + skipped.err); // el asunto lleva el marcador → salta

  // Control: nuevo commit SIN el marcador en el asunto → vuelve a bloquear el fichero sucio.
  writeFileSync(join(dir, "extra.md"), "solo texto\n");
  git("add", ".");
  git("commit", "-q", "-m", "chore: sin marcador");
  const blocked = run(["dirty.md"], dir);
  assert.equal(blocked.code, 1, blocked.out + blocked.err);
});

// T-301 (adversario R5, ADV-T301-1): vault-push publica sin revisión humana y lanzaba el escáner desde el repo del
// framework; un commit con [skip-unicode] en el asunto, o un [unicode-allow] dentro de lo publicado, apagaban el gate.
test("--strict ignora [skip-unicode] en el asunto y [unicode-allow] en la línea", () => {
  const dir = mkdtempSync(join(tmpdir(), "unistrict-"));
  const git = (...a) => spawnSync("git", a, { cwd: dir, encoding: "utf8" });
  git("init", "-q");
  git("config", "user.email", "t@t.t");
  git("config", "user.name", "t");
  const tag = String.fromCodePoint(0xe0041);
  writeFileSync(join(dir, "sucio.md"), `x${String.fromCodePoint(0x200b)}y\n`);
  writeFileSync(join(dir, "permitido.md"), `A${tag}B [unicode-allow: U+E0041 coartada]\n`);
  git("add", ".");
  git("commit", "-q", "-m", "chore: prueba [skip-unicode]");
  assert.equal(run(["sucio.md"], dir).code, 0); // sin --strict, el marcador salta el run
  const r = run(["--strict", "sucio.md"], dir);
  assert.equal(r.code, 1, r.out + r.err);
  assert.match(r.out, /U\+200B/);
  const p = run(["--strict", "permitido.md"], dir);
  assert.equal(p.code, 1, p.out + p.err);
  assert.match(p.out, /U\+E0041 \(tag\)/);
});

// T-301 (adversario R6, ADV-T301-4): ALWAYS_EXCLUDE se aplicaba también a los ficheros nombrados, así que un .md bajo
// assets/ o node_modules/ salía como «0 escaneados, exit 0»; y un binario de extensión desconocida se saltaba.
test("--strict escanea un fichero nombrado bajo assets/ o node_modules/ y no salta binarios desconocidos", () => {
  const dir = mkdtempSync(join(tmpdir(), "unistrict2-"));
  const tag = String.fromCodePoint(0xe0041);
  for (const sub of ["assets", "node_modules"]) {
    mkdirSync(join(dir, sub));
    const p = join(dir, sub, "nota.md");
    writeFileSync(p, `x${tag}y\n`);
    assert.equal(run([p]).code, 0); // sin --strict, la exclusión de siempre
    const r = run(["--strict", p]);
    assert.equal(r.code, 1, r.out + r.err);
    assert.match(r.out, /U\+E0041 \(tag\)/);
  }
  const canvas = join(dir, "lienzo.canvas");
  writeFileSync(canvas, Buffer.concat([Buffer.from([0]), Buffer.from(`{"t":"x${tag}y"}\n`)]));
  assert.equal(run([canvas]).code, 0); // sin --strict, «binario desconocido»: aviso de cobertura
  const c = run(["--strict", canvas]);
  assert.equal(c.code, 1, c.out + c.err);
  assert.match(c.out, /binario-sin-escanear/);
});

// T-301 (adversario R7, ADV-T301-5): un UTF-16LE con BOM y sin ASCII no lleva ningún NUL; el escáner lo leía como UTF-8
// y no veía los Tag, que la herramienta Read sí entrega al decodificar por el BOM.
test("--strict rechaza lo que no es UTF-8 (UTF-16 con BOM, Latin-1) y deja pasar el UTF-8 y los binarios conocidos", () => {
  const dir = mkdtempSync(join(tmpdir(), "unistrict3-"));
  // «ПР» + U+E0041 en UTF-16LE: 1F 04 20 04 40 DB 41 DC, sin un solo byte 0.
  const utf16 = join(dir, "nota.md");
  writeFileSync(utf16, Buffer.from([0xff, 0xfe, 0x1f, 0x04, 0x20, 0x04, 0x40, 0xdb, 0x41, 0xdc]));
  assert.equal(run([utf16]).code, 0); // sin --strict, el punto ciego de siempre
  const r = run(["--strict", utf16]);
  assert.equal(r.code, 1, r.out + r.err);
  assert.match(r.out, /codificacion-utf16/);
  const latin1 = join(dir, "latin1.txt");
  writeFileSync(latin1, Buffer.from([0x63, 0x61, 0x66, 0xe9, 0x0a])); // «café» en Latin-1
  const l = run(["--strict", latin1]);
  assert.equal(l.code, 1, l.out + l.err);
  assert.match(l.out, /utf8-invalido/);
  const ok = join(dir, "bien.md");
  writeFileSync(ok, "café con tilde y ñ\n");
  assert.equal(run(["--strict", ok]).code, 0);
  // Los medios del vault (audio y vídeo de las trayectorias de vídeo) son binarios conocidos: con --strict, pasan.
  for (const ext of [".mp3", ".mp4", ".m4a", ".wav"]) {
    const m = join(dir, `medio${ext}`);
    writeFileSync(m, Buffer.from([0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70]));
    assert.equal(run(["--strict", m]).code, 0, ext);
  }
});

// T-315 (the human's decision «Rechazarlos»): the Read tool extracts a PDF's text layer and hands it to the model, but
// this scanner cannot decode PDFs. Under --strict (vault-push) a .pdf is a finding whatever its content; without
// --strict it is still skipped, and the other known binaries are still skipped under --strict.
test("--strict rejects .pdf files (any case, any content); without --strict they are still skipped", () => {
  const dir = mkdtempSync(join(tmpdir(), "unistrict-pdf-"));
  const pdfBytes = Buffer.from([0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37, 0x0a, 0x00, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a]);
  for (const name of ["doc.pdf", "SCAN.PDF", "notes.Pdf"]) {
    const p = join(dir, name);
    writeFileSync(p, pdfBytes);
    assert.equal(run([p]).code, 0, `${name} without --strict`);
    const r = run(["--strict", p]);
    assert.equal(r.code, 1, `${name}: ${r.out}${r.err}`);
    assert.match(r.out, /pdf-text-layer/);
  }
  const textOnly = join(dir, "plain.pdf");
  writeFileSync(textOnly, "just ASCII, no binary marker\n");
  assert.equal(run(["--strict", textOnly]).code, 1, "a .pdf is rejected by its extension, not by its content");
  const png = join(dir, "image.png");
  writeFileSync(png, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00]));
  assert.equal(run(["--strict", png]).code, 0, "other known binaries are still skipped under --strict");
});

// T-315, guardian R1 (ADV-T315-1): the Read tool also PARSES Jupyter notebooks and hands the decoded cell source to the
// model, so a pure-ASCII .ipynb can carry Tag characters as JSON escapes the scanner never sees. Same rule as PDFs.
test("--strict rejects .ipynb files (Read decodes their JSON escapes); without --strict they are scanned as before", () => {
  const dir = mkdtempSync(join(tmpdir(), "unistrict-ipynb-"));
  const escaped = Array.from(String.fromCodePoint(0xe0069, 0xe0067), (ch) => {
    const cp = ch.codePointAt(0) - 0x10000;
    return `\\u${(0xd800 + (cp >> 10)).toString(16)}\\u${(0xdc00 + (cp & 0x3ff)).toString(16)}`;
  }).join("");
  const notebook = `{"cells":[{"cell_type":"markdown","metadata":{},"source":["Visible note${escaped}"]}],"metadata":{},"nbformat":4,"nbformat_minor":5}\n`;
  assert.ok(/^[\x00-\x7f]*$/.test(notebook), "the attack notebook is pure ASCII");
  for (const name of ["analysis.ipynb", "RESCUED.IPYNB"]) {
    const p = join(dir, name);
    writeFileSync(p, notebook);
    assert.equal(run([p]).code, 0, `${name} without --strict: the old blind spot`);
    const r = run(["--strict", p]);
    assert.equal(r.code, 1, `${name}: ${r.out}${r.err}`);
    assert.match(r.out, /notebook-decoded-by-read/);
  }
});

test("--exclude omite el fichero sucio (substring y glob)", () => {
  const dir = mkdtempSync(join(tmpdir(), "uniex-"));
  mkdirSync(join(dir, "sub"));
  writeFileSync(join(dir, "sub", "bad.md"), `x${String.fromCodePoint(0x200b)}y\n`);
  assert.equal(run([dir]).code, 1); // sin exclude → bloquea
  assert.equal(run([dir, "--exclude", "bad.md"]).code, 0); // substring
  assert.equal(run([dir, "--exclude", "**/bad.md"]).code, 0); // glob
});

test("no marca el ZWJ de una secuencia de emoji (cocinero y familia)", () => {
  const { p } = tmpFile("f.md", "cocinero 👨‍🍳 y familia 👨‍👩‍👧 ok\n");
  assert.equal(run([p]).code, 0);
});

test("exit 0 en un fichero limpio (tab, acentos y emoji normal)", () => {
  const { p } = tmpFile("f.md", "solo texto legítimo con tab\ty un emoji 🎉 suelto\n");
  assert.equal(run([p]).code, 0);
});

// --- Enmienda T-166 (evasión por encoding): F1 sin NUL en el fuente, F2 cobertura + bypass -------

test("F1: el fuente del scanner no contiene NINGÚN byte NUL (texto revisable + auto-escaneable)", () => {
  const raw = readFileSync(SCANNER); // en binario: un Buffer
  assert.equal(raw.indexOf(0), -1, `el scanner tiene ${raw.filter((b) => b === 0).length} NUL(s)`);
});

test("F2: un NUL temprano en un .md de texto es HALLAZGO (bypass por prefijo-NUL cerrado)", () => {
  // Antes: el NUL disparaba la heurística binaria y el tag-smuggle tras él pasaba con exit 0.
  // El NUL y el tag se GENERAN en runtime (nunca literales en este fichero).
  const smuggle = "harmless" + "\x00" + " instruccion oculta " + String.fromCodePoint(0xe0001) + "x\n";
  const { p } = tmpFile("bypass.md", smuggle);
  const r = run([p]);
  assert.equal(r.code, 1, r.out + r.err); // antes daba 0
  assert.match(r.out, /U\+0000/, r.out); // se reporta el U+0000 en superficie de texto
});

test("F2: una extensión binaria legítima (.woff2) con NUL se salta SIN marcarla (cobertura aparte)", () => {
  const dir = mkdtempSync(join(tmpdir(), "unifont-"));
  const p = join(dir, "font.woff2");
  writeFileSync(p, Buffer.from([0x77, 0x4f, 0x46, 0x32, 0x00, 0x01, 0x00, 0x00])); // "wOF2" + NUL binario
  const r = run([p]);
  assert.equal(r.code, 0, r.out + r.err); // font legítima: no es un ataque
  assert.equal(r.out.includes("U+0000"), false, r.out); // NO se marca como hallazgo
  assert.match(r.out, /0 fichero\(s\) escaneado\(s\).*saltados 1 por binario/, r.out); // cobertura honesta
});

test("exit 2 con opción desconocida", () => {
  assert.equal(run(["--bogus"]).code, 2);
});

test("exit 2 con --exclude sin valor", () => {
  assert.equal(run(["--exclude"]).code, 2);
});
