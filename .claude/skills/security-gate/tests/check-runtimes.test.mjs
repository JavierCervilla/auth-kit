// =============================================================================
// Tests del sub-paso de runtimes del peldaño (3) (T-326). Node puro (node:test + node:assert), sin deps.
// Cada regla de la tabla del plan tiene un caso en rojo y otro en verde: si se quita la regla del script, su caso rojo
// pasa a verde y el test lo dice. La tabla de mínimos va fijada en el test (TABLE) para que un cambio de versiones en
// presets/runtimes.json no mueva estos casos; el preset real se comprueba aparte.
//
// Correr:  node --test .claude/skills/security-gate/tests/check-runtimes.test.mjs
// =============================================================================

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const SCRIPT = fileURLToPath(new URL("../scripts/check-runtimes.mjs", import.meta.url));
const PRESET = fileURLToPath(new URL("../presets/runtimes.json", import.meta.url));

const TABLE = { node: { minimos: { "22": "22.23.4", "24": "24.22.1" } } };

function project(files) {
  const dir = mkdtempSync(join(tmpdir(), "rt-"));
  for (const [path, content] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, path)), { recursive: true });
    writeFileSync(join(dir, path), content);
  }
  const table = join(dir, ".table.json");
  writeFileSync(table, JSON.stringify(TABLE));
  return { dir, table };
}

function run(files) {
  const { dir, table } = project(files);
  const r = spawnSync(process.execPath, [SCRIPT, dir, "--table", table], { encoding: "utf8" });
  assert.equal(r.status, 0, `exit ${r.status}: ${r.stderr}`);
  return JSON.parse(r.stdout);
}

const problems = (out) => out.findings.map((f) => `${f.file}:${f.line} ${f.problem}`);

// --- Dockerfile -----------------------------------------------------------------------------------
test("Dockerfile: una versión exacta igual o superior al mínimo pasa, con variante y con digest", () => {
  const out = run({
    Dockerfile: "FROM node:22.23.4-alpine AS build\nFROM node:24.22.1@sha256:" + "a".repeat(64) + "\n",
    "web/app.Dockerfile": "FROM node:22.24.0-bookworm-slim\n",
  });
  assert.deepEqual(out.findings, []);
  assert.equal(out.checked.length, 2);
});

test("Dockerfile: etiqueta flotante (rama sola, variante sin versión, lts, latest, sin tag) bloquea", () => {
  const out = run({
    Dockerfile: [
      "FROM node:22-alpine AS a",
      "FROM node:22 AS b",
      "FROM node:lts-slim AS c",
      "FROM node:latest AS d",
      "FROM node AS e",
      "FROM --platform=linux/amd64 node:alpine AS f",
    ].join("\n"),
  });
  assert.equal(out.findings.length, 6, problems(out).join("\n"));
  assert.ok(out.findings.every((f) => /flotante/.test(f.problem)), problems(out).join("\n"));
});

test("Dockerfile: por debajo del mínimo de su rama bloquea y nombra el mínimo", () => {
  const out = run({ Dockerfile: "FROM node:22.23.3-alpine\nFROM docker.io/library/node:24.22.0\n" });
  assert.equal(out.findings.length, 2, problems(out).join("\n"));
  assert.match(out.findings[0].problem, /22\.23\.4/);
  assert.match(out.findings[1].problem, /24\.22\.1/);
});

test("Dockerfile: una rama sin soporte (no está en la tabla) bloquea", () => {
  const out = run({ Dockerfile: "FROM node:20.20.2-slim\nFROM node:23.11.1\n" });
  assert.equal(out.findings.length, 2, problems(out).join("\n"));
  assert.ok(out.findings.every((f) => /sin soporte/.test(f.problem)));
});

test("Dockerfile: node@sha256 sin etiqueta bloquea (no se sabe qué versión es)", () => {
  const out = run({ Dockerfile: "FROM node@sha256:" + "b".repeat(64) + "\n" });
  assert.equal(out.findings.length, 1);
  assert.match(out.findings[0].problem, /sin etiqueta/);
});

test("Dockerfile: otras imágenes, FROM de una etapa anterior y mayúsculas mezcladas", () => {
  const out = run({
    Dockerfile: "FROM alpine:3.22\nfrom node:22.23.4 as deps\nFROM deps AS final\nFROM nodered/node-red:4\n",
  });
  assert.deepEqual(out.findings, [], problems(out).join("\n"));
});

test("Dockerfile: el escape `runtime-gate: allow` con motivo deja pasar la línea; sin motivo no", () => {
  const out = run({
    Dockerfile: [
      "FROM node:20-slim # runtime-gate: allow fixture de un test que reproduce Node 20",
      "FROM node:20-slim # runtime-gate: allow",
    ].join("\n"),
  });
  assert.equal(out.findings.length, 1, problems(out).join("\n"));
  assert.equal(out.findings[0].line, 2);
  assert.equal(out.allowed.length, 1);
});

// --- .nvmrc / .node-version -----------------------------------------------------------------------
test(".nvmrc: rama soportada sola pasa (nvm instala la última); exacta vieja o rama sin soporte bloquea", () => {
  assert.deepEqual(run({ ".nvmrc": "22\n" }).findings, []);
  assert.deepEqual(run({ ".node-version": "v24.22.1\n" }).findings, []);
  const out = run({ ".nvmrc": "22.23.3\n", "app/.node-version": "20\n" });
  assert.equal(out.findings.length, 2, problems(out).join("\n"));
});

test(".nvmrc: una versión parcial (rama.minor) bloquea: instala la última de ese minor, que puede quedar por debajo", () => {
  const out = run({ ".nvmrc": "22.20\n", "b/.node-version": "v24.21\n" });
  assert.equal(out.findings.length, 2, problems(out).join("\n"));
  assert.ok(out.findings.every((f) => /parcial/.test(f.problem)), problems(out).join("\n"));
  assert.deepEqual(run({ ".nvmrc": "22.x\n" }).findings, []);
});

// --- setup-node en workflows ----------------------------------------------------------------------
const wf = (withBlock) => `name: ci\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/setup-node@v5\n        with:\n${withBlock}\n`;

test("workflow: rama sola con check-latest: true pasa; sin check-latest bloquea", () => {
  assert.deepEqual(run({ ".github/workflows/ci.yml": wf('          node-version: "22"\n          check-latest: true') }).findings, []);
  const out = run({ ".github/workflows/ci.yml": wf('          node-version: "22"\n          cache: npm') });
  assert.equal(out.findings.length, 1, problems(out).join("\n"));
  assert.match(out.findings[0].problem, /check-latest/);
});

test("workflow: versión exacta vieja o rama sin soporte bloquea aunque lleve check-latest", () => {
  const out = run({
    ".github/workflows/a.yml": wf("          node-version: 22.23.3\n          check-latest: true"),
    ".github/workflows/b.yaml": wf("          node-version: '20'\n          check-latest: true"),
  });
  assert.equal(out.findings.length, 2, problems(out).join("\n"));
});

test("workflow: una versión parcial (rama.minor) bloquea aunque lleve check-latest; rama.x con check-latest pasa", () => {
  const out = run({ ".github/workflows/ci.yml": wf('          node-version: "22.20"\n          check-latest: true') });
  assert.equal(out.findings.length, 1, problems(out).join("\n"));
  assert.match(out.findings[0].problem, /parcial/);
  assert.deepEqual(run({ ".github/workflows/ci.yml": wf("          node-version: 22.x\n          check-latest: true") }).findings, []);
});

test("workflow: un node-version que no es una versión (rango, alias, lts) bloquea aunque lleve check-latest", () => {
  for (const value of ["'^20'", "'~22.20.0'", "lts/iron", "'>=18 <21'", "'lts/*'", "latest"]) {
    const out = run({ ".github/workflows/ci.yml": wf(`          node-version: ${value}\n          check-latest: true`) });
    assert.equal(out.findings.length, 1, `${value}: ${problems(out).join("\n")}`);
    assert.match(out.findings[0].problem, /no se puede juzgar/, value);
  }
});

test("workflow: check-latest de OTRO paso no vale para este", () => {
  const two = `name: ci\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/setup-node@v5\n        with:\n          node-version: "22"\n      - uses: actions/setup-node@v5\n        with:\n          node-version: "24"\n          check-latest: true\n`;
  const out = run({ ".github/workflows/ci.yml": two });
  assert.equal(out.findings.length, 1, problems(out).join("\n"));
  assert.equal(out.findings[0].line, 9);
});

test("workflow: node-version de una expresión (${{ … }}) no se puede juzgar y bloquea", () => {
  const out = run({ ".github/workflows/ci.yml": wf("          node-version: ${{ matrix.node }}\n          check-latest: true") });
  assert.equal(out.findings.length, 1);
  assert.match(out.findings[0].problem, /expresión/);
});

// --- Ronda 3 del Guardián: formas válidas que R1 y R2 no probaron ---------------------------------
const step = (body) => `name: ci\non: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n${body}\n`;

test("workflow: node-version en estilo flujo, con la clave entre comillas o el paso en una línea también se juzga", () => {
  const malos = {
    ".github/workflows/a.yml": step('      - uses: actions/setup-node@v5\n        with: { node-version: "20", check-latest: true }'),
    ".github/workflows/b.yml": step("      - uses: actions/setup-node@v5\n        with: {node-version: 20}"),
    ".github/workflows/c.yml": step('      - uses: "actions/setup-node@v5"\n        with:\n          "node-version": 20\n          check-latest: true'),
    ".github/workflows/d.yml": step('      - { uses: actions/setup-node@v5, with: { node-version: "20", check-latest: true } }'),
    ".github/workflows/e.yml": step("      - uses: actions/setup-node@v5\n        with: {\n          node-version: 20 }"),
  };
  const out = run(malos);
  assert.deepEqual(out.findings.map((f) => f.file).sort(), Object.keys(malos).sort(), problems(out).join("\n"));
  const buenos = run({
    ".github/workflows/a.yml": step('      - uses: actions/setup-node@v5\n        with: { node-version: "22", check-latest: true }'),
    ".github/workflows/d.yml": step('      - { uses: actions/setup-node@v5, with: { "node-version": "22", "check-latest": true } }'),
  });
  assert.deepEqual(buenos.findings, [], problems(buenos).join("\n"));
});

test("workflow: node-version-file sin check-latest bloquea si el fichero da una rama; con versión exacta o check-latest pasa", () => {
  const rama = run({ ".nvmrc": "22\n", ".github/workflows/ci.yml": wf("          node-version-file: .nvmrc") });
  assert.equal(rama.findings.length, 1, problems(rama).join("\n"));
  assert.match(rama.findings[0].problem, /check-latest/);
  assert.deepEqual(run({ ".nvmrc": "22.23.4\n", ".github/workflows/ci.yml": wf("          node-version-file: .nvmrc") }).findings, []);
  assert.deepEqual(
    run({ ".nvmrc": "22\n", ".github/workflows/ci.yml": wf("          node-version-file: .nvmrc\n          check-latest: true") }).findings,
    [],
  );
});

test("acciones compuestas (.github/actions/*/action.yml) se miran como los workflows", () => {
  const out = run({ ".github/actions/setup/action.yml": "runs:\n  using: composite\n  steps:\n    - uses: actions/setup-node@v5\n      with:\n        node-version: 20\n" });
  assert.equal(out.findings.length, 1, problems(out).join("\n"));
});

test(".tool-versions (asdf/mise): nodejs o node con versión vieja bloquea, al día pasa", () => {
  assert.equal(run({ ".tool-versions": "python 3.12.1\nnodejs 20.10.0\n" }).findings.length, 1);
  assert.equal(run({ "sub/.tool-versions": "node 22.20\n" }).findings.length, 1);
  assert.deepEqual(run({ ".tool-versions": "nodejs 22.23.4\n" }).findings, []);
  assert.deepEqual(run({ ".tool-versions": "python 3.12.1\n" }).findings, []);
});

test("Dockerfile con otro nombre (Dockerfile-prod, Dockerfile_prod, Containerfile, app.dockerfile) también se mira", () => {
  const files = { "Dockerfile-prod": "FROM node:20\n", "Dockerfile_prod": "FROM node:20\n", Containerfile: "FROM node:20\n", "web/app.dockerfile": "FROM node:20\n" };
  const out = run(files);
  assert.deepEqual(out.findings.map((f) => f.file).sort(), Object.keys(files).sort(), problems(out).join("\n"));
});

test("la imagen oficial servida por otro registro (mirror.gcr.io, public.ecr.aws) es node; una de otro autor no", () => {
  const out = run({
    Dockerfile: "FROM mirror.gcr.io/library/node:20\nFROM public.ecr.aws/docker/library/node:20\nFROM registry.example.com:5000/node:20\nFROM ghcr.io/alguien/node:20\n",
  });
  assert.deepEqual(out.findings.map((f) => f.line), [1, 2, 3], problems(out).join("\n"));
});

// --- Ronda 4 del Guardián: setup-node sin versión legible y FROM partido --------------------------
test("workflow: setup-node sin node-version que se pueda leer (alias, merge key o ninguno) bloquea", () => {
  const casos = {
    ".github/workflows/alias.yml": "x: &w {node-version: 20}\n" + step("      - uses: actions/setup-node@v5\n        with: *w"),
    ".github/workflows/merge.yml": "x: &w {node-version: 20}\n" + step("      - uses: actions/setup-node@v5\n        with: {<<: *w}"),
    ".github/workflows/nada.yml": step("      - uses: actions/setup-node@v4"),
  };
  const out = run(casos);
  assert.deepEqual(out.findings.map((f) => f.file).sort(), Object.keys(casos).sort(), problems(out).join("\n"));
});

test("workflow: 'uses' con otras mayúsculas también es setup-node; check-latest en env: o en name: no cuenta", () => {
  const out = run({
    ".github/workflows/may.yml": step('      - uses: Actions/Setup-Node@v4\n        with:\n          node-version: "20"'),
    ".github/workflows/env.yml": step('      - name: instalar con check-latest: true\n        uses: actions/setup-node@v5\n        env:\n          check-latest: true\n        with:\n          node-version: "22"'),
  });
  assert.deepEqual(out.findings.map((f) => f.file).sort(), [".github/workflows/env.yml", ".github/workflows/may.yml"], problems(out).join("\n"));
});

test("workflow: un node-version dentro del script de run: | no es el input de setup-node", () => {
  const out = run({ ".github/workflows/run.yml": step('      - uses: actions/setup-node@v5\n        with:\n          node-version: "20"\n      - run: |\n          echo "node-version: 22"') });
  assert.equal(out.findings.length, 1, problems(out).join("\n"));
  const cola = run({ ".github/workflows/run2.yml": step('      - name: x\n        run: |\n          echo node-version: 22\n          echo check-latest: true\n        uses: actions/setup-node@v5\n        with:\n          node-version: "22"') });
  assert.equal(cola.findings.length, 1, problems(cola).join("\n"));
});

test("action.yml en la raíz del repo (acción publicada) se mira", () => {
  const out = run({ "action.yml": "runs:\n  using: composite\n  steps:\n    - uses: actions/setup-node@v5\n      with:\n        node-version: 20\n" });
  assert.equal(out.findings.length, 1, problems(out).join("\n"));
});

test("Dockerfile: FROM partido con «\\», COPY --from=node y RUN --mount=from=node también se juzgan", () => {
  const out = run({
    "a/Dockerfile": "FROM \\\n  node:20 AS base\n",
    "b/Dockerfile": "FROM alpine:3.22\nCOPY --from=node:20 /usr/local/bin/node /usr/local/bin/node\n",
    "c/Dockerfile": "FROM alpine:3.22\nRUN --mount=type=bind,from=node:20,source=/usr/local/bin,target=/n true\n",
    "d/Dockerfile": "FROM node:22.23.4 AS deps\nFROM alpine:3.22\nCOPY --from=deps /x /x\n",
  });
  assert.deepEqual(out.findings.map((f) => `${f.file}:${f.line}`).sort(), ["a/Dockerfile:1", "b/Dockerfile:2", "c/Dockerfile:2"], problems(out).join("\n"));
});

// --- Ronda 5 del Guardián: imagen de un ARG y continuaciones con comentarios ----------------------
test("Dockerfile: la imagen que sale de un ARG con valor por defecto se juzga; sin valor, no se puede juzgar", () => {
  const out = run({
    "a/Dockerfile": "ARG BASE=node:20\nFROM $BASE\n",
    "b/Dockerfile": "ARG BASE=node:20\nFROM ${BASE} AS x\n",
    "c/Dockerfile": "ARG V=20\nFROM node:${V}-alpine\n",
    "d/Dockerfile": "ARG BASE\nFROM $BASE\n",
  });
  assert.deepEqual(out.findings.map((f) => f.file).sort(), ["a/Dockerfile", "b/Dockerfile", "c/Dockerfile", "d/Dockerfile"], problems(out).join("\n"));
  const buenos = run({
    "a/Dockerfile": "ARG BASE=node:22.23.4-alpine\nFROM $BASE\n",
    "b/Dockerfile": "ARG BASE=alpine:3.22\nFROM ${BASE}\n",
    "c/Dockerfile": "ARG V=22.23.4\nFROM node:${V}-alpine\n",
  });
  assert.deepEqual(buenos.findings, [], problems(buenos).join("\n"));
});

test("Dockerfile: un comentario o una línea vacía dentro de la continuación no la corta; la directiva escape se respeta", () => {
  const out = run({
    "a/Dockerfile": "FROM \\\n# la base\n  node:20\n",
    "b/Dockerfile": "FROM \\\n\n  node:20\n",
    "c/Dockerfile": "# escape=`\nFROM `\n  node:20\n",
  });
  assert.deepEqual(out.findings.map((f) => `${f.file}:${f.line}`).sort(), ["a/Dockerfile:1", "b/Dockerfile:1", "c/Dockerfile:2"], problems(out).join("\n"));
});

// --- Alcance --------------------------------------------------------------------------------------
test("node_modules y .git no se miran", () => {
  const out = run({
    "node_modules/pkg/Dockerfile": "FROM node:18\n",
    ".git/Dockerfile": "FROM node:18\n",
  });
  assert.deepEqual(out.findings, []);
  assert.deepEqual(out.checked, []);
});

// --- Errores --------------------------------------------------------------------------------------
test("tabla ilegible o directorio inexistente: exit 2, nunca un JSON vacío que pase por limpio", () => {
  const { dir } = project({ Dockerfile: "FROM node:22-alpine\n" });
  const bad = join(dir, "bad.json");
  writeFileSync(bad, "{ no es json");
  assert.equal(spawnSync(process.execPath, [SCRIPT, dir, "--table", bad], { encoding: "utf8" }).status, 2);
  assert.equal(spawnSync(process.execPath, [SCRIPT, join(dir, "no-existe")], { encoding: "utf8" }).status, 2);
  assert.equal(spawnSync(process.execPath, [SCRIPT], { encoding: "utf8" }).status, 2);
});

// --- El preset real -------------------------------------------------------------------------------
test("presets/runtimes.json: cada mínimo es una versión exacta de su propia rama", () => {
  const preset = JSON.parse(readFileSync(PRESET, "utf8"));
  const minimos = Object.entries(preset.node.minimos);
  assert.ok(minimos.length > 0);
  for (const [rama, version] of minimos) {
    assert.match(version, /^\d+\.\d+\.\d+$/, `${rama}: ${version}`);
    assert.equal(version.split(".")[0], rama, `${rama}: ${version}`);
  }
  assert.match(preset.node.actualizado, /^\d{4}-\d{2}-\d{2}$/);
  assert.match(preset.node.aviso, /^https:\/\//);
});

test("sin --table usa presets/runtimes.json", () => {
  const { dir } = project({ Dockerfile: "FROM node:22.0.0\n" });
  const r = spawnSync(process.execPath, [SCRIPT, dir], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(JSON.parse(r.stdout).findings.length, 1);
});
