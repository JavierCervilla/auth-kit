// =============================================================================
// Preset ESLint anti-slop (flat config) — skill `code-anti-slop`.
// Gate DETERMINISTA de slop en backend/lógica TS: lo que `tsc` no atrapa
// (duplicación, complejidad, escapes de tipo, ciclos de import, console olvidado).
//
// USO (en el eslint.config.mjs del proyecto):
//   import antiSlop from "<ruta>/eslint.anti-slop.mjs";
//   export default [ ...compat.extends("next/core-web-vitals","next/typescript"), ...antiSlop ];
//
// Requiere devDeps: eslint-plugin-sonarjs, eslint-plugin-import.
// (Las reglas @typescript-eslint/* las aporta `next/typescript`; en proyectos
//  no-Next, añade @typescript-eslint/parser + plugin y un languageOptions.parser.)
//
// Filosofía RATCHET: las reglas de alto valor y baja fricción van como `error`;
// las ruidosas (duplicación/complejidad) entran como `warn` para no romper un
// codebase existente de golpe — se suben a `error` cuando el proyecto está limpio.
// =============================================================================
import sonarjs from "eslint-plugin-sonarjs";
import importPlugin from "eslint-plugin-import";

export default [
  {
    plugins: { sonarjs, import: importPlugin },
    rules: {
      // --- Escapes de tipo: error (alto valor, baja fricción) ---
      "@typescript-eslint/no-explicit-any": "error",
      // --- console olvidado: error salvo warn/error intencionales ---
      "no-console": ["error", { allow: ["warn", "error"] }],
      // --- Duplicación / sobre-ingeniería: warn (ratchet → error) ---
      "sonarjs/no-identical-functions": "warn",
      "sonarjs/no-duplicate-string": ["warn", { threshold: 5 }],
      // --- Complejidad cognitiva: warn (ratchet → error) ---
      "sonarjs/cognitive-complexity": ["warn", 15],
      // --- Ciclos de import: warn (necesita resolver TS para alias) ---
      "import/no-cycle": ["warn", { maxDepth: 6 }],
    },
  },
  {
    // Relaja en código no-de-producción: generadores/seed, tests y configs.
    files: [
      "**/scripts/**",
      "**/prisma/**",
      "**/*.test.*",
      "**/tests/**",
      "**/*.config.*",
      "**/*.setup.*",
    ],
    rules: {
      "no-console": "off",
      "@typescript-eslint/no-explicit-any": "off",
      "sonarjs/cognitive-complexity": "off",
      "sonarjs/no-duplicate-string": "off",
      "sonarjs/no-identical-functions": "off",
    },
  },
];
