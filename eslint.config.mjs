import tseslint from "typescript-eslint";

import antiSlop from "./eslint.anti-slop.mjs";

export default [
  { ignores: ["dist/", "node_modules/", ".english-gate/", ".claude/", ".security-gate-presets/"] },
  ...tseslint.configs.recommended,
  ...antiSlop,
];
