#!/usr/bin/env bash
# PreToolUse gate — seguridad determinista ENFORCED en todos los proyectos (T-061-B).
#
# Espejo EXACTO de anti-slop-gate.sh. La doctrina del Guardián (doctrina_guardian.md) no debe
# depender de que el agente SE ACUERDE: este hook la FUERZA en el límite real, cuando código de
# producción va a entrar al repo. Dos comprobaciones, ambas deterministas y fail-open:
#   (1) PRESENCIA: si hay ficheros de código staged dentro de un proyecto JS/TS (tiene package.json)
#       que NO lleva el gate de seguridad (.security-gate) → BLOQUEA y pide instalarlo con el
#       scaffolder de la skill security-gate.
#   (2) ESCANEO LIGERO (opcional, fail-open): si gitleaks está presente, corre un
#       `gitleaks git --staged` rápido; bloquea SOLO ante secreto. Si gitleaks no está, NO bloquea.
# El pass/fail exhaustivo (secretos+SAST+deps) queda en CI (gate duro de merge); aquí van los
# "dientes" rápidos al commit (presencia + secreto staged).
#
# Entrada (stdin, JSON PreToolUse): { tool_name, tool_input:{ command }, ... }
# Bloqueo: { hookSpecificOutput:{ ..., permissionDecision:"deny", permissionDecisionReason } } (exit 0).
#
# Filosofía SRE: **fail-open**. Sin jq/git, ante duda o error de uso → DEJA PASAR. Solo bloquea cuando
# determina POSITIVAMENTE el problema. Escape: [skip-traj] en el mensaje del commit; por línea:
# `gitleaks:allow` (secreto) o `// nosemgrep: <id>` (SAST en CI).

# Bash 3.2-safe: macOS trae /bin/bash 3.2.57 (GPLv3, congelado). Si corremos bajo <4 y hay un bash 4+
# (Homebrew), re-ejecutamos con él. `exec` preserva stdin (el JSON del hook no se pierde). Centinela
# `_GATE_REEXEC` evita bucle infinito. Si no hay bash 4+, seguimos: la lógica de abajo es 3.2-safe.
if [ -z "${_GATE_REEXEC:-}" ] && [ "${BASH_VERSINFO:-0}" -lt 4 ]; then
  for _b in /opt/homebrew/bin/bash /usr/local/bin/bash; do
    if [ -x "$_b" ]; then export _GATE_REEXEC=1; exec "$_b" "$0" "$@"; fi
  done
fi

set -u

input="$(cat)"

command -v jq >/dev/null 2>&1 || exit 0
tool="$(printf '%s' "$input" | jq -r '.tool_name // empty' 2>/dev/null)"
[ "$tool" = "Bash" ] || exit 0
cmd="$(printf '%s' "$input" | jq -r '.tool_input.command // empty' 2>/dev/null)"
# T-221: mismo detector que los gates hermanos (T-14A), con las opciones GLOBALES entre `git` y
# `commit`: sin él, `git -C <repo> commit` —la forma de commitear en sesiones multi-repo— ni se veía.
# T-221 (ADV-6): el detector de `git … commit` es el común de `lib/commit-repo.sh`, que entiende la
# continuación de línea (`git -C R \<salto> commit`); antes cada hook llevaba su copia del patrón.
# shellcheck source=lib/commit-repo.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/commit-repo.sh" 2>/dev/null || exit 0   # sin lib → fail-open
es_git_commit "$cmd" || exit 0
printf '%s' "$cmd" | grep -q '\[skip-traj\]' && exit 0

command -v git >/dev/null 2>&1 || exit 0
# T-221: el repo es el DEL COMANDO (`cd <repo> && git commit`, `git -C <repo> commit`), no el cwd de
# la sesión, que en sesiones multi-repo no es un repo o es otro. Lo indeterminado sigue en fail-open,
# pero avisado (stderr + `systemMessage`). Ver `lib/commit-repo.sh`.
cwd_ev="$(printf '%s' "$input" | jq -r '.cwd // empty' 2>/dev/null)"
repo_del_commit "$cmd" "$cwd_ev" || { commit_repo_avisar security-gate --system-message; exit 0; }
root="$COMMIT_REPO"
# T-221 ronda 4: lo que el gate NO ve de este commit (varios commits, staging decidido en el propio
# comando) se avisa al salir, junto a la decisión que tome: nunca en silencio.
commit_repo_nota_al_salir security-gate
[ -n "$root" ] || exit 0

# La decisión —(1) presencia del gate en cada proyecto JS/TS tocado, (2) escaneo— vive en
# `lib/commit-gates.sh` (T-223), la MISMA que aplica el hook de git `hooks/git/commit-msg`.
# shellcheck source=lib/commit-gates.sh
. "$(dirname "${BASH_SOURCE[0]}")/lib/commit-gates.sh" 2>/dev/null || exit 0   # sin lib → fail-open
staged="$(_cg_staged "$root")"
[ -n "$staged" ] || exit 0
# ROOT del FRAMEWORK: de ahí sale el escáner y el preset de gitleaks, nunca del repo commiteado (T-223).
ROOT="${FRAMEWORK_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}"
gate_seguridad "$ROOT" "$root" "$staged" "" "$cmd" && exit 0

jq -n --arg r "$GATE_MOTIVO" '{
  hookSpecificOutput: {
    hookEventName: "PreToolUse",
    permissionDecision: "deny",
    permissionDecisionReason: $r
  }
}'
exit 0
