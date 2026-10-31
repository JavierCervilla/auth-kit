# shellcheck shell=bash
# shellcheck disable=SC2034  # VAULT_DIR/VAULT_ORIGEN/VAULT_ERROR son la salida de la lib: las leen quienes la cargan
# lib/vault.sh — ¿dónde está el vault? (T-295, épica T-294: el vault se muda a JavierCervilla/AgenticVault).
#
# Todo lo que lee o escribe el vault (retome, arranque, compactación, gates, scripts) pregunta aquí en vez de dar por
# hecho `$ROOT/Contexto_Base_SRE`. Su gemelo en node es `vault-root.mjs`: misma tabla de casos, y
# `tests/vault-resolver.test.sh` corre los dos contra los mismos fixtures.
#
# Orden de búsqueda:
#   1. `AGENTIC_VAULT_ROOT`. Si está definida y NO es un vault → error (rc 2): no se cae al siguiente paso, porque una
#      variable mal puesta resuelta en silencio a otro sitio escribiría en el vault equivocado.
#   2. El checkout hermano `$(dirname fw)/AgenticVault` (en la nube, el repo añadido a la sesión), si es un vault.
#   3. `$fw/Contexto_Base_SRE`, salvo que exista el centinela `$fw/.vault-movido` (lo pone el corte, T-296). Es lo de
#      siempre, exista o no la carpeta: hasta el corte el framework se comporta exactamente como antes.
# «Ser un vault» = tener `00_INDEX.md` y `trayectorias/`: un AgenticVault recién creado y vacío no cuenta.
#
# API (bash 3.2-safe, no escribe en stdout salvo `vault_root`):
#   vault_resolver <fw> → rc 0/1/2 y deja VAULT_DIR, VAULT_ORIGEN (env|hermano|legacy) y VAULT_ERROR.
#   vault_root <fw>     → imprime VAULT_DIR (para `$(…)`), mismo rc.
#   vault_es_externo <fw> → rc 0 externo / 1 interno / 2 error, y deja VAULT_TOP (T-301; ver la función).

VAULT_MSG_SIN="no encuentro el vault: añade JavierCervilla/AgenticVault a la sesión o exporta AGENTIC_VAULT_ROOT"

vault_es() { [ -n "${1:-}" ] && [ -d "$1" ] && [ -f "$1/00_INDEX.md" ] && [ -d "$1/trayectorias" ]; }

# Ruta física de un directorio, sin que la toquen CDPATH ni el `cd -` (que salta a $OLDPWD): una relativa se ancla con
# `./` y CDPATH se vacía para ese `cd`. Sin esto, con un CDPATH exportado `cd` imprime la ruta y VAULT_DIR salía con dos
# líneas, distinta de la de node (adversario de T-295, H2).
_vault_fisica() {
  local p="$1"
  case "$p" in /*) ;; *) p="./$p" ;; esac
  (CDPATH='' cd -P -- "$p" 2>/dev/null && pwd -P)
}

vault_resolver() {
  local fw="${1:-}" d
  VAULT_DIR=""; VAULT_ORIGEN=""; VAULT_ERROR=""
  if [ -n "${AGENTIC_VAULT_ROOT:-}" ]; then
    if vault_es "$AGENTIC_VAULT_ROOT"; then
      VAULT_DIR="$(_vault_fisica "$AGENTIC_VAULT_ROOT")"; VAULT_ORIGEN="env"; return 0
    fi
    VAULT_ERROR="AGENTIC_VAULT_ROOT=$AGENTIC_VAULT_ROOT no es un vault (le falta 00_INDEX.md o trayectorias/): corrígela o quítala"
    return 2
  fi
  [ -n "$fw" ] && [ -d "$fw" ] || { VAULT_ERROR="$VAULT_MSG_SIN"; return 1; }
  fw="$(_vault_fisica "$fw")"
  d="$(dirname "$fw")/AgenticVault"
  if vault_es "$d"; then
    VAULT_DIR="$(_vault_fisica "$d")"; VAULT_ORIGEN=hermano; return 0
  fi
  if [ ! -e "$fw/.vault-movido" ]; then
    VAULT_DIR="$fw/Contexto_Base_SRE"; VAULT_ORIGEN=legacy; return 0
  fi
  VAULT_ERROR="$VAULT_MSG_SIN"
  return 1
}

vault_root() {
  vault_resolver "${1:-}" || return $?
  printf '%s' "$VAULT_DIR"
}

# vault_es_externo <fw> — ¿el vault vive en SU PROPIO repo git, fuera del del framework? (T-301). Decide el modo de
# scaffold, close, vault-push y vault-rescue: externo = planes directos al `main` del vault; interno = como siempre, en
# el PR. Solo bash: ningún script de node lo necesita.
#   rc 0 externo (VAULT_TOP = raíz del repo del vault, que es el propio vault);
#   rc 1 interno: legacy, o un vault de la variable/hermano que cae dentro del repo del framework;
#   rc 2 error (VAULT_ERROR): sin vault, variable inválida, o un vault externo que no es la raíz de un repo git (no hay
#        `main` al que publicar sin arrastrar el repo que lo contiene).
vault_es_externo() {
  local fw="${1:-}" ft
  VAULT_TOP=""
  vault_resolver "$fw" || return 2
  [ "$VAULT_ORIGEN" != "legacy" ] || return 1
  VAULT_TOP="$(_vault_git_top "$VAULT_DIR")"
  ft="$(_vault_git_top "$fw")"
  if [ -n "$VAULT_TOP" ] && [ "$VAULT_TOP" = "$ft" ]; then return 1; fi
  if [ "$VAULT_TOP" != "$VAULT_DIR" ]; then
    VAULT_ERROR="el vault ($VAULT_DIR) no es la raíz de un repo git: clónalo como repo propio (JavierCervilla/AgenticVault)"
    VAULT_TOP=""
    return 2
  fi
  return 0
}

# Raíz física del repo git que contiene <dir>, o vacío. Sin el entorno que git exporta a sus hooks: con GIT_DIR puesto
# `rev-parse` respondería por otro repo.
_vault_git_top() {
  local t
  t="$(cd "$1" 2>/dev/null && env -u GIT_DIR -u GIT_WORK_TREE git rev-parse --show-toplevel 2>/dev/null)" || return 0
  [ -n "$t" ] && _vault_fisica "$t"
}
