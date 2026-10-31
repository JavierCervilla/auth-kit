#!/usr/bin/env bash
# lib/retome.sh — resolución del punto de retome, compartida por los hooks que lo leen o lo escriben
# (`session-start.sh`, `pre-compact.sh`, `trajectory-gate.sh`). E-RET/RET-A.
#
# POR QUÉ EXISTE. El retome era UN fichero con N escritores: el propio frontmatter documentaba a mano
# «Escalar con TRES escritores esta semana… se queda quien escribió el último» y «DOS SESIONES EN
# VUELO y la sentinela es UN escalar». Eso no es un caso raro: es el modo normal de trabajo. Tres
# síntomas, uno detrás de otro:
#   1. la sentinela `trayectoria_activa` la pisa la última sesión que escribe;
#   2. dos ramas que tocan el fichero chocan al mergear;
#   3. `SessionStart` re-inyectaba el fichero ENTERO → una sesión de Pokelock recibía en su contexto
#      el estado vivo de ft_ai_learn. El retome existía justo para no contaminar el contexto.
#
# LA CLAVE ES LA SESIÓN, NO EL PROYECTO. Partirlo por proyecto no cierra el caso real que ya ocurrió
# (dos sesiones a la vez sobre el mismo proyecto). Cada sesión tiene su contenedor, su copia de
# trabajo y su trayectoria en vuelo, y los hooks **ya reciben `session_id` por stdin**: la clave
# natural estaba ahí desde el principio.
#
# CÓMO SE USA (sourcing, no ejecución):
#   . "$(dirname "${BASH_SOURCE[0]}")/lib/retome.sh"
#   f="$(retome_file "$ROOT" "$session_id")"      # el que hay que LEER (sesión, o legacy)
#   f="$(retome_ensure "$ROOT" "$session_id")"    # el de la sesión, creándolo si falta
#
# COMPATIBILIDAD. Mientras haya sesiones vivas con el fichero antiguo, `retome_file` cae al legacy
# `punto_de_retome_sesion.md` si la sesión no tiene el suyo. Sin `session_id` (o vacío) → legacy.
# El legacy no se borra: se queda como archivo y como red de los hooks viejos.
#
# DÓNDE ESTÁ EL VAULT (T-295). El retome vive en el vault, y el vault ya no es por fuerza `$ROOT/Contexto_Base_SRE`: lo
# dice `lib/vault.sh` (AGENTIC_VAULT_ROOT → `../AgenticVault` → el de siempre). Sin vault, las rutas del retome no
# existen (rc 1 / vacío) y quien las pide decide: los gates fallan en cerrado, el arranque avisa. Los MARCADORES del
# handshake con PreCompact no son narrativa sino estado de sesión: viven en `$ROOT/.claude/state/needs_resume/`, junto
# a la sentinela, para que un `git add -A` en el repo del vault no se los lleve.
if ! command -v vault_resolver >/dev/null 2>&1; then
  # shellcheck source=lib/vault.sh
  . "$(dirname "${BASH_SOURCE[0]}")/vault.sh" 2>/dev/null || {
    # Copia parcial de lib/ sin vault.sh (una instalación de antes de T-295 en un proyecto, o un fixture): el vault de
    # siempre, que es exactamente lo que hacía esta lib antes.
    vault_resolver() { VAULT_DIR="${1:-}/Contexto_Base_SRE"; VAULT_ORIGEN="legacy"; VAULT_ERROR=""; return 0; }
    vault_root() { vault_resolver "${1:-}"; printf '%s' "$VAULT_DIR"; }
  }
fi

# ── LA SENTINELA (T-214) ──────────────────────────────────────────────────────────────────────────
#
# `trayectoria_activa` vivía en el FRONTMATTER del retome, que está versionado. El docblock de arriba
# enumera los tres síntomas de tener la sentinela en un fichero compartido; RET-A partió el fichero por
# sesión y cerró el 1 y el 3, pero el **2 — «dos ramas que tocan el fichero chocan al mergear»** —
# siguió vivo, porque partir no es desversionar. Medido: tres conflictos en una noche, uno de ellos con
# el MISMO valor a ambos lados.
#
# Y lo más caro no eran los conflictos: era que **la sentinela mentía**. De 33 retomes del vault, 4
# declaraban una trayectoria activa y las CUATRO apuntaban a trayectorias `done`. Si una de esas
# sesiones reviviera, el gate dejaría pasar código de producción amparado en una trayectoria cerrada
# hace semanas — dientes falsos, en el gate que da nombre al modo de operación.
#
# Ahora el valor vive en un SIDECAR sin versionar, uno por sesión. El retome se queda con la narrativa
# (que sí es SoT del vault); lo que sale de git es el escalar efímero. Un fichero ignorado que se
# pierde al reciclarse el contenedor es EXACTAMENTE lo correcto para estado de sesión: una sesión nueva
# no tiene trayectoria en vuelo.

sentinela_dir() { printf '%s/.claude/state/trayectoria-activa' "$1"; }

# La sesión de quien llama, en UN sitio (T-284): `CLAUDE_SESSION_ID` (la de los hooks, o la que se pasa a mano) y, si
# falta, `CLAUDE_CODE_SESSION_ID`, la que trae el Bash de Claude Code y con la que el gate `commit-msg` busca la
# sentinela. Cada script la resolvía por su cuenta y solo con la primera: desde el Bash de Claude Code,
# trajectory-create no encendía la sentinela y trajectory-close no la apagaba. Vacía si no hay ninguna: nunca se adivina.
sesion_actual() { printf '%s' "${CLAUDE_SESSION_ID:-${CLAUDE_CODE_SESSION_ID:-}}"; }

# Ruta del sidecar de ESTA sesión (exista o no). Reusa `retome_slug`, así que hereda su saneado.
sentinela_file() {
  local root="$1" sid="${2:-}"
  [ -n "$sid" ] || return 1
  printf '%s/%s' "$(sentinela_dir "$root")" "$(retome_slug "$sid")"
}

# Valor de la sentinela: el TRAJECTORY_ID, o `none`. Un sidecar AUSENTE es `none` y no un error: es la
# respuesta correcta a «¿hay trayectoria en vuelo?» cuando nadie ha declarado ninguna. Quien necesite
# distinguir «no hay sesión del framework» de «no hay trayectoria» mira el RETOME, que es el marcador
# de lo primero — así el fail-open de los gates sigue colgando de la misma señal que antes.
sentinela_leer() {
  local root="$1" sid="${2:-}" f v
  f="$(sentinela_file "$root" "$sid")" || { printf 'none'; return 0; }
  [ -f "$f" ] || { printf 'none'; return 0; }
  v="$(tr -d '[:space:]' < "$f" 2>/dev/null)"
  case "$v" in
    "" | none | None | NONE | null) printf 'none' ;;
    *) printf '%s' "$v" ;;
  esac
}

# Fija la sentinela (escribe el sidecar). `none` para apagarla. Devuelve 1 si no se pudo escribir, para
# que quien cierra una trayectoria pueda cantarlo en vez de dar por hecho que quedó apagada.
sentinela_fijar() {
  local root="$1" sid="${2:-}" val="${3:-none}" f dir
  f="$(sentinela_file "$root" "$sid")" || return 1
  dir="$(sentinela_dir "$root")"
  mkdir -p "$dir" 2>/dev/null || return 1
  printf '%s\n' "$val" > "$f" 2>/dev/null || return 1
  return 0
}

# Directorio de retomes por sesión, en el vault que resuelva `vault_root`. rc 1 si no hay vault.
retome_dir() {
  local v
  v="$(vault_root "$1")" || return 1
  printf '%s/04_Logs_de_Trayectoria/retome' "$v"
}

# Fichero legacy compartido (el de antes de RET-A). rc 1 si no hay vault.
retome_legacy() {
  local v
  v="$(vault_root "$1")" || return 1
  printf '%s/04_Logs_de_Trayectoria/punto_de_retome_sesion.md' "$v"
}

# Estado de sesión que no es narrativa: fuera del vault (T-295).
retome_state_dir() { printf '%s/.claude/state/needs_resume' "$1"; }

# Marcador del handshake PreCompact → SessionStart ("vengo de compactar, re-inyecta"). Es por sesión
# por el mismo motivo que el retome: era UN fichero, así que la sesión que arrancara primero se lo
# comía (lo consume al leerlo) y la que de verdad había compactado no veía nada.
retome_marker() {
  local root="$1" sid="${2:-}"
  if [ -n "$sid" ]; then
    printf '%s/.needs_resume-%s' "$(retome_state_dir "$root")" "$(retome_slug "$sid")"
  else
    retome_marker_legacy "$root"
  fi
}
retome_marker_legacy() { printf '%s/.needs_resume' "$(retome_state_dir "$1")"; }

# Normaliza un session_id para usarlo como nombre de fichero: el harness manda cosas como
# `session_01Y8…` o un UUID, pero no confiamos en que siempre sea inocuo (una `/` bastaría para
# escribir fuera del vault). Todo lo que no sea [A-Za-z0-9._-] se colapsa a `-`.
retome_slug() {
  printf '%s' "$1" | tr -c 'A-Za-z0-9._-' '-' | cut -c1-96
}

# Ruta del fichero de ESTA sesión (exista o no).
retome_session_file() {
  local root="$1" sid="$2" d
  [ -n "$sid" ] || return 1
  d="$(retome_dir "$root")" || return 1
  printf '%s/%s.md' "$d" "$(retome_slug "$sid")"
}

# El fichero que hay que LEER: el de la sesión si existe, si no el legacy. Vacío si no hay ninguno.
retome_file() {
  local root="$1" sid="${2:-}" f
  if [ -n "$sid" ] && f="$(retome_session_file "$root" "$sid")" && [ -f "$f" ]; then
    printf '%s' "$f"; return 0
  fi
  f="$(retome_legacy "$root")" || return 0
  [ -f "$f" ] && printf '%s' "$f"
  return 0
}

# El fichero de la sesión, creándolo desde la plantilla si falta. Imprime la ruta; vacío si no se
# puede (sin session_id, o el vault no es escribible → los hooks caen a legacy y siguen: fail-open).
retome_ensure() {
  local root="$1" sid="${2:-}" f dir
  [ -n "$sid" ] || return 0
  f="$(retome_session_file "$root" "$sid")" || return 0
  [ -f "$f" ] && { printf '%s' "$f"; return 0; }
  dir="$(retome_dir "$root")" || return 0
  mkdir -p "$dir" 2>/dev/null || return 0
  cat > "$f" <<EOF 2>/dev/null || return 0
---
actualizado: $(date -u +%Y-%m-%dT%H:%M:%SZ)
sesion_id: ${sid}
proyecto: por-decidir
compactaciones: 0
---

# 🔄 Punto de retome — sesión \`${sid}\`

> Estado vivo del orquestador **de esta sesión**, y solo de esta. Se **sobrescribe**, no acumula: el
> histórico narrativo va a \`heartbeat/\` (una entrada por fichero). Un fichero por sesión (E-RET/RET-A) para que
> dos sesiones a la vez no se pisen la sentinela ni se contaminen el contexto al recompactar.

## Trayectoria en vuelo
_(sin trayectoria activa todavía)_

> La SENTINELA que leen los gates ya **no vive aquí** (T-214): es un sidecar sin versionar,
> \`.claude/state/trayectoria-activa/<sesión>\`, que fijan \`trajectory-scaffold.sh\` y apaga
> \`trajectory-close.sh\`. Esta sección es para la narrativa: qué llevas en vuelo y por dónde ibas.

## TODOs con sus IDs

## PRs sin linkear

## Subagentes lanzados (rol · TRAJECTORY_ID · Task ID)

## Cola pendiente

## Fase del workflow
EOF
  printf '%s' "$f"
}
