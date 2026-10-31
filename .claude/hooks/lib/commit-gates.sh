# shellcheck shell=bash
# lib/commit-gates.sh — la DECISIÓN de los cuatro gates de commit, en un solo sitio (T-223).
#
# Los gates (trajectory, anti-slop, security, ui-canvas) se aplican en dos capas:
#   · los PreToolUse (`<gate>.sh`), que corren ANTES de que bash ejecute el comando y tienen que
#     PREDECIR el repo y el staging (aviso temprano, y `--no-verify`);
#   · el hook de git (`hooks/git/commit-msg`, llamado por el shim `.git/hooks/commit-msg` de cada repo), que corre DENTRO
#     del commit, con el repo y el índice reales. Es el que decide.
# Las dos capas llaman a las mismas funciones, así que la regla existe una sola vez.
# Since T-359 there is a fifth gate, english (gate_english), which only runs in the git hook: it can warn without
# blocking, which a PreToolUse decision cannot express.
#
# CONTRATO COMÚN:
#   gate_<nombre> <raíz-del-framework> <repo> <ficheros> <sesión> <mensaje>
#     · <repo>: raíz del árbol de trabajo que se commitea;
#     · <ficheros>: los del commit, uno por línea, relativos a <repo>;
#     · <sesión>: el session_id de Claude Code (vacío = no se sabe);
#     · <mensaje>: el texto donde buscar los escapes (`[skip-traj]`, `[skip-ui: razón]`). El hook de git
#       pasa el mensaje del commit; el PreToolUse, el comando entero (como antes).
#   rc 0 = deja pasar; rc 1 = bloquea, con el motivo en GATE_MOTIVO (texto plano).
#   No escribe NADA por stdout: en los PreToolUse ese canal es el del JSON de la decisión.
#
# Filosofía: fail-open cuando no se puede decidir (sin retome, sin sesión, sin plan…), y bloqueo solo
# cuando el problema se determina POSITIVAMENTE. Bash 3.2-safe (lo cargan anti-slop y security).
#
# Depende de `lib/retome.sh` (sentinela y retome por sesión): se carga aquí si no lo estaba.

# Sin retome.sh, la carga de ESTA lib falla (return 1), y quien la carga avisa con su mensaje diseñado
# en vez de caer en un «command not found» a mitad de un gate.
if ! command -v retome_file >/dev/null 2>&1; then
  # shellcheck source=lib/retome.sh
  . "$(dirname "${BASH_SOURCE[0]}")/retome.sh" 2>/dev/null || return 1
fi

# El resolver del vault (T-295) llega con retome.sh; se carga aparte por si alguien ya tenía retome.sh cargado sin él.
if ! command -v vault_resolver >/dev/null 2>&1; then
  # shellcheck source=lib/vault.sh
  . "$(dirname "${BASH_SOURCE[0]}")/vault.sh" 2>/dev/null || {
    # Copia parcial sin vault.sh (la de un proyecto anterior a T-295): el vault de siempre, como antes.
    vault_resolver() { VAULT_DIR="${1:-}/Contexto_Base_SRE"; VAULT_ORIGEN="legacy"; VAULT_ERROR=""; return 0; }
  }
fi

# _cg_vault <fw> <repo> — dónde está el vault respecto al repo que se commitea (T-295). Deja:
#   CG_VAULT_RC   lo que devolvió `vault_resolver` (0 hay vault, 1 no hay, 2 variable inválida), con VAULT_DIR/VAULT_ERROR;
#   CG_VAULT_PREF el prefijo de las rutas del vault DENTRO del repo:
#     "Contexto_Base_SRE/"  el vault de siempre (y sin vault: se clasifica como siempre y quien llama decide);
#     "<ruta>/"             el vault vive DENTRO del repo sin ser su raíz: sus rutas son las de debajo de <ruta>;
#     "/"                   el checkout del commit ES el vault (su raíz, u otro worktree suyo que también es un vault):
#                           todo lo commiteado es vault;
#     ""                    el vault vive fuera de este repo: todo lo commiteado es código.
# «Mismo git-common-dir» NO basta para decir «es el repo del vault»: un subdirectorio comparte el del repo que lo
# contiene, y con AGENTIC_VAULT_ROOT=$FW/Contexto_Base_SRE el framework entero pasaba por vault (adversario, H1).
_cg_vault() {
  local top vtop
  CG_VAULT_PREF="Contexto_Base_SRE/"
  vault_resolver "$1"; CG_VAULT_RC=$?
  [ "$CG_VAULT_RC" -eq 0 ] || return 0
  [ "$VAULT_ORIGEN" = "legacy" ] && return 0
  CG_VAULT_PREF=""
  top="$(cd "$2" 2>/dev/null && t="$(_cg_git_fuera rev-parse --show-toplevel 2>/dev/null)" && cd "$t" && pwd -P)" || top=""
  [ -n "$top" ] || return 0
  if [ "$VAULT_DIR" = "$top" ]; then
    CG_VAULT_PREF="/"
  elif [ "${VAULT_DIR#"$top"/}" != "$VAULT_DIR" ]; then
    CG_VAULT_PREF="${VAULT_DIR#"$top"/}/"
  else
    # El vault vive en OTRO checkout. Si es del mismo repo que el commit (un worktree), lo que cuenta es dónde está el
    # vault dentro de SU checkout: en una subcarpeta → esa misma ruta en este (adversario de T-295, H4: un commit solo
    # de vault desde un worktree del framework se bloqueaba en falso); en la raíz → todo es vault solo si ESTE checkout
    # también es un vault (otro worktree de la rama del vault). Un worktree con la rama del vault (`git subtree split`)
    # cuelga del framework o de un clon suyo, y decidirlo por el repo abría el gate al código de ese repo: por el del
    # framework (H5) y, arreglado eso, por el de un segundo clon (H7). Lo que se mira es el checkout, no el repo.
    vtop="$(cd "$VAULT_DIR" 2>/dev/null && t="$(_cg_git_fuera rev-parse --show-toplevel 2>/dev/null)" && cd "$t" && pwd -P)" || vtop=""
    if [ -n "$vtop" ] && _cg_mismo_repo "$2" "$VAULT_DIR"; then
      if [ "$vtop" = "$VAULT_DIR" ]; then
        vault_es "$top" && CG_VAULT_PREF="/"
      elif [ "${VAULT_DIR#"$vtop"/}" != "$VAULT_DIR" ]; then
        CG_VAULT_PREF="${VAULT_DIR#"$vtop"/}/"
      fi
    fi
  fi
}

# _cg_fuera_del_vault <ficheros> — los que NO cuelgan de CG_VAULT_PREF, uno por línea. Comparación LITERAL: el prefijo
# es una ruta del disco y puede llevar `.`, `[` o `*`; usado como regex abría el gate (adversario de T-295, H3).
_cg_fuera_del_vault() {
  local f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in "$CG_VAULT_PREF"*) ;; *) printf '%s\n' "$f" ;; esac
  done <<LISTA
$1
LISTA
}

# `timeout 60` delante de lo que ejecuta procesos externos (escáner, gitleaks), si existe: un proceso
# colgado no puede colgar el commit. Un rc 124 (se agotó) no es 1, así que cae en el fail-open.
_CG_TIMEOUT=()
command -v timeout >/dev/null 2>&1 && _CG_TIMEOUT=(timeout 60)

# _cg_mismo_repo <a> <b> — ¿comparten git-common-dir? (el mismo repo, o un worktree suyo)
# _cg_git_fuera — git SIN el entorno que git exporta a sus hooks. Dentro de un hook de un worktree, git
# pone `GIT_DIR` (y a veces `GIT_WORK_TREE`, `GIT_INDEX_FILE`…), y con eso `cd "$fw" && git …` responde
# por el repo COMMITEADO, no por el framework (ADV-T223-3). Toda consulta a un repo que no sea el del
# commit pasa por aquí.
_cg_git_fuera() {
  env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE -u GIT_PREFIX -u GIT_OBJECT_DIRECTORY \
      -u GIT_ALTERNATE_OBJECT_DIRECTORIES -u GIT_COMMON_DIR git "$@"
}
_cg_common() { (cd "$1" 2>/dev/null && c="$(_cg_git_fuera rev-parse --git-common-dir 2>/dev/null)" && cd "$c" && pwd -P); }
_cg_mismo_repo() {
  local a b
  a="$(_cg_common "$1")" && b="$(_cg_common "$2")" && [ -n "$a" ] && [ "$a" = "$b" ]
}

# _cg_staged <repo> — los ficheros del índice, uno por línea. `-z`: sin él git entrecomilla las rutas con
# tab, comillas o no ASCII, y la comilla rompe `[ -f ]` y los globs de extensión.
_cg_staged() {
  local f
  while IFS= read -r -d '' f; do printf '%s\n' "$f"; done < <(git -C "$1" diff --cached --name-only -z 2>/dev/null)
}

# [skip-traj] en el mensaje: el escape global del framework.
_cg_skip_traj() { printf '%s' "$1" | grep -q '\[skip-traj\]'; }

# _cg_code_files <repo> <ficheros> — los de código (familia TS/JS/back) que existen en disco, uno por
# línea. Los .sh no entran: los cubre el linter de shell.
_cg_code_files() {
  local repo="$1" f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
      *.ts|*.tsx|*.js|*.jsx|*.mjs|*.cjs|*.py|*.go|*.rb|*.rs|*.java) ;;
      *) continue ;;
    esac
    [ -f "$repo/$f" ] || continue
    printf '%s\n' "$f"
  done <<EOF
$2
EOF
}

# Sube por los ancestros de $2 buscando package.json, sin salir de $1 (raíz del repo). Imprime la raíz
# del proyecto o falla.
_cg_find_project() {
  local root="$1" d="$2" parent
  while :; do
    [ -f "$d/package.json" ] && { printf '%s' "$d"; return 0; }
    [ "$d" = "$root" ] && return 1
    parent="$(dirname "$d")"
    [ "$parent" = "$d" ] && return 1
    d="$parent"
  done
}

# Proyectos JS/TS tocados por <ficheros de código> que NO llevan ninguno de los marcadores dados.
# _cg_ungated <repo> <ficheros-de-código> <marcador> [<marcador>…]  → " proj1 proj2" (vacío si todos lo llevan)
_cg_ungated() {
  local root="$1" files="$2" f proj m d ok ungated="" seen_proj=""
  shift 2
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    proj="$(_cg_find_project "$root" "$(dirname "$root/$f")")" || continue   # fuera de un proyecto JS/TS → no exige gate
    case "$seen_proj" in *"|$proj|"*) continue ;; esac                      # ¿ya visto?
    seen_proj="${seen_proj}|$proj|"                                          # set bash-3.2-safe
    ok=0
    # El marcador vale en el proyecto o en cualquier ancestro hasta la raíz del repo (T-228): en un
    # monorepo de workspaces el gate se instala en la raíz y el código vive en packages/*/.
    d="$proj"
    while [ "$ok" = 0 ]; do
      for m in "$@"; do [ -f "$d/$m" ] && ok=1; done
      [ "$d" = "$root" ] && break
      d="$(dirname "$d")"
      case "$d" in "$root"|"$root"/*) ;; *) break ;; esac
    done
    [ "$ok" = 1 ] || ungated="${ungated} ${proj#"${root}/"}"
  done <<EOF
$files
EOF
  printf '%s' "$ungated"
}

# ================================ trajectory ========================================================
# Bloquea si hay código de producción (algo fuera del vault) en el commit, la sesión es del framework (tiene retome) y
# su sentinela está a `none`. Ver la cabecera de `trajectory-gate.sh`. Sin vault que resolver, un commit de producción
# BLOQUEA (T-295): antes no había retome y se dejaba pasar en silencio, que es justo el caso «clon nuevo» que T-214 se
# negó a dejar abierto. Un commit en el propio repo del vault no es de producción.
gate_trayectoria() {
  GATE_MOTIVO=""
  local fw="$1" root="$2" files="$3" sid="$4" msg="$5" retome prod sample side
  _cg_skip_traj "$msg" && return 0
  [ -n "$files" ] || return 0
  _cg_vault "$fw" "$root"
  [ "$CG_VAULT_PREF" = "/" ] && return 0      # commit en el repo del vault
  if [ -n "$CG_VAULT_PREF" ]; then
    prod="$(_cg_fuera_del_vault "$files")"
  else
    prod="$files"
  fi
  [ -n "$prod" ] || return 0     # commit solo-vault → permitir
  if [ "$CG_VAULT_RC" -ne 0 ]; then
    sample="$(printf '%s\n' "$prod" | head -3 | tr '\n' ' ')"
    GATE_MOTIVO="Vas a commitear código de producción (${sample}…) y no puedo comprobar tu trayectoria porque ${VAULT_ERROR}. El retome y los planes viven en el vault (épica T-294). Excepción legítima: añade [skip-traj] al mensaje del commit."
    return 1
  fi
  retome="$(retome_file "$fw" "$sid")"
  [ -n "$retome" ] && [ -f "$retome" ] || return 0   # sin vault del framework a la vista → fail-open
  # Sentinela: SIDECAR sin versionar, uno por sesión (T-214). Antes vivía en el frontmatter del retome
  # y eso costaba conflictos en cada merge — y, peor, la clave se quedaba CONGELADA: 4 de los 33 retomes
  # del vault declaraban una trayectoria activa que llevaba semanas `done`. Un gate que aprueba por un
  # valor viejo es un gate con dientes falsos.
  #
  # La ausencia del sidecar es `none`, no un error: el fail-open sigue colgando del RETOME (si no hay
  # retome, ya salimos arriba), así que «hay sesión del framework pero nadie ha declarado trayectoria»
  # se lee como lo que es y BLOQUEA.
  #
  # Sin sesión NO hay sidecar posible (`sentinela_file` lo exige) y por tanto tampoco forma de cumplir:
  # bloquear ahí sería una trampilla sin salida más que un gate. Fail-open explícito.
  [ -n "$sid" ] || return 0
  [ "$(sentinela_leer "$fw" "$sid")" = "none" ] || return 0
  sample="$(printf '%s\n' "$prod" | head -3 | tr '\n' ' ')"
  side="$(sentinela_file "$fw" "$sid" 2>/dev/null)"
  GATE_MOTIVO="Vas a commitear código de producción (${sample}…) sin una trayectoria activa registrada. En este repo TODA tarea es una trayectoria (CLAUDE.md). Antes de commitear: 1) crea la trayectoria — bash .claude/skills/agentic-dashboard/scripts/dashboard-api.sh trajectory-create --project <PROJECT_ID> --title \"…\"  (pásala a executing); 2) fija la sentinela de TU sesión (sidecar, NO el retome — T-214): bash .claude/skills/agentic-dashboard/scripts/sentinela.sh set <TRAJECTORY_ID>  (el fichero es ${side}; tu retome, ${retome}). Luego repite el commit. Excepción legítima (p.ej. fix trivial de vault/infra): añade [skip-traj] al mensaje del commit."
  return 1
}

# ================================ anti-slop =========================================================
# (1) presencia del gate anti-slop en cada proyecto JS/TS tocado; (2) el linter bash de la skill sobre
# los ficheros de código del commit. Ver la cabecera de `anti-slop-gate.sh`.
gate_anti_slop() {
  GATE_MOTIVO=""
  local fw="$1" root="$2" files="$3" msg="$5" code ungated scanner scan_out rc sample f
  _cg_skip_traj "$msg" && return 0
  code="$(_cg_code_files "$root" "$files")"
  [ -n "$code" ] || return 0
  ungated="$(_cg_ungated "$root" "$code" .anti-slop-gate eslint.anti-slop.mjs)"
  if [ -n "${ungated# }" ]; then
    GATE_MOTIVO="Vas a commitear código en un proyecto SIN el gate anti-slop:${ungated# }. En este repo el gate anti-slop determinista es parte del DoD en TODOS los proyectos (doctrina_anti_slop.md). Instálalo: bash .claude/skills/code-anti-slop/scripts/install.sh <proyecto>  (añade el preset ESLint+sonarjs, el paso de lint en CI y este hook). Luego repite el commit. Excepción legítima: añade [skip-traj] al mensaje del commit."
    return 1
  fi
  # El escáner NUNCA se ejecuta desde el repo que se commitea: un repo clonado que versionara su propio
  # `code-anti-slop.sh` conseguiría ejecución de código en cuanto el agente commitea. Solo corre si ese
  # repo ES el framework (mismo git-common-dir), y es la copia del framework. En los demás proyectos el
  # escáner es su CI (así era ya de hecho: no llevan la skill). Excepción: la copia de este hook que el scaffolder
  # instala EN un proyecto (T-280) tiene ese proyecto por framework, y corre el escáner del propio proyecto; no abre
  # nada que no abriera ya registrar su propio hook en su propio settings.json.
  _cg_mismo_repo "$root" "$fw" || return 0
  scanner="$fw/.claude/skills/code-anti-slop/scripts/code-anti-slop.sh"
  [ -f "$scanner" ] || return 0   # skill no presente → fail-open (CI es el gate duro)
  local abs=()
  while IFS= read -r f; do [ -n "$f" ] && abs+=("$root/$f"); done <<EOF
$code
EOF
  scan_out="$(${_CG_TIMEOUT[@]+"${_CG_TIMEOUT[@]}"} bash "$scanner" "${abs[@]}" 2>/dev/null)"; rc=$?
  [ "$rc" -eq 1 ] || return 0     # rc 0 = limpio; rc 2 = error de uso → fail-open
  sample="$(printf '%s' "$scan_out" | grep -E '^VIOLACION' | head -3 | tr '\n' ' ')"
  GATE_MOTIVO="Anti-slop: hay patrones de slop en el código staged (${sample}…). Límpialos (escapes de tipo any, console.log/debugger, FIXME/XXX, eslint-disable sin razón) o, si es intencional, añade en la línea \`// anti-slop-allow: <razón>\`. Corre el detalle: bash .claude/skills/code-anti-slop/scripts/code-anti-slop.sh <ficheros>. Excepción global: [skip-traj] en el mensaje del commit."
  return 1
}

# ================================ english ===========================================================
# Spanish outside the UI in the staged lines or in the commit message (T-359, epic T-324). Only in repos that carry
# `.english-gate/config.json`, whose `local` key decides: "warn" lets the commit through and leaves the notice in
# GATE_NOTICE, "block" stops it. During a merge only the message is read: the staged lines are the merged branch's.
# Like anti-slop, the scanner is always the framework's copy, never one versioned in the repo being committed; the
# repo only provides its config, which the scanner reads as JSON.
gate_english() {
  GATE_MOTIVO=""
  GATE_NOTICE=""
  local fw="$1" root="$2" msg="$5" script out rc sample staged="--staged"
  [ -f "$root/.english-gate/config.json" ] || return 0
  _cg_skip_traj "$msg" && return 0
  script="$fw/.claude/skills/english-gate/scripts/check-english.mjs"
  { [ -f "$script" ] && command -v node >/dev/null 2>&1; } || return 0
  git -C "$root" rev-parse -q --verify MERGE_HEAD >/dev/null 2>&1 && staged=""
  out="$(printf '%s\n' "$msg" | ${_CG_TIMEOUT[@]+"${_CG_TIMEOUT[@]}"} node "$script" --root "$root" ${staged:+"$staged"} --text - --local 2>&1)"; rc=$?
  sample="$(printf '%s\n' "$out" | grep -E '^[^ ]+:[0-9]+: ' | head -3 | tr '\n' ' ')"
  case "$rc" in
    0) [ -n "$sample" ] && GATE_NOTICE="Spanish outside the UI in this commit (warning only in this repo): ${sample}… Write it in English; quote Spanish UI text between «»." ;;
    1) GATE_MOTIVO="Spanish outside the UI in this commit: ${sample}… Write it in English; quote Spanish UI text between «». Details: node $script --staged. Escape: [skip-traj] in the commit message."
       return 1 ;;
    *) GATE_NOTICE="the English gate could not run (exit $rc): $(printf '%s' "$out" | head -1). Check .english-gate/config.json." ;;
  esac
  return 0
}

# ================================ security ==========================================================
# (1) presencia del gate de seguridad en cada proyecto JS/TS tocado; (2) si hay gitleaks, secretos en
# el staging. Ver la cabecera de `security-gate.sh`.
gate_seguridad() {
  GATE_MOTIVO=""
  local fw="$1" root="$2" files="$3" msg="$5" code ungated preset_cfg rc
  _cg_skip_traj "$msg" && return 0
  code="$(_cg_code_files "$root" "$files")"
  if [ -z "$code" ]; then
    # Sin código no hay proyecto que exigir, pero en el repo del VAULT (T-295) gitleaks pasa igual: ahí entran logs y
    # salidas de producción en Markdown, y ya no viajan en un PR de código que pase por la escalera de CI.
    _cg_vault "$fw" "$root"
    [ "$CG_VAULT_PREF" = "/" ] || return 0
  else
    ungated="$(_cg_ungated "$root" "$code" .security-gate)"
  fi
  if [ -n "${ungated:-}" ] && [ -n "${ungated# }" ]; then
    GATE_MOTIVO="Vas a commitear código en un proyecto SIN el gate de seguridad:${ungated# }. En este repo el gate de seguridad determinista es parte del DoD en TODOS los proyectos (doctrina_guardian.md). Instálalo: bash .claude/skills/security-gate/scripts/install.sh <proyecto>  (añade el preset SAST/secretos/deps, el paso de CI y este hook). Luego repite el commit. Excepción legítima: añade [skip-traj] al mensaje del commit."
    return 1
  fi
  # Escaneo ligero de secretos staged: solo si gitleaks está presente; si no, NO bloquea (la red dura
  # es CI). gitleaks v8: `git --staged`. rc 1 = secreto (salida redactada; nunca se imprime).
  command -v gitleaks >/dev/null 2>&1 || return 0
  local gl_cfg=()
  # El preset sale SIEMPRE del framework: el del repo commiteado podría excluir sus propios secretos.
  preset_cfg="$fw/.claude/skills/security-gate/presets/gitleaks.toml"
  [ -f "$preset_cfg" ] && gl_cfg=(-c "$preset_cfg")
  ${_CG_TIMEOUT[@]+"${_CG_TIMEOUT[@]}"} gitleaks git "$root" --staged "${gl_cfg[@]}" --no-banner --redact --exit-code 1 >/dev/null 2>&1
  rc=$?
  [ "$rc" -eq 1 ] || return 0     # 0 = sin secreto; otro = error de ejecución → fail-open
  GATE_MOTIVO="Seguridad: gitleaks detectó un SECRETO en el diff staged (salida redactada). ROTA de inmediato la credencial y quítala del commit/historial. Detalle: bash .claude/skills/security-gate/scripts/security-gate.sh --staged. Si es un falso positivo intencional, añade \`gitleaks:allow\` en la línea. Excepción global: [skip-traj] en el mensaje del commit."
  return 1
}

# ================================ ui-canvas =========================================================
# «La forma de lo que se ve se valida ANTES de implementarla» (T-197). Ver la cabecera de
# `ui-canvas-gate.sh`: dos disparadores —el commit AÑADE superficie visible, o el plan declara
# `superficie_visible: si` y el commit toca UI— y, en ambos, bloqueo SOLO si el `plan.md` de la
# trayectoria activa no registra `lienzo:` + `veredicto_humano:`.
#
# --- El heurístico de «superficie visible», como datos. Se casa con `[[ $p == $glob ]]`; `*` cruza `/`.
# Una fila por familia: si borras una fila, la suite de ui-canvas-gate tiene que ponerse roja (se
# comprueba mutándolas). La justificación de cada fila vive en la cabecera de `ui-canvas-gate.sh`.
UI_EXCLUDE_GLOBS=(
  '*.test.*' '*.spec.*' '*/__tests__/*' '*/test/*' '*/tests/*' '*/e2e/*' '*/cypress/*' '*/playwright/*'
  '*.stories.*' '*/.storybook/*'
  '*.config.*' '*/node_modules/*' '*/dist/*' '*/build/*' '*/.next/*' '*/out/*' '*/coverage/*' '*/vendor/*'
  '*.min.css' '*.md' '*/Contexto_Base_SRE/*' '*/docs/*' '*/.claude/*'
  '*/tools/*' '*/scripts/*' '*/bin/*'
  '*/pages/api/*' '*/app/api/*'
)
UI_INCLUDE_GLOBS=(
  '*.tsx' '*.jsx' '*.vue' '*.svelte' '*.astro'
  '*.css' '*.scss' '*.sass' '*.less'
  '*.html' '*.htm' '*.hbs' '*.ejs' '*.pug' '*.njk' '*.twig' '*.blade.php' '*.html.erb'
  '*/app/page.js' '*/app/*/page.js' '*/app/layout.js' '*/app/*/layout.js'
)
# Notas de las dos filas menos obvias:
#  · plantillas — `.html` cubre también el `.component.html` de Angular; `.html.erb` en vez de `.erb`
#    a secas porque un `.erb` suelto suele ser una plantilla de config (Puppet/Chef), no una vista.
#  · rutas — solo `page.js`/`layout.js` bajo `app/`; sus variantes `.tsx`/`.jsx` ya entran por
#    extensión, y `page.ts` a secas no existe en Next.

# ¿Es $1 (ruta relativa al repo) superficie visible? Exclusiones primero.
is_ui_file() {
  local p="/$1" g
  for g in "${UI_EXCLUDE_GLOBS[@]}"; do
    # shellcheck disable=SC2053  # glob a propósito: $g es un patrón, no un literal
    [[ $p == $g ]] && return 1
  done
  for g in "${UI_INCLUDE_GLOBS[@]}"; do
    # shellcheck disable=SC2053
    [[ $p == $g ]] && return 0
  done
  return 1
}

# Valor CRUDO de la clave $2 en el plan $1 (primer match). Acepta viñeta `- ` y negritas `**clave**:`,
# recorta el comentario `#` inline —la plantilla lo pone pegado al valor y sin esto `si   # …` no
# casaba con nada, apagando el disparador (b) en silencio (T-197·B2)— y admite el valor en la línea
# siguiente (YAML multilínea). Ignora bloques de código y comentarios HTML: citar el contrato en la
# doctrina no es cumplirlo.
plan_field() {
  local file="$1" key="$2"
  awk -v key="$key" '
    { line = $0 }
    line ~ /^[[:space:]]*(```|~~~)/ { fence = !fence; next }     # los dos fences de markdown
    fence { next }
    html { if (line ~ /-->/) html = 0; next }                    # dentro de un comentario multilínea
    {
      # El comentario HTML se RECORTA de la línea, no tira la línea: un
      # `lienzo: <url> <!-- el definitivo -->` es un registro legítimo.
      gsub(/<!--.*-->/, " ", line)
      if (line ~ /<!--/) { sub(/<!--.*$/, "", line); html = 1 }
    }
    pend {
      if (line ~ /^[[:space:]]*$/) next
      if (line ~ /^[[:space:]]*(#|---)/) exit
      if (line !~ /^[[:space:]]+/) exit
      v = line; sub(/^[[:space:]]+/, "", v); sub(/[[:space:]]+#.*$/, "", v); print v; exit
    }
    {
      l = tolower(line)
      if (l ~ ("^ ?[ ]?[ ]?(- +)?[*]?[*]?" key "[*]?[*]?:")) {
        v = line
        sub(/^[^:]*:[[:space:]]*/, "", v)
        sub(/[[:space:]]+#.*$/, "", v)   # con espacio delante: una URL con #fragmento sobrevive
        if (v ~ /^#/) v = ""             # `clave:   # pendiente` es una clave SIN valor, no un valor
        sub(/[[:space:]]+$/, "", v)
        if (v == "") { pend = 1; next }
        print v; exit
      }
    }
  ' "$file" 2>/dev/null | sed -E 's/^["'"'"']//; s/["'"'"']$//'
}

# Placeholders: un registro que dice "todavía no" no es un registro. Prefijo e insensible a mayúsculas
# (`LC_ALL=C` para no destrozar UTF-8 al bajar a minúsculas).
is_placeholder() {
  local low
  low="$(printf '%s' "$1" | LC_ALL=C tr 'A-Z' 'a-z')"
  case "$low" in
    "" | none | null | "-" | "?" | "n/a" | na | "…" | "...") return 0 ;;
    todo* | tbd* | tba* | pendiente* | pending* | "por definir"* | "por hacer"* | "por montar"*) return 0 ;;
  esac
  return 1
}

# `lienzo` es un LOCALIZADOR (URL o ruta), no prosa: sin espacios y con `/`. Así `lienzo: aún no se ha
# montado` no cuela como registro, y `https://…` o `artifacts/lienzo.canvas` sí.
is_locator() {
  case "$1" in
    *[[:space:]]* | "") return 1 ;;
    */*) return 0 ;;
  esac
  return 1
}

# Escape específico de ui-canvas, CON RAZÓN OBLIGATORIA. rc 0 = escape válido. Si viene vacío
# (`[skip-ui:]`) no escapa y deja la nota en GATE_UI_NOTA, que el motivo del bloqueo incluye: un escape
# sin motivo es un interruptor de apagado.
gate_ui_escape() {
  GATE_UI_NOTA=""
  local esc reason
  esc="$(printf '%s' "$1" | grep -oE '\[skip-ui:[^]]*\]' | head -n1)"
  [ -n "$esc" ] || return 1
  reason="$(printf '%s' "$esc" | sed -E 's/^\[skip-ui:[[:space:]]*//; s/[[:space:]]*\]$//')"
  [ -n "$reason" ] && return 0
  GATE_UI_NOTA=" (Tu [skip-ui:] viene SIN razón: un escape sin motivo es un interruptor de apagado, no una excepción; por eso no cuenta.)"
  return 1
}

gate_ui_canvas() {
  GATE_MOTIVO=""
  local fw="$1" repo="$2" files="$3" sid="$4" msg="$5" f nl=$'\n'
  local touched_ui="" new_ui="" retome tid plan p lienzo veredicto decl motivo sample
  _cg_skip_traj "$msg" && return 0
  gate_ui_escape "$msg" && return 0
  # En el repo del vault (T-295) las rutas no llevan `Contexto_Base_SRE/` delante, así que un lienzo
  # `trayectorias/T-X/artifacts/lienzo.html` casaría con UI_INCLUDE: ahí no hay superficie visible que validar.
  _cg_vault "$fw" "$repo"
  [ "$CG_VAULT_PREF" = "/" ] && return 0
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    is_ui_file "$f" && touched_ui="${touched_ui}${f}${nl}"
  done <<EOF
$files
EOF
  [ -n "$touched_ui" ] || return 0   # no hay UI en este commit → nada que decir
  # Lo que el commit AÑADE: `-z` porque con `core.quotepath` git entrecomilla las rutas no ASCII y la
  # comilla final rompía los globs de extensión (`Página.tsx`).
  # Solo lo que está en <ficheros> (ronda 4, ADV-T223-2): en un merge, el dispatcher ya dejó ahí solo el
  # contenido PROPIO del merge; lo que `main` añade no es superficie nueva de ESTE commit.
  while IFS= read -r -d '' f; do
    [ -n "$f" ] || continue
    is_ui_file "$f" || continue
    printf '%s\n' "$touched_ui" | grep -Fxq -- "$f" && new_ui="${new_ui}${f}${nl}"
  done < <(git -C "$repo" diff --cached --name-only -z --diff-filter=A 2>/dev/null)

  # Trayectoria activa (misma sentinela por sesión que el trajectory-gate).
  retome="$(retome_file "$fw" "$sid")"
  [ -n "$retome" ] && [ -f "$retome" ] || return 0   # sin retome → no sabemos qué plan mirar → fail-open
  tid="$(sentinela_leer "$fw" "$sid")"
  [ "$tid" = "none" ] && return 0                    # sin trayectoria → de eso se ocupa trajectory
  # Un ID que no es un ID (o trae metacaracteres) no se usa para construir un patrón de búsqueda.
  printf '%s' "$tid" | grep -qE '^[A-Za-z0-9._-]+$' || return 0

  # El `plan.md` de esa trayectoria, en el vault que resuelve el framework (T-295). Sin vault → fail-open: de bloquear
  # se encarga el gate de trayectoria.
  [ "$CG_VAULT_RC" -eq 0 ] || return 0
  plan=""
  for p in "$VAULT_DIR"/trayectorias/*/plan.md; do
    [ -f "$p" ] || continue
    if grep -qE "^trajectory_id:[[:space:]]*\"?${tid}\"?[[:space:]]*$" "$p" 2>/dev/null; then
      plan="$p"; break
    fi
  done
  [ -n "$plan" ] || return 0   # trayectoria sin plan localizable → no podemos decidir → fail-open

  # ¿Está el registro del lienzo? Si sí, este gate no tiene nada más que decir.
  lienzo="$(plan_field "$plan" lienzo)"
  veredicto="$(plan_field "$plan" veredicto_humano)"
  if is_locator "$lienzo" && ! is_placeholder "$lienzo" \
     && [ -n "$veredicto" ] && ! is_placeholder "$veredicto"; then
    return 0
  fi

  if [ -n "$new_ui" ]; then
    motivo="el commit AÑADE superficie visible nueva"
    sample="$(printf '%s' "$new_ui" | head -n3 | tr '\n' ' ')"
  else
    # Sin superficie nueva, solo dispara si el plan lo declara (rediseño: git no lo distingue de un
    # retoque, así que la decisión vuelve al plan).
    decl="$(plan_field "$plan" superficie_visible)"
    case "$(printf '%s' "$decl" | LC_ALL=C tr 'A-Z' 'a-z')" in
      si|sí|yes|true) ;;
      *) return 0 ;;
    esac
    motivo="el plan declara superficie_visible: si y el commit toca UI"
    sample="$(printf '%s' "$touched_ui" | head -n3 | tr '\n' ' ')"
  fi

  GATE_MOTIVO="Validación de UI: ${motivo} (${sample}…) y el plan de la trayectoria activa NO registra el lienzo. En este framework ninguna superficie visible se implementa sin que el humano haya validado su forma en un LIENZO antes del código (doctrina_validacion_ui.md). Antes de commitear: 1) monta el lienzo con la skill \`design\` (brief de \`frontend-anti-slop\` primero) y enséñaselo al humano; 2) registra su veredicto en ${plan} → dos líneas: \`lienzo: <URL o ruta del canvas, sin espacios>\` y \`veredicto_humano: <qué dijo, incluido lo que descartó>\`. Luego repite el commit. Excepción legítima: añade [skip-ui: <razón>] al mensaje del commit (la razón es obligatoria y queda escrita en la historia).${GATE_UI_NOTA}"
  return 1
}
