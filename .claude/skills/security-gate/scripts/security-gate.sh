#!/usr/bin/env bash
#
# security-gate.sh — runner DETERMINISTA de la escalera de seguridad (sin cloud, sin LLM).
# Parte de la skill `security-gate` (T-061-B). Materializa la escalera de la doctrina_guardian.md:
#   (1) Secretos   — gitleaks (no negociable; una fuga = severidad máxima → recordar ROTAR).
#   (2) SAST       — semgrep con el ruleset VENDORIZADO de presets/semgrep (NUNCA el registry).
#   (3) Deps       — osv-scanner (CVE) + npm audit si hay package-lock.json.
# La "lectura con criterio" (peldaño 4) y el red-team (peldaño 5) son del rol `seguridad`, fuera
# de este script. Reproducible en local y en CI: el veredicto es el mismo offline.
#
# Degradación grácil: si una herramienta falta, AVISA y degrada (no peta). En CI se instalan →
# ahí es gate duro. Toda la salida va REDACTADA (gitleaks --redact; nunca volcamos secretos).
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
SEMGREP_RULES="${SKILL_DIR}/presets/semgrep"
GITLEAKS_CONFIG="${SKILL_DIR}/presets/gitleaks.toml"

usage() {
  cat <<'EOF'
security-gate.sh — escalera de seguridad determinista (gitleaks + semgrep + osv-scanner, sin cloud)

USO:
  security-gate.sh [--help] [--staged] [--deps-advisory] [--sast-preset <nombre>] [--strict] [<path> ...]

  <path>      Ficheros y/o directorios a escanear (por defecto: la raíz del repo git, o el
              directorio actual si no hay repo).
  --staged    Escanea SOLO el diff staged del repo (secretos vía `gitleaks git --staged`).
              Pensado para una pasada rápida pre-commit. SAST/deps siguen sobre el árbol.
  --sast-preset <nombre>
              Suma al SAST el preset `presets/semgrep-<nombre>` (además del de por defecto). Hoy existe
              `infra` (T-256): Dockerfile, compose y scripts de despliegue (privileged, socket de Docker,
              namespaces del host, capacidades peligrosas, seccomp/apparmor unconfined, curl | sh). Un nombre
              inválido o sin directorio es error de uso (exit 2): un preset pedido que no carga no puede
              pasar por «sin hallazgos».
  --strict    Cualquier peldaño SIN COMPROBAR (herramienta ausente o que falla al ejecutarse) pone el gate
              en rojo (exit 1). Para CI, donde las herramientas están instaladas y un peldaño sin correr es
              un fallo, no una degradación (T-257). Sin la opción, degrada con aviso (exit 0).
  --deps-advisory
              Degrada el peldaño (3) Dependencias a ADVISORY: reporta las CVE pero NO bloquea
              (no cuenta como hallazgo). Ratchet honesto (T-044/T-032): se usa para onboardar un
              proyecto con deuda de deps PRE-EXISTENTE sin defangar secretos/SAST (que sí bloquean
              desde el día 1). Quítalo cuando las deps estén saneadas. Secretos y SAST nunca degradan.

ESCALERA (en orden, cada peldaño bloqueante):
  1) Secretos  — gitleaks dir/git con presets/gitleaks.toml (--redact).
  2) SAST      — semgrep --config presets/semgrep --metrics=off (ruleset vendorizado).
  3) Deps      — osv-scanner (+ npm audit si hay package-lock.json) y runtimes: Node de los Dockerfile,
                 .nvmrc/.node-version y setup-node contra presets/runtimes.json (check-runtimes.mjs, T-326).

ESCAPE (excepción trazada, lo soportan las herramientas de serie):
  • secretos: comentario `gitleaks:allow` en la línea del hallazgo.
  • SAST:     comentario `// nosemgrep: <id-regla>` (o `# nosemgrep`) en la línea.
  • deps:     `osv-scanner.toml` con [[IgnoredVulns]] id + ignoreUntil + reason (vale para osv y npm audit;
              sin reason, sin ignoreUntil o caducada → bloquea).
  • runtime:  comentario `runtime-gate: allow <motivo>` en la línea (sin motivo no vale).
  Úsalos con razón; quedan en el diff.

EXIT CODES:
  0  Limpio (verde para CI/verificador/hook).
  1  Hallazgo bloqueante (secreto, patrón SAST crítico/alto, o CVE).
  2  Error de uso (path inexistente, etc.).

DEGRADACION:
  Si una herramienta falta (command -v) o falla al ejecutarse, se avisa y ese peldaño queda NO COMPROBADO
  (nunca «OK»); sin --strict no peta (exit 0), con --strict sale 1. osv-scanner sin ficheros de
  dependencias (rc=128, «No package sources found») es «no aplica», no un fallo. En CI las
  herramientas se instalan → gate duro. Versiones de referencia: gitleaks v8, semgrep 1.16x,
  osv-scanner 1.9.x.
EOF
}

STAGED=0
DEPS_ADVISORY=0
STRICT=0
declare -a INPUTS=()
declare -a SEMGREP_CONFIGS=("$SEMGREP_RULES")
while [[ $# -gt 0 ]]; do
  arg="$1"; shift
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    --staged) STAGED=1 ;;
    --deps-advisory) DEPS_ADVISORY=1 ;;
    --strict) STRICT=1 ;;
    --sast-preset)
      # T-256: solo un nombre ([a-z0-9-]), nunca una ruta: el preset sale siempre de presets/ de esta skill.
      name="${1:-}"; shift || true
      if [[ ! "$name" =~ ^[a-z0-9][a-z0-9-]*$ ]]; then
        echo "ERROR: --sast-preset necesita un nombre ([a-z0-9-]), recibido: '${name}'" >&2; exit 2
      fi
      extra="${SKILL_DIR}/presets/semgrep-${name}"
      if [[ ! -d "$extra" ]]; then
        echo "ERROR: --sast-preset ${name}: no existe ${extra}" >&2; exit 2
      fi
      SEMGREP_CONFIGS+=("$extra") ;;
    -*) echo "ERROR: opción desconocida: $arg" >&2; usage >&2; exit 2 ;;
    *) INPUTS+=("$arg") ;;
  esac
done

# Resuelve el target por defecto: raíz del repo git, o cwd.
INPUTS_EXPLICIT=0; [[ ${#INPUTS[@]} -gt 0 ]] && INPUTS_EXPLICIT=1
if [[ ${#INPUTS[@]} -eq 0 ]]; then
  if root="$(git rev-parse --show-toplevel 2>/dev/null)" && [[ -n "$root" ]]; then
    INPUTS=("$root")
  else
    INPUTS=(".")
  fi
fi
for p in "${INPUTS[@]}"; do
  if [[ ! -e "$p" ]]; then
    echo "ERROR: path inexistente: $p" >&2
    exit 2
  fi
done

FINDINGS=0          # peldaños con hallazgo bloqueante
SECRET_LEAK=0       # ¿hubo fuga de secreto? → recordar ROTAR
declare -a SKIPPED=()

echo "== security-gate :: escalera de seguridad determinista (sin cloud) =="
echo "   targets: ${INPUTS[*]}"
echo

# -------------------------------- (1) SECRETOS (gitleaks) --------------------------------
echo "--- (1) Secretos :: gitleaks ---"
if command -v gitleaks >/dev/null 2>&1; then
  gl_cfg=()
  [[ -f "$GITLEAKS_CONFIG" ]] && gl_cfg=(-c "$GITLEAKS_CONFIG")
  if [[ "$STAGED" -eq 1 ]]; then
    # Diff staged del repo actual (good for pre-commit, según `gitleaks git --help`).
    repo="$(git rev-parse --show-toplevel 2>/dev/null || echo .)"
    gitleaks git "$repo" --staged "${gl_cfg[@]}" --no-banner --redact --exit-code 1 >/dev/null 2>&1
    rc=$?
  else
    rc=0
    for p in "${INPUTS[@]}"; do
      # `gitleaks dir` escanea directorios o ficheros (alias: file, directory).
      gitleaks dir "$p" "${gl_cfg[@]}" --no-banner --redact --exit-code 1 >/dev/null 2>&1 || rc=$?
    done
  fi
  if [[ "$rc" -eq 0 ]]; then
    echo "    OK: sin secretos detectados."
  else
    echo "    BLOQUEANTE: gitleaks detectó secreto(s) (salida redactada, secretos NO impresos)."
    echo "    >>> RECOMENDACION: ROTA de inmediato cualquier credencial expuesta y elimínala del historial."
    FINDINGS=$((FINDINGS+1)); SECRET_LEAK=1
  fi
else
  echo "    WARN: gitleaks no instalado → peldaño OMITIDO (degrada; en CI es gate duro)."
  SKIPPED+=("gitleaks")
fi
echo

# -------------------------------- (2) SAST (semgrep) --------------------------------
echo "--- (2) SAST :: semgrep (ruleset vendorizado) ---"
if command -v semgrep >/dev/null 2>&1; then
  if [[ ! -d "$SEMGREP_RULES" ]]; then
    echo "    WARN: ruleset vendorizado ausente ($SEMGREP_RULES) → peldaño OMITIDO."
    SKIPPED+=("semgrep-rules")
  else
    # --config <dir vendorizado> (NUNCA p/... ni auto); --metrics=off (sin telemetría/red);
    # --error → exit 1 si hay findings. Severidad ERROR = bloqueante; WARNING/INFO informativo.
    sg_cfg=()
    for c in "${SEMGREP_CONFIGS[@]}"; do sg_cfg+=(--config "$c"); done
    [[ "${#SEMGREP_CONFIGS[@]}" -gt 1 ]] && echo "    presets: ${SEMGREP_CONFIGS[*]#"${SKILL_DIR}/"}"
    # T-352: en un repo git sin .semgrepignore propio, semgrep aplica su lista por defecto relativa a la RAÍZ del repo,
    # y esa lista descarta test/, tests/ y testsuite/: un input pedido como `.claude/tests` salía con 0 ficheros.
    # A un directorio PEDIDO que vive bajo uno de esos nombres se le pasan sus ficheros (git ls-files, que respeta
    # .gitignore), porque semgrep no filtra un fichero que se le nombra. Ni `--x-ignore-semgrepignore-files` (INTERNAL,
    # puede desaparecer, y quitaría también node_modules/dist) ni `--project-root` (deja de leer .gitignore). Sin
    # inputs explícitos, con inputs fuera de tests/ o con un .semgrepignore propio, el alcance no cambia.
    # T-353: de esa lista solo van ficheros regulares que existen (semgrep rechaza un symlink o un borrado sin stagear
    # como «scanning root» y cae entero; al recorrer un directorio tampoco sigue enlaces), y fuera lo que excluya un
    # `.semgrepignore` anidado o intermedio (semgrep los honra al recorrer; git los lee igual, de la raíz hacia abajo).
    sg_targets=()
    for p in "${INPUTS[@]}"; do
      sg_files=()
      if [[ "$INPUTS_EXPLICIT" -eq 1 && -d "$p" ]] \
         && sg_root="$(git -C "$p" rev-parse --show-toplevel 2>/dev/null)" && [[ ! -e "$sg_root/.semgrepignore" ]] \
         && [[ "/$(git -C "$p" rev-parse --show-prefix 2>/dev/null)" =~ /(test|tests|testsuite)/ ]]; then
        # Resta «todos − ignorados» sin bash-4-ismos (T-136: macOS trae bash 3.2, sin `declare -A`): las dos listas,
        # NUL-separadas y ordenadas con `LC_ALL=C sort -z -u` (GNU y BSD sort tienen -z; comm y grep de BSD no), se
        # recorren a la vez (los ignorados por el fd 3) en un subshell con LC_ALL=C, para que `[[ < ]]` compare bytes como sort. Si no hay temporal,
        # no se expande: queda el directorio como objetivo y, si semgrep no escanea nada, el peldaño es NO COMPROBADO.
        if sg_tmp="$(mktemp -d 2>/dev/null)" && [[ -n "$sg_tmp" ]]; then
          git -C "$p" ls-files -z -co --exclude-standard | LC_ALL=C sort -z -u > "$sg_tmp/all"
          git -C "$p" ls-files -z -co -i --exclude-per-directory=.semgrepignore | LC_ALL=C sort -z -u > "$sg_tmp/ign"
          (
            LC_ALL=C
            ign=""; more=0
            IFS= read -r -u 3 -d '' ign && more=1
            while IFS= read -r -d '' f; do
              while [[ "$more" -eq 1 && "$ign" < "$f" ]]; do IFS= read -r -u 3 -d '' ign || more=0; done
              [[ "$more" -eq 1 && "$ign" == "$f" ]] && continue
              [[ -f "${p%/}/$f" && ! -L "${p%/}/$f" ]] && printf '%s\0' "${p%/}/$f"
            done < "$sg_tmp/all"
          ) 3< "$sg_tmp/ign" > "$sg_tmp/sel"
          while IFS= read -r -d '' f; do sg_files+=("$f"); done < "$sg_tmp/sel"
          rm -rf "$sg_tmp"
        else
          echo "    WARN: no se pudo crear un temporal para la lista de ficheros de $p → se pasa el directorio."
        fi
      fi
      if [[ "${#sg_files[@]}" -gt 0 ]]; then sg_targets+=("${sg_files[@]}"); else sg_targets+=("$p"); fi
    done
    # T-353: con miles de ficheros nombrados la lista supera ARG_MAX (rc=126, el SAST no corre). Van en tandas de
    # ≤500 KB de argumentos (cabe también en el ARG_MAX de 1 MB de macOS) y los JSON se agregan con jq. Si una tanda no
    # devuelve JSON con `.results`, el agregado sale vacío y el peldaño queda NO COMPROBADO, como con una sola.
    sg_run() {
      local -a batch=() outs=()
      local t bytes=0 rc=0 r
      for t in "${sg_targets[@]}" ""; do
        if [[ "${#batch[@]}" -gt 0 && ( -z "$t" || $((bytes + ${#t} + 1)) -gt 500000 ) ]]; then
          outs+=("$(semgrep scan "${sg_cfg[@]}" --metrics=off ${1+"$@"} --json --quiet "${batch[@]}" 2>/dev/null)"); r=$?
          [[ "$rc" -eq 0 ]] && rc=$r
          batch=(); bytes=0
        fi
        [[ -n "$t" ]] && { batch+=("$t"); bytes=$((bytes + ${#t} + 1)); }
      done
      if [[ "${#outs[@]}" -eq 1 ]]; then
        printf '%s' "${outs[0]}"
      else
        printf '%s\n' "${outs[@]}" | jq -s --argjson n "${#outs[@]}" 'if length == $n and all(.[]; (.results | type) == "array")
          then {results: (map(.results) | add), errors: (map(.errors // []) | add),
                paths: {scanned: (map(.paths.scanned // []) | add)}} else empty end' 2>/dev/null
      fi
      return "$rc"
    }
    sg_json="$(sg_run --severity=ERROR)"; sg_rc=$?
    # Resumen por severidad (corre aparte para contar WARNING sin que bloqueen).
    sg_all="$(sg_run)"; sg_all_rc=$?
    # T-257: dos preguntas separadas, porque un fallo de semgrep no borra los hallazgos que sí ha devuelto.
    #  (a) ¿Qué ha encontrado? Si la salida es JSON con `.results`, sus ERROR bloquean SIEMPRE, salga semgrep
    #      con el código que salga: con una regla rota en el preset, semgrep sale 2 pero devuelve lo que
    #      encontraron las demás (lo cazó el verificador: tirar esos resultados dejaba pasar un `eval`).
    #  (b) ¿Ha mirado todo? No, si sale ≠0 en cualquiera de las dos invocaciones (sin `--error` sale 0 con o sin
    #      hallazgos; regex o preset rotos: 2; config inexistente: 7), si la salida no es JSON con `.results`,
    #      si falta jq o si no ha escaneado ningún fichero. Entonces el peldaño es NO COMPROBADO, nunca «OK».
    n_err=""; n_warn=""; n_scanned=""
    if command -v jq >/dev/null 2>&1; then
      n_err="$(printf '%s' "$sg_json" | jq -e '.results | length' 2>/dev/null)" || n_err=""
      n_warn="$(printf '%s' "$sg_all" | jq -e '[.results[] | select(.extra.severity=="WARNING")] | length' 2>/dev/null)" || n_warn=""
      n_scanned="$(printf '%s' "$sg_json" | jq -e '(.paths.scanned // []) | length' 2>/dev/null)" || n_scanned=""
    fi
    echo "    severidad: ERROR(bloqueante)=${n_err:-?} | WARNING(informativo)=${n_warn:-?}"
    if [[ "${n_err:-0}" -gt 0 ]]; then
      # Lista archivo:línea:regla (sin volcar el snippet completo).
      printf '%s' "$sg_json" | jq -r '.results[] | "    ERROR \(.path):\(.start.line) [\(.check_id | split(".") | last)]"' 2>/dev/null | head -20
      echo "    BLOQUEANTE: semgrep encontró patrones de seguridad de severidad ERROR."
      FINDINGS=$((FINDINGS+1))
    fi
    if ! command -v jq >/dev/null 2>&1; then
      echo "    WARN: jq no instalado → no se pueden contar los hallazgos de semgrep."
      sg_ok=0
    elif [[ "$sg_rc" -ne 0 || "$sg_all_rc" -ne 0 || -z "$n_err" || -z "$n_warn" ]]; then
      echo "    WARN: semgrep falló al ejecutarse (rc=${sg_rc}/${sg_all_rc}) o su salida no es JSON válido."
      sg_ok=0
    elif [[ "${n_scanned:-0}" -eq 0 ]]; then
      echo "    WARN: semgrep no ha escaneado ningún fichero (¿.semgrepignore, tamaño, target vacío?)."
      sg_ok=0
    else
      sg_ok=1
    fi
    if [[ "$sg_ok" -eq 0 ]]; then
      echo "    NO COMPROBADO: el SAST no se ha hecho entero → este peldaño NO da cobertura."
      SKIPPED+=("semgrep(error)")
    elif [[ "${n_err:-0}" -eq 0 ]]; then
      echo "    OK: sin patrones SAST de severidad ERROR (${n_scanned} fichero(s) escaneados)."
    fi
  fi
else
  echo "    WARN: semgrep no instalado → peldaño OMITIDO (degrada; en CI es gate duro)."
  SKIPPED+=("semgrep")
fi
echo

# -------------------------------- (3) DEPS (osv-scanner + npm audit) --------------------------------
echo "--- (3) Dependencias :: osv-scanner (+ npm audit) ---"
# Los JSON de este peldaño se guardan para que `deps-cut.sh` derive la versión de corte REAL desde los
# avisos individuales (T-158). Sin esto solo queda el rango AGREGADO del gestor, que es la unión de
# todos los avisos del paquete y empuja más lejos de lo necesario.
DEPS_TMP="$(mktemp -d 2>/dev/null || echo "")"
[[ -n "$DEPS_TMP" ]] && trap 'rm -rf "$DEPS_TMP"' EXIT
idx=0
if command -v osv-scanner >/dev/null 2>&1; then
  osv_rc=0
  # T-160: un fallo de EJECUCIÓN no es un peldaño limpio. Sin esta bandera, `osv_rc` se queda en 0
  # tras un rc>1 y el resumen de abajo imprime "OK: sin vulnerabilidades" sobre un escaneo que nunca
  # ocurrió (reproducido en la auditoría T-159 con rc=127).
  osv_err=0
  osv_scanned=0   # T-257: cuántos targets se escanearon de verdad («no aplica» no cuenta)
  for p in "${INPUTS[@]}"; do
    [[ -d "$p" ]] || continue
    # T-257: el stderr va a un fichero de `mktemp` (nunca a una ruta fija de /tmp); si no se puede crear, el
    # peldaño no se puede leer bien y queda NO COMPROBADO.
    if ! osv_err_file="$(mktemp 2>/dev/null)" || [[ -z "$osv_err_file" ]]; then
      echo "    WARN: no se pudo crear un temporal para osv-scanner en $p → degrada."
      osv_err=1; idx=$((idx+1)); continue
    fi
    osv_json="$(osv-scanner scan --format json --recursive "$p" 2>"$osv_err_file")"; rc=$?
    # T-257: sin ficheros de dependencias osv-scanner 1.x sale 128 con «No package sources found». Eso es «no
    # aplica», no un fallo; otro 128 sigue siendo un error. Pero osv se salta lo que lista `.gitignore`, así que
    # un PR podría ocultar su lockfile y conseguir «no aplica» (lo reprodujo el rol seguridad). Antes de darlo
    # por bueno se repite con `--no-ignore`: solo si tampoco así encuentra manifiestos, no aplica.
    if [[ "$rc" -eq 128 ]] && grep -q 'No package sources found' "$osv_err_file" 2>/dev/null; then
      osv_json="$(osv-scanner scan --format json --recursive --no-ignore "$p" 2>"$osv_err_file")"; rc=$?
      if [[ "$rc" -eq 128 ]] && grep -q 'No package sources found' "$osv_err_file" 2>/dev/null; then
        echo "    no aplica: $p no tiene ficheros de dependencias que osv-scanner sepa leer."
        rm -f "$osv_err_file"; idx=$((idx+1)); continue
      fi
      echo "    AVISO: $p tiene ficheros de dependencias que su .gitignore oculta; se escanean igual (--no-ignore)."
    fi
    rm -f "$osv_err_file"
    osv_scanned=$((osv_scanned+1))
    # osv-scanner: exit 0 = sin vulns; 1 = vulns encontradas; >1 = error de ejecución (degrada).
    if [[ "$rc" -eq 1 ]]; then
      n_vuln=0
      if command -v jq >/dev/null 2>&1 && [[ -n "$osv_json" ]]; then
        n_vuln="$(printf '%s' "$osv_json" | jq '[.results[].packages[].vulnerabilities[]] | length' 2>/dev/null || echo 0)"
      fi
      echo "    osv-scanner encontró ${n_vuln} vulnerabilidad(es) de dependencias en $p."
      [[ -n "$DEPS_TMP" && -n "$osv_json" ]] && printf '%s' "$osv_json" > "$DEPS_TMP/osv-$idx.json"
      osv_rc=1
    elif [[ "$rc" -gt 1 ]]; then
      echo "    WARN: osv-scanner error (rc=$rc) en $p → degrada (no bloquea por fallo de ejecución)."
      osv_err=1
    fi
    idx=$((idx+1))
  done
  if [[ "${osv_err:-0}" -eq 1 ]]; then
    echo "    NO COMPROBADO: osv-scanner falló al ejecutarse → este peldaño NO da cobertura."
    SKIPPED+=("osv-scanner(error)")
  elif [[ "$osv_scanned" -eq 0 ]]; then
    :   # todo «no aplica» (ya dicho arriba): no hay escaneo del que decir «OK»
  elif [[ "$osv_rc" -eq 0 ]]; then
    echo "    OK: osv-scanner sin vulnerabilidades de dependencias."
  elif [[ "$DEPS_ADVISORY" -eq 1 ]]; then
    echo "    ADVISORY: CVE de deps reportadas pero NO bloquean (--deps-advisory, ratchet). Sanea y quita el flag."
  else
    echo "    BLOQUEANTE: CVE de dependencias (osv-scanner)."
    FINDINGS=$((FINDINGS+1))
  fi
else
  echo "    WARN: osv-scanner no instalado → peldaño OMITIDO (degrada; en CI es gate duro)."
  SKIPPED+=("osv-scanner")
fi

# npm audit complementario (solo donde haya package-lock.json).
if command -v npm >/dev/null 2>&1; then
  idx=0
  for p in "${INPUTS[@]}"; do
    if [[ ! -d "$p" || ! -f "$p/package-lock.json" ]]; then idx=$((idx+1)); continue; fi
    audit_json="$(cd "$p" && npm audit --audit-level=high --json 2>/dev/null)"; arc=$?
    [[ -n "$DEPS_TMP" && -n "$audit_json" ]] && printf '%s' "$audit_json" > "$DEPS_TMP/npm-$idx.json"
    n_hi=0
    if command -v jq >/dev/null 2>&1 && [[ -n "$audit_json" ]]; then
      n_hi="$(printf '%s' "$audit_json" | jq '((.metadata.vulnerabilities.high // 0) + (.metadata.vulnerabilities.critical // 0))' 2>/dev/null || echo 0)"
    fi
    # T-229: las excepciones de `$p/osv-scanner.toml` restan de npm audit SOLO los avisos que nombran. Si el filtro
    # no reconoce ningún aviso high/critical en el JSON (otro formato) o falla, cuenta todo, como sin excepciones.
    # La validez del TOML (motivo, fecha) se comprueba aparte, para todos los ficheros (ver abajo).
    if [[ "${n_hi:-0}" -gt 0 && -f "$p/osv-scanner.toml" && -n "$DEPS_TMP" ]] && command -v node >/dev/null 2>&1; then
      printf '%s' "$audit_json" > "$DEPS_TMP/npm-raw-$idx.json"
      if exc_json="$(node "${SCRIPT_DIR}/deps-exceptions.mjs" "$DEPS_TMP/npm-raw-$idx.json" "$p")" \
         && [[ "$(printf '%s' "$exc_json" | jq '.recognized')" -gt 0 ]]; then
        while IFS= read -r line; do [[ -n "$line" ]] && echo "    $line"; done < <(printf '%s' "$exc_json" | jq -r \
          '(.excepted[] | "EXCEPCIÓN: \(.id) (\(.pkg)) hasta \(.until) — \(.reason)"),
           (.blocking[] | "AVISO: \(.id) \(.severity) en \(.pkg) — \(.title)")')
        n_hi="$(printf '%s' "$exc_json" | jq '.blocking | length')"
      else
        echo "    WARN: el JSON de npm audit no se pudo cruzar con osv-scanner.toml → cuenta todo, sin excepciones."
      fi
    fi
    if [[ "$arc" -ne 0 && "${n_hi:-0}" -gt 0 ]]; then
      if [[ "$DEPS_ADVISORY" -eq 1 ]]; then
        echo "    ADVISORY: npm audit reporta ${n_hi} vuln(s) high/critical en $p (NO bloquea, ratchet)."
      else
        echo "    BLOQUEANTE: npm audit reporta ${n_hi} vuln(s) high/critical en $p/package-lock.json."
        FINDINGS=$((FINDINGS+1))
      fi
    else
      echo "    OK: npm audit sin vulns high/critical en $p (fuera de las excepciones nombradas arriba, si las hay)."
    fi
    idx=$((idx+1))
  done
fi

# T-229: TODO `osv-scanner.toml` del proyecto (también en subdirectorios: osv --recursive los usa) se valida, haya o
# no lockfile o npm. Una excepción sin reason, sin ignoreUntil, caducada o en un fichero ilegible es un hallazgo:
# osv-scanner aceptaría para siempre una sin fecha. Sin node no se puede validar → peldaño sin cobertura.
for p in "${INPUTS[@]}"; do
  [[ -d "$p" ]] || continue
  while IFS= read -r toml; do
    [[ -n "$toml" ]] || continue
    if ! command -v node >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
      echo "    NO COMPROBADO: $toml no se puede validar sin node y jq."
      SKIPPED+=("deps-exceptions(sin node/jq)"); break 2
    fi
    if ! exc_json="$(node "${SCRIPT_DIR}/deps-exceptions.mjs" - "$(dirname "$toml")")"; then
      echo "    BLOQUEANTE: no se pudo leer $toml."; FINDINGS=$((FINDINGS+1)); continue
    fi
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      echo "    BLOQUEANTE: $line"; FINDINGS=$((FINDINGS+1))
    done < <(printf '%s' "$exc_json" | jq -r --arg f "$toml" '.invalid[] | "EXCEPCIÓN INVÁLIDA en \($f): \(.id) \(.problem) (necesita reason e ignoreUntil futuro)"')
  done < <(find "$p" -name osv-scanner.toml -not -path '*/node_modules/*' -not -path '*/.git/*' 2>/dev/null)
done

# T-326: el Node que CORRE también es una dependencia. `check-runtimes.mjs` compara la imagen base de los Dockerfile,
# `.nvmrc`/`.node-version` y el `node-version` de setup-node con presets/runtimes.json (mínimo por rama). Una etiqueta
# flotante en un Dockerfile cuenta como hallazgo: la versión la decide la caché de capas del host. Sin node → sin
# cobertura, como la validación de osv-scanner.toml.
# Sin ningún fichero candidato (un proyecto Deno o Python sin Dockerfile ni workflows) no aplica y no pide node. El
# filtro es un SUPERCONJUNTO de lo que mira el script (`kindOf` en check-runtimes.mjs): si deja pasar de más, el script
# lo descarta. Si se queda corto, el script no llega a correr: por eso casa por subcadena (`*dockerfile*`) y no por forma.
for p in "${INPUTS[@]}"; do
  [[ -d "$p" ]] || continue
  # T-353 (ADV-18): cualquier enlace es candidato: `find` no entra en un directorio enlazado y el script sí lo sigue si
  # queda dentro del repo; quién decide si hay algo que juzgar detrás es el script (sin seguir lo que sale del repo).
  rt_any="$(find "$p" \( -name node_modules -o -name .git \) -prune -o \( -type l -o -type f \( -iname '*dockerfile*' -o \
    -iname '*containerfile*' -o -name .nvmrc -o -name .node-version -o -name .tool-versions -o -path '*/.github/*' \) \) \
    -print -quit 2>/dev/null)"
  [[ -n "$rt_any" ]] || continue
  if ! command -v node >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
    echo "    NO COMPROBADO: runtimes (Dockerfile, .nvmrc, setup-node) sin node y jq."
    SKIPPED+=("runtimes(sin node/jq)"); break
  fi
  if ! rt_json="$(node "${SCRIPT_DIR}/check-runtimes.mjs" "$p")"; then
    echo "    BLOQUEANTE: no se pudieron comprobar los runtimes de $p."; FINDINGS=$((FINDINGS+1)); continue
  fi
  while IFS= read -r line; do
    [[ -n "$line" ]] && echo "    EXCEPCIÓN (runtime-gate: allow): $line"
  done < <(printf '%s' "$rt_json" | jq -r --arg p "$p" '.allowed[] | "\($p)/\(.file):\(.line) \(.found) — \(.reason)"')
  rt_n="$(printf '%s' "$rt_json" | jq '.findings | length')"
  rt_checked="$(printf '%s' "$rt_json" | jq '.checked | length')"
  # T-353 (ADV-14): lo que el script no pudo leer (un `pgdata/` ajeno con modo 700) se saltó con aviso: no es «limpio».
  rt_unread="$(printf '%s' "$rt_json" | jq '(.unreadable // []) | length')"
  if [[ "$rt_unread" -gt 0 ]]; then
    echo "    NO COMPROBADO: runtimes — ${rt_unread} ruta(s) ilegibles en $p: $(printf '%s' "$rt_json" | jq -r '.unreadable | join(", ")')"
    SKIPPED+=("runtimes(ilegibles)")
  fi
  if [[ "$rt_n" -eq 0 && "$rt_checked" -eq 0 ]]; then
    # R3 de T-326: un OK de «0 ficheros mirados» es un OK sin haber mirado nada.
    [[ "$rt_unread" -gt 0 ]] || echo "    NO APLICA: runtimes — ningún Dockerfile, .nvmrc, .tool-versions ni workflow que juzgar en $p."
    continue
  fi
  if [[ "$rt_n" -eq 0 && "$rt_unread" -gt 0 ]]; then
    continue
  fi
  if [[ "$rt_n" -eq 0 ]]; then
    echo "    OK: runtimes al día en $p (${rt_checked} fichero(s) mirados)."
    continue
  fi
  label="BLOQUEANTE"; [[ "$DEPS_ADVISORY" -eq 1 ]] && label="ADVISORY (--deps-advisory, NO bloquea)"
  while IFS= read -r line; do
    echo "    ${label}: RUNTIME $line"
    [[ "$DEPS_ADVISORY" -eq 1 ]] || FINDINGS=$((FINDINGS+1))
  done < <(printf '%s' "$rt_json" | jq -r --arg p "$p" '.findings[] | "\($p)/\(.file):\(.line) \(.problem)"')
done

# Corte real desde los avisos (T-158). INFORMATIVO: no cambia el veredicto — quien bloquea sigue
# siendo osv-scanner/npm audit arriba. Solo evita que el rango agregado dicte la versión de corte.
if [[ -n "$DEPS_TMP" ]]; then
  dc="${SCRIPT_DIR}/deps-cut.sh"
  i=0
  for p in "${INPUTS[@]}"; do
    if [[ -f "$DEPS_TMP/osv-$i.json" ]]; then
      if [[ -f "$DEPS_TMP/npm-$i.json" ]]; then
        bash "$dc" --osv "$DEPS_TMP/osv-$i.json" --npm-audit "$DEPS_TMP/npm-$i.json"
      else
        bash "$dc" --osv "$DEPS_TMP/osv-$i.json"
      fi
    fi
    i=$((i+1))
  done
fi
echo

# -------------------------------- VEREDICTO --------------------------------
echo "-------------------------------------------------------------"
if [[ "${#SKIPPED[@]}" -gt 0 ]]; then
  echo "OMITIDOS (no instalados o con error al ejecutarse): ${SKIPPED[*]} — en CI son gate duro (--strict)."
fi
if [[ "$SECRET_LEAK" -eq 1 ]]; then
  echo "FUGA DE SECRETO detectada → ROTA la credencial y purga el historial (severidad máxima)."
fi
if [[ "$FINDINGS" -gt 0 ]]; then
  echo "VEREDICTO: BLOQUEADO (${FINDINGS} peldaño(s) con hallazgo)."
  exit 1
fi
# T-160: "LIMPIO" afirma que se miró todo. Con peldaños sin correr, lo honesto es decir que no hubo
# hallazgos EN LO QUE SÍ SE MIRÓ. Sigue siendo exit 0: degrada, no rompe el commit de nadie.
if [[ "${#SKIPPED[@]}" -gt 0 ]]; then
  # T-257: con --strict (CI), un peldaño sin comprobar es un fallo: no hay verde sin haber mirado.
  if [[ "$STRICT" -eq 1 ]]; then
    echo "VEREDICTO: BLOQUEADO (cobertura incompleta con --strict: ${#SKIPPED[@]} peldaño(s) sin comprobar)."
    exit 1
  fi
  echo "VEREDICTO: SIN HALLAZGOS, pero COBERTURA INCOMPLETA (${#SKIPPED[@]} peldaño(s) sin comprobar)."
  exit 0
fi
echo "VEREDICTO: LIMPIO."
exit 0
