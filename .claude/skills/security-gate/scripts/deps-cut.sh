#!/usr/bin/env bash
#
# deps-cut.sh — la versión de corte REAL de un paquete vulnerable, derivada del AVISO y no del
# resumen del gestor de paquetes. Complemento informativo del peldaño 3 de `security-gate.sh`.
#
# POR QUÉ EXISTE (2026-08-21, Compass ATS — lección destilada, T-158):
#   `npm audit` colapsa los N avisos de un paquete en UNA entrada cuyo `range` es la **unión** de
#   todos. Se arrastró «CVE en better-auth <=1.6.21» cuando el aviso que afectaba a la versión
#   instalada se cerraba en **1.6.11**: el `<=1.6.21` lo estiraba otro aviso que ni siquiera aplicaba.
#   Coste real: se persiguió un salto a `latest` que exigía una columna de DB nueva en el login.
#
#   La regla, en una línea: **para decidir una versión de corte, ve al aviso (OSV/GHSA), no al
#   resumen agregado del gestor.** Este script la hace ejecutable en vez de dejarla en prosa.
#
# NO ES UN GATE, y es deliberado: informa y sale 0 siempre. Quien bloquea sigue siendo el peldaño 3
# (osv-scanner + npm audit) en `security-gate.sh`. Añadir aquí un exit no-cero sería meter una segunda
# opinión sobre lo mismo y dejar dos gates discrepando sobre el mismo paquete.
#
# Sin cloud y sin red: solo lee los JSON que las herramientas del peldaño 3 ya produjeron.
set -uo pipefail

usage() {
  cat <<'EOF'
deps-cut.sh — versión de corte real desde los avisos (OSV/GHSA), no desde el rango agregado del gestor

USO:
  deps-cut.sh --osv <osv-scanner.json> [--npm-audit <npm-audit.json>]

  --osv <f>         Salida JSON de `osv-scanner scan --format json` (los avisos INDIVIDUALES).
  --npm-audit <f>   Salida JSON de `npm audit --json` (el rango AGREGADO). Opcional: si se pasa, se
                    compara con el corte real y se delata cuando el gestor empuja más lejos.

SALIDA: por paquete, los avisos que afectan a la versión instalada con su `fixed`, la versión de
corte real (el mayor `fixed` de los aplicables) y, si procede, el aviso RANGO AGREGADO.

EXIT: siempre 0 — es informe, no gate. El gate es el peldaño 3 de security-gate.sh.

LÍMITE CONOCIDO (dicho, no escondido): el corte se calcula como el mayor `fixed` de los avisos que
aplican, que es lo correcto cuando cada rango es «todo lo anterior a fixed» — el caso normal. En un
paquete con varias ramas mantenidas a la vez (backports a 1.x y 2.x), el mínimo real puede estar en
la rama propia y no en el máximo global. Cuando eso pase, la tabla de avisos de arriba es la buena:
está para leerla, no para sustituir el criterio.
EOF
}

OSV=""
NPM_AUDIT=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --osv) OSV="${2:-}"; shift 2 || true ;;
    --npm-audit) NPM_AUDIT="${2:-}"; shift 2 || true ;;
    *) echo "ERROR: opción desconocida: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if ! command -v jq >/dev/null 2>&1; then
  echo "    WARN: jq no instalado → corte de deps OMITIDO (degrada, no peta)."
  exit 0
fi
if [[ -z "$OSV" || ! -f "$OSV" ]]; then
  echo "    WARN: sin JSON de osv-scanner (${OSV:-no indicado}) → no hay avisos de los que derivar el corte. Degrada."
  exit 0
fi

# ¿a < b? Comparación por VERSIÓN (sort -V), no por texto: 1.6.9 < 1.6.11, que como cadenas va al revés.
ver_lt() {
  [[ "$1" == "$2" ]] && return 1
  [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" == "$1" ]]
}
ver_le() { [[ "$1" == "$2" ]] || ver_lt "$1" "$2"; }

# Aplana osv-scanner a TSV: paquete, versión instalada, id del aviso, introduced, fixed.
# Se filtran los `affected` de OTROS paquetes (un aviso puede describir varios).
ROWS="$(jq -r '
  .results[]?.packages[]?
  | .package.name as $n | (.package.version // "") as $v
  | .vulnerabilities[]?
  | .id as $id
  | .affected[]?
  | select((.package.name // $n) == $n)
  | .ranges[]?
  | select((.type // "SEMVER") | ascii_upcase | test("SEMVER|ECOSYSTEM"))
  | {
      intro: ([.events[]? | .introduced // empty] | first // "0"),
      fixed: ([.events[]? | .fixed // empty] | first // "")
    }
  | [$n, $v, $id, .intro, .fixed] | @tsv
' "$OSV" 2>/dev/null || true)"

if [[ -z "$ROWS" ]]; then
  echo "    OK: sin vulnerabilidades de dependencias en el informe de osv-scanner."
  exit 0
fi

PKGS="$(printf '%s\n' "$ROWS" | cut -f1 | sort -u)"

echo "    Versión de corte derivada del AVISO (no del rango agregado del gestor):"
while IFS= read -r pkg; do
  [[ -n "$pkg" ]] || continue
  installed="$(printf '%s\n' "$ROWS" | awk -F'\t' -v p="$pkg" '$1==p {print $2; exit}')"
  echo "      · ${pkg}@${installed:-?}"

  cut_real=""
  aplicables=0
  while IFS=$'\t' read -r _p _v id intro fixed; do
    [[ "$_p" == "$pkg" ]] || continue
    if [[ -z "$fixed" ]]; then
      echo "          - ${id}: sin versión 'fixed' publicada → no da corte (léelo a mano)."
      continue
    fi
    # Aplica si: introduced <= instalada < fixed.
    if [[ -n "$installed" ]] && ver_le "${intro:-0}" "$installed" && ver_lt "$installed" "$fixed"; then
      echo "          - ${id}: afecta a ${installed} → se cierra en ${fixed}"
      aplicables=$((aplicables+1))
      if [[ -z "$cut_real" ]] || ver_lt "$cut_real" "$fixed"; then cut_real="$fixed"; fi
    else
      echo "          - ${id}: NO aplica a ${installed} (rango ${intro:-0} … ${fixed}) → no debe estirar el corte"
    fi
  done <<< "$ROWS"

  if [[ "$aplicables" -eq 0 ]]; then
    echo "        → ningún aviso afecta a la versión instalada."
    continue
  fi
  echo "        → corte real: ${cut_real}  (el mayor 'fixed' de los ${aplicables} aviso(s) que sí aplican)"

  # Contraste con el rango AGREGADO del gestor: es el que engañó en agosto.
  if [[ -n "$NPM_AUDIT" && -f "$NPM_AUDIT" ]]; then
    rango="$(jq -r --arg p "$pkg" '.vulnerabilities[$p].range // empty' "$NPM_AUDIT" 2>/dev/null || true)"
    if [[ -n "$rango" ]]; then
      # Corte que el gestor IMPLICA: '<X' pide >=X; '<=X' pide algo mayor que X.
      # gate-lint-allow: tail -n1 elige la última versión del rango, no traga ningún veredicto
      borde="$(printf '%s' "$rango" | grep -oE '[0-9]+(\.[0-9]+)*([-+][0-9A-Za-z.-]+)?' | tail -n1 || true)"
      inclusivo=0
      printf '%s' "$rango" | grep -q '<=' && inclusivo=1
      if [[ -n "$borde" ]]; then
        estira=0
        if [[ "$inclusivo" -eq 1 ]]; then
          # '<=borde' exige pasar de borde; si el corte real llega hasta borde, el gestor pide de más.
          ver_le "$cut_real" "$borde" && estira=1
        else
          ver_lt "$cut_real" "$borde" && estira=1
        fi
        if [[ "$estira" -eq 1 ]]; then
          echo "        ⚠ RANGO AGREGADO: el gestor declara '${rango}' y te empuja más lejos que ${cut_real}."
          echo "          Ese rango es la UNIÓN de TODOS los avisos del paquete, incluidos los que no te"
          echo "          afectan. Para decidir la versión de corte, ve al aviso — no al resumen."
        else
          echo "        (el rango del gestor '${rango}' concuerda con el corte real)"
        fi
      fi
    fi
  fi
done <<< "$PKGS"

exit 0
