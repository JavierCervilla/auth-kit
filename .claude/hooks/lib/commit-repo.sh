# shellcheck shell=bash
# lib/commit-repo.sh — ¿en QUÉ repo cae el `git commit` de un comando? (T-221)
#
# Los gates de commit (trajectory/anti-slop/security/ui-canvas) y el re-indexado (code-memory-refresh)
# resolvían el repo con `git rev-parse --show-toplevel` en el cwd del PROCESO del hook, que es el de
# la sesión, no el del comando. En sesiones multi-repo (cwd `/home/user`) los commits se hacen como
# `cd /home/user/FlyCLAIM && git commit …` o `git -C <repo> commit …`: con el cwd sin repo el gate
# salía por el fail-open sin mirar nada; con el cwd en otro repo, miraba el staging equivocado.
#
# Uso (sin subshell: deja el resultado en variables, y NO escribe nada por stdout, que en los
# PreToolUse es el canal del JSON de la decisión):
#   . lib/commit-repo.sh
#   repo_del_commit "$cmd" "$cwd_del_evento" || { commit_repo_avisar <hook> [--system-message]; exit 0; }
#   root="$COMMIT_REPO"
#
# Qué resuelve, por orden (sobre el PRIMER `git … commit` del comando):
#   1. `git -C <dir> … commit` (varias `-C` se componen, como en git, FÍSICAS: git hace chdir());
#   2. los `cd <dir>` anteriores (`&&`, `;`, saltos de línea, subshell con paréntesis —un `cd` dentro
#      de `( … )` ya cerrado no se hereda—, grupos `{ …; }`), componiendo la ruta LÓGICA como bash;
#   3. si no hay nada de eso, el `cwd` del evento;
#   4. y si el evento no lo trae, el cwd del proceso (lo de antes).
# El detector de «¿hay un commit?» también vive aquí, `es_git_commit`, y lo usan los cinco hooks.
#
# NUNCA ejecuta nada del comando: es un tokenizador de bash de juguete que solo quita comillas y
# expande `~`/`~/…` a `$HOME`.
#
# REGLA (ronda 4): SI EL RESULTADO NO ES SEGURO, AVISA. Nunca silencio. Dos niveles:
#   · INDETERMINADO → `repo_del_commit` sale 1 con el porqué en `COMMIT_REPO_AVISO` y el gate no mira
#     (fail-open); `commit_repo_avisar` lo dice por stderr y, en los PreToolUse, como `systemMessage`
#     (campo común de la salida de hooks: aviso que NO altera la decisión). Casos: ruta con `$VAR`,
#     `$(…)`, backticks, comodines o `~usuario`; `cd -`; `pushd`/`popd`; `GIT_DIR`/`GIT_WORK_TREE`
#     como prefijo, `export`/`declare -x` o asignación suelta, o `--git-dir`/`--work-tree` con `=` o
#     con el valor separado (ADV-4, B-R4);
#     un `cd` en una rama condicional —tras `&&`/`||` sin que el commit vaya en esa misma cadena `&&`,
#     o dentro de if/for/while/case— (ADV-3); ruta que no existe o no es un repo; palabra o ruta
#     compuesta de más de 4096 bytes; un commit que el detector ve pero el analizador no sitúa como
#     comando simple —`timeout`/`nice`/`xargs` delante, dentro de `$(…)`, `bash -c`, `eval`— (ADV-2);
#     y los dos topes de coste (abajo).
#   · RESUELTO PERO INCOMPLETO → sale 0 con `COMMIT_REPO`, y `COMMIT_REPO_NOTA` dice lo que el gate no
#     ve; `commit_repo_nota_al_salir` lo añade como `systemMessage` a la decisión del hook, sea cual
#     sea. Casos: más de un commit en el comando, solo se mira el primero (ADV-1); el staging se
#     decide en el propio comando —`git add/rm/mv/stage` antes, o `-a`/`--all`/pathspecs en el commit—
#     (ADV-8). El arreglo de fondo de ambos es el gate DENTRO de git (hook commit-msg, T-223), que
#     es el que decide; esto queda como aviso previo.
# Un `cd` en una tubería (`cd A | x`, `x | cd A`) o en segundo plano (`cd A &`, `cd A && x &`) corre
# en un subshell y no se aplica (ADV-7). Si NO hay `cd`/`-C` y el cwd no es un repo, sale 1 sin aviso:
# no hay nada que resolver (ese `git commit` fallaría igual).
#
# LÍMITES DECLARADOS (T-221). Desde T-223 no deciden: el gate dentro de git (`hooks/git/commit-msg`)
# mira el repo y el staging reales, y este analizador queda para el aviso temprano:
#   · el gate es un PreToolUse: PREDICE lo que hará bash; repo y staging reales solo existen al correr
#     el commit. De ahí ADV-1 y ADV-8: se avisan, no se miran;
#   · no entiende alias, funciones, `bash -c`, `xargs`, `eval`, `sh <<EOF` ni la expansión `{a,b}`:
#     si el commit va ahí dentro, se avisa (ADV-2); un `cd` ahí dentro no se ve;
#   · un `cd` condicional se trata como indeterminado aunque la rama sea evidente (`if true`): avisa de
#     más, no de menos;
#   · el detector (`es_git_commit`) reconoce `git` (también entre comillas) seguido de opciones
#     globales con su valor —pegado, con `=` o separado, y entre comillas con espacios (B-R4)— y
#     `commit`. Un commit que NO aparece así en el texto sale sin mirar y SIN aviso: alias de git
#     (`git ci`), alias o funciones de shell, `$GIT commit`, un script que commitea. Los ve el gate en git;
#   · el entorno de la sesión (un GIT_DIR exportado antes del comando) no se ve;
#   · Bash 3.2-safe (lo cargan anti-slop-gate y security-gate), sin verificar en 3.2.
#
# COSTE: el hook tiene 10 s de timeout y morir por timeout es un fail-open MUDO. En bash, `${s:i:1}`
# cuesta O(longitud de s) y `w="$w$c"` O(longitud de w), así que recorrer byte a byte era cuadrático.
# El parser lee por una VENTANA pequeña (`_CR_WIN`) que se rellena de un búfer intermedio
# (`_CR_BLOQUE`), avanza por TRAMOS (una expansión de patrón se traga de golpe la tirada de bytes sin
# significado), acota palabras, rutas compuestas y líneas de heredoc a 4096 bytes, quita los tabs de
# `<<-` por tramos (ADV-5) y reconoce `git … commit` incrementalmente (N4). Dos topes explícitos, los
# dos CON aviso: `_CR_TOPE` bytes (no se recorre) y `_CR_PASOS` pasos del analizador; cada paso es
# O(1), así que el tope acota el tiempo. El comando se recorre ENTERO (para contar commits, ADV-1).
# COTA MEDIDA (ronda 4, este contenedor, lib sola, 21 formas barridas repetidas hasta el tope): peor
# ~2,1 s, `(a)` repetido; el hook completo suma ~50 ms. Los tests exigen < 4 s a las más caras.

_CR_WIN=64
_CR_BLOQUE=8192
_CR_TOPE=262144
# Tope de PASOS del analizador (cada paso consume un tramo o un byte con significado). El coste
# por byte depende de la forma del comando: un tramo de 60 KB sin nada especial son ~1000 pasos, pero
# `(a)(a)(a)…` es un paso por byte. El tope en pasos acota el peor caso en tiempo (~2,1 s medidos, ver
# arriba) y, como el de bytes, sale indeterminado CON aviso, nunca por el timeout del hook, que es mudo.
# Bajó de 20000 a 15000 en la ronda 4: recorrer el comando entero encareció el paso medio.
_CR_PASOS=15000
# Bytes con significado fuera de comillas: todo lo demás se consume por tramos (ver `_cr_tramo`).
_CR_ESPECIALES=' 	
;&|()<>#\\'"'"'"$`~*?['

_cr_reset_word() { _cr_w=""; _cr_ws=0; _cr_wbad=""; _cr_wtilde=0; }

# Garantiza al menos 8 bytes en la ventana desde `_cr_i` (o todo lo que quede). Dos niveles, porque
# en bash cualquier `${s:i:n}` cuesta O(longitud de s): la ventana (`_CR_WIN`, pequeña: cada acceso
# byte a byte la paga) se rellena de un búfer intermedio (`_CR_BLOQUE`), y éste del comando completo.
# Así ningún acceso frecuente toca una cadena larga y el total es ~lineal en el tamaño del comando.
#
# Cada llamada cuenta un PASO (los bucles internos la llaman en cada vuelta): al pasar de `_CR_PASOS`
# marca `_cr_agotado` y agota la entrada, con lo que todos los bucles terminan.
_cr_fill() {
  _cr_pasos=$((_cr_pasos + 1))
  if [ "$_cr_pasos" -gt "$_CR_PASOS" ]; then
    _cr_agotado=1; _cr_i=$_cr_n; _cr_moff=$_cr_mN; _cr_off=$_cr_N; return 0
  fi
  [ $((_cr_n - _cr_i)) -lt 8 ] || return 0
  if [ "$_cr_moff" -ge "$_cr_mN" ]; then
    [ "$_cr_off" -lt "$_cr_N" ] || return 0
    _cr_mid="${_cr_full:$_cr_off:$_CR_BLOQUE}"; _cr_off=$((_cr_off + _CR_BLOQUE))
    _cr_mN=${#_cr_mid}; _cr_moff=0
  fi
  _cr_s="${_cr_s:$_cr_i}${_cr_mid:$_cr_moff:$_CR_WIN}"
  _cr_moff=$((_cr_moff + _CR_WIN)); _cr_i=0; _cr_n=${#_cr_s}
}

# Consume, dentro de la ventana, la tirada de bytes que NO están en el conjunto `$1` (patrón de
# corchete) y la añade a la palabra. Al menos un byte, para avanzar siempre.
_cr_tramo() {
  local r="${_cr_s:$_cr_i}"
  r="${r%%[$1]*}"
  [ -n "$r" ] || r="${_cr_s:$_cr_i:1}"
  _cr_add "$r"; _cr_i=$((_cr_i + ${#r}))
}

# Añade a la palabra en curso. Una palabra de más de 4096 bytes (PATH_MAX en Linux) no puede ser una
# ruta a la que hacer `cd`: se deja de copiar —si no, concatenar tramo a tramo es cuadrático— y se
# marca como indeterminada por si acabara siendo el destino de un `cd`/`-C`.
_cr_add() {
  if [ "${#_cr_w}" -lt 4096 ]; then _cr_w="$_cr_w$1"; else _cr_wbad="palabra de más de 4096 bytes"; fi
}

# Texto crudo de una sustitución que se salta: solo sirve para el aviso, así que se recorta.
_cr_crudo() { [ "${#_cr_w}" -ge 200 ] || _cr_w="$_cr_w$1"; }

# Mueve el directorio actual del parser. _cr_move <destino> <razón-si-indeterminado> <etiqueta>
# `cd` compone la ruta LÓGICA, como bash (`..` deshace el último componente, aunque sea un symlink);
# `git -C` la deja tal cual, porque git hace `chdir()` y el kernel la resuelve FÍSICA (ADV-7).
_cr_move() {
  _cr_explicit=1
  if [ -n "$2" ]; then _cr_indet="$3 $1: $2"; return 0; fi
  [ -n "$1" ] || return 0                       # `cd ""` / `git -C ""` no mueven
  if [ "$3" = cd ]; then
    _cr_logico "$1"
  else
    case "$1" in
      /*) _cr_dir="$1"; _cr_indet="" ;;         # absoluta: vuelve a dejarlo determinado
      *)  [ -n "$_cr_indet" ] || _cr_dir="${_cr_dir%/}/$1" ;;
    esac
  fi
  # Cada `cd` relativo alarga la ruta compuesta, y copiarla es O(su longitud): `cd a/b;` repetido
  # miles de veces era cuadrático (13 s). Más de 4096 bytes (PATH_MAX) no es una ruta: indeterminado.
  if [ "${#_cr_dir}" -gt 4096 ] && [ -z "$_cr_indet" ]; then
    _cr_indet="ruta compuesta de más de 4096 bytes"
  fi
}

# Compone la ruta lógica de `cd <destino>` sobre `_cr_dir`, componente a componente. Cada componente
# cuenta un paso (el tope de pasos acota también esto).
_cr_logico() {
  local d rest comp
  case "$1" in
    /*) d=/; _cr_indet="" ;;
    *)  [ -z "$_cr_indet" ] || return 0; d="$_cr_dir" ;;
  esac
  rest="$1/"
  while [ -n "$rest" ]; do
    comp="${rest%%/*}"; rest="${rest#*/}"; _cr_pasos=$((_cr_pasos + 1))
    case "$comp" in
      ''|.) ;;
      ..) d="${d%/*}"; [ -n "$d" ] || d=/ ;;
      *) d="${d%/}/$comp" ;;
    esac
  done
  _cr_dir="$d"
}

# ¿Es el comando simple en curso un `git … commit`? Se decide INCREMENTALMENTE, una palabra cada vez
# y en O(1): una máquina de estados sobre prefijos → `git` → opciones globales → subcomando. Antes se
# re-recorría el comando desde el principio con cada palabra `commit` y eso era cuadrático, fuera del
# tope de pasos: `env `×1100 + `commit `×1100 mataba el hook por timeout, mudo (T-221 ronda 3, N4).
#   _cr_gst: 0 prefijos · 1 opciones de git · 3 espera el dir de `-C` · 4 espera el valor de otra
#            opción · 5 argumentos del PRIMER commit (¿`-a`, pathspecs?) · 7 tras `--` · 9 nada más
#            que mirar en este comando.  Se reinicia con cada comando simple (`_cr_reset_cmd`).
_cr_reset_cmd() {
  _cr_words=(); _cr_bads=(); _cr_nw=0
  _cr_gst=0; _cr_gitenv=0; _cr_cw=(); _cr_cb=(); _cr_nc=0; _cr_cval=0
}

_cr_git_palabra() {   # _cr_git_palabra <palabra> <razón-si-indeterminada>
  local re='^[A-Za-z_][A-Za-z0-9_]*='
  case "$_cr_gst" in
    0)
      case "$1" in
        GIT_DIR=*|GIT_WORK_TREE=*) _cr_gitenv=1 ;;
        if|then|else|elif|do|while|until|'!'|'{'|command|time|exec|nohup|env) ;;
        git|*/git) _cr_gst=1 ;;
        *) [[ $1 =~ $re ]] || _cr_gst=9 ;;
      esac ;;
    1)
      case "$1" in
        commit) _cr_git_commit ;;
        add|rm|mv|stage) [ "$_cr_found" = 1 ] || _cr_stage=1; _cr_gst=9 ;;   # ADV-8
        -C) _cr_gst=3 ;;
        -C*) _cr_cw[_cr_nc]="${1#-C}"; _cr_cb[_cr_nc]="$2"; _cr_nc=$((_cr_nc + 1)) ;;
        -c|--namespace|--config-env|--exec-path|--super-prefix) _cr_gst=4 ;;
        --git-dir|--work-tree) _cr_gitenv=1; _cr_gst=4 ;;
        --git-dir=*|--work-tree=*) _cr_gitenv=1 ;;
        -*) ;;
        *) _cr_gst=9 ;;                         # otro subcomando (`git log`, `git add`…)
      esac ;;
    3) _cr_cw[_cr_nc]="$1"; _cr_cb[_cr_nc]="$2"; _cr_nc=$((_cr_nc + 1)); _cr_gst=1 ;;
    4) _cr_gst=1 ;;
    5) _cr_commit_arg "$1" ;;
    7) _cr_cpaths=1; _cr_gst=9 ;;
  esac
  return 0
}

# Argumentos del primer `git commit`: si lleva `-a`/`--all` o pathspecs, lo que se commitea NO es el
# staging que el gate puede ver antes de que corra el comando (ADV-8).
_cr_commit_arg() {
  if [ "$_cr_cval" = 1 ]; then _cr_cval=0; return 0; fi     # valor de la opción anterior
  local o ch
  case "$1" in
    --) _cr_gst=7 ;;
    --all) _cr_call=1 ;;
    --pathspec-from-file|--pathspec-from-file=*) _cr_cpaths=1 ;;
    --message|--file|--reuse-message|--reedit-message|--template|--author|--date|--cleanup|--fixup|--squash|--trailer)
      _cr_cval=1 ;;
    --*) ;;
    -?*)
      o="${1#-}"
      while [ -n "$o" ]; do
        ch="${o:0:1}"; o="${o:1}"
        case "$ch" in
          a) _cr_call=1 ;;
          m|F|C|c|t) [ -n "$o" ] || _cr_cval=1; break ;;
          S|u) break ;;                                      # valor opcional pegado
        esac
      done ;;
    *) _cr_cpaths=1 ;;
  esac
}

# Ha llegado el `commit` de un `git …`. El PRIMERO fija el resultado (sus `-C` aplicados); el recorrido
# sigue solo para CONTAR los demás (ADV-1) y leer los argumentos del primero (ADV-8).
_cr_git_commit() {
  _cr_ncommits=$((_cr_ncommits + 1))
  if [ "$_cr_found" = 1 ]; then _cr_gst=9; return 0; fi
  _cr_found=1; _cr_gst=5
  local c=0
  while [ "$c" -lt "$_cr_nc" ]; do _cr_move "${_cr_cw[$c]}" "${_cr_cb[$c]}" "git -C"; c=$((c + 1)); done
  if [ "$_cr_gitenv" = 1 ] || [ "$_cr_gitenv_g" = 1 ]; then
    _cr_explicit=1
    _cr_indet="GIT_DIR/GIT_WORK_TREE/--git-dir/--work-tree cambian el repo y no los interpreto"
  fi
  if [ "$_cr_lcd" = 1 ] && [ "$_cr_lor" = 1 ]; then     # `cd A || git commit`: ¿corrió el cd? (ADV-3)
    _cr_explicit=1; _cr_indet="un cd y un || en la misma cadena que el commit: no sé qué rama corre"
  fi
  _cr_r_dir="$_cr_dir"; _cr_r_indet="$_cr_indet"; _cr_r_explicit="$_cr_explicit"
}

_cr_finish_word() {
  [ "$_cr_ws" = 1 ] || return 0
  if [ "$_cr_wtilde" = 1 ]; then
    case "$_cr_w" in
      "~") _cr_w="$HOME" ;;
      "~/"*) _cr_w="$HOME${_cr_w#\~}" ;;
      *) [ -n "$_cr_wbad" ] || _cr_wbad="~usuario no se expande" ;;
    esac
  fi
  case "$_cr_redir" in
    1) _cr_redir=0; _cr_reset_word; return 0 ;;                    # destino de una redirección
    2|3) _cr_hd[_cr_nhd]="$_cr_w"; _cr_hdt[_cr_nhd]=$((_cr_redir - 2)); _cr_nhd=$((_cr_nhd + 1))
         _cr_redir=0; _cr_reset_word; return 0 ;;                  # delimitador de heredoc
  esac
  _cr_words[_cr_nw]="$_cr_w"; _cr_bads[_cr_nw]="$_cr_wbad"; _cr_nw=$((_cr_nw + 1))
  [ "$_cr_gst" = 9 ] || _cr_git_palabra "$_cr_w" "$_cr_wbad"
  _cr_reset_word
}

# Empieza una lista nueva (tras `;`, salto de línea, `&` o al abrir un subshell): foto del estado
# para deshacer la lista si acaba en segundo plano, y contadores de la cadena `&&`/`||` a cero.
_cr_lista_nueva() {
  _cr_ls_dir="$_cr_dir"; _cr_ls_indet="$_cr_indet"; _cr_ls_exp="$_cr_explicit"
  _cr_lpos=0; _cr_lor=0; _cr_lcd=0; _cr_lcdcond=0; _cr_inpipe=0
}

# Fin de un comando simple. _cr_end_cmd <terminador: ; nl && || | & ( ) eof>
#   · un `cd` se aplica salvo en una tubería o en segundo plano, que corren en un subshell (ADV-7);
#   · un `cd` que depende de una condición (tras `&&`/`||` en su cadena, o dentro de if/for/while/
#     case) deja el resultado indeterminado si el commit no va en esa misma cadena `&&` (ADV-3);
#   · `export`/`declare -x`/asignación suelta de GIT_DIR o GIT_WORK_TREE → indeterminado (ADV-4).
_cr_end_cmd() {
  _cr_finish_word
  if [ "$_cr_found" = 1 ]; then _cr_reset_cmd; return 0; fi
  local k=0 w re='^[A-Za-z_][A-Za-z0-9_]*=' t="${1:-eof}"
  if [ "$_cr_nw" -gt 0 ]; then
    case "${_cr_words[0]}" in
      if|while|until|for|case|select) _cr_blk=$((_cr_blk + 1)) ;;
      fi|done|esac) [ "$_cr_blk" = 0 ] || _cr_blk=$((_cr_blk - 1)) ;;
      # `{ …; }` agrupa sin subshell: dentro empieza una cadena nueva, y al cerrar, la cadena de fuera
      # hereda «hubo un cd» (condicional si el grupo lo era). `cd A && { cd B; } && git commit` → B.
      '{') _cr_bst[_cr_bn]="$_cr_lpos $_cr_lor $_cr_lcd $_cr_lcdcond $_cr_bcd"; _cr_bn=$((_cr_bn + 1))
           _cr_lpos=0; _cr_lor=0; _cr_lcd=0; _cr_lcdcond=0; _cr_bcd=0 ;;
      '}') if [ "$_cr_bn" -gt 0 ]; then
             local dentro="$_cr_bcd"
             _cr_bn=$((_cr_bn - 1))
             set -- ${_cr_bst[$_cr_bn]}
             _cr_lpos=$1; _cr_lor=$2; _cr_lcd=$3; _cr_lcdcond=$4; _cr_bcd=$5
             if [ "$dentro" = 1 ]; then
               _cr_lcd=1; _cr_bcd=1; [ "$_cr_lpos" = 1 ] && _cr_lcdcond=1
             fi
           fi ;;
    esac
  fi
  while [ "$k" -lt "$_cr_nw" ]; do
    w="${_cr_words[$k]}"
    case "$w" in
      if|then|else|elif|do|while|until|'!'|'{'|command|builtin) ;;
      GIT_DIR=*|GIT_WORK_TREE=*) _cr_gdtmp=1 ;;
      *) [[ $w =~ $re ]] || break ;;
    esac
    k=$((k + 1))
  done
  if [ "$k" -ge "$_cr_nw" ]; then
    [ "${_cr_gdtmp:-0}" = 1 ] && _cr_gitenv_g=1        # `GIT_DIR=x;` suelto: queda en el entorno
  else
    case "${_cr_words[$k]}" in
      export|declare|typeset|readonly|local)
        while [ "$k" -lt "$_cr_nw" ]; do
          case "${_cr_words[$k]}" in GIT_DIR|GIT_DIR=*|GIT_WORK_TREE|GIT_WORK_TREE=*) _cr_gitenv_g=1 ;; esac
          k=$((k + 1))
        done ;;
      cd)
        if [ "$_cr_inpipe" = 0 ] && [ "$t" != '|' ] && [ "$t" != '&' ]; then
          k=$((k + 1))
          while [ "$k" -lt "$_cr_nw" ]; do
            case "${_cr_words[$k]}" in
              --) k=$((k + 1)); break ;;
              -[LPe@]*) k=$((k + 1)) ;;
              *) break ;;
            esac
          done
          if [ "$k" -ge "$_cr_nw" ]; then
            _cr_move "$HOME" "" cd
          elif [ "${_cr_words[$k]}" = "-" ]; then
            _cr_move "-" "vuelve al directorio anterior" cd
          else
            _cr_move "${_cr_words[$k]}" "${_cr_bads[$k]}" cd
          fi
          _cr_lcd=1; _cr_bcd=1
          if [ "$_cr_blk" -gt 0 ]; then
            _cr_indet="cd dentro de un if/for/while/case: no sé si corre"
          elif [ "$_cr_lpos" = 1 ]; then
            _cr_lcdcond=1
          fi
        fi ;;
      pushd|popd)
        _cr_explicit=1; _cr_indet="${_cr_words[$k]} no se interpreta" ;;
    esac
  fi
  _cr_gdtmp=0
  _cr_reset_cmd
  case "$t" in
    '&&') _cr_lpos=1; _cr_inpipe=0 ;;
    '||') _cr_lpos=1; _cr_lor=1; _cr_inpipe=0 ;;
    '|')  _cr_inpipe=1 ;;
    '&')  _cr_dir="$_cr_ls_dir"; _cr_indet="$_cr_ls_indet"; _cr_explicit="$_cr_ls_exp"   # corrió aparte
          _cr_lista_nueva ;;
    ';'|nl|')'|eof)
          if [ "$_cr_lcdcond" = 1 ]; then
            _cr_explicit=1; _cr_indet="cd en una rama condicional (&&/||) antes del commit: no sé si corrió"
          fi
          _cr_lista_nueva ;;
  esac
}

# Salta un `$( … )` / `<( … )` desde el índice del `(`; añade (recortado) el texto crudo. Entiende
# los heredocs de dentro (`$(cat <<'EOF' … EOF)`): su cuerpo no son comillas ni paréntesis (ADV-2).
_cr_skip_paren() {
  local depth=0 c q="" rest part nl=$'\n' d dt
  local -a hd=() ht=(); local nh=0 h
  while _cr_fill; [ "$_cr_i" -lt "$_cr_n" ]; do
    rest="${_cr_s:$_cr_i}"
    if [ -n "$q" ]; then
      case "$rest" in
        *"$q"*) part="${rest%%"$q"*}"; _cr_crudo "$part$q"; _cr_i=$((_cr_i + ${#part} + 1)); q="" ;;
        *) _cr_crudo "$rest"; _cr_i=$_cr_n ;;
      esac
      continue
    fi
    c="${rest:0:1}"
    case "$c" in
      "'"|'"') q="$c"; _cr_crudo "$c"; _cr_i=$((_cr_i + 1)) ;;
      '(') depth=$((depth + 1)); _cr_crudo "$c"; _cr_i=$((_cr_i + 1)) ;;
      ')') depth=$((depth - 1)); _cr_crudo "$c"; _cr_i=$((_cr_i + 1)); [ "$depth" -gt 0 ] || return 0 ;;
      '<')
        if [ "${rest:1:1}" = '<' ] && [ "${rest:2:1}" != '<' ]; then
          _cr_i=$((_cr_i + 2)); dt=0
          [ "${_cr_s:$_cr_i:1}" = '-' ] && { dt=1; _cr_i=$((_cr_i + 1)); }
          d=""
          while _cr_fill; [ "$_cr_i" -lt "$_cr_n" ]; do
            c="${_cr_s:$_cr_i:1}"
            case "$c" in
              ' '|$'\t') [ -z "$d" ] || break ;;
              "'"|'"'|'\') ;;
              $'\n'|';'|'&'|'|'|'('|')'|'<'|'>') break ;;
              *) [ "${#d}" -ge 4096 ] || d="$d$c" ;;
            esac
            _cr_i=$((_cr_i + 1))
          done
          hd[nh]="$d"; ht[nh]="$dt"; nh=$((nh + 1))
        else
          _cr_crudo "$c"; _cr_i=$((_cr_i + 1))
        fi ;;
      "$nl")
        _cr_i=$((_cr_i + 1)); h=0
        while [ "$h" -lt "$nh" ]; do
          while _cr_fill; [ "$_cr_i" -lt "$_cr_n" ]; do
            _cr_leer_linea "${ht[$h]}"; [ "$_cr_linea" = "${hd[$h]}" ] && break
          done
          h=$((h + 1))
        done
        hd=(); ht=(); nh=0 ;;
      *) part="${rest%%[\'\"()<$nl]*}"; [ -n "$part" ] || part="$c"; _cr_crudo "$part"; _cr_i=$((_cr_i + ${#part})) ;;
    esac
  done
}

# Salta hasta el cierre `$1` (backtick o `}`), añadiendo (recortado) el texto crudo.
_cr_skip_to() {
  local rest part
  while _cr_fill; [ "$_cr_i" -lt "$_cr_n" ]; do
    rest="${_cr_s:$_cr_i}"
    case "$rest" in
      *"$1"*) part="${rest%%"$1"*}"; _cr_crudo "$part$1"; _cr_i=$((_cr_i + ${#part} + 1)); return 0 ;;
      *) _cr_crudo "$rest"; _cr_i=$_cr_n ;;
    esac
  done
}

# `$` en la posición actual (fuera de comillas simples): marca la palabra como indeterminada.
_cr_dollar() {
  local nx="${_cr_s:$((_cr_i + 1)):1}"
  case "$nx" in
    '(') _cr_wbad="sustitución \$(…)"; _cr_w="$_cr_w\$"; _cr_i=$((_cr_i + 1)); _cr_skip_paren ;;
    '{') _cr_wbad="variable"; _cr_w="$_cr_w\$"; _cr_i=$((_cr_i + 1)); _cr_skip_to '}' ;;
    [A-Za-z_]) _cr_wbad="variable"; _cr_w="$_cr_w\$"; _cr_i=$((_cr_i + 1))
       while _cr_fill; [ "$_cr_i" -lt "$_cr_n" ]; do
         case "${_cr_s:$_cr_i:1}" in [A-Za-z0-9_]) _cr_crudo "${_cr_s:$_cr_i:1}"; _cr_i=$((_cr_i + 1)) ;; *) break ;; esac
       done ;;
    [0-9@*#?\$!-]) _cr_wbad="variable"; _cr_w="$_cr_w\$$nx"; _cr_i=$((_cr_i + 2)) ;;
    "'"|'"') _cr_wbad="cita \$'…'"; _cr_w="$_cr_w\$"; _cr_i=$((_cr_i + 1)) ;;
    *) _cr_w="$_cr_w\$"; _cr_i=$((_cr_i + 1)) ;;
  esac
}

# Lee una línea (sin el salto) cruzando ventanas; la deja en `_cr_linea`. _cr_leer_linea [1 = `<<-`]
# Con `<<-` quita los tabuladores del principio POR TRAMOS de ventana (antes, de uno en uno sobre la
# línea entera: cuadrático y fuera del tope, ADV-5). Guarda como mucho 4097 bytes: una línea más larga
# no puede ser un delimitador (las palabras se acotan a 4096).
_cr_leer_linea() {
  local rest part fin lead="${1:-0}" tab=$'\t' t
  _cr_linea=""
  while _cr_fill; [ "$_cr_i" -lt "$_cr_n" ]; do
    rest="${_cr_s:$_cr_i}"
    case "$rest" in
      *$'\n'*) part="${rest%%$'\n'*}"; _cr_i=$((_cr_i + ${#part} + 1)); fin=1 ;;
      *) part="$rest"; _cr_i=$_cr_n; fin=0 ;;
    esac
    if [ "$lead" = 1 ]; then
      t="${part%%[!$tab]*}"; part="${part#"$t"}"; [ -z "$part" ] || lead=0
    fi
    [ "${#_cr_linea}" -gt 4096 ] || _cr_linea="$_cr_linea$part"
    [ "$fin" = 1 ] && return 0
  done
}

# Tras un salto de línea (en `_cr_i`, ya consumido), se come el cuerpo de los heredocs pendientes.
_cr_eat_heredocs() {
  local h=0
  while [ "$h" -lt "$_cr_nhd" ]; do
    while _cr_fill; [ "$_cr_i" -lt "$_cr_n" ]; do
      _cr_leer_linea "${_cr_hdt[$h]}"
      [ "$_cr_linea" = "${_cr_hd[$h]}" ] && break
    done
    h=$((h + 1))
  done
  _cr_hd=(); _cr_hdt=(); _cr_nhd=0
}

# Recorre el comando. Deja: _cr_found (0/1), _cr_dir, _cr_indet, _cr_explicit.
_cr_parse() {
  # Byte a byte: en una locale UTF-8, `${s:i:1}` recorre desde el principio en cada acceso (coste
  # cuadrático; ~3x más lento medido). Las rutas no ASCII salen igual: se copian sus bytes tal cual.
  # Va ANTES de medir `${#1}`: medido en caracteres, el bucle se quedaba corto en bytes y perdía el
  # final del comando con cualquier ruta no ASCII.
  local LC_ALL=C
  _cr_full="$1"; _cr_N=${#1}; _cr_off=0; _cr_mid=""; _cr_mN=0; _cr_moff=0; _cr_s=""; _cr_n=0; _cr_i=0
  _cr_dir="$2"; _cr_indet=""; _cr_explicit=0; _cr_found=0; _cr_ncommits=0
  _cr_r_dir=""; _cr_r_indet=""; _cr_r_explicit=0
  _cr_stage=0; _cr_call=0; _cr_cpaths=0; _cr_gitenv_g=0; _cr_gdtmp=0; _cr_blk=0
  _cr_bst=(); _cr_bn=0; _cr_bcd=0
  _cr_reset_cmd
  _cr_lista_nueva
  _cr_hd=(); _cr_hdt=(); _cr_nhd=0; _cr_redir=0; _cr_arr=0
  # Pila de subshells: el estado de fuera (dir y cadena en curso) se recupera al cerrar el paréntesis.
  local -a sd=() si=() se=() sl=(); local sn=0
  local c nx n2 rest
  _cr_pasos=0; _cr_agotado=0
  _cr_reset_word
  while :; do
    _cr_fill
    [ "$_cr_i" -lt "$_cr_n" ] || break
    c="${_cr_s:$_cr_i:1}"
    case "$c" in
      '&'|'|'|'<'|'>'|'\') nx="${_cr_s:$((_cr_i + 1)):1}" ;;
    esac
    case "$c" in
      ' '|$'\t') [ "$_cr_ws" = 0 ] || _cr_finish_word; _cr_i=$((_cr_i + 1)) ;;
      $'\n') _cr_end_cmd nl; _cr_i=$((_cr_i + 1)); [ "$_cr_nhd" = 0 ] || _cr_eat_heredocs ;;
      ';') _cr_end_cmd ';'; _cr_i=$((_cr_i + 1)) ;;
      '&')
        if [ "$nx" = '>' ]; then
          _cr_finish_word; _cr_redir=1; _cr_i=$((_cr_i + 2))
          [ "${_cr_s:$_cr_i:1}" = '>' ] && _cr_i=$((_cr_i + 1))
        elif [ "$nx" = '&' ]; then
          _cr_end_cmd '&&'; _cr_i=$((_cr_i + 2))
        else
          _cr_end_cmd '&'; _cr_i=$((_cr_i + 1))
        fi ;;
      '|')
        if [ "$nx" = '|' ]; then _cr_end_cmd '||'; _cr_i=$((_cr_i + 2))
        else _cr_end_cmd '|'; _cr_i=$((_cr_i + 1)); [ "$nx" = '&' ] && _cr_i=$((_cr_i + 1)); fi ;;
      '(')
        if [ "$_cr_ws" = 1 ]; then                # `a=(…)`: asignación de array, no subshell
          _cr_arr=$((_cr_arr + 1)); _cr_w="$_cr_w("; _cr_i=$((_cr_i + 1))
        else
          _cr_end_cmd '('
          sd[sn]="$_cr_dir"; si[sn]="$_cr_indet"; se[sn]="$_cr_explicit"
          sl[sn]="$_cr_lpos $_cr_lor $_cr_lcd $_cr_lcdcond $_cr_inpipe"; sn=$((sn + 1))
          _cr_lista_nueva
          _cr_i=$((_cr_i + 1))
        fi ;;
      ')')
        if [ "$_cr_arr" -gt 0 ]; then
          _cr_arr=$((_cr_arr - 1)); _cr_w="$_cr_w)"; _cr_i=$((_cr_i + 1))
        else
          _cr_end_cmd ')'
          if [ "$sn" -gt 0 ]; then
            sn=$((sn - 1)); _cr_dir="${sd[$sn]}"; _cr_indet="${si[$sn]}"; _cr_explicit="${se[$sn]}"
            set -- ${sl[$sn]}
            _cr_lpos=$1; _cr_lor=$2; _cr_lcd=$3; _cr_lcdcond=$4; _cr_inpipe=$5
          fi
          _cr_i=$((_cr_i + 1))
        fi ;;
      '<'|'>')
        if [ "$nx" = '(' ]; then                  # <(…) / >(…): sustitución de proceso
          _cr_ws=1; _cr_wbad="sustitución de proceso"; _cr_w="$_cr_w$c"; _cr_i=$((_cr_i + 1)); _cr_skip_paren
        else
          case "$_cr_w" in *[!0-9]*|'') _cr_finish_word ;; *) _cr_reset_word ;; esac   # `2>` → fd
          n2="${_cr_s:$_cr_i:3}"
          case "$n2" in
            '<<<') _cr_redir=1; _cr_i=$((_cr_i + 3)) ;;
            '<<-') _cr_redir=3; _cr_i=$((_cr_i + 3)) ;;
            '<<'*) _cr_redir=2; _cr_i=$((_cr_i + 2)) ;;
            '<>'*|'<&'*|'>>'*|'>&'*|'>|'*) _cr_redir=1; _cr_i=$((_cr_i + 2)) ;;
            *) _cr_redir=1; _cr_i=$((_cr_i + 1)) ;;
          esac
        fi ;;
      '#')
        if [ "$_cr_ws" = 0 ]; then                # comentario hasta el fin de línea
          while _cr_fill; [ "$_cr_i" -lt "$_cr_n" ]; do   # hasta el salto, sin consumirlo
            rest="${_cr_s:$_cr_i}"
            case "$rest" in
              *$'\n'*) rest="${rest%%$'\n'*}"; _cr_i=$((_cr_i + ${#rest})); break ;;
              *) _cr_i=$_cr_n ;;
            esac
          done
        else
          _cr_w="$_cr_w#"; _cr_i=$((_cr_i + 1))
        fi ;;
      '\')
        if [ "$nx" = $'\n' ]; then _cr_i=$((_cr_i + 2))
        else _cr_w="$_cr_w$nx"; _cr_ws=1; _cr_i=$((_cr_i + 2)); fi ;;
      "'")
        _cr_ws=1; _cr_i=$((_cr_i + 1))
        while _cr_fill; [ "$_cr_i" -lt "$_cr_n" ]; do
          rest="${_cr_s:$_cr_i}"
          case "$rest" in
            *"'"*) rest="${rest%%\'*}"; _cr_add "$rest"; _cr_i=$((_cr_i + ${#rest} + 1)); break ;;
            *) _cr_add "$rest"; _cr_i=$_cr_n ;;
          esac
        done ;;
      '"')
        _cr_ws=1; _cr_i=$((_cr_i + 1))
        while _cr_fill; [ "$_cr_i" -lt "$_cr_n" ]; do
          c="${_cr_s:$_cr_i:1}"
          case "$c" in
            '"') break ;;
            '\')
              nx="${_cr_s:$((_cr_i + 1)):1}"
              case "$nx" in
                '$'|'`'|'"'|'\') _cr_w="$_cr_w$nx" ;;
                $'\n') ;;
                *) _cr_w="$_cr_w\\$nx" ;;
              esac
              _cr_i=$((_cr_i + 2)) ;;
            '$') _cr_dollar ;;
            '`') _cr_wbad="sustitución \`…\`"; _cr_w="$_cr_w\`"; _cr_i=$((_cr_i + 1)); _cr_skip_to '`' ;;
            *) _cr_tramo '"\\$`' ;;
          esac
        done
        _cr_i=$((_cr_i + 1)) ;;
      '$') _cr_ws=1; _cr_dollar ;;
      '`') _cr_ws=1; _cr_wbad="sustitución \`…\`"; _cr_w="$_cr_w\`"; _cr_i=$((_cr_i + 1)); _cr_skip_to '`' ;;
      '~') [ "$_cr_ws" = 1 ] || _cr_wtilde=1; _cr_ws=1; _cr_w="$_cr_w~"; _cr_i=$((_cr_i + 1)) ;;
      '*'|'?'|'[') _cr_ws=1; _cr_wbad="comodín"; _cr_w="$_cr_w$c"; _cr_i=$((_cr_i + 1)) ;;
      *) _cr_ws=1                                 # tramo sin nada especial (en línea: es el caso caliente)
         rest="${_cr_s:$_cr_i}"; rest="${rest%%[$_CR_ESPECIALES]*}"; [ -n "$rest" ] || rest="$c"
         if [ "${#_cr_w}" -lt 4096 ]; then _cr_w="$_cr_w$rest"; else _cr_wbad="palabra de más de 4096 bytes"; fi
         _cr_i=$((_cr_i + ${#rest})) ;;
    esac
  done
  [ "$_cr_agotado" = 1 ] && return 0
  _cr_end_cmd eof
}

# es_git_commit <comando> — ¿hay un `git [opciones globales] commit` en el comando? El detector de
# los cinco hooks vive AQUÍ (ADV-6): antes cada hook llevaba su copia del `grep` y ninguna entendía
# la continuación de línea (`git -C R \<salto> commit`). Se normaliza `\`+salto a espacio y se busca
# por patrón. `commit-tree`/`commit-graph` no son commits del árbol de trabajo: no cuentan.
es_git_commit() { es_git_sub "$1" commit; }

# es_git_sub <comando> <subcomandos ERE> — ¿hay un `git [opciones globales] <subcomando>` en el comando?
# El mismo detector que `es_git_commit` (T-223 lo usa también para `cherry-pick|am`).
es_git_sub() {
  local LC_ALL=C c="$1" sub="$2" bsnl=$'\\\n'
  case "$c" in *git*) ;; *) return 1 ;; esac
  c="${c//"$bsnl"/ }"
  # Un VALOR de opción: sin comillas, o con tramos entre comillas simples/dobles que pueden llevar
  # espacios (`user.name="Claude Bot"`, `"/ruta con espacios"`). B-R4: antes solo valía pegado y sin
  # espacios, y `--git-dir X`, `-c k="a b"` o `-C "a b"` dejaban al hook mudo.
  local v="([^[:space:]\"']|\"[^\"]*\"|'[^']*')+"
  local o="-[cC][[:space:]]*$v|--(git-dir|work-tree|namespace|exec-path|super-prefix|config-env)([[:space:]]+|=)$v|--[a-z-]+(=$v)?|-[a-zA-Z][^[:space:]]*"
  # `git` también entre comillas (`"git" commit`): el analizador ya le quita las comillas.
  printf '%s' "$c" | grep -Eq "(^|[^a-zA-Z])[\"']?git[\"']?([[:space:]]+($o))*[[:space:]]+($sub)(\$|[^a-zA-Z-])"
}

# comando_evade_gate <comando> → 0 si el TEXTO del comando (en cualquier parte: también dentro de
# `bash -c`, `eval` o tras `$G`) lleva una forma reconocible de saltarse el gate en git (T-223), con el
# motivo en COMMIT_EVASION. Solo mira comandos que mencionan `git`. Lectura de texto a propósito: es un
# gate de disciplina, no una frontera contra un agente que quiera evadirlo (ver LÍMITES en
# `lib/git-hooks.sh`). Cuenta:
#   · `--no-verify` (se salta los hooks de git);
#   · `core.hooksPath`, sin distinguir mayúsculas (cambia qué hooks ejecuta git);
#   · `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_*`, `GIT_CONFIG_PARAMETERS` (configuración por entorno);
#   · `commit-tree`, `fast-import` y `hash-object -t commit` (crean commits sin pasar por `git commit` ni
#     sus hooks);
#   · escribir, borrar, mover o `chmod` sobre `hooks/commit-msg`.
comando_evade_gate() {
  COMMIT_EVASION=""
  local LC_ALL=C c="$1" low
  case "$c" in *git*) ;; *) return 1 ;; esac
  low="$(printf '%s' "$c" | tr 'A-Z' 'a-z')"
  case "$c" in *--no-verify*) COMMIT_EVASION="--no-verify"; return 0 ;; esac
  case "$low" in *core.hookspath*) COMMIT_EVASION="core.hooksPath"; return 0 ;; esac
  case "$c" in *GIT_CONFIG_COUNT*|*GIT_CONFIG_KEY_*|*GIT_CONFIG_PARAMETERS*) COMMIT_EVASION="GIT_CONFIG_* (configuración de git por entorno)"; return 0 ;; esac
  case "$c" in *commit-tree*) COMMIT_EVASION="commit-tree"; return 0 ;; esac
  case "$c" in *fast-import*) COMMIT_EVASION="fast-import"; return 0 ;; esac
  if printf '%s' "$c" | grep -Eq 'hash-object[^;&|]*-t[[:space:]]*commit'; then COMMIT_EVASION="hash-object -t commit"; return 0; fi
  if printf '%s' "$c" | grep -Eq '>[>|]?[[:space:]]*[^[:space:];&|]*hooks/commit-msg|(^|[^a-zA-Z_-])(rm|unlink|shred|chmod|chown|mv|cp|ln|tee|truncate|install|dd)([[:space:]][^;&|]*)?hooks/commit-msg|sed[[:space:]]+(-[a-zA-Z]*[[:space:]]+)*-i[^;&|]*hooks/commit-msg'; then
    COMMIT_EVASION="escribir, borrar o cambiar permisos de hooks/commit-msg"; return 0
  fi
  return 1
}

# commit_salta_hooks <comando> → 0 si algún `git … commit` del comando se salta los hooks de git
# (T-223), con el trozo culpable en COMMIT_SALTO; 1 si no. Tras T-223 el gate que decide es el hook
# `commit-msg` de git, así que saltárselo es evadir el gate. Cuenta como salto:
#   · `--no-verify` (y sus abreviaturas, `--no-veri…`) o `-n`, suelto o en un grupo de opciones cortas
#     (`-nm x`, `-anm x`), en las opciones del `commit`;
#   · `-c core.hooksPath=…` (o `--config-env core.hooksPath=…`) en las opciones globales de git.
# Aproximado a propósito (lee texto, no ejecuta): se quitan antes los tramos entre comillas (un
# `-m "usa --no-verify"` no cuenta) y se salta el valor de las opciones que lo llevan (`-m -n` es un
# mensaje). Un cuerpo de heredoc que contenga `git commit -n` cuenta de más: el escape es [skip-traj].
commit_salta_hooks() {
  COMMIT_SALTO=""
  local LC_ALL=C c="$1" bsnl=$'\\\n' seg
  case "$c" in *git*commit*) ;; *) return 1 ;; esac
  c="${c//"$bsnl"/ }"
  # Fuera los tramos entrecomillados y, después, cada separador de comandos es un salto de línea.
  c="$(printf '%s' "$c" | sed -E 's/"[^"]*"/Q/g; s/'"'"'[^'"'"']*'"'"'/Q/g' | tr ';|&()`' '\n\n\n\n\n\n')"
  while IFS= read -r seg; do
    _cr_salto_en "$seg" && return 0
  done <<EOF
$c
EOF
  return 1
}

# _cr_salto_en <comando simple> — el trabajo de `commit_salta_hooks` sobre un solo comando.
_cr_salto_en() {
  local toks t i=0 n salta="" sub="" low
  read -r -a toks <<< "$1"
  n=${#toks[@]}
  # Hasta el `git` (lo que haya delante —`timeout 60`, `nice`, `env A=b`— no importa).
  while [ "$i" -lt "$n" ]; do
    case "${toks[$i]}" in git|*/git) break ;; esac
    i=$((i + 1))
  done
  [ "$i" -lt "$n" ] || return 1
  i=$((i + 1))
  # Opciones globales hasta el subcomando.
  while [ "$i" -lt "$n" ]; do
    t="${toks[$i]}"
    low="$(printf '%s' "$t" | tr 'A-Z' 'a-z')"
    case "$low" in
      -c|-C|--git-dir|--work-tree|--namespace|--super-prefix|--config-env)
        [ "$low" = -c ] || [ "$low" = --config-env ] && salta="$(printf '%s' "${toks[$((i + 1))]:-}" | tr 'A-Z' 'a-z')"
        case "$salta" in core.hookspath=*) COMMIT_SALTO="$t ${toks[$((i + 1))]}"; return 0 ;; esac
        salta=""; i=$((i + 2)); continue ;;
      -ccore.hookspath=*|--config-env=core.hookspath=*) COMMIT_SALTO="$t"; return 0 ;;
      -*) i=$((i + 1)); continue ;;
    esac
    sub="$t"; break
  done
  [ "$sub" = commit ] || return 1
  i=$((i + 1))
  # Opciones del commit, hasta `--` (lo de detrás son pathspecs).
  while [ "$i" -lt "$n" ]; do
    t="${toks[$i]}"
    case "$t" in
      --) return 1 ;;
      --no-veri*) COMMIT_SALTO="$t"; return 0 ;;
      --message|--file|--author|--date|--template|--reuse-message|--reedit-message|--fixup|--squash|--cleanup|--trailer|--pathspec-from-file)
        i=$((i + 2)); continue ;;
      --*) ;;
      -[a-zA-Z]*)
        # Grupo de opciones cortas: `n` es --no-verify; una que lleva valor (m F c C t) se come el
        # resto del grupo o, si es la última, el token siguiente.
        local k=1 l
        while [ "$k" -lt "${#t}" ]; do
          l="${t:$k:1}"
          case "$l" in
            n) COMMIT_SALTO="$t"; return 0 ;;
            m|F|c|C|t) [ "$k" -eq $((${#t} - 1)) ] && i=$((i + 1)); break ;;
            S|u) break ;;
          esac
          k=$((k + 1))
        done ;;
    esac
    i=$((i + 1))
  done
  return 1
}

# repo_del_commit <comando> [cwd del evento] → 0 y COMMIT_REPO=<raíz>, o 1 (y quizá COMMIT_REPO_AVISO).
# Con 0 puede dejar además COMMIT_REPO_NOTA: el resultado vale, pero el gate NO ve todo el commit
# (varios commits, staging decidido en el propio comando…). Ver `commit_repo_nota_al_salir`.
# T-292: COMMIT_REPO_NOTA_CUBIERTA=1 si el gate en git (commit-msg) va a correr en ese repo y revisará lo que
# esta nota dice que el aviso previo no ve; entonces la nota no sube a la pantalla del humano.
repo_del_commit() {
  COMMIT_REPO=""; COMMIT_REPO_AVISO=""; COMMIT_REPO_NOTA=""; COMMIT_REPO_NOTA_CUBIERTA=0
  local cmd="$1" base="${2:-}" dir top corto nota=""
  [ -n "$base" ] || base="$PWD"
  local nbytes; nbytes="$(LC_ALL=C; printf '%s' "${#cmd}")"
  if [ "$nbytes" -gt "$_CR_TOPE" ]; then
    COMMIT_REPO_AVISO="el comando mide $nbytes bytes y pasa del tope de $_CR_TOPE que analizo; este gate no lo inspecciona (fail-open)"
    return 1
  fi
  _cr_parse "$cmd" "$base"
  corto="$(printf '%s' "$cmd" | tr '\n\t' '  ' | cut -c1-160)"
  if [ "$_cr_found" = 0 ]; then
    if [ "$_cr_agotado" = 1 ]; then
      COMMIT_REPO_AVISO="el comando pasa del tope de $_CR_PASOS pasos que analizo (demasiado largo o troceado); este gate no lo inspecciona (fail-open)"
    else
      # ADV-2: el detector vio un `git … commit` que el analizador no sitúa como comando simple
      # (prefijo desconocido como `timeout`/`nice`, dentro de `$(…)`, `bash -c`, `xargs`, `eval`…).
      COMMIT_REPO_AVISO="veo un git commit en «$corto» pero no lo sitúo como comando simple (¿timeout/nice/xargs delante, dentro de \$(…), bash -c o eval?); este gate no lo inspecciona (fail-open)"
    fi
    return 1
  fi
  dir="$_cr_r_dir"
  if [ -n "$_cr_r_indet" ]; then
    COMMIT_REPO_AVISO="no puedo resolver en qué repo cae el commit ($_cr_r_indet) en «$corto»; este gate no lo inspecciona (fail-open)"
    return 1
  fi
  if [ "$_cr_r_explicit" = 1 ] && [ ! -d "$dir" ]; then
    COMMIT_REPO_AVISO="el commit cae en $dir, que no existe, en «$corto»; este gate no lo inspecciona (fail-open)"
    return 1
  fi
  if ! top="$(git -C "$dir" rev-parse --show-toplevel 2>/dev/null)" || [ -z "$top" ]; then
    [ "$_cr_r_explicit" = 1 ] && \
      COMMIT_REPO_AVISO="el commit cae en $dir, que no es un repo git, en «$corto»; este gate no lo inspecciona (fail-open)"
    return 1
  fi
  COMMIT_REPO="$top"
  # Resultado resuelto, pero con lo que el gate NO ve dicho en voz alta.
  if [ "$_cr_ncommits" -gt 1 ]; then
    nota="hay $_cr_ncommits commits en el comando y aquí solo se mira el primero ($top); $(_cr_gate_git "$top")"
  elif [ "$_cr_agotado" = 1 ]; then
    nota="no pude recorrer el comando entero (tope de $_CR_PASOS pasos): si hay más commits detrás del primero, aquí no se miran; $(_cr_gate_git "$top")"
  fi
  if [ "$_cr_stage" = 1 ] || [ "$_cr_call" = 1 ] || [ "$_cr_cpaths" = 1 ]; then
    nota="${nota:+$nota; }el staging se decide en este mismo comando (git add/rm/mv/stage, -a/--all o pathspecs): este aviso previo no lo ve; $(_cr_gate_git "$top")"
  fi
  COMMIT_REPO_NOTA="$nota"
  # Solo se sabe cubierto el repo del PRIMER commit: con varios commits (o un comando que no se recorrió entero) los
  # demás pueden caer en un repo sin el gate en git, así que la nota nunca se da por cubierta (T-292 R1). Y con
  # core.hooksPath (local o global) git no ejecuta .git/hooks: un shim que siga ahí no cubre nada. Se mira aquí y
  # no solo en commit_repo_nota_hookspath, que únicamente llama el trajectory-gate (T-292 R2). Cuenta la clave
  # PRESENTE, aunque esté vacía: con el valor "" git tampoco ejecuta .git/hooks (R3, ADV-T292-2). Y una config que
  # el comando incluye o inyecta (`-c include.path=…`, `includeIf`, `--config-env`) puede traer esa clave sin que
  # el texto la nombre, así que tampoco se da por cubierta (R3, ADV-T292-3).
  # Las claves de git no distinguen mayúsculas (`Include.Path`, `INCLUDEIF.…`): se compara en minúsculas (R4).
  # Con `tr` y no `${cmd,,}`, que no existe en el bash 3.2 de macOS.
  local _cr_incluye='include(if[^=]*)?[.]path|--config-env' _cr_min
  _cr_min="$(printf '%s' "$cmd" | tr '[:upper:]' '[:lower:]')"
  [ -n "$nota" ] && [ "$_cr_ncommits" -le 1 ] && [ "$_cr_agotado" != 1 ] \
    && ! git -C "$top" config --get core.hooksPath >/dev/null 2>&1 \
    && [[ ! "$_cr_min" =~ $_cr_incluye ]] \
    && _cr_hook_instalado "$(_cr_dir_hooks "$top")" && COMMIT_REPO_NOTA_CUBIERTA=1
  return 0
}

# _cr_hook_instalado <dir-de-hooks> — la MISMA decisión que el instalador y su --check (ronda 5,
# ADV-T223-5): `agentic_hook_instalado` de `lib/git-hook-estado.sh`. Sin esa lib, fail-open (instalado).
_cr_hook_instalado() {
  if ! command -v agentic_hook_instalado >/dev/null 2>&1; then
    # shellcheck source=lib/git-hook-estado.sh
    . "$(dirname "${BASH_SOURCE[0]}")/git-hook-estado.sh" 2>/dev/null || return 0
  fi
  agentic_hook_instalado "$1"
}

# _cr_gate_git <repo> — la frase de «quién decide» para las notas (T-223): el hook `commit-msg` del repo,
# que ve el repo y el staging reales. Si en ese repo aún no está instalado, lo dice: prometer un gate que
# no está es el bug de los dientes falsos.
# _cr_dir_hooks <repo> — el directorio de hooks de git del repo (el común, también desde un worktree).
_cr_dir_hooks() {
  local c
  c="$(git -C "$1" rev-parse --git-common-dir 2>/dev/null)"
  printf '%s/hooks' "$(cd "$1" 2>/dev/null && cd "$c" 2>/dev/null && pwd -P)"
}

_cr_gate_git() {
  if _cr_hook_instalado "$(_cr_dir_hooks "$1")"; then
    printf 'el gate en git (commit-msg, T-223) es el que decide'
  else
    printf 'el gate en git (commit-msg, T-223) es el que decide, pero en este repo aún no está instalado (el trajectory-gate lo instala al ver el commit; o bash .claude/hooks/install-git-hooks.sh <repo>)'
  fi
}

# commit_repo_nota_hookspath — si el repo resuelto tiene `core.hooksPath` efectivo (local, como husky, o
# global), git no ejecuta `.git/hooks`; y si tiene su propio `commit-msg`, el shim no se instala (ronda 4).
# En los dos casos el gate en git no corre ahí: se añade a COMMIT_REPO_NOTA. Llamar
# tras `repo_del_commit` y antes de `commit_repo_nota_al_salir`.
commit_repo_nota_hookspath() {
  local hp
  [ -n "${COMMIT_REPO:-}" ] || return 0
  local c h
  # La clave presente cuenta aunque esté vacía (T-292 R3): git deja de mirar .git/hooks igual.
  if hp="$(git -C "$COMMIT_REPO" config --get core.hooksPath 2>/dev/null)"; then
    [ -n "$hp" ] || hp="vacío"
    COMMIT_REPO_NOTA="${COMMIT_REPO_NOTA:+$COMMIT_REPO_NOTA; }$COMMIT_REPO tiene core.hooksPath ($hp), así que git no ejecuta .git/hooks: el gate en git (commit-msg, T-223) NO corre en este repo y solo queda este aviso previo"
    COMMIT_REPO_NOTA_CUBIERTA=0
    return 0
  fi
  # Ronda 4: un commit-msg PROPIO del repo (sin nuestra firma, ni la nuestra en .legacy) no se mueve ni se
  # encadena, así que ahí el shim no se instala y el gate en git tampoco corre.
  c="$(git -C "$COMMIT_REPO" rev-parse --git-common-dir 2>/dev/null)" || return 0
  h="$(cd "$COMMIT_REPO" 2>/dev/null && cd "$c" 2>/dev/null && pwd -P)/hooks"
  { [ -e "$h/commit-msg" ] || [ -L "$h/commit-msg" ]; } || return 0
  _cr_hook_instalado "$h" && return 0
  COMMIT_REPO_NOTA="${COMMIT_REPO_NOTA:+$COMMIT_REPO_NOTA; }$COMMIT_REPO ya tiene su propio commit-msg, que el framework no mueve ni encadena: el gate en git (commit-msg, T-223) NO corre en este repo y solo queda este aviso previo"
  COMMIT_REPO_NOTA_CUBIERTA=0
}

# commit_repo_nota_al_salir <hook> [--portavoz] — para los PreToolUse, justo tras resolver el repo. Si hay
# COMMIT_REPO_NOTA, el hook sigue decidiendo como siempre, pero su stdout se desvía a un temporal y,
# al salir, se le añade `systemMessage` cuando el humano tiene que verla (T-292):
#   · si el hook deniega, en el MISMO JSON que el deny (explica con qué staging decidió);
#   · si permite, solo si el gate en git NO cubre el repo (COMMIT_REPO_NOTA_CUBIERTA=0), y entonces la da el
#     portavoz (`--portavoz`), o cada gate si el portavoz no está instalado a su lado. El
#     portavoz es uno, el trajectory-gate (el que mira core.hooksPath y el commit-msg propio, e instala el
#     shim): los cuatro gates se instalan juntos y antes la misma nota salía cuatro veces en pantalla.
# Con el gate en git instalado y el commit permitido, la nota no pide nada al humano: solo stderr.
# Una línea por stderr siempre. Sin nota, no hace nada.
# LÍMITES (T-292 R5, decisión del humano: «Disciplina, no evasión», el mismo modelo que CLAUDE.md da a estos gates):
# «cubierto» se decide con el repo y el entorno del HOOK, antes de que el comando corra. Defiende de los fallos honestos
# (shim sin +x, core.hooksPath, commit-msg propio, varios commits, repos sin el gate en git), no de un comando que
# desactiva el gate en git a propósito: variables delante del commit que cambian la config de git (GIT_CONFIG_GLOBAL,
# GIT_CONFIG_SYSTEM, HOME, XDG_CONFIG_HOME), o chmod/rm/escrituras sobre .git/hooks o .git/config en el mismo comando.
# Ahí la nota se da por cubierta y no sale en pantalla. Detectar esa evasión es del trajectory-gate (T-223,
# `comando_evade_gate`). Repro como trinquete abierto: tests/nota-evasion-en-comando.adv.test.sh.
commit_repo_nota_al_salir() {
  [ -n "${COMMIT_REPO_NOTA:-}" ] || return 0
  _CR_NOTA_MSG="[$1] $COMMIT_REPO_NOTA"
  _CR_NOTA_VISIBLE=0
  if [ "${COMMIT_REPO_NOTA_CUBIERTA:-0}" != 1 ]; then
    # Sin portavoz al lado (un proyecto onboardado con los scaffolders solo copia security-gate/anti-slop-gate y
    # sus libs, no el trajectory-gate: T-280 H5), cada gate lo dice él mismo; si no, quedaría sin decir.
    if [ "${2:-}" = "--portavoz" ] || [ ! -f "$(dirname "${BASH_SOURCE[0]}")/../trajectory-gate.sh" ]; then
      _CR_NOTA_VISIBLE=1
    fi
  fi
  printf '%s\n' "$_CR_NOTA_MSG" >&2
  command -v jq >/dev/null 2>&1 || return 0
  _CR_NOTA_TMP="$(mktemp 2>/dev/null)" || return 0
  exec 3>&1 1>"$_CR_NOTA_TMP"
  trap '_cr_nota_volcar' EXIT
}

_cr_nota_volcar() {
  exec 1>&3 3>&-
  if [ -s "$_CR_NOTA_TMP" ]; then
    jq --arg m "$_CR_NOTA_MSG" --argjson v "$_CR_NOTA_VISIBLE" \
      'if $v == 1 or .hookSpecificOutput.permissionDecision == "deny" then . + {systemMessage: $m} else . end' \
      "$_CR_NOTA_TMP" 2>/dev/null || cat "$_CR_NOTA_TMP"
  elif [ "$_CR_NOTA_VISIBLE" = 1 ]; then
    jq -cn --arg m "$_CR_NOTA_MSG" '{systemMessage: $m}'
  fi
  rm -f "$_CR_NOTA_TMP"
}

# commit_repo_avisar <hook> [--system-message] — si hay aviso pendiente, una línea por stderr y, con
# `--system-message`, `{"systemMessage": …}` por stdout (solo para los PreToolUse que PERMITEN: no
# lleva `permissionDecision`, así que no altera la decisión). Sin aviso, calla.
commit_repo_avisar() {
  [ -n "${COMMIT_REPO_AVISO:-}" ] || return 0
  local msg="[$1] $COMMIT_REPO_AVISO"
  printf '%s\n' "$msg" >&2
  if [ "${2:-}" = "--system-message" ] && command -v jq >/dev/null 2>&1; then
    jq -cn --arg m "$msg" '{systemMessage: $m}'
  fi
  return 0
}
