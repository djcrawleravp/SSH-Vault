#!/usr/bin/env bash
# SSH Launcher - macOS (Bash 3.2), Linux y FreeBSD (con Bash).
# Configuracion portable: raiz/keys/config, raiz/keys/priv y raiz/keys/pub.
# No escribe en ~/.ssh local. Conexiones usando configuracion y known_hosts portables.
# Despues de cerrar SSH, retorna automaticamente al launcher.
set -u
set -o pipefail
umask 077

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
ROOT="$(cd "$APP_DIR/.." && pwd -P)" || exit 1
SRC="$ROOT/keys"
# IdentityFile relativas se interpretan desde el directorio raiz del launcher.
cd "$ROOT" || exit 1
TEMP=""
CURSOR_HIDDEN=0
# Short-lived SSH multiplexing is used only while authorizing a new key.
# The master connection never substitutes for the independent key_test().
SSH_CONTROL_PATH=""
SSH_CONTROL_DIR=""
SSH_CONTROL_USER=""
SSH_CONTROL_HOST=""
SSH_CONTROL_PORT=""
stop_ssh_control() {
  if [[ -n "$SSH_CONTROL_PATH" ]]; then
    ssh -q -F /dev/null -o "ControlPath=$SSH_CONTROL_PATH" \
      -o BatchMode=yes -O exit -p "$SSH_CONTROL_PORT" \
      "$SSH_CONTROL_USER@$SSH_CONTROL_HOST" >/dev/null 2>&1 || true
    SSH_CONTROL_PATH=""
    SSH_CONTROL_USER=""
    SSH_CONTROL_HOST=""
    SSH_CONTROL_PORT=""
  fi
  if [[ -n "$SSH_CONTROL_DIR" && -d "$SSH_CONTROL_DIR" && ! -L "$SSH_CONTROL_DIR" ]]; then
    rm -rf -- "$SSH_CONTROL_DIR"
  fi
  SSH_CONTROL_DIR=""
}
start_ssh_control() {
  local user="$1" host="$2" port="$3"
  [[ -n "$TEMP" && -d "$TEMP" ]] || return 1
  stop_ssh_control
  # UNIX socket paths have a short length limit on macOS. Use a private /tmp dir.
  SSH_CONTROL_DIR="$(mktemp -d /tmp/ssh-launcher-mux.XXXXXXXX)" || return 1
  SSH_CONTROL_USER="$user"
  SSH_CONTROL_HOST="$host"
  SSH_CONTROL_PORT="$port"
  SSH_CONTROL_PATH="$SSH_CONTROL_DIR/mux-%C"
}
cleanup() {
  stop_ssh_control
  if (( CURSOR_HIDDEN )); then printf '\033[?25h'; CURSOR_HIDDEN=0; fi
  [[ -z "$TEMP" || ! -d "$TEMP" ]] || rm -rf -- "$TEMP"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  B=$'\033[1m'; CY=$'\033[38;5;81m'; GR=$'\033[38;5;114m'; YL=$'\033[38;5;221m'; RD=$'\033[38;5;203m'; X=$'\033[0m'
  DIM=$'\033[38;5;245m'; BGSEL=$'\033[48;5;237m'; WHITE=$'\033[38;5;255m' 
else
  B=''; CY=''; GR=''; YL=''; RD=''; X=''; DIM=''; BGSEL=''; WHITE=''
fi
say() { printf '  %s\n' "$*"; }
info() { printf '\n  %s%s%s\n' "$B$CY" "$*" "$X"; }
warn() { printf '  %s! %s%s\n' "$YL" "$*" "$X"; }
err() { printf '  %sERROR: %s%s\n' "$RD" "$*" "$X" >&2; }
ok() { printf '  %sOK%s  %s\n' "$B$GR" "$X" "$*"; }
show_cursor() {
  if (( CURSOR_HIDDEN )); then printf '\033[?25h'; CURSOR_HIDDEN=0; fi
}
hide_cursor() {
  if (( ! CURSOR_HIDDEN )) && [[ -t 1 ]]; then printf '\033[?25l'; CURSOR_HIDDEN=1; fi
}
raw_clear_screen() { printf '\033[2J\033[H'; }
clear_screen() {
  show_cursor
  raw_clear_screen
  printf '  %s%sSSH%s %s/ LAUNCHER%s\n' "$B" "$CY" "$X" "$DIM" "$X"
  printf '  %s------------------------------------------------------------%s\n\n' "$DIM" "$X"
}
pause() { printf '\n  %s[Enter] Return to launcher%s' "$DIM" "$X"; IFS= read -r _ || true; }
ask() { local _out="$1" _msg="$2"; printf '  %s> %s%s' "$CY" "$X" "$_msg"; IFS= read -r "$_out" || return 1; }
yesno() { local a; ask a "$1 [Y/N]: " || return 1; [[ "$a" == [Yy] ]]; }
confirm_yes() { local a; ask a 'Type YES to proceed: ' || return 1; [[ "$a" == YES ]]; }
check_structure() {
  [[ ! -L "$SRC" && -f "$SRC/config" && -d "$SRC/priv" && -d "$SRC/pub" ]] || {
    err "Required: config, priv/ and pub/ in $SRC"; return 1;
  }
  [[ ! -L "$SRC/config" && ! -L "$SRC/priv" && ! -L "$SRC/pub" && ! -L "$SRC/known_hosts" ]] || {
    err 'Config, priv/, pub/ and known_hosts must not be symlinks.'; return 1;
  }
}
# Rutas con espacios, comillas o barras invertidas en opciones OpenSSH.
portable_known_hosts_option() {
  local path="$SRC/known_hosts"
  path="${path//\\/\\\\}"
  path="${path//\"/\\\"}"
  printf 'UserKnownHostsFile="%s"' "$path"
}
valid_alias() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9_-]*$ ]]; }
valid_host() { [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9.:-]*$ ]]; }
valid_user() { [[ "$1" =~ ^[A-Za-z_][A-Za-z0-9_-]*$ ]]; }
valid_port() { [[ "$1" =~ ^[0-9]+$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535)); }

# Solo administra bloques "Host ALIAS" (uno por bloque), no patrones ni Match.
alias_exists() {
  awk -v t="$1" 'tolower($1)=="host" && NF==2 && $2==t {found=1} END {exit !found}' "$SRC/config"
}
list_aliases() {
  awk 'tolower($1)=="host" && NF==2 && $2 !~ /[*?]/ {print $2}' "$SRC/config"
}
# Selector numerico compartido por Editar y Eliminar (Bash 3.2 compatible).
# El nombre elegido se devuelve en la variable indicada como argumento.
config_value() {
  # Valores efectivos segun ssh -G, incluidos defaults (puerto 22).
  ssh -G -F "$SRC/config" "$1" 2>/dev/null | awk -v k="$2" '$1==k {print $2; exit}'
}
# Nombre de archivo de la clave; se admite "Host seafile" con "seafile-server".
# Solo se opera sobre ficheros en keys/priv y keys/pub; NO fuera de la app.
key_name_for_alias() {
  local alias="$1" configured filename
  configured="$(config_value "$alias" identityfile)" || true
  filename="${configured##*/}"
  filename="${filename%\"}"
  if [[ -n "$filename" && "$filename" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
    printf '%s\n' "$filename"
  else
    printf '%s\n' "$alias"
  fi
}
key_name_in_use_elsewhere() {
  local removed="$1" filename="$2" other
  while IFS= read -r other; do
    [[ -n "$other" && "$other" != "$removed" ]] || continue
    if [[ "$(key_name_for_alias "$other")" == "$filename" ]]; then
      return 0
    fi
  done < <(list_aliases)
  return 1
}
# Quita solo el bloque Host ALIAS especificado, preservando todos los otros.
strip_alias() {
  local file="$1" alias="$2" out="$3"
  awk -v t="$alias" '
    /^[[:space:]]*Host[[:space:]]+/ { skip=(NF==2 && $2==t) }
    /^[[:space:]]*Match[[:space:]]+/ { skip=0 }
    !skip {print}
  ' "$file" > "$out"
}
write_entry() {
  local alias="$1" host="$2" user="$3" port="$4" outfile="$5" base="$6" key_file="${7:-$1}"
  [[ "$key_file" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || return 1
  strip_alias "$base" "$alias" "$outfile" || return 1
  cat >> "$outfile" <<EOF

Host $alias
    HostName $host
    User $user
    Port $port
    IdentityFile keys/priv/$key_file
    IdentitiesOnly yes
EOF
}
make_temp() {
  [[ -z "$TEMP" || ! -d "$TEMP" ]] || rm -rf -- "$TEMP"
  TEMP="$(mktemp -d "${TMPDIR:-/tmp}/gestor-ssh.XXXXXXXX")"
}

# SSH sin aplicar ~/.ssh/config (que puede contener un alias o clave antiguos).
# Aceptamos nuevas host keys silenciosamente, nunca una host key que haya cambiado.
# El codigo remoto se manda en base64 dentro del comando, SIN ocupar stdin:
# permite los dialogos de contrasena SSH y sudo aun con pseudo-TTY.
# One SSH password prompt at most during initial key authorization.
# Once a key is verified, other commands never fall back to password login.
remote_run() {
  local user="$1" host="$2" port="$3" key="$4" body="$5" auth_mode="${6:-key-only}" b64
  [[ "$auth_mode" == bootstrap || "$auth_mode" == key-only ]] || return 2
  b64="$(printf '%s\n' "$body" | base64 | tr -d '\r\n')" || return 1
  local -a cmd=(ssh -q -F /dev/null -o "$(portable_known_hosts_option)" \
    -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -p "$port" \
    -o ConnectTimeout=12 -o ServerAliveInterval=15 -tt)
  if [[ -n "$SSH_CONTROL_PATH" ]]; then
    [[ "$user" == "$SSH_CONTROL_USER" && "$host" == "$SSH_CONTROL_HOST" && "$port" == "$SSH_CONTROL_PORT" ]] || {
      err 'SSH control socket destination mismatch.'; return 1;
    }
    cmd+=(-o ControlMaster=auto -o ControlPersist=45s -o "ControlPath=$SSH_CONTROL_PATH")
  else
    cmd+=(-o ControlMaster=no -o ControlPath=none)
  fi
  if [[ -n "$key" && -f "$key" ]]; then
    cmd+=(-i "$key" -o IdentitiesOnly=yes)
  fi
  if [[ "$auth_mode" == key-only ]]; then
    # Prevent another password prompt on a failure or an SSH server policy change.
    [[ -n "$key" && -f "$key" ]] || { err 'Private key missing.'; return 1; }
    cmd+=(-o BatchMode=yes -o PreferredAuthentications=publickey \
      -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no)
  else
    cmd+=(-o NumberOfPasswordPrompts=1)
  fi
  cmd+=("$user@$host" "printf '%s' '$b64' | base64 -d | bash")
  "${cmd[@]}"
}

key_test() {
  local user="$1" host="$2" port="$3" key="$4"
  ssh -F /dev/null -o "$(portable_known_hosts_option)" -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR \
    -p "$port" -i "$key" -o IdentityAgent=none \
    -o ControlMaster=no -o ControlPath=none \
    -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=12 \
    -o PreferredAuthentications=publickey -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no -T "$user@$host" true
}
password_test() {
  local user="$1" host="$2" port="$3"
  ssh -F /dev/null -o "$(portable_known_hosts_option)" -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR \
    -p "$port" -o PubkeyAuthentication=no \
    -o ControlMaster=no -o ControlPath=none \
    -o PreferredAuthentications=password,keyboard-interactive \
    -o NumberOfPasswordPrompts=1 -o ConnectTimeout=12 -T "$user@$host" true
}
remote_install_key() {
  local user="$1" host="$2" port="$3" private="$4" public="$5" authkey="${6:-$4}" pub body
  pub="$(cat "$public")" || return 1
  [[ "$pub" == ssh-ed25519\ * ]] || { err 'Public key is not Ed25519.'; return 1; }
  # La clave la emite ssh-keygen; solo se permiten caracteres seguros.
  [[ "$pub" =~ ^[A-Za-z0-9+/=_-]+[[:space:]][A-Za-z0-9+/=]+([[:space:]][A-Za-z0-9_-]+)?$ ]] || { err 'Invalid public key format.'; return 1; }
  body="$(cat <<EOF
set -eu
PUB='$pub'
UMASK_OLD=\$(umask); umask 077
ME=\$(id -un); MYGROUP=\$(id -gn)
if ! (mkdir -p "\$HOME/.ssh" && touch "\$HOME/.ssh/authorized_keys" && chmod 700 "\$HOME/.ssh" && chmod 600 "\$HOME/.ssh/authorized_keys" && chmod go-w "\$HOME"); then
  echo 'Repairing permissions/ownership using remote sudo...'
  sudo -v
  sudo mkdir -p "\$HOME/.ssh"
  sudo touch "\$HOME/.ssh/authorized_keys"
  sudo chown "\$ME:\$MYGROUP" "\$HOME/.ssh" "\$HOME/.ssh/authorized_keys"
  sudo chmod 700 "\$HOME/.ssh"
  sudo chmod 600 "\$HOME/.ssh/authorized_keys"
  sudo chmod go-w "\$HOME"
fi
if [ -L "\$HOME/.ssh/authorized_keys" ]; then echo 'authorized_keys is a symlink; cancelled.'; exit 1; fi
if ! grep -Fqx -- "\$PUB" "\$HOME/.ssh/authorized_keys"; then
  printf '%s\\n' "\$PUB" >> "\$HOME/.ssh/authorized_keys"
fi
grep -Fqx -- "\$PUB" "\$HOME/.ssh/authorized_keys"
echo 'Public key authorized.'
EOF
)"
  # Si el alias existia, usar su clave anterior para autorizar la nueva;
  # asi funciona incluso si el servidor ya tiene las contrasenas deshabilitadas.
  if ! remote_run "$user" "$host" "$port" "$authkey" "$body" bootstrap; then
    if [[ "$authkey" == "$private" ]] || ! remote_run "$user" "$host" "$port" "$private" "$body" bootstrap; then
      return 1
    fi
  fi
  if ! key_test "$user" "$host" "$port" "$private"; then
    # A veces el directorio ya existia con propietario equivocado.
    warn 'Key rejected; attempting to repair owner using sudo...'
    body='set -eu; sudo -v; sudo chown "$(id -un):$(id -gn)" "$HOME/.ssh" "$HOME/.ssh/authorized_keys"; sudo chmod go-w "$HOME"; sudo chmod 700 "$HOME/.ssh"; sudo chmod 600 "$HOME/.ssh/authorized_keys"'
    remote_run "$user" "$host" "$port" "$authkey" "$body" bootstrap || return 1
    key_test "$user" "$host" "$port" "$private" || { err 'sshd rejected the key. Local files were not changed.'; return 1; }
  fi
  return 0
}

# Cambia contrasenas SSH de todo sshd, NO la clave/clave de login del sistema.
# Drop-in deliberadamente al comienzo (OpenSSH usa la primera opcion encontrada).
# Se restaura el contenido anterior si sshd -t / -T / reload falla.
# La segunda sesion prueba una conexion NUEVA sin solicitar sudo: confirma mediante
# una marca temporal al verificador root, iniciado con el sudo de la primera sesion.
set_password() {
  local user="$1" host="$2" port="$3" key="$4" mode="$5" body guard check_body
  [[ "$mode" == yes || "$mode" == no ]] || return 1
  key_test "$user" "$host" "$port" "$key" || { err 'SSH key authentication must work first.'; return 1; }
  # Identificador aleatorio para impedir colisiones entre operaciones simultaneas.
  guard="gestor-ssh-guard-${RANDOM}-${RANDOM}-$$"
  body="$(cat <<EOF
set -eu
if [ "\$(id -u)" -eq 0 ]; then
  sudo() { if [ "\${1:-}" = -v ]; then return 0; fi; "\$@"; }
fi
sudo -v
P=/etc/ssh/sshd_config.d/00-gestor-ssh-password.conf
GUARD='$guard'
DIR="/run/\$GUARD"
ACK_DIR="/tmp/ssh-launcher-ack-\$GUARD"
# Sin systemd-run no podemos garantizar un rollback automatico si cae SSH.
command -v systemd-run >/dev/null || { echo 'ERROR: systemd-run unavailable; change cancelled.'; exit 1; }
# Directorio de acuse accesible solo para el usuario de la conexion.
# mkdir SIN -p impide enlaces simbolicos o directorios preexistentes.
mkdir -m 700 "\$ACK_DIR" || { echo 'ERROR: Duplicate confirmation marker.'; exit 1; }
sudo install -d -m 700 "\$DIR"
sudo mkdir -p /etc/ssh/sshd_config.d
if sudo test -L "\$P"; then echo 'ERROR: SSH drop-in is a symlink.'; sudo rmdir "\$DIR"; exit 1; fi
if sudo test -e "\$P"; then
  sudo cp -p "\$P" "\$DIR/original"
  sudo touch "\$DIR/had_old"
fi
# Este script de rollback se ejecuta automaticamente si la conexion nueva falla.
# Se deja preparado ANTES de cambiar la configuracion de SSH.
sudo tee "\$DIR/rollback.sh" >/dev/null <<'ROLLBACK_SH'
#!/bin/sh
set -eu
DIR="\$1"
P=/etc/ssh/sshd_config.d/00-gestor-ssh-password.conf
if [ -f "\$DIR/had_old" ]; then cp -p "\$DIR/original" "\$P"; else rm -f "\$P"; fi
if systemctl is-active --quiet ssh.socket; then
  systemctl restart ssh.service || true
else
  systemctl reload ssh.service || systemctl restart ssh.service || true
fi
rm -rf "\$DIR"
rm -rf "/tmp/ssh-launcher-ack-\${DIR##*/}"
ROLLBACK_SH
sudo chmod 700 "\$DIR/rollback.sh"
if ! sudo systemd-run --quiet --unit="\$GUARD" --on-active=150s /bin/sh "\$DIR/rollback.sh" "\$DIR"; then
  echo 'ERROR: Unable to schedule automatic rollback. Aborting.'
  sudo rm -rf "\$DIR"
  exit 1
fi
restore_now() {
  sudo /bin/sh "\$DIR/rollback.sh" "\$DIR" || true
  sudo systemctl stop "\$GUARD.timer" >/dev/null 2>&1 || true
  sudo systemctl stop "\$GUARD-finalize.timer" >/dev/null 2>&1 || true
  rm -rf "\$ACK_DIR"
}
# La primera opcion efectiva gana en OpenSSH; el archivo empieza por 00.
printf 'PubkeyAuthentication yes\\nPasswordAuthentication $mode\\nKbdInteractiveAuthentication $mode\\n' | sudo tee "\$P" >/dev/null
sudo chmod 644 "\$P"
SSHD=\$(command -v sshd || printf /usr/sbin/sshd)
if ! sudo "\$SSHD" -t; then echo 'ERROR: sshd -t failed. Rolling back.'; restore_now; exit 1; fi
CLIENT_IP=\$(printf '%s' "\${SSH_CONNECTION:-}" | awk '{print \$1}')
SERVER_IP=\$(printf '%s' "\${SSH_CONNECTION:-}" | awk '{print \$3}')
SERVER_PORT=\$(printf '%s' "\${SSH_CONNECTION:-}" | awk '{print \$4}')
CONTEXT="user=\$(id -un),host=\$(hostname),addr=\${CLIENT_IP:-127.0.0.1},laddr=\${SERVER_IP:-127.0.0.1},lport=\${SERVER_PORT:-22}"
EFFECTIVE=\$(sudo "\$SSHD" -T -C "\$CONTEXT") || { restore_now; exit 1; }
for PARAM in passwordauthentication kbdinteractiveauthentication; do
  GOT=\$(printf '%s\\n' "\$EFFECTIVE" | awk -v p="\$PARAM" '\$1==p {print \$2; exit}')
  if [ "\$GOT" != '$mode' ]; then
    echo "ERROR: Effective SSH \$PARAM=\$GOT, expected $mode. Rolling back."
    restore_now; exit 1
  fi
done
GOT=\$(printf '%s\\n' "\$EFFECTIVE" | awk '\$1=="pubkeyauthentication" {print \$2; exit}')
if [ "\$GOT" != yes ]; then echo 'ERROR: public-key authentication was disabled. Rolling back.'; restore_now; exit 1; fi
# Debian 13 con ssh.socket tiene un fallo conocido al hacer reload ssh.service.
# En ese caso reiniciamos el SERVICIO, conservando ssh.socket activo.
if sudo systemctl is-active --quiet ssh.socket; then
  if ! sudo systemctl restart ssh.service; then
    echo 'ERROR: Could not restart SSH; restoring previous settings.'
    restore_now; exit 1
  fi
else
  if ! sudo systemctl reload ssh.service; then
    if ! sudo systemctl restart ssh.service; then
      echo 'ERROR: Could not activate SSH; rolling back.'
      restore_now; exit 1
    fi
  fi
fi

# El verificador en segundo plano conserva el privilegio de la PRIMERA
# autenticacion sudo. La prueba de acceso se efectua en una nueva sesion SSH.
printf '%s\n' "\$CONTEXT" | sudo tee "\$DIR/context" >/dev/null
printf '%s\n' '$mode' | sudo tee "\$DIR/mode" >/dev/null
sudo tee "\$DIR/finalize.sh" >/dev/null <<'FINALIZE_SH'
#!/bin/sh
set -eu
DIR="\$1"
ACK_DIR="\$2"
GUARD="\$3"
count=0
# Terminar antes del rollback (150 s), incluso con latencia de scheduler.
while [ "\$count" -lt 125 ]; do
  if [ -f "\$ACK_DIR/confirmed" ] && [ ! -L "\$ACK_DIR/confirmed" ] &&
     [ "\$(cat "\$ACK_DIR/confirmed")" = "\$GUARD" ]; then
    SSHD=\$(command -v sshd || printf /usr/sbin/sshd)
    CONTEXT=\$(cat "\$DIR/context")
    MODE=\$(cat "\$DIR/mode")
    EFFECTIVE=\$(\$SSHD -T -C "\$CONTEXT") || exit 1
    for PARAM in passwordauthentication kbdinteractiveauthentication; do
      GOT=\$(printf '%s\n' "\$EFFECTIVE" | awk -v p="\$PARAM" '\$1==p {print \$2; exit}')
      [ "\$GOT" = "\$MODE" ] || exit 1
    done
    GOT=\$(printf '%s\n' "\$EFFECTIVE" | awk '\$1=="pubkeyauthentication" {print \$2; exit}')
    [ "\$GOT" = yes ] || exit 1
    systemctl stop "\$GUARD.timer" || exit 1
    rm -rf "\$ACK_DIR" "\$DIR"
    exit 0
  fi
  sleep 1
  count=\$((count+1))
done
# Ninguna confirmacion: NO cancelar el rollback.
exit 1
FINALIZE_SH
sudo chmod 700 "\$DIR/finalize.sh"
if ! sudo systemd-run --quiet --unit="\$GUARD-finalize" --on-active=1s \
       /bin/sh "\$DIR/finalize.sh" "\$DIR" "\$ACK_DIR" "\$GUARD"; then
  echo 'ERROR: Could not schedule final verification; rolling back.'
  restore_now
  exit 1
fi
EOF
)"
  if ! remote_run "$user" "$host" "$port" "$key" "$body"; then
    err 'Change not confirmed. Automatic rollback is scheduled if SSH access was lost.'
    return 1
  fi
  # Prueba nueva independiente: no basta con la conexion inicial abierta.
  if ! key_test "$user" "$host" "$port" "$key"; then
    err 'No new SSH key session. The rollback timer remains active.'
    return 1
  fi
  # Solo confirmar el acceso desde otra sesion SSH. No se necesita sudo aqui:
  # un verificador root ya iniciado con el primer sudo revalida sshd -T y
  # cancela el rollback cuando recibe este acuse. Si no llega, restaura.
  check_body="$(cat <<EOF
set -eu
ACK_DIR='/tmp/ssh-launcher-ack-$guard'
[ -d "\$ACK_DIR" ] && [ ! -L "\$ACK_DIR" ] || exit 1
(umask 077; printf '%s\\n' '$guard' > "\$ACK_DIR/confirmed")
n=0
while [ "\$n" -lt 25 ]; do
  if [ ! -d "\$ACK_DIR" ]; then exit 0; fi
  sleep 1
  n=\$((n+1))
done
echo 'ERROR: the server did not confirm the change; rollback pending.'
exit 1
EOF
)"
  if ! remote_run "$user" "$host" "$port" "$key" "$check_body"; then
    err 'Second SSH session not confirmed. Automatic rollback remains active.'
    return 1
  fi
  ok "OK: SSH password login $([[ "$mode" == yes ]] && echo ENABLED || echo DISABLED)"
}

remote_revoke_key() {
  local user="$1" host="$2" port="$3" key="$4" public="$5" pub token body
  pub="$(cat "$public")" || return 1
  token="$(printf '%s\n' "$pub" | awk '{print $2}')"
  [[ "$token" =~ ^[A-Za-z0-9+/=]+$ ]] || { err 'Invalid local public key.'; return 1; }
  body="$(cat <<EOF
set -eu
FILE="\$HOME/.ssh/authorized_keys"
if [ -e "\$FILE" ]; then
  [ ! -L "\$FILE" ] || { echo 'authorized_keys is a symlink; cancelled'; exit 1; }
  TMP=\$(mktemp "\$HOME/.ssh/authorized_keys.XXXXXXXX") || exit 1
  trap 'rm -f "\$TMP"' EXIT
  awk -v token='$token' 'index(\$0,token)==0 {print}' "\$FILE" > "\$TMP"
  chmod 600 "\$TMP"
  cat "\$TMP" > "\$FILE"
  chmod 600 "\$FILE"
  if grep -Fq '$token' "\$FILE"; then echo 'Could not revoke the key'; exit 1; fi
fi
echo 'Public key revoked on remote server.'
EOF
)"
  remote_run "$user" "$host" "$port" "$key" "$body"
}

# Interfaz automatizable: todos los argumentos son variables, nunca evaluados como shell.
# Se usa exclusivamente desde launcher.py; remote_run/sshd conservan las verificaciones.
backend_create() {
  local name="$1" host="$2" user="$3" port="$4" change_pw="${5:-keep}"
  check_structure || return 1
  valid_alias "$name" && valid_host "$host" && valid_user "$user" && valid_port "$port" || { err 'Invalid arguments.'; return 1; }
  if alias_exists "$name" || [[ -e "$SRC/priv/$name" || -L "$SRC/priv/$name" || -e "$SRC/pub/$name.pub" || -L "$SRC/pub/$name.pub" ]]; then
    err 'Alias or key file already exists. Nothing was replaced.'; return 1
  fi
  make_temp || return 1
  local key="$TEMP/key" pub="$TEMP/key.pub" conf="$TEMP/config"
  ssh-keygen -q -t ed25519 -N '' -C "$name" -f "$key" || return 1
  info "Authorizing key on $user@$host:$port..."
  start_ssh_control "$user" "$host" "$port" || return 1
  remote_install_key "$user" "$host" "$port" "$key" "$pub" || { err 'SSH authorization failed. Nothing was saved.'; return 1; }
  # The newly authorized key is now independently verified; close password-backed master.
  stop_ssh_control
  write_entry "$name" "$host" "$user" "$port" "$conf" "$SRC/config" || return 1
  cp "$key" "$SRC/priv/$name" || return 1
  cp "$pub" "$SRC/pub/$name.pub" || return 1
  cp "$conf" "$SRC/config" || return 1
  chmod 600 "$SRC/config" "$SRC/priv/$name"
  chmod 644 "$SRC/pub/$name.pub"
  ok "Connection $name created. Key verified."
  if [[ "$change_pw" == no ]]; then
    if ! set_password "$user" "$host" "$port" "$SRC/priv/$name" no; then
      warn 'Key installed, but remote password login could not be disabled.'
      return 1
    fi
  fi
}
backend_rename() {
  local old="$1" new="$2" h u p key_file new_file
  check_structure || return 1
  valid_alias "$old" && valid_alias "$new" && alias_exists "$old" || { err 'Invalid alias.'; return 1; }
  if [[ "$old" == "$new" ]]; then ok 'No changes.'; return 0; fi
  if alias_exists "$new" || [[ -e "$SRC/priv/$new" || -L "$SRC/priv/$new" || -e "$SRC/pub/$new.pub" || -L "$SRC/pub/$new.pub" ]]; then
    err 'New alias or key filename already exists.'; return 1
  fi
  h="$(config_value "$old" hostname)"; u="$(config_value "$old" user)"; p="$(config_value "$old" port)"
  key_file="$(key_name_for_alias "$old")"
  new_file="$key_file"
  # Claves con nombre del alias cambian con el alias. Nombres personalizados
  # como seafile-server permanecen intactos y referenciados correctamente.
  if [[ "$key_file" == "$old" ]]; then new_file="$new"; fi
  make_temp || return 1
  write_entry "$new" "$h" "$u" "$p" "$TEMP/config2" "$SRC/config" "$new_file" || return 1
  strip_alias "$TEMP/config2" "$old" "$TEMP/config3" || return 1
  if [[ "$key_file" == "$old" && -f "$SRC/priv/$old" && -f "$SRC/pub/$old.pub" ]]; then
    [[ ! -L "$SRC/priv/$old" && ! -L "$SRC/pub/$old.pub" ]] || { err 'Symlink key rejected.'; return 1; }
    if key_name_in_use_elsewhere "$old" "$key_file"; then
      err 'Key is also used by another host; cannot rename.'; return 1
    fi
    mv "$SRC/priv/$old" "$SRC/priv/$new" || return 1
    mv "$SRC/pub/$old.pub" "$SRC/pub/$new.pub" || return 1
  fi
  cp "$TEMP/config3" "$SRC/config" || return 1
  chmod 600 "$SRC/config"
  ok "Alias renamed: $old -> $new"
}

backend_target() {
  local name="$1" host="$2" user="$3" port="$4" pkey pub key_file
  check_structure || return 1
  valid_alias "$name" && alias_exists "$name" && valid_host "$host" && valid_user "$user" && valid_port "$port" || { err 'Invalid arguments.'; return 1; }
  key_file="$(key_name_for_alias "$name")"
  pkey="$SRC/priv/$key_file"; pub="$SRC/pub/$key_file.pub"
  [[ -f "$pkey" && ! -L "$pkey" && -f "$pub" && ! -L "$pub" ]] || { err 'A portable key pair is required to change the target.'; return 1; }
  info "Validating new target $user@$host:$port..."
  make_temp || return 1
  start_ssh_control "$user" "$host" "$port" || return 1
  remote_install_key "$user" "$host" "$port" "$pkey" "$pub" || { err 'Not verified. Configuration unchanged.'; return 1; }
  stop_ssh_control
  make_temp || return 1
  write_entry "$name" "$host" "$user" "$port" "$TEMP/config" "$SRC/config" "$key_file" || return 1
  cp "$TEMP/config" "$SRC/config" || return 1
  chmod 600 "$SRC/config"
  ok "Target updated: $name -> $user@$host:$port"
  warn 'Key may remain authorized on the previous host.'
}
backend_password() {
  local name="$1" mode="$2" host user port pkey key_file
  check_structure || return 1
  valid_alias "$name" && alias_exists "$name" && [[ "$mode" == yes || "$mode" == no ]] || { err 'Invalid arguments.'; return 1; }
  host="$(config_value "$name" hostname)"; user="$(config_value "$name" user)"; port="$(config_value "$name" port)"
  key_file="$(key_name_for_alias "$name")"
  pkey="$SRC/priv/$key_file"
  [[ -f "$pkey" && ! -L "$pkey" ]] || { err 'Launcher private key is missing.'; return 1; }
  set_password "$user" "$host" "$port" "$pkey" "$mode"
}
backend_delete() {
  local name="$1" mode="$2" host user port pkey pub key_file shared
  check_structure || return 1
  valid_alias "$name" && alias_exists "$name" || { err 'Invalid alias.'; return 1; }
  [[ "$mode" == enable_password || "$mode" == keep_password ]] || { err 'Invalid deletion mode.'; return 1; }
  host="$(config_value "$name" hostname)"; user="$(config_value "$name" user)"; port="$(config_value "$name" port)"
  key_file="$(key_name_for_alias "$name")"
  pkey="$SRC/priv/$key_file"; pub="$SRC/pub/$key_file.pub"
  shared=0
  if key_name_in_use_elsewhere "$name" "$key_file"; then shared=1; fi
  if (( shared )); then
    warn 'Key is shared by another alias. Only this host entry will be removed.'
  elif [[ -f "$pkey" && ! -L "$pkey" && -f "$pub" && ! -L "$pub" ]]; then
    if [[ "$mode" == enable_password ]]; then
      set_password "$user" "$host" "$port" "$pkey" yes || { err 'Could not enable password login. Nothing was deleted.'; return 1; }
      password_test "$user" "$host" "$port" || { err 'Password login verification failed. Nothing was deleted.'; return 1; }
    fi
    remote_revoke_key "$user" "$host" "$port" "$pkey" "$pub" || { err 'Remote key revocation failed. No local data deleted.'; return 1; }
  else
    warn 'No portable key pair found; only the local config entry will be deleted.'
  fi
  make_temp || return 1
  strip_alias "$SRC/config" "$name" "$TEMP/stripped" || return 1
  cp "$TEMP/stripped" "$SRC/config" || return 1
  if (( ! shared )); then rm -f -- "$pkey" "$pub"; fi
  chmod 600 "$SRC/config"
  ok "Connection $name deleted."
}

if [[ ${1:-} == '' ]]; then err 'Backend command required.'; exit 2; fi
case "$1" in
  create)  [[ $# -eq 6 ]] || exit 2; backend_create "$2" "$3" "$4" "$5" "$6" ;;
  rename)  [[ $# -eq 3 ]] || exit 2; backend_rename "$2" "$3" ;;
  target)  [[ $# -eq 5 ]] || exit 2; backend_target "$2" "$3" "$4" "$5" ;;
  passwd)  [[ $# -eq 3 ]] || exit 2; backend_password "$2" "$3" ;;
  delete)  [[ $# -eq 3 ]] || exit 2; backend_delete "$2" "$3" ;;
  *) err 'Unknown command.'; exit 2 ;;
esac
