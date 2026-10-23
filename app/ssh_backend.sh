#!/usr/bin/env bash
# SSH Vault - macOS (Bash 3.2), Linux and FreeBSD (Bash).
# SSH admin operations use a short-lived, private staging directory populated
# from the encrypted vault; never write to the client machine ~/.ssh folder.
set -u
set -o pipefail
umask 077

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)" || exit 1
ROOT="$(cd "$APP_DIR/.." && pwd -P)" || exit 1
SRC="${SSH_VAULT_WORKDIR:-$ROOT/keys}"
# Relative IdentityFile paths are resolved from the project root.
cd "$ROOT" || exit 1
TEMP=""
# Diagnostics are kept only in the operation's private temporary staging area.
# Never log credentials, private key content, or passwords.
DIAG_FILE="${SSH_VAULT_DIAGNOSTIC_FILE:-}"
LAST_PHASE="starting"
report_diagnostic() {
  if [[ -n "$DIAG_FILE" && -f "$DIAG_FILE" && ! -L "$DIAG_FILE" ]]; then
    printf '%s\n' "$*" >> "$DIAG_FILE" || true
  fi
}
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
warn() { printf '  %s! %s%s\n' "$YL" "$*" "$X"; report_diagnostic "NOTICE: $*"; }
err() { printf '  %sERROR: %s%s\n' "$RD" "$*" "$X" >&2; report_diagnostic "ERROR: $*"; }
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
# Support spaces, quotes, and backslashes in OpenSSH path options.
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

# Manage only individual Host ALIAS blocks, not patterns or Match blocks.
alias_exists() {
  awk -v t="$1" 'tolower($1)=="host" && NF==2 && $2==t {found=1} END {exit !found}' "$SRC/config"
}
list_aliases() {
  awk 'tolower($1)=="host" && NF==2 && $2 !~ /[*?]/ {print $2}' "$SRC/config"
}
# Shared alias helpers remain compatible with macOS Bash 3.2.
# Return the selected alias to the caller.
config_value() {
  # Effective OpenSSH settings from ssh -G, including default port 22.
  ssh -G -F "$SRC/config" "$1" 2>/dev/null | awk -v k="$2" '$1==k {print $2; exit}'
}
# Nombre de archivo de la clave; se admite "Host seafile" con "seafile-server".
# Admin operations use staged keys/priv and keys/pub files only.
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
# Remove exactly one Host ALIAS block, preserving all unrelated entries.
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
# Accept new host fingerprints silently, but reject changes to known fingerprints.
# Encode remote commands as base64 without consuming stdin:
# this keeps interactive SSH and sudo prompts available on a pseudo-TTY.
# One SSH password prompt at most during initial key authorization.
# Once a key is verified, other commands never fall back to password login.
remote_run() {
  local user="$1" host="$2" port="$3" key="$4" body="$5" auth_mode="${6:-key-only}" remote_shell="${7:-bash}" b64
  [[ "$auth_mode" == bootstrap || "$auth_mode" == key-only ]] || return 2
  [[ "$remote_shell" == sh || "$remote_shell" == bash ]] || return 2
  b64="$(printf '%s\n' "$body" | base64 | tr -d '\r\n')" || return 1
  local -a cmd=(ssh -q -F /dev/null -o "$(portable_known_hosts_option)" \
    -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR -p "$port" \
    -o ConnectTimeout=12 -o IdentityAgent=none -o IdentitiesOnly=yes -o ServerAliveInterval=15 -tt)
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
  cmd+=("$user@$host" "printf '%s' '$b64' | base64 -d | $remote_shell")
  local rc
  if [[ -n "$DIAG_FILE" && -f "$DIAG_FILE" && ! -L "$DIAG_FILE" ]]; then
    # -tt merges remote stderr into stdout. Capture both to show the actual
    # failure in the TUI, while keeping the temporary diagnostic private.
    "${cmd[@]}" 2>&1 | tee -a "$DIAG_FILE"
    rc=${PIPESTATUS[0]}
  else
    "${cmd[@]}"
    rc=$?
  fi
  if (( rc != 0 )); then
    err "Remote SSH command failed (exit $rc) while $LAST_PHASE. Check server login permissions and remote output."
  fi
  return "$rc"
}

key_test() {
  local user="$1" host="$2" port="$3" key="$4"
  local rc
  ssh -F /dev/null -o "$(portable_known_hosts_option)" -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR \
    -p "$port" -i "$key" -o IdentityAgent=none \
    -o ControlMaster=no -o ControlPath=none \
    -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=12 \
    -o PreferredAuthentications=publickey -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no -T "$user@$host" true \
    2> >(if [[ -n "$DIAG_FILE" && -f "$DIAG_FILE" ]]; then tee -a "$DIAG_FILE" >&2; else cat >&2; fi)
  rc=$?
  if ((rc != 0)); then
    err "Public-key authentication test failed (SSH exit $rc) for $user@$host:$port."
  fi
  return "$rc"
}
password_test() {
  local user="$1" host="$2" port="$3"
  ssh -F /dev/null -o "$(portable_known_hosts_option)" -o StrictHostKeyChecking=accept-new -o LogLevel=ERROR \
    -p "$port" -o PubkeyAuthentication=no \
    -o ControlMaster=no -o ControlPath=none \
    -o PreferredAuthentications=password,keyboard-interactive \
    -o NumberOfPasswordPrompts=1 -o ConnectTimeout=12 -T "$user@$host" true
}
# Generate a portable remote /bin/sh operation from the same, reviewed source
# for Linux, FreeBSD, and macOS. No server-specific paths are embedded here.
remote_key_body() {
  local operation="$1" public="$2" override_marker="${3:-}" typ blob marker extra
  [[ -f "$public" && ! -L "$public" ]] || return 1
  read -r typ blob marker extra < "$public" || true
  [[ "$typ" == ssh-ed25519 && "$blob" =~ ^[A-Za-z0-9+/=]+$ ]] || {
    err 'Unsupported SSH public key.'; return 1;
  }
  if [[ "$operation" == adopt ]]; then
    marker="$override_marker"
  fi
  if [[ "$operation" == add && "$marker" != ssh-vault-managed-* ]]; then
    err 'The new key lacks the SSH Vault ownership marker.'; return 1
  fi
  if [[ ( "$operation" == remove || "$operation" == probe ) && "$marker" != ssh-vault-managed-* ]]; then
    err 'This legacy/imported key has no SSH Vault ownership marker. Remote revocation is refused to avoid deleting another application’s authorization.'
    return 1
  fi
  if [[ "$operation" == add || "$operation" == remove || "$operation" == probe ]]; then
    [[ -z "${extra:-}" ]] || { err 'Malformed public key comment.'; return 1; }
  fi
  [[ "$marker" =~ ^ssh-vault-managed-[A-Za-z0-9_-]+$ ]] || {
    err 'Unrecognized SSH Vault ownership marker.'; return 1;
  }
  [[ -f "$APP_DIR/remote_authorized_keys.sh" && ! -L "$APP_DIR/remote_authorized_keys.sh" ]] || {
    err 'Portable remote key module missing.'; return 1;
  }
  printf "VAULT_ACTION='%s'\nVAULT_TYPE='%s'\nVAULT_BLOB='%s'\nVAULT_MARKER='%s'\n" \
    "$operation" "$typ" "$blob" "$marker"
  cat "$APP_DIR/remote_authorized_keys.sh"
}

remote_install_key() {
  local user="$1" host="$2" port="$3" private="$4" public="$5" authkey="${6:-$4}" body
  body="$(remote_key_body add "$public")" || return 1
  # Reuse the initial authenticated SSH channel for authorization, while an
  # independent key-only SSH connection must pass before we persist identity.
  if ! remote_run "$user" "$host" "$port" "$authkey" "$body" bootstrap sh; then
    if [[ "$authkey" == "$private" ]] || ! remote_run "$user" "$host" "$port" "$private" "$body" bootstrap sh; then
      return 1
    fi
  fi
  if ! key_test "$user" "$host" "$port" "$private"; then
    warn 'Independent key-only SSH login failed; attempting to undo our own enrollment.'
    local undo
    undo="$(remote_key_body remove "$public")" || return 1
    remote_run "$user" "$host" "$port" "$authkey" "$undo" bootstrap sh || \
      warn 'Could not undo the newly authorized key. Inspect the remote managed entry manually.'
    err 'SSH login with the new key was not verified. Nothing was saved to the vault.'
    return 1
  fi
  return 0
}

# Change the sshd password-login policy, not the account password.
# Place the drop-in early: OpenSSH uses the first effective directive.
# Restore prior settings when sshd validation or reload fails.
# A second SSH session verifies fresh access without a second sudo prompt:
# it acknowledges the root-side verifier started by the initial sudo authentication.
set_password() {
  local user="$1" host="$2" port="$3" key="$4" mode="$5" body guard check_body
  [[ "$mode" == yes || "$mode" == no ]] || return 1
  key_test "$user" "$host" "$port" "$key" || { err 'SSH key authentication must work first.'; return 1; }
  # Identificador aleatorio para impedir colisiones entre operaciones simultaneas.
  guard="gestor-ssh-guard-${RANDOM}-${RANDOM}-$$"
  body="$(cat <<EOF
set -eu
[ "\$(uname -s)" = Linux ] || { echo 'ERROR: Password policy changes require the Linux/systemd rollback adapter on this host; key-only SSH remains supported.' >&2; exit 1; }
command -v systemd-run >/dev/null && command -v systemctl >/dev/null || { echo 'ERROR: The required systemd rollback service is unavailable. Server was not modified.' >&2; exit 1; }
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
# Acknowledgement directory accessible only to the logged-in account.
# mkdir without -p refuses existing directories or symbolic links.
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
# OpenSSH uses the first effective option; the drop-in starts with 00.
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

# The background verifier retains privilege from the FIRST sudo
# authentication. Access is checked in a fresh SSH session.
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
  if ! remote_run "$user" "$host" "$port" "$key" "$body" key-only sh; then
    err 'Change not confirmed. Automatic rollback is scheduled if SSH access was lost.'
    return 1
  fi
  # Prueba nueva independiente: no basta con la conexion inicial abierta.
  if ! key_test "$user" "$host" "$port" "$key"; then
    err 'No new SSH key session. The rollback timer remains active.'
    return 1
  fi
  # Confirm access from another SSH session; sudo is not needed here:
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
  if ! remote_run "$user" "$host" "$port" "$key" "$check_body" key-only sh; then
    err 'Second SSH session not confirmed. Automatic rollback remains active.'
    return 1
  fi
  ok "OK: SSH password login $([[ "$mode" == yes ]] && echo ENABLED || echo DISABLED)"
}

remote_revoke_key() {
  local user="$1" host="$2" port="$3" key="$4" public="$5" body
  body="$(remote_key_body remove "$public")" || return 1
  remote_run "$user" "$host" "$port" "$key" "$body" key-only sh
}

# Refuse dangerous sshd setting changes and destructive operations if the
# specific key's remote ownership has not been proved first.
remote_probe_key() {
  local user="$1" host="$2" port="$3" key="$4" public="$5" body
  body="$(remote_key_body probe "$public")" || return 1
  remote_run "$user" "$host" "$port" "$key" "$body" key-only sh
}

# An authentication failure is only proof of revocation when OpenSSH explicitly
# rejects public-key auth. Network timeouts or host-key errors are NOT success.
verify_key_revoked() {
  local user="$1" host="$2" port="$3" key="$4" output rc
  output="$(ssh -F /dev/null -o "$(portable_known_hosts_option)" \
    -o StrictHostKeyChecking=yes -o LogLevel=ERROR \
    -p "$port" -i "$key" -o IdentityAgent=none -o IdentitiesOnly=yes \
    -o BatchMode=yes -o ConnectTimeout=12 -o ConnectionAttempts=1 \
    -o PreferredAuthentications=publickey -o PasswordAuthentication=no \
    -o KbdInteractiveAuthentication=no -o ControlMaster=no -o ControlPath=none \
    -T "$user@$host" true 2>&1)"
  rc=$?
  if (( rc != 0 )) && [[ "$output" == *"Permission denied (publickey"* ]]; then
    return 0
  fi
  err 'Cannot prove the key has lost remote SSH access (another provider, network error or unexpected success). Keep the vault identity and investigate.'
  report_diagnostic "NOTICE: SSH post-revocation check: ${output:0:220}"
  return 1
}

backend_adopt() {
  local name="$1" host user port key_file pkey pub body marker typ blob original_line
  check_structure || return 1
  valid_alias "$name" && alias_exists "$name" || { err 'Invalid alias.'; return 1; }
  key_file="$(key_name_for_alias "$name")"
  if key_name_in_use_elsewhere "$name" "$key_file"; then
    err 'Identity is shared by multiple aliases. Adoption requires a uniquely owned key.'; return 1
  fi
  pkey="$SRC/priv/$key_file"; pub="$SRC/pub/$key_file.pub"
  [[ -f "$pkey" && ! -L "$pkey" && -f "$pub" && ! -L "$pub" ]] || {
    err 'Missing private/public identity.'; return 1;
  }
  read -r typ blob _ < "$pub" || true
  [[ "$typ" == ssh-ed25519 && "$blob" =~ ^[A-Za-z0-9+/=]+$ ]] || {
    err 'Adoption requires an Ed25519 key.'; return 1;
  }
  host="$(config_value "$name" hostname)"
  user="$(config_value "$name" user)"
  port="$(config_value "$name" port)"
  marker="ssh-vault-managed-$name"
  LAST_PHASE="checking public-key authentication before adoption"
  key_test "$user" "$host" "$port" "$pkey" || return 1
  # Repeating after a crash is safe: same marker, no duplicate line.
  LAST_PHASE="adopting exactly one remote key authorization"
  body="$(remote_key_body adopt "$pub" "$marker")" || return 1
  remote_run "$user" "$host" "$port" "$pkey" "$body" key-only sh || {
    err 'Adoption refused; original public identity is unchanged in vault.'; return 1;
  }
  LAST_PHASE="confirming adopted identity remains able to authenticate"
  key_test "$user" "$host" "$port" "$pkey" || {
    err 'Remote authorization changed but authentication is not verified. Keep this connection and retry/review adoption.'
    return 1
  }
  # Only the comment is changed; the cryptographic public key is unchanged.
  make_temp || return 1
  printf '%s %s %s\n' "$typ" "$blob" "$marker" > "$TEMP/adopted.pub" || return 1
  chmod 644 "$TEMP/adopted.pub"
  mv "$TEMP/adopted.pub" "$pub" || {
    err 'Remote adoption succeeded, but updating staged public key failed. Re-run Adopt to recover.'; return 1;
  }
  ok "Remote identity adopted for $name. It is now eligible for managed revocation."
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
  make_temp || { err 'Could not create a protected temporary staging directory.'; return 1; }
  local key="$TEMP/key" pub="$TEMP/key.pub" conf="$TEMP/config"
  LAST_PHASE="generating the Ed25519 identity"
  ssh-keygen -q -t ed25519 -N '' -C "ssh-vault-managed-$name" -f "$key" || {
    err 'Could not generate a local Ed25519 identity.'; return 1;
  }
  info "Authorizing key on $user@$host:$port..."
  LAST_PHASE="authorizing a new key on $user@$host:$port"
  start_ssh_control "$user" "$host" "$port" || {
    err 'Could not prepare a temporary SSH control socket.'; return 1;
  }
  remote_install_key "$user" "$host" "$port" "$key" "$pub" || {
    err 'SSH key authorization or independent authentication test failed. No connection was saved.'
    return 1
  }
  # The newly authorized key is now independently verified; close password-backed master.
  stop_ssh_control
  LAST_PHASE="saving the verified identity to a temporary staging area"
  write_entry "$name" "$host" "$user" "$port" "$conf" "$SRC/config" || {
    err 'Could not write the new SSH configuration.'; return 1;
  }
  cp "$key" "$SRC/priv/$name" || { err 'Could not stage the private key.'; return 1; }
  cp "$pub" "$SRC/pub/$name.pub" || { err 'Could not stage the public key.'; return 1; }
  cp "$conf" "$SRC/config" || { err 'Could not stage the server configuration.'; return 1; }
  chmod 600 "$SRC/config" "$SRC/priv/$name"
  chmod 644 "$SRC/pub/$name.pub"
  ok "Connection $name created. Key verified."
  if [[ "$change_pw" == no ]]; then
    LAST_PHASE="disabling password login on the remote sshd"
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
  # Moving one credential between targets is not atomic: the old server could
  # retain an orphan key or the new target could share an authorization store.
  # Require explicit New -> Verify -> Delete rather than silently leaking keys.
  if [[ "$host" != "$(config_value "$name" hostname)" ||
        "$user" != "$(config_value "$name" user)" ||
        "$port" != "$(config_value "$name" port)" ]]; then
    err 'In-place remote target changes are disabled to prevent abandoned remote keys. Create and verify a NEW connection, then delete the old connection to revoke its key.'
    return 1
  fi
  ok 'Target unchanged. No remote credential was modified.'
  return 0

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
backend_verify() {
  local name="$1" host user port file pkey pub
  check_structure || return 1
  valid_alias "$name" && alias_exists "$name" || { err 'Invalid alias.'; return 1; }
  file="$(key_name_for_alias "$name")"
  pkey="$SRC/priv/$file"; pub="$SRC/pub/$file.pub"
  [[ -f "$pkey" && ! -L "$pkey" && -f "$pub" && ! -L "$pub" ]] || {
    err 'Missing complete SSH key pair.'; return 1;
  }
  host="$(config_value "$name" hostname)"; user="$(config_value "$name" user)"; port="$(config_value "$name" port)"
  LAST_PHASE="verifying independent public-key SSH authentication"
  key_test "$user" "$host" "$port" "$pkey" || return 1
  LAST_PHASE="verifying exact managed remote authorization"
  remote_probe_key "$user" "$host" "$port" "$pkey" "$pub" || return 1
  ok "Identity $name is authorized and is uniquely owned by SSH Vault."
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
    err 'Shared identity: cannot revoke without affecting another saved connection. Nothing deleted.'
    return 1
  elif [[ -f "$pkey" && ! -L "$pkey" && -f "$pub" && ! -L "$pub" ]]; then
    # Verify local ownership marking BEFORE any server-wide sshd change.
    # Legacy/imported identities are not owned by SSH Vault and cannot be
    # revoked automatically. The previous order enabled password login first,
    # then discovered it could not revoke the key.
    remote_key_body remove "$pub" >/dev/null || {
      err 'Imported or unmarked SSH key: no remote credential was revoked, no local identity deleted, and sshd password settings were not changed.'
      return 1
    }
    LAST_PHASE="verifying remote ownership before any sshd policy change"
    remote_probe_key "$user" "$host" "$port" "$pkey" "$pub" || {
      err 'Remote owned authorization could not be proven. Nothing deleted.'; return 1;
    }
    if [[ "$mode" == enable_password ]]; then
      set_password "$user" "$host" "$port" "$pkey" yes || { err 'Could not enable password login. Nothing was deleted.'; return 1; }
      password_test "$user" "$host" "$port" || { err 'Password login verification failed. Nothing was deleted.'; return 1; }
    fi
    LAST_PHASE="revoking the exact SSH Vault-owned remote authorization"
    remote_revoke_key "$user" "$host" "$port" "$pkey" "$pub" || {
      err 'Remote key revocation failed. No vault identity deleted.'; return 1;
    }
    LAST_PHASE="verifying independent authentication now rejects that key"
    verify_key_revoked "$user" "$host" "$port" "$pkey" || return 1
  else
    err 'Missing private/public key pair. Refusing vault-only deletion.'; return 1
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
  adopt)   [[ $# -eq 2 ]] || exit 2; backend_adopt "$2" ;;
  verify)  [[ $# -eq 2 ]] || exit 2; backend_verify "$2" ;;
  *) err 'Unknown command.'; exit 2 ;;
esac
