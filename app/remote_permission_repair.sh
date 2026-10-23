#!/bin/sh
# Remote OpenSSH StrictModes metadata repair — portable POSIX sh.
# Used only after independent public-key verification has FAILED and a
# password-authenticated SSH control channel remains open. No passwords,
# sshd configuration, authorized_keys contents or unrelated files are changed.
set -eu
umask 077

notice() { printf 'REPAIR: %s\n' "$*"; }
refuse() { printf 'REPAIR SKIPPED: %s\n' "$*" >&2; exit 3; }

[ "${VAULT_REPAIR_MODE:-}" = apply ] || refuse 'Invalid repair request.'
[ -n "${HOME:-}" ] && [ "$HOME" != / ] || refuse 'Unusable remote HOME.'
[ -d "$HOME" ] && [ ! -L "$HOME" ] || refuse 'HOME is missing or a symbolic link.'
home=$(cd "$HOME" && pwd -P) || refuse 'Cannot resolve HOME.'
[ "$home" != / ] || refuse 'Refusing to change the filesystem root.'
sshdir="$home/.ssh"
auth="$sshdir/authorized_keys"
[ -d "$sshdir" ] && [ ! -L "$sshdir" ] || refuse '.ssh is not an ordinary directory.'
[ -f "$auth" ] && [ ! -L "$auth" ] || refuse 'authorized_keys is not an ordinary file (possibly a shared key store).'

# Make sure these three paths are on one filesystem. Refuse a mountpoint,
# including a Linux bind mount that has the same device number.
metadata() {
  if stat -c '%u %g %a %d %h' "$1" 2>/dev/null; then return 0; fi
  stat -f '%u %g %Lp %d %l' "$1" 2>/dev/null
}
mountpoint_present() {
  [ -r /proc/self/mountinfo ] || return 1
  # mountinfo escapes spaces. Conservatively refuse HOME paths with spaces.
  case "$home" in *' '*|*'\\'*) return 0 ;; esac
  awk -v a="$home" -v b="$sshdir" -v c="$auth" \
    '$5==a || $5==b || $5==c {found=1} END {exit !found}' /proc/self/mountinfo
}
mountpoint_present && refuse 'HOME, .ssh or authorized_keys is a mountpoint; manual review required.'
parent=$(dirname "$home")
parentmeta=$(metadata "$parent") || refuse 'Cannot inspect parent filesystem.'
homemeta=$(metadata "$home") || refuse 'Cannot inspect HOME.'
sshmeta=$(metadata "$sshdir") || refuse 'Cannot inspect .ssh.'
authmeta=$(metadata "$auth") || refuse 'Cannot inspect authorized_keys.'
set -- $parentmeta
[ "$#" -eq 5 ] || refuse 'Unexpected parent metadata.'
pdev=$4
set -- $homemeta
[ "$#" -eq 5 ] || refuse 'Unexpected HOME metadata.'
hdev=$4
set -- $sshmeta
[ "$#" -eq 5 ] || refuse 'Unexpected .ssh metadata.'
sdev=$4
set -- $authmeta
[ "$#" -eq 5 ] || refuse 'Unexpected authorized_keys metadata.'
adev=$4; links=$5
[ "$pdev" = "$hdev" ] && [ "$hdev" = "$sdev" ] && [ "$sdev" = "$adev" ] || \
  refuse 'Path crosses a filesystem boundary; automatic repair is disabled.'
[ "$links" = 1 ] || refuse 'authorized_keys has multiple hard links; automatic repair is disabled.'

# Repair only when OpenSSH itself reports that StrictModes is enabled and
# that this specific, ordinary authorized_keys file is in its active policy.
sshd_bin=$(command -v sshd 2>/dev/null || true)
if [ -z "$sshd_bin" ]; then
  for path in /usr/sbin/sshd /usr/local/sbin/sshd /usr/libexec/sshd /usr/local/libexec/sshd; do
    if [ -x "$path" ]; then sshd_bin=$path; break; fi
  done
fi
[ -n "$sshd_bin" ] || refuse 'Cannot inspect the effective OpenSSH configuration.'
remote_user=$(id -un) || refuse 'Cannot identify account.'
client_ip=$(printf '%s\n' "${SSH_CONNECTION:-}" | awk '{print $1}')
local_ip=$(printf '%s\n' "${SSH_CONNECTION:-}" | awk '{print $3}')
local_port=$(printf '%s\n' "${SSH_CONNECTION:-}" | awk '{print $4}')
context="user=$remote_user"
case "$client_ip" in ''|*[!0-9A-Fa-f:.]*) ;; *) context="$context,host=$client_ip,addr=$client_ip" ;; esac
case "$local_ip" in ''|*[!0-9A-Fa-f:.]*) ;; *) context="$context,laddr=$local_ip" ;; esac
case "$local_port" in ''|*[!0-9]*) ;; *) context="$context,lport=$local_port" ;; esac
policy=$("$sshd_bin" -T -C "$context" 2>/dev/null) || refuse 'sshd -T failed; cannot verify StrictModes or AuthorizedKeysFile.'
strict=$(printf '%s\n' "$policy" | awk '$1=="strictmodes" {print $2;exit}')
pubkey=$(printf '%s\n' "$policy" | awk '$1=="pubkeyauthentication" {print $2;exit}')
files=$(printf '%s\n' "$policy" | awk '$1=="authorizedkeysfile" {for(i=2;i<=NF;i++) print $i}')
[ "$strict" = yes ] && [ "$pubkey" = yes ] || refuse 'This failure is not a confirmed StrictModes-enabled public-key configuration.'
found=0
for file in $files; do
  if [ "$file" = .ssh/authorized_keys ] || [ "$file" = "$auth" ]; then found=1; fi
done
[ "$found" -eq 1 ] || refuse 'The inspected key file is not among effective AuthorizedKeysFile paths.'

uid=$(id -u) || refuse 'Cannot identify user UID.'
gid=$(id -g) || refuse 'Cannot identify user GID.'
# Preflight EVERY path before touching any metadata. A non-root session may
# tighten its own permissions but cannot fix files owned by another user.
needs_change=0
for path in "$home" "$sshdir" "$auth"; do
  meta=$(metadata "$path") || refuse 'Metadata changed while preparing repair.'
  set -- $meta
  [ "$#" -eq 5 ] || refuse 'Unexpected metadata format.'
  owner=$1; mode=$3
  case "$owner:$uid" in "$uid":*|0:*) ;; *)
    [ "$uid" = 0 ] || refuse "Foreign owner on $path, and no root privileges for safe ownership repair."
    needs_change=1
    ;;
  esac
  # OpenSSH rejects group/other-writable directories and key files.
  lasttwo=$(printf '%s' "$mode" | sed 's/.*\(..\)$/\1/')
  [ "${#lasttwo}" -eq 2 ] || refuse 'Unexpected permissions format.'
  group=${lasttwo%?}; other=${lasttwo#?}
  case "$group" in 2|3|6|7) needs_change=1 ;; esac
  case "$other" in 2|3|6|7) needs_change=1 ;; esac
done

if [ "$needs_change" -eq 0 ]; then
  notice 'Owner and write permissions already satisfy the checked StrictModes requirements; no changes made.'
  exit 4
fi

# These are metadata-only changes to the three inspected objects. No -R,
# no SSH policy change, no disabling StrictModes, no modification of key data.
for path in "$home" "$sshdir" "$auth"; do
  meta=$(metadata "$path") || refuse 'Metadata changed before repair.'
  set -- $meta
  owner=$1; mode=$3
  if [ "$owner" != "$uid" ] && [ "$owner" != 0 ]; then
    [ "$uid" = 0 ] || refuse 'Foreign-owned path cannot be repaired as non-root.'
    chown "$uid:$gid" "$path" || refuse "Could not safely change ownership of $path."
    notice "Corrected ownership of $path to $uid:$gid."
  fi
  lasttwo=$(printf '%s' "$mode" | sed 's/.*\(..\)$/\1/')
  group=${lasttwo%?}; other=${lasttwo#?}
  change=0
  case "$group" in 2|3|6|7) change=1 ;; esac
  case "$other" in 2|3|6|7) change=1 ;; esac
  if [ "$change" -eq 1 ]; then
    chmod go-w "$path" || refuse "Could not correct write permissions of $path."
    notice "Removed group/other write permissions from $path."
  fi
done
notice 'Metadata repair completed; independent key-only SSH verification is required.'
