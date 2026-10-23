#!/bin/sh
# SSH Vault: conservative, distribution-independent OpenSSH key ownership.
# Inputs: VAULT_ACTION={inspect,add,replace,adopt,probe,remove}, VAULT_TYPE, VAULT_BLOB, VAULT_MARKER.
# Unknown key providers, ambiguous entries and unsafe files fail closed.
set -eu
umask 077
export LC_ALL=C
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
notice() { printf 'NOTICE: %s\n' "$*"; }
case "${VAULT_ACTION:-}" in inspect|add|replace|adopt|probe|remove) : ;; *) fail 'Invalid action.' ;; esac
[ "${VAULT_TYPE:-}" = ssh-ed25519 ] || fail 'Only Ed25519 keys can be enrolled.'
case "${VAULT_BLOB:-}" in ''|*[!A-Za-z0-9+/=]*) fail 'Invalid public-key blob.' ;; esac
case "${VAULT_MARKER:-}" in ssh-vault-managed-*) : ;; *) fail 'Missing vault ownership marker.' ;; esac
case "$VAULT_MARKER" in *[!A-Za-z0-9_-]*) fail 'Invalid vault ownership marker.' ;; esac
[ -n "${HOME:-}" ] && [ -d "$HOME" ] || fail 'No valid account home directory.'

resolve_config_path() {
    candidate=$1
    case "$candidate" in *\**|*\?*|*\[*|*\]*|*'~'*|*'`'*) return 1 ;; esac
    user=$(id -un) || return 1
    uid=$(id -u) || return 1
    case "$user" in *[!A-Za-z0-9_.-]*|'') return 1 ;; esac
    case "$HOME" in *'|'*|*'&'*|*'\'* ) return 1 ;; esac
    resolved=$(printf '%s\n' "$candidate" | sed -e "s|%h|$HOME|g" -e "s|%u|$user|g" -e "s|%U|$uid|g" -e 's|%%|%|g') || return 1
    case "$resolved" in *%*) return 1 ;; /*) : ;; *) resolved="$HOME/$resolved" ;; esac
    printf '%s\n' "$resolved"
}
resolve_file_path() {
    path=$1; depth=0
    while :; do
        [ "$depth" -le 12 ] || return 1
        base=$(basename "$path") || return 1
        dir=$(dirname "$path") || return 1
        [ -d "$dir" ] || return 1
        dir=$(cd -P "$dir" 2>/dev/null && pwd -P) || return 1
        path="$dir/$base"
        if [ -L "$path" ]; then
            target=$(readlink "$path") || return 1
            case "$target" in /*) path=$target ;; *) path="$dir/$target" ;; esac
            depth=$((depth + 1))
            continue
        fi
        [ ! -e "$path" ] || [ -f "$path" ] || return 1
        printf '%s\n' "$path"
        return 0
    done
}

# For adoption/removal we must inspect the real OpenSSH key sources.
# Different OpenSSH versions/platforms accept different -C context fields.
# Never silently swallow the actual sshd diagnostic, and never infer that a
# default path is effective for a destructive operation.
sshd_bin=$(command -v sshd 2>/dev/null || true)
if [ -z "$sshd_bin" ]; then
    for candidate in /usr/sbin/sshd /usr/local/sbin/sshd /usr/libexec/sshd /usr/local/libexec/sshd; do
        if [ -x "$candidate" ]; then sshd_bin=$candidate; break; fi
    done
fi
auth_files=''
auth_command='none'
sshd_diagnostic=''
if [ -n "$sshd_bin" ]; then
    client_ip=$(printf '%s\n' "${SSH_CONNECTION:-}" | awk '{print $1}')
    local_ip=$(printf '%s\n' "${SSH_CONNECTION:-}" | awk '{print $3}')
    local_port=$(printf '%s\n' "${SSH_CONNECTION:-}" | awk '{print $4}')
    ssh_user=$(id -un)
    # Match Host means the remote CLIENT name, not hostname(1) of the server.
    # Prefer the numeric client address unless a trusted name is available;
    # never invent a name from the local server hostname.
    context="user=$ssh_user"
    case "$client_ip" in *[!0-9A-Fa-f:.]*|'') : ;; *)
        context="$context,host=$client_ip,addr=$client_ip" ;;
    esac
    full_context=$context
    case "$local_ip" in *[!0-9A-Fa-f:.]*|'') : ;; *) full_context="$full_context,laddr=$local_ip" ;; esac
    case "$local_port" in *[!0-9]*|'') : ;; *) full_context="$full_context,lport=$local_port" ;; esac
    # Full-context lookup first, followed by the smaller context when older
    # sshd builds reject newer -C keys. A context-free -T is NOT trusted for
    # revocation, because Match blocks could select a different key store.
    if effective=$("$sshd_bin" -T -C "$full_context" 2>&1); then
        :
    else
        sshd_diagnostic=$effective
        if [ "$context" != "$full_context" ] && effective=$("$sshd_bin" -T -C "$context" 2>&1); then
            notice 'sshd effective configuration evaluated using compatible client context.'
        else
            sshd_diagnostic="$sshd_diagnostic; $effective"
            effective=''
        fi
    fi
    if [ -n "$effective" ]; then
        auth_files=$(printf '%s\n' "$effective" | awk '$1=="authorizedkeysfile" { for (i=2;i<=NF;i++) print $i; exit }')
        auth_command=$(printf '%s\n' "$effective" | awk '$1=="authorizedkeyscommand" {print $2; exit }')
        [ -n "$auth_command" ] || auth_command=none
    fi
else
    sshd_diagnostic='sshd executable not found in PATH or standard system directories'
fi
if [ -z "$auth_files" ]; then
    # A conservative escape hatch for systems where sshd -T is unavailable
    # (including some chroots, appliances or macOS configurations). We may
    # inspect ONLY a pre-existing regular ~/.ssh/authorized_keys entry, never
    # create or replace it for adoption/removal, and never infer other paths.
    # Independent public-key login is checked before adoption, and rejection
    # after removal is checked by the calling backend. If either fails, vault
    # identity is retained. The only remote line ever changed is the EXACT key.
    if [ "$VAULT_ACTION" = add ]; then
        auth_files='.ssh/authorized_keys'
        notice 'Enrollment uses standard authorized_keys because sshd -T was unavailable; independent authentication is required.'
    elif [ "$VAULT_ACTION" = inspect ]; then
        # Read-only preflight may also inspect an account with NO existing
        # ~/.ssh directory. Enrollment still has to pass key-only verification.
        auth_files='.ssh/authorized_keys'
        notice 'Limited read-only inspection of standard authorized_keys.'
    elif [ -e "$HOME/.ssh/authorized_keys" ] || [ -L "$HOME/.ssh/authorized_keys" ]; then
        auth_files='.ssh/authorized_keys'
        notice 'LIMITED INSPECTION: sshd -T unavailable; using only the existing ~/.ssh/authorized_keys. Other providers cannot be audited. Independent SSH authentication is required.'
    else
        printf 'DETAIL: sshd inspection: %.300s\n' "$sshd_diagnostic" >&2
        fail 'Could not inspect effective AuthorizedKeysFile and no existing standard key file is available. No remote credentials were changed.'
    fi
fi
[ "$auth_files" != none ] || fail 'Server has no AuthorizedKeysFile; an external provider cannot be managed.'
if [ "$VAULT_ACTION" != add ] && [ "$auth_command" != none ]; then
    fail 'AuthorizedKeysCommand is enabled; refusing to claim or revoke an identity potentially supplied by an external provider.'
fi

# Canonicalize and de-duplicate paths (multiple aliases may point at the same
# cluster-managed file). Nonportable paths are rejected, not guessed.
entries=''
old_ifs=$IFS
IFS='
'
for candidate in $auth_files; do
    [ -n "$candidate" ] || continue
    path=$(resolve_config_path "$candidate") || fail "Unsupported AuthorizedKeysFile: $candidate"
    if [ "$VAULT_ACTION" = add ] && [ "$path" = "$HOME/.ssh/authorized_keys" ] \
       && [ ! -e "$HOME/.ssh" ] && [ ! -L "$HOME/.ssh" ]; then
        # A brand-new remote account may not have ~/.ssh yet. Only the
        # standard path can be created, and only with restrictive permissions.
        final=$path
    else
        final=$(resolve_file_path "$path") || {
            if [ "$VAULT_ACTION" = add ] || [ "$VAULT_ACTION" = inspect ]; then continue; fi
            fail "Unsafe path or dangling symlink: $path"
        }
    fi
    case "
$entries
" in *"
$final
"*) continue ;; esac
    entries="$entries
$final"
done
IFS=$old_ifs
if [ -z "$entries" ]; then
    if [ "$VAULT_ACTION" = inspect ]; then
        notice 'SSH_VAULT_STATUS=new'
        exit 0
    fi
    fail 'No inspectable AuthorizedKeysFile path.'
fi

# Count actual key records, ignoring comments. The Ed25519 type+blob pair is
# identified irrespective of pre-key restrictions containing quoted spaces.
key_count() {
    awk -v t="$VAULT_TYPE" -v b="$VAULT_BLOB" '
        /^[[:space:]]*#/ {next}
        {for(i=1;i<NF;i++) if($i==t && $(i+1)==b) {n++; break}}
        END{print n+0}' "$1"
}
marked_count() {
    awk -v t="$VAULT_TYPE" -v b="$VAULT_BLOB" -v m="$VAULT_MARKER" '
        /^[[:space:]]*#/ {next}
        {for(i=1;i<NF;i++) if($i==t && $(i+1)==b && $NF==m) {n++; break}}
        END{print n+0}' "$1"
}
foreign_marker_count() {
    awk -v t="$VAULT_TYPE" -v b="$VAULT_BLOB" -v m="$VAULT_MARKER" '
        /^[[:space:]]*#/ {next}
        {for(i=1;i<NF;i++) if($i==t && $(i+1)==b && $NF ~ /^ssh-vault-managed-/ && $NF!=m) {n++; break}}
        END{print n+0}' "$1"
}
marker_collision_count() {
    awk -v t="$VAULT_TYPE" -v b="$VAULT_BLOB" -v m="$VAULT_MARKER" '
        /^[[:space:]]*#/ {next}
        $NF==m {found=0; for(i=1;i<NF;i++) if($i==t && $(i+1)==b) found=1; if(!found) n++}
        END{print n+0}' "$1"
}
match_total=0
mark_total=0
foreign_total=0
collision_total=0
selected=''
old_ifs=$IFS; IFS='
'
for final in $entries; do
    [ -n "$final" ] || continue
    [ -e "$final" ] || continue
    [ -f "$final" ] && [ ! -L "$final" ] || fail "Unsafe authorization file: $final"
    count=$(key_count "$final") || fail 'Unable to inspect key records.'
    marks=$(marked_count "$final") || fail 'Unable to inspect ownership markers.'
    others=$(foreign_marker_count "$final") || fail 'Unable to inspect ownership markers.'
    collision=$(marker_collision_count "$final") || fail 'Unable to inspect marker conflicts.'
    match_total=$((match_total+count))
    mark_total=$((mark_total+marks))
    foreign_total=$((foreign_total+others))
    collision_total=$((collision_total+collision))
    if [ "$count" -gt 0 ]; then selected=$final; fi
done
IFS=$old_ifs
if [ "$VAULT_ACTION" = inspect ]; then
    # Read-only preflight. The UI can confirm a safe replacement BEFORE any
    # write; a single authenticated SSH master persists across both phases.
    [ "$collision_total" -le 1 ] || fail 'Multiple old managed entries use this marker; replacement is unsafe.'
    if [ "$collision_total" -eq 1 ]; then
        notice 'SSH_VAULT_STATUS=replace'
    else
        notice 'SSH_VAULT_STATUS=new'
    fi
    exit 0
fi
if [ "$VAULT_ACTION" = replace ]; then
    # Explicit recovery of a LOST private key. Only a single existing SSH Vault
    # entry with the SAME ownership marker is eligible for replacement.
    [ "$collision_total" -eq 1 ] && [ "$match_total" -eq 0 ] || \
        fail 'Safe key replacement requires exactly one stale entry with this ownership marker and no authorization for the new key.'
else
    [ "$collision_total" -eq 0 ] || fail 'Ownership marker already belongs to another public key.'
fi
[ "$foreign_total" -eq 0 ] || fail 'Identity is managed using a different marker; refusing takeover.'
[ "$match_total" -le 1 ] || fail 'Public key is authorized in multiple entries. Refusing ambiguous adoption or revocation.'
[ "$mark_total" -le 1 ] || fail 'Duplicate managed marker detected.'

if [ "$VAULT_ACTION" = probe ]; then
    [ "$match_total" -eq 1 ] && [ "$mark_total" -eq 1 ] || fail 'No uniquely owned remote authorization found.'
    notice "Verified the exact SSH Vault-owned authorization in $selected."
    exit 0
fi
if [ "$VAULT_ACTION" = add ]; then
    if [ "$match_total" -eq 1 ]; then
        [ "$mark_total" -eq 1 ] || fail 'Public key already exists without ownership marker; adopt it instead of creating a duplicate.'
        notice 'Managed public key already authorized; no duplicate created.'
        exit 0
    fi
    # Only add to a safely writable configured path. Do not edit ACLs or a
    # cluster-owned file that the remote user cannot update.
    old_ifs=$IFS; IFS='
'
    for final in $entries; do
        [ -n "$final" ] || continue
        dir=$(dirname "$final")
        if [ ! -e "$final" ] && [ "$final" = "$HOME/.ssh/authorized_keys" ] && [ ! -d "$dir" ]; then
            mkdir -m 700 "$dir" 2>/dev/null || :
        fi
        if [ -f "$final" ] && [ -w "$final" ]; then selected=$final; break; fi
        if [ ! -e "$final" ] && [ -w "$dir" ]; then selected=$final; break; fi
    done
    IFS=$old_ifs
    [ -n "$selected" ] || fail 'No writable safe authorization file.'
    if [ ! -e "$selected" ]; then
        (set -C; : > "$selected") 2>/dev/null || fail 'Authorization file appeared concurrently; retry.'
        chmod 600 "$selected" || fail 'Unable to secure new authorization file.'
    fi
    if [ -s "$selected" ]; then
        last_byte=$(tail -c 1 "$selected" | od -An -tu1 | tr -d ' \n')
        [ "$last_byte" = 10 ] || fail 'Authorization file has no trailing newline; append refused.'
    fi
    printf '%s %s %s\n' "$VAULT_TYPE" "$VAULT_BLOB" "$VAULT_MARKER" >> "$selected" || fail 'Unable to append managed key.'
    [ "$(marked_count "$selected")" -eq 1 ] || fail 'Cannot verify newly appended key.'
    notice "Added exactly one managed key in $selected."
    exit 0
fi

# ADOPT/REMOVE identify an existing key by its exact public blob. REPLACE is
# only allowed with one explicitly confirmed, uniquely marked stale key.
if [ "$VAULT_ACTION" = replace ]; then
    [ "$collision_total" -eq 1 ] || fail 'Old managed key cannot be identified uniquely.'
    old_ifs=$IFS; IFS='
'
    for final in $entries; do
        [ -n "$final" ] && [ -f "$final" ] || continue
        if awk -v m="$VAULT_MARKER" '$NF==m {found=1} END{exit !found}' "$final"; then
            selected=$final; break
        fi
    done
    IFS=$old_ifs
else
    [ "$match_total" -eq 1 ] || fail 'Public key has no unique authorization in the configured key files.'
fi
[ -n "$selected" ] && [ -f "$selected" ] && [ -w "$selected" ] || fail 'Remote authorization file is not writable.'
if [ "$VAULT_ACTION" = adopt ] && [ "$mark_total" -eq 1 ]; then
    notice "Identity already adopted with this marker in $selected."
    exit 0
fi
if [ "$VAULT_ACTION" = remove ]; then
    [ "$mark_total" -eq 1 ] || fail 'Remote key has not been adopted by SSH Vault.'
fi
if [ -s "$selected" ]; then
    last_byte=$(tail -c 1 "$selected" | od -An -tu1 | tr -d ' \n')
    [ "$last_byte" = 10 ] || fail 'No final newline. Refusing replacement.'
fi
nlinks=$(stat -c '%h' "$selected" 2>/dev/null || stat -f '%l' "$selected" 2>/dev/null || true)
case "$nlinks" in ''|*[!0-9]*) fail 'Cannot reliably inspect the authorization file hardlink count.' ;; esac
[ "$nlinks" -eq 1 ] || fail 'Hardlinked file cannot be replaced safely.'
dir=$(dirname "$selected")
snapshot=$(mktemp "$dir/.ssh-vault-before.XXXXXXXX") || fail 'Cannot stage authorization snapshot.'
tmp=$(mktemp "$dir/.ssh-vault-after.XXXXXXXX") || { rm -f "$snapshot"; fail 'Cannot stage updated file.'; }
metadata=''
cleanup() { rm -f "$snapshot" "$tmp"; [ -z "$metadata" ] || rm -f "$metadata"; }
trap cleanup EXIT HUP INT TERM
cp -p "$selected" "$snapshot" || fail 'Cannot make exact file snapshot.'
if [ "$VAULT_ACTION" = adopt ]; then
    awk -v t="$VAULT_TYPE" -v b="$VAULT_BLOB" -v m="$VAULT_MARKER" '
        /^[[:space:]]*#/ {print;next}
        {hit=0; for(i=1;i<NF;i++) if($i==t && $(i+1)==b) hit=1
         if(hit) print $0 " " m; else print}
    ' "$snapshot" > "$tmp" || fail 'Cannot stage adoption.'
elif [ "$VAULT_ACTION" = replace ]; then
    # Preserve ALL options and comments on the old managed line. Replace just
    # the old SSH public-key type/blob, never touch unrelated authorizations.
    awk -v t="$VAULT_TYPE" -v b="$VAULT_BLOB" -v m="$VAULT_MARKER" '
        $NF==m {
            hits=0
            for(i=1;i<NF;i++) if($i=="ssh-ed25519" && $(i+1)~/^[A-Za-z0-9+\/=]+$/) {
                old=$i " " $(i+1); idx=index($0,old)
                if(idx>0) {
                    print substr($0,1,idx-1) t " " b substr($0,idx+length(old))
                    hits++; break
                }
            }
            if(hits!=1) exit 72
            next
        }
        {print}
    ' "$snapshot" > "$tmp" || fail 'Cannot safely replace the previously managed key.'
else
    awk -v t="$VAULT_TYPE" -v b="$VAULT_BLOB" -v m="$VAULT_MARKER" '
        /^[[:space:]]*#/ {print;next}
        {hit=0; for(i=1;i<NF;i++) if($i==t && $(i+1)==b && $NF==m) hit=1
         if(!hit) print}
    ' "$snapshot" > "$tmp" || fail 'Cannot stage revocation.'
fi
if [ "$VAULT_ACTION" = adopt ] || [ "$VAULT_ACTION" = replace ]; then
    [ "$(marked_count "$tmp")" -eq 1 ] || fail 'Cannot verify staged key ownership.'
else
    [ "$(key_count "$tmp")" -eq 0 ] || fail 'Key is still present in proposed authorization.'
fi
metadata=$(mktemp "$dir/.ssh-vault-meta.XXXXXXXX") || fail 'Cannot stage metadata.'
cp -p "$snapshot" "$metadata" || fail 'Cannot preserve metadata.'
cat "$tmp" > "$metadata" || fail 'Cannot prepare replacement.'
[ ! -L "$selected" ] && cmp -s "$selected" "$snapshot" || fail 'Authorization file changed concurrently; aborting.'
mv -f "$metadata" "$selected" || fail 'No atomic filesystem replacement available; original unchanged.'
metadata=''
if [ "$VAULT_ACTION" = adopt ] || [ "$VAULT_ACTION" = replace ]; then
    [ "$(marked_count "$selected")" -eq 1 ] || fail 'Managed key not present after commit.'
    if [ "$VAULT_ACTION" = replace ]; then
        notice "Replaced exactly one stale SSH Vault-managed key in $selected; all other entries preserved."
    else
        notice "Adopted exactly one remote authorization in $selected."
    fi
else
    [ "$(key_count "$selected")" -eq 0 ] || fail 'Key still present after revocation.'
    notice "Revoked only the adopted SSH Vault entry from $selected."
fi
