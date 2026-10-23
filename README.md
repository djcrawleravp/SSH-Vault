# SSH Vault

**One master password. Your SSH identities. Every machine.**

SSH Vault is a keyboard-first, mouse-friendly terminal application for macOS, Linux, and FreeBSD. Register a remote server once, install and test its Ed25519 public key, and return to it without entering the remote account password. Optionally disable SSH password authentication on the remote server, with validation and rollback safeguards.

Unlike a plain SSH configuration manager, **SSH Vault encrypts its connection inventory, private and public keys, known host fingerprints, and last-used SSH username in one portable KDBX 4 database**. It uses the established KeePass file format with **Argon2id** key derivation and AES-256 encryption. The master password is not written to disk.

> **Security note:** SSH passwordless sign-in uses asymmetric keys. Your SSH *private* key still controls access to the remote host. SSH Vault protects it at rest; it does not eliminate the need to guard a running, unlocked computer.

## Project layout

Only the source files are included in the repository:

```text
SSH-Vault/
├── README.md
├── .gitignore
├── run.sh
└── app/
    ├── launcher.py           # Python curses TUI
    ├── bootstrap.py          # Full-screen isolated dependency setup
    ├── startup.py            # Master-password and migration screens
    ├── vault.py              # KDBX database, migration, backups, export
    ├── session.py            # Dedicated ssh-agent and isolated admin staging
    ├── ssh_backend.sh        # SSH enrollment / remote administration
    ├── remote_authorized_keys.sh # POSIX remote key handling
    ├── requirements.txt      # pykeepass (installed into .venv/)
    └── tests/                # Regression tests
```

Created only when needed, **and excluded from Git**:

```text
SSH-Vault/
├── vault.kdbx              # Encrypted source of truth
├── .vault-backups/         # Encrypted, verified backup before source cleanup
├── .venv/                  # Python dependency environment if needed
├── keys/                   # OPTIONAL legacy import inbox
│   ├── config
│   ├── known_hosts
│   ├── priv/
│   └── pub/
└── exported_keys/          # OPTIONAL plaintext export, never import inbox
    ├── config
    ├── known_hosts
    ├── priv/
    └── pub/
```

**`keys/` is never created automatically.** If there are no legacy keys to import, the only durable SSH identity store is `vault.kdbx`.

## Quick start

Requirements: Python 3.9+, Bash, OpenSSH (`ssh`, `ssh-keygen`, `ssh-agent`, `ssh-add`), and a terminal supporting curses. An internet connection may be required **once** to install the Python KDBX dependency (`pykeepass==4.2.0`).

```bash
git clone https://github.com/djcrawleravp/SSH-Vault.git
cd SSH-Vault
chmod +x run.sh
./run.sh
```

On first launch SSH Vault displays a **full-screen startup panel** while preparing the isolated `.venv/` and installing its cryptographic dependencies. Installer output is hidden during normal setup, but diagnostic lines are shown if installation fails. It never installs Python packages globally or writes credentials to the local `~/.ssh`. The encrypted vault creation/unlock prompt and migration summary are also shown inside the TUI.

### First launch

1. After the startup panel prepares the runtime, enter a new master password of **at least 12 characters** in the masked TUI prompt.
2. Confirm it. SSH Vault creates `vault.kdbx` using KDBX4/Argon2id.
3. If an existing `keys/` folder is present, SSH Vault verifies and migrates eligible connections, reporting what was imported, skipped, preserved, or cleaned.
4. The main TUI opens. Press `N` or select **New** to register a server.
5. Enter alias, hostname/IP, remote username (initial default `root`, then last successful user), and port (always defaults to `22`).
6. SSH Vault creates an Ed25519 key, installs its public half remotely, verifies key-based login, then offers to disable password-based SSH login across the remote server. **No keeps the existing password setting and completes creation.**

On subsequent launches the master password is requested once in the TUI. Wrong passwords never unlock the vault; an incorrect password can be retried without erasing existing data.

### Universal OpenSSH key management (Linux, macOS, FreeBSD)

SSH Vault does **not** use a Proxmox-specific path exception. The remote key
manager runs under POSIX `/bin/sh` and follows the SSH daemon's effective
`AuthorizedKeysFile` settings, when `sshd -T` is accessible. Supported settings
include multiple key files, alternative paths, and the usual `%h`, `%u`, `%U`
tokens. When those settings cannot be read, SSH Vault uses the standard
`~/.ssh/authorized_keys` location and requires a **separate successful
public-key login** to confirm enrollment. If `AuthorizedKeysFile none` or an
external-only `AuthorizedKeysCommand` is configured, it reports the limitation
rather than writing an unrelated file. OpenSSH documents these options and
restrictions in `sshd_config(5)`.

**Symlinks are followed conservatively, not replaced.** An `authorized_keys`
symlink can point to another local file or a cluster-managed store; the
launcher examines the actual destination and checks whether it can be written
without changing the link, existing permissions, or other authorized lines.
Adding a key appends a single entry without modifying other records.

SSH Vault **marks newly installed keys**, for example:

```text
ssh-ed25519 AAAA... ssh-vault-managed-server
```

Older imported identities start in **LEGACY** status. From **Edit → Adopt Remote
Key**, SSH Vault first proves independent key-only login, inspects the effective
OpenSSH authorization files and requires exactly **one** matching key entry.
It appends an ownership marker to that entry's *comment*, preserving the
existing key restrictions and any original comment. Once the remote change is
confirmed and saved to KDBX, the identity becomes **TAGGED**.

**Edit → Verify Managed Remote Key** separately confirms both public-key login
and that there is one matching Vault-owned authorization. `TAGGED` alone
is *not* proof that the remote entry still exists. If the same key is in
multiple authorized_keys records, is controlled by a different marker, or is
supplied by `AuthorizedKeysCommand`, adoption fails without changing anything.

**Delete** requires a uniquely tagged authorization; first it checks ownership
without changing the remote server's password policy. Then it removes only the
matching public-key record and checks that a new independent key-only login is
explicitly rejected before it deletes the encrypted vault identity. It NEVER
performs a `vault-only` deletion of an unmanaged identity.

Network and disk operations across two different machines cannot form one
perfectly atomic transaction. If a remote revocation succeeds but the local
vault write fails, the encrypted identity is intentionally retained for manual
recovery; a warning is shown instead of falsely claiming synchronized deletion.

For revocation, SSH Vault stages an updated file alongside the original,
checks the source has not changed and uses an atomic rename. **Special
filesystems that cannot support safe replacement (including some cluster
filesystems) are deliberately refused**, leaving the original unchanged. Some
SSH servers use databases, LDAP, a certificate authority or other external
key providers: SSH Vault cannot universally modify these mechanisms. A
successful key-based SSH connection does not imply SSH Vault can edit every
possible backing store.

**Scope warning:** if a linked file is shared across several machines, adding
or removing an entry can affect authentication on every server that consumes
that shared file. This is inherent to the remote SSH configuration, not a
per-distribution special case.

**Remote SSH password policy is separate.** Enabling/disabling passwords
requires OS/service-manager-specific privileged actions. The existing safe
rollback workflow supports compatible Linux/systemd SSH servers; it does not
claim to change every macOS, FreeBSD or appliance SSH daemon. Unsupported
servers must keep their current password policy and remain accessible by key.

### Connection creation diagnostics

If the remote server refuses the initial SSH password or key, SSH Vault now shows the available SSH error and the failed step **inside a scrollable TUI dialog** rather than immediately clearing the terminal and showing only exit code `1`. A newly generated key is not stored unless key authentication has been verified. If a **separate, optional** server-wide password-login change fails after that verification, the verified connection is still stored, and the dialog explicitly distinguishes that partial result.

Creating an SSH identity requires a reachable host and an authentication method that the server already permits. The option to disable password-based SSH login requires additional Linux/systemd privileges and is not supported on every remote SSH server. No app can guarantee a successful new enrollment when the remote server rejects its credentials.

## Daily operation

| Action | Keyboard | Mouse |
|---|---|---|
| Navigate servers | `↑` / `↓`, `J` / `K` | Click or wheel (one item per step) |
| Connect | `Enter`, `C` | Double click or **Connect** |
| New connection | `N` | **New** |
| Edit / password policy / adopt / verify | `E` | **Edit** |
| Delete / revoke identity | `D` | **Delete** |
| Search | `/`, `S` | **Search** |
| Vault management | `V` | **Vault** or **Menu** |
| Help | `H`, `?` | **Help** |
| Quit / lock | `Q`, `Esc` | **Quit** |
| Focus on footer buttons | `Tab`, `Shift+Tab` | Click |

Dialogs support `Y/N`, arrows, `Tab`, `Enter`, `Esc`, and clickable choices. Sessions return to SSH Vault after you log out or use `Ctrl+D`. The unlocked launcher auto-closes after **10 minutes of TUI inactivity**, but does not interrupt an active SSH session.

**Normal SSH login uses a dedicated, short-lived `ssh-agent`.** The private key is loaded through stdin and no persistent decrypted private-key file is produced for routine connections. SSH host fingerprints temporarily live in a private session file; new fingerprints are saved back to the encrypted database when SSH returns.

## Migrating the old `keys/` folder

Place the **original** portable `keys/` folder next to `run.sh` before starting SSH Vault:

```text
keys/
├── config
├── known_hosts
├── priv/
│   ├── seafile-server
│   └── orphan-key
└── pub/
    ├── seafile-server.pub
    └── orphan-key.pub
```

Only simple, literal `Host alias` configurations with a matching private/public key pair are eligible. `IdentityFile` **determines the filename**: a connection called `seafile` can use `seafile-server` without renaming it.

For every recognized server the importer:

1. Parses its explicit `HostName`, `User`, `Port` and `IdentityFile` directives.
2. Checks the SSH private/public key relationship with `ssh-keygen -y` (encrypted/passphrase-protected or malformed legacy identities are left untouched).
3. Compares the alias and identity to existing vault entries. Identical duplicates are skipped; conflicts are preserved.
4. Saves all accepted records and confidently matched un-hashed host fingerprints to KDBX.
5. **Reopens and compares the encrypted data**, creates and verifies an encrypted backup in `.vault-backups/`.
6. Removes **only** imported, verified blocks from `keys/config` and their corresponding original private/public files, provided the keys are not referenced by unresolved entries.
7. Retains orphan keys, unsupported SSH directives, unknown fingerprints, changed files, invalid pairs, and all other leftovers. macOS `.DS_Store` metadata is ignored during import and removed **only** from directories that are otherwise empty. Unknown hidden files (`.*`) are never deleted automatically. When nothing remains, it removes the empty `keys/` directory too.

An import report appears at startup and is accessible again through **Vault → Import legacy keys/**.

**No secure-erase guarantee:** On SSDs, snapshots, cloud sync, or filesystem backups, deleting the original `keys/` files cannot guarantee permanent erasure. Back up the encrypted vault separately before making an irreversible change. Automatic cleanup occurs only after the encrypted backup is verified.

### Unsupported source entries

SSH Vault deliberately does not silently migrate complex OpenSSH options such as `ProxyJump`, `ProxyCommand`, forwarding directives, `Match`, or wildcard aliases. Their source blocks remain in `keys/config` for manual review. Hashed/unrecognized `known_hosts` entries are preserved instead of guessed. Symlinks are refused for sensitive source files.

## Exporting

Use **Vault → Export** to create a **new** plaintext `exported_keys/` folder containing the selected vault's connection inventory, private/public key files, and fingerprints. Exports are compatible with ordinary OpenSSH:

```bash
cd exported_keys
ssh -F config ALIAS
```

If `exported_keys/` already exists, SSH Vault generates a **new timestamped sibling** such as `exported_keys-20261022-204500-abcdef/`. Existing exports and `keys/` are never overwritten. Exports are intentionally not scanned for import on the next launch.

> Exported private keys are **not encrypted**. Store and transfer exports only to trusted destinations; delete them when finished. Never commit `exported_keys/` to GitHub.

## Remote password authentication and safety

- SSH Vault installs key access first and verifies it before optionally changing `sshd`.
- Disabling remote SSH password authentication affects **the entire server**, not just the selected user.
- **Key enrollment/revocation** uses portable POSIX shell on OpenSSH targets across Linux, macOS and FreeBSD (subject to the destination authorization store allowing safe file operations).
- **Changing the password-login policy** is currently limited to compatible Linux with `systemd`, OpenSSH `sshd` and sufficient root/sudo privileges. On other servers SSH Vault preserves the existing policy and reports that the operation is unsupported.
- It validates `sshd -t`, effective settings, a fresh key-only SSH login, and maintains an automatic remote rollback timer when supported.
- Removing a remote identity can lock you out. Confirm alternative access before revocation.
- **Shared key identities are not automatically revoked.** Ownership must be unambiguous, and a single authorized key may be shared between machines through the remote server's own configuration. Other services, host aliases or external providers may still authorize the same credential; ambiguous situations are refused, not guessed.
- The first server fingerprint is accepted automatically (`accept-new`), but a changed known fingerprint is not automatically accepted. Consider verifying fingerprints out of band for high-value servers.
- A remote administrator's `sudo` authentication may be separate from their initial SSH login. Passwords are never persisted or passed as process arguments.

For remote admin changes, short-lived **plaintext key files** exist in a private temporary directory because the OpenSSH backend requires path-based identities. They are removed after the operation, but secure-erasure of swap/filesystem snapshots cannot be guaranteed.

## Backup, portability and recovery

To move your connections to another machine, copy `vault.kdbx` and the code (`app/`, `run.sh`) into a trusted location. Enter the original master password at startup. Keep encrypted `.vault-backups/` copies in another place as disaster recovery.

You may open `vault.kdbx` with software compatible with KeePass KDBX 4. The SSH Vault data is stored as a **protected JSON password field inside one KeePass entry**; this is a machine-readable data structure rather than one human-readable entry per host.

If the master password is forgotten and you have no other backup/unlock mechanism, SSH Vault cannot recover the keys.

## Testing

```bash
python3 -m pip install pytest cryptography
python3 -m pytest -q app/tests
```

Behavioral tests cover migration and selective cleanup (including macOS `.DS_Store`), duplicates, conflicts, shared identities, untouched orphan files, export isolation, generic OpenSSH key authorization paths, symlinks, exact Vault-owned revocation, disposable administration staging, mouse/keyboard UI actions, and command safety. A separate optional test exercises **real KDBX 4 creation, encrypted round-trip and password change**, and runs when `pykeepass` is installed.

**Compatibility note:** Validation in the development environment is not a substitute for testing a new remote `sshd` password policy on your own servers. Keep an independent SSH console or alternative recovery method available when first trying remote changes.

## Why SSH Vault?

A portable SSH launcher should be more than a menu of `ssh` commands: **set up key authentication once, remove routine password entry, carry encrypted credentials with you, and recover/export your environment without manually copying secret files across computers.**

---

Made for portable, auditable SSH identity management. Contributions and issue reports are welcome.


### Unlock troubleshooting and legacy deletion safety (v12.1)

SSH Vault only retries the master-password prompt when the KDBX reader raises
`CredentialsError`. Corruption, incompatible data, filesystem failures or other
exceptions are reported separately instead of being mistaken for a bad password.
This does not assume or assert that the user's typed password is wrong.

Deleting an imported/unmarked identity is **refused** for remote revocation.
Neither the encrypted identity nor the remote authorized key is deleted. The
backend now performs this eligibility check **before** attempting to enable
remote SSH password authentication. To remove an imported identity manually,
verify the corresponding public-key fingerprint and remote authorization source
through an independent administrative channel; SSH Vault does not remove
unmarked keys automatically.

## Adopting and deleting imported connections

Select a **LEGACY** connection, choose **Edit → Adopt Remote Key**, and confirm.
The operation is safe to retry after an interrupted local save: it uses the
same ownership marker and does not append a second authorization entry.
Then use **Edit → Verify Managed Remote Key** to verify the remotely owned key.
Only after this succeeds should you select **Delete**; it will check a new
public-key login is rejected before removing the key and connection from KDBX.

**Limitations:** SSH Vault cannot safely adopt or revoke arbitrary SSH
certificate authorities, LDAP records, provider-generated keys, unreadable
`sshd -T` settings, duplicate authorized entries or writable stores that do
not support atomic replacement. It will refuse these cases. Some managed
cluster filesystems have special semantics; real-server verification remains
necessary before relying on destructive operations.

## Running tests

```bash
python3 -m pytest -q app/tests
bash -n app/ssh_backend.sh
sh -n app/remote_authorized_keys.sh
```

The SSH authorization test suite uses a **fake SSH server and private HOME**.
The KDBX integration test runs only when `pykeepass` is available. Do not assume
that local simulations establish end-to-end correctness on every Linux, macOS
or FreeBSD OpenSSH installation. Back up `vault.kdbx` before a live migration,
adoption or revocation.

### Moving a connection to a different remote target

**In-place changes to HostName, User, or Port are intentionally disabled** in
this security-focused release: the old server could retain an orphaned remote
public key, especially when two hosts share a cluster-managed authorization
file. To move safely, create a *new* connection with a new identity, verify its
SSH login, then delete the original connection and confirm that revocation
succeeds. Renaming a local alias is still supported.
