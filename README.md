# SSH Launcher

**A portable, keyboard-first SSH connection manager for your terminal.**

Create an SSH connection, generate an Ed25519 key pair, install the public key on the remote host, and sign in with your key from then on. Optionally disable SSH password authentication on supported servers—without manually editing `sshd_config`. Keep your connections and private keys in one folder that you can move or back up as a unit.

No cloud account. No database server. No `pip install`. Just Python, Bash, and OpenSSH.

## Why SSH Launcher?

Setting up passwordless SSH usually means generating a key, transferring it to a server, editing SSH configuration, checking file permissions, and—if desired—safely hardening remote authentication. SSH Launcher brings those steps together in one terminal interface.

- **One-time setup:** create an Ed25519 key and authorize it on the remote host. After successful key setup, normal SSH logins use the key instead of requiring the remote account password. The generated private key has no passphrase; protect your backup accordingly.
- **Optional SSH hardening:** enable or disable SSH password authentication server-wide on supported Linux servers, with independent key-login verification and a timed rollback mechanism.
- **Portable by design:** the connection config, key pairs, and `known_hosts` live under the project's own `keys/` folder. The local `~/.ssh` directory is not synchronized or written by the launcher.
- **An actual launcher:** select a server, press **Enter**, use the real SSH terminal, and return to the launcher automatically when you disconnect.
- **Keyboard first, mouse supported:** arrows, quick actions, keyboard-accessible forms and confirmations, mouse selection, double-click, scroll wheel, and clickable actions.
- **No external Python dependencies:** the interface is built with the standard-library `curses` module.

## Quick start

**Requirements:** Python **3.9+**, Bash, and OpenSSH (`ssh` and `ssh-keygen`). Client support targets macOS, Linux, and FreeBSD with these tools installed. An interactive terminal is required.

```bash
# Clone the repository (or extract the release ZIP)
git clone https://github.com/YOUR-ACCOUNT/ssh-launcher.git
cd ssh-launcher

chmod +x run.sh
./run.sh
```

Replace the sample GitHub URL above with your own repository address, or simply run `./run.sh` after extracting the release ZIP. You can launch the script **from any working directory**; paths are based on the location of `run.sh`.

**Nothing needs to be created manually.** On the first run, SSH Launcher creates `keys/config`, `keys/known_hosts`, `keys/priv/`, and `keys/pub/` with restricted permissions. No actual SSH key pair is generated until you create a connection.

### Create your first connection

1. Press **N** or select **New**. Enter an alias, host or IP address, SSH username, and port.
2. The suggested username starts as `root`. After a connection is successfully registered, the launcher suggests that connection's username next time. The port always starts at **22**.
3. Confirm creation. The launcher generates an **Ed25519** key pair and authorizes its public key on the remote host. An initial password or other existing access may be required for authorization. Automated key authorization currently executes Bash on the remote host, so that host must have Bash installed.
4. Choose whether to **disable SSH password login** once key authentication has been verified. **No** keeps the existing password setting and **still creates the connection**. **Cancel** aborts the creation before it starts.
5. Select the new connection and press **Enter**. When you close the SSH session (for example with `exit`), the launcher returns.

The private key is used directly from the portable `keys/priv/` directory; you do not need to install or copy it into `~/.ssh`.

## Keyboard and mouse

| Action | Keyboard | Mouse |
| --- | --- | --- |
| Select a server | `↑` / `↓`, `J` / `K` | Left click, wheel |
| Connect | `Enter`, `C` | Double click, **Connect** |
| Create | `N` | **New** |
| Edit | `E` | **Edit**, context menu |
| Delete | `D` | **Delete**, context menu |
| Search | `/` or `S` | **Search** |
| Reload | `R` | **Reload** |
| Help | `H`, `?`, `F1` | **Help** |
| Actions menu | `M` | **Menu**, right click |
| Quit | `Q` or `Esc` | **Quit** |
| Focus buttons | `Tab` / `Shift+Tab` | Click buttons |
| Confirm / cancel | `Y` / `N`, `Enter`, `Esc` | Click the appropriate option |

Mouse support depends on the terminal emulator. The launcher understands common SGR, X10, and urxvt mouse reports; keyboard controls work even when mouse reporting is unavailable.

## File structure

**Files included in the repository or release:**

```text
ssh-launcher/
├── README.md
├── .gitignore
├── run.sh
└── app/
    ├── launcher.py
    └── ssh_backend.sh
```

**Created when you first run the launcher or register a connection:**

```text
ssh-launcher/
├── app/
│   └── .launcher_state.json    # Last successfully registered SSH username
└── keys/                      # Private runtime data (Git-ignored)
    ├── config                # Portable OpenSSH host entries
    ├── known_hosts           # Saved host fingerprints
    ├── priv/                 # Private keys; protect these carefully
    └── pub/                  # Public keys
```

The state file is created when a connection is registered. Until then, the suggested username is `root`. Its only preference is the last SSH username; it contains no passwords. If the state file is absent, damaged, or deleted, the default becomes `root` again.

SSH Launcher supports key filenames different from their aliases (for example an alias `seafile` using `keys/priv/seafile-server`). Existing portable configurations and keys are kept when the application updates.

### Moving or backing up your launcher

For a **fully restorable personal backup**, copy the entire folder, including `keys/` and the application preference in `app/`. You can move it to another path and run `./run.sh` there. No reinstallation of SSH keys into the new computer's `~/.ssh` is required.

> **Security:** `keys/priv/` contains unencrypted private keys. Treat a backup as sensitive credential material: encrypt it, restrict access, and **never commit `keys/` to GitHub**. The supplied `.gitignore` excludes the runtime keys and local state, but review `git status` before pushing. If you previously tracked a private key in Git, `.gitignore` alone will not remove it from Git history.

### Updating

Replace `run.sh` and `app/` with the newer version, preserving your existing `keys/` folder. Your connections, key pairs, and known host fingerprints remain in place. The username preference in `app/.launcher_state.json` is also excluded from version control; preserve that file if you want to keep its current value across manual replacements of the `app/` directory.

## Remote SSH password-login management

You can enable or disable password-based SSH access while creating a connection or later in **Edit**.

**Important distinctions:**

- Passwordless **SSH login** does not mean passwordless **`sudo`**. A non-root account may require its sudo password to change server settings.
- Disabling SSH password authentication affects the **whole SSH server**, not just one login account. Before doing so, ensure another tested administrative access path exists.
- The current remote configuration workflow requires a **systemd-based Linux server** with `sudo` or root access, OpenSSH `sshd`, `systemctl`, and `systemd-run`. The target SSH server must load `/etc/ssh/sshd_config.d/` for the drop-in policy to be effective. General SSH connections can still work with macOS, FreeBSD, and other Unix servers; remote password-policy management is not universal.
- The launcher first verifies key authentication, validates the effective `sshd` settings, and checks a fresh SSH connection. A scheduled rollback is used if the policy change cannot be confirmed. A successful change is intended to persist across service restarts; a verification failure prevents claiming success.
- Initial host fingerprints are accepted automatically into `keys/known_hosts` using `StrictHostKeyChecking=accept-new`. Changed fingerprints are rejected. On first contact this is **trust on first use**, so independently verify fingerprints if you require stronger protection against man-in-the-middle attacks.

## Design and privacy

- **Local isolation:** SSH connections use the launcher's `keys/config` and `keys/known_hosts`; the launcher does not synchronize or intentionally modify the client's `~/.ssh`.
- **Remote changes are intentional:** creating or deleting a connection changes the remote user's `~/.ssh/authorized_keys`. Changing password-login policy changes the remote SSH daemon configuration.
- **No saved passwords:** passwords, when requested by SSH or `sudo`, are handled by their native prompts; the local state file contains only the suggested username.
- **Safe first run:** directories and files are created only when missing. Existing configs, fingerprints, and keys are never reset on startup. Symbolic links are rejected for sensitive managed paths.

## License

No license has been specified yet. If you plan to accept outside contributions or allow public reuse, add a `LICENSE` file with your chosen terms before publishing.
