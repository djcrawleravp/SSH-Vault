"""Safety regression for confirmed replacement of a previously managed lost key."""
from pathlib import Path
import os
import subprocess

HELPER = Path(__file__).resolve().parents[1] / 'remote_authorized_keys.sh'

# The remote helper validates only syntactic base64; use distinct Ed25519-looking
# blobs to make accidental broad string replacements obvious.
OLD_BLOB = 'AAAAC3NzaC1lZDI1NTE5AAAAIG9sZC1rZXktZGVtb25zdHJhdGlvbg=='
NEW_BLOB = 'AAAAC3NzaC1lZDI1NTE5AAAAIG5ldy1rZXktZGVtb25zdHJhdGlvbg=='
MARK = 'ssh-vault-managed-solid'


def prepare(tmp_path):
    home = tmp_path / 'home'
    home.mkdir()
    ssh = home / '.ssh'
    ssh.mkdir()
    auth = ssh / 'authorized_keys'
    unrelated = ('restrict,command="printf some-key-comments" '
                 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHVucmVsYXRlZA== other\n')
    original = f'from="192.0.2.0/24",no-pty ssh-ed25519 {OLD_BLOB} {MARK}\n'
    auth.write_text(unrelated + original)
    auth.chmod(0o600)
    env = {**os.environ, 'HOME': str(home), 'PATH': '/usr/bin:/bin',
           'VAULT_TYPE': 'ssh-ed25519', 'VAULT_BLOB': NEW_BLOB,
           'VAULT_MARKER': MARK}
    # No sshd executable in sandbox, so code uses the already-existing known
    # authorized_keys file in conservative limited-inspection mode.
    return auth, unrelated, original, env


def act(env, name):
    return subprocess.run(['sh', str(HELPER)], env={**env, 'VAULT_ACTION': name},
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=8)


def test_stale_marker_blocks_ordinary_create(tmp_path):
    auth, other, old, env = prepare(tmp_path)
    r=act(env, 'add')
    assert r.returncode != 0
    assert 'Ownership marker already belongs' in r.stderr
    assert auth.read_text() == other + old


def test_explicit_replace_only_changes_old_public_key(tmp_path):
    auth, other, old, env = prepare(tmp_path)
    r=act(env, 'replace')
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert auth.read_text() == other + old.replace(OLD_BLOB, NEW_BLOB)
    assert act(env, 'probe').returncode == 0
    assert act(env, 'remove').returncode == 0
    assert auth.read_text() == other


def test_replacement_refuses_multiple_old_markers(tmp_path):
    auth, other, old, env = prepare(tmp_path)
    auth.write_text(other + old + old)
    r=act(env, 'replace')
    assert r.returncode != 0
    assert auth.read_text() == other + old + old


def test_replace_rejects_unmarked_old_key(tmp_path):
    auth, other, old, env = prepare(tmp_path)
    auth.write_text(other + old.replace(MARK,'old-comment'))
    r=act(env, 'replace')
    assert r.returncode != 0
    assert auth.read_text() == other + old.replace(MARK,'old-comment')


def test_backend_replacement_requires_explicit_confirmation(tmp_path):
    from test_universal_remote_keys import fixture_env, backend
    home, auth, stage, env = fixture_env(tmp_path)
    before = f'ssh-ed25519 {OLD_BLOB} {MARK}\n'
    untouched = 'ssh-ed25519 OTHER_BLOB other-account\n'
    auth.write_text(untouched + before)
    ordinary = backend(env, 'create', 'solid', 'fake-unix', 'root', '22', 'keep')
    assert ordinary.returncode != 0
    assert 'Ownership marker already belongs' in (stage / 'diag').read_text()
    assert auth.read_text() == untouched + before
    assert not (stage / 'priv' / 'solid').exists()
    explicit = backend(env, 'create', 'solid', 'fake-unix', 'root', '22', 'keep', 'replace')
    assert explicit.returncode == 0, (explicit.stdout, explicit.stderr, (stage/'diag').read_text())
    assert (stage / 'priv' / 'solid').is_file()
    assert (stage / 'pub' / 'solid.pub').is_file()
    new_blob = (stage / 'pub' / 'solid.pub').read_text().split()[1]
    assert new_blob != OLD_BLOB
    assert auth.read_text() == untouched + before.replace(OLD_BLOB, new_blob)
