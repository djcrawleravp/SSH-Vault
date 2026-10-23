"""Regression coverage: adoption, exact revocation and fail-closed behavior.
Runs POSIX sh against private fake OpenSSH server home (no live server).
"""
from pathlib import Path
import subprocess

from test_universal_remote_keys import fixture_env, backend


def legacy(stage, env, alias='legacy', key_file='old-identity', host='fake-unix'):
    # A real Ed25519 key pair is generated with the fake tools fixture, but
    # the local public-key comment has no Vault marker yet.
    import os
    p = subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', 'legacy@oldhost',
                        '-f', str(stage / 'priv' / key_file)], env=env, capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    (stage / 'priv' / (key_file + '.pub')).rename(stage / 'pub' / (key_file + '.pub'))
    (stage / 'config').write_text(
        f'Host {alias}\n    HostName {host}\n    User root\n'
        f'    Port 22\n    IdentityFile keys/priv/{key_file}\n    IdentitiesOnly yes\n')
    return (stage / 'pub' / (key_file + '.pub')).read_text().split()[:2]


def test_adopt_preserves_options_and_other_keys_then_delete(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path)
    typ, blob = legacy(stage, env)
    before_unrelated = 'restrict,command="echo keep original flags" ssh-ed25519 OTHER_BLOB someone-else\n'
    original_line = f'from="192.0.2.10",no-pty {typ} {blob} original notes with spaces'
    auth.write_text(before_unrelated + original_line + '\n')
    adopted = backend(env, 'adopt', 'legacy')
    assert adopted.returncode == 0, (adopted.stdout, adopted.stderr)
    assert auth.read_text() == before_unrelated + original_line + ' ssh-vault-managed-legacy\n'
    assert (stage / 'pub' / 'old-identity.pub').read_text() == f'{typ} {blob} ssh-vault-managed-legacy\n'
    assert backend(env, 'verify', 'legacy').returncode == 0
    deleted = backend(env, 'delete', 'legacy', 'keep_password')
    assert deleted.returncode == 0, (deleted.stdout, deleted.stderr)
    assert auth.read_text() == before_unrelated
    assert not (stage / 'priv' / 'old-identity').exists()
    assert not (stage / 'pub' / 'old-identity.pub').exists()
    assert 'Host legacy' not in (stage / 'config').read_text()


def test_adopt_duplicate_key_in_two_files_never_changes_anything(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path, mode='multiple')
    typ, blob = legacy(stage, env)
    other = home / '.ssh' / 'keyfile'
    other.write_text(f'{typ} {blob} older\n')
    auth.write_text(f'{typ} {blob} old\n')
    first, second = auth.read_bytes(), other.read_bytes()
    result = backend(env, 'adopt', 'legacy')
    assert result.returncode != 0
    assert auth.read_bytes() == first and other.read_bytes() == second
    assert 'ssh-vault-managed-' not in (stage / 'pub' / 'old-identity.pub').read_text()


def test_adopt_external_provider_fails_closed(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path, mode='none')
    typ, blob = legacy(stage, env)
    auth.write_text(f'{typ} {blob} legacy\n')
    before = auth.read_bytes()
    result = backend(env, 'adopt', 'legacy')
    assert result.returncode != 0
    assert auth.read_bytes() == before


def test_adopt_idempotent_after_remote_marker_applied(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path)
    typ, blob = legacy(stage, env)
    auth.write_text(f'{typ} {blob} old-comment ssh-vault-managed-legacy\n')
    result = backend(env, 'adopt', 'legacy')
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert auth.read_text().count('ssh-vault-managed-legacy') == 1
    assert 'ssh-vault-managed-legacy' in (stage / 'pub' / 'old-identity.pub').read_text()


def test_adopt_different_ownership_marker_refuses(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path)
    typ, blob = legacy(stage, env)
    original = f'{typ} {blob} ssh-vault-managed-other\n'
    auth.write_text(original)
    result = backend(env, 'adopt', 'legacy')
    assert result.returncode != 0
    assert auth.read_text() == original


def test_delete_unmarked_does_not_delete_local_or_remote(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path)
    typ, blob = legacy(stage, env)
    original = f'{typ} {blob} unmanaged\n'
    auth.write_text(original)
    assert backend(env, 'delete', 'legacy', 'keep_password').returncode != 0
    assert auth.read_text() == original
    assert (stage / 'priv' / 'old-identity').exists()


def test_shared_legacy_filename_requires_review(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path)
    typ, blob = legacy(stage, env)
    auth.write_text(f'{typ} {blob} legacy\n')
    with (stage / 'config').open('a') as f:
        f.write('Host another\n    HostName fake-unix\n    User root\n    Port 22\n    IdentityFile keys/priv/old-identity\n')
    assert backend(env, 'adopt', 'legacy').returncode != 0
    assert backend(env, 'delete', 'legacy', 'keep_password').returncode != 0
    assert 'ssh-vault-managed-' not in auth.read_text()


def test_adopted_public_identity_survives_staged_vault_reload(tmp_path, monkeypatch):
    """Ensure a successful remote adoption is represented by valid vault data."""
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    import session
    import vault
    home, auth, stage, env = fixture_env(tmp_path)
    typ, blob = legacy(stage, env)
    auth.write_text(f'{typ} {blob} legacy-comment\n')
    before_private = (stage / 'priv' / 'old-identity').read_bytes()
    assert backend(env, 'adopt', 'legacy').returncode == 0
    class Store:
        data = {'servers': {}, 'known_hosts': '', 'last_user': 'root', 'version': 1}
    monkeypatch.setenv('PATH', env['PATH'])
    updated = session.changed_payload(Store(), stage)
    record = updated['servers']['legacy']
    assert vault.unb64(record['private']) == before_private
    assert record['key_name'] == 'old-identity'
    assert record['public'].startswith('c3NoLWVk')  # base64 of ssh-ed...
    assert b'ssh-vault-managed-legacy' in vault.unb64(record['public'])


def test_adoption_of_symlinked_store_keeps_symlink_and_unrelated_entry(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path, linked=True)
    typ, blob = legacy(stage, env)
    other = 'ssh-ed25519 OTHER_BLOB leave-this-alone\n'
    auth.write_text(other + f'{typ} {blob} old-legacy\n')
    mode = auth.stat().st_mode & 0o777
    assert backend(env, 'adopt', 'legacy').returncode == 0
    assert (home / '.ssh' / 'authorized_keys').is_symlink()
    assert auth.stat().st_mode & 0o777 == mode
    assert auth.read_text() == other + f'{typ} {blob} old-legacy ssh-vault-managed-legacy\n'
    assert backend(env, 'delete', 'legacy', 'keep_password').returncode == 0
    assert auth.read_text() == other
    assert (home / '.ssh' / 'authorized_keys').is_symlink()


def test_target_change_never_creates_orphan_key(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path)
    assert backend(env, 'create', 'alpha', 'fake-unix', 'root', '22', 'keep').returncode == 0
    before=auth.read_bytes()
    result=backend(env, 'target', 'alpha', 'new-target', 'root', '22')
    assert result.returncode != 0
    assert auth.read_bytes()==before
    assert 'Host alpha' in (stage / 'config').read_text()
