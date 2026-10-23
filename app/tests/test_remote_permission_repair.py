"""StrictModes repair regression tests; never contact a real SSH server.

Only dedicated temporary test directories are touched.  Ownership changes
are tested only when the test process has UID 0.
"""
import os
import subprocess
from pathlib import Path

import pytest

HELPER = Path(__file__).resolve().parents[1] / 'remote_permission_repair.sh'


def make_fixture(tmp_path, *, key_as_symlink=False):
    home = tmp_path / 'remote-home'
    home.mkdir(mode=0o700)
    ssh = home / '.ssh'
    ssh.mkdir(mode=0o700)
    auth = ssh / 'authorized_keys'
    if key_as_symlink:
        target = ssh / 'shared-keys'
        target.write_text('ssh-ed25519 aaaa unrelated\n')
        target.chmod(0o600)
        auth.symlink_to(target)
    else:
        auth.write_text('ssh-ed25519 aaaa unrelated\n')
        auth.chmod(0o600)
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    sshd = bindir / 'sshd'
    sshd.write_text('#!/bin/sh\n[ "$1" = -T ] || exit 1\nprintf "strictmodes yes\\npubkeyauthentication yes\\nauthorizedkeysfile .ssh/authorized_keys\\n"\n')
    sshd.chmod(0o755)
    env = {**os.environ, 'PATH': str(bindir) + os.pathsep + os.environ.get('PATH', ''),
           'HOME': str(home), 'SSH_CONNECTION': '127.0.0.1 50000 127.0.0.1 22',
           'VAULT_REPAIR_MODE': 'apply'}
    return home, ssh, auth, env


def invoke(env):
    return subprocess.run(['/bin/sh', str(HELPER)], env=env,
                          capture_output=True, text=True, timeout=8)


@pytest.mark.skipif(os.geteuid() != 0, reason='Ownership-mismatch test requires isolated root test runner')
def test_root_repairs_mismatched_uid_without_changing_authorized_keys_content(tmp_path):
    home, ssh, auth, env = make_fixture(tmp_path)
    before = auth.read_bytes()
    os.chown(home, 100000, 100000)
    os.chown(ssh, 100000, 100000)
    result = invoke(env)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert home.stat().st_uid == 0 and ssh.stat().st_uid == 0
    assert auth.read_bytes() == before
    assert 'Corrected ownership' in result.stdout


def test_safe_permissions_are_left_unchanged(tmp_path):
    home, ssh, auth, env = make_fixture(tmp_path)
    before = (home.stat().st_mode & 0o777, ssh.stat().st_mode & 0o777,
              auth.read_bytes())
    result = invoke(env)
    assert result.returncode == 4, (result.stdout, result.stderr)
    assert before == (home.stat().st_mode & 0o777, ssh.stat().st_mode & 0o777,
                      auth.read_bytes())


def test_world_writable_ssh_directory_is_hardened_only_at_path(tmp_path):
    home, ssh, auth, env = make_fixture(tmp_path)
    ssh.chmod(0o777)
    before = auth.read_bytes()
    result = invoke(env)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert (ssh.stat().st_mode & 0o022) == 0
    assert auth.read_bytes() == before


def test_shared_symlink_is_refused_without_modifying_target(tmp_path):
    home, ssh, auth, env = make_fixture(tmp_path, key_as_symlink=True)
    target = ssh / 'shared-keys'
    before = target.read_bytes()
    result = invoke(env)
    assert result.returncode != 0
    assert 'SKIPPED' in result.stderr
    assert auth.is_symlink()
    assert target.read_bytes() == before


def test_incompatible_policy_is_refused_without_touching_anything(tmp_path):
    home, ssh, auth, env = make_fixture(tmp_path)
    auth.chmod(0o666)
    before = auth.read_bytes()
    sshd = Path(env['PATH'].split(os.pathsep)[0]) / 'sshd'
    sshd.write_text('#!/bin/sh\nprintf "strictmodes no\\npubkeyauthentication yes\\nauthorizedkeysfile .ssh/authorized_keys\\n"\n')
    result = invoke(env)
    assert result.returncode != 0
    assert auth.read_bytes() == before
    assert (auth.stat().st_mode & 0o022) != 0


def test_unknown_authorized_keys_location_is_refused(tmp_path):
    home, ssh, auth, env = make_fixture(tmp_path)
    auth.chmod(0o666)
    sshd = Path(env['PATH'].split(os.pathsep)[0]) / 'sshd'
    sshd.write_text('#!/bin/sh\nprintf "strictmodes yes\\npubkeyauthentication yes\\nauthorizedkeysfile .ssh/elsewhere\\n"\n')
    result = invoke(env)
    assert result.returncode != 0
    assert (auth.stat().st_mode & 0o022) != 0

@pytest.mark.skipif(os.geteuid() != 0, reason='Ownership-mismatch SSH simulator needs UID 0')
def test_enrollment_repairs_bad_remote_owner_then_independently_verifies(tmp_path):
    """End-to-end fake SSH: first key-only test denied, metadata fixed,
    second independent test succeeds, key and other authorizations preserved.
    """
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from test_universal_remote_keys import fixture_env, backend, FAKE_SSH

    home, auth, stage, env = fixture_env(tmp_path)
    # Use a dedicated fake sshd to report the active policy.
    fake_sshd = Path(env['PATH'].split(os.pathsep)[0]) / 'sshd'
    fake_sshd.write_text('#!/bin/sh\nprintf "strictmodes yes\\npubkeyauthentication yes\\nauthorizedkeysfile .ssh/authorized_keys\\n"\n')
    fake_sshd.chmod(0o755)
    os.chown(home, 100000, 100000)
    os.chown(home / '.ssh', 100000, 100000)
    ssh_stub = Path(env['PATH'].split(os.pathsep)[0]) / 'ssh'
    # Override just the -T key check; run the real remote POSIX helper.
    stub = FAKE_SSH.replace(
        "if '-T' in args:\n",
        "if '-T' in args and (os.stat(os.environ['FAKE_HOME']).st_uid != 0 or "
        "os.stat(Path(os.environ['FAKE_HOME'])/'.ssh').st_uid != 0):\n"
        "    print('Permission denied (publickey).', file=sys.stderr)\n"
        "    sys.exit(255)\n"
        "if '-T' in args:\n",
    )
    ssh_stub.write_text(stub)
    ssh_stub.chmod(0o755)
    mux = tmp_path / 'mux'
    mux.mkdir(mode=0o700)
    env['SSH_VAULT_MUX_PATH'] = str(mux / 'control')
    original = auth.read_text()
    result = backend(env, 'create', 'media', 'fake-unix', 'root', '22', 'keep')
    assert result.returncode == 0, (result.stdout, result.stderr, (stage / 'diag').read_text())
    assert (stage / 'priv' / 'media').is_file()
    assert os.stat(home).st_uid == 0 and os.stat(home / '.ssh').st_uid == 0
    assert auth.read_text().startswith(original)
    assert 'ssh-vault-managed-media' in auth.read_text()
    assert 'SSH metadata repaired and new key independently authenticated' in result.stdout
