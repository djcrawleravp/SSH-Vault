"""Regression: a rejected new key is diagnosed without relaxing server SSH settings.

The SSH server and sshd are test doubles. No live server is contacted.
"""
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_universal_remote_keys import fixture_env, backend, FAKE_SSH


def test_key_only_rejection_collects_readonly_diagnostics_then_rolls_back(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path)
    ssh_stub = Path(env['PATH'].split(os.pathsep)[0]) / 'ssh'
    patched = FAKE_SSH.replace(
        "if '-T' in args:\n",
        "if '-T' in args and os.getenv('FAKE_DENY_KEY_ONLY') == '1':\n"
        "    print('Permission denied (publickey,password,keyboard-interactive).', file=sys.stderr)\n"
        "    sys.exit(255)\n"
        "if '-T' in args:\n",
    )
    ssh_stub.write_text(patched)
    ssh_stub.chmod(0o755)
    env['FAKE_DENY_KEY_ONLY'] = '1'
    mux = tmp_path / 'mux'
    mux.mkdir(mode=0o700)
    env['SSH_VAULT_MUX_PATH'] = str(mux / 'ctl')
    original = auth.read_bytes()

    result = backend(env, 'create', 'media', 'fake-unix', 'root', '22', 'keep')
    log = (stage / 'diag').read_text()
    assert result.returncode != 0
    assert 'DIAG: Remote account: ' in log, log
    assert 'DIAG: Permissions: ' in log, log
    assert 'DIAG: sshd authorizedkeysfile ' in log, log
    assert 'Permission denied (publickey,password,keyboard-interactive).' in log
    assert 'Revoked only the adopted SSH Vault entry' in log
    assert auth.read_bytes() == original
    assert not (stage/'priv'/'media').exists()
    assert not (stage/'pub'/'media.pub').exists()
    assert 'Host media' not in (stage/'config').read_text()
