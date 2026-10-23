"""Offline backend integration using executable OpenSSH test doubles.

These confirm portable staging, error reporting and partial commits. Actual
remote sshd/pam behavior still requires a real integration environment.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import session
import vault

BACKEND = Path(__file__).resolve().parents[1] / 'ssh_backend.sh'

SSH_STUB = '''#!/usr/bin/env python3
import sys, os, re, base64
from pathlib import Path
args = sys.argv[1:]
if '-G' in args:
    path = Path(args[args.index('-F')+1])
    text = path.read_text()
    vals = dict((k.lower(), v) for k,v in re.findall(r'^\\s*(HostName|User|Port|IdentityFile)\\s+(.*?)\\s*$', text, re.M))
    for key,default in [('hostname',args[-1]),('user','root'),('port','22'),('identityfile','')]:
        print(key, vals.get(key, default))
    sys.exit(0)
if '-O' in args:
    sys.exit(0)
if os.getenv('FAKE_SSH_MODE') == 'deny':
    print('Permission denied (publickey,password).', file=sys.stderr)
    sys.exit(255)
if os.getenv('FAKE_SSH_MODE') == 'policyfail':
    try:
        encoded = re.findall("'([^']+)'", args[-1])[-1]
        text = base64.b64decode(encoded).decode()
        if 'systemd-run' in text:
            print('Remote sshd policy validation failed (simulated).', file=sys.stderr)
            sys.exit(1)
    except Exception:
        pass
sys.exit(0)
'''

KEYGEN_STUB = '''#!/usr/bin/env python3
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption, PublicFormat, load_ssh_private_key)
a = sys.argv[1:]
path = Path(a[a.index('-f') + 1])
if '-y' in a:
    k = load_ssh_private_key(path.read_bytes(), password=None)
    print(k.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode())
else:
    key = Ed25519PrivateKey.generate()
    path.write_bytes(key.private_bytes(Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()))
    path.chmod(0o600)
    comment = a[a.index('-C') + 1] if '-C' in a else ''
    path.with_name(path.name + '.pub').write_bytes(
        key.public_key().public_bytes(Encoding.OpenSSH,PublicFormat.OpenSSH) + (' '+comment+'\\n').encode())
'''


@pytest.fixture
def fake_tools(tmp_path):
    bin_dir = tmp_path / 'bin'
    bin_dir.mkdir()
    for name, script in [('ssh', SSH_STUB), ('ssh-keygen', KEYGEN_STUB)]:
        path = bin_dir / name
        path.write_text(script)
        path.chmod(0o755)
    env = os.environ.copy()
    env['PATH'] = str(bin_dir) + os.pathsep + env.get('PATH','')
    return env


def do_backend(tmp_path, env, mode='keep'):
    stage = tmp_path / 'staged'
    stage.mkdir()
    for folder in ('priv', 'pub'):
        (stage/folder).mkdir()
    (stage/'config').write_text('')
    (stage/'known_hosts').write_text('')
    diag = stage/'diag'
    diag.write_text('')
    env = {**env, 'SSH_VAULT_WORKDIR':str(stage), 'SSH_VAULT_DIAGNOSTIC_FILE':str(diag)}
    # Symlinked project root is not used; all writable files are in a temporary area.
    result = subprocess.run(['bash',str(BACKEND),'create','alpha','test.example','root','22',mode],
                           env=env, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=30)
    return stage, result, diag.read_text()


def test_new_connection_success_and_verified_staging(tmp_path, fake_tools, monkeypatch):
    stage, result, diagnostic = do_backend(tmp_path, fake_tools)
    assert result.returncode == 0, (result.stdout, result.stderr, diagnostic)
    assert (stage/'priv'/'alpha').is_file()
    assert (stage/'pub'/'alpha.pub').is_file()
    assert 'Host alpha' in (stage/'config').read_text()
    # Isolated ephemeral staging can be loaded as a vault record and verified
    monkeypatch.setenv('PATH', fake_tools['PATH'])
    class Store:
        data = vault.data_default()
    record = session.changed_payload(Store(), stage)['servers']['alpha']
    assert record['host'] == 'test.example'
    assert record['user'] == 'root'


def test_failed_new_connection_reports_cause_and_writes_no_keys(tmp_path, fake_tools):
    fake_tools['FAKE_SSH_MODE'] = 'deny'
    stage, result, details = do_backend(tmp_path, fake_tools)
    assert result.returncode != 0
    assert 'Permission denied' in details
    assert 'authorization' in details.lower()
    assert not (stage/'priv'/'alpha').exists()
    assert 'Host alpha' not in (stage/'config').read_text()


def test_optional_password_policy_failure_preserves_new_verified_key(tmp_path, fake_tools, monkeypatch):
    fake_tools['FAKE_SSH_MODE'] = 'policyfail'
    stage, result, details = do_backend(tmp_path, fake_tools, mode='no')
    assert result.returncode == 1, (result.stdout, result.stderr, details)
    assert (stage/'priv'/'alpha').is_file()
    assert 'Host alpha' in (stage/'config').read_text()
    monkeypatch.setenv('PATH', fake_tools['PATH'])
    class Store:
        data = vault.data_default()
    assert 'alpha' in session.changed_payload(Store(), stage)['servers']
    assert 'password login' in details.lower() or 'sshd' in details.lower()
