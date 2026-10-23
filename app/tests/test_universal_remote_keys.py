"""Portable OpenSSH keys integration against a private fake server HOME.

The actual POSIX remote key script executes; no system SSH config or real
remote host is modified. Supplement with real target tests before rollout.
"""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from test_new_connection_regressions import KEYGEN_STUB

APP = Path(__file__).resolve().parents[1]
BACKEND = APP / 'ssh_backend.sh'
HELPER = APP / 'remote_authorized_keys.sh'

FAKE_SSH = r'''#!/usr/bin/env python3
import sys, os, subprocess, re, base64
from pathlib import Path
args = sys.argv[1:]
if '-G' in args:
    cfg = Path(args[args.index('-F') + 1]).read_text()
    d = dict((k.lower(), v) for k,v in re.findall(r'^\s*(HostName|User|Port|IdentityFile)\s+(.*?)\s*$', cfg, re.M))
    for k,default in [('hostname','fake-unix'),('user','root'),('port','22'),('identityfile','')]:
        print(k, d.get(k,default))
    sys.exit(0)
if '-O' in args: sys.exit(0)
remote = args[-1]
match = re.fullmatch(r"printf '%s' '([A-Za-z0-9+/=]+)' \| base64 -d \| (?:sh|bash)", remote)
if match:
    body = base64.b64decode(match.group(1)).decode()
    env = os.environ.copy()
    env['HOME'] = os.environ['FAKE_HOME']
    env['SSH_CONNECTION'] = '127.0.0.1 50000 127.0.0.1 22'
    p = subprocess.run(['/bin/sh' if remote.endswith('| sh') else '/bin/bash','-c',body], env=env)
    sys.exit(p.returncode)
if '-T' in args:
    identity=Path(args[args.index('-i')+1])
    pubpath=Path(str(identity)+'.pub')
    if not pubpath.is_file(): pubpath=Path(os.environ['SSH_VAULT_WORKDIR'])/'pub'/(identity.name+'.pub')
    pub=pubpath.read_text().split()
    cfg=os.getenv('FAKE_SSH_AUTH_FILE', '')
    if cfg:
        file=Path(cfg)
    else:
        file=Path(os.environ['FAKE_HOME'])/'.ssh'/'authorized_keys'
    if not file.is_file(): sys.exit(255)
    lines=file.read_text().splitlines()
    if any(any(words[i:i+2]==pub[:2] for i in range(max(0,len(words)-1))) for words in (l.split() for l in lines) if words and not words[0].startswith('#')): sys.exit(0)
    print('Permission denied (publickey).', file=sys.stderr)
    sys.exit(255)
print('Unexpected SSH arguments', repr(args), file=sys.stderr)
sys.exit(2)
'''

FAKE_SSHD = r'''#!/bin/sh
[ "$1" = -T ] || exit 1
case "$TEST_AUTH_MODE" in
 custom) echo 'authorizedkeysfile .ssh/keyfile' ;;
 none) echo 'authorizedkeysfile none'; echo 'authorizedkeyscommand /usr/local/bin/keys-provider' ;;
 multiple) echo 'authorizedkeysfile .ssh/keyfile .ssh/authorized_keys' ;;
 *) echo 'authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2' ;;
esac
'''


def fixture_env(tmp_path, linked=False, custom=False, mode=None):
    home = tmp_path / 'home'
    (home / '.ssh').mkdir(parents=True)
    auth = home / '.ssh' / ('keyfile' if custom else 'authorized_keys')
    if linked:
        auth = tmp_path / 'cluster-auth'
        auth.write_text('ssh-ed25519 OTHER_BLOB unrelated-entry\n')
        auth.chmod(0o640)
        (home / '.ssh' / 'authorized_keys').symlink_to(auth)
    else:
        auth.write_text('ssh-ed25519 OTHER_BLOB unrelated-entry\n')
        auth.chmod(0o600)
    bin_path=tmp_path/'bin'; bin_path.mkdir()
    for name, code in [('ssh',FAKE_SSH), ('ssh-keygen',KEYGEN_STUB), ('sshd',FAKE_SSHD)]:
        target=bin_path/name; target.write_text(code); target.chmod(0o755)
    stage=tmp_path/'stage'; stage.mkdir()
    (stage/'priv').mkdir(); (stage/'pub').mkdir()
    (stage/'config').write_text(''); (stage/'known_hosts').write_text('')
    (stage/'diag').write_text('')
    env=os.environ.copy()
    env.update(PATH=str(bin_path)+os.pathsep+env.get('PATH',''),
               FAKE_HOME=str(home), FAKE_SSH_AUTH_FILE=str(auth),
               SSH_VAULT_WORKDIR=str(stage), SSH_VAULT_DIAGNOSTIC_FILE=str(stage/'diag'),
               TEST_AUTH_MODE=mode or ('custom' if custom else 'standard'))
    return home, auth, stage, env


def backend(env, *args):
    return subprocess.run(['bash',str(BACKEND),*args], env=env, capture_output=True, text=True, timeout=30)


def test_symlink_creation_preserves_unrelated_keys(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path, linked=True)
    result=backend(env, 'create', 'solid', 'fake-unix', 'root', '22', 'keep')
    assert result.returncode == 0, (result.stdout,result.stderr,(stage/'diag').read_text())
    assert auth.read_text().startswith('ssh-ed25519 OTHER_BLOB unrelated-entry\n')
    assert auth.read_text().count('ssh-vault-managed-solid') == 1
    assert (home/'.ssh'/'authorized_keys').is_symlink()
    assert (auth.stat().st_mode & 0o777) == 0o640


def test_symlink_revocation_removes_only_owned_line(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path, linked=True)
    assert backend(env, 'create','solid','fake-unix','root','22','keep').returncode == 0
    result=backend(env, 'delete','solid','keep_password')
    assert result.returncode == 0,(result.stdout,result.stderr,(stage/'diag').read_text())
    assert auth.read_text() == 'ssh-ed25519 OTHER_BLOB unrelated-entry\n'
    assert (home/'.ssh'/'authorized_keys').is_symlink()
    assert (auth.stat().st_mode & 0o777) == 0o640


def test_custom_authorized_keysfile_from_sshd(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path, custom=True)
    result=backend(env, 'create','custom','fake-unix','root','22','keep')
    assert result.returncode == 0,(result.stdout,result.stderr,(stage/'diag').read_text())
    assert 'ssh-vault-managed-custom' in auth.read_text()
    assert not (home/'.ssh'/'authorized_keys').exists()


def test_no_authorizedkeysfile_rejected_without_changes(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path, mode='none')
    before=auth.read_bytes()
    result=backend(env, 'create','alpha','fake-unix','root','22','keep')
    assert result.returncode != 0
    assert auth.read_bytes() == before
    assert not (stage/'priv'/'alpha').exists()


def test_unmarked_legacy_key_never_revoked(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path)
    (stage/'config').write_text('Host old\n    HostName fake-unix\n    User root\n    Port 22\n    IdentityFile keys/priv/old\n')
    (stage/'priv'/'old').write_text('placeholder')
    (stage/'pub'/'old.pub').write_text('ssh-ed25519 AAAAAold original-comment\n')
    before=auth.read_bytes()
    result=backend(env, 'delete','old','keep_password')
    assert result.returncode != 0
    assert auth.read_bytes()==before
    assert 'Host old' in (stage/'config').read_text()


def test_no_partial_deletion_for_substring_occurrence(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path)
    auth.write_text('ssh-ed25519 OTHER_BLOB unrelated-entry\n# token ssh-vault-managed-alpha in comment\n')
    before=auth.read_bytes()
    result = subprocess.run(['/bin/sh',str(HELPER)],env={**env,'HOME':str(home),
        'VAULT_ACTION':'remove','VAULT_TYPE':'ssh-ed25519','VAULT_BLOB':'AAAAgoodblob',
        'VAULT_MARKER':'ssh-vault-managed-alpha'},capture_output=True,text=True)
    assert result.returncode != 0
    assert auth.read_bytes()==before


def test_existing_identical_key_in_other_file_not_duplicated(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path, mode='multiple')
    # A managed key that already exists in the second AuthorizedKeysFile
    # should not be enrolled a second time into the first.
    key='ssh-ed25519 AAAAAalready ssh-vault-managed-alpha\n'
    auth.write_text('ssh-ed25519 OTHER_BLOB unrelated-entry\n'+key)
    first=home/'.ssh'/'keyfile'; first.write_text('ssh-ed25519 FIRST_OTHER another\n')
    payload = {**env, 'HOME':str(home), 'VAULT_ACTION':'add',
               'VAULT_TYPE':'ssh-ed25519', 'VAULT_BLOB':'AAAAAalready',
               'VAULT_MARKER':'ssh-vault-managed-alpha'}
    result=subprocess.run(['/bin/sh',str(HELPER)], env=payload,
                          capture_output=True,text=True)
    assert result.returncode == 0, (result.stdout,result.stderr)
    assert first.read_text()=='ssh-ed25519 FIRST_OTHER another\n'
    assert auth.read_text().count(key)==1


def test_unrecognized_hidden_file_does_not_get_processed_as_public_key(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path)
    before=auth.read_bytes()
    payload={**env, 'HOME':str(home),'VAULT_ACTION':'remove',
             'VAULT_TYPE':'ssh-ed25519', 'VAULT_BLOB':'BBBBexample',
             'VAULT_MARKER':'ssh-vault-managed-alpha'}
    result=subprocess.run(['/bin/sh',str(HELPER)],env=payload,capture_output=True,text=True)
    assert result.returncode != 0
    assert auth.read_bytes()==before


def test_relative_symlink_supported_without_replacing_it(tmp_path):
    home,auth,stage,env=fixture_env(tmp_path)
    original=auth.read_bytes()
    auth.rename(home/'.ssh'/'keys-shared')
    symlink=home/'.ssh'/'authorized_keys'
    symlink.symlink_to('keys-shared')
    env['FAKE_SSH_AUTH_FILE']=str(symlink)
    create=backend(env,'create','rel','fake-unix','root','22','keep')
    assert create.returncode==0,(create.stdout,create.stderr,(stage/'diag').read_text())
    assert symlink.is_symlink()
    assert (home/'.ssh'/'keys-shared').read_bytes().startswith(original)
    delete=backend(env,'delete','rel','keep_password')
    assert delete.returncode==0,(delete.stdout,delete.stderr,(stage/'diag').read_text())
    assert symlink.is_symlink()
    assert (home/'.ssh'/'keys-shared').read_bytes()==original


def test_legacy_unmarked_deletion_refuses_before_password_change(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path)
    (stage/'config').write_text('Host old\n    HostName fake-unix\n    User root\n    Port 22\n    IdentityFile keys/priv/old\n')
    (stage/'priv'/'old').write_text('placeholder')
    (stage/'pub'/'old.pub').write_text('ssh-ed25519 AAAAAold original-comment\n')
    before = auth.read_bytes()
    result = backend(env, 'delete', 'old', 'enable_password')
    assert result.returncode != 0
    assert auth.read_bytes() == before
    assert 'Host old' in (stage/'config').read_text()
    diagnostic = (stage/'diag').read_text()
    assert 'sshd password settings were not changed' in diagnostic


def test_first_enrollment_creates_ssh_dir_when_missing(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path)
    auth.unlink()
    (home / '.ssh').rmdir()
    outcome=backend(env, 'create', 'fresh', 'fake-unix', 'root', '22', 'keep')
    assert outcome.returncode == 0, (outcome.stdout, outcome.stderr)
    assert auth.is_file()
    assert auth.stat().st_mode & 0o777 == 0o600
    assert (home / '.ssh').stat().st_mode & 0o777 == 0o700
    assert 'ssh-vault-managed-fresh' in auth.read_text()
