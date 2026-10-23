"""Short-lived OpenSSH operations against the in-memory vault.

Interactive login: one dedicated ssh-agent with ONE identity; no private key file.
Administrative operations: a restricted, disposable temporary directory because
legacy ssh_backend.sh and ssh-keygen need a pathname for the private key.
"""
from __future__ import annotations

from contextlib import contextmanager
import copy
import os
from pathlib import Path
import re
import signal
import subprocess
import tempfile

from vault import (VaultError, VaultStore, b64, unb64, save_file,
                   parse_blocks, fields, identity_basename, validate_server,
                   verify_pair, FILE_RE)


def config_text(servers: dict) -> str:
    stanzas = []
    for alias, r in sorted(servers.items()):
        validate_server(r)
        stanzas.append(f'Host {alias}\n    HostName {r["host"]}\n'
                       f'    User {r["user"]}\n    Port {r["port"]}\n'
                       f'    IdentityFile keys/priv/{r["key_name"]}\n'
                       '    IdentitiesOnly yes\n')
    return '\n'.join(stanzas) + '\n'


def changed_payload(store: VaultStore, stage: Path) -> dict:
    """Re-read admin command output; reject partial/corrupt pairs."""
    updated = copy.deepcopy(store.data)
    existing = {}
    contents = (stage / 'config').read_text(encoding='utf-8')
    for alias, text in parse_blocks(contents):
        if not alias:
            continue
        opts = fields(text)
        name = identity_basename(opts.get('identityfile', ''))
        if not name:
            raise VaultError(f'No identity configured for {alias}')
        private = stage / 'priv' / name
        public = stage / 'pub' / (name + '.pub')
        if private.is_symlink() or public.is_symlink() or not private.is_file() or not public.is_file():
            raise VaultError(f'Incomplete staged identity: {alias}')
        priv_bytes, pub_bytes = private.read_bytes(), public.read_bytes()
        if not verify_pair(priv_bytes, pub_bytes):
            raise VaultError(f'Invalid staged identity: {alias}')
        record = {'host': opts['hostname'], 'user': opts['user'],
                  'port': str(opts['port']), 'key_name': name,
                  'private': b64(priv_bytes), 'public': b64(pub_bytes)}
        validate_server(record)
        if alias in existing:
            raise VaultError('Duplicate staged host alias')
        existing[alias] = record
    updated['servers'] = existing
    updated['known_hosts'] = (stage / 'known_hosts').read_text(encoding='utf-8')
    return updated


@contextmanager
def backend_stage(store: VaultStore):
    """Private admin credential files exist ONLY inside this context."""
    with tempfile.TemporaryDirectory(prefix='ssh-vault-admin-') as tmp:
        stage = Path(tmp)
        (stage / 'priv').mkdir(mode=0o700)
        (stage / 'pub').mkdir(mode=0o700)
        contents = {}
        for alias, rec in store.data['servers'].items():
            name = rec['key_name']
            pair = (unb64(rec['private']), unb64(rec['public']))
            if name in contents and contents[name] != pair:
                raise VaultError('Conflicting key filenames in vault')
            contents[name] = pair
        for name, (private, public) in contents.items():
            save_file(stage / 'priv' / name, private)
            save_file(stage / 'pub' / (name + '.pub'), public, 0o644)
        save_file(stage / 'config', config_text(store.data['servers']).encode())
        save_file(stage / 'known_hosts', store.data['known_hosts'].encode())
        yield stage


@contextmanager
def login_agent(private: bytes):
    """Only private key is streamed over stdin to ssh-add; never written."""
    with tempfile.TemporaryDirectory(prefix='ssh-vault-agent-') as tmp:
        sock = str(Path(tmp) / 'ssh-agent.sock')
        result = subprocess.run(['ssh-agent', '-s', '-a', sock],
                                capture_output=True, text=True, check=True)
        pid_match = re.search(r'SSH_AGENT_PID=(\d+)', result.stdout)
        if not pid_match:
            raise VaultError('ssh-agent did not provide a PID')
        pid = int(pid_match.group(1))
        env = os.environ.copy()
        env['SSH_AUTH_SOCK'] = sock
        env['SSH_AGENT_PID'] = str(pid)
        try:
            add = subprocess.run(['ssh-add', '-'], input=private,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=env, check=False)
            if add.returncode:
                raise VaultError('Could not load SSH identity into dedicated agent')
            yield env, Path(tmp)
        finally:
            try:
                subprocess.run(['ssh-agent', '-k'], env=env,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                               timeout=4, check=False)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    os.kill(pid, signal.SIGTERM)
                except (ProcessLookupError, PermissionError):
                    pass


def login_command(alias: str, rec: dict, agent_env: dict, public: Path, known: Path):
    return ['ssh', '-F', '/dev/null', '-o', 'GlobalKnownHostsFile=/dev/null',
            '-o', f'UserKnownHostsFile={known}',
            '-o', 'StrictHostKeyChecking=accept-new',
            '-o', 'UpdateHostKeys=no', '-o', 'LogLevel=ERROR',
            '-o', 'BatchMode=yes', '-o', 'PasswordAuthentication=no',
            '-o', 'KbdInteractiveAuthentication=no',
            '-o', 'PreferredAuthentications=publickey',
            '-o', 'IdentitiesOnly=yes',
            '-o', f'IdentityAgent={agent_env["SSH_AUTH_SOCK"]}',
            '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
            '-i', str(public), '-p', str(rec['port']),
            '-l', rec['user'], rec['host']]
