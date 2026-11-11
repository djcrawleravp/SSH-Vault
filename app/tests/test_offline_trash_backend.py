"""Offline backend guards: a trashed alias still owns its name, key file and identity."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys

APP = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(APP))
import session  # noqa: E402
import vault  # noqa: E402

BACKEND = APP / 'ssh_backend.sh'
MOMENT = datetime(2024, 1, 1, tzinfo=timezone.utc)


def keypair(directory: Path, name: str) -> dict:
    subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '',
                    '-C', f'ssh-vault-managed-{name}', '-f', str(directory / name)],
                   check=True)
    return {'host': '127.0.0.1', 'user': 'root', 'port': '1', 'key_name': name,
            'private': vault.b64((directory / name).read_bytes()),
            'public': vault.b64((directory / (name + '.pub')).read_bytes())}


def run_backend(stage: Path, *args: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, SSH_VAULT_WORKDIR=str(stage),
               SSH_VAULT_DIAGNOSTIC_FILE=str(stage / 'diagnostic.txt'))
    return subprocess.run(['bash', str(BACKEND), *args], env=env,
                          capture_output=True, text=True, timeout=60)


def canonical(data: dict) -> str:
    return json.dumps(data, sort_keys=True)


def setup(tmp_path: Path, trashed_alias: str = 'T'):
    keys = tmp_path / 'keys'
    keys.mkdir()
    data = vault.data_default()
    data['servers'] = {'A': keypair(keys, 'A'), 'T': keypair(keys, 'T')}
    data['servers'][trashed_alias] = vault.trash_record(
        data, trashed_alias, moment=MOMENT)['servers'][trashed_alias]
    return type('Store', (), {'data': data})()


def test_trashed_alias_still_blocks_create(tmp_path):
    store = setup(tmp_path)
    with session.backend_stage(store) as stage:
        result = run_backend(stage, 'create', 'T', '127.0.0.1', 'root', '1', 'keep', 'normal')
        assert result.returncode == 1
        assert 'Alias or key file already exists' in result.stdout + result.stderr
        updated = session.changed_payload(store, stage)
    assert canonical(updated) == canonical(store.data)
    assert vault.is_trashed(updated['servers']['T'])


def test_trashed_alias_still_blocks_rename_target(tmp_path):
    store = setup(tmp_path)
    with session.backend_stage(store) as stage:
        result = run_backend(stage, 'rename', 'A', 'T')
        assert result.returncode == 1
        updated = session.changed_payload(store, stage)
    assert canonical(updated) == canonical(store.data)


def test_rename_of_active_keeps_trashed_record_trashed(tmp_path):
    store = setup(tmp_path)
    with session.backend_stage(store) as stage:
        result = run_backend(stage, 'rename', 'A', 'X')
        assert result.returncode == 0, result.stdout + result.stderr
        updated = session.changed_payload(store, stage)
    assert set(updated['servers']) == {'T', 'X'}
    assert vault.is_trashed(updated['servers']['T'])
    assert updated['servers']['T']['trashed_utc'] == '2024-01-01T00:00:00Z'
    assert not vault.is_trashed(updated['servers']['X'])


def test_failed_offline_delete_leaves_trash_and_identity_untouched(tmp_path):
    """S1 path: an unreachable host must fail closed and keep every record."""
    store = setup(tmp_path)
    with session.backend_stage(store) as stage:
        result = run_backend(stage, 'delete', 'A', 'keep_password')
        assert result.returncode == 1
        assert 'Nothing deleted' in result.stdout + result.stderr
        assert (stage / 'priv' / 'A').exists()
        updated = session.changed_payload(store, stage)
    assert canonical(updated) == canonical(store.data)
