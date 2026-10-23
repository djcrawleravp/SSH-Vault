"""Behavioral tests for destructive import, idempotency, export, stage and safety.
Real KDBX crypto and OpenSSH require external dependencies and have separate tests.
"""
import base64
import copy
import json
import os
from pathlib import Path
import sys
import tempfile

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import vault
import session


def pair():
    p = Ed25519PrivateKey.generate()
    return (p.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.OpenSSH,
                            serialization.NoEncryption()),
            p.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                        serialization.PublicFormat.OpenSSH) + b' test-key\n')


def cryptographic_verify(priv, pub):
    try:
        from cryptography.hazmat.primitives.serialization import load_ssh_private_key
        p = load_ssh_private_key(priv, password=None)
        computed = p.public_key().public_bytes(serialization.Encoding.OpenSSH,
                                               serialization.PublicFormat.OpenSSH)
        return computed.split()[:2] == pub.split()[:2]
    except Exception:
        return False


class VerifiedStore:
    """Tests deliberately replace KDBX I/O but NOT import cleanup semantics."""
    def __init__(self, root):
        self.data = vault.data_default()
        self.root = root
        self.saved = 0
        self.backups = 0

    def save(self, data):
        self.data = copy.deepcopy(data)
        self.saved += 1

    def open(self):
        return None

    def backup_verified(self):
        self.backups += 1
        return self.root / 'verified.kdbx'


@pytest.fixture(autouse=True)
def public_match(monkeypatch):
    monkeypatch.setattr(vault, 'verify_pair', cryptographic_verify)
    monkeypatch.setattr(session, 'verify_pair', cryptographic_verify)


def add_pair(root, name, p=None):
    (root / 'priv').mkdir(exist_ok=True)
    (root / 'pub').mkdir(exist_ok=True)
    private, public = p or pair()
    (root / 'priv' / name).write_bytes(private)
    (root / 'pub' / (name + '.pub')).write_bytes(public)
    return private, public


def stanza(alias, name, host='10.0.0.10', user='root', port='22'):
    return (f'Host {alias}\n    HostName {host}\n    User {user}\n'
            f'    Port {port}\n    IdentityFile ~/.ssh/keys/priv/{name}\n'
            '    IdentitiesOnly yes\n')


def test_import_then_cleanup_orphans_and_unmatched_known_hosts(tmp_path):
    root = tmp_path / 'keys'; root.mkdir()
    add_pair(root, 'seafile-server')
    add_pair(root, 'orphan-key')
    (root / 'config').write_text(stanza('seafile', 'seafile-server'))
    (root / 'known_hosts').write_text('10.0.0.10 ssh-ed25519 VALID\notherhost ssh-ed25519 OTHER\n')
    st = VerifiedStore(tmp_path)
    r = vault.migrate(st, root)
    assert r['imported'] == ['seafile']
    assert r['removed_keys'] == ['seafile-server']
    assert st.data['servers']['seafile']['key_name'] == 'seafile-server'
    assert '10.0.0.10' in st.data['known_hosts']
    assert not (root / 'config').exists()
    assert not (root / 'priv' / 'seafile-server').exists()
    assert (root / 'priv' / 'orphan-key').exists()
    assert (root / 'pub' / 'orphan-key.pub').exists()
    assert (root / 'known_hosts').read_text() == 'otherhost ssh-ed25519 OTHER\n'
    assert st.backups == 1


def test_import_complete_removes_entire_keys_dir(tmp_path):
    root = tmp_path / 'keys'; root.mkdir()
    add_pair(root, 'alpha')
    (root / 'config').write_text(stanza('alpha', 'alpha'))
    (root / 'known_hosts').write_text('10.0.0.10 ssh-ed25519 VALID\n')
    st = VerifiedStore(tmp_path)
    vault.migrate(st, root)
    assert not root.exists()


def test_failed_pair_and_unrelated_entries_preserved(tmp_path):
    root = tmp_path / 'keys'; root.mkdir()
    add_pair(root, 'bad')
    (root / 'pub' / 'bad.pub').write_bytes(pair()[1])
    (root / 'config').write_text(stanza('bad', 'bad'))
    (root / 'known_hosts').write_text('')
    st = VerifiedStore(tmp_path)
    r = vault.migrate(st, root)
    assert not r['imported']
    assert st.saved == st.backups == 0
    assert (root / 'config').exists()
    assert (root / 'priv' / 'bad').exists()


def test_existing_equal_import_is_idempotent_and_cleans(tmp_path):
    root = tmp_path / 'keys'; root.mkdir()
    pvt, pub = add_pair(root, 'shared')
    (root / 'config').write_text(stanza('alpha', 'shared'))
    st = VerifiedStore(tmp_path)
    st.data['servers']['alpha'] = {'host': '10.0.0.10', 'user': 'root',
        'port': '22', 'key_name': 'shared', 'private': vault.b64(pvt), 'public': vault.b64(pub)}
    r = vault.migrate(st, root)
    assert r['duplicates'] == ['alpha'] and not r['imported']
    assert not root.exists()


def test_conflicting_duplicate_remains_untouched(tmp_path):
    root = tmp_path / 'keys'; root.mkdir()
    add_pair(root, 'alpha')
    (root / 'config').write_text(stanza('alpha', 'alpha'))
    st = VerifiedStore(tmp_path)
    st.data['servers']['alpha'] = {'host': '10.0.0.11', 'user': 'root',
        'port': '22', 'key_name': 'alpha',
        'private': vault.b64(pair()[0]), 'public': vault.b64(pair()[1])}
    r = vault.migrate(st, root)
    assert r['problems'] and (root / 'config').exists()
    assert (root / 'priv' / 'alpha').exists()
    assert st.backups == 0


def test_shared_key_preserved_for_unresolved_connection(tmp_path):
    root = tmp_path / 'keys'; root.mkdir()
    add_pair(root, 'shared')
    (root / 'config').write_text(stanza('alpha', 'shared') +
                                 stanza('broken', 'shared', user='bad@name'))
    st = VerifiedStore(tmp_path)
    r = vault.migrate(st, root)
    assert 'alpha' in r['imported']
    assert (root / 'priv' / 'shared').exists()
    assert 'Host broken' in (root / 'config').read_text()
    assert 'Host alpha' not in (root / 'config').read_text()


def test_repeated_alias_untouched(tmp_path):
    root = tmp_path / 'keys'; root.mkdir()
    add_pair(root, 'alpha')
    (root / 'config').write_text(stanza('alpha','alpha') + stanza('alpha','alpha'))
    st = VerifiedStore(tmp_path)
    r = vault.migrate(st, root)
    assert not r['imported'] and not r['removed_keys']
    assert (root / 'config').read_text().count('Host alpha') == 2


def test_export_new_dir_never_overwrites(tmp_path):
    st = VerifiedStore(tmp_path)
    pri, pub = pair()
    st.data['servers']['alpha'] = {'host': 'host.example', 'user': 'root', 'port': '22',
         'key_name': 'alpha', 'private': vault.b64(pri), 'public': vault.b64(pub)}
    one = vault.export_vault(st, tmp_path)
    two = vault.export_vault(st, tmp_path)
    assert one != two and one.exists() and two.exists()
    assert (one / 'priv' / 'alpha').read_bytes() == pri
    assert (two / 'config').read_text().startswith('Host alpha')
    assert not (tmp_path / 'keys').exists()
    assert os.stat(one / 'priv' / 'alpha').st_mode & 0o077 == 0


def test_backend_stage_changes_and_no_persistent_private(tmp_path):
    st = VerifiedStore(tmp_path)
    pri, pub = pair()
    st.data['servers']['alpha'] = {'host':'old.example','user':'root','port':'22',
        'key_name':'alpha','private':vault.b64(pri),'public':vault.b64(pub)}
    with session.backend_stage(st) as directory:
        (directory / 'config').write_text(session.config_text(st.data['servers']).replace('old.example','new.example'))
        new = session.changed_payload(st, directory)
        assert new['servers']['alpha']['host'] == 'new.example'
        assert (directory / 'priv' / 'alpha').exists()
    assert not directory.exists()
    assert st.data['servers']['alpha']['host'] == 'old.example'


def test_migration_failure_to_backup_keeps_files(tmp_path):
    root = tmp_path / 'keys'; root.mkdir()
    add_pair(root, 'alpha')
    (root / 'config').write_text(stanza('alpha','alpha'))
    st = VerifiedStore(tmp_path)
    def broken_backup():
        raise vault.VaultError('backup failed')
    st.backup_verified = broken_backup
    with pytest.raises(vault.VaultError):
        vault.migrate(st, root)
    assert (root / 'config').exists()
    assert (root / 'priv' / 'alpha').exists()


def test_ssh_login_never_references_home_ssh(tmp_path):
    rec = {'host':'somehost','user':'alice','port':'22','key_name':'x'}
    cmd = session.login_command('x', rec, {'SSH_AUTH_SOCK':'/tmp/sock'},
                                tmp_path/'identity.pub', tmp_path/'known_hosts')
    assert cmd[:3] == ['ssh','-F','/dev/null']
    assert 'GlobalKnownHostsFile=/dev/null' in cmd
    assert 'IdentityAgent=/tmp/sock' in cmd
    assert 'PasswordAuthentication=no' in cmd
    assert '~/.ssh' not in ' '.join(cmd)


def test_unsupported_ssh_directive_preserved(tmp_path):
    root=tmp_path/'keys';root.mkdir()
    add_pair(root,'alpha')
    (root/'config').write_text(stanza('alpha','alpha')+'    ProxyJump jumphost\n')
    st=VerifiedStore(tmp_path)
    rep=vault.migrate(st,root)
    assert rep['problems'] and (root/'priv'/'alpha').exists()
    assert st.data['servers']=={}


def test_unmanaged_host_key_references_prevent_key_removal(tmp_path):
    root=tmp_path/'keys';root.mkdir()
    add_pair(root,'alpha')
    (root/'config').write_text(stanza('alpha','alpha')+\
        'Host *.example.org\n    IdentityFile keys/priv/alpha\n')
    st=VerifiedStore(tmp_path)
    rep=vault.migrate(st,root)
    assert rep['imported']==['alpha']
    assert (root/'priv'/'alpha').exists()


def test_empty_inbox_without_config_is_removed(tmp_path):
    root=tmp_path/'keys';root.mkdir()
    (root/'priv').mkdir()
    (root/'pub').mkdir()
    (root/'known_hosts').write_bytes(b'')
    vault.migrate(VerifiedStore(tmp_path),root)
    assert not root.exists()


def test_orphan_only_without_config_is_preserved(tmp_path):
    root=tmp_path/'keys';root.mkdir()
    add_pair(root,'orphan')
    vault.migrate(VerifiedStore(tmp_path),root)
    assert (root/'priv'/'orphan').exists()


def test_ds_store_metadata_is_ignored_then_cleaned_only_when_empty(tmp_path):
    root=tmp_path/'keys'; root.mkdir()
    add_pair(root,'alpha')
    (root/'config').write_text(stanza('alpha','alpha'))
    for directory in (root,root/'priv',root/'pub'):
        (directory/'.DS_Store').write_bytes(b'Finder metadata')
    st=VerifiedStore(tmp_path)
    result=vault.migrate(st,root)
    assert result['imported']==['alpha']
    assert not root.exists()


def test_other_hidden_files_are_preserved(tmp_path):
    root=tmp_path/'keys'; root.mkdir()
    add_pair(root,'alpha')
    (root/'config').write_text(stanza('alpha','alpha'))
    (root/'.DS_Store').write_bytes(b'Finder metadata')
    (root/'.important-secret').write_text('do not delete')
    st=VerifiedStore(tmp_path)
    vault.migrate(st,root)
    assert (root/'.DS_Store').exists()
    assert (root/'.important-secret').read_text()=='do not delete'
