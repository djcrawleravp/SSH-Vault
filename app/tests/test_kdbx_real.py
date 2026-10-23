"""These tests run end-to-end only when the optional KDBX dependency exists."""
import sys
from pathlib import Path
import pytest

pytest.importorskip('pykeepass')
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from vault import VaultStore, VaultError


def test_kdbx4_argon2id_create_roundtrip_and_rekey(tmp_path):
    db=tmp_path/'vault.kdbx'
    store=VaultStore('initial-secret-at-least-twelve',db)
    store.create()
    assert db.is_file()
    assert db.read_bytes().startswith(b'\x03\xd9\xa2\x9a')
    store.open()
    assert store.data['servers']=={}
    new=store.data.copy()
    new['last_user']='tester'
    store.save(new)
    again=VaultStore('initial-secret-at-least-twelve',db)
    again.open()
    assert again.data['last_user']=='tester'
    store.change_password('another-secret-at-least-twelve')
    with pytest.raises(Exception):
        VaultStore('initial-secret-at-least-twelve',db).open()
    VaultStore('another-secret-at-least-twelve',db).open()
