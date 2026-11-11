"""Offline revocation trash: lifecycle fields, expiry by stored time, purge rules."""
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pytest

import session
import vault

MOMENT = datetime(2024, 1, 1, tzinfo=timezone.utc)
STAMP = '2024-01-01T00:00:00Z'


def record(**over):
    rec = {'host': 'example.com', 'user': 'root', 'port': '22',
           'key_name': 'a_key', 'private': vault.b64(b'private-bytes'),
           'public': vault.b64(b'public-bytes')}
    rec.update(over)
    return rec


def payload(**servers):
    data = vault.data_default()
    data['servers'] = servers or {'a': record()}
    return data


def days_later(count):
    return MOMENT + timedelta(days=count)


# --- S1/S2: trashing hides without destroying -------------------------------

def test_trash_hides_record_but_keeps_key_material():
    data = payload()
    updated = vault.trash_record(data, 'a', moment=MOMENT)
    stored = updated['servers']['a']
    assert stored['status'] == 'trashed'
    assert stored['trashed_utc'] == STAMP
    assert stored['private'] == data['servers']['a']['private']
    assert stored['public'] == data['servers']['a']['public']
    assert vault.active_records(updated['servers']) == {}
    assert list(vault.trashed_records(updated['servers'])) == ['a']


def test_trash_does_not_mutate_the_caller_payload():
    data = payload()
    vault.trash_record(data, 'a', moment=MOMENT)
    assert 'status' not in data['servers']['a']


def test_trashing_twice_keeps_the_first_timestamp():
    once = vault.trash_record(payload(), 'a', moment=MOMENT)
    twice = vault.trash_record(once, 'a', moment=days_later(3))
    assert twice['servers']['a']['trashed_utc'] == STAMP


def test_trash_rejects_unknown_alias():
    with pytest.raises(vault.VaultError):
        vault.trash_record(payload(), 'missing', moment=MOMENT)


# --- S3: restore ------------------------------------------------------------

def test_restore_returns_record_to_the_active_list():
    trashed = vault.trash_record(payload(), 'a', moment=MOMENT)
    restored = vault.restore_record(trashed, 'a')
    stored = restored['servers']['a']
    assert vault.is_trashed(stored) is False
    assert 'trashed_utc' not in stored
    assert list(vault.active_records(restored['servers'])) == ['a']


def test_restore_preserves_the_identity_exactly():
    trashed = vault.trash_record(payload(), 'a', moment=MOMENT)
    restored = vault.restore_record(trashed, 'a')
    original = payload()['servers']['a']
    assert restored['servers']['a'] == original


def test_restore_of_an_active_record_is_a_no_op():
    data = payload()
    assert vault.restore_record(data, 'a') == data


# --- S5: purge is explicit --------------------------------------------------

def test_purge_removes_the_record_entirely():
    trashed = vault.trash_record(payload(), 'a', moment=MOMENT)
    purged = vault.purge_record(trashed, 'a')
    assert purged['servers'] == {}
    assert 'a' in trashed['servers']


def test_purge_refuses_a_connection_that_is_not_trashed():
    with pytest.raises(vault.VaultError):
        vault.purge_record(payload(), 'a')


# --- S4: expiry is derived from the stored timestamp ------------------------

def test_record_expires_after_thirty_days():
    trashed = vault.trash_record(payload(), 'a', moment=MOMENT)
    assert vault.expired_records(trashed, moment=days_later(31)) != {}
    assert vault.expired_records(trashed, moment=days_later(30)) != {}


def test_record_does_not_expire_before_the_window():
    trashed = vault.trash_record(payload(), 'a', moment=MOMENT)
    assert vault.expired_records(trashed, moment=days_later(29)) == {}


def test_active_record_never_expires():
    data = payload()
    assert vault.expired_records(data, moment=days_later(4000)) == {}


# --- S6: a wrong clock never destroys a record ------------------------------

def test_clock_behind_the_trash_timestamp_is_not_expired():
    trashed = vault.trash_record(payload(), 'a', moment=MOMENT)
    before = MOMENT - timedelta(days=800)
    assert vault.expired_records(trashed, moment=before) == {}


def test_unreadable_trash_timestamp_is_never_expired():
    data = payload(a=record(status='trashed', trashed_utc='not-a-timestamp'))
    assert vault.expired_records(data, moment=days_later(9999)) == {}


# --- S8: format stays version 1 and older records keep working -------------

def test_legacy_record_without_lifecycle_fields_is_active():
    rec = record()
    vault.validate_server(rec)
    assert vault.is_trashed(rec) is False
    assert vault.active_records({'a': rec}) == {'a': rec}


def test_validation_accepts_a_trashed_record():
    vault.validate_server(record(status='trashed', trashed_utc=STAMP))


def test_validation_rejects_an_unknown_status():
    with pytest.raises(vault.VaultError):
        vault.validate_server(record(status='deleted', trashed_utc=STAMP))


def test_validation_rejects_a_trashed_record_without_timestamp():
    with pytest.raises(vault.VaultError):
        vault.validate_server(record(status='trashed'))


def test_vault_schema_version_is_unchanged():
    assert vault.data_default()['version'] == 1
    assert payload()['version'] == 1


# --- S1: the staged config round-trip must carry lifecycle fields ----------

def test_carry_lifecycle_preserves_trash_state():
    previous = record(status='trashed', trashed_utc=STAMP)
    fresh = record()
    merged = session.carry_lifecycle(fresh, previous)
    assert merged['status'] == 'trashed'
    assert merged['trashed_utc'] == STAMP
    assert merged['host'] == 'example.com'


def test_carry_lifecycle_leaves_a_known_active_record_active():
    assert 'status' not in session.carry_lifecycle(record(), record())


def test_carry_lifecycle_ignores_absence():
    assert session.carry_lifecycle(record(), {}) == record()


def test_changed_payload_keeps_trashed_entries(tmp_path, monkeypatch):
    """The staged config is the only source of servers; lifecycle must survive it."""
    monkeypatch.setattr(session, 'verify_pair', lambda *a: True)
    trashed = vault.trash_record(payload(), 'a', moment=MOMENT)
    stage = tmp_path
    (stage / 'priv').mkdir()
    (stage / 'pub').mkdir()
    (stage / 'priv' / 'a_key').write_bytes(b'private-bytes')
    (stage / 'pub' / 'a_key.pub').write_bytes(b'public-bytes')
    (stage / 'config').write_text(
        'Host a\n    HostName example.com\n    User root\n    Port 22\n'
        '    IdentityFile keys/priv/a_key\n    IdentitiesOnly yes\n')
    (stage / 'known_hosts').write_text('')
    store = type('Store', (), {'data': trashed})()
    updated = session.changed_payload(store, stage)
    assert updated['servers']['a']['status'] == 'trashed'
    assert updated['servers']['a']['trashed_utc'] == STAMP
    vault.validate_server(updated['servers']['a'])


# --- S5: a trashed identity must not leak into the plaintext export --------

def test_export_skips_trashed_identities(tmp_path, monkeypatch):
    monkeypatch.setattr(vault, 'verify_pair', lambda *a: True)
    data = payload(a=record(status='trashed', trashed_utc=STAMP),
                   b=record(key_name='b_key'))
    store = type('Store', (), {'data': data})()
    target = vault.export_vault(store, root=tmp_path)
    config = (target / 'config').read_text(encoding='utf-8')
    assert 'Host b' in config
    assert 'Host a' not in config
    assert not (target / 'priv' / 'a_key').exists()
    assert (target / 'priv' / 'b_key').exists()


# --- S2/S8: the real KDBX round trip must keep the lifecycle state ---------

def test_real_kdbx_roundtrip_keeps_trash_state(tmp_path):
    pytest.importorskip('pykeepass')
    path = tmp_path / 'vault.kdbx'
    store = vault.VaultStore('correct horse battery staple', path=path)
    store.create()
    store.open()
    trashed = vault.trash_record(payload(), 'a', moment=MOMENT)
    store.save(trashed)

    reopened = vault.VaultStore('correct horse battery staple', path=path)
    reopened.open()
    assert reopened.data['version'] == 1
    stored = reopened.data['servers']['a']
    assert stored['status'] == 'trashed'
    assert stored['trashed_utc'] == STAMP
    assert stored['private'] == trashed['servers']['a']['private']
    assert vault.expired_records(reopened.data, moment=days_later(31)) != {}


def test_real_kdbx_restore_and_purge_survive_the_roundtrip(tmp_path):
    pytest.importorskip('pykeepass')
    path = tmp_path / 'vault.kdbx'
    store = vault.VaultStore('correct horse battery staple', path=path)
    store.create()
    store.open()
    store.save(vault.trash_record(payload(), 'a', moment=MOMENT))
    store.save(vault.restore_record(store.data, 'a'))
    reopened = vault.VaultStore('correct horse battery staple', path=path)
    reopened.open()
    assert 'status' not in reopened.data['servers']['a']
    reopened.save(vault.trash_record(reopened.data, 'a', moment=MOMENT))
    reopened.save(vault.purge_record(reopened.data, 'a'))
    final = vault.VaultStore('correct horse battery staple', path=path)
    final.open()
    assert final.data['servers'] == {}


def test_real_kdbx_still_opens_records_without_lifecycle_fields(tmp_path):
    pytest.importorskip('pykeepass')
    path = tmp_path / 'vault.kdbx'
    store = vault.VaultStore('correct horse battery staple', path=path)
    store.create()
    store.open()
    store.save(payload())
    reopened = vault.VaultStore('correct horse battery staple', path=path)
    reopened.open()
    assert not vault.is_trashed(reopened.data['servers']['a'])
