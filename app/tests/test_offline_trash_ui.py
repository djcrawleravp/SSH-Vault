"""Trash UI: moves are local-only, restore works, purge needs a confirmation."""
from pathlib import Path
import sys
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import launcher
import vault


def record(**over):
    rec = {'host': 'example.com', 'user': 'root', 'port': '22',
           'key_name': 'a_key', 'private': vault.b64(b'private-bytes'),
           'public': vault.b64(b'public-bytes')}
    rec.update(over)
    return rec


def tagged(**over):
    public = vault.b64(b'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample ssh-vault-managed-a')
    return record(public=public, **over)


class DummyStore:
    def __init__(self, data):
        self.data = data
        self.saved = 0
        self.backups = 0

    def save(self, data):
        self.data = data
        self.saved += 1

    def backup_verified(self):
        self.backups += 1
        return Path('/dev/null')


def make_ui(monkeypatch, servers, confirm=True, menu=None):
    data = vault.data_default()
    data['servers'] = servers
    store = DummyStore(data)
    monkeypatch.setattr(launcher, 'current_store', lambda: store)
    ui = launcher.Launcher.__new__(launcher.Launcher)
    ui.servers = []
    ui.trash = []
    ui.index = 0
    ui.notice = ''
    ui.popup = Mock()
    ui.reload = Mock()
    ui.confirm = Mock(return_value=confirm)
    ui.menu = Mock(return_value=menu)
    ui.run_backend = Mock(return_value=1)
    ui.after = Mock()
    return ui, store


def server(alias='a', kind='TAGGED'):
    return launcher.Server(alias=alias, host='example.com', user='root',
                           port='22', key='a_key', key_kind=kind)


# --- S1: an unreachable server never traps the user ------------------------

def test_failed_delete_offers_trash_and_saves_locally(monkeypatch):
    ui, store = make_ui(monkeypatch, {'a': tagged()}, menu=1)
    ui.selected = lambda: server()
    ui.delete()
    assert ui.run_backend.call_count == 1
    assert store.saved == 1
    assert vault.is_trashed(store.data['servers']['a'])


def test_failed_delete_keeps_the_server_when_the_user_declines(monkeypatch):
    ui, store = make_ui(monkeypatch, {'a': tagged()}, confirm=False, menu=1)
    ui.selected = lambda: server()
    ui.delete()
    assert store.saved == 0
    assert not vault.is_trashed(store.data['servers']['a'])


def test_successful_delete_archives_the_identity_as_revoked(monkeypatch):
    """S9/S10: a verified delete keeps the identity, marked as revoked."""
    ui, store = make_ui(monkeypatch, {'a': tagged()}, menu=1)
    ui.run_backend = Mock(return_value=0)
    ui.selected = lambda: server()
    ui.delete()
    assert store.saved == 1
    archived = store.data['servers']['a']
    assert vault.is_trashed(archived)
    assert vault.is_revoked(archived)
    assert archived['revoked_utc'] == archived['trashed_utc']
    assert archived['private'] == tagged()['private']


def test_online_delete_keeps_its_exact_backend_contract(monkeypatch):
    """S7: the reachable-server path must not change its argv or its safety menu."""
    ui, store = make_ui(monkeypatch, {'a': tagged()}, menu=0)
    ui.run_backend = Mock(return_value=0)
    ui.selected = lambda: server()
    ui.delete()
    assert ui.run_backend.call_args[0][0] == ['delete', 'a', 'enable_password']
    assert ui.run_backend.call_args[0][1] == 'DELETE CONNECTION'
    assert ui.confirm.call_args[0][0] == 'DELETE CONNECTION'


# --- S1/S5: the deliberate, offline path ------------------------------------

def test_move_to_trash_saves_without_contacting_the_server(monkeypatch):
    ui, store = make_ui(monkeypatch, {'a': tagged()})
    ui.move_to_trash('a')
    assert ui.run_backend.call_count == 0
    assert store.saved == 1
    assert vault.is_trashed(store.data['servers']['a'])
    assert store.data['servers']['a']['private'] == tagged()['private']


def test_move_to_trash_can_pick_from_the_active_list(monkeypatch):
    ui, store = make_ui(monkeypatch, {'a': tagged(), 'b': tagged()}, menu=1)
    ui.move_to_trash()
    assert store.saved == 1
    assert vault.is_trashed(store.data['servers']['b'])
    assert not vault.is_trashed(store.data['servers']['a'])


def test_move_to_trash_honours_a_cancelled_menu(monkeypatch):
    ui, store = make_ui(monkeypatch, {'a': tagged()}, menu=None)
    ui.move_to_trash()
    assert store.saved == 0


# --- S3: restore ------------------------------------------------------------

def test_restore_returns_the_connection_to_the_list(monkeypatch):
    server_record = tagged(status='trashed', trashed_utc='2024-01-01T00:00:00Z')
    ui, store = make_ui(monkeypatch, {'a': server_record})
    ui.restore_from_trash('a')
    assert store.saved == 1
    assert not vault.is_trashed(store.data['servers']['a'])
    assert store.data['servers']['a']['private'] == server_record['private']
    assert ui.reload.call_args[0][0] == 'a'


# --- S5: purge is never implicit -------------------------------------------

def test_purge_requires_confirmation(monkeypatch):
    trashed = tagged(status='trashed', trashed_utc='2024-01-01T00:00:00Z')
    ui, store = make_ui(monkeypatch, {'a': trashed}, confirm=False)
    ui.purge_from_trash('a')
    assert store.saved == 0
    assert 'a' in store.data['servers']


def test_purge_removes_the_identity_after_confirmation(monkeypatch):
    trashed = tagged(status='trashed', trashed_utc='2024-01-01T00:00:00Z')
    ui, store = make_ui(monkeypatch, {'a': trashed}, confirm=True)
    ui.purge_from_trash('a')
    assert store.saved == 1
    assert 'a' not in store.data['servers']
    message = ui.confirm.call_args[0][1]
    assert 'cannot be undone' in message
    assert '.vault-backups' in message


# --- S4/S6: expiry is reported, never acted on -----------------------------

def test_expired_trash_is_labelled_and_never_purged(monkeypatch):
    old = tagged(status='trashed', trashed_utc='2020-01-01T00:00:00Z')
    ui, store = make_ui(monkeypatch, {'a': old}, menu=None)
    ui.trash_screen()
    labels = ui.menu.call_args[0][1]
    assert any('EXPIRED' in label for label in labels)
    assert store.saved == 0
    assert 'a' in store.data['servers']


def test_fresh_trash_is_not_labelled_expired(monkeypatch):
    now = vault.utc_stamp()
    fresh = tagged(status='trashed', trashed_utc=now)
    ui, store = make_ui(monkeypatch, {'a': fresh}, menu=None)
    ui.trash_screen()
    labels = ui.menu.call_args[0][1]
    assert not any('EXPIRED' in label for label in labels)
    assert store.saved == 0


def test_empty_trash_offers_to_move_a_connection(monkeypatch):
    ui, store = make_ui(monkeypatch, {'a': tagged()}, confirm=False)
    ui.trash_screen()
    assert ui.confirm.call_args[0][0] == 'TRASH IS EMPTY'
    assert store.saved == 0


# --- S2: hidden connections are really hidden ------------------------------

def test_trashed_connections_are_not_listed(monkeypatch):
    trashed = tagged(status='trashed', trashed_utc='2024-01-01T00:00:00Z')
    ui, store = make_ui(monkeypatch, {'a': trashed, 'b': tagged()})
    monkeypatch.setattr(launcher, 'current_store', lambda: store)
    listed = [s.alias for s in launcher.load_servers()]
    assert listed == ['b']
    assert [alias for alias, _ in launcher.trash_entries()] == ['a']


# --- F2/F5: the purge disclosure must be true, not reassuring --------------

def test_purge_writes_a_verified_backup_first(monkeypatch):
    trashed = tagged(status='trashed', trashed_utc='2024-01-01T00:00:00Z')
    ui, store = make_ui(monkeypatch, {'a': trashed}, confirm=True)
    ui.purge_from_trash('a')
    assert store.backups == 1
    assert store.saved == 1


def test_purge_message_admits_exports_and_missing_revocation(monkeypatch):
    trashed = tagged(status='trashed', trashed_utc='2024-01-01T00:00:00Z')
    ui, store = make_ui(monkeypatch, {'a': trashed}, confirm=True)
    ui.purge_from_trash('a')
    message = ui.confirm.call_args[0][1]
    assert 'exported_keys' in message
    assert 'does NOT revoke' in message
    assert 'cannot be undone' in message


# --- F3: an unmanaged identity can leave the list without being revoked ----

def test_legacy_delete_never_calls_the_backend(monkeypatch):
    ui, store = make_ui(monkeypatch, {'a': tagged()}, confirm=False)
    ui.selected = lambda: server(kind='LEGACY')
    ui.delete()
    assert ui.run_backend.call_count == 0
    assert store.saved == 0
    assert ui.confirm.call_args[0][0] == 'ADOPTION REQUIRED'


def test_legacy_delete_offers_the_trash_instead_of_a_dead_end(monkeypatch):
    ui, store = make_ui(monkeypatch, {'a': tagged()}, confirm=True)
    ui.selected = lambda: server(kind='LEGACY')
    ui.delete()
    assert ui.run_backend.call_count == 0
    assert store.saved == 1
    assert vault.is_trashed(store.data['servers']['a'])


# --- S4: the launch report is read-only and precise -----------------------

def test_expired_at_launch_reports_only_old_trash(monkeypatch):
    old = tagged(status='trashed', trashed_utc='2020-01-01T00:00:00Z')
    fresh = tagged(status='trashed', trashed_utc=vault.utc_stamp())
    ui, store = make_ui(monkeypatch, {'old': old, 'fresh': fresh})
    assert launcher.expired_at_launch() == ['old']
    assert store.saved == 0


def test_expired_at_launch_tolerates_a_store_without_data(monkeypatch):
    monkeypatch.setattr(launcher, 'current_store', lambda: object())
    assert launcher.expired_at_launch() == []


# --- F8: a trashed alias is refused before any remote work ----------------

def test_create_offers_to_purge_an_alias_held_by_the_trash(monkeypatch):
    """S12: always-archive must not make an alias permanently unusable."""
    trashed = tagged(status='trashed', trashed_utc='2024-01-01T00:00:00Z')
    ui, store = make_ui(monkeypatch, {'a': trashed}, confirm=True)
    ui.trash = [('a', trashed)]
    ui.prompt = Mock(return_value='a')
    ui.create()
    assert ui.confirm.call_args[0][0] == 'ALIAS IN TRASH'
    assert store.saved == 1
    assert store.backups == 1
    assert 'a' not in store.data['servers']


def test_create_keeps_a_trashed_alias_when_the_user_cancels(monkeypatch):
    trashed = tagged(status='trashed', trashed_utc='2024-01-01T00:00:00Z')
    ui, store = make_ui(monkeypatch, {'a': trashed}, confirm=False)
    ui.trash = [('a', trashed)]
    ui.prompt = Mock(return_value='a')
    ui.create()
    assert store.saved == 0
    assert vault.is_trashed(store.data['servers']['a'])


# --- S10/S11: the two trash states must never be conflated ------------------

def test_trash_label_states_whether_revocation_was_proven():
    assert launcher.Launcher.trash_label('a', tagged(), False).endswith('NOT REVOKED')
    revoked = tagged(revoked_utc='2024-01-01T00:00:00Z')
    assert launcher.Launcher.trash_label('a', revoked, True).endswith('REVOKED · EXPIRED')


def test_restore_of_a_revoked_identity_warns_that_it_will_not_connect(monkeypatch):
    revoked = tagged(status='trashed', trashed_utc='2024-01-01T00:00:00Z',
                     revoked_utc='2024-01-01T00:00:00Z')
    ui, store = make_ui(monkeypatch, {'a': revoked}, confirm=True)
    ui.restore_from_trash('a')
    warning = ui.confirm.call_args[0][1]
    assert 'does NOT' in warning
    assert 'install the key' in warning
    assert store.saved == 1


def test_restore_of_an_unverified_identity_says_it_may_still_be_authorized(monkeypatch):
    trashed = tagged(status='trashed', trashed_utc='2024-01-01T00:00:00Z')
    ui, store = make_ui(monkeypatch, {'a': trashed}, confirm=True)
    ui.restore_from_trash('a')
    warning = ui.confirm.call_args[0][1]
    assert 'may still accept' in warning or 'never verified revoked' in warning


def test_purge_message_for_a_revoked_identity_does_not_claim_it_is_still_authorized(monkeypatch):
    revoked = tagged(status='trashed', trashed_utc='2024-01-01T00:00:00Z',
                     revoked_utc='2024-01-01T00:00:00Z')
    ui, store = make_ui(monkeypatch, {'a': revoked}, confirm=True)
    ui.purge_from_trash('a')
    message = ui.confirm.call_args[0][1]
    assert 'verified revoked' in message
    assert 'may still authorize' not in message
