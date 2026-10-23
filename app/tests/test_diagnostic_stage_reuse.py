"""Regression: preflight and create share one stage, but never one diag file."""
from pathlib import Path
import json
import os
import sys
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import launcher
import vault


class DummyStore:
    def __init__(self):
        self.data = vault.data_default()
        self.saved = 0
    def save(self, data):
        self.data = data
        self.saved += 1
    def backup_verified(self):
        pass


def make_ui(monkeypatch):
    store = DummyStore()
    monkeypatch.setattr(launcher, 'current_store', lambda: store)
    ui = launcher.Launcher.__new__(launcher.Launcher)
    ui.servers = []
    ui.notice = ''
    ui.last_backend_details = ''
    ui.reload = Mock()
    ui.popup = Mock()
    files = []

    def external(argv, title, pause=False, env=None):
        path = Path(env['SSH_VAULT_DIAGNOSTIC_FILE'])
        assert path.is_file()
        assert os.stat(path).st_mode & 0o077 == 0
        files.append(path)
        if argv[-1] == '22' and argv[-5] == 'preflight':
            path.write_text('SSH_VAULT_STATUS=new\n', encoding='utf-8')
        else:
            path.write_text('operation complete\n', encoding='utf-8')
        return 0

    ui.run_external = external
    return ui, store, files


def test_repeated_backend_operations_use_distinct_files_and_remove_them(tmp_path, monkeypatch):
    ui, store, files = make_ui(monkeypatch)
    with launcher.backend_stage(store) as stage:
        assert ui.run_backend(['preflight', 'fresh', 'host', 'root', '22'],
                              'CHECK REMOTE KEY', stage=stage, quiet=True) == 0
        assert ui.last_backend_details == 'SSH_VAULT_STATUS=new'
        assert ui.run_backend(['create', 'fresh', 'host', 'root', '22', 'keep', 'normal'],
                              'CREATE CONNECTION', stage=stage, quiet=True) == 0
        assert ui.last_backend_details == 'operation complete'
        assert files[0] != files[1]
        assert not files[0].exists() and not files[1].exists()
        assert not list(stage.glob('operation-diagnostics-*'))
    assert ui.popup.call_count == 0


def test_create_wizard_reuses_staging_without_fileexists(tmp_path, monkeypatch):
    ui, store, files = make_ui(monkeypatch)
    ui.prompt = Mock(side_effect=['fresh', 'host.example', 'root', '22'])
    ui.confirm = Mock(side_effect=[True, False])
    monkeypatch.setattr(launcher, 'last_remote_user', lambda: 'root')
    monkeypatch.setattr(launcher, 'remember_remote_user', lambda user: None)
    # Avoid sending an SSH control-socket exit command to a real server.
    monkeypatch.setattr(launcher.subprocess, 'run', lambda *a, **kw: None)
    ui.create()
    assert len(files) == 2
    assert files[0] != files[1]
    assert all(not f.exists() for f in files)
    assert not any(c.args[0] == 'VAULT UPDATE ERROR' for c in ui.popup.call_args_list)


def test_diagnostics_deleted_even_if_staging_read_fails(tmp_path, monkeypatch):
    ui, store, files = make_ui(monkeypatch)
    def fail(*args):
        raise vault.VaultError('Staged file invalid')
    monkeypatch.setattr(launcher, 'changed_payload', fail)
    with launcher.backend_stage(store) as stage:
        assert ui.run_backend(['preflight', 'a', 'b', 'root', '22'],
                              'CHECK', stage=stage, quiet=True) == 1
        assert len(files) == 1 and not files[0].exists()
        assert ui.popup.call_args.args[0] == 'VAULT UPDATE ERROR'
