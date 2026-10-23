"""Fast regressions for password editing, fallback remote key ownership and export discoverability.

These tests deliberately do not need pykeepass or a live SSH server.
"""
from pathlib import Path
import os
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import startup
import launcher

HELPER = Path(__file__).resolve().parents[1] / 'remote_authorized_keys.sh'


def local_remote(tmp_path, action, content, blob='AAAAillustrativeblob'):
    home = tmp_path / 'user'
    ssh_dir = home / '.ssh'
    ssh_dir.mkdir(parents=True, exist_ok=True)
    auth = ssh_dir / 'authorized_keys'
    auth.write_text(content)
    binaries = tmp_path / 'bin'
    binaries.mkdir(exist_ok=True)
    sshd = binaries / 'sshd'
    sshd.write_text('#!/bin/sh\necho "sshd test failed with fake environment" >&2\nexit 1\n')
    sshd.chmod(0o755)
    env = {**os.environ, 'PATH': str(binaries)+os.pathsep+os.environ['PATH'],
           'HOME': str(home), 'SSH_CONNECTION': '192.0.2.4 12345 192.0.2.5 22',
           'VAULT_ACTION': action, 'VAULT_TYPE': 'ssh-ed25519',
           'VAULT_BLOB': blob, 'VAULT_MARKER': 'ssh-vault-managed-old'}
    result = subprocess.run(['sh', str(HELPER)], env=env, capture_output=True,
                            text=True, timeout=12)
    return result, auth


def test_limited_inspection_adopts_exact_key(tmp_path):
    original = ('ssh-ed25519 DIFFERENT unrelated\n'
                'from="192.0.2.4",no-pty ssh-ed25519 AAAAillustrativeblob old comment\n')
    result, auth = local_remote(tmp_path, 'adopt', original)
    assert result.returncode == 0, result.stderr
    assert 'LIMITED INSPECTION' in result.stdout
    assert auth.read_text() == (
        'ssh-ed25519 DIFFERENT unrelated\n'
        'from="192.0.2.4",no-pty ssh-ed25519 AAAAillustrativeblob old comment ssh-vault-managed-old\n')


def test_limited_inspection_revokes_only_managed(tmp_path):
    original = ('ssh-ed25519 DIFFERENT unrelated\n'
                'ssh-ed25519 AAAAillustrativeblob old comment ssh-vault-managed-old\n')
    result, auth = local_remote(tmp_path, 'remove', original)
    assert result.returncode == 0, result.stderr
    assert auth.read_text() == 'ssh-ed25519 DIFFERENT unrelated\n'


def test_limited_inspection_rejects_missing_target(tmp_path):
    result, auth = local_remote(tmp_path, 'remove', 'ssh-ed25519 DIFFERENT unrelated\n')
    assert result.returncode != 0
    assert auth.read_text() == 'ssh-ed25519 DIFFERENT unrelated\n'


def test_export_direct_shortcut_present():
    import inspect
    source = inspect.getsource(launcher.Launcher)
    assert 'def export(self):' in source
    assert '("X Export", "export")' in source
    assert 'ord(\'x\')' in source


def test_password_screen_handles_delete_and_visibility(monkeypatch):
    import curses
    # Keys: 12 letters, macOS Delete (KEY_DC), corrected character, Enter.
    keys = list('abcdefghijkx') + [getattr(curses, 'KEY_DC'), 'l', '\x12', '\n']
    lengths = []
    class FakeWindow:
        def keypad(self, v): pass
        def get_wch(self): return keys.pop(0)
    def fake_screen(win, title, subtitle, fields, selected, message='', busy=False, reveal=False):
        lengths.append((len(fields[0][1]), reveal))
        return ([(0, 0, 20)], (0, 20, 1), (25, 34, 1))
    monkeypatch.setattr(startup, 'screen', fake_screen)
    monkeypatch.setattr(startup, 'colors', lambda: None)
    monkeypatch.setattr(curses, 'curs_set', lambda _: None)
    monkeypatch.setattr(curses, 'noecho', lambda: None)
    monkeypatch.setattr(curses, 'mousemask', lambda *_: 0)
    password = startup.password_form(FakeWindow(), create=False)
    assert password == 'abcdefghijkl'
    assert any(reveal for _, reveal in lengths)
    assert not keys


def test_limited_inspection_preserves_symlink_and_others(tmp_path):
    home = tmp_path / 'user'; sshdir = home / '.ssh'; sshdir.mkdir(parents=True)
    target = tmp_path / 'pve-auth'; target.write_text('ssh-ed25519 OTHER_BLOB separate\nssh-ed25519 AAAAillustrativeblob old\n')
    link = sshdir / 'authorized_keys'; link.symlink_to(target)
    binary = tmp_path / 'bin'; binary.mkdir()
    fake = binary / 'sshd'; fake.write_text('#!/bin/sh\nexit 1\n'); fake.chmod(0o755)
    env = {**os.environ, 'PATH': str(binary)+os.pathsep+os.environ['PATH'],
           'HOME': str(home), 'SSH_CONNECTION': '192.0.2.4 5000 192.0.2.1 22',
           'VAULT_ACTION': 'adopt', 'VAULT_TYPE': 'ssh-ed25519',
           'VAULT_BLOB': 'AAAAillustrativeblob', 'VAULT_MARKER': 'ssh-vault-managed-old'}
    result = subprocess.run(['sh', str(HELPER)], env=env, capture_output=True, text=True, timeout=12)
    assert result.returncode == 0, result.stderr
    assert link.is_symlink()
    assert target.read_text() == ('ssh-ed25519 OTHER_BLOB separate\n'
                                  'ssh-ed25519 AAAAillustrativeblob old ssh-vault-managed-old\n')


def test_key_in_two_lines_is_never_adopted(tmp_path):
    original = 'ssh-ed25519 AAAAillustrativeblob first\nssh-ed25519 AAAAillustrativeblob second\n'
    result, auth = local_remote(tmp_path, 'adopt', original)
    assert result.returncode != 0
    assert auth.read_text() == original


def test_unknown_existing_managed_tag_not_stolen(tmp_path):
    original = 'ssh-ed25519 AAAAillustrativeblob ssh-vault-managed-another\n'
    result, auth = local_remote(tmp_path, 'adopt', original)
    assert result.returncode != 0
    assert auth.read_text() == original
