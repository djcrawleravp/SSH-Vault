"""Do not interpret arbitrary KDBX failures as wrong passwords."""
from pathlib import Path
import sys
import types
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import launcher


class CredentialsError(Exception):
    pass


def harness(monkeypatch, tmp_path, behaviors):
    # The real pykeepass library is not required for error-routing unit tests.
    mod = types.ModuleType('pykeepass')
    mod.__path__ = []
    errors = types.ModuleType('pykeepass.exceptions')
    errors.CredentialsError = CredentialsError
    monkeypatch.setitem(sys.modules, 'pykeepass', mod)
    monkeypatch.setitem(sys.modules, 'pykeepass.exceptions', errors)
    vault_file = tmp_path / 'vault.kdbx'
    vault_file.write_bytes(b'no live crypto in unit test')
    monkeypatch.setattr(launcher, 'KDBX', vault_file)
    monkeypatch.setattr(launcher, 'INBOX', tmp_path / 'absent-legacy-inbox')
    prompts, reports, completed = [], [], []
    def prompt(*args, **kwargs):
        prompts.append(kwargs.get('previous_error', ''))
        return 'example master password'
    class FakeStore:
        def __init__(self, password):
            self.password = password
        def open(self):
            outcome = behaviors.pop(0)
            if outcome: raise outcome
    class FakeLauncher:
        def __init__(self, window): self.window=window
        def loop(self): completed.append(True)
        def disable_mouse(self): pass
    monkeypatch.setattr(launcher, 'password_form', prompt)
    monkeypatch.setattr(launcher, 'VaultStore', FakeStore)
    monkeypatch.setattr(launcher, 'Launcher', FakeLauncher)
    monkeypatch.setattr(launcher, 'report_screen', lambda win,title,lines:reports.append((title,lines)))
    return prompts, reports, completed


def test_wrong_password_only_then_success(monkeypatch, tmp_path):
    prompts, reports, completed = harness(monkeypatch, tmp_path,
                        [CredentialsError('wrong'), CredentialsError('wrong'), CredentialsError('wrong'), CredentialsError('wrong'), None])
    launcher.run(types.SimpleNamespace(erase=lambda:None))
    assert len(prompts) == 3
    assert 'attempt 1' in prompts[1]
    assert 'attempt 2' in prompts[2]
    assert not reports
    assert completed == [True]


@pytest.mark.parametrize('error', [OSError('disk busy'), ValueError('invalid schema'),
                                    MemoryError('kdf memory failure')])
def test_non_credentials_error_must_not_reprompt(monkeypatch, tmp_path, error):
    prompts, reports, completed = harness(monkeypatch, tmp_path, [error])
    launcher.run(types.SimpleNamespace(erase=lambda:None))
    assert len(prompts) == 1
    assert reports and reports[0][0] == 'VAULT OPEN ERROR'
    assert 'NOT confirmed' in '\n'.join(reports[0][1])
    assert not completed


def test_transient_credentials_error_retried_without_another_prompt(monkeypatch, tmp_path):
    prompts, reports, completed = harness(monkeypatch, tmp_path,
                                          [CredentialsError('transient'), None])
    launcher.run(types.SimpleNamespace(erase=lambda:None))
    assert len(prompts) == 1
    assert not reports and completed == [True]
