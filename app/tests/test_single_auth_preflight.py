"""Two-phase recovery uses a single SSH authentication and preserves other keys."""
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_universal_remote_keys import fixture_env, backend, FAKE_SSH
from test_lost_key_recovery import OLD_BLOB, MARK

# Adapt the existing fake SSH to model OpenSSH's ControlMaster socket lifecycle.
MULTIPLEX_SSH = FAKE_SSH.replace(
    "if '-O' in args: sys.exit(0)",
    """if '-fN' in args:
    opts=[args[j+1] for j,a in enumerate(args[:-1]) if a=='-o']
    sock=[o.split('=',1)[1] for o in opts if o.startswith('ControlPath=')][0]
    Path(sock).write_text('ssh-master-available')
    counter=Path(os.environ['AUTH_COUNTER'])
    counter.write_text(str(int(counter.read_text() if counter.exists() else '0')+1))
    sys.exit(0)
if '-O' in args:
    opts=[args[j+1] for j,a in enumerate(args[:-1]) if a=='-o']
    sock=[o.split('=',1)[1] for o in opts if o.startswith('ControlPath=')][0]
    if args[args.index('-O')+1]=='exit':
        Path(sock).unlink(missing_ok=True)
        sys.exit(0)
    sys.exit(0 if Path(sock).exists() else 255)
""")


def test_replacement_is_proposed_before_failure_and_reuses_login(tmp_path):
    home, auth, stage, env = fixture_env(tmp_path)
    bin_path = Path(env['PATH'].split(os.pathsep)[0])
    fake_ssh = bin_path / 'ssh'
    fake_ssh.write_text(MULTIPLEX_SSH)
    fake_ssh.chmod(0o755)
    counter = tmp_path / 'auth-counter'
    env['AUTH_COUNTER'] = str(counter)
    muxdir = tmp_path / 'mux'
    muxdir.mkdir(mode=0o700)
    env['SSH_VAULT_MUX_PATH'] = str(muxdir / 'ctl')
    old = f'ssh-ed25519 {OLD_BLOB} {MARK}\n'
    other = 'ssh-ed25519 OTHER_BLOB another-key\n'
    auth.write_text(other + old)
    preflight = backend(env, 'preflight','solid','fake-unix','root','22')
    assert preflight.returncode == 0, (preflight.stdout, preflight.stderr)
    assert 'SSH_VAULT_STATUS=replace' in preflight.stdout
    assert auth.read_text() == other + old
    assert counter.read_text() == '1'
    replaced = backend(env, 'create','solid','fake-unix','root','22','keep','replace')
    assert replaced.returncode == 0, (replaced.stdout, replaced.stderr)
    assert counter.read_text() == '1'  # No second SSH login.
    assert auth.read_text().startswith(other)
    assert auth.read_text().count(MARK) == 1
    assert OLD_BLOB not in auth.read_text()
    assert (stage/'priv'/'solid').exists()


def test_new_connection_preflight_avoids_replacement_prompt(tmp_path):
    _,auth,stage,env=fixture_env(tmp_path)
    bin_path = Path(env['PATH'].split(os.pathsep)[0])
    (bin_path/'ssh').write_text(MULTIPLEX_SSH)
    (bin_path/'ssh').chmod(0o755)
    env['AUTH_COUNTER'] = str(tmp_path/'counter')
    (tmp_path/'mux').mkdir()
    env['SSH_VAULT_MUX_PATH'] = str(tmp_path/'mux'/'ctl')
    result=backend(env,'preflight','new','fake-unix','root','22')
    assert result.returncode==0, (result.stdout,result.stderr)
    assert 'SSH_VAULT_STATUS=new' in result.stdout
    assert backend(env,'create','new','fake-unix','root','22','keep','normal').returncode == 0
    assert Path(env['AUTH_COUNTER']).read_text() == '1'


def test_create_ui_shows_replacement_choice_before_running_mutation(tmp_path, monkeypatch):
    """No generic failure dialog and no second backend login on confirmation."""
    import contextlib
    import launcher
    from unittest.mock import Mock
    dummy_stage = tmp_path / 'stage'
    dummy_stage.mkdir()
    @contextlib.contextmanager
    def fake_stage(store):
        yield dummy_stage
    monkeypatch.setattr(launcher, 'backend_stage', fake_stage)
    monkeypatch.setattr(launcher.subprocess, 'run', lambda *args, **kw: None)
    monkeypatch.setattr(launcher, 'remember_remote_user', lambda x: None)
    monkeypatch.setattr(launcher, 'current_store', lambda: type('Store', (), {'data': {'servers': {}, 'last_user': 'root'}, 'backup_verified':lambda self: None})())
    ui = launcher.Launcher.__new__(launcher.Launcher)
    ui.servers = []
    ui.notice = ''
    ui.last_backend_details = ''
    ui.prompt = Mock(side_effect=['solid', 'Solid', 'root', '22'])
    decisions = []
    def confirm(title, *args, **kwargs):
        decisions.append(title)
        return True
    ui.confirm = confirm
    backend_calls = []
    def backend(args, title, **kwargs):
        backend_calls.append((args, title, kwargs))
        if args[0] == 'preflight':
            ui.last_backend_details = 'NOTICE: SSH_VAULT_STATUS=replace'
        return 0
    ui.run_backend = backend
    ui.reload = Mock()
    ui.create()
    assert decisions == ['CREATE CONNECTION', 'PASSWORD LOGIN (OPTIONAL)',
                         'REPLACE LOST MANAGED KEY']
    assert [a[0][0] for a in backend_calls] == ['preflight','create']
    assert backend_calls[1][0][-1] == 'replace'
    assert backend_calls[0][2]['stage'] is backend_calls[1][2]['stage']
    assert backend_calls[0][2]['mux_path'] == backend_calls[1][2]['mux_path']


def test_create_ui_cancel_replacement_never_mutates(tmp_path, monkeypatch):
    import contextlib, launcher
    from unittest.mock import Mock
    @contextlib.contextmanager
    def stage(store):
        yield tmp_path
    monkeypatch.setattr(launcher,'backend_stage',stage)
    monkeypatch.setattr(launcher.subprocess,'run',lambda *a,**kw:None)
    monkeypatch.setattr(launcher, 'current_store', lambda: type('Store', (), {'data': {'servers': {}, 'last_user': 'root'}, 'backup_verified':lambda self: None})())
    ui=launcher.Launcher.__new__(launcher.Launcher)
    ui.servers=[];ui.notice='';ui.last_backend_details=''
    ui.prompt=Mock(side_effect=['solid','Solid','root','22'])
    ui.confirm=Mock(side_effect=[True,False,False])
    called=[]
    def backend(args,*a,**kw):
        called.append(args[0]);ui.last_backend_details='SSH_VAULT_STATUS=replace';return 0
    ui.run_backend=backend
    ui.reload=Mock()
    ui.create()
    assert called==['preflight']
    assert 'cancelled' in ui.notice.lower()


def test_readonly_preflight_allows_new_account_without_ssh_dir(tmp_path):
    import subprocess
    home = tmp_path / 'home'
    home.mkdir()
    helper = Path(__file__).resolve().parents[1] / 'remote_authorized_keys.sh'
    env = {**os.environ,'HOME':str(home), 'PATH':'/usr/bin:/bin',
           'VAULT_ACTION':'inspect', 'VAULT_TYPE':'ssh-ed25519',
           'VAULT_BLOB':'AQ==', 'VAULT_MARKER':'ssh-vault-managed-newhost'}
    result = subprocess.run(['/bin/sh',str(helper)],env=env,capture_output=True,text=True,timeout=6)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert 'SSH_VAULT_STATUS=new' in result.stdout
    assert not (home/'.ssh').exists()  # Read-only inspection, no changes.
