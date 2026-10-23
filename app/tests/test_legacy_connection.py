"""Imported identities must remain usable without adopting their remote keys."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from session import login_command


def test_legacy_identity_login_is_independent_of_ownership(tmp_path):
    legacy = dict(host='38.143.58.154', user='root', port='22',
                  key_name='seafile-server', private='', public='')
    identity = tmp_path / 'identity.pub'
    known = tmp_path / 'known_hosts'
    command = login_command('seafile', legacy, {'SSH_AUTH_SOCK': '/tmp/test-ssh-agent.sock'}, identity, known)
    joined=' '.join(command)
    assert command[0] == 'ssh'
    assert '-tt' in command
    assert '-i' in command and command[command.index('-i')+1] == str(identity)
    assert 'IdentityAgent=/tmp/test-ssh-agent.sock' in joined
    assert 'PasswordAuthentication=no' in joined
    assert 'ConnectTimeout=12' in joined
    assert 'ServerAliveCountMax=3' in joined
    assert '-l' in command and command[command.index('-l')+1]=='root'
    assert 'ssh-vault-managed-' not in joined
    assert 'adopt' not in joined
