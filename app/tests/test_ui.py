"""Curses-independent regression tests for keyboard and mouse actions."""
import curses
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import launcher


class FakeWindow:
    def __init__(self, h=38, w=140): self.h, self.w=h,w; self.ink=[]
    def getmaxyx(self): return self.h,self.w
    def erase(self): pass
    def refresh(self): pass
    def addstr(self,y,x,s,style=0): self.ink.append((y,x,s))
    def getch(self): return 27
    def timeout(self,n): pass


def make_ui(h=38,w=140):
    l=launcher.Launcher.__new__(launcher.Launcher)
    l.win=FakeWindow(h,w);l.style=lambda *args,**kw:0
    l.servers=[launcher.Server('alpha',host='192.0.2.1',user='tester'),
               launcher.Server('beta',host='192.0.2.2',user='tester')]
    l.index=0;l.scroll=0;l.notice='';l.query='';l.mode='normal';l.color=False
    l.footer_actions=[];l.footer_order=[];l.main_focus=None;l.list_hitbox=None
    l.last_click=(0.,-1,-1)
    return l


def test_vault_button_and_all_actions_mouse_keyboard():
    for w in [48,70,90,120,160]:
        l=make_ui(w=w); l.show()
        assert 'vault' in l.footer_order
        names=[]
        l.action=lambda name: names.append(name) or True
        for x0,x1,y,a in l.footer_actions:
            l.handle_mouse(launcher.Mouse(x0+1,y,'left'))
        assert names == l.footer_order
        for _ in range(len(l.footer_order)):
            l.focus_main_button()
        assert l.main_focus==l.footer_order[-1]
        l.focus_main_button()
        assert l.main_focus==l.footer_order[0]


def test_key_confirmations():
    for key, value in [(ord('y'),True),(ord('Y'),True),(ord('n'),False),(ord('N'),False),(27,None)]:
        l=make_ui()
        l.centered_box=lambda title,lines,**kw:(5,5,11,65)
        l.read_event=lambda **kw:key
        assert l.confirm('TEST','disable passwords?',allow_cancel=True) is value


def test_arrow_selection():
    l=make_ui()
    l.move(1)
    assert l.selected().alias=='beta'
    l.move(1)
    assert l.selected().alias=='beta'
    l.move(-1)
    assert l.selected().alias=='alpha'


def test_ownership_labels_are_descriptive_not_remote_claims(monkeypatch):
    import base64
    def identity(comment):
        return {'host': '192.0.2.5', 'user': 'root', 'port': '22', 'key_name': 'key',
                'public': base64.b64encode(('ssh-ed25519 AAAAA '+comment+'\n').encode()).decode()}
    class FakeStore:
        data = {'servers': {'old': identity('original-comment'),
                            'tagged': identity('ssh-vault-managed-tagged')}}
    monkeypatch.setattr(launcher, 'current_store', lambda: FakeStore())
    loaded = {s.alias:s for s in launcher.load_servers()}
    assert loaded['old'].key_kind == 'LEGACY'
    assert loaded['tagged'].key_kind == 'TAGGED'
    assert 'verify' in loaded['tagged'].note.lower()
