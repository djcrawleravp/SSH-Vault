#!/usr/bin/env python3
"""SSH Launcher: terminal UI, Python stdlib + OpenSSH, no local ~/.ssh writes.

Portable layout: run.sh at root, app/ for code, keys/ for config and credentials.
The app doesn't check network connectivity until the user connects or administers a host.
"""
from __future__ import annotations

import curses
import locale
import json
import tempfile
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import textwrap
import atexit
from startup import password_form, report_screen
from dataclasses import dataclass

from vault import (VaultStore, VaultError, KDBX, ROOT, INBOX, EXPORT, BACKUPS,
                   migrate, export_vault, unb64, save_file,
                   verify_pair)
from session import backend_stage, changed_payload, login_agent, login_command

APP = Path(__file__).resolve().parent
BACKEND = APP / "ssh_backend.sh"
ACTIVE_VAULT: VaultStore | None = None

try:
    locale.setlocale(locale.LC_ALL, "")
except locale.Error:
    pass


def initialize_storage() -> None:
    """The keys/ import inbox is NEVER created automatically."""
    local_ssh = (Path.home() / '.ssh').resolve()
    project = ROOT.resolve()
    if project == local_ssh or local_ssh in project.parents:
        raise OSError('Refusing to run from the local ~/.ssh directory')
    if not BACKEND.is_file() or BACKEND.is_symlink():
        raise OSError(f'Missing or invalid backend: {BACKEND}')


def current_store() -> VaultStore:
    if ACTIVE_VAULT is None:
        raise VaultError('Vault has not been unlocked')
    return ACTIVE_VAULT


def last_remote_user() -> str:
    return current_store().data.get('last_user', 'root')


def remember_remote_user(user: str) -> None:
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', user):
        raise ValueError('Invalid SSH username')
    vault = current_store()
    updated = json.loads(json.dumps(vault.data))
    updated['last_user'] = user
    vault.save(updated)

@dataclass
class Server:
    alias: str
    host: str = ""
    user: str = ""
    port: str = "22"
    key: str = ""
    key_kind: str = "NO KEY"
    note: str = ""


def locally_owned(record: dict) -> bool:
    """A marker signals intended ownership, NOT verified remote state."""
    try:
        parts = unb64(record['public']).decode('ascii').split()
        return (len(parts) == 3 and parts[0] == 'ssh-ed25519'
                and bool(re.fullmatch(r'ssh-vault-managed-[A-Za-z0-9_-]+', parts[2])))
    except (ValueError, UnicodeError, KeyError):
        return False


def load_servers() -> list[Server]:
    result = []
    for alias, rec in sorted(current_store().data['servers'].items()):
        tagged = locally_owned(rec)
        result.append(Server(alias=alias, host=rec['host'], user=rec['user'],
                             port=rec['port'], key=rec['key_name'],
                             key_kind='TAGGED' if tagged else 'LEGACY',
                             note=('Vault ownership tag present; use Edit / Verify Remote Key'
                                   if tagged else
                                   'Encrypted legacy identity; use Edit / Adopt Remote Key')))
    return result


@dataclass
class Mouse:
    x: int
    y: int
    action: str


class Launcher:
    # curses color pairs
    C_TEXT = 0
    C_CYAN = 1
    C_DIM = 2
    C_GREEN = 3
    C_YELLOW = 4
    C_RED = 5
    C_FOCUS = 6
    C_PANEL = 7
    C_ACCENT = 8

    def __init__(self, win):
        self.win = win
        self.servers: list[Server] = []
        self.index = 0
        self.scroll = 0
        self.notice = ""
        self.query = ""
        self.mode = "normal"
        self.color = False
        self.footer_actions = []
        self.footer_order = []
        self.main_focus = None
        self.list_hitbox = None
        self.mouse_enabled = False
        self.last_click = (0.0, -1, -1)
        self.last_mouse = None
        self.last_activity = time.monotonic()
        self.initialize()
        self.reload()

    def initialize(self):
        self.win.keypad(False)
        self.win.timeout(1000)
        if hasattr(curses, "set_escdelay"):
            curses.set_escdelay(70)
        curses.noecho()
        curses.cbreak()
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        if curses.has_colors():
            curses.start_color()
            try:
                curses.use_default_colors()
            except curses.error:
                pass
            bg = -1
            for pair, fg, back in [
                (1, curses.COLOR_CYAN, bg),
                (2, curses.COLOR_WHITE, bg),
                (3, curses.COLOR_GREEN, bg),
                (4, curses.COLOR_YELLOW, bg),
                (5, curses.COLOR_RED, bg),
                (6, curses.COLOR_BLACK, curses.COLOR_CYAN),
                (7, curses.COLOR_BLUE, bg),
                (8, curses.COLOR_WHITE, curses.COLOR_BLUE),
            ]:
                try:
                    curses.init_pair(pair, fg, back)
                except curses.error:
                    pass
            self.color = True
        # Manage xterm SGR 1006 ourselves instead of relying on macOS' older
        # curses mouse constants (e.g. BUTTON5_PRESSED is frequently missing).
        # Some terminals cannot report mouse; keyboard remains fully usable.
        try:
            curses.mousemask(0)
        except (AttributeError, curses.error):
            pass
        self.enable_mouse()

    def enable_mouse(self):
        if not self.mouse_enabled:
            try:
                sys.stdout.write("\x1b[?1000h\x1b[?1002h\x1b[?1006h")
                sys.stdout.flush()
                self.mouse_enabled = True
            except OSError:
                pass

    def disable_mouse(self):
        if self.mouse_enabled:
            try:
                sys.stdout.write("\x1b[?1006l\x1b[?1002l\x1b[?1000l")
                sys.stdout.flush()
            except OSError:
                pass
            self.mouse_enabled = False

    @staticmethod
    def decode_mouse(button: int, x: int, y: int, released=False):
        """Decode an xterm mouse report without depending on curses constants.

        SGR (1006), legacy X10 (1000/1002) and urxvt (1015) all use the
        same button bits after the legacy offsets have been removed.
        64/65 are vertical wheel; 66/67 horizontal wheel (ignored).
        """
        if not (1 <= x <= 100000 and 1 <= y <= 100000):
            return -1
        if button & 64:
            wheel = button & 3
            if wheel == 0:
                return Mouse(x - 1, y - 1, 'wheel-up')
            if wheel == 1:
                return Mouse(x - 1, y - 1, 'wheel-down')
            return -1  # Horizontal wheels must not jump the server list.
        if released or (button & 3) == 3:
            action = 'release'
        elif button & 32:
            action = 'drag' if (button & 3) == 0 else 'move'
        else:
            action = ('left', 'middle', 'right', 'move')[button & 3]
        return Mouse(x - 1, y - 1, action)

    def _read_csi_sequence(self, first: int):
        """Read numeric CSI key, xterm SGR 1006 or urxvt 1015 mouse.

        A finite buffer and timeout protect against partial/unsupported input.
        """
        chars = [] if first == ord('<') else [chr(first)]
        for _ in range(38):
            part = self.win.getch()
            if part in (ord('M'), ord('m')):
                try:
                    fields = list(map(int, ''.join(chars).split(';')))
                    if len(fields) != 3:
                        return -1
                    button, x, y = fields
                    if first != ord('<'):
                        button -= 32  # urxvt uses legacy button offset.
                    return self.decode_mouse(button, x, y, released=(part == ord('m')))
                except (ValueError, TypeError):
                    return -1
            if part == ord('~'):
                return {'1': curses.KEY_HOME, '3': curses.KEY_DC,
                        '4': curses.KEY_END, '5': curses.KEY_PPAGE,
                        '6': curses.KEY_NPAGE, '7': curses.KEY_HOME,
                        '8': curses.KEY_END}.get(''.join(chars), -1)
            if part in (ord('A'), ord('B'), ord('C'), ord('D'), ord('H'), ord('F')):
                # Arrow/Home/End with modifiers, e.g. ESC [ 1 ; 5 A.
                return {ord('A'): curses.KEY_UP, ord('B'): curses.KEY_DOWN,
                        ord('C'): curses.KEY_RIGHT, ord('D'): curses.KEY_LEFT,
                        ord('H'): curses.KEY_HOME, ord('F'): curses.KEY_END}[part]
            if part < 0 or part > 127 or chr(part) not in '0123456789;':
                return -1
            chars.append(chr(part))
        return -1

    def read_event(self, wide=False):
        """Read keyboard and portable mouse (SGR, X10, urxvt, KEY_MOUSE).

        Most modern terminals send SGR reports; older ones may fall back to
        X10. We do not rely on BUTTON5_PRESSED, absent in macOS curses.
        """
        try:
            key = self.win.get_wch() if wide else self.win.getch()
        except curses.error:
            return -1
        if key != 27 and key != "\x1b":
            if key == curses.KEY_MOUSE:
                return self.curses_mouse_fallback()
            return key
        self.win.timeout(85)
        try:
            prefix = self.win.getch()
            if prefix not in (ord('['), ord('O')):
                return 27
            part = self.win.getch()
            if prefix == ord('[') and part == ord('<'):
                # SGR 1006: ESC [ < button ; x ; y M/m
                return self._read_csi_sequence(part)
            if prefix == ord('[') and part == ord('M'):
                # X10: ESC [ M followed by three binary (button,x,y) bytes.
                values = [self.win.getch() for _ in range(3)]
                if any(value < 32 or value > 255 for value in values):
                    return -1
                return self.decode_mouse(values[0] - 32, values[1] - 32,
                                         values[2] - 32)
            if part in (ord('A'), ord('B'), ord('C'), ord('D'), ord('H'), ord('F')):
                return {ord('A'): curses.KEY_UP, ord('B'): curses.KEY_DOWN,
                        ord('C'): curses.KEY_RIGHT, ord('D'): curses.KEY_LEFT,
                        ord('H'): curses.KEY_HOME, ord('F'): curses.KEY_END}[part]
            if prefix == ord('O') and part == ord('M'):
                return 10  # Numeric keypad Enter in application mode.
            if prefix == ord('O') and part == ord('P'):
                return curses.KEY_F1
            if prefix == ord('[') and part == ord('Z'):
                return getattr(curses, 'KEY_BTAB', -200)
            if prefix == ord('[') and (part == ord('<') or ord('0') <= part <= ord('9')):
                # CSI numeric key, or older urxvt 1015 mouse report.
                return self._read_csi_sequence(part)
            # Ignore unsupported escape sequences, do not quit unexpectedly.
            return -1
        finally:
            self.win.timeout(1000)

    def curses_mouse_fallback(self):
        """Accept native curses KEY_MOUSE if a terminal emits it anyway."""
        try:
            _, x, y, _, b = curses.getmouse()
        except (AttributeError, curses.error):
            return -1
        for name, action in (
            ('BUTTON4_PRESSED', 'wheel-up'), ('BUTTON5_PRESSED', 'wheel-down'),
            ('BUTTON3_CLICKED', 'right'), ('BUTTON3_PRESSED', 'right'),
            ('BUTTON1_DOUBLE_CLICKED', 'double'), ('BUTTON1_CLICKED', 'left'),
            ('BUTTON1_PRESSED', 'left'), ('BUTTON1_RELEASED', 'release')):
            if b & getattr(curses, name, 0):
                return Mouse(x, y, action)
        return -1

    def style(self, name="normal", bold=False):
        palette = {
            "normal": 0, "accent": self.C_CYAN, "muted": self.C_DIM,
            "good": self.C_GREEN, "warning": self.C_YELLOW, "error": self.C_RED,
            "selected": self.C_FOCUS, "border": self.C_PANEL,
            "brand": self.C_ACCENT,
        }
        color = curses.color_pair(palette.get(name, 0)) if self.color else 0
        if name == "muted":
            color |= curses.A_DIM
        if bold or name in ("accent", "selected", "brand"):
            color |= curses.A_BOLD
        if name == "selected" and not self.color:
            color |= curses.A_REVERSE
        return color

    def put(self, y, x, text, width=None, style="normal", fill=False):
        h, w = self.win.getmaxyx()
        if y < 0 or y >= h or x >= w or x < 0:
            return
        avail = min((w - x - 1), width if width is not None else w - x - 1)
        if avail <= 0:
            return
        text = str(text).replace("\r", " ").replace("\n", " ").replace("\t", " ")
        # All known table fields are ASCII or ordinary single-width letters.
        text = text[:avail]
        if fill:
            text = text.ljust(avail)
        try:
            self.win.addstr(y, x, text, self.style(style))
        except curses.error:
            pass

    def rule(self, y, x, width, color="border"):
        self.put(y, x, "─" * max(width, 0), width, color)

    def panel(self, top, left, bottom, right, title=""):
        if bottom - top < 2 or right - left < 4:
            return
        self.put(top, left, "╭" + "─" * (right - left - 1) + "╮", right - left + 1, "border")
        self.put(bottom, left, "╰" + "─" * (right - left - 1) + "╯", right - left + 1, "border")
        for line in range(top + 1, bottom):
            self.put(line, left, "│", 1, "border")
            self.put(line, right, "│", 1, "border")
        if title:
            self.put(top, left + 2, " " + title + " ", right - left - 4, "accent")

    def reload(self, keep=None):
        old = keep or (self.servers[self.index].alias if self.servers and self.index < len(self.servers) else "")
        try:
            self.servers = load_servers()
            self.index = next((i for i, s in enumerate(self.servers) if s.alias == old), min(self.index, len(self.servers) - 1))
            self.index = max(0, self.index)
        except Exception as exc:
            self.servers = []
            self.index = 0
            self.notice = f"Error loading config: {exc}"

    def rows(self):
        if not self.query:
            return list(range(len(self.servers)))
        q = self.query.casefold()
        return [i for i, s in enumerate(self.servers) if q in f"{s.alias} {s.host} {s.user}".casefold()]

    def selected(self):
        if 0 <= self.index < len(self.servers):
            return self.servers[self.index]
        return None

    def show(self):
        self.win.erase()
        h, w = self.win.getmaxyx()
        if h < 15 or w < 48:
            self.put(1, 2, "Terminal too small", style="warning")
            self.put(3, 2, "Resize to at least 48x15.", style="muted")
            self.put(5, 2, "Q / Esc to quit")
            self.win.refresh()
            return
        wide = w >= 103
        self.put(1, 3, "▰  SSH VAULT", style="accent")
        self.put(1, max(34, w - 30), "ENCRYPTED  /  OPENSSH", 25, "muted")
        self.put(2, 3, f"{len(self.servers)} connections  ·  {ROOT}", w - 7, "muted")
        self.rule(3, 3, w - 7)
        self.footer_rows = 2 if h >= 22 else 1
        bottom = h - 4 - self.footer_rows
        left = 2
        compact = not wide and h < 25
        if wide:
            split = max(48, int(w * .59))
            self.panel(5, left, bottom, split, " CONNECTIONS ")
            self.panel(5, split + 2, bottom, w - 3, " SERVER ")
            width = split - left - 5
            dleft, dtop, dwidth = split + 5, 7, w - split - 11
        elif compact:
            split = w - 3
            detail_top = bottom + 1
            self.panel(5, left, bottom, split, " CONNECTIONS ")
            width = split - left - 5
            dleft, dtop, dwidth = 5, bottom + 2, w - 12
        else:
            split = w - 3
            detail_top = max(12, h - 14)
            self.panel(5, left, detail_top - 1, split, " CONNECTIONS ")
            self.panel(detail_top, left, bottom, split, " SERVER ")
            width = split - left - 5
            dleft, dtop, dwidth = 5, detail_top + 2, w - 12
        self.put(7, 5, "ALIAS", 19, "muted")
        if width > 48:
            self.put(7, 24, "HOST", max(10, width - 43), "muted")
        self.put(7, 5 + max(0, width - 14), "KEY", 12, "muted")
        list_top = 9
        list_bottom = (bottom - 1) if (wide or compact) else (detail_top - 2)
        visible = max(1, list_bottom - list_top)
        self.list_hitbox = (5, 5 + width, list_top, list_top + visible)
        found = self.rows()
        selected_pos = next((j for j, idx in enumerate(found) if idx == self.index), None)
        if selected_pos is not None:
            if selected_pos < self.scroll:
                self.scroll = selected_pos
            if selected_pos >= self.scroll + visible:
                self.scroll = selected_pos - visible + 1
        self.scroll = min(max(0, self.scroll), max(0, len(found) - visible))
        for j, idx in enumerate(found[self.scroll:self.scroll + visible]):
            s = self.servers[idx]
            y = list_top + j
            picked = idx == self.index
            line_width = width + 1
            style = "selected" if picked else "normal"
            marker = "▶" if picked else " "
            self.put(y, 5, marker + " " * (line_width - 1), line_width, style, True)
            self.put(y, 7, f"{idx+1:02}  {s.alias[:15]}", max(0, min(19, line_width - 3)), style)
            if width > 48:
                host_space = max(8, width - 44)
                self.put(y, 24, s.host[:host_space], host_space, style)
            tag = s.key_kind if s.key_kind in ("TAGGED", "LEGACY") else "NO KEY"
            if picked:
                self.put(y, 5 + max(0, width - 14), tag, 11, style)
            else:
                self.put(y, 5 + max(0, width - 14), tag, 11, "good" if tag == "TAGGED" else "warning")
        if not found:
            self.put(list_top, 7, "No connections. N to create or / to search.", width - 5, "muted")
        if len(found) > visible:
            self.put((bottom - 1) if (wide or compact) else (detail_top - 2), 7,
                     f"{self.scroll+1}-{min(self.scroll + visible, len(found))} / {len(found)} · PgUp/PgDn",
                     width - 4, "muted")
        if not compact:
            self.draw_detail(dleft, dtop, dwidth, bottom)
        self.rule(h - 3 - self.footer_rows, 3, w - 7)
        self.draw_footer(h, w)
        help2 = "Keyboard: Up/Down select · Enter connect · Tab actions · ? help   |   Mouse: click / double-click / wheel" if w >= 102 else "Up/Down: select · Enter: connect · Tab: buttons · ? help"
        self.put(h - 2, 3, help2, w - 6, "muted")
        status = ("Filter: " + self.query) if self.mode == "search" else self.notice
        if not status:
            status = "KDBX4 / Argon2id · Exiting SSH returns here · ~/.ssh untouched."
        self.put(h - 1, 3, status, w - 6, "warning" if self.notice else "muted")
        self.win.refresh()

    def draw_footer(self, h, w):
        """Every visible footer button has one mouse target and one keyboard focus.

        The layout is re-created after a resize, so hitboxes always follow the
        actual text that curses draws. For short terminals Menu exposes actions
        that cannot fit on the bottom row.
        """
        self.footer_actions = []
        options = [
            ("Menu", "menu"), ("Connect", "connect"), ("New", "create"),
            ("Edit", "edit"), ("Delete", "delete"), ("Search", "search"),
            ("Vault", "vault"), ("Reload", "reload"), ("Help", "help"), ("Quit", "quit"),
        ]
        row = h - 4 if self.footer_rows == 2 else h - 3
        last_row = h - 3
        x = 3
        for label, action in options:
            rendered = f"[{label}]"
            if x + len(rendered) > w - 3:
                if row == last_row:
                    break
                row = last_row
                x = 3
            self.put(row, x, rendered, len(rendered),
                     'selected' if self.main_focus == action else 'accent')
            self.footer_actions.append((x, x + len(rendered), row, action))
            x += len(rendered) + 1
        self.footer_order = [entry[3] for entry in self.footer_actions]
        if self.main_focus not in self.footer_order:
            self.main_focus = None

    def focus_main_button(self, backward=False):
        if not self.footer_order:
            return
        if self.main_focus is None:
            self.main_focus = self.footer_order[-1 if backward else 0]
            return
        i = self.footer_order.index(self.main_focus)
        self.main_focus = self.footer_order[(i + (-1 if backward else 1)) % len(self.footer_order)]

    def action(self, action):
        if action == "menu":
            commands = ["Connect", "New", "Edit", "Delete", "Search", "Vault", "Reload", "Help", "Quit"]
            option = self.menu("MAIN MENU", commands, details="Actions available by mouse or keyboard")
            if option is not None:
                return self.action(["connect", "create", "edit", "delete", "search", "vault", "reload", "help", "quit"][option])
        elif action == "connect":
            self.connect()
        elif action == "create":
            self.create()
        elif action == "edit":
            self.edit()
        elif action == "delete":
            self.delete()
        elif action == "search":
            self.search()
        elif action == "vault":
            self.vault_menu()
        elif action == "reload":
            self.reload()
            self.notice = "Configuration reloaded."
        elif action == "help":
            self.help()
        elif action == "quit":
            return False
        return True

    def handle_mouse(self, event: Mouse):
        if event.action in ('wheel-up', 'wheel-down'):
            self.main_focus = None
            self.move(-1 if event.action == 'wheel-up' else 1)
            return True
        if event.action not in ('left', 'double', 'right', 'drag'):
            return True
        x, y = event.x, event.y
        if event.action == 'left':
            now = time.monotonic()
            previous, px, py = self.last_click
            is_double = px == x and py == y and now - previous <= 0.40
            self.last_click = (now, x, y)
            if is_double:
                event = Mouse(x, y, 'double')
                self.last_click = (0.0, -1, -1)
        # Dispatch on the same hitboxes that were used to draw the labels.
        # Do this before list navigation so bottom buttons always work.
        for x0, x1, y0, action in self.footer_actions:
            if y == y0 and x0 <= x < x1 and event.action in ('left', 'double'):
                self.main_focus = action
                try:
                    return self.action(action)
                finally:
                    self.main_focus = None
        if self.list_hitbox is not None:
            x0, x1, y0, y1 = self.list_hitbox
            if x0 <= x < x1 and y0 <= y < y1:
                found = self.rows()
                idx = self.scroll + y - y0
                if 0 <= idx < len(found):
                    self.index = found[idx]
                    self.main_focus = None
                    if event.action == 'double':
                        self.connect()
                    elif event.action == 'right':
                        selection = self.menu('SERVER ACTIONS',
                            ['Connect', 'Edit', 'Delete'],
                            details=self.servers[self.index].alias)
                        if selection == 0:
                            self.connect()
                        elif selection == 1:
                            self.edit()
                        elif selection == 2:
                            self.delete()
        return True

    def draw_detail(self, x, y, width, bottom):
        s = self.selected()
        if not s:
            self.put(y, x, "NEW CONNECTION", width, "accent")
            self.put(y + 2, x, "Press N to add your first connection.", width - 2, "muted")
            return
        items = [
            ("Alias", s.alias),
            ("Host", s.host or "—"),
            ("User", s.user or "—"),
            ("Port", s.port),
            ("Identity", s.key_kind),
            ("Key name", s.key or "Unavailable"),
        ]
        self.put(y, x, "●  " + s.alias, width, "accent")
        max_rows = min(len(items), max(0, bottom - y - 3))
        for i, (label, value) in enumerate(items[:max_rows]):
            self.put(y + 2 + i, x, f"{label:<10}", min(11, width), "muted")
            self.put(y + 2 + i, x + 12, value, max(0, width - 13), "normal")
        if bottom - y >= 12:
            self.rule(bottom - 4, x, width)
            self.put(bottom - 3, x, "VAULT STATUS", width, "accent")
            self.put(bottom - 2, x, s.note, width, "muted")

    def centered_box(self, title, lines, width=None):
        h, w = self.win.getmaxyx()
        contentwidth = max(len(title) + 7, *(len(z) + 6 for z in lines)) if lines else len(title) + 7
        width = min(max(36, contentwidth, width or 0), w - 4)
        height = min(max(6, len(lines) + 5), h - 3)
        top = (h - height) // 2
        left = (w - width) // 2
        # Paint solid backing to avoid double-drawn content inside borders.
        for r in range(top, top + height):
            self.put(r, left, " " * width, width, "normal")
        self.panel(top, left, top + height - 1, left + width - 1, title)
        for i, line in enumerate(lines[:height - 4]):
            self.put(top + i + 2, left + 3, line, width - 6)
        self.win.refresh()
        return top, left, height, width

    def popup(self, title, message):
        """Fully scrollable dialog; mouse/keyboard always close and navigate."""
        offset = 0
        while True:
            self.show()
            h, w = self.win.getmaxyx()
            max_chars = max(15, min(88, w - 14))
            lines = []
            for raw in (message.splitlines() or ['']):
                lines.extend(textwrap.wrap(raw, width=max_chars,
                           break_long_words=True, break_on_hyphens=False) or [''])
            visible = max(1, h - 10)
            offset = max(0, min(offset, max(0, len(lines) - visible)))
            current = lines[offset:offset + visible]
            if len(lines) > visible:
                current += [f'Showing {offset + 1}-{offset + len(current)} of {len(lines)}  (Up/Down to scroll)']
            top, left, height, width = self.centered_box(title, current + ['', ''], width=65)
            y = top + height - 2
            x = left + 3
            self.put(y, x, '[ CLOSE ]', 9, 'selected')
            self.win.refresh()
            key = self.read_event()
            if key in (10, 13, 27, ord(' '), ord('q'), ord('Q'), curses.KEY_ENTER):
                return
            if key in (curses.KEY_UP, ord('k'), ord('K')):
                offset -= 1
            elif key in (curses.KEY_DOWN, ord('j'), ord('J')):
                offset += 1
            elif key == curses.KEY_PPAGE:
                offset -= visible
            elif key == curses.KEY_NPAGE:
                offset += visible
            elif isinstance(key, Mouse):
                if key.action == 'wheel-up':
                    offset -= 1
                elif key.action == 'wheel-down':
                    offset += 1
                elif key.action in ('left', 'double') and key.y == y and x <= key.x < x + 9:
                    return
            offset = max(0, min(offset, max(0, len(lines) - visible)))

    def menu(self, title, choices, details=''):
        """Navigation dialog with explicit SELECT and BACK buttons.

        Up/Down and J/K select an entry; Enter selects; Tab focuses buttons;
        Escape backs out. Both the entry rows and buttons accept mouse clicks.
        """
        if not choices:
            return None
        pos, scroll, focus = 0, 0, 'entries'
        while True:
            self.show()
            h, _ = self.win.getmaxyx()
            height = min(h - 3, max(9, len(choices) + 8))
            visible = max(1, min(len(choices), height - 8))
            scroll = min(max(scroll, pos - visible + 1), pos)
            lines = [details, ''] + ['' for _ in range(visible)] + ['']
            top, left, actual_height, width = self.centered_box(title, lines, width=74)
            entry_top = top + 4
            for i, label in enumerate(choices[scroll:scroll + visible]):
                is_active = scroll + i == pos
                self.put(entry_top + i, left + 3, ('▶ ' if is_active else '  ') + label,
                         width - 6, 'selected' if is_active else 'normal', fill=True)
            info_y = top + actual_height - 3
            self.put(info_y, left + 3,
                     f'{scroll + 1}-{min(scroll + visible, len(choices))}/{len(choices)}  ·  ↑↓/J/K  ·  Enter  ·  Tab  ·  Esc',
                     width - 6, 'muted')
            button_y = top + actual_height - 2
            select_text, back_text = '[ SELECT ]', '[ BACK ]'
            select_x = left + 3
            back_x = select_x + len(select_text) + 3
            self.put(button_y, select_x, select_text, len(select_text),
                     'selected' if focus == 'select' else 'accent')
            self.put(button_y, back_x, back_text, len(back_text),
                     'selected' if focus == 'back' else 'accent')
            self.win.refresh()
            key = self.read_event()
            if key in (curses.KEY_UP, ord('k'), ord('K')):
                pos = (pos - 1) % len(choices)
                focus = 'entries'
            elif key in (curses.KEY_DOWN, ord('j'), ord('J')):
                pos = (pos + 1) % len(choices)
                focus = 'entries'
            elif key == curses.KEY_PPAGE:
                pos = max(0, pos - visible)
                focus = 'entries'
            elif key == curses.KEY_NPAGE:
                pos = min(len(choices) - 1, pos + visible)
                focus = 'entries'
            elif key in (9, getattr(curses, 'KEY_BTAB', -200)):
                order = ('entries', 'select', 'back')
                shift = -1 if key != 9 else 1
                focus = order[(order.index(focus) + shift) % len(order)]
            elif key in (10, 13, curses.KEY_ENTER, ord(' ')):
                return None if focus == 'back' else pos
            elif key in (27, ord('q'), ord('Q')):
                return None
            elif isinstance(key, int) and ord('1') <= key <= ord('9'):
                chosen = key - ord('1')
                if chosen < len(choices):
                    return chosen
            elif isinstance(key, Mouse):
                if key.action == 'wheel-up':
                    pos = max(0, pos - 1)
                    focus = 'entries'
                elif key.action == 'wheel-down':
                    pos = min(len(choices) - 1, pos + 1)
                    focus = 'entries'
                elif key.action in ('left', 'double'):
                    mx, my = key.x, key.y
                    if my == button_y:
                        if select_x <= mx < select_x + len(select_text):
                            return pos
                        if back_x <= mx < back_x + len(back_text):
                            return None
                    if left + 2 <= mx < left + width - 2 and entry_top <= my < entry_top + visible:
                        chosen = scroll + my - entry_top
                        if chosen < len(choices):
                            return chosen
                elif key.action == 'right':
                    return None

    def confirm(self, title, message, danger=False,
                yes_label="YES", no_label="NO / CANCEL", allow_cancel=False):
        """Three-way dialogs distinguish NO from CANCEL when appropriate.

        Y and N always work, independently of the focused button. Esc cancels.
        Tab, Shift+Tab and Left/Right select the visible buttons for Enter.
        Clicking a visible button returns precisely its documented action.
        """
        choices = [(yes_label, True), (no_label, False)]
        if allow_cancel:
            choices.append(('CANCEL', None))
        focus = 1  # Default to safe / NO.
        while True:
            self.show()
            lines = message.splitlines() + ['', '']
            top, left, height, width = self.centered_box(title, lines, width=80)
            rendered = [f'[ {label} ]' for label, _ in choices]
            needed = sum(map(len, rendered)) + 3 * (len(rendered) - 1)
            if needed > width - 6:
                rendered = ['[ YES ]', '[ NO ]'] + (['[ CANCEL ]'] if allow_cancel else [])
            y = top + height - 2
            x = left + 3
            buttons = []
            for i, (label, value) in enumerate(choices):
                text = rendered[i]
                self.put(y, x, text, len(text),
                         'selected' if i == focus else ('warning' if danger and value is True else 'accent'))
                buttons.append((x, x + len(text), value))
                x += len(text) + 3
            self.win.refresh()
            key = self.read_event()
            if key in (ord('y'), ord('Y')):
                return True
            if key in (ord('n'), ord('N')):
                return False
            if key in (27, ord('q'), ord('Q')):
                return None if allow_cancel else False
            if key in (9, curses.KEY_LEFT, curses.KEY_RIGHT,
                       getattr(curses, 'KEY_BTAB', -200)):
                delta = -1 if key in (curses.KEY_LEFT, getattr(curses, 'KEY_BTAB', -200)) else 1
                focus = (focus + delta) % len(choices)
            elif key in (10, 13, curses.KEY_ENTER, ord(' ')):
                return choices[focus][1]
            elif isinstance(key, Mouse):
                if key.action in ('left', 'double') and key.y == y:
                    for x0, x1, result in buttons:
                        if x0 <= key.x < x1:
                            return result
                elif key.action == 'right':
                    return None if allow_cancel else False

    def prompt(self, title, label, default='', max_chars=120):
        """Text entry with keyboard-first Enter/Tab and clickable Save/Cancel."""
        value, focus = default, 'field'
        while True:
            self.show()
            lines = [label, '', '', '', '', '']
            top, left, height, width = self.centered_box(title, lines, width=71)
            input_y = top + 4
            shown = value[-(width - 9):]
            self.put(input_y, left + 3, ' ' * (width - 6), width - 6,
                     'selected' if focus == 'field' else 'normal', fill=True)
            self.put(input_y, left + 4, shown + ('▏' if focus == 'field' else ''),
                     width - 8, 'selected' if focus == 'field' else 'normal')
            self.put(top + height - 3, left + 3,
                     'Type · Enter save · Tab move · Esc cancel', width - 6, 'muted')
            button_y = top + height - 2
            save_x, cancel_x = left + 3, left + 17
            self.put(button_y, save_x, '[ SAVE ]', 8,
                     'selected' if focus == 'save' else 'accent')
            self.put(button_y, cancel_x, '[ CANCEL ]', 10,
                     'selected' if focus == 'cancel' else 'accent')
            self.win.refresh()
            key = self.read_event(wide=True)
            if isinstance(key, Mouse):
                if key.action in ('left', 'double'):
                    mx, my = key.x, key.y
                    if my == input_y and left + 3 <= mx < left + width - 3:
                        focus = 'field'
                    if my == button_y and save_x <= mx < save_x + 8:
                        return value.strip()
                    if my == button_y and cancel_x <= mx < cancel_x + 10:
                        return None
                elif key.action == 'right':
                    return None
                continue
            if key in ('\n', '\r', 10, 13, curses.KEY_ENTER):
                return None if focus == 'cancel' else value.strip()
            if key in ('\x1b', 27):
                return None
            if key in ('\t', 9, getattr(curses, 'KEY_BTAB', -200)):
                order = ('field', 'save', 'cancel')
                delta = -1 if key == getattr(curses, 'KEY_BTAB', -200) else 1
                focus = order[(order.index(focus) + delta) % len(order)]
            elif key in (curses.KEY_LEFT, curses.KEY_RIGHT) and focus != 'field':
                focus = 'save' if key == curses.KEY_LEFT else 'cancel'
            elif key in ('\b', '\x7f', curses.KEY_BACKSPACE, 127, 8):
                focus = 'field'
                value = value[:-1]
            elif isinstance(key, str) and key.isprintable() and len(value) < max_chars:
                focus = 'field'
                value += key
            elif isinstance(key, int) and 32 <= key <= 126 and len(value) < max_chars:
                focus = 'field'
                value += chr(key)

    def run_external(self, argv, title="SSH OPERATION", pause=True, env=None):
        """Hand over the *actual terminal* to SSH or backend, then restore curses.

        SSH gets stdin/out and terminal device unmodified. Not wrapped in a pseudo-shell.
        """
        code = 1
        self.disable_mouse()
        curses.def_prog_mode()
        curses.endwin()
        try:
            print("\033[2J\033[H", end="", flush=True)
            print("\n  SSH VAULT  /  " + title)
            print("  " + "─" * 58 + "\n", flush=True)
            try:
                code = subprocess.call(argv, cwd=ROOT, env=env)
            except KeyboardInterrupt:
                code = 130
            except OSError as exc:
                print(f"\n  ERROR: {exc}")
                code = 127
            # Do not require a keyboard-only 'Press Enter' after an operation.
            # The curses result dialog below can be dismissed by mouse or keys.
            if pause:
                print(f"\n  {'Operation completed' if code == 0 else f'Process exited with code {code}' }.", flush=True)
        finally:
            curses.reset_prog_mode()
            self.enable_mouse()
            self.win.keypad(False)
            try:
                curses.curs_set(0)
            except curses.error:
                pass
            self.win.clear()
            self.win.refresh()
        self.last_activity = time.monotonic()  # active SSH is never idle-locked
        self.reload()
        self.notice = f"{title}: {'completed successfully' if code == 0 else f'error ({code})'}"
        if pause:
            self.popup('OPERATION COMPLETE' if code == 0 else 'OPERATION FAILED',
                       f'{title}\n' + ('Completed successfully.' if code == 0 else
                                         f'Exited with code {code}. See terminal output for diagnostics.'))
        return code

    def connect(self):
        s = self.selected()
        if not s:
            return
        record = current_store().data['servers'][s.alias]
        try:
            private = unb64(record['private'])
            public = unb64(record['public'])
            # Only the PUBLIC key and host fingerprints are staged on disk.
            with login_agent(private) as (agent_env, agent_dir):
                identity = agent_dir / 'identity.pub'
                hosts = agent_dir / 'known_hosts'
                save_file(identity, public, 0o600)
                save_file(hosts, current_store().data['known_hosts'].encode())
                self.run_external(login_command(s.alias, record, agent_env, identity, hosts),
                                  f'CONNECTION {s.alias}', pause=False, env=agent_env)
                seen = hosts.read_text(encoding='utf-8')
                if seen != current_store().data['known_hosts']:
                    updated = json.loads(json.dumps(current_store().data))
                    updated['known_hosts'] = seen
                    current_store().save(updated)
                    self.notice = 'New host fingerprints securely saved to vault.'
        except (OSError, VaultError, subprocess.CalledProcessError, ValueError) as error:
            self.popup('SSH CONNECTION FAILED', str(error))

    def run_backend(self, arguments, title):
        """Stage credentials, persist verified identities, and report actual errors.

        A failed optional sshd policy change must not be reported as a failed
        connection registration when public-key authentication already worked.
        """
        try:
            # Keep an encrypted recovery snapshot BEFORE attempting remote
            # revocation. If backup validation fails, do not touch the server.
            if arguments and arguments[0] == 'delete':
                current_store().backup_verified()
            with backend_stage(current_store()) as stage:
                diag_file = stage / 'operation-diagnostics.txt'
                save_file(diag_file, b'')  # Only private temp storage; cleaned after operation.
                env = os.environ.copy()
                env['SSH_VAULT_WORKDIR'] = str(stage)
                env['SSH_VAULT_DIAGNOSTIC_FILE'] = str(diag_file)
                previous = set(current_store().data['servers'])
                status = self.run_external(['bash', str(BACKEND)] + arguments, title,
                                           pause=False, env=env)
                # SSH authorization may succeed while an OPTIONAL sshd change fails.
                updated = changed_payload(current_store(), stage)
                saved = updated != current_store().data
                if saved:
                    current_store().save(updated)
                new_servers = sorted(set(updated['servers']) - previous)
                try:
                    details = diag_file.read_text(encoding='utf-8', errors='replace').strip()
                except OSError:
                    details = ''
                self.reload()
            if status == 0:
                headline = 'OPERATION COMPLETE'
                message = title + ' completed successfully.'
            elif new_servers and arguments[0] == 'create' and arguments[-1] == 'no':
                headline = 'CONNECTION SAVED / SSHD CHANGE FAILED'
                message = ('Key authentication was verified and the new connection was '
                           'saved in the encrypted vault. The optional change to SSH '
                           'password authentication did not complete.')
            else:
                headline = 'OPERATION FAILED'
                message = (title + ' failed (exit code ' + str(status) + '). '
                           + ('No new connection was stored.' if not saved else
                              'Verified changes were saved in the encrypted vault.'))
            if details:
                # Show details in curses instead of immediately clearing stderr.
                message += '\n\nDetails: ' + details[-1700:]
            elif status != 0:
                message += ('\n\nThe server could not be reached, refused authentication, '
                            'or the remote command failed. Check IP, port, account, '
                            'SSH login permissions and server console.')
            self.popup(headline, message)
            return status
        except (VaultError, OSError, ValueError, subprocess.CalledProcessError) as error:
            self.popup('VAULT UPDATE ERROR', str(error))
            return 1

    def create(self):
        self.notice = ""
        alias = self.prompt("NEW CONNECTION · 1/4", "Name / alias (letters, digits, - and _):")
        if alias is None:
            return
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", alias):
            self.popup("INVALID INPUT", "Invalid alias.")
            return
        if alias in [s.alias for s in self.servers]:
            self.popup("ALREADY EXISTS", "Alias already exists in config. Choose Edit.")
            return
        host = self.prompt("NEW CONNECTION · 2/4", "IP address or DNS hostname:")
        if host is None:
            return
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]*", host):
            self.popup("INVALID INPUT", "Invalid host/IP.")
            return
        user = self.prompt("NEW CONNECTION · 3/4", "Remote user:", last_remote_user())
        if user is None:
            return
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", user):
            self.popup("INVALID INPUT", "Invalid user.")
            return
        port = self.prompt("NEW CONNECTION · 4/4", "SSH port:", "22", max_chars=5)
        if port is None:
            return
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            self.popup("INVALID INPUT", "Invalid port (1-65535).")
            return
        if not self.confirm(
            "CREATE CONNECTION",
            f"{alias}  ·  {user}@{host}:{port}\n\n"
            "An Ed25519 key will be generated and authorized on the remote host.",
            yes_label="Y · CREATE", no_label="N · CANCEL"
        ):
            return
        # Both answers continue creation. NO preserves remote sshd settings.
        disable_password = self.confirm(
            "PASSWORD LOGIN (OPTIONAL)",
            "After the new key works, disable SSH password login?\n"
            "YES: Disable passwords for ALL SSH users on this server.\n"
            "NO: Keep the current password setting; still create the key.\n"
            "Esc: Cancel creating this connection.",
            yes_label="Y · DISABLE", no_label="N · KEEP PASSWORD",
            allow_cancel=True
        )
        if disable_password is None:
            return
        mode = "no" if disable_password else "keep"
        self.run_backend(["create", alias, host, user, port, mode], "CREATE CONNECTION")
        self.reload(alias)
        # Store the most recently registered user only if the connection was
        # actually saved. The key may be saved even if changing remote sshd
        # settings subsequently failed; do not lose that successful registration.
        if any(server.alias == alias for server in self.servers):
            try:
                remember_remote_user(user)
            except (OSError, ValueError) as exc:
                self.notice = f"Connection saved, but UI preference was not: {exc}"

    def edit(self):
        s = self.selected()
        if not s:
            return
        selection = self.menu("EDIT SERVER", [
            "Change name / alias",
            "Change IP / hostname",
            "Change remote user",
            "Change SSH port",
            "Disable SSH password login (entire server)",
            "Enable SSH password login (entire server)",
            "Adopt legacy remote key (one authorization only)",
            "Verify managed remote key",
        ], details=f"{s.alias}  ·  {s.user}@{s.host}:{s.port}")
        if selection is None:
            return
        if selection == 0:
            value = self.prompt("CHANGE ALIAS", "New alias:", s.alias)
            if value is None or value == s.alias:
                return
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]*", value):
                self.popup("ERROR", "Invalid alias.")
                return
            self.run_backend(["rename", s.alias, value], "RENAME CONNECTION")
            self.reload(value)
        elif selection in (1, 2, 3):
            self.popup('SAFE TARGET CHANGE',
                       'Changing a remote host, user or port could leave an orphan '
                       'authorization on the old server.\n'
                       'To move securely: create and verify a NEW connection, '
                       'then Delete the old connection to revoke its remote key.')
            return
        elif selection in (4, 5):
            mode = "no" if selection == 4 else "yes"
            verbo = "DISABLE" if mode == "no" else "ENABLE"
            if not self.confirm("SERVER-WIDE SSHD CHANGE", f"{verbo} SSH password login on {s.host}?\nThis affects the ENTIRE server and requires remote sudo.", danger=True):
                return
            self.run_backend(["passwd", s.alias, mode], "CONFIGURE SSHD")
        elif selection == 6:
            if s.key_kind != 'LEGACY':
                self.popup('ALREADY TAGGED', 'This identity already has a Vault ownership marker.\nUse Verify Remote Key to inspect the authorization.')
                return
            if not self.confirm('ADOPT REMOTE KEY',
                                f'Adopt {s.alias} on {s.user}@{s.host}:{s.port}?\n'
                                'One unique matching authorized_keys entry is required.\n'
                                'Its restrictions and original comment will be preserved.\n'
                                'No unrelated key will be modified.', danger=True):
                return
            self.run_backend(['adopt', s.alias], 'ADOPT REMOTE KEY')
        elif selection == 7:
            self.run_backend(['verify', s.alias], 'VERIFY MANAGED REMOTE KEY')

    def delete(self):
        s = self.selected()
        if not s:
            return
        if s.key_kind != 'TAGGED':
            self.popup('ADOPTION REQUIRED',
                       'This imported key has no Vault ownership marker.\n'
                       'Open Edit / Adopt Remote Key first. No local or remote key was removed.')
            return
        if not self.confirm("DELETE CONNECTION", f"Delete '{s.alias}' and revoke its key on host {s.host}?\nThis cannot be undone; you could lose SSH access.", danger=True):
            return
        option = self.menu("DELETE SAFETY", [
            "Enable and verify remote password login first",
            "Keep password setting (risk of losing access)",
            "Cancel deletion",
        ], details="Recommended: enable and verify password login.")
        if option is None or option == 2:
            return
        if option == 1 and not self.confirm("FINAL CONFIRMATION", "Revoking this key could lock you out of SSH.\nConfirm that another authentication method works?", danger=True):
            return
        mode = "enable_password" if option == 0 else "keep_password"
        self.run_backend(["delete", s.alias, mode], "DELETE CONNECTION")

    def vault_menu(self):
        option = self.menu('VAULT MANAGEMENT', [
            'Import legacy keys/ now',
            'Export decrypted keys to NEW exported_keys/',
            'Change master password',
            'Lock vault and exit',
        ], details='Encrypted database is always the source of truth.')
        if option == 0:
            if not self.confirm('IMPORT LEGACY KEYS',
                                'Import verified keys from keys/?\n'
                                'Successfully imported pairs are removed AFTER\n'
                                'encrypted backup and round-trip verification.'):
                return
            try:
                report = migrate(current_store())
                self.reload()
                summary = ('Imported: ' + ', '.join(report['imported']) + '\n'
                           'Duplicates: ' + ', '.join(report['duplicates']) + '\n'
                           'Removed key pairs: ' + ', '.join(report['removed_keys']) + '\n'
                           'Preserved: ' + ', '.join(report['preserved'][:6]) + '\n'
                           'Problems: ' + '; '.join(report['problems'][:6]))
                self.popup('MIGRATION REPORT', summary)
            except (VaultError, OSError, ValueError) as error:
                self.popup('IMPORT FAILED', str(error))
        elif option == 1:
            if not self.confirm('EXPORT UNENCRYPTED IDENTITIES',
                                'Export private keys in plaintext to a NEW directory?\n'
                                'Never put exported_keys/ in Git. Existing exports stay intact.',
                                danger=True):
                return
            try:
                path = export_vault(current_store())
                self.popup('EXPORT COMPLETE', str(path))
            except (VaultError, OSError, ValueError) as error:
                self.popup('EXPORT FAILED', str(error))
        elif option == 2:
            if not self.confirm('CHANGE MASTER PASSWORD',
                                'A new encrypted vault and backup will be verified first.'):
                return
            try:
                new = password_form(self.win, create=True)
            finally:
                try:
                    curses.mousemask(0)
                except (curses.error, AttributeError):
                    pass
                self.disable_mouse()
                self.enable_mouse()
                self.win.keypad(False)
            if new is None:
                return
            try:
                current_store().change_password(new)
                self.popup('MASTER PASSWORD', 'Master password changed and encrypted vault verified.')
            except Exception as error:
                self.popup('PASSWORD UPDATE FAILED', str(error))
        elif option == 3:
            self.lock_requested = True

    def search(self):
        value = self.prompt("SEARCH CONNECTIONS", "Search alias, hostname or user:", self.query)
        if value is None:
            return
        self.query = value
        self.scroll = 0
        found = self.rows()
        if found:
            self.index = found[0]
        self.notice = f"Filter: {self.query or 'no filter'}"

    def help(self):
        self.popup('KEYBOARD & MOUSE',
                   'Click: select  ·  Double-click: connect\n'
                   'Right-click: server actions  ·  Wheel: one item per step\n'
                   'Up / Down or J / K: navigate\n'
                   'Enter/C: connect  ·  N: new  ·  E: edit  ·  D: delete\n'
                   '/: search  ·  R: reload  ·  H/?: help  ·  Q/Esc: quit\n'
                   'Tab: focus clickable buttons  ·  Enter: activate focus\n'
                   'Dialogs: Y/N, Tab, arrows, Enter, Esc or click\n'
                   'VAULT: identity protected in KDBX4 (not login status).\n'
                   'V: vault management · Auto-lock after 10 idle minutes.\n'
                   'Closing SSH returns here.')

    def move(self, delta):
        available = self.rows()
        if not available:
            return
        try:
            pos = available.index(self.index)
        except ValueError:
            pos = 0
        self.index = available[max(0, min(len(available) - 1, pos + delta))]

    def loop(self):
        while True:
            if getattr(self, 'lock_requested', False):
                break
            self.show()
            key = self.read_event()
            if key == -1:
                if time.monotonic() - self.last_activity >= 600:
                    self.notice = 'Vault locked after 10 minutes of inactivity.'
                    break
                continue
            self.last_activity = time.monotonic()
            if key == curses.KEY_RESIZE:
                self.win.clear()
                continue
            if isinstance(key, Mouse):
                if not self.handle_mouse(key):
                    break
                continue
            if key in (ord('q'), ord('Q'), 27):
                break
            if key in (9, getattr(curses, 'KEY_BTAB', -200)):
                self.focus_main_button(backward=(key != 9))
            elif key in (curses.KEY_UP, ord('k'), ord('K')):
                self.main_focus = None
                self.move(-1)
            elif key in (curses.KEY_DOWN, ord('j'), ord('J')):
                self.main_focus = None
                self.move(1)
            elif key == curses.KEY_HOME:
                self.main_focus = None
                if self.rows():
                    self.index = self.rows()[0]
            elif key == curses.KEY_END:
                self.main_focus = None
                if self.rows():
                    self.index = self.rows()[-1]
            elif key == curses.KEY_PPAGE:
                self.main_focus = None
                self.move(-10)
            elif key == curses.KEY_NPAGE:
                self.main_focus = None
                self.move(10)
            elif key in (10, 13, curses.KEY_ENTER):
                action = self.main_focus or 'connect'
                self.main_focus = None
                if not self.action(action):
                    break
            elif key in (ord('m'), ord('M')):
                if not self.action('menu'):
                    break
            elif key in (ord('c'), ord('C')):
                self.action('connect')
            elif key in (ord('n'), ord('N')):
                self.action('create')
            elif key in (ord('e'), ord('E')):
                self.action('edit')
            elif key in (ord('d'), ord('D')):
                self.action('delete')
            elif key in (ord('/'), ord('s'), ord('S')):
                self.action('search')
            elif key in (ord('v'), ord('V')):
                self.action('vault')
            elif key in (ord('r'), ord('R')):
                self.action('reload')
            elif key in (ord('?'), ord('h'), ord('H'), curses.KEY_F1):
                self.action('help')




def run(win):
    """Show initial vault entry and migration inside curses, before main launcher.

    ONLY an actual KDBX credential failure triggers another password prompt.
    Other failures must be reported, never silently interpreted as a bad password.
    """
    from pykeepass.exceptions import CredentialsError
    global ACTIVE_VAULT
    created = not KDBX.exists()
    warning = ''
    rejected = 0
    while True:
        password = password_form(win, create=created, previous_error=warning)
        if password is None:
            return
        store = VaultStore(password)
        try:
            if created:
                store.create()
            else:
                store.open()
        except CredentialsError:
            # KDBX authenticates deterministically: never tell users a general
            # read or integrity error means they typed the wrong password.
            if created:
                report_screen(win, 'VAULT CREATION FAILED',
                              ['The newly-created vault could not be verified.',
                               'No existing vault was overwritten.'])
                return
            rejected += 1
            warning = ('Vault rejected the entered password (attempt %d). '
                       'Check keyboard layout and Caps Lock.' % rejected)
            continue
        except Exception as error:
            # Includes corrupted KDBX, file access errors, schema validation,
            # memory exhaustion, and other library errors. Re-entering the same
            # secret cannot be assumed to repair any of these conditions.
            report_screen(win, 'VAULT CREATION FAILED' if created else 'VAULT OPEN ERROR', [
                '%s: %s' % (type(error).__name__, str(error)),
                'This is NOT confirmed to be a wrong master password.',
                'Your existing encrypted vault has not been replaced.',
                'Preserve vault.kdbx and its backups for diagnosis.',
            ])
            return
        ACTIVE_VAULT = store
        break
    if INBOX.exists():
        try:
            report = migrate(current_store())
            details = [
                f"Imported connections: {len(report['imported'])}",
                f"Existing identical connections: {len(report['duplicates'])}",
                f"Verified key pairs removed from keys/: {len(report['removed_keys'])}",
                f"Unimported files preserved: {len(report['preserved'])}",
                f"Import problems: {len(report['problems'])}",
            ]
            details += [''] + ['Imported: ' + a for a in report['imported']]
            details += ['Preserved: ' + p for p in report['preserved']]
            details += ['Problem: ' + p for p in report['problems']]
            if report['backup']:
                details.append('Verified encrypted backup: ' + report['backup'])
            report_screen(win, 'LEGACY IMPORT REPORT', details)
        except (VaultError, OSError, ValueError, Exception) as error:
            report_screen(win, 'IMPORT ERROR', [str(error),
                'Legacy keys were not deleted unless individually verified.',
                'Check keys/ before retrying.'])
            return
    win.erase()
    launcher = Launcher(win)
    try:
        launcher.loop()
    finally:
        launcher.disable_mouse()


def main() -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print('SSH Vault requires an interactive terminal.', file=sys.stderr)
        return 2
    for cmd in ('ssh', 'ssh-keygen', 'ssh-agent', 'ssh-add'):
        if not shutil.which(cmd):
            print(f'Missing required OpenSSH utility: {cmd}', file=sys.stderr)
            return 2
    os.umask(0o077)
    try:
        initialize_storage()
        from pykeepass import PyKeePass
    except (ImportError, VaultError, OSError) as error:
        print('SSH Vault startup error: ' + str(error), file=sys.stderr)
        return 2
    try:
        curses.wrapper(run)
    except KeyboardInterrupt:
        pass
    except Exception as error:
        print(f'\nLauncher error: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
