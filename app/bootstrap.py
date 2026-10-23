#!/usr/bin/env python3
"""Dependency bootstrap, with a small curses screen and actionable failure output.

This module uses the Python standard library only. No secrets are accepted here.
All application dependencies are installed in the project's isolated .venv.
"""
from __future__ import annotations

from collections import deque
import curses
import os
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parent.parent
APP = ROOT / 'app'
VENV = ROOT / '.venv'
REQUIREMENTS = APP / 'requirements.txt'


def dependency_ready(python):
    code = ('import importlib.metadata as m; '
            'assert m.version("pykeepass") == "4.2.0"; '
            'from pykeepass import PyKeePass, create_database')
    try:
        return subprocess.run([str(python), '-c', code], timeout=12,
                              stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def prepare(status, log):
    """Return Python executable and avoid touching existing vault data."""
    venv_python = VENV / 'bin' / 'python'
    if venv_python.is_file() and dependency_ready(venv_python):
        status.put(('status', 'Encrypted vault support is ready'))
        return venv_python
    if dependency_ready(sys.executable):
        status.put(('status', 'Existing Python vault support is ready'))
        return Path(sys.executable)
    if not venv_python.is_file():
        status.put(('status', 'Creating an isolated Python environment'))
        execute([sys.executable, '-m', 'venv', str(VENV)], log)
    status.put(('status', 'Installing encrypted vault support'))
    execute([str(venv_python), '-m', 'pip', 'install', '--no-input',
             '--disable-pip-version-check', '-r', str(REQUIREMENTS)], log)
    status.put(('status', 'Verifying encrypted vault libraries'))
    if not dependency_ready(venv_python):
        raise RuntimeError('pykeepass could not be verified after installation')
    return venv_python


def execute(argv, log):
    try:
        result = subprocess.run(argv, cwd=ROOT, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, errors='replace', timeout=300)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError('Dependency setup timed out') from exc
    except OSError as exc:
        raise RuntimeError(f'Could not start dependency installer: {exc}') from exc
    if result.stdout:
        log.extend(result.stdout.splitlines())
    if result.returncode:
        raise RuntimeError(f'Dependency setup failed (exit {result.returncode})')


def draw(win, label, error=None, details=(), frame=0):
    win.erase()
    h, w = win.getmaxyx()
    if h < 8 or w < 32:
        try:
            win.addnstr(0, 0, 'SSH VAULT - enlarge terminal', max(1, w - 1))
            win.refresh()
        except curses.error:
            pass
        return
    left = max(1, (w - min(w - 4, 76)) // 2)
    width = min(w - 4, 76)
    top = max(1, (h - 13) // 2)
    cyan = curses.color_pair(1) if curses.has_colors() else curses.A_BOLD
    dim = curses.color_pair(2) if curses.has_colors() else curses.A_DIM
    good = curses.color_pair(3) if curses.has_colors() else curses.A_BOLD
    try:
        win.addnstr(top, left + 2, 'SSH VAULT  /  SECURE STARTUP', width - 4, cyan | curses.A_BOLD)
        win.hline(top + 2, left, curses.ACS_HLINE, width)
        win.addnstr(top + 4, left + 2, ('!' if error else '|/-\\'[frame % 4]) + '  ' + label, width - 4, good if not error else curses.A_BOLD)
        if error:
            for n, line in enumerate(list(details)[-min(max(1, h - top - 9), 5):]):
                win.addnstr(top + 6 + n, left + 2, line.strip()[:width - 4], width - 4, dim)
            win.addnstr(min(h - 2, top + 12), left + 2, 'Press Enter or Esc to exit', width - 4, cyan)
        else:
            win.addnstr(top + 7, left + 2, 'Initializing SSH Vault without exposing installation logs.', width - 4, dim)
            win.addnstr(top + 9, left + 2, 'Private keys and vault files are not touched during setup.', width - 4, dim)
        win.refresh()
    except curses.error:
        pass


def interactive_bootstrap(win):
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    curses.noecho()
    win.nodelay(True)
    win.keypad(True)
    if curses.has_colors():
        curses.start_color()
        try:
            curses.use_default_colors()
        except curses.error:
            pass
        for n, color in [(1, curses.COLOR_CYAN), (2, curses.COLOR_WHITE), (3, curses.COLOR_GREEN)]:
            try:
                curses.init_pair(n, color, -1)
            except curses.error:
                pass
    events = queue.Queue()
    log = deque(maxlen=60)
    def worker():
        try:
            events.put(('done', prepare(events, log)))
        except Exception as exc:
            events.put(('failed', str(exc)))
    threading.Thread(target=worker, daemon=True).start()
    phase = 'Checking encrypted vault requirements'
    frame = 0
    while True:
        try:
            while True:
                event, value = events.get_nowait()
                if event == 'status':
                    phase = value
                elif event == 'done':
                    draw(win, 'Vault runtime is ready', frame=frame)
                    return str(value)
                else:
                    draw(win, value, error=True, details=log, frame=frame)
                    win.nodelay(False)
                    while True:
                        key = win.getch()
                        if key in (10, 13, 27, ord('q'), ord('Q')):
                            return None
        except queue.Empty:
            pass
        draw(win, phase, frame=frame)
        frame += 1
        time.sleep(0.12)


def main():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print('SSH Vault requires an interactive terminal.', file=sys.stderr)
        return 2
    python = curses.wrapper(interactive_bootstrap)
    if not python:
        return 2
    os.execv(python, [python, str(APP / 'launcher.py'), *sys.argv[1:]])


if __name__ == '__main__':
    raise SystemExit(main())
