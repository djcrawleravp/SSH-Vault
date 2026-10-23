"""Keyboard-first, mouse-aware, no-dependency curses vault entry screens.

No master password is ever printed, logged, or placed on command lines.
"""
from __future__ import annotations

import curses


def colors():
    if curses.has_colors():
        curses.start_color()
        try:
            curses.use_default_colors()
        except curses.error:
            pass
        for n, foreground, background in (
            (1, curses.COLOR_CYAN, -1),
            (2, curses.COLOR_WHITE, -1),
            (3, curses.COLOR_BLACK, curses.COLOR_CYAN),
            (4, curses.COLOR_YELLOW, -1),
            (5, curses.COLOR_GREEN, -1),
        ):
            try:
                curses.init_pair(n, foreground, background)
            except curses.error:
                pass


def style(n):
    return curses.color_pair(n) if curses.has_colors() else curses.A_BOLD


def put(win, y, x, content, max_width, attr=0):
    h, w = win.getmaxyx()
    if not (0 <= y < h and 0 <= x < w and max_width > 0):
        return
    try:
        win.addnstr(y, x, content, min(max_width, w - x - 1), attr)
    except curses.error:
        pass


def screen(win, title, subtitle, fields, selected, message='', busy=False, reveal=False):
    win.erase()
    h, w = win.getmaxyx()
    if w < 48 or h < 19:
        put(win, 0, 0, 'SSH VAULT / Resize terminal (min 48x19)', w - 1, style(1))
        win.refresh()
        return None
    width = min(w - 6, 72)
    left = (w - width) // 2
    top = max(1, (h - 19) // 2)
    put(win, top, left + 1, 'SSH VAULT  /  ENCRYPTED IDENTITY MANAGER', width - 2, style(1) | curses.A_BOLD)
    try:
        win.hline(top + 2, left, curses.ACS_HLINE, width)
    except curses.error:
        pass
    put(win, top + 4, left + 2, title, width - 4, style(1) | curses.A_BOLD)
    put(win, top + 5, left + 2, subtitle, width - 4, curses.A_DIM)
    positions = []
    for i, (label, value) in enumerate(fields):
        y = top + 7 + i * 3
        put(win, y, left + 2, f'{label}  ({len(value)} characters)', width - 4, style(2))
        width_field = width - 6
        attr = style(3) if selected == i else style(2)
        put(win, y + 1, left + 2, ' ' * width_field, width_field, attr)
        display = (value if reveal else ('*' * len(value)))
        display = display[-max(1, width_field - 3):]
        put(win, y + 1, left + 3, display, width_field - 2, attr)
        positions.append((left + 2, y + 1, width_field))
    button_y = top + 7 + len(fields) * 3 + 1
    primary = '[ CREATE VAULT ]' if len(fields) == 2 else '[ UNLOCK VAULT ]'
    if busy:
        primary = '[ WORKING ... ]'
    x_primary, x_cancel = left + 2, left + 2 + len(primary) + 4
    put(win, button_y, x_primary, primary, len(primary), style(3) if selected == len(fields) else style(1))
    put(win, button_y, x_cancel, '[ EXIT ]', 8, style(3) if selected == len(fields) + 1 else style(1))
    if message:
        put(win, min(h - 3, button_y + 2), left + 2, message, width - 4, style(4))
    put(win, h - 2, left + 2, 'Tab: next | Enter: confirm | Ctrl-R: show/hide | Esc: exit', width - 4, curses.A_DIM)
    win.refresh()
    return positions, (x_primary, x_primary + len(primary), button_y), (x_cancel, x_cancel + 8, button_y)


def password_form(win, create, previous_error=''):
    """Password entry in curses; Esc returns None and does not alter vault."""
    colors()
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    curses.noecho()
    win.keypad(True)
    try:
        curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
    except (AttributeError, curses.error):
        try:
            curses.mousemask(curses.ALL_MOUSE_EVENTS)
        except curses.error:
            pass
    fields = [('Master password', '')]
    if create:
        fields.append(('Confirm master password', ''))
    selected = 0
    error = previous_error
    reveal = False
    # Do not accept terminal mouse reporting as password characters.
    while True:
        layout = screen(win,
                        'CREATE YOUR ENCRYPTED VAULT' if create else 'UNLOCK SSH VAULT',
                        'Use a unique password of at least 12 characters.' if create
                        else 'Enter your master password to unlock your identities.',
                        fields, selected, error, reveal=reveal)
        try:
            key = win.get_wch()
        except curses.error:
            continue
        if isinstance(key, int) and key == curses.KEY_RESIZE:
            continue
        # macOS/Linux/FreeBSD may send KEY_MOUSE or keypad variants.
        # Neither is a password character.
        if isinstance(key, int) and key == curses.KEY_MOUSE and not layout:
            continue
        if key == '\x12':  # Ctrl-R: explicit, temporary password visibility
            reveal = not reveal
            continue
        if layout is None and key not in ('\x1b', 27, '\x03'):
            continue  # Never accept invisible password input in a tiny terminal.
        if isinstance(key, int) and key == curses.KEY_MOUSE and layout:
            try:
                _, x, y, _, _ = curses.getmouse()
            except curses.error:
                continue
            positions, primary, cancel = layout
            for i, (fx, fy, fw) in enumerate(positions):
                if y == fy and fx <= x < fx + fw:
                    selected = i
                    break
            else:
                if y == primary[2] and primary[0] <= x < primary[1]:
                    selected = len(fields)
                    key = '\n'
                elif y == cancel[2] and cancel[0] <= x < cancel[1]:
                    return None
                else:
                    continue
        if key in ('\x1b', 27, '\x03'):
            return None
        if key in (curses.KEY_UP, curses.KEY_DOWN):
            selected = (selected + (-1 if key == curses.KEY_UP else 1)) % (len(fields) + 2)
            continue
        if key in ('\t', 9, getattr(curses, 'KEY_BTAB', -200)):
            delta = -1 if key == getattr(curses, 'KEY_BTAB', -200) else 1
            selected = (selected + delta) % (len(fields) + 2)
            continue
        if key in ('\n', '\r', 10, 13, curses.KEY_ENTER):
            if selected == len(fields) + 1:
                return None
            if selected < len(fields) - 1:
                selected += 1
                continue
            first = fields[0][1]
            if create and (len(first) < 12 or first != fields[1][1]):
                error = ('Passwords must match and have at least 12 characters.'
                         if first != fields[1][1] else 'At least 12 characters are required.')
                selected = 0
                fields = [(label, '') for label, _ in fields]
                continue
            if not first:
                error = 'Master password cannot be empty.'
                selected = 0
                continue
            screen(win, 'SECURING VAULT', 'Encrypting and verifying your identities...',
                   [(label, '') for label, _ in fields], len(fields),
                   'Please do not close the terminal.', busy=True)
            return first
        if selected >= len(fields):
            if key in (curses.KEY_LEFT, curses.KEY_RIGHT):
                selected = len(fields) if selected == len(fields) + 1 else len(fields) + 1
            continue
        label, val = fields[selected]
        if key in ('\x7f', '\b', 127, 8, curses.KEY_BACKSPACE,
                   getattr(curses, 'KEY_DC', -300), getattr(curses, 'KEY_DL', -301)):
            fields[selected] = (label, val[:-1])
            error = ''
        elif key in ('\x15', '\x17'):  # Ctrl-U / Ctrl-W clear text
            fields[selected] = (label, '')
        elif isinstance(key, str) and len(key) == 1 and key.isprintable() and len(val) < 512:
            fields[selected] = (label, val + key)
            error = ''


def report_screen(win, title, lines):
    """Small modal for first-run errors and migration details."""
    colors()
    win.keypad(True)
    offset = 0
    entries = [str(x) for x in lines]
    while True:
        win.erase()
        h, w = win.getmaxyx()
        width = min(max(w - 4, 1), 94)
        left = max(1, (w - width) // 2)
        put(win, 1, left, 'SSH VAULT  /  ' + title, width, style(1) | curses.A_BOLD)
        available = max(1, h - 7)
        for i, line in enumerate(entries[offset:offset + available]):
            put(win, 3 + i, left + 1, line, width - 2, style(2))
        put(win, h - 2, left + 1, '[ CONTINUE ]  Enter / Esc   |   Up / Down: scroll', width - 2, style(1))
        win.refresh()
        key = win.getch()
        if key in (10, 13, 27, ord(' '), ord('q')):
            return
        if key == curses.KEY_MOUSE:
            try:
                _, mx, my, _, state = curses.getmouse()
                if my == h - 2 and left <= mx < left + width:
                    return
            except curses.error:
                pass
        if key in (curses.KEY_UP, ord('k')):
            offset = max(0, offset - 1)
        elif key in (curses.KEY_DOWN, ord('j')):
            offset = min(max(0, len(entries) - available), offset + 1)
