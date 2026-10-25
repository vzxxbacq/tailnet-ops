"""Prompts for the terminal: a menu moved with the arrow keys, a line of text, yes or no.

In a terminal the menu redraws in place and folds into one line once chosen. Without one
(a pipe, a test) every prompt falls back to a plain numbered question.
"""

import os
import select as _select
import sys

KEYS = {b"[A": "up", b"OA": "up", b"[B": "down", b"OB": "down"}


def menu_key(index, key, count):
    """(new index, chosen?) for a key in a menu of count items. Raises KeyboardInterrupt on escape."""
    if key in ("up", "k"):
        return (index - 1) % count, False
    if key in ("down", "j"):
        return (index + 1) % count, False
    if key == "enter":
        return index, True
    if key.isdigit() and 1 <= int(key) <= count:
        return int(key) - 1, True
    if key in ("esc", "q"):
        raise KeyboardInterrupt
    return index, False


class UI:
    def __init__(self, inp=None, out=None, tty=None):
        self.inp = inp or sys.stdin
        self.out = out or sys.stdout
        if tty is None:
            tty = self.inp.isatty() and self.out.isatty()
        self.tty = tty
        self.color = tty and not os.environ.get("NO_COLOR")

    # --- output ---------------------------------------------------------------------

    def _style(self, text, code):
        return f"\x1b[{code}m{text}\x1b[0m" if self.color else text

    def bold(self, text):
        return self._style(text, "1")

    def dim(self, text):
        return self._style(text, "2")

    def accent(self, text):
        return self._style(text, "36")

    def _write(self, text):
        self.out.write(text)
        self.out.flush()

    def note(self, text):
        self._write(f"  {self.dim(text)}\n")

    def say(self, text=""):
        self._write(f"{text}\n")

    def warn(self, text):
        self._write(f"{self._style('!', '33')} {self.bold(text)}\n")

    def command(self, text):
        """A command to copy: on its own line, indented, nothing else on it."""
        self._write(f"\n    {text}\n\n")

    def _done(self, title, answer):
        self._write(f"{self.accent('✔')} {self.bold(title)} {self.accent(answer)}\n")

    # --- input ----------------------------------------------------------------------

    def _line(self, prompt):
        self._write(prompt)
        line = self.inp.readline()
        if not line:
            raise KeyboardInterrupt
        return line.strip()

    def text(self, title, default=None, check=None):
        hint = f" {self.dim(f'({default})')}" if default else ""
        for _ in range(3):
            answer = self._line(f"{self.accent('?')} {self.bold(title)}{hint} ") or (default or "")
            problem = check(answer) if check else (None if answer else "an answer is needed")
            if problem is None:
                return answer
            self._write(f"  {problem}\n")
        raise ValueError(f"no valid answer for: {title}")

    def secret(self, title, check=None):
        """A line typed or pasted without echo, such as a link code."""
        import getpass

        for _ in range(3):
            prompt = f"{self.accent('?')} {self.bold(title)} {self.dim('(hidden, paste and press Enter)')} "
            if self.tty:
                answer = getpass.getpass(prompt, stream=self.out).strip()
            else:
                answer = self._line(prompt)
            problem = check(answer) if check else (None if answer else "an answer is needed")
            if problem is None:
                self._done(title, "received")
                return answer
            self._write(f"  {problem}\n")
        raise ValueError(f"no valid answer for: {title}")

    def confirm(self, title, default=False):
        answer = self.text(f"{title} {'[Y/n]' if default else '[y/N]'}", "y" if default else "n",
                           check=lambda v: None if v.lower() in ("y", "yes", "n", "no") else "y or n")
        return answer.lower().startswith("y")

    def select(self, title, options, default=0):
        """options: [(value, label, hint)]. Returns the chosen value."""
        if not options:
            raise ValueError(f"nothing to choose for: {title}")
        index = self._keys(title, options, default) if self.tty else self._numbered(title, options, default)
        self._done(title, options[index][1])
        return options[index][0]

    def _rows(self, options, index):
        width = max(len(label) for _v, label, _h in options)
        rows = []
        for i, (_v, label, hint) in enumerate(options):
            mark = self.accent("❯") if i == index else " "
            text = label.ljust(width)
            rows.append(f"  {mark} {self.accent(text) if i == index else text}  {self.dim(hint or '')}".rstrip())
        return rows

    def _numbered(self, title, options, default):
        self._write(f"{self.accent('?')} {self.bold(title)}\n")
        width = max(len(label) for _v, label, _h in options)
        for i, (_v, label, hint) in enumerate(options, 1):
            self._write(f"  {i}. {label.ljust(width)}  {hint or ''}".rstrip() + "\n")
        answer = self.text("Choose", str(default + 1),
                           check=lambda v: None if v.isdigit() and 1 <= int(v) <= len(options)
                           else f"a number from 1 to {len(options)}")
        return int(answer) - 1

    def _read_key(self, fd):
        b = os.read(fd, 1)
        if b == b"\x1b":
            seq = b""
            while len(seq) < 2 and _select.select([fd], [], [], 0.05)[0]:
                seq += os.read(fd, 1)
            return KEYS.get(seq, "esc")
        if b in (b"\r", b"\n"):
            return "enter"
        return b.decode(errors="ignore")

    def _keys(self, title, options, index):
        import termios
        import tty

        fd = self.inp.fileno()
        saved = termios.tcgetattr(fd)
        drawn = 0
        self._write(f"{self.accent('?')} {self.bold(title)} {self.dim('↑/↓ to move, Enter to choose')}\n")
        try:
            tty.setcbreak(fd)
            self._write("\x1b[?25l")
            while True:
                rows = self._rows(options, index)
                self._write((f"\x1b[{drawn}F\x1b[J" if drawn else "") + "\n".join(rows) + "\n")
                drawn = len(rows)
                index, chosen = menu_key(index, self._read_key(fd), len(options))
                if chosen:
                    break
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
            self._write(f"\x1b[{drawn + 1}F\x1b[J\x1b[?25h")
        return index
