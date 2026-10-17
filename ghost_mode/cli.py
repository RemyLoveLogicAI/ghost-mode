"""ghost: scrub secrets from terminal output before it is shared."""
from __future__ import annotations

import argparse
import io
import os
import shutil
import subprocess
import sys
from typing import Iterator, List, Optional, Sequence

from . import __version__
from .rules import rule_names
from .scrub import Options, Scrubber

EXIT_FOUND = 1
EXIT_NOT_FOUND = 127
EXIT_USAGE = 2


def _decode(raw: bytes) -> str:
    return raw.decode("utf-8", "replace")


def _binary_lines(stream) -> Iterator[str]:
    for raw in iter(stream.readline, b""):
        yield _decode(raw)


_unreadable = 0  # unreadable inputs must fail closed: a missing file is not a clean file


def _sources(paths: Sequence[str]) -> Iterator[tuple]:
    """Yield (display name, line iterator) for each input; "-" or no paths means stdin."""
    global _unreadable
    for path in paths or ["-"]:
        if path == "-":
            yield "<stdin>", _binary_lines(sys.stdin.buffer)
            continue
        try:
            fh = open(path, "rb")
        except OSError as exc:
            print(f"ghost: {path}: {exc.strerror}", file=sys.stderr)
            _unreadable += 1
            continue
        with fh:
            yield path, _binary_lines(fh)


def _options(args: argparse.Namespace) -> Options:
    return Options(
        pii=args.pii,
        strip_ansi=args.strip_ansi,
        use_env=not args.no_env,
        home=not args.no_home,
        extra_literals=tuple(args.literal or ()),
    )


def _write(text: str) -> None:
    sys.stdout.buffer.write(text.encode("utf-8", "replace"))
    sys.stdout.buffer.flush()


def _summary(scrubber: Scrubber) -> str:
    secrets, privacy = scrubber.counts()
    return f"ghost: redacted {secrets} secret(s), {privacy} privacy item(s)"


# ---- commands --------------------------------------------------------


def cmd_scrub(args) -> int:
    scrubber = Scrubber(_options(args))
    for _name, lines in _sources(args.files):
        for line in lines:
            _write(scrubber.scrub_line(line))
    if args.report:
        print(_summary(scrubber), file=sys.stderr)
    return EXIT_USAGE if _unreadable else 0


def cmd_scan(args) -> int:
    found = 0
    for name, lines in _sources(args.files):
        scrubber = Scrubber(_options(args))
        for line in lines:
            scrubber.scrub_line(line)
        for f in scrubber.findings:
            if f.kind == "secret":
                print(f"{name}:{f.line}: {f.rule}")
                found += 1
    if found:
        return EXIT_FOUND
    return EXIT_USAGE if _unreadable else 0


def cmd_rules(args) -> int:
    print("\n".join(rule_names()))
    return 0


def _emit_lines_from_fd(fd: int, scrubber: Scrubber) -> None:
    buf = b""
    while True:
        try:
            chunk = os.read(fd, 4096)
        except OSError:  # EIO once the child closes its side of the pty
            break
        if not chunk:
            break
        buf += chunk
        while (i := buf.find(b"\n")) >= 0:
            line, buf = buf[: i + 1], buf[i + 1:]
            _write(scrubber.scrub_line(_decode(line)))
    if buf:
        _write(scrubber.scrub_line(_decode(buf)))


def _run_pty(argv: List[str], scrubber: Scrubber) -> int:
    import pty

    master, slave = pty.openpty()
    try:
        proc = subprocess.Popen(argv, stdin=None, stdout=slave, stderr=slave, close_fds=True)
    finally:
        os.close(slave)
    try:
        _emit_lines_from_fd(master, scrubber)
    finally:
        os.close(master)
    return proc.wait()


def _run_pipe(argv: List[str], scrubber: Scrubber) -> int:
    proc = subprocess.Popen(argv, stdin=None, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for line in _binary_lines(proc.stdout):
        _write(scrubber.scrub_line(line))
    return proc.wait()


def cmd_run(args) -> int:
    argv = args.command[1:] if args.command[:1] == ["--"] else list(args.command)
    if not argv:
        print("ghost run: no command given (use: ghost run -- <command>)", file=sys.stderr)
        return EXIT_USAGE
    scrubber = Scrubber(_options(args))
    try:
        if args.pty and os.name == "posix":
            code = _run_pty(argv, scrubber)
        else:
            code = _run_pipe(argv, scrubber)
    except FileNotFoundError:
        print(f"ghost: command not found: {argv[0]}", file=sys.stderr)
        return EXIT_NOT_FOUND
    except KeyboardInterrupt:
        return 130
    if args.report:
        print(_summary(scrubber), file=sys.stderr)
    return 128 - code if code < 0 else code


def _clipboard_tools() -> Optional[tuple]:
    pairs = (
        (["pbpaste"], ["pbcopy"]),
        (["wl-paste"], ["wl-copy"]),
        (["xclip", "-o", "-selection", "clipboard"], ["xclip", "-selection", "clipboard"]),
    )
    for paste, copy in pairs:
        if shutil.which(paste[0]) and shutil.which(copy[0]):
            return paste, copy
    return None


def cmd_clip(args) -> int:
    tools = _clipboard_tools()
    if not tools:
        print("ghost clip: no clipboard tool found (pbpaste/pbcopy, wl-clipboard or xclip)", file=sys.stderr)
        return EXIT_USAGE
    paste, copy = tools
    pasted = subprocess.run(paste, capture_output=True, check=False)
    if pasted.returncode != 0:
        print("ghost clip: could not read the clipboard", file=sys.stderr)
        return EXIT_USAGE
    scrubber = Scrubber(_options(args))
    cleaned = "".join(scrubber.scrub_line(l) for l in io.StringIO(_decode(pasted.stdout), newline=""))
    if subprocess.run(copy, input=cleaned.encode("utf-8"), check=False).returncode != 0:
        print("ghost clip: could not write the clipboard", file=sys.stderr)
        return EXIT_USAGE
    print(_summary(scrubber), file=sys.stderr)
    return 0


# ---- argument parsing ------------------------------------------------


def _common() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--pii", action="store_true", help="also redact emails")
    p.add_argument("--strip-ansi", action="store_true", help="remove ANSI escape sequences")
    p.add_argument("--no-env", action="store_true", help="do not scrub values of secret-looking environment variables")
    p.add_argument("--no-home", action="store_true", help="keep the home directory path")
    p.add_argument("--literal", action="append", metavar="TEXT", help="always redact this exact text (repeatable)")
    return p


def build_parser() -> argparse.ArgumentParser:
    common = _common()
    parser = argparse.ArgumentParser(prog="ghost", description=__doc__)
    parser.add_argument("--version", action="version", version=f"ghost-mode {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scrub", parents=[common], help="scrub files or stdin to stdout")
    p.add_argument("files", nargs="*")
    p.add_argument("--report", action="store_true", help="print a count summary to stderr")
    p.set_defaults(func=cmd_scrub)

    p = sub.add_parser("scan", parents=[common], help="list findings as file:line: rule; exit 1 if any secret")
    p.add_argument("files", nargs="*")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("run", parents=[common], help="run a command and scrub its output live")
    p.add_argument("--pty", action="store_true", help="run under a pseudo-terminal so colors and tty behaviour survive")
    p.add_argument("--report", action="store_true", help="print a count summary to stderr")
    p.add_argument("command", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_run)

    p = sub.add_parser("clip", parents=[common], help="scrub the clipboard in place")
    p.set_defaults(func=cmd_clip)

    p = sub.add_parser("rules", help="list detection rule names")
    p.set_defaults(func=cmd_rules)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    global _unreadable
    _unreadable = 0
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        return 0


if __name__ == "__main__":
    sys.exit(main())
