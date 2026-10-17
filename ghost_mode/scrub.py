"""Line-oriented scrubber with just enough state to cover PEM private keys."""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import List, Mapping, Optional, Tuple

from .rules import (
    ANSI,
    BEGIN_KEY,
    END_KEY,
    MIN_ENV_SECRET_LEN,
    PII_RULES,
    PRIVATE_KEY_RULE,
    SECRET_NAME,
    SECRET_RULES,
    plausible_secret,
)


@dataclass(frozen=True)
class Options:
    pii: bool = False
    strip_ansi: bool = False
    use_env: bool = True
    home: bool = True
    extra_literals: Tuple[str, ...] = ()


@dataclass(frozen=True)
class Finding:
    """Where and what, never the secret itself."""

    line: int
    rule: str
    kind: str  # "secret" or "privacy"


@dataclass(frozen=True)
class _Literal:
    name: str
    kind: str


# (start, end, rule name, kind, secret text)
_Span = Tuple[int, int, str, str, str]


class Scrubber:
    def __init__(self, options: Optional[Options] = None, env: Optional[Mapping[str, str]] = None,
                 home: Optional[str] = None):
        self.options = options or Options()
        self.findings: List[Finding] = []
        self._line = 0
        self._in_key = False
        self._rules = SECRET_RULES + (PII_RULES if self.options.pii else ())
        self._literals = self._build_literals(env, home)
        self._literal_re = (
            re.compile("|".join(re.escape(v) for v in sorted(self._literals, key=len, reverse=True)))
            if self._literals else None
        )

    def _build_literals(self, env, home) -> dict:
        found: dict = {}
        for value in self.options.extra_literals:
            if value:
                found[value] = _Literal("literal", "secret")
        if self.options.use_env:
            source = os.environ if env is None else env
            for name, value in source.items():
                if (len(value) >= MIN_ENV_SECRET_LEN and SECRET_NAME.search(name)
                        and plausible_secret(value)):
                    found.setdefault(value, _Literal(f"env:{name}", "secret"))
        if self.options.home:
            path = home if home is not None else os.path.expanduser("~")
            if len(path) > 1:
                found.setdefault(path, _Literal("home-path", "privacy"))
        return found

    # ---- public API -------------------------------------------------

    def scrub_line(self, line: str) -> str:
        self._line += 1
        if self.options.strip_ansi:
            line = ANSI.sub("", line)
        if self._in_key:
            return self._continue_key(line)
        begin = BEGIN_KEY.search(line)
        if not begin:
            return self._scrub_text(line)
        return self._start_key(line, begin)

    # ---- private keys -----------------------------------------------

    def _start_key(self, line: str, begin: "re.Match[str]") -> str:
        self._record(PRIVATE_KEY_RULE, "secret")
        head = self._scrub_text(line[: begin.start()])
        rest = line[begin.end():]
        end = END_KEY.search(rest)
        label = f"[REDACTED:{PRIVATE_KEY_RULE}]"
        if end:
            return head + label + self._scrub_text(rest[end.end():])
        self._in_key = True
        newline = "\r\n" if line.endswith("\r\n") else ("\n" if line.endswith("\n") else "")
        return head + label + newline

    def _continue_key(self, line: str) -> str:
        end = END_KEY.search(line)
        if not end:
            return ""
        self._in_key = False
        tail = line[end.end():]
        return self._scrub_text(tail) if tail.strip() else ""

    # ---- everything else --------------------------------------------

    def _scrub_text(self, text: str) -> str:
        view, index = text, None
        if "\x1b" in text:  # detect on the plain text so colour codes cannot split a secret
            view, index = _strip_with_index(text)
        spans = self._spans(view)
        if not spans:
            return text
        if index is not None:  # map back, so the redaction also swallows codes inside the secret
            spans = [(index[a], index[b - 1] + 1, n, k, sec) for a, b, n, k, sec in spans]
        out, cursor = [], 0
        for start, end, name, kind, secret in spans:
            out.append(text[cursor:start])
            out.append(self._label(name))
            self._record(name, kind)
            cursor = end
        out.append(text[cursor:])
        return "".join(out)

    def _spans(self, text: str) -> List[_Span]:
        found: List[_Span] = []
        for rule in self._rules:
            for m in rule.pattern.finditer(text):
                secret = m.group(rule.group)
                if secret is None or (rule.validate and not rule.validate(secret)):
                    continue
                found.append((m.start(rule.group), m.end(rule.group), rule.name, rule.kind, secret))
        if self._literal_re:
            for m in self._literal_re.finditer(text):
                lit = self._literals[m.group(0)]
                if lit.name == "home-path" and _continues_name(text, m.end()):
                    continue
                found.append((m.start(), m.end(), lit.name, lit.kind, m.group(0)))
        found.sort(key=lambda s: (s[0], -(s[1] - s[0])))
        merged: List[_Span] = []
        for span in found:
            if merged and span[0] < merged[-1][1]:
                prev = merged[-1]
                if span[1] > prev[1]:  # partial overlap: grow, so no tail is left in the clear
                    keep = span if prev[2] == "home-path" else prev
                    merged[-1] = (prev[0], span[1], keep[2], keep[3], keep[4])
                continue
            merged.append(span)
        return merged

    @staticmethod
    def _label(name: str) -> str:
        return "~" if name == "home-path" else f"[REDACTED:{name}]"

    def _record(self, rule: str, kind: str) -> None:
        self.findings.append(Finding(self._line, rule, kind))

    def counts(self) -> Tuple[int, int]:
        secrets = sum(1 for f in self.findings if f.kind == "secret")
        return secrets, len(self.findings) - secrets


def _strip_with_index(text: str) -> Tuple[str, List[int]]:
    """Remove ANSI sequences; index[i] is the original offset of stripped char i."""
    parts: List[str] = []
    index: List[int] = []
    pos = 0
    for m in ANSI.finditer(text):
        parts.append(text[pos:m.start()])
        index.extend(range(pos, m.start()))
        pos = m.end()
    parts.append(text[pos:])
    index.extend(range(pos, len(text)))
    return "".join(parts), index


def _continues_name(text: str, end: int) -> bool:
    return end < len(text) and (text[end].isalnum() or text[end] in "_-")
