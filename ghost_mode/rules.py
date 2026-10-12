"""Detection rules. Each rule names the span of the secret to redact."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional, Pattern

_WORDS = (
    r"(?:SECRET|TOKEN|PASSWORD|PASSWD|PWD|API[_-]?KEY|PRIVATE[_-]?KEY|"
    r"ACCESS[_-]?KEY|AUTH|CREDENTIAL)"
)
SECRET_NAME = re.compile(_WORDS, re.IGNORECASE)

BEGIN_KEY = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
END_KEY = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")
ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")

MIN_ENV_SECRET_LEN = 8


def plausible_secret(value: str) -> bool:
    """False for values that are references or flags rather than secrets."""
    if value.startswith(("[REDACTED", "$", "${", "<", "%")):
        return False
    if value.isdigit() or value.lower() in {"true", "false", "null", "none", "yes", "no"}:
        return False
    return True


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: Pattern[str]
    group: int = 0
    kind: str = "secret"
    validate: Optional[Callable[[str], bool]] = None


def _rule(name: str, pattern: str, group: int = 0, kind: str = "secret",
          validate: Optional[Callable[[str], bool]] = None) -> Rule:
    return Rule(name, re.compile(pattern), group, kind, validate)


SECRET_RULES = (
    _rule("aws-access-key", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[A-Z0-9]{16}\b"),
    _rule("aws-secret-key", r"(?i)aws_?secret_?access_?key[\"'\s:=]+([A-Za-z0-9/+=]{40})\b", 1),
    _rule("github-token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
    _rule("gitlab-token", r"\bglpat-[A-Za-z0-9_-]{20,}\b"),
    _rule("slack-token", r"\bxox[abprso]-[A-Za-z0-9-]{10,}\b"),
    _rule("slack-webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"),
    _rule("stripe-key", r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    _rule("anthropic-key", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    _rule("openai-key", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}"),
    _rule("google-api-key", r"\bAIza[0-9A-Za-z_-]{35}\b"),
    _rule("huggingface-token", r"\bhf_[A-Za-z0-9]{30,}\b"),
    _rule("npm-token", r"\bnpm_[A-Za-z0-9]{36}\b"),
    _rule("sendgrid-key", r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
    _rule("twilio-key", r"\bSK[0-9a-f]{32}\b"),
    _rule("jwt", r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    _rule("bearer", r"(?i)\bBearer\s+([A-Za-z0-9._~+/=-]{16,})", 1, validate=plausible_secret),
    _rule("basic-auth", r"(?i)\bAuthorization\s{0,8}[=:]\s{0,8}Basic\s+([A-Za-z0-9+/]{8,512}={0,2})", 1),
    _rule(
        "curl-user",
        r"(?i)\bcurl\b[^\n|;&]{0,300}?\s(?:-u|--user)[ =]+[^\s:]{1,64}:(\S{4,256})",
        1,
        validate=plausible_secret,
    ),
    _rule("url-password", r"\b[a-z][a-z0-9+.-]{0,31}://[^\s:/@]{1,128}:([^\s@/]{1,256})@", 1, validate=plausible_secret),
    _rule(
        "json-secret",
        r"(?i)[\"'][\w.-]{0,64}" + _WORDS + r"[\w.-]{0,64}[\"']\s*:\s*[\"']([^\"'\s]{8,256})[\"']",
        1,
        validate=plausible_secret,
    ),
    _rule(
        "assignment",
        r"(?i)\b[\w.-]{0,64}" + _WORDS + r"[\w.-]{0,64}\s{0,8}[=:]\s{0,8}([^\s\"'`]{8,256})",
        1,
        validate=plausible_secret,
    ),
    _rule(
        "assignment",
        r"(?i)\b[\w.-]{0,64}" + _WORDS + r"[\w.-]{0,64}\s{0,8}[=:]\s{0,8}([\"'])((?:(?!\1)[^\n]){8,256})\1",
        2,
        validate=plausible_secret,
    ),
)

PII_RULES = (
    _rule("email", r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,24}\b", kind="privacy"),
)

PRIVATE_KEY_RULE = "private-key"


def rule_names() -> list:
    names = [PRIVATE_KEY_RULE]
    for rule in SECRET_RULES:
        if rule.name not in names:
            names.append(rule.name)
    return names + [f"{r.name} (--pii)" for r in PII_RULES]
