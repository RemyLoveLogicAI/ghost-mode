# ghost-mode

Strip secrets from terminal sessions so the output is safe to paste into a PR or Slack.

Zero dependencies. One file of rules. Python 3.9+.

```console
$ ghost run -- env | head -3
HOME=~
OPENAI_API_KEY=[REDACTED:env:OPENAI_API_KEY]
PATH=/usr/local/bin:/usr/bin
```

## Install

```sh
pipx install .        # or: pip install .
```

Or run in place: `python3 -m ghost_mode ...`

## Use

| Command | What it does |
| --- | --- |
| `ghost run -- <cmd>` | Run a command, scrub stdout and stderr live, keep its exit code. `--pty` keeps colors and tty behaviour. |
| `<cmd> 2>&1 \| ghost scrub` | Scrub anything piped in. Also takes files: `ghost scrub build.log`. |
| `ghost clip` | Scrub whatever is on the clipboard, in place (pbcopy, wl-clipboard or xclip). |
| `ghost scan [files]` | List `file:line: rule` for each secret, never the secret. Exit 1 if any. Good for pre-commit and CI. |
| `ghost rules` | List what it detects. |

Flags shared by `scrub`, `scan`, `run` and `clip`:

- `--hash` labels each redaction with a short per-run hash, so two equal secrets stay recognisable as equal (`[REDACTED:github-token:3f2a]`) without being reversible.
- `--pii` also redacts email addresses.
- `--strip-ansi` removes color and cursor escape codes first.
- `--literal TEXT` always redacts that exact text (repeatable). Use it for customer names and internal hostnames.
- `--no-env` / `--no-home` turn off the two dynamic sources below.

## What it catches

- Token formats: AWS, GitHub, GitLab, Slack (tokens and webhooks), Stripe, Anthropic, OpenAI, Google, Hugging Face, npm, SendGrid, Twilio, JWTs.
- PEM private keys, including multi-line blocks.
- `Authorization: Bearer ...`, `https://user:password@host`, `"api_key": "..."` and `SOME_SECRET=...` assignments.
- **Your own environment.** The value of any environment variable whose name contains `TOKEN`, `SECRET`, `PASSWORD`, `API_KEY` and similar is redacted wherever it appears, even if it matches no known format.
- Your home directory path becomes `~`, so your username does not leak.

## Pre-commit

```yaml
repos:
  - repo: local
    hooks:
      - id: ghost-scan
        name: ghost scan
        entry: ghost scan
        language: system
        types: [text]
```

## Limits

Be honest about what this is: a pattern matcher, not a guarantee.

- A secret with no recognisable format and no secret-like name is not caught. Use `--literal`.
- Output is processed line by line, so a secret hard-wrapped across two lines by something else will slip through. Values shorter than 8 characters are ignored by the assignment rules (use `--literal`).
- Colour codes inside a secret are handled: detection runs on the plain text and the redaction swallows the codes.
- `ghost run` waits for a newline before emitting, so interactive prompts without a trailing newline appear late.
- Read the scrubbed output before you paste it.

## Develop

```sh
python3 -m unittest discover -s tests -t .
```
