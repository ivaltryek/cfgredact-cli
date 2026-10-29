# cfgredact-cli

Hide secrets in coding-agent tool output before the model reads it.

- `cfgredact-cli` (Go) reads text on stdin and writes the redacted text to stdout.
  It applies a text-level key and token-shape mask to all input, and
  [cfgredact](https://github.com/rehearsedai/cfgredact) subtree redaction to JSON and YAML.
- `pi/cfgredact.ts` is a Pi (`@earendil-works/pi-coding-agent`) extension. It runs the CLI on every
  tool result. If the CLI fails or times out, the extension hides the output (fail closed).
  It also blocks `write` and `edit` calls that add more `[redacted]` markers than they replace,
  so a redacted read cannot overwrite a real secret on disk.

## Agent setup

### Pi

Install Go and Pi, then clone this repository. From the repository root, run:

```sh
mkdir -p ~/.pi/agent/bin ~/.pi/agent/extensions
GOBIN="$HOME/.pi/agent/bin" go install github.com/ivaltryek/cfgredact-cli@latest
cp pi/cfgredact.ts ~/.pi/agent/extensions/
```

Run `/reload` in Pi. The extension redacts text and structured tool results. It passes non-text
content through unchanged. It hides text when the CLI fails or times out.

### Claude Code

`claude/redact-output.js` is a Claude Code hook. A `PostToolUse` hook rewrites the string values of
each tool result through the CLI. A `PreToolUse` hook denies `Write`, `Edit` and `MultiEdit` calls
that add `[redacted]` markers. It needs Node.js and the CLI at `~/.claude/hooks/cfgredact-cli`
(or the path in `CFGREDACT_BIN`).

```sh
mkdir -p ~/.claude/hooks
GOBIN="$HOME/.claude/hooks" go install github.com/ivaltryek/cfgredact-cli@latest
cp claude/redact-output.js ~/.claude/hooks/
node ~/.claude/hooks/redact-output.js selftest
```

Merge this into the `hooks` object in `~/.claude/settings.json`. Use the absolute path to `node`
(`command -v node`) and to your home directory. If you already have `PostToolUse` or `PreToolUse`
entries, add these to the existing arrays.

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "*",
        "hooks": [{ "type": "command", "command": "node /home/you/.claude/hooks/redact-output.js post", "timeout": 15 }]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Edit|Write|MultiEdit",
        "hooks": [{ "type": "command", "command": "node /home/you/.claude/hooks/redact-output.js guard", "timeout": 5 }]
      }
    ]
  }
}
```

Limits: if the hook crashes or times out, Claude Code keeps the original output. The hook hides
text only when the CLI itself fails. It skips images, documents, and short strings. The transcript
and the terminal can still hold raw output.

### Codex

Codex is not supported. Its `PostToolUse` hook cannot replace tool output. Installing the CLI does
not filter Codex tool results. You can pipe single commands through `cfgredact-cli`, but direct
reads and other tools bypass it.

```sh
printf 'password: example\n' | cfgredact-cli
```

## Test

```sh
go test ./...
NODE_PATH=~/.bun/install/global/node_modules bun pi/tests/cfgredact.test.ts
```

## Known limits

The redaction is best effort. These cases are not covered: YAML block scalars,
JSON objects under a secret key, and JSON that is escaped twice.
The CLI rejects inputs larger than 16 MiB. Pi hides text when the CLI rejects input. Redaction
does not cover images or other non-text Pi content. It does not protect secrets sent directly in
prompts or passed through tools that are not filtered.

## Community

See [CONTRIBUTING.md](CONTRIBUTING.md), [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md),
[SUPPORT.md](SUPPORT.md), and [SECURITY.md](SECURITY.md).
