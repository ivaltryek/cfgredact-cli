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

### Claude Code and Codex

This repository does not currently include Claude Code or Codex integrations. Installing the CLI
alone does not automatically filter their tool results. You can pipe individual commands through
`cfgredact-cli`, but direct reads and other tools bypass that filter. Do not assume this provides
complete protection.

```sh
printf 'password: example\n' | cfgredact-cli
```

For this example, install the CLI on your `PATH` with
`go install github.com/ivaltryek/cfgredact-cli@latest`.

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
