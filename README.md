# cfgredact-cli

Hide secrets in coding-agent tool output before the model reads it.

- `cfgredact-cli` (Go) reads text on stdin and writes the redacted text to stdout.
  It applies a text-level key and token-shape mask to all input, and
  [cfgredact](https://github.com/rehearsedai/cfgredact) subtree redaction to JSON and YAML.
- `pi/cfgredact.ts` is a Pi (`@earendil-works/pi-coding-agent`) extension. It runs the CLI on every
  tool result. If the CLI fails or times out, the extension hides the output (fail closed).
  It also blocks `write` and `edit` calls that add more `[redacted]` markers than they replace,
  so a redacted read cannot overwrite a real secret on disk.

## Install

```sh
GOBIN=~/.pi/agent/bin go install github.com/ivaltryek/cfgredact-cli@latest
cp pi/cfgredact.ts ~/.pi/agent/extensions/
```

Then run `/reload` in Pi.

## Test

```sh
go test ./...
NODE_PATH=~/.bun/install/global/node_modules bun pi/tests/cfgredact.test.ts
```

## Known limits

The redaction is best effort. These cases are not covered: YAML block scalars,
JSON objects under a secret key, and JSON that is escaped twice.
Inputs larger than 16 MiB fail closed.
