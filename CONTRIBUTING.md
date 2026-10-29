# Contributing

Report bugs and propose changes through GitHub issues. Do not include secrets in reports or test fixtures.

For a change:

1. Open an issue for substantial changes before you start.
2. Add tests for changed behavior, including redaction failures and edge cases.
3. Run `go test ./...` and `go vet ./...`.
4. For Pi extension changes, run the self-check described in the README.
5. Open a pull request that describes the change and its tests.

Use synthetic secrets in tests. See [SECURITY.md](SECURITY.md) for vulnerability reports.
