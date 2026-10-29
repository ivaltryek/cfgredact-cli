// Command cfgredact-cli hides secrets in tool output. It reads stdin and
// writes the result to stdout. The Pi extension cfgredact.ts runs it.
package main

import (
	"fmt"
	"io"
	"os"
)

// maxInput is the largest input the CLI reads. Pi cuts bash and read output
// to 50 KB, but custom tools have no limit. The extension hides output
// when the CLI fails, so a larger input fails closed.
const maxInput = 16 << 20

func main() {
	in, err := readInput(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cfgredact-cli: %v\n", err)
		os.Exit(1)
	}
	if _, err := io.WriteString(os.Stdout, Redact(in)); err != nil {
		fmt.Fprintf(os.Stderr, "cfgredact-cli: write stdout: %v\n", err)
		os.Exit(1)
	}
}

// readInput reads all of r. It returns an error when r holds more than
// maxInput bytes.
func readInput(r io.Reader) (string, error) {
	in, err := io.ReadAll(io.LimitReader(r, maxInput+1))
	if err != nil {
		return "", fmt.Errorf("read stdin: %w", err)
	}
	if len(in) > maxInput {
		return "", fmt.Errorf("input is larger than %d bytes: narrow the output, for example with head, grep or jq", maxInput)
	}
	return string(in), nil
}
