import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { isToolCallEventType, type ExtensionAPI } from "@earendil-works/pi-coding-agent";

// Hide secrets in tool results before the model reads them.
// Each text part goes through cfgredact-cli: cfgredact on JSON and YAML, and a token-shape mask on all text.
// If the CLI fails, the text is hidden. Raw output never goes to the model.
// The model also sees redacted reads. So a write or edit that adds the marker would replace a real secret on disk.
// The tool_call guard blocks such calls.
// CLI source: the Go module at the repository root. Self-check: tests/cfgredact.test.ts.

const DEFAULT_TIMEOUT_MS = 10_000;
// The same marker as cfgredact.DefaultMarker in the CLI.
const MARKER = "[redacted]";
const BLOCK_REASON =
  `The new text adds ${MARKER}. Tool output is redacted, so this text can replace a real secret with the marker. ` +
  "Keep the secret lines out of the change. If the marker is meant literally, write the file with bash.";

const markerCount = (s: string) => s.split(MARKER).length - 1;

function readOrEmpty(path: string): string {
  try {
    return readFileSync(path, "utf8");
  } catch {
    // A new file holds no markers.
    return "";
  }
}
// The CLI writes one short error line. The cap keeps a broken CLI from filling the reason.
const MAX_STDERR_CHARS = 500;

// redact runs the CLI on one text. It returns the CLI output, or rejects with the failure reason.
function redact(binPath: string, timeoutMs: number, text: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const fail = (reason: string) => reject(new Error(reason));
    const child = spawn(binPath, [], { stdio: ["pipe", "pipe", "pipe"] });
    const chunks: Buffer[] = [];
    let stderr = "";
    child.stderr.on("data", (chunk: Buffer) => {
      stderr = (stderr + chunk.toString("utf8")).slice(0, MAX_STDERR_CHARS);
    });
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      fail(`timeout after ${timeoutMs} ms`);
    }, timeoutMs);
    child.stdout.on("data", (chunk: Buffer) => chunks.push(chunk));
    child.on("error", (err) => {
      clearTimeout(timer);
      fail(err.message);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (code === 0) resolve(Buffer.concat(chunks).toString("utf8"));
      else fail((signal ? `signal ${signal}` : `exit code ${code}`) + (stderr.trim() ? `: ${stderr.trim()}` : ""));
    });
    // The CLI can exit before it reads all of stdin. The exit code then reports the failure, so ignore EPIPE here.
    child.stdin.on("error", () => {});
    child.stdin.end(text);
  });
}

export function createCfgredact(binPath: string, timeoutMs = DEFAULT_TIMEOUT_MS) {
  return function (pi: ExtensionAPI) {
    pi.on("tool_call", (event, ctx) => {
      if (isToolCallEventType("write", event)) {
        const onDisk = readOrEmpty(resolve(ctx.cwd, event.input.path));
        if (markerCount(event.input.content) > markerCount(onDisk)) return { block: true, reason: BLOCK_REASON };
      }
      if (isToolCallEventType("edit", event)) {
        if (event.input.edits.some((e) => markerCount(e.newText) > markerCount(e.oldText))) {
          return { block: true, reason: BLOCK_REASON };
        }
      }
      return undefined;
    });

    pi.on("tool_result", async (event) => {
      const redactStructured = async () => {
        try {
          return JSON.parse(await redact(binPath, timeoutMs, JSON.stringify(event.structuredContent)));
        } catch {
          // The CLI failed, or a token mask broke the JSON. null keeps the raw value from the caller.
          return null;
        }
      };
      const contentParts = Promise.all(
        event.content.map(async (part) =>
          part.type === "text"
            ? {
                ...part,
                text: await redact(binPath, timeoutMs, part.text).catch(
                  (err: Error) => `[output hidden: redactor failed: ${err.message}]`,
                ),
              }
            : part,
        ),
      );
      if (event.structuredContent === undefined) return { content: await contentParts };
      const [content, structuredContent] = await Promise.all([contentParts, redactStructured()]);
      return { content, structuredContent };
    });
  };
}

export default createCfgredact(join(homedir(), ".pi/agent/bin/cfgredact-cli"));
