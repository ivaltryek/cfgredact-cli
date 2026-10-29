// Self-check for ../cfgredact.ts. Pi does not load this file because it is in a subdirectory without index.ts.
// Run: NODE_PATH=~/.bun/install/global/node_modules bun pi/tests/cfgredact.test.ts
import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type {
  ExtensionAPI,
  ExtensionContext,
  ExtensionHandler,
  ToolCallEvent,
  ToolCallEventResult,
  ToolResultEvent,
  ToolResultEventResult,
} from "@earendil-works/pi-coding-agent";
import { createCfgredact } from "../cfgredact.ts";

const dir = mkdtempSync(join(tmpdir(), "cfgredact-test-"));

function fakeCli(name: string, script: string): string {
  const path = join(dir, name);
  writeFileSync(path, `#!/bin/sh\n${script}\n`);
  chmodSync(path, 0o755);
  return path;
}

const upper = fakeCli("upper", "tr a-z A-Z");
const fails = fakeCli("fails", "cat >/dev/null; echo 'input too big: narrow the output' >&2; exit 3");
const slow = fakeCli("slow", "sleep 30");

function load(binPath: string, timeoutMs?: number) {
  let handler: ExtensionHandler<ToolResultEvent, ToolResultEventResult> | undefined;
  let callHandler: ExtensionHandler<ToolCallEvent, ToolCallEventResult> | undefined;
  // The fake implements only the member that the extension uses. This is why the cast is necessary.
  const fakePi = {
    on: (event: string, h: never) => {
      if (event === "tool_result") handler = h;
      if (event === "tool_call") callHandler = h;
    },
  } as unknown as ExtensionAPI;
  createCfgredact(binPath, timeoutMs)(fakePi);
  const registered = handler;
  assert.ok(registered, "the extension must register a tool_result handler");
  const registeredCall = callHandler;
  assert.ok(registeredCall, "the extension must register a tool_call handler");
  const toolCall = (toolName: string, input: Record<string, unknown>) =>
    registeredCall({ type: "tool_call", toolName, toolCallId: "1", input } as ToolCallEvent, { cwd: dir } as ExtensionContext) as Promise<
      ToolCallEventResult | undefined
    >;
  const toolResult = (event: Partial<ToolResultEvent>) =>
    registered(
      { type: "tool_result", toolName: "bash", toolCallId: "1", input: {}, isError: false, details: undefined, ...event } as ToolResultEvent,
      {} as ExtensionContext,
    ) as Promise<ToolResultEventResult | undefined>;
  return Object.assign(toolResult, { toolCall });
}

const text = (t: string) => ({ type: "text" as const, text: t });
const hidden = "[output hidden: redactor failed: ";

// The CLI output replaces the text.
{
  const result = await load(upper)({ content: [text("abc")] });
  assert.deepEqual(result?.content, [text("ABC")]);
}

// A non-zero exit hides the text.
{
  const result = await load(fails)({ content: [text("abc")] });
  assert.deepEqual(result?.content, [text(`${hidden}exit code 3: input too big: narrow the output]`)]);
}

// A timeout hides the text, and stops the CLI.
{
  const started = Date.now();
  const result = await load(slow, 200)({ content: [text("abc")] });
  const out = result?.content?.[0];
  assert.ok(out?.type === "text" && out.text.startsWith(hidden) && out.text.includes("timeout"), JSON.stringify(out));
  assert.ok(Date.now() - started < 5000, "the timeout must stop the CLI");
}

// A missing CLI hides the text.
{
  const result = await load(join(dir, "missing"))({ content: [text("abc")] });
  const out = result?.content?.[0];
  assert.ok(out?.type === "text" && out.text.startsWith(hidden), JSON.stringify(out));
}

// Image parts stay the same object. Text parts next to them go through the CLI.
{
  const image = { type: "image" as const, data: "AAAA", mimeType: "image/png" };
  const result = await load(upper)({ content: [image, text("abc")] });
  assert.equal(result?.content?.[0], image);
  assert.deepEqual(result?.content?.[1], text("ABC"));
}

// structuredContent goes through the CLI too. A handler that replaces content without it drops it.
{
  const result = await load(upper)({ content: [text("abc")], structuredContent: { key: "value" } });
  assert.deepEqual(result?.structuredContent, { KEY: "VALUE" });
}

// When the CLI fails, structuredContent becomes null, so the raw value cannot reach the model.
{
  const result = await load(fails)({ content: [text("abc")], structuredContent: { key: "value" } });
  assert.equal(result?.structuredContent, null);
}

// The model sees redacted reads. A write or edit that adds the marker would put it in place of the real secret.
{
  const { toolCall } = load(upper);
  writeFileSync(join(dir, ".env"), "API_KEY=real\n");
  const marker = "[redacted]";
  const blockedWrite = await toolCall("write", { path: ".env", content: `API_KEY=${marker}\nMODE=dev\n` });
  assert.equal(blockedWrite?.block, true);
  assert.match(blockedWrite?.reason ?? "", /bash/);
  const blockedEdit = await toolCall("edit", { path: ".env", edits: [{ oldText: "MODE=a", newText: `MODE=a\nAPI_KEY=${marker}` }] });
  assert.equal(blockedEdit?.block, true);
  // No new marker, or a file that already holds as many markers, is fine.
  assert.equal(await toolCall("write", { path: ".env", content: "API_KEY=real\nMODE=dev\n" }), undefined);
  writeFileSync(join(dir, "notes.md"), `The redactor writes ${marker}.\n`);
  assert.equal(await toolCall("write", { path: "notes.md", content: `The redactor writes ${marker}. More.\n` }), undefined);
  assert.equal(await toolCall("edit", { path: "notes.md", edits: [{ oldText: `writes ${marker}`, newText: `writes ${marker} here` }] }), undefined);
  assert.equal(await toolCall("bash", { command: `echo ${marker}` }), undefined);
}

console.log("cfgredact self-check: ok");
