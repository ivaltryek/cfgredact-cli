#!/usr/bin/env node
// Hide secrets in tool output before the model reads it. Claude Code version of pi/cfgredact.ts.
// Modes (argv[2]):
//   post      PostToolUse, matcher "*"   rewrite string values in tool_response through cfgredact-cli
//   guard     PreToolUse Write|Edit|...  deny a write that adds the [redacted] marker
//   selftest
// post walks the response and touches string values only, so the output shape never changes.
// Claude Code ignores an updatedToolOutput whose shape does not match the tool, so shape is what matters.
// A redactor failure hides the string. Raw output never goes to the model.
// A crash or timeout of this hook keeps the original output, so keep the work bounded.
// Limits: redaction covers what the model sees. The transcript and the UI can still hold raw output.
const fs = require("fs");
const os = require("os");
const path = require("path");
const { spawn } = require("child_process");

const bin = () => process.env.CFGREDACT_BIN || path.join(os.homedir(), ".claude/hooks/cfgredact-cli");
const BUDGET_MS = 10_000;
// The same marker as cfgredact.DefaultMarker in the CLI.
const MARKER = "[redacted]";
const MIN_LEN = 8;
// Metadata that must stay exact. base64 holds image or PDF bytes, which a text mask would corrupt.
const SKIP_KEYS = new Set(["filePath", "file_path", "path", "base64"]);
const BLOCK_REASON =
  `The new text adds ${MARKER}. Tool output is redacted, so this text can replace a real secret with the marker. ` +
  "Keep the secret lines out of the change. If the marker is meant literally, write the file with bash.";

// Runs the CLI on one text. Resolves to the CLI output. Rejects with the failure reason.
function redact(text, timeoutMs) {
  return new Promise((resolve, reject) => {
    const child = spawn(bin(), [], { stdio: ["pipe", "pipe", "pipe"] });
    const chunks = [];
    let stderr = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`timeout after ${timeoutMs} ms`));
    }, timeoutMs);
    child.stderr.on("data", (c) => (stderr = (stderr + c).slice(0, 500)));
    child.stdout.on("data", (c) => chunks.push(c));
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (code === 0) resolve(Buffer.concat(chunks).toString("utf8"));
      else reject(new Error((signal ? `signal ${signal}` : `exit code ${code}`) + (stderr.trim() ? `: ${stderr.trim()}` : "")));
    });
    // The CLI can exit before it reads all of stdin. The exit code then reports the failure.
    child.stdin.on("error", () => {});
    child.stdin.end(text);
  });
}

const hidden = (err) => `[output hidden: redactor failed: ${err.message}; hook ~/.claude/hooks/redact-output.js]`;

// When the CLI parses a JSON document, the cfgredact library blanks a whole free-text value that mentions a
// secret word, for example a note or manifest text that says "secret" and has a newline or a backtick.
// MCP results are JSON text, so notes that mention a secret came back fully masked.
// Fix: pull free-text values out of the JSON and redact each one as plain text.
// Only the skeleton goes through the CLI, so key rules such as {"password": "x"} still work.
const isFreeText = (s) => s.length > 100 || /[\n`]/.test(s);
const mapStrings = (v, fn) =>
  Array.isArray(v)
    ? v.map((x) => mapStrings(x, fn))
    : v && typeof v === "object"
      ? Object.fromEntries(Object.entries(v).map(([k, x]) => [k, mapStrings(x, fn)]))
      : typeof v === "string"
        ? fn(v)
        : v;

function parseDoc(text) {
  const t = text.trimStart();
  if (t[0] !== "{" && t[0] !== "[") return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function redactText(text, deadline) {
  const left = () => Math.max(1, deadline - Date.now());
  const doc = parseDoc(text);
  if (doc === null) return redact(text, left());
  const free = [];
  const skeleton = mapStrings(doc, (s) => (isFreeText(s) ? `__FREE_${free.push(s) - 1}__` : s));
  if (!free.length) return redact(text, left());
  const [outText, ...cleaned] = await Promise.all([redact(JSON.stringify(skeleton), left()), ...free.map((s) => redact(s, left()))]);
  const result = mapStrings(JSON.parse(outText), (s) => {
    const m = /^__FREE_(\d+)__$/.exec(s);
    return m ? cleaned[Number(m[1])] : s;
  });
  // Nothing was masked: return the original text, so its formatting stays exact.
  if (JSON.stringify(result) === JSON.stringify(doc)) return text;
  return JSON.stringify(result, null, text.includes("\n") ? 2 : 0);
}

async function walk(v, key, deadline) {
  if (typeof v === "string") {
    if (v.length < MIN_LEN || SKIP_KEYS.has(key)) return v;
    return redactText(v, deadline).catch(hidden);
  }
  if (Array.isArray(v)) return Promise.all(v.map((x) => walk(x, key, deadline)));
  if (v && typeof v === "object") {
    // Image and document payloads are bytes, not text.
    if (v.isImage === true || v.type === "image" || v.type === "document") return v;
    const entries = await Promise.all(Object.entries(v).map(async ([k, x]) => [k, await walk(x, k, deadline)]));
    return Object.fromEntries(entries);
  }
  return v;
}

async function post(input) {
  if (input.tool_response === undefined || input.tool_response === null) return null;
  const out = await walk(input.tool_response, "", Date.now() + BUDGET_MS);
  if (JSON.stringify(out) === JSON.stringify(input.tool_response)) return null;
  return { hookSpecificOutput: { hookEventName: "PostToolUse", updatedToolOutput: out } };
}

const markerCount = (s) => String(s ?? "").split(MARKER).length - 1;
const readOrEmpty = (p) => {
  try {
    return fs.readFileSync(p, "utf8");
  } catch {
    // A new file holds no markers.
    return "";
  }
};

function guard(input) {
  const ti = input.tool_input ?? {};
  const deny = { hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: BLOCK_REASON } };
  if (input.tool_name === "Write") {
    const onDisk = readOrEmpty(path.resolve(input.cwd || process.cwd(), String(ti.file_path ?? "")));
    return markerCount(ti.content) > markerCount(onDisk) ? deny : null;
  }
  const edits = Array.isArray(ti.edits) ? ti.edits : [ti];
  return edits.some((e) => markerCount(e.new_string) > markerCount(e.old_string)) ? deny : null;
}

const modes = { post, guard };

async function selftest() {
  const assert = require("assert");
  const fake = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"; // made-up token
  const bash = { stdout: `token ${fake}\nlonger line without secrets`, stderr: "", interrupted: false, isImage: false, noOutputExpected: false };

  const r = await post({ tool_response: bash });
  const out = r.hookSpecificOutput.updatedToolOutput;
  assert(out.stdout.includes(MARKER) && !out.stdout.includes(fake), "bash: token masked");
  assert.deepStrictEqual(Object.keys(out), Object.keys(bash), "bash: same keys, same order");
  assert(out.interrupted === false && out.stderr === "", "bash: non-strings kept");

  const clean = { type: "text", file: { filePath: "/x/a.go", content: "package main\n\nfunc main() {}\n", numLines: 4 } };
  assert((await post({ tool_response: clean })) === null, "clean read: no rewrite");

  const secret = { type: "text", file: { filePath: "/x/" + fake, content: `name: demo\npassword: fakepass12345\n` } };
  const s = (await post({ tool_response: secret })).hookSpecificOutput.updatedToolOutput;
  assert(s.file.filePath === secret.file.filePath, "filePath untouched");
  assert(!s.file.content.includes("fakepass12345"), "yaml password masked");

  const img = { type: "image", file: { base64: "iVBORw0KGgo=".repeat(20), type: "image/png" } };
  assert((await post({ tool_response: img })) === null, "image untouched");
  assert((await post({ tool_response: fake + " as a plain string" })).hookSpecificOutput.updatedToolOutput.includes(MARKER), "top-level string");

  // MCP results are JSON text. A note that mentions a secret word must not be blanked as a whole.
  const note = "Applied the patch.\n`cert-manager/zerossl-ssl-eabsecret` exists with `tls.key`.";
  const mcpClean = JSON.stringify({ title: "t", permalink: "main/x", content: note });
  assert((await post({ tool_response: mcpClean })) === null, "json text with a secret word in free text: untouched");
  const mcpTok = JSON.stringify({ title: "t", content: `${note}\nToken ${fake} here.` });
  const m = JSON.parse((await post({ tool_response: mcpTok })).hookSpecificOutput.updatedToolOutput);
  assert(m.title === "t" && m.content.includes("eabsecret") && !m.content.includes(fake) && m.content.includes(MARKER), "json text: token masked, note kept");
  const keyed = JSON.parse((await post({ tool_response: JSON.stringify({ password: "hunter2hunter2", note }) })).hookSpecificOutput.updatedToolOutput);
  assert(keyed.password === MARKER && keyed.note === note, "json text: key rule still masks, note kept");
  const pair = JSON.parse((await post({ tool_response: JSON.stringify({ name: "API_KEY", value: "abcdefgh12345", note }) })).hookSpecificOutput.updatedToolOutput);
  assert(pair.value === MARKER && pair.note === note, "json text: name/value pair masked");

  process.env.CFGREDACT_BIN = "/nonexistent/cfgredact-cli";
  const h = (await post({ tool_response: bash })).hookSpecificOutput.updatedToolOutput;
  assert(h.stdout.startsWith("[output hidden") && h.stderr === "" && Object.keys(h).length === 5, "missing redactor: hidden, shape kept");
  delete process.env.CFGREDACT_BIN;

  const tmp = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "ro-")), "f.sh");
  fs.writeFileSync(tmp, `x='${MARKER}'\n`);
  const w = (c) => guard({ tool_name: "Write", cwd: "/", tool_input: { file_path: tmp, content: c } });
  assert(w(`x='${MARKER}'\ny=1\n`) === null, "write: equal marker count passes");
  assert(w(`x='${MARKER}'\ny='${MARKER}'\n`) !== null, "write: added marker denied");
  assert(guard({ tool_name: "Edit", tool_input: { old_string: "key: real", new_string: `key: ${MARKER}` } }) !== null, "edit: added marker denied");
  assert(guard({ tool_name: "Edit", tool_input: { old_string: `a ${MARKER}`, new_string: `b ${MARKER}` } }) === null, "edit: equal count passes");
  assert(guard({ tool_name: "MultiEdit", tool_input: { edits: [{ old_string: "a", new_string: "b" }, { old_string: "c", new_string: MARKER }] } }) !== null, "multiedit: denied");
  console.log("selftest ok");
}

if (process.argv[2] === "selftest") {
  selftest().catch((e) => {
    console.error(e.message);
    process.exit(1);
  });
} else if (modes[process.argv[2]]) {
  let raw = "";
  process.stdin.on("data", (d) => (raw += d));
  process.stdin.on("end", async () => {
    try {
      const out = await modes[process.argv[2]](JSON.parse(raw || "{}"));
      if (out) process.stdout.write(JSON.stringify(out));
    } catch {
      // A broken hook must not block work. Claude Code keeps the original output.
    }
  });
}
