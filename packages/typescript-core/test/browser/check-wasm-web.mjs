#!/usr/bin/env node
// Load the package the way a browser does, in a real one.
//
// Why this exists (2026-11-12). `npm test` runs under Node against the Node
// wasm build, and nothing built or ran `wasm-web`. Two defects lived in that
// gap: the transport called `fetch` as a method, which only a browser refuses
// ("Illegal invocation"), and the browser glue was shipped unexercised. This
// serves `dist/` and `wasm-web/` as they are published, opens a headless
// Chrome on a page that imports the package's own entry, and compares what it
// computes there with what the Node build computes here.
//
//   usage: node test/browser/check-wasm-web.mjs      (after `npm run build`)
//   env:   CHROME_BIN — the browser to run (default: the first found on PATH)
//
// Silent on success; a failure prints what differed and exits 1.
import { spawn, spawnSync } from "node:child_process";
import { createReadStream, existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { extname, join, normalize, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(fileURLToPath(import.meta.url), "..", "..", "..");
const TIMEOUT_MS = 60_000;
/** How long a killed browser gets to exit before its profile is removed anyway. */
const EXIT_WAIT_MS = 5_000;
const MIME = { ".js": "text/javascript", ".wasm": "application/wasm", ".html": "text/html", ".json": "application/json" };
const SERVED = ["dist", "wasm-web"];
const KEY_FILL = 7;
const HEALTH = { status: "active", epoch: 3 };

const fail = (message) => {
  console.error(`check-wasm-web: ${message}`);
  process.exit(1);
};

for (const dir of SERVED) {
  if (!existsSync(join(ROOT, dir))) fail(`${dir}/ is missing — run \`npm run build\` first`);
}

const browser =
  process.env.CHROME_BIN ??
  ["google-chrome", "chromium", "chromium-browser", "chrome"].find(
    (name) => spawnSync("which", [name], { stdio: "ignore" }).status === 0,
  );
if (browser === undefined) fail("no Chrome found on PATH; set CHROME_BIN");

// What the Node build answers for the same input.
const nodeWasm = createRequire(import.meta.url)(join(ROOT, "wasm", "matter_sdk_wasm.js"));
const expected = {
  loginNonce: nodeWasm.loginNonce(new Uint8Array(32).fill(KEY_FILL)),
  cryptoProtocolVersion: nodeWasm.cryptoProtocolVersion(),
  health: HEALTH,
};

// `#wasm` is a package-internal import a bundler resolves; here an import map
// points it at this module, which instantiates the published glue by hand.
const WASM_SHIM = `
import * as glue from "/wasm-web/matter_sdk_wasm_bg.js";
const { instance } = await WebAssembly.instantiateStreaming(fetch("/wasm-web/matter_sdk_wasm_bg.wasm"), {
  "./matter_sdk_wasm_bg.js": glue,
});
glue.__wbg_set_wasm(instance.exports);
instance.exports.__wbindgen_start();
export * from "/wasm-web/matter_sdk_wasm_bg.js";
`;

const PAGE = `<!doctype html><meta charset="utf-8"><title>matter-sdk-core in a browser</title>
<script type="importmap">{ "imports": { "#wasm": "/wasm-shim.js" } }</script>
<script type="module">
const report = (body) => fetch("/result", { method: "POST", body: JSON.stringify(body) });
try {
  const sdk = await import("/dist/index.js");
  report({
    loginNonce: sdk.loginNonce(new Uint8Array(32).fill(${KEY_FILL})),
    cryptoProtocolVersion: sdk.cryptoProtocolVersion(),
    // The DEFAULT transport: the global fetch, under a browser's receiver rule.
    health: await new sdk.FetchTransport().health(location.origin),
  });
} catch (e) {
  report({ error: String(e && e.stack || e) });
}
</script>`;

const STATIC = { "/": [PAGE, MIME[".html"]], "/wasm-shim.js": [WASM_SHIM, MIME[".js"]], "/health": [JSON.stringify(HEALTH), MIME[".json"]] };

let finish;
const result = new Promise((resolveResult) => {
  finish = resolveResult;
});

const server = createServer((req, res) => {
  const path = new URL(req.url, "http://x").pathname;
  if (req.method === "POST" && path === "/result") {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      res.end();
      finish(JSON.parse(body));
    });
    return;
  }
  if (STATIC[path]) {
    res.writeHead(200, { "content-type": STATIC[path][1] }).end(STATIC[path][0]);
    return;
  }
  const file = normalize(join(ROOT, path));
  const allowed = SERVED.some((dir) => file.startsWith(join(ROOT, dir) + "/"));
  if (!allowed || !existsSync(file)) {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(200, { "content-type": MIME[extname(file)] ?? "application/octet-stream" });
  createReadStream(file).pipe(res);
});

await new Promise((listening) => server.listen(0, "127.0.0.1", listening));
const profile = mkdtempSync(join(tmpdir(), "matter-sdk-browser-"));
const chrome = spawn(
  browser,
  ["--headless=new", "--no-sandbox", "--disable-gpu", `--user-data-dir=${profile}`, `http://127.0.0.1:${server.address().port}/`],
  { stdio: "ignore" },
);
const timer = setTimeout(() => finish({ error: `no answer from the browser within ${TIMEOUT_MS} ms` }), TIMEOUT_MS);

const got = await result;
clearTimeout(timer);
// Wait for the browser to be GONE before removing its profile: `kill()` only
// sends the signal, and a browser still shutting down keeps writing there —
// on a CI runner the removal met "ENOTEMPTY" and failed a check that had
// passed. And tidying up is never the verdict: a profile that will not go is
// reported and left for the OS's temp cleaner.
const exited = new Promise((gone) => chrome.once("exit", gone));
chrome.kill("SIGKILL");
await Promise.race([exited, new Promise((waited) => setTimeout(waited, EXIT_WAIT_MS))]);
server.close();
try {
  rmSync(profile, { recursive: true, force: true, maxRetries: 10, retryDelay: 200 });
} catch (e) {
  console.error(`check-wasm-web: left ${profile} behind (${e.code ?? e.message})`);
}

if (got.error) fail(`the page failed: ${got.error}`);
const differing = Object.keys(expected).filter((key) => JSON.stringify(got[key]) !== JSON.stringify(expected[key]));
if (differing.length > 0) {
  fail(differing.map((key) => `${key}: browser ${JSON.stringify(got[key])}, node ${JSON.stringify(expected[key])}`).join("; "));
}
