// Consumer smoke test for @openmatter-network/matter-sdk (the chain client), run by
// scripts/smoke-npm.sh from a project outside this repository.
//
// The client re-exports the core. If it resolved a second copy of the core — a bundled
// one, or a different version — a consumer would hold two wasm instances whose ApiKey
// handles are not interchangeable. Identity of the re-exported function is the proof
// that there is one.
import { fileURLToPath } from "node:url";

import * as core from "@openmatter-network/matter-sdk-core";
import * as client from "@openmatter-network/matter-sdk";

const fail = (message) => {
  console.error(`npm-client smoke: ${message}`);
  process.exit(1);
};

const resolved = fileURLToPath(import.meta.resolve("@openmatter-network/matter-sdk"));
if (!resolved.includes("node_modules")) fail(`resolved outside node_modules: ${resolved}`);

if (typeof client.MatterClient !== "function") fail("MatterClient is not exported");
if (client.encrypt !== core.encrypt) fail("the client re-exports a different copy of the core");
