// Consumer smoke test for the chain client, run by scripts/smoke-npm.sh.
// The client must re-export the SAME core instance: two wasm copies would make ApiKey
// handles non-interchangeable.
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
