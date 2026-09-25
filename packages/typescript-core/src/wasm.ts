// The wasm core, built from `bindings/wasm` by `npm run build:wasm` (Node, `wasm/`)
// and `npm run build:wasm-web` (bundlers, `wasm-web/`). `#wasm` resolves via the
// package.json `imports` conditions; neither target needs an async init step.
import * as core from "#wasm";

export const wasm = core;
export type { EncryptedSecretJs } from "#wasm";
