// The wasm cryptographic core, built from `bindings/wasm` by `npm run build:wasm`
// (Node, into `wasm/`) and `npm run build:wasm-web` (bundlers, into `wasm-web/`).
// This is the single source of crypto truth; the rest of the package is the
// (networking, signing, ergonomics) shell.
//
// `#wasm` resolves per environment via the package.json `imports` conditions:
// bundlers (`browser` condition) get the wasm-pack bundler-target ESM glue,
// everything else gets the nodejs-target CommonJS glue, which loads its `.wasm`
// from disk synchronously — so there is no async init step in either case
// (bundlers handle instantiation through their own wasm support).
import * as core from "#wasm";

export const wasm = core;
export type { EncryptedSecretJs } from "#wasm";
