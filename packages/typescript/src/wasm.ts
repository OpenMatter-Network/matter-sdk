// The wasm cryptographic core, built from `bindings/wasm` by `npm run build:wasm`
// into the local `wasm/` directory. This is the single source of crypto truth;
// the rest of the package is the (networking, signing, ergonomics) shell.
//
// The nodejs-target wasm-pack output is CommonJS that loads its `.wasm` from disk
// synchronously, so there is no async init step.
import * as core from "../wasm/matter_vault_wasm.js";

export const wasm = core;
export type { EncryptedSecretJs } from "../wasm/matter_vault_wasm.js";
