# End-to-end: OpenMatter Login, local chain and committee

This harness runs [OpenMatter Login](../../docs/login.md) against a **local** dev chain
and committee, with the SDK's TypeScript core doing everything login-specific:

1. Start a local sign-in issuer on a free port and, as sudo, register a new app that
   trusts it (`Logins.register_app`, `Logins.set_issuer`).
2. Make a session key, mint a token bound to it, seal a new seed
   (`prepareLoginRegistration`).
3. Collect a threshold of attestations (`collectLoginAttestations`) and submit
   `Logins.register_login` signed by the seed's account.
4. From a **fresh** session key and token, read the login record and recover the seed
   (`oidcSigner`, `openLogin`), and compare it in process.
5. Check two refusals: a second registration (`already-registered`) and another
   subject's token.

@polkadot only submits extrinsics and makes `state_call`s.

It refuses to run unless the endpoint is on loopback and the chain names itself a dev
chain: it uses the `//Alice` sudo key, and its issuer signs a token for anyone. The
committee nodes must be able to reach `127.0.0.1`, so they run on the same machine.
Alice funds the new account, which pays for its own registration.

## Run

```bash
# From the repository root: build the core the harness imports from source.
npm --prefix packages/typescript-core ci && npm --prefix packages/typescript-core run build

cd examples/login-e2e
npm install
npm start                       # MATTER_RPC_URL defaults to ws://127.0.0.1:9944
```

The recovered seed is compared in process and never printed.
