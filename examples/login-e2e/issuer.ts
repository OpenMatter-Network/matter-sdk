// A local sign-in issuer for this harness: one RSA key held in memory, a JWKS
// endpoint on 127.0.0.1, and RS256 ID tokens. Test-only — it signs a token for
// any subject it is asked for.

import { createSign, generateKeyPairSync, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

const ALG = "RS256";
const TOKEN_TTL_SECS = 300;
const HOST = "127.0.0.1";

const b64url = (input: string) => Buffer.from(input).toString("base64url");

export interface TokenRequest {
  aud: string;
  sub: string;
  /** `loginNonce(requester)`: binds the token to one session key. */
  nonce: string;
}

export interface LocalIssuer {
  /** The `iss` claim of every token, and the issuer an app registers. */
  iss: string;
  jwksUri: string;
  mint(request: TokenRequest): string;
  /** How often the committee fetched the signing keys. */
  jwksHits(): number;
  stop(): Promise<void>;
}

/** Start an issuer on a free port (or `port`). */
export async function startIssuer(port = 0): Promise<LocalIssuer> {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const kid = randomBytes(8).toString("hex");
  const jwks = JSON.stringify({ keys: [{ ...publicKey.export({ format: "jwk" }), kid, alg: ALG, use: "sig" }] });
  let hits = 0;

  const server = createServer((req, res) => {
    if (req.url !== "/jwks") {
      res.writeHead(404).end();
      return;
    }
    hits += 1;
    res.writeHead(200, { "content-type": "application/json" }).end(jwks);
  });
  await new Promise<void>((resolve, reject) => server.once("error", reject).listen(port, HOST, resolve));
  const iss = `http://${HOST}:${(server.address() as AddressInfo).port}`;

  const mint = ({ aud, sub, nonce }: TokenRequest): string => {
    const iat = Math.floor(Date.now() / 1000);
    const head = b64url(JSON.stringify({ alg: ALG, typ: "JWT", kid }));
    const body = b64url(JSON.stringify({ iss, aud, sub, nonce, iat, exp: iat + TOKEN_TTL_SECS }));
    const signature = createSign("RSA-SHA256").update(`${head}.${body}`).sign(privateKey).toString("base64url");
    return `${head}.${body}.${signature}`;
  };

  return {
    iss,
    jwksUri: `${iss}/jwks`,
    mint,
    jwksHits: () => hits,
    stop: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
