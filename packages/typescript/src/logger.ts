// Where this client's diagnostics go.
//
// Its own module rather than a member of the client's: the backend needs it too,
// and importing it from `client.ts` would close a cycle, since that module
// lazily imports the backend.

/** The minimum a logger must offer. `console` satisfies it. */
export interface ClientLogger {
  info(message: string): void;
  warn(message: string): void;
}

/** The console, which is what a caller gets unless they say otherwise. */
export const defaultLogger: ClientLogger = {
  // eslint-disable-next-line no-console
  info: (message) => console.info(message),
  // eslint-disable-next-line no-console
  warn: (message) => console.warn(message),
};
