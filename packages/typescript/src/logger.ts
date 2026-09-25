// Own module so client.ts and polkadot.ts share it without an import cycle.

/** The minimum a logger must offer. `console` satisfies it. */
export interface ClientLogger {
  info(message: string): void;
  warn(message: string): void;
}

/** Logs to `console`. */
export const defaultLogger: ClientLogger = {
  // eslint-disable-next-line no-console
  info: (message) => console.info(message),
  // eslint-disable-next-line no-console
  warn: (message) => console.warn(message),
};
