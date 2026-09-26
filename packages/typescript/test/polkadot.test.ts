// The @polkadot/api backend's pure edges, checked against the real spec-330 runtime.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Metadata, TypeRegistry } from "@polkadot/types";
import { describe, expect, it } from "vitest";

import { palletNamesByIndex, receiptEvents, storedValue } from "../src/polkadot.js";

const vectorsDir = resolve(import.meta.dirname, "../../../testvectors");

function spec330(): { registry: TypeRegistry; metadata: Metadata } {
  const registry = new TypeRegistry();
  const metadata = new Metadata(
    registry,
    new Uint8Array(readFileSync(resolve(vectorsDir, "spec330_metadata.scale"))),
  );
  registry.setMetadata(metadata);
  return { registry, metadata };
}

describe("receipt event names", () => {
  it("names the pallet as metadata spells it, not as @polkadot camelCases it", () => {
    const { registry, metadata } = spec330();
    const secrets = metadata.asLatest.pallets.find((p) => p.name.toString() === "Secrets");
    expect(secrets, "spec 330 has a Secrets pallet").toBeDefined();
    const variant = registry.lookup
      .getSiType(secrets!.events.unwrap().type)
      .def.asVariant.variants.find((v) => v.name.toString() === "SecretStored");
    expect(variant, "Secrets emits SecretStored").toBeDefined();

    // SecretStored { secret_id: u128, owner: AccountId32 }, all zero.
    const encoded = new Uint8Array(2 + 16 + 32);
    encoded[0] = secrets!.index.toNumber();
    encoded[1] = variant!.index.toNumber();
    const event = registry.createType("Event", encoded);
    expect(event.section).toBe("secrets"); // what the receipt used to carry

    const events = receiptEvents([{ event }], palletNamesByIndex(metadata));
    expect(events).toEqual([["Secrets", "SecretStored"]]);
  });

  it("maps every pallet index to its metadata name", () => {
    const { metadata } = spec330();
    const names = palletNamesByIndex(metadata);
    expect(names.size).toBe(metadata.asLatest.pallets.length);
    for (const pallet of metadata.asLatest.pallets) {
      expect(names.get(pallet.index.toNumber())).toBe(pallet.name.toString());
    }
    expect([...names.values()]).toContain("NominationPools");
  });
});

describe("query results", () => {
  it("returns a stored zero, not undefined", () => {
    const { registry } = spec330();
    const zero = registry.createType("u128", 0);
    expect(storedValue(zero)).toBe(zero);
  });

  it("reads an absent entry with a storage default as undefined", () => {
    const { registry } = spec330();
    const fallback = registry.createType("u128", 0);
    (fallback as { isStorageFallback?: boolean }).isStorageFallback = true;
    expect(storedValue(fallback)).toBeUndefined();
  });

  it("reads an absent optional entry as undefined", () => {
    const { registry } = spec330();
    expect(storedValue(registry.createType("Option<u128>", null))).toBeUndefined();
    const some = registry.createType("Option<u128>", 0);
    expect(storedValue(some)).toBe(some);
  });
});
