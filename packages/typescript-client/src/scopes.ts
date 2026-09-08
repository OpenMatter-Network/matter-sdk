// Per-interaction-group Read/Write permissions for member-tied API keys.
//
// A member-tied API key is a delegate holding a `ProxyType::Scoped(ScopeSet)`
// proxy on the account of the member who minted it, and everything it does it
// does as that member. The runtime maps every tenant-facing call to the set it
// requires and admits the call iff the key's set covers it.
//
// This is a wire contract, mirrored from matter-node's `common/src/scopes.rs`
// and pinned across languages by `testvectors/scope_bits.json` and
// `testvectors/required_scopes.json`. A `ScopeSet` is a bare `u32` whose bit for
// `(scope, access)` is `scope * 2 + access`. Both vocabularies are append-only:
// a new group takes the next index and the next two bits, and nothing already
// assigned ever moves.
//
// Ported rather than shared through wasm on purpose. A scope set is not
// cryptography, so it does not belong behind the shared core; and the two
// argument-sensitive rows below must read call arguments as JS values, before
// anything is encoded, which a wasm boundary could not do without being handed
// the whole argument tree.

/** An interaction group a key may be permissioned for. Index = bit-pair. */
export enum Scope {
  Deployments = 0,
  Collaborations = 1,
  Secrets = 2,
  Volumes = 3,
  Datasets = 4,
  Networking = 5,
  Resources = 6,
  Organization = 7,
  Billing = 8,
  Communities = 9,
}

/** The half of a scope a key is granted. Neither implies the other. */
export enum Access {
  Read = 0,
  Write = 1,
}

/** Scope names, indexed by discriminant. One table, so rendering and parsing
 * cannot disagree about a spelling. */
const SCOPE_NAMES: readonly string[] = [
  "deployments",
  "collaborations",
  "secrets",
  "volumes",
  "datasets",
  "networking",
  "resources",
  "organization",
  "billing",
  "communities",
];

/** How an empty set renders, and one of the two spellings that parse back. */
const EMPTY_TEXT = "(none)";

const SCOPE_COUNT = SCOPE_NAMES.length;

function bit(scope: Scope, access: Access): number {
  return 1 << (scope * 2 + access);
}

/**
 * A set of `(scope, access)` grants, as a bare `u32` bitmask.
 *
 * Immutable: every combinator returns a new set, so a set handed to the client
 * cannot be widened behind its back.
 */
export class ScopeSet {
  /** No grants. */
  static readonly EMPTY = new ScopeSet(0);
  /** Every defined `(scope, access)` bit. */
  static readonly ALL = new ScopeSet((1 << (SCOPE_COUNT * 2)) - 1);

  readonly bits: number;

  private constructor(bits: number) {
    // `>>> 0` keeps this an unsigned 32-bit value: JS bitwise operators work on
    // signed int32, so bit 31 would otherwise make the whole set negative.
    this.bits = bits >>> 0;
  }

  /** A set from raw bits — the wire form. Validate with `isValid()`. */
  static fromBits(bits: number): ScopeSet {
    return new ScopeSet(bits);
  }

  /** The set holding exactly `(scope, access)`. */
  static single(scope: Scope, access: Access): ScopeSet {
    return new ScopeSet(bit(scope, access));
  }

  /** Both halves of every listed scope. */
  static covering(scopes: readonly Scope[]): ScopeSet {
    let bits = 0;
    for (const scope of scopes) bits |= bit(scope, Access.Read) | bit(scope, Access.Write);
    return new ScopeSet(bits);
  }

  /** `this` plus `(scope, access)`. */
  with(scope: Scope, access: Access): ScopeSet {
    return new ScopeSet(this.bits | bit(scope, access));
  }

  /** `this ∪ other`. */
  union(other: ScopeSet): ScopeSet {
    return new ScopeSet(this.bits | other.bits);
  }

  /** Whether `(scope, access)` is granted. */
  contains(scope: Scope, access: Access): boolean {
    return (this.bits & bit(scope, access)) !== 0;
  }

  /** Whether every grant in `other` is also here (`this ⊇ other`). */
  isSuperset(other: ScopeSet): boolean {
    return (this.bits & other.bits) === other.bits;
  }

  /** Whether every grant here is also in `other` (`this ⊆ other`). */
  isSubset(other: ScopeSet): boolean {
    return other.isSuperset(this);
  }

  /** Whether the set grants nothing. */
  isEmpty(): boolean {
    return this.bits === 0;
  }

  /** Whether every set bit names a defined `(scope, access)`. */
  isValid(): boolean {
    return (this.bits & ~ScopeSet.ALL.bits) === 0;
  }

  /** `deployments:rw, secrets:r`, in index order; `(none)` when empty. */
  toString(): string {
    if (this.isEmpty()) return EMPTY_TEXT;
    const parts: string[] = [];
    for (let index = 0; index < SCOPE_COUNT; index += 1) {
      const scope = index as Scope;
      const r = this.contains(scope, Access.Read);
      const w = this.contains(scope, Access.Write);
      if (!r && !w) continue;
      parts.push(`${SCOPE_NAMES[index]}:${r ? "r" : ""}${w ? "w" : ""}`);
    }
    return parts.join(", ");
  }

  /**
   * Parse `deployments:rw, secrets:r`. Case-insensitive; entries may be
   * separated by commas, whitespace, or both. An empty string and `(none)` both
   * yield an empty set, so `toString` round-trips.
   */
  static parse(text: string): ScopeSet {
    const trimmed = text.trim();
    if (trimmed === "" || trimmed.toLowerCase() === EMPTY_TEXT) return ScopeSet.EMPTY;

    let set = ScopeSet.EMPTY;
    for (const entry of trimmed.split(/[,\s]+/).filter((e) => e !== "")) {
      const at = entry.indexOf(":");
      if (at < 0) {
        throw new Error(`scope entry "${entry}" is missing its :r, :w or :rw suffix`);
      }
      const name = entry.slice(0, at).toLowerCase();
      const access = entry.slice(at + 1).toLowerCase();

      const index = SCOPE_NAMES.indexOf(name);
      if (index < 0) throw new Error(`unknown scope "${name}"`);

      let read = false;
      let write = false;
      for (const c of access) {
        // A repeated letter means the caller's generator is confused; folding
        // it silently would hide that.
        if (c === "r" && !read) read = true;
        else if (c === "w" && !write) write = true;
        else throw new Error(`scope "${name}" has invalid access "${access}": expected r, w, or rw`);
      }
      if (!read && !write) {
        throw new Error(`scope "${name}" has invalid access "${access}": expected r, w, or rw`);
      }

      const scope = index as Scope;
      if (read) set = set.with(scope, Access.Read);
      if (write) set = set.with(scope, Access.Write);
    }
    return set;
  }
}

const write = (scope: Scope): ScopeSet => ScopeSet.single(scope, Access.Write);

/** Shipping a secret into a container the key controls is a read of it. */
const DEPLOY_WITH_SECRET = write(Scope.Deployments).with(Scope.Secrets, Access.Read);

/**
 * What `pallet.call(args)` requires of a delegated key, or `null` if no set
 * admits it at all — provider-signed, root-only, org lifecycle, the roster
 * calls, and every treasury value mover.
 *
 * # This check is a courtesy, not a boundary
 *
 * The runtime's own filter is the only real enforcer. This exists so a caller
 * reads "your key lacks volumes:w" instead of the pool rejection a balance-less
 * delegated key actually gets, which complains about fees and names neither the
 * call nor the scope. It follows that being wrong in the *safe* direction —
 * demanding more than the chain would — costs a caller a local rejection they
 * can work around, while the opposite would let through a call the chain then
 * refuses. So where an argument cannot be read, the wider set is required.
 */
export function requiredScopes(
  pallet: string,
  call: string,
  args: readonly unknown[],
): ScopeSet | null {
  switch (pallet) {
    case "Jobs":
      switch (call) {
        case "request_deployment":
          return requestReferencesSecret(args[0]) ? DEPLOY_WITH_SECRET : write(Scope.Deployments);
        case "set_deployment_secret_ref":
          // `args.length` before `isNone`: an argument that is absent is one
          // this client cannot read, which takes the wider set, while an
          // argument explicitly passed as `null`/`undefined` is a real `None`
          // and takes the narrow one. Conflating the two would break the
          // fail-safe direction in exactly the quiet way the fixtures exist to
          // catch.
          return args.length > 1 && isNone(args[1])
            ? write(Scope.Deployments)
            : DEPLOY_WITH_SECRET;
        case "cancel_deployment":
        case "set_deployment_env":
        case "set_deployment_image":
        case "set_deployment_launch":
        case "set_deployment_policy_root":
          return write(Scope.Deployments);
        case "register_wg_peer":
        case "remove_wg_peer":
          return write(Scope.Networking);
        // update_deployment_status, set_deployment_network, report_tls_status:
        // provider-signed.
        default:
          return null;
      }
    case "Collaborations":
      // Every call but the two root-only setters, cranks included.
      return call === "set_compute_node_image" || call === "set_compute_node_sku_id"
        ? null
        : write(Scope.Collaborations);
    case "Secrets":
      return write(Scope.Secrets);
    case "Volumes":
      return write(Scope.Volumes);
    case "OverlayNetworks":
      return write(Scope.Networking);
    case "Datasets":
      return call.startsWith("force_") ? null : write(Scope.Datasets);
    case "Resources":
      return RESOURCES_WRITE.has(call) ? write(Scope.Resources) : null;
    case "Organizations":
      return ORGANIZATION_WRITE.has(call) ? write(Scope.Organization) : null;
    case "Budgets":
      return BILLING_WRITE.has(call) ? write(Scope.Billing) : null;
    case "Communities":
      return call.startsWith("force_") ? null : write(Scope.Communities);
    default:
      return null;
  }
}

// `report_consumption`, `report_capacity`, `request_consumption_report` are
// provider-signed; the SKU and stake setters are root.
const RESOURCES_WRITE = new Set([
  "register_resource",
  "register_private_resource",
  "register_org_resource",
  "reactivate_resource",
  "set_resource_privacy",
  "add_to_whitelist",
  "remove_from_whitelist",
  "update_resource_name",
  "remove_resource",
]);

// `create_org` / `delete_org` stay human-signed.
const ORGANIZATION_WRITE = new Set([
  "add_member",
  "set_member_role",
  "remove_member",
  "create_project",
  "assign_to_project",
  "unassign_from_project",
  "delete_project",
  "add_project_deployment_peer",
]);

// Everything else in budgets — the roster calls, so a key never mints
// authority, and the treasury value movers.
const BILLING_WRITE = new Set([
  "allot",
  "defund_project",
  "set_plan_allotment",
  "add_purchased_allotment",
  "set_purchased_allotment",
  "set_member_billing",
  "clear_member_billing",
  "set_member_gas_limit",
]);

/**
 * Whether `value` is definitely an absent `Option`.
 *
 * `@polkadot` accepts several spellings for one: `null`, `undefined`, and the
 * `{ None: null }` enum shape all mean the same thing on the wire. Anything else
 * — including a value this cannot read — counts as present, which is the wider
 * requirement.
 */
function isNone(value: unknown): boolean {
  if (value === null || value === undefined) return true;
  if (typeof value === "object" && "None" in (value as Record<string, unknown>)) return true;
  return false;
}

/**
 * Whether a `ResourceRequest` sets either secret reference.
 *
 * The request is whatever the caller passed — the deployments façade
 * deliberately does not mirror its shape — so this reads the fields by name and
 * gives up safely. Anything unreadable is treated as referencing a secret.
 */
function requestReferencesSecret(request: unknown): boolean {
  if (typeof request !== "object" || request === null) return true;
  const fields = request as Record<string, unknown>;
  for (const name of ["secret_ref", "tls_secret_ref"]) {
    // A request without the field is one this client cannot reason about.
    if (!(name in fields)) return true;
    if (!isNone(fields[name])) return true;
  }
  return false;
}
