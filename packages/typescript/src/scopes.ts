// Read/Write scopes for member-tied API keys. Port of `matter_sdk_key::scopes`,
// which documents the wire contract; pinned by `testvectors/scope_bits.json` and
// `testvectors/required_scopes.json`. Ported rather than wasm-shared so
// argument-sensitive rows can read call arguments before encoding.

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

/** Scope names, indexed by discriminant; shared by rendering and parsing. */
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

/** Rendering of an empty set. */
const EMPTY_TEXT = "(none)";

const SCOPE_COUNT = SCOPE_NAMES.length;

function bit(scope: Scope, access: Access): number {
  return 1 << (scope * 2 + access);
}

/** An immutable set of `(scope, access)` grants, as a `u32` bitmask. */
export class ScopeSet {
  /** No grants. */
  static readonly EMPTY = new ScopeSet(0);
  /** Every defined `(scope, access)` bit. */
  static readonly ALL = new ScopeSet((1 << (SCOPE_COUNT * 2)) - 1);

  readonly bits: number;

  private constructor(bits: number) {
    // Unsigned: JS bitwise ops are int32, so bit 31 would go negative.
    this.bits = bits >>> 0;
  }

  /** A set from raw wire bits. Unvalidated; check with `isValid()`. */
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

  with(scope: Scope, access: Access): ScopeSet {
    return new ScopeSet(this.bits | bit(scope, access));
  }

  union(other: ScopeSet): ScopeSet {
    return new ScopeSet(this.bits | other.bits);
  }

  contains(scope: Scope, access: Access): boolean {
    return (this.bits & bit(scope, access)) !== 0;
  }

  /** `this ⊇ other`. */
  isSuperset(other: ScopeSet): boolean {
    return (this.bits & other.bits) === other.bits;
  }

  /** `this ⊆ other`. */
  isSubset(other: ScopeSet): boolean {
    return other.isSuperset(this);
  }

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
   * Parse `deployments:rw, secrets:r`. Case-insensitive; comma and/or
   * whitespace separated; `""` and `(none)` are empty. Round-trips `toString`.
   * Throws on unknown scopes, missing or repeated access letters.
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
        // Reject repeated letters rather than fold them.
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
 * What `pallet.call(args)` requires of a delegated key, or `null` if no key may
 * make it (provider-signed, root-only, org lifecycle, roster calls, treasury
 * value movers).
 *
 * A courtesy for clear errors, not a boundary: the runtime enforces. Fails safe:
 * an unreadable argument requires the wider set.
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
          // A missing argument is unreadable (wider set); an explicit
          // `null`/`undefined` is a real `None` (narrow set).
          return args.length > 1 && isNone(args[1])
            ? write(Scope.Deployments)
            : DEPLOY_WITH_SECRET;
        default:
          if (JOBS_DEPLOYMENTS_WRITE.has(call)) return write(Scope.Deployments);
          if (JOBS_NETWORKING_WRITE.has(call)) return write(Scope.Networking);
          // update_deployment_status, set_deployment_network, report_tls_status:
          // provider-signed.
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

const JOBS_DEPLOYMENTS_WRITE = new Set([
  "cancel_deployment",
  "set_deployment_env",
  "set_deployment_image",
  "set_deployment_launch",
  "set_deployment_policy_root",
  "set_deployment_volumes",
  "set_deployment_restart_policy",
]);

const JOBS_NETWORKING_WRITE = new Set(["register_wg_peer", "remove_wg_peer"]);

// `report_consumption`, `report_capacity`, `request_consumption_report` are
// provider-signed; the SKU and stake setters are root.
const RESOURCES_WRITE = new Set([
  "register_resource",
  "register_private_resource",
  "register_org_resource",
  "reactivate_resource",
  "suspend_resource",
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

// Not listed: roster calls (a key never mints authority) and treasury value movers.
const BILLING_WRITE = new Set([
  "allot",
  "defund_project",
  "set_plan_allotment",
  "add_purchased_allotment",
  "set_purchased_allotment",
  "set_member_billing",
  "clear_member_billing",
  "set_member_gas_limit",
  "set_project_spend_cap",
]);

/**
 * Every `(pallet, call)` this module names explicitly, for the fixture replay's
 * reverse direction: a name the runtime no longer has is drift. Not exported
 * from the package.
 *
 * @internal
 */
export const LOCALLY_NAMED_CALLS: readonly (readonly [string, string])[] = [
  ["Jobs", "request_deployment"],
  ["Jobs", "set_deployment_secret_ref"],
  ...[...JOBS_DEPLOYMENTS_WRITE, ...JOBS_NETWORKING_WRITE].map((c) => ["Jobs", c] as const),
  ["Collaborations", "set_compute_node_image"],
  ["Collaborations", "set_compute_node_sku_id"],
  ...[...RESOURCES_WRITE].map((c) => ["Resources", c] as const),
  ...[...ORGANIZATION_WRITE].map((c) => ["Organizations", c] as const),
  ...[...BILLING_WRITE].map((c) => ["Budgets", c] as const),
];

/**
 * Whether `value` is definitely an absent `Option`: `null`, `undefined`, or
 * `{ None: null }`. Anything else counts as present (the wider requirement).
 */
function isNone(value: unknown): boolean {
  if (value === null || value === undefined) return true;
  if (typeof value === "object" && "None" in (value as Record<string, unknown>)) return true;
  return false;
}

/**
 * Whether a `ResourceRequest` sets either secret reference. Anything unreadable,
 * including a missing field, counts as referencing a secret.
 */
function requestReferencesSecret(request: unknown): boolean {
  if (typeof request !== "object" || request === null) return true;
  const fields = request as Record<string, unknown>;
  for (const name of ["secret_ref", "tls_secret_ref"]) {
    if (!(name in fields)) return true;
    if (!isNone(fields[name])) return true;
  }
  return false;
}
