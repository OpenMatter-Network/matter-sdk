// Operator account transfer: what still has to happen to move everything an
// old account holds to a new one. Pure — chain facts in, calls out — so every
// tool that runs a transfer plans it the same way; pinned by
// `testvectors/account_transfer.json`.
//
// A step is emitted only while its end state is not on record, so a plan made
// from fresh facts after an interruption is exactly what is still missing.
//
// Every fact about the old account is a pair (`Held`): `before` is the
// snapshot taken when the transfer began — what the new account must end up
// with — and `now` is the live state — what is still to be taken away. One
// batch is not atomic (see `toSudoBatch`): a revoke can land while the grant
// it pairs with fails, and only the snapshot still knows what to grant.
// Nothing here builds, signs or sends: a step names the account it runs as,
// and the caller dispatches it as that account (an operator through
// `Sudo.sudo_as`, see `toSudoBatch`).
//
// In the operator plan the old account's key is never needed and never
// trusted. What the chain gives no call to move is reported in `unmovable`,
// never dropped silently.
//
// Since 2.5.0 the same facts also plan a SELF-SERVE move (`planSelfTransfer`,
// at the end of this file) for a person who holds both keys; it is the path
// applications use. The operator plan stays for tools that act through
// `Sudo.sudo_as`, and is what the self-serve plan is derived from, so the two
// can never disagree about what a move consists of.

/** The first runtime with the two-step organization hand-over. */
export const MIN_TRANSFER_SPEC_VERSION = 333;

/** The runtime's `organizations::Role` variants. */
export enum OrgRole {
  Owner = "Owner",
  Admin = "Admin",
  Member = "Member",
  Viewer = "Viewer",
}

/** Whose authority a step runs under. `actor` on the step is the address. */
export enum TransferActor {
  Old = "old",
  New = "new",
  /** The owner of an organization the old account is only a member of. */
  OrgOwner = "org_owner",
  /** An organization's sponsor that is neither account nor its owner. */
  Sponsor = "sponsor",
}

/** Who an agent key the old account held acts for on chain now. */
export enum KeyPrincipal {
  Old = "old",
  New = "new",
  /** Revoked from the old account and not yet bound again. */
  None = "none",
}

export enum AgentKeyKind {
  /** Re-bound to the new account under the same address and scopes. */
  ApiKey = "api_key",
  /** A browser's own key: revoked, never re-created for another account. */
  SessionKey = "session_key",
}

/** Why nothing may be moved. No step is planned while any stands. */
export enum TransferRefusal {
  SameAccount = "same_account",
  /** This network predates the organization hand-over. */
  SpecTooOld = "spec_too_old",
  /** The new account is itself an agent key; it cannot hold keys of its own. */
  NewAccountIsAgentKey = "new_account_is_agent_key",
  /** The new account already belongs to an organization the old one does not. */
  NewAccountHasWorkspace = "new_account_has_workspace",
  /** The old account signed after the incident: investigate, do not move. */
  OldAccountActiveSinceIncident = "old_account_active_since_incident",
  /** Personal workloads would be left behind and nobody has accepted that. */
  UnmovableNotAcknowledged = "unmovable_not_acknowledged",
}

/** What the chain has no call to move. */
export enum UnmovableKind {
  Deployments = "deployments",
  Volumes = "volumes",
  Networks = "networks",
  Resources = "resources",
}

/** A fact about the old account: at the snapshot, and live. */
export interface Held<T> {
  readonly before: T;
  readonly now: T;
}

export interface Allowance {
  readonly plan: bigint;
  readonly purchased: bigint;
}

export interface ProjectTransferFacts {
  readonly id: string;
  readonly oldAssigned: Held<boolean>;
  readonly newAssigned: boolean;
  /** Holds a Deploy proxy on the project's budget account. */
  readonly oldDeployer: Held<boolean>;
  readonly newDeployer: boolean;
}

export interface OrgTransferFacts {
  readonly id: string;
  readonly owner: string;
  readonly pendingOwner: string | null;
  /** `null` when the old account is not a member. */
  readonly oldRole: Held<OrgRole | null>;
  readonly newRole: OrgRole | null;
  readonly sponsor: string | null;
  readonly oldAllowance: Held<Allowance>;
  readonly newAllowance: Allowance;
  readonly oldResourceOperator: Held<boolean>;
  readonly newResourceOperator: boolean;
  /** EVERY live project of the org, read from chain: the hand-over moves only
   *  the networks of the projects it is given. */
  readonly projects: readonly ProjectTransferFacts[];
}

export interface AgentKeyFacts {
  readonly key: string;
  readonly principal: KeyPrincipal;
  /** The key's `ScopeSet` bits as granted on chain. */
  readonly scopes: number;
  readonly kind: AgentKeyKind;
}

export interface OldSecretFacts {
  /** Decimal secret id. */
  readonly id: string;
  readonly grantedToNew: boolean;
  /** The new account has re-sealed it and nothing reads the original any more. */
  readonly replaced: boolean;
}

export type PersonalHoldings = Readonly<Record<UnmovableKind, number>>;

export interface TransferFacts {
  readonly specVersion: number;
  readonly old: string;
  readonly new: string;
  readonly newIsAgentKey: boolean;
  /** Organizations the new account is in that the old account is not. */
  readonly newOtherOrgCount: number;
  readonly oldActiveSinceIncident: boolean;
  /** The organization the old account billed to when the transfer began. */
  readonly oldBillingOrgBefore: string | null;
  readonly newBillingOrg: string | null;
  /** Every organization either account is, or the old account was, a member of. */
  readonly orgs: readonly OrgTransferFacts[];
  /** Every agent key the old account held when the transfer began. */
  readonly agentKeys: readonly AgentKeyFacts[];
  /** Proxies on the old account that are not agent keys. */
  readonly oldOtherProxies: number;
  readonly oldSecrets: readonly OldSecretFacts[];
  readonly oldTransferable: bigint;
  readonly personal: PersonalHoldings;
  /** The account's owner has accepted that `personal` stays behind. */
  readonly acknowledgedUnmovable: boolean;
}

export interface TransferStep {
  readonly as: TransferActor;
  /** The address the call is dispatched as. */
  readonly actor: string;
  /** Pallet and call as the runtime metadata names them. */
  readonly pallet: string;
  readonly call: string;
  /** Positional arguments; amounts are decimal strings. */
  readonly args: readonly unknown[];
}

export interface Unmovable {
  readonly kind: UnmovableKind;
  readonly count: number;
}

export interface TransferPlan {
  readonly steps: readonly TransferStep[];
  readonly refusals: readonly TransferRefusal[];
  readonly unmovable: readonly Unmovable[];
}

/** A call as data: what `MatterClient.tx` and metadata-driven builders take. */
export interface CallTree {
  readonly pallet: string;
  readonly call: string;
  readonly args: readonly unknown[];
}

const Pallet = {
  Organizations: "Organizations",
  Budgets: "Budgets",
  Secrets: "Secrets",
  Proxy: "Proxy",
  Balances: "Balances",
  Utility: "Utility",
  Sudo: "Sudo",
} as const;

const NO_ALLOWANCE = "0";

interface Actor {
  readonly as: TransferActor;
  readonly address: string;
}

const step = (actor: Actor, pallet: string, call: string, args: readonly unknown[]): TransferStep => ({
  as: actor.as,
  actor: actor.address,
  pallet,
  call,
  args,
});

const when = <T>(condition: boolean, ...items: T[]): T[] => (condition ? items : []);

const unmovableOf = (personal: PersonalHoldings): Unmovable[] =>
  // The enum's own order is the reporting order.
  Object.values(UnmovableKind)
    .map((kind) => ({ kind, count: personal[kind] }))
    .filter((u) => u.count > 0);

function refusalsOf(facts: TransferFacts, unmovable: readonly Unmovable[]): TransferRefusal[] {
  if (facts.old === facts.new) return [TransferRefusal.SameAccount];
  const ownsAnOrg = facts.orgs.some((o) => o.owner === facts.old);
  return [
    ...when(ownsAnOrg && facts.specVersion < MIN_TRANSFER_SPEC_VERSION, TransferRefusal.SpecTooOld),
    ...when(facts.newIsAgentKey, TransferRefusal.NewAccountIsAgentKey),
    ...when(facts.newOtherOrgCount > 0, TransferRefusal.NewAccountHasWorkspace),
    ...when(facts.oldActiveSinceIncident, TransferRefusal.OldAccountActiveSinceIncident),
    ...when(unmovable.length > 0 && !facts.acknowledgedUnmovable, TransferRefusal.UnmovableNotAcknowledged),
  ];
}

function projectSteps(manager: Actor, facts: TransferFacts, org: string, p: ProjectTransferFacts): TransferStep[] {
  return [
    ...when(
      p.oldAssigned.before && !p.newAssigned,
      step(manager, Pallet.Organizations, "assign_to_project", [org, p.id, facts.new]),
    ),
    ...when(
      p.oldDeployer.before && !p.newDeployer,
      step(manager, Pallet.Budgets, "authorize_project_deployer", [org, p.id, facts.new]),
    ),
    // Removing a member leaves its Deploy proxy working: the revoke is its own step.
    ...when(p.oldDeployer.now, step(manager, Pallet.Budgets, "revoke_project_deployer", [org, p.id, facts.old])),
    ...when(p.oldAssigned.now, step(manager, Pallet.Organizations, "unassign_from_project", [org, p.id, facts.old])),
  ];
}

function allowanceSteps(sponsor: Actor, facts: TransferFacts, org: OrgTransferFacts): TransferStep[] {
  const { before: was, now: still } = org.oldAllowance;
  const has = org.newAllowance;
  return [
    // Raised to what the old account had; never lowered.
    ...when(
      has.plan < was.plan,
      step(sponsor, Pallet.Budgets, "set_plan_allotment", [org.id, facts.new, was.plan.toString()]),
    ),
    ...when(
      has.purchased < was.purchased,
      step(sponsor, Pallet.Budgets, "set_purchased_allotment", [org.id, facts.new, was.purchased.toString()]),
    ),
    // Removal does not clear an allowance either.
    ...when(still.plan > 0n, step(sponsor, Pallet.Budgets, "set_plan_allotment", [org.id, facts.old, NO_ALLOWANCE])),
    ...when(
      still.purchased > 0n,
      step(sponsor, Pallet.Budgets, "set_purchased_allotment", [org.id, facts.old, NO_ALLOWANCE]),
    ),
  ];
}

function orgSteps(facts: TransferFacts, org: OrgTransferFacts): TransferStep[] {
  const old: Actor = { as: TransferActor.Old, address: facts.old };
  const successor: Actor = { as: TransferActor.New, address: facts.new };
  const oldOwns = org.owner === facts.old;

  // Who manages the org once any hand-over in this plan has run.
  const ownerAfter = oldOwns ? facts.new : org.owner;
  const manager: Actor = ownerAfter === facts.new ? successor : { as: TransferActor.OrgOwner, address: ownerAfter };

  const sponsorAfter = org.sponsor === facts.old ? facts.new : org.sponsor;
  const sponsor: Actor | null =
    sponsorAfter === null
      ? null
      : sponsorAfter === facts.new
        ? successor
        : sponsorAfter === ownerAfter
          ? manager
          : { as: TransferActor.Sponsor, address: sponsorAfter };

  const membership = oldOwns
    ? [
        // The nominee must already be a member, and nobody can add an Owner.
        ...when(
          org.newRole === null,
          step(old, Pallet.Organizations, "add_member", [org.id, facts.new, OrgRole.Admin]),
        ),
        ...when(
          org.pendingOwner !== facts.new,
          step(old, Pallet.Organizations, "propose_ownership_transfer", [org.id, facts.new]),
        ),
        step(successor, Pallet.Organizations, "accept_ownership_transfer", [org.id, org.projects.map((p) => p.id)]),
      ]
    : when(
        org.newRole === null && org.oldRole.before !== null,
        step(manager, Pallet.Organizations, "add_member", [org.id, facts.new, org.oldRole.before]),
      );

  return [
    ...membership,
    ...org.projects.flatMap((p) => projectSteps(manager, facts, org.id, p)),
    ...when(org.sponsor === facts.old, step(old, Pallet.Budgets, "transfer_sponsorship", [org.id, facts.new])),
    ...(sponsor === null ? [] : allowanceSteps(sponsor, facts, org)),
    ...when(
      facts.oldBillingOrgBefore === org.id && facts.newBillingOrg !== org.id,
      step(manager, Pallet.Budgets, "set_member_billing", [org.id, facts.new]),
    ),
    ...when(
      org.oldResourceOperator.before && !org.newResourceOperator,
      step(manager, Pallet.Budgets, "authorize_org_resource_operator", [org.id, facts.new]),
    ),
    // Last in the org: after a hand-over the old account is an Admin until here.
    ...when(org.oldRole.now !== null, step(manager, Pallet.Organizations, "remove_member", [org.id, facts.old])),
  ];
}

function agentKeySteps(facts: TransferFacts): TransferStep[] {
  const old: Actor = { as: TransferActor.Old, address: facts.old };
  const successor: Actor = { as: TransferActor.New, address: facts.new };
  return facts.agentKeys.flatMap((k) => [
      // A key can be bound again only after its principal lets go of it.
      ...when(k.principal === KeyPrincipal.Old, step(old, Pallet.Budgets, "revoke_agent_key", [k.key])),
      ...when(
        k.kind === AgentKeyKind.ApiKey && k.principal !== KeyPrincipal.New,
        step(successor, Pallet.Budgets, "authorize_agent_key", [k.key, k.scopes]),
      ),
    ]);
}

/**
 * Everything still to do to leave the old account holding nothing and the new
 * one holding what it held. Ordered; safe to dispatch in one batch.
 */
export function planAccountTransfer(facts: TransferFacts): TransferPlan {
  const unmovable = unmovableOf(facts.personal);
  const refusals = refusalsOf(facts, unmovable);
  if (refusals.length > 0) return { steps: [], refusals, unmovable };

  const old: Actor = { as: TransferActor.Old, address: facts.old };
  const steps = [
    ...facts.orgs.flatMap((org) => orgSteps(facts, org)),
    ...agentKeySteps(facts),
    // A secret's owner can never change: the new account is let in, re-seals
    // for itself, and the originals go in `planSecretCleanup`.
    ...facts.oldSecrets
      .filter((s) => !s.grantedToNew && !s.replaced)
      .map((s) => step(old, Pallet.Secrets, "grant_access", [s.id, { User: facts.new }])),
    // After the agent keys: removing a key's proxy this way would strand its binding.
    ...when(facts.oldOtherProxies > 0, step(old, Pallet.Proxy, "remove_proxies", [])),
    // Last: the old account's balance is what its remaining steps would be paid from.
    ...when(facts.oldTransferable > 0n, step(old, Pallet.Balances, "transfer_all", [facts.new, false])),
  ];
  return { steps, refusals, unmovable };
}

/** Phase 2: delete the old account's secrets the new account has replaced. */
export function planSecretCleanup(old: string, secrets: readonly OldSecretFacts[]): TransferStep[] {
  return secrets
    .filter((s) => s.replaced)
    .map((s) => step({ as: TransferActor.Old, address: old }, Pallet.Secrets, "delete_secret", [s.id]));
}

/**
 * Whether the old account is left with nothing to use or lose: the post-check
 * a transfer must pass. A secret not yet replaced counts as something.
 */
export function oldAccountHoldsNothing(facts: TransferFacts): boolean {
  return (
    facts.orgs.every(
      (o) =>
        o.oldRole.now === null &&
        o.owner !== facts.old &&
        o.pendingOwner !== facts.old &&
        o.sponsor !== facts.old &&
        o.oldAllowance.now.plan === 0n &&
        o.oldAllowance.now.purchased === 0n &&
        o.projects.every((p) => !p.oldAssigned.now && !p.oldDeployer.now),
    ) &&
    facts.agentKeys.every((k) => k.principal !== KeyPrincipal.Old) &&
    facts.oldOtherProxies === 0 &&
    facts.oldSecrets.every((s) => s.replaced) &&
    facts.oldTransferable === 0n
  );
}

/**
 * One operator call for a plan: `Utility.batch_all` of `Sudo.sudo_as(actor,
 * call)`, in order. `sudo_as` never fails the outer call — each item reports
 * its own result in `Sudo.SudoAsDone`, so the caller must read every one and
 * re-plan from fresh facts if any failed.
 */
export function toSudoBatch(steps: readonly TransferStep[]): CallTree {
  if (steps.length === 0) throw new Error("toSudoBatch: no steps to dispatch");
  return {
    pallet: Pallet.Utility,
    call: "batch_all",
    args: [
      steps.map((s) => ({
        pallet: Pallet.Sudo,
        call: "sudo_as",
        args: [s.actor, { pallet: s.pallet, call: s.call, args: s.args }],
      })),
    ],
  };
}

// ── The self-serve move ─────────────────────────────────────────────────────
//
// The same facts, for a person who holds BOTH keys: each account signs its own
// half as ordinary calls, with no operator. What differs from the plan above:
//
//  - The calls are grouped into PHASES, each one account's `Utility.batch_all`
//    — which, signed by its own account, is atomic. Every dependency between
//    the two accounts points one way (the old account lets go, then the new
//    one takes), so the phases run in one fixed order.
//  - What only a third party can sign (another organization's owner, or a
//    sponsor that is neither account) cannot be done at all: it is reported in
//    `needsOthers`, never planned.
//  - The old account signing is the point, so that it "signed since the
//    incident" is not a refusal. Only an account that OWNS an organization is
//    served; a member asks its organization's owner for a fresh invite.
//
// Between `take` and `leave` the new account re-seals the secrets it was let
// into; that is the caller's work, and `leave` deletes a secret only once the
// facts say it was replaced.

/** One account's batch. The values are the fixed order they run in. */
export enum SelfTransferPhase {
  /** Old: let the new account in — membership, the hand-over offer, its keys
   *  released, its secrets shared. */
  Share = "share",
  /** New: accept the hand-over and take what the old account held in it. */
  Take = "take",
  /** Old: delete what was replaced, hand over sponsorship, clear its proxies,
   *  and send its balance — last, since nothing it sends after could be paid. */
  Leave = "leave",
  /** New, once it is the sponsor: the allowances. */
  Settle = "settle",
  /** New: remove the old account from the organization. */
  Close = "close",
}

export enum SelfTransferRefusal {
  SameAccount = "same_account",
  SpecTooOld = "spec_too_old",
  NewAccountIsAgentKey = "new_account_is_agent_key",
  NewAccountHasWorkspace = "new_account_has_workspace",
  /** The old account owned no organization when the move began. */
  OldOwnsNoOrganization = "old_owns_no_organization",
  UnmovableNotAcknowledged = "unmovable_not_acknowledged",
}

export type SelfSigner = TransferActor.Old | TransferActor.New;

export interface SelfTransferBatch {
  readonly phase: SelfTransferPhase;
  readonly signer: SelfSigner;
  /** Never empty: a phase with nothing left is not in the plan. */
  readonly steps: readonly TransferStep[];
}

export interface SelfTransferPlan {
  readonly phases: readonly SelfTransferBatch[];
  /** Calls only another organization's owner, or a sponsor, can make. */
  readonly needsOthers: readonly TransferStep[];
  readonly refusals: readonly SelfTransferRefusal[];
  readonly unmovable: readonly Unmovable[];
}

const PHASE_SIGNER: Readonly<Record<SelfTransferPhase, SelfSigner>> = {
  [SelfTransferPhase.Share]: TransferActor.Old,
  [SelfTransferPhase.Take]: TransferActor.New,
  [SelfTransferPhase.Leave]: TransferActor.Old,
  [SelfTransferPhase.Settle]: TransferActor.New,
  [SelfTransferPhase.Close]: TransferActor.New,
};

/** Which phase each call belongs to, by the account that signs it. A call
 *  the operator plan emits and this table lacks is a bug, found at once. */
const PHASE_OF: Readonly<Record<SelfSigner, Readonly<Record<string, SelfTransferPhase>>>> = {
  [TransferActor.Old]: {
    "Organizations.add_member": SelfTransferPhase.Share,
    "Organizations.propose_ownership_transfer": SelfTransferPhase.Share,
    "Budgets.revoke_agent_key": SelfTransferPhase.Share,
    "Secrets.grant_access": SelfTransferPhase.Share,
    "Secrets.delete_secret": SelfTransferPhase.Leave,
    "Budgets.transfer_sponsorship": SelfTransferPhase.Leave,
    "Proxy.remove_proxies": SelfTransferPhase.Leave,
    "Balances.transfer_all": SelfTransferPhase.Leave,
  },
  [TransferActor.New]: {
    "Organizations.accept_ownership_transfer": SelfTransferPhase.Take,
    "Organizations.assign_to_project": SelfTransferPhase.Take,
    "Budgets.authorize_project_deployer": SelfTransferPhase.Take,
    "Budgets.revoke_project_deployer": SelfTransferPhase.Take,
    "Organizations.unassign_from_project": SelfTransferPhase.Take,
    "Budgets.set_member_billing": SelfTransferPhase.Take,
    "Budgets.authorize_org_resource_operator": SelfTransferPhase.Take,
    "Budgets.authorize_agent_key": SelfTransferPhase.Take,
    "Budgets.set_plan_allotment": SelfTransferPhase.Settle,
    "Budgets.set_purchased_allotment": SelfTransferPhase.Settle,
    "Organizations.remove_member": SelfTransferPhase.Close,
  },
};

const isSelfSigned = (s: TransferStep): boolean => s.as === TransferActor.Old || s.as === TransferActor.New;

function phaseOf(s: TransferStep): SelfTransferPhase {
  const phase = PHASE_OF[s.as as SelfSigner][`${s.pallet}.${s.call}`];
  if (phase === undefined) throw new Error(`planSelfTransfer: no phase for ${s.pallet}.${s.call} signed as ${s.as}`);
  return phase;
}

const OPERATOR_TO_SELF: Readonly<Partial<Record<TransferRefusal, SelfTransferRefusal>>> = {
  [TransferRefusal.SameAccount]: SelfTransferRefusal.SameAccount,
  [TransferRefusal.SpecTooOld]: SelfTransferRefusal.SpecTooOld,
  [TransferRefusal.NewAccountIsAgentKey]: SelfTransferRefusal.NewAccountIsAgentKey,
  [TransferRefusal.NewAccountHasWorkspace]: SelfTransferRefusal.NewAccountHasWorkspace,
  [TransferRefusal.UnmovableNotAcknowledged]: SelfTransferRefusal.UnmovableNotAcknowledged,
};

function selfRefusalsOf(facts: TransferFacts, operatorRefusals: readonly TransferRefusal[]): SelfTransferRefusal[] {
  const carried = operatorRefusals.flatMap((r) => OPERATOR_TO_SELF[r] ?? []);
  if (carried.includes(SelfTransferRefusal.SameAccount)) return carried;
  // The SNAPSHOT's role: after the hand-over the old account is an Admin, and
  // a move resumed there is still the move of an account that owned one.
  const ownedOne = facts.orgs.some((o) => o.oldRole.before === OrgRole.Owner);
  // The enum's own order is the reporting order.
  return Object.values(SelfTransferRefusal).filter(
    (r) => carried.includes(r) || (r === SelfTransferRefusal.OldOwnsNoOrganization && !ownedOne),
  );
}

/**
 * Everything still to do for a person holding both keys to move what the old
 * account held, as the batches each account signs, in the order they run.
 *
 * POST: no phase is empty; every step of a phase is signed by that phase's
 *       account; `Balances.transfer_all` is the last step of `leave`.
 */
export function planSelfTransfer(facts: TransferFacts): SelfTransferPlan {
  const operator = planAccountTransfer({ ...facts, oldActiveSinceIncident: false });
  const refusals = selfRefusalsOf(facts, operator.refusals);
  if (refusals.length > 0) return { phases: [], needsOthers: [], refusals, unmovable: operator.unmovable };

  const all = [...operator.steps, ...planSecretCleanup(facts.old, facts.oldSecrets)];
  const own = all.filter(isSelfSigned);
  // Within a phase the operator plan's order holds, except that the balance
  // goes after everything else the old account still has to send.
  const leavingLast = (steps: readonly TransferStep[]): TransferStep[] => [
    ...steps.filter((s) => s.call !== "transfer_all"),
    ...steps.filter((s) => s.call === "transfer_all"),
  ];
  const phases = Object.values(SelfTransferPhase)
    .map((phase) => ({
      phase,
      signer: PHASE_SIGNER[phase],
      steps: leavingLast(own.filter((s) => phaseOf(s) === phase)),
    }))
    .filter((p) => p.steps.length > 0);
  return { phases, needsOthers: all.filter((s) => !isSelfSigned(s)), refusals, unmovable: operator.unmovable };
}

/**
 * Whether a self-serve move has nothing left to send. `keptSecretIds` are the
 * old account's secrets the new account could NOT replace (something still
 * reads the original): they stay with the old account, shared, and do not
 * hold the move open. Any other secret must be gone.
 */
export function selfTransferIsComplete(facts: TransferFacts, keptSecretIds: readonly string[]): boolean {
  const plan = planSelfTransfer(facts);
  const kept = new Set(keptSecretIds);
  return (
    plan.refusals.length === 0 &&
    plan.phases.length === 0 &&
    facts.oldSecrets.every((s) => kept.has(s.id))
  );
}
