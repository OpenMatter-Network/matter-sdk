"""Connect from an apiKey and exercise the client surface.

Read-only unless ``MATTER_SUBMIT=yes``. Environment variables: examples/README.md.

    MATTER_API_KEY=$TEST_KEY ./bindings/python/.venv/bin/python examples/client-python/run.py
"""

import os
import sys

from matter_sdk import ApiKey, FeeEstimate, MatterClient, Network

# Opt-in gate for anything that costs gas.
SUBMIT_ENV = "MATTER_SUBMIT"
SUBMIT_VALUE = "yes"

# The well-known development account, read when no key is set so a read-only run
# still shows a real balance.
SAMPLE_ACCOUNT = "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"

# The call this tour submits behind the gate, and so the one it prices.
WRITE_PALLET = "Staking"
WRITE_CALL = "chill"


def read_key():
    """Read the key from the environment, never argv (shell history, ``ps``)."""
    for name in ("MATTER_API_KEY", "MATTER_SIGNER_SEED", "TEST_KEY"):
        value = os.environ.get(name)
        if value and value.strip():
            key = ApiKey(value)
            # Prints the account only: repr is redacted.
            print(f"{name} -> {key!r}")
            return value, key
    return None, None


def describe_chain(client: MatterClient) -> None:
    p = client.properties
    print("\n--- chain ---")
    print(f"  name            : {p.chain_name}")
    print(f"  spec_version    : {p.spec_version}")
    print(f"  token           : {p.token_symbol}")
    print(f"  ss58 prefix     : {p.ss58_prefix}")
    print(f"  decimals (spec) : {p.token_decimals_declared}")
    print(f"  decimals (live) : {p.token_decimals_effective}")
    if p.decimals_disagree:
        print("  ^ the node's chain spec disagrees with its runtime; the live value wins")
    print(f"  signing as      : {client.address or '(read-only)'}")


def read_state(client: MatterClient) -> None:
    print("\n--- reads (the generic surface) ---")

    print(f"  Secrets.NextSecretId        = {client.query('Secrets', 'NextSecretId')}")

    # Absence is not an error: an unfunded account has no row.
    if client.address is not None:
        entry = client.query("System", "Account", [client.address])
        free = entry["data"]["free"] if entry else None
        print(f"  System.Account(me).free     = {free if free is not None else 'absent'}")

    # substrate-interface cannot infer a raw state_call's type; this one is a bare u32.
    epoch = client.runtime_api("KgcApi_dkg_epoch", return_type="u32")
    print(f"  KgcApi_dkg_epoch            = {epoch}")
    print(f"  Balances.ExistentialDeposit = {client.constant('Balances', 'ExistentialDeposit')}")


def read_balance(client: MatterClient) -> None:
    """Façade reads: one question, one call, no pallet or encoding knowledge."""
    print("\n--- reads (friendly helpers) ---")

    # Two reads, one block: the balance is pinned to the head just read.
    head = client.network.head()
    balance = client.accounts.at(head.hash).balance(client.account_id or SAMPLE_ACCOUNT)

    def amount(plancks: int) -> str:
        return tokens(client, plancks)

    print(f"  at block        : {head.number}")
    print(f"  account         : {balance.account}")
    print(f"  exists          : {balance.exists}")
    print(f"  total           : {amount(balance.total)}")
    # Not ``free``: freezes and the existential deposit hold some of it back.
    print(f"  transferable    : {amount(balance.transferable)}")
    for hold in balance.holds:
        print(f"  on hold         : {amount(hold.amount)} for {hold.reason}")
    for freeze in balance.freezes:
        print(f"  frozen          : {amount(freeze.amount)} for {freeze.reason}")


def tokens(client: MatterClient, plancks: int) -> str:
    """An amount of plancks as the chain's token, for printing."""
    return f"{client.format_amount(plancks)} {client.properties.token_symbol}"


def charged_to(estimate: FeeEstimate) -> tuple:
    """Whose balance a fee comes out of, and how the tour knows. The runtime's
    answer comes first; where it has none, the signer is the working assumption;
    a read-only client charges nobody, so the sample account stands in."""
    if estimate.payer is not None:
        how = "per the runtime" if estimate.billed_to is None else "an organization's treasury"
        return estimate.payer, how
    if estimate.signer is not None:
        return estimate.signer, "the signer; the runtime did not say"
    return SAMPLE_ACCOUNT, "a sample account; this client is read-only"


def preflight(client: MatterClient) -> None:
    """Three reads put together: can whoever pays for this tour's write afford
    it?"""
    print("\n--- pre-flight (three reads, one block) ---")

    # Every read is pinned to one block, so the fee and the balance agree.
    head = client.network.head()
    estimate = client.fees.at(head.hash).estimate(WRITE_PALLET, WRITE_CALL, {})
    payer, how = charged_to(estimate)
    balance = client.accounts.at(head.hash).balance(payer)
    # A fee may not take the payer below the existential deposit.
    spendable = balance.transferable_keep_alive
    deposit = client.network.info().existential_deposit

    print(f"  call            : {estimate.pallet}.{estimate.call}")
    print(f"  at block        : {head.number}")
    print(f"  fee             : {tokens(client, estimate.partial_fee)} for {estimate.encoded_len} bytes")
    print(f"  charged to      : {balance.account} ({how})")
    print(
        f"  can spend       : {tokens(client, spendable)}, "
        f"keeping the existential deposit of {tokens(client, deposit)}"
    )
    if spendable >= estimate.partial_fee:
        print(f"  verdict         : affordable, leaving {tokens(client, spendable - estimate.partial_fee)}")
    else:
        print(f"  verdict         : short by {tokens(client, estimate.partial_fee - spendable)}")


def demonstrate_amounts(client: MatterClient) -> None:
    print("\n--- amounts (always plancks, never floats) ---")
    one = client.one_token()
    print(f"  1 {client.properties.token_symbol} = {one} plancks")
    print(f"  \"1.5\" = {client.parse_amount('1.5')} plancks")
    print(f"  {one} plancks reads back as {client.format_amount(one)}")

    try:
        client.parse_amount("0." + "0" * 40 + "1")
        print("  unexpectedly parsed an over-precise amount")
    except ValueError as e:
        print(f"  over-precise amount rejected: {e}")


def maybe_submit(client: MatterClient) -> None:
    print("\n--- writes ---")

    if client.address is None:
        print("  read-only client: nothing to submit.")
        return
    if os.environ.get(SUBMIT_ENV) != SUBMIT_VALUE:
        print("  would submit Staking.chill() via the curated staking façade:")
        print("      client.staking.chill()")
        print("  and the same call through the generic surface:")
        print('      client.tx("Staking", "chill", {})')
        print(f"  set {SUBMIT_ENV}={SUBMIT_VALUE} to actually send it (costs a fee).")
        return

    # `chill` is idempotent, self-targeted, and a no-op for a non-nominator: the
    # cheapest signed call that moves no funds.
    print("  submitting Staking.chill() ...")
    receipt = client.staking.chill()
    print(f"  finalized in block {receipt.block_hash}")
    print(f"  events: {[f'{p}.{e}' for p, e, _ in receipt.events]}")


def main() -> int:
    network = os.environ.get("MATTER_NETWORK", Network.TESTNET)
    rpc_url = os.environ.get("MATTER_RPC_URL")

    key_string, key = read_key()
    if key_string is None:
        print("No key set — connecting read-only.")
        client = MatterClient.connect(network=network, rpc_url=rpc_url)
    else:
        print("Connecting with an api key ...")
        client = MatterClient.connect_with_api_key(key_string, network=network, rpc_url=rpc_url)

    with client:
        describe_chain(client)
        read_state(client)
        read_balance(client)
        preflight(client)
        demonstrate_amounts(client)
        maybe_submit(client)

    print("\nDone.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - a demo should print, not traceback
        print(f"\nFAILED: {exc}", file=sys.stderr)
        sys.exit(1)
