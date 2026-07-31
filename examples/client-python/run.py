"""Connect to OpenMatter from an apiKey and exercise the whole client surface.

Read-only by default. Every call here is a read unless you opt into submission
with ``MATTER_SUBMIT=yes``, so running it costs nothing and cannot change chain
state by accident.

    MATTER_API_KEY=$TEST_KEY ./bindings/python/.venv/bin/python examples/client-python/run.py
    MATTER_API_KEY=$TEST_KEY MATTER_SUBMIT=yes ...    # actually submits

    MATTER_API_KEY   the key; falls back to MATTER_SIGNER_SEED, then TEST_KEY
    MATTER_RPC_URL   endpoint override (default: testnet)
    MATTER_NETWORK   testnet (default) or mainnet
    MATTER_CONFIRM   must be "yes" for a signing client on mainnet
    MATTER_SUBMIT    must be "yes" to submit anything
"""

import os
import sys

from matter_vault import ApiKey, MatterClient, Network

# Opt-in gate for anything that costs gas.
SUBMIT_ENV = "MATTER_SUBMIT"
SUBMIT_VALUE = "yes"


def read_key():
    """The key is read from the environment, never from argv — argv lands in shell
    history and ``ps`` output."""
    for name in ("MATTER_API_KEY", "MATTER_SIGNER_SEED", "TEST_KEY"):
        value = os.environ.get(name)
        if value and value.strip():
            key = ApiKey(value)
            # Note what this prints: the account, never the key. repr is redacted,
            # so even a careless log is safe.
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
    """The generic surface: every pallet the runtime exposes, resolved by name."""
    print("\n--- reads (the generic surface) ---")

    print(f"  Secrets.NextSecretId        = {client.query('Secrets', 'NextSecretId')}")

    # Absence is normal control flow, not an error: an unfunded account has no row.
    if client.address is not None:
        entry = client.query("System", "Account", [client.address])
        free = entry["data"]["free"] if entry else None
        print(f"  System.Account(me).free     = {free if free is not None else 'absent'}")

    # The return type is the caller's to state: substrate-interface cannot infer it
    # from a raw `state_call`. `KgcApi_dkg_epoch` returns a bare u32, not an Option.
    epoch = client.runtime_api("KgcApi_dkg_epoch", return_type="u32")
    print(f"  KgcApi_dkg_epoch            = {epoch}")
    print(f"  Balances.ExistentialDeposit = {client.constant('Balances', 'ExistentialDeposit')}")


def demonstrate_amounts(client: MatterClient) -> None:
    """Amounts are always integer plancks; conversion is explicit."""
    print("\n--- amounts (always plancks, never floats) ---")
    one = client.one_token()
    print(f"  1 {client.properties.token_symbol} = {one} plancks")
    print(f"  \"1.5\" = {client.parse_amount('1.5')} plancks")
    print(f"  {one} plancks reads back as {client.format_amount(one)}")

    # Excess precision is rejected rather than rounded: losing someone's funds to a
    # silent truncation is not a trade worth making for convenience.
    try:
        client.parse_amount("0." + "0" * 40 + "1")
        print("  unexpectedly parsed an over-precise amount")
    except ValueError as e:
        print(f"  over-precise amount rejected: {e}")


def maybe_submit(client: MatterClient) -> None:
    """What submission looks like. Gated, because it costs gas."""
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

    # `chill` is the demo call because it is idempotent, self-targeted, and a no-op
    # for an account that is not nominating — the cheapest way to prove the signing
    # path end-to-end without moving funds.
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
