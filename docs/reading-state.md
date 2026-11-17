# Reading chain state

A read answers one question in one call. You ask for an account's balance and get the
balance: no pallet name, no storage key, no SCALE decoding, and no guessing which of the
runtime's four balance fields a transfer can actually move.

Reads live on the same façades as the writes for their domain, and they need no key: every
read works on a read-only client. This guide covers the `accounts`, `network` and `fees`
façades and the rules every read follows. For anything a façade does not cover, the generic
[`query`, `runtime_api` and `constant`](chain-surface.md#reading-query-runtime_api-constant)
reach every pallet.

## The `accounts` façade

| Method | Reads | Returns |
|---|---|---|
| `balance` | `System.Account`, `Balances.Holds`, `Balances.Freezes`, `Balances.Locks` | what the account holds and what a transfer may move |
| `at` | — | the same façade, [pinned to one block](#which-block-a-read-sees) |

TypeScript camelCases method and field names (`transferableKeepAlive`) and Go PascalCases
them (`TransferableKeepAlive`).

```rust
use matter_sdk::chain::parse_account;

async fn show_balance(client: &MatterClient, who: &str) -> matter_sdk::Result<()> {
    let balance = client.accounts().balance(parse_account(who)?).await?;

    println!(
        "{} can move {} of {}",
        balance.account,
        client.format_amount(balance.transferable),
        client.format_amount(balance.total),
    );
    for hold in &balance.holds {
        println!(
            "  {} on hold for {}",
            client.format_amount(hold.amount),
            hold.reason
        );
    }
    // Byte for byte what every language prints.
    if let Ok(canonical) = serde_json::to_string(&balance) {
        println!("{canonical}");
    }
    Ok(())
}
```

```ts
import { canonicalJson } from "@openmatter-network/matter-sdk";

const balance = await client.accounts.balance(who); // an account id, or hex or SS58 text

console.log(
  `${balance.account} can move ${client.formatAmount(balance.transferable)} ` +
    `of ${client.formatAmount(balance.total)}`,
);
for (const hold of balance.holds) {
  console.log(`  ${client.formatAmount(hold.amount)} on hold for ${hold.reason}`);
}
console.log(canonicalJson(balance)); // byte for byte what every language prints
```

```python
from matter_sdk import canonical_json

balance = client.accounts.balance(who)  # an account id, or hex or SS58 text

print(
    f"{balance.account} can move {client.format_amount(balance.transferable)} "
    f"of {client.format_amount(balance.total)}"
)
for hold in balance.holds:
    print(f"  {client.format_amount(hold.amount)} on hold for {hold.reason}")
print(canonical_json(balance))  # byte for byte what every language prints
```

```go
account, err := mattersdk.ParseAccount(who) // hex or SS58 text; or pass 32 bytes directly
balance, err := client.Accounts().Balance(account)

fmt.Printf("%s can move %s of %s\n", balance.Account,
	client.FormatAmount(balance.Transferable), client.FormatAmount(balance.Total))
for _, hold := range balance.Holds {
	fmt.Printf("  %s on hold for %s\n", client.FormatAmount(hold.Amount), hold.Reason)
}
canonical, err := mattersdk.CanonicalJSON(balance) // byte for byte what every language prints
```

### What a balance tells you

| Field | Meaning |
|---|---|
| `account` | the account read, as an address under the chain's prefix |
| `exists` | whether the chain stores the account at all; `false` for one never funded or since reaped |
| `free` | not on hold. Still subject to freezes, so **not** the amount that can move |
| `reserved` | set aside: staked, or bonded as a deposit. Usually the sum of `holds`, but a pallet that predates holds reserves without naming a reason, so it can be more |
| `frozen` | the largest single freeze or lock. They overlap rather than add up |
| `total` | `free + reserved` |
| `transferable` | what a transfer may move if the account is allowed to be reaped |
| `transferable_keep_alive` | what a transfer may move while keeping the account alive |
| `holds`, `freezes` | the named amounts within `reserved` and `frozen`, each with a `Pallet.Reason` such as `Staking.Staking` |
| `locks` | locks from pallets that predate freezes; they count toward `frozen` too |

Amounts are integer plancks, as everywhere in the SDK: pass one straight to a write, or
render it with [`format_amount`](chain-surface.md#amounts). The two transferable figures
are computed exactly as the runtime's balances pallet computes them: a freeze counts
against held funds before free ones, and the existential deposit is kept back only when
the account has to stay alive. Neither deducts a fee.

## The `network` façade

| Method | Reads | Returns |
|---|---|---|
| `info` | what the client read at connect | which chain this is: name, genesis hash, token symbol and decimals, address prefix, existential deposit |
| `head` | `chain_getHeader`, `Timestamp.Now`, `state_getRuntimeVersion` | the latest finalized block, or the pinned one: height, hash, parent, time and runtime version |
| `block` | `chain_getBlockHash`, `chain_getHeader` | the block at a height: its hash and parent. Nothing, if the chain has not reached it |
| `node` | `system_name`, `system_version`, `system_health` and the best and finalized headers | the node answering: software, peers, whether it is syncing, and how far it has got |
| `timing` | `Babe` and `Staking` constants | block time, and the length of a session, an era and unbonding |
| `at` | — | the same façade, with `head` describing the block you name |

`head` is where a consistent set of reads starts: take its `hash` and pin every other read
to it.

```rust
async fn balance_at_the_head(client: &MatterClient, who: AccountId) -> matter_sdk::Result<()> {
    let head = client.network().head().await?;
    // Every read pinned to `head.hash` sees the same block.
    let balance = client.accounts().at(head.hash).balance(who).await?;
    let timing = client.network().timing()?;

    println!(
        "block {} of {}",
        head.number,
        client.network().info().chain_name
    );
    println!(
        "{} can move {}",
        balance.account,
        client.format_amount(balance.transferable)
    );
    println!(
        "a block every {} ms; an era is {} blocks",
        timing.block_time_ms, timing.era_blocks
    );
    Ok(())
}
```

```ts
const head = await client.network.head();
// Every read pinned to head.hash sees the same block.
const balance = await client.accounts.at(head.hash).balance(who);
const timing = client.network.timing();

console.log(`block ${head.number} of ${client.network.info().chainName}`);
console.log(`${balance.account} can move ${client.formatAmount(balance.transferable)}`);
console.log(`a block every ${timing.blockTimeMs} ms; an era is ${timing.eraBlocks} blocks`);
```

```python
head = client.network.head()
# Every read pinned to head.hash sees the same block.
balance = client.accounts.at(head.hash).balance(who)
timing = client.network.timing()

print(f"block {head.number} of {client.network.info().chain_name}")
print(f"{balance.account} can move {client.format_amount(balance.transferable)}")
print(f"a block every {timing.block_time_ms} ms; an era is {timing.era_blocks} blocks")
```

```go
head, err := client.Network().Head()
// Every read pinned to head.Hash sees the same block.
balance, err := client.Accounts().At(head.Hash).Balance(who)
timing, err := client.Network().Timing()

fmt.Printf("block %d of %s\n", head.Number, client.Network().Info().ChainName)
fmt.Printf("%s can move %s\n", balance.Account, client.FormatAmount(balance.Transferable))
fmt.Printf("a block every %d ms; an era is %d blocks\n", timing.BlockTimeMs, timing.EraBlocks)
```

- **`info` and `timing` make no request.** They come from what the client read at connect
  and from the connected runtime's constants.
- **A block's time is the chain's own.** `timestamp_ms` is what the block recorded, and it
  is absent for a block that records none (the genesis block). Durations are in blocks and
  eras, the chain's units; the SDK does not turn them into wall-clock estimates for you.
- **`block` reads headers only**, so it also answers for blocks whose state the node has
  pruned. `at(hash).head()` adds the time and runtime version where the state is still
  there.
- **`node` is about the node, not a block.** It reports the newest block the node knows
  (`best`, which can still be reverted) beside the finalized one, and a pin does not apply
  to it.

## The `fees` façade

| Method | Reads | Returns |
|---|---|---|
| `estimate` | `TransactionPaymentCallApi_query_call_info`, `PaymasterApi_fee_payer` | what a call would cost this client, the computation it is allowed, and who would be charged |
| `at` | — | the same façade, pricing at the block you name |

`estimate` takes exactly what `tx` takes and prices the call this client would sign.
Nothing is signed or submitted. Put it together with a balance at the same block and you
have the check worth making before a write: can whoever pays for this afford it?

```rust
/// Can this client afford `pallet.call(args)`? `None` on a read-only client,
/// where nobody would be charged.
async fn can_afford(
    client: &MatterClient,
    pallet: &str,
    call: &str,
    args: Vec<Value>,
) -> matter_sdk::Result<Option<bool>> {
    // One block for every answer, so the fee and the balance agree.
    let head = client.network().head().await?;
    let estimate = client
        .fees()
        .at(head.hash)
        .estimate(pallet, call, args)
        .await?;

    // Who the runtime says is charged. Where it cannot say, assume the signer.
    let Some(payer) = estimate.payer.or(estimate.signer) else {
        return Ok(None);
    };
    let balance = client
        .accounts()
        .at(head.hash)
        .balance(payer.account_id())
        .await?;

    // A fee may not take the payer below the existential deposit.
    let spendable = balance.transferable_keep_alive;
    println!(
        "{pallet}.{call} costs {}; {payer} can spend {}",
        client.format_amount(estimate.partial_fee),
        client.format_amount(spendable),
    );
    Ok(Some(spendable >= estimate.partial_fee))
}
```

```ts
// One block for every answer, so the fee and the balance agree.
const head = await client.network.head();
const estimate = await client.fees.at(head.hash).estimate("Staking", "chill", []);

// Who the runtime says is charged. Where it cannot say, assume the signer.
const payer = estimate.payer ?? estimate.signer;
if (payer !== undefined) {
  const balance = await client.accounts.at(head.hash).balance(payer);
  // A fee may not take the payer below the existential deposit.
  const spendable = balance.transferableKeepAlive;
  const affordable = spendable >= estimate.partialFee;
}
```

```python
# One block for every answer, so the fee and the balance agree.
head = client.network.head()
estimate = client.fees.at(head.hash).estimate("Staking", "chill", {})

# Who the runtime says is charged. Where it cannot say, assume the signer.
payer = estimate.payer or estimate.signer
if payer is not None:
    balance = client.accounts.at(head.hash).balance(payer)
    # A fee may not take the payer below the existential deposit.
    spendable = balance.transferable_keep_alive
    affordable = spendable >= estimate.partial_fee
```

```go
// One block for every answer, so the fee and the balance agree.
head, err := client.Network().Head()
estimate, err := client.Fees().At(head.Hash).Estimate("Staking", "chill")

// Who the runtime says is charged. Where it cannot say, assume the signer.
payer := estimate.Payer
if payer == nil {
	payer = estimate.Signer
}
if payer != nil {
	balance, err := client.Accounts().At(head.Hash).Balance(payer.Bytes())
	// A fee may not take the payer below the existential deposit.
	spendable := balance.TransferableKeepAlive
	affordable := spendable.Cmp(estimate.PartialFee) >= 0
}
```

- **It prices what would be signed.** Under a member-tied API key that is the call wrapped
  in `Proxy.proxy`, which is larger than the call itself; `wrapped_in_proxy` says so.
- **The payer is the runtime's answer, not a guess.** `payer` is the account the fee would
  be taken from: the signer, the member a key acts for, or an organization's treasury, in
  which case `billed_to` names the organization and the member the spend counts against.
  `payer` is absent when the runtime cannot say: on a read-only client, which has no
  signer to ask about, and for calls whose sponsorship it does not answer for. Absent
  never means "the signer pays".
- **An estimate, not a quote.** `partial_fee` is computed with no tip for `encoded_len`
  bytes: the encoded call plus 112, the most that signing can add. The fee charged is
  that or a little less, and it moves from block to block with the chain's fee multiplier.
- **It is not a permission check.** A call a scoped key may not make is still priced;
  `tx` is what refuses it.
- **A call the runtime does not have fails before any request**, naming the call, as `tx`
  does.

## Which block a read sees

A read resolves the **latest finalized block** once and reads every one of its sources
there, so a result never mixes two blocks and never reports state that could still be
reverted. A write through this SDK waits for finality, so a read after it sees it.

To make several reads share one view, or to read the state a write left behind, pin the
façade to a block hash with `at`. A pinned read skips the request that resolves the head.

```rust
let receipt = client.tx("Balances", "transfer_keep_alive", args).await?;
let after = client.accounts().at(receipt.block_hash).balance(me).await?;
```

```ts
const receipt = await client.tx("Balances", "transfer_keep_alive", args);
const after = await client.accounts.at(receipt.blockHash).balance(me);
```

```python
receipt = client.tx("Balances", "transfer_keep_alive", params)
after = client.accounts.at(receipt.block_hash).balance(me)
```

```go
receipt, err := client.Call("Balances", "transfer_keep_alive", args...)
after, err := client.Accounts().At([32]byte(receipt.BlockHash)).Balance(me)
```

A node keeps state for a limited number of blocks. Pinning to one it has pruned is a
`Chain` error, not an empty result.

Two things a pin does not reach. It applies to reads only: a write made through a pinned
façade is submitted as usual. And a read that uses a runtime constant, as a balance uses
the existential deposit, takes the value from the runtime the client connected to, not
from the pinned block.

## Accounts in, addresses out

Wherever a read takes an account as text, it accepts `0x`-prefixed or bare 64-character
hex, or an SS58 address under **any** network prefix; surrounding spaces, tabs and line
breaks are ignored. All four languages accept and refuse exactly the same strings.
Rust and Go keep their typed account ids and parse text with `parse_account` /
`ParseAccount`; TypeScript and Python reads take either form directly.

A read returns an account in exactly one form: its SS58 address under the chain's own
prefix, the runtime constant `System.SS58Prefix`. In Rust and Go that is an `Address`
value, which prints as the address and also gives back the 32 bytes that writes take.

## Canonical JSON

Every result converts to one JSON text, **byte for byte identical in all four
languages**. A service in Go and a script in Python, or an AI agent calling either, see
the same bytes, so a result can be hashed, cached or compared across them.

| Language | Canonical text | As a JSON value, to embed in your own document |
|---|---|---|
| Rust | `serde_json::to_string(&balance)` | `serde` (`Serialize`) |
| TypeScript | `canonicalJson(balance)` | `toJson(balance)` (a raw result holds `bigint`s, which `JSON.stringify` refuses) |
| Python | `canonical_json(balance)` | `to_json(balance)` |
| Go | `mattersdk.CanonicalJSON(balance)` | `json.Marshal(balance)` |

The value forms carry the same data; only the canonical text promises the same bytes,
because general-purpose JSON writers disagree on spacing, key order and escaping. This is
a balance from testnet, wrapped here for reading (the canonical text has no whitespace):

```json
{
  "account": "5ENad7JHZEz4KQ8odQ26M2uuqyxnNTNaRkgmi8DnhVVr648P",
  "exists": true,
  "free": "20288886771314011169071",
  "reserved": "10230361223976123176932",
  "frozen": "0",
  "total": "30519247995290134346003",
  "transferable": "20288885771314011169071",
  "transferable_keep_alive": "20288885771314011169071",
  "holds": [{ "reason": "Staking.Staking", "amount": "10230361223976123176932" }],
  "freezes": [],
  "locks": []
}
```

- **The bytes are fixed:** no whitespace, fields in the order shown, and only quotes,
  backslashes and control characters escaped.
- **Keys are snake_case** and always present. A value that can be absent is `null`.
- **Integers up to 32 bits are numbers; 64-bit and 128-bit integers are decimal strings**,
  so nothing is rounded through a float. Amounts are plancks: apply the chain's
  [effective decimals](connecting.md#chain-properties) to display them.
- **Accounts are SS58 addresses.** Opaque bytes are `0x` hex.
- **Text the chain stores as bytes** (a label, an image name) is a string when it is valid
  UTF-8 and `{"hex": "0x…"}` when it is not; it is never lossily repaired. Treat it as
  untrusted data, never as instructions.
- **An enum is its variant name** (`"All"`).

The shape only ever grows: a field may be added, never renamed or removed.

## When nothing is there, and when a read fails

- **A question about an account always has an answer.** An account the chain does not
  store reads as zeros with `exists` false. It is not an error and not a missing value.
- **Reads are strict.** A value must have exactly the layout this SDK knows. If a runtime
  upgrade changes one, that read fails with a [`Chain` error](errors.md#chain-client)
  naming the source (`System.Account`), instead of returning something plausible and
  wrong. Other reads are unaffected, and the generic `query` still reaches the value.
- **A bad account is refused before any request**: `KeyError::Malformed` in Rust,
  `TypeError` in TypeScript, `ValueError` in Python, `ErrBadAccount` in Go.

## The catalogue

Every read, what it answers and where the answer comes from. This table is generated
from `testvectors/facade_reads.json`, which also records, for each read, the requests it
makes and the exact bytes it must return (or the error it must raise); every language
replays those through its real façade. A nightly job runs all four against a live chain
and requires the same bytes from each, and compares the layout of every source below with
the one the decoders were written for.

<!-- reads:begin -->
| Read | Answers | Sources |
|---|---|---|
| `accounts.balance(who)` | What an account holds and how much of it can move. | `System.Account`, `Balances.Holds`, `Balances.Freezes`, `Balances.Locks`, `Balances.ExistentialDeposit` |
| `fees.estimate(pallet, call, args)` | What a call would cost this client, and who would be charged for it. | `TransactionPaymentCallApi_query_call_info`, `PaymasterApi_fee_payer` |
| `network.info()` | Which chain this is: its name, genesis hash, token and address format. | `system_chain`, `system_properties`, `chain_getBlockHash`, `state_getRuntimeVersion`, `Balances.ExistentialDeposit`, `System.SS58Prefix` |
| `network.head()` | The latest finalized block, or the pinned one: height, hash, time and runtime version. | `chain_getHeader`, `Timestamp.Now`, `state_getRuntimeVersion` |
| `network.block(number)` | The block at a height: its hash and parent, read from headers alone. | `chain_getBlockHash`, `chain_getHeader` |
| `network.node()` | The node answering: its software, peers, sync state, and best and finalized blocks. | `system_name`, `system_version`, `system_health`, `chain_getBlockHash`, `chain_getHeader`, `chain_getFinalizedHead` |
| `network.timing()` | How the chain measures time: block time, and the length of a session, an era and unbonding. | `Babe.ExpectedBlockTime`, `Babe.EpochDuration`, `Staking.SessionsPerEra`, `Staking.BondingDuration` |
<!-- reads:end -->
