# Staking

The `staking` façade covers MatterChain's standard FRAME staking (`Staking`) and
nomination pools (`NominationPools`): bond, nominate, unbond, and collect pool rewards.
Every amount is an integer number of plancks. Convert from tokens with
[`parse_amount`](chain-surface.md#amounts), never with a hand-written exponent.

## Methods

| Method | Pallet call | Notes |
|---|---|---|
| `bond` | `Staking.bond` | Takes an amount and the runtime's `RewardDestination` (e.g. `Staked`) |
| `bond_extra` | `Staking.bond_extra` | Adds to an existing bond |
| `unbond` | `Staking.unbond` | Starts the unbonding period. Funds stay locked until you call `withdraw_unbonded` |
| `withdraw_unbonded` | `Staking.withdraw_unbonded` | Returns unlocked funds to your free balance. Takes the number of slashing spans |
| `nominate` | `Staking.nominate` | Nominates validators by account id |
| `chill` | `Staking.chill` | Stops nominating or validating |
| `join_pool` | `NominationPools.join` | Joins pool `pool_id` with `amount` plancks |
| `claim_pool_payout` | `NominationPools.claim_payout` | Claims accrued pool rewards |

TypeScript camelCases these names (`bondExtra`) and Go PascalCases them (`BondExtra`).
Staking moves the signer's own funds, so a [scoped key](keys-and-scopes.md#scoped-keys)
cannot call any of these methods: they return `NeverAdmitted`. Stake from the member's
account directly, or through a [signer](secure-signing.md).

```rust
use matter_sdk::chain::Value;

let amount = client.parse_amount("10")?;
client.staking().bond(amount, Value::unnamed_variant("Staked", [])).await?;
client.staking().nominate(&[validator]).await?;
```

```ts
const amount = client.parseAmount("10");
await client.staking.bond(amount, { Staked: null });
await client.staking.nominate([validator]);                   // 32-byte Uint8Array ids
```

```python
amount = client.parse_amount("10")
client.staking.bond(amount, {"Staked": None})
client.staking.nominate([validator])                          # SS58 addresses
```

```go
amount, err := client.ParseAmount("10")
if err != nil {
	return err
}
// RewardDestination::Staked is variant 0 (types is go-substrate-rpc-client/v4/types).
if _, err := client.Staking().Bond(amount, types.NewU8(0)); err != nil {
	return err
}
_, err = client.Staking().Nominate([][]byte{validator})
```

## Nomination pools

A pool bonds and nominates on your behalf, so you need only an amount and a pool id:

```rust
client.staking().join_pool(client.parse_amount("5")?, pool_id).await?;
client.staking().claim_pool_payout().await?;
```

```ts
await client.staking.joinPool(client.parseAmount("5"), poolId);
await client.staking.claimPoolPayout();
```

```python
client.staking.join_pool(client.parse_amount("5"), pool_id)
client.staking.claim_pool_payout()
```

```go
five, _ := client.ParseAmount("5")
if _, err := client.Staking().JoinPool(five, poolID); err != nil {
	return err
}
_, err := client.Staking().ClaimPoolPayout()
```

## Not covered

`StakingGateway`, the Ethereum meta-transaction path to staking, is not part of the
façade. It needs EIP-712 signing, which the SDK does not provide; see
[Language parity](parity.md). Every other `Staking` and `NominationPools` extrinsic is
reachable by name through [`tx`](chain-surface.md), and every read through `query`.
