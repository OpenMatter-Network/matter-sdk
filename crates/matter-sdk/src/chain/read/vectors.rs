//! The read catalogue and its decode vectors: `testvectors/facade_reads.json`.
//!
//! Each row names a façade read, its sources and its result shape, and carries
//! cases. A case is a transcript: every JSON-RPC exchange the read makes, and
//! either the canonical JSON it must return or the source its error must name.
//! A read whose answer comes from connect-time facts or runtime constants makes
//! no exchange at all, and its transcript says so.
//! Rust emits the file by running the real façade over a fake chain; the other
//! bindings replay each transcript through theirs, so all four make the same
//! requests and return the same bytes.
//!
//! Sample values are encoded against the type in the spec-330 metadata, so a
//! source or field the runtime does not have fails here, offline.
//!
//! Regenerate with:
//!
//! ```bash
//! cargo test -p matter-sdk --features chain --lib -- --ignored emit_read_vectors
//! ```

use parity_scale_codec::{Compact, Decode, DecodeAll, Encode};
use serde_json::{json, Value as Json};
use subxt::dynamic::Value;
use subxt::ext::scale_encode::EncodeAsType;

use super::accounts::{
    balance_requests,
    ReasonGroup,
    ACCOUNT,
    FREEZES,
    FREEZE_REASONS,
    HOLDS,
    HOLD_REASONS,
    LOCKS,
    LOCK_REASONS,
};
use super::leaf::{hex0x, ss58_with_checksum, Address, SS58_MAX_PREFIX};
use super::testing::{
    offline_client,
    offline_client_as,
    storage_key,
    test_properties,
    FakeChain,
    ALICE,
    ALICE_SS58,
    TOKEN,
};
use super::{fees, network, parse_account, StorageEntry, StorageRequest};
use crate::chain::{test_metadata, Mode};
use crate::error::SdkError;
use crate::{AccountId, ScopeSet};

const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testvectors/facade_reads.json"
);
/// Bumped only if a shape changes incompatibly; additions do not bump it.
const SCHEMA_VERSION: u32 = 1;
/// The façade method every binding spells (in its own case) to pin a block.
const PIN_METHOD: &str = "at";
/// The block every case is read at: pinned, so no case depends on a head.
const CASE_BLOCK: [u8; 32] = [0xb1; 32];
/// `ExtraFlags` with its "new logic" bit set, as on every live account.
const ACCOUNT_FLAGS: u128 = 1 << 127;

/// Bare lowercase hex: how `testvectors/` writes raw bytes.
fn bare_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

/// What a case puts under one storage key.
enum Stored {
    /// A value encoded as the entry's type in the fixture runtime.
    Typed(Value),
    /// Bytes the runtime would never store: the input of an error case.
    Raw(Vec<u8>),
}

/// How a case must end.
enum Expect {
    /// The read returns; its canonical JSON is recorded.
    Result,
    /// The read fails with a chain error naming this source.
    ErrorAt(String),
}

impl Expect {
    fn error_at(source: StorageEntry) -> Self {
        Expect::ErrorAt(source.target())
    }

    fn error_at_rpc(method: &str) -> Self {
        Expect::ErrorAt(method.to_string())
    }
}

/// SCALE-encode `value` as the storage entry's value type in the fixture runtime.
fn encode_stored(entry: StorageEntry, value: &Value) -> Vec<u8> {
    let metadata = test_metadata();
    let value_ty = metadata
        .pallet_by_name(entry.pallet)
        .and_then(|pallet| pallet.storage())
        .and_then(|storage| storage.entry_by_name(entry.entry))
        .unwrap_or_else(|| panic!("{} is not in the fixture runtime", entry.target()))
        .entry_type()
        .value_ty();
    value
        .encode_as_type(value_ty, metadata.types())
        .unwrap_or_else(|e| {
            panic!(
                "sample {} does not fit the runtime type: {e}",
                entry.target()
            )
        })
}

/// A fake chain holding `values` under `requests`.
fn chain_holding(requests: &[StorageRequest], values: Vec<Option<Stored>>) -> FakeChain {
    assert_eq!(requests.len(), values.len(), "one value slot per source");
    requests
        .iter()
        .zip(values)
        .fold(FakeChain::new(), |chain, (request, value)| match value {
            None => chain,
            Some(Stored::Raw(bytes)) => chain.with_storage(storage_key(request), bytes),
            Some(Stored::Typed(value)) => {
                chain.with_storage(storage_key(request), encode_stored(request.entry, &value))
            }
        })
}

/// The façade must have made exactly one storage request, for `requests`, at
/// the case block: the catalogue's sources are what was really asked.
fn assert_asked_for(chain: &FakeChain, requests: &[StorageRequest]) {
    let keys: Vec<String> = requests.iter().map(|r| hex0x(&storage_key(r))).collect();
    let asked = chain.exchanges();
    assert_eq!(asked.len(), 1, "a pinned read is one request: {asked:?}");
    assert_eq!(asked[0].params, json!([keys, hex0x(&CASE_BLOCK)]));
}

/// The transcript the other bindings replay: every request and its answer.
fn exchanges(chain: &FakeChain) -> Vec<Json> {
    chain
        .exchanges()
        .into_iter()
        .map(|e| match e.result {
            Ok(result) => json!({ "method": e.method, "params": e.params, "result": result }),
            Err(message) => json!({ "method": e.method, "params": e.params, "error": message }),
        })
        .collect()
}

/// A case's outcome: the result as a JSON value and as the exact canonical
/// string, or the source a chain error named.
fn outcome<T: serde::Serialize>(name: &str, result: crate::Result<T>, expect: Expect) -> Json {
    match (result, expect) {
        (Ok(value), Expect::Result) => json!({
            "expected": value,
            "expected_json": serde_json::to_string(&value).expect("a result serializes"),
        }),
        (Err(SdkError::Chain { target, .. }), Expect::ErrorAt(source)) => {
            assert_eq!(target, source, "case {name} failed at the wrong source");
            json!({ "error": { "target": target } })
        }
        (Ok(_), Expect::ErrorAt(source)) => {
            panic!("case {name} must fail at {source}, but it read")
        }
        (Err(e), _) => panic!("case {name} does not end as declared: {e}"),
    }
}

/// One case: its name, the caller's arguments, the transcript, and how it ends.
fn case<T: serde::Serialize>(
    name: &str,
    args: Json,
    chain: &FakeChain,
    result: crate::Result<T>,
    expect: Expect,
) -> Json {
    let mut case = json!({
        "name": name,
        "args": args,
        "at": bare_hex(&CASE_BLOCK),
        "exchanges": exchanges(chain),
    });
    case.as_object_mut().expect("a case is an object").extend(
        outcome(name, result, expect)
            .as_object()
            .cloned()
            .expect("an outcome is an object"),
    );
    case
}

/// The methods a case's read called, in order.
fn methods(chain: &FakeChain) -> Vec<String> {
    chain.exchanges().into_iter().map(|e| e.method).collect()
}

fn account_info(consumers: u32, providers: u32, free: u128, reserved: u128, frozen: u128) -> Value {
    Value::named_composite([
        ("nonce", Value::u128(7)),
        ("consumers", Value::u128(consumers.into())),
        ("providers", Value::u128(providers.into())),
        ("sufficients", Value::u128(0)),
        (
            "data",
            Value::named_composite([
                ("free", Value::u128(free)),
                ("reserved", Value::u128(reserved)),
                ("frozen", Value::u128(frozen)),
                ("flags", Value::u128(ACCOUNT_FLAGS)),
            ]),
        ),
    ])
}

/// `Vec<IdAmount>` under a runtime-composed reason enum.
fn reasoned(items: &[(&str, &str, u128)]) -> Value {
    Value::unnamed_composite(items.iter().map(|(pallet, reason, amount)| {
        Value::named_composite([
            (
                "id",
                Value::unnamed_variant(*pallet, [Value::unnamed_variant(*reason, [])]),
            ),
            ("amount", Value::u128(*amount)),
        ])
    }))
}

fn locks(items: &[(&[u8; 8], u128, &str)]) -> Value {
    Value::unnamed_composite(items.iter().map(|(id, amount, reasons)| {
        Value::named_composite([
            ("id", Value::from_bytes(id)),
            ("amount", Value::u128(*amount)),
            ("reasons", Value::unnamed_variant(*reasons, [])),
        ])
    }))
}

fn typed(value: Value) -> Option<Stored> {
    Some(Stored::Typed(value))
}

fn raw(bytes: Vec<u8>) -> Option<Stored> {
    Some(Stored::Raw(bytes))
}

/// One `accounts.balance` case. `who` is the text a caller would pass, so the
/// case also pins that every accepted account form reaches the same key.
async fn balance_case(name: &str, who: &str, values: [Option<Stored>; 4], expect: Expect) -> Json {
    let account = parse_account(who).expect("case accounts are valid");
    let requests = balance_requests(account);
    let chain = chain_holding(&requests, values.into());

    let result = offline_client(&chain)
        .accounts()
        .at(CASE_BLOCK)
        .balance(account)
        .await;

    assert_asked_for(&chain, &requests);
    case(name, json!({ "who": who }), &chain, result, expect)
}

async fn accounts_balance() -> Json {
    let alice_hex = hex0x(&ALICE);
    let alice_polkadot = Address::new(AccountId(ALICE), 0).to_string();
    let funded = || typed(account_info(0, 1, TOKEN, 0, 0));
    let cases = vec![
        balance_case(
            "staked_and_frozen",
            ALICE_SS58,
            [
                typed(account_info(1, 1, 5 * TOKEN, 3 * TOKEN, 4 * TOKEN)),
                typed(reasoned(&[("Staking", "Staking", 3 * TOKEN)])),
                typed(reasoned(&[(
                    "NominationPools",
                    "PoolMinBalance",
                    4 * TOKEN,
                )])),
                typed(locks(&[(b"staking ", 2 * TOKEN, "All")])),
            ],
            Expect::Result,
        )
        .await,
        balance_case(
            "never_funded",
            ALICE_SS58,
            [None, None, None, None],
            Expect::Result,
        )
        .await,
        // A consumer and a single provider: the deposit stays even on a
        // transfer that may reap. Passed as hex to pin that input form.
        balance_case(
            "only_provider_keeps_the_deposit",
            &alice_hex,
            [typed(account_info(1, 1, TOKEN, 0, 0)), None, None, None],
            Expect::Result,
        )
        .await,
        // Two providers: nothing is kept back. Passed under another network's
        // prefix; the result is still rendered under this chain's.
        balance_case(
            "second_provider_frees_the_deposit",
            &alice_polkadot,
            [typed(account_info(1, 2, TOKEN, 0, 0)), None, None, None],
            Expect::Result,
        )
        .await,
        // The widest amounts, every reason the runtime defines, and a lock id
        // that is not text.
        balance_case(
            "widest_amounts_and_every_reason",
            ALICE_SS58,
            [
                typed(account_info(0, 1, u128::MAX, u128::MAX, 1)),
                typed(reasoned(&[
                    ("Staking", "Staking", u128::MAX),
                    ("Preimage", "Preimage", 1),
                    ("Council", "ProposalSubmission", 2),
                    ("TechnicalCommittee", "ProposalSubmission", 3),
                    ("AssetRewards", "PoolCreation", 4),
                    ("DelegatedStaking", "StakingDelegation", 5),
                ])),
                typed(reasoned(&[
                    ("AssetRewards", "Staked", 6),
                    ("NominationPools", "PoolMinBalance", 7),
                ])),
                typed(locks(&[
                    (&[0xff, 0xfe, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05], 8, "Fee"),
                    (b"vesting ", 9, "Misc"),
                ])),
            ],
            Expect::Result,
        )
        .await,
        // Text that JSON writers disagree on unless told: quotes and backslashes,
        // markup characters, non-ASCII, and every kind of control character.
        balance_case(
            "text_that_needs_escaping",
            ALICE_SS58,
            [
                funded(),
                None,
                None,
                typed(locks(&[
                    (b"a\"\\<&\xc3\xa9\x01", 1, "All"),
                    (b"\xe2\x80\xa8\x7f\t\n\x08\x0c", 2, "All"),
                ])),
            ],
            Expect::Result,
        )
        .await,
        balance_case(
            "a_hold_reason_the_sdk_does_not_know",
            ALICE_SS58,
            [funded(), raw(vec![(99u8, 0u8, TOKEN)].encode()), None, None],
            Expect::error_at(HOLDS),
        )
        .await,
        balance_case(
            "an_account_with_a_byte_left_over",
            ALICE_SS58,
            [
                raw([
                    encode_stored(ACCOUNT, &account_info(0, 1, TOKEN, 0, 0)),
                    vec![0],
                ]
                .concat()),
                None,
                None,
                None,
            ],
            Expect::error_at(ACCOUNT),
        )
        .await,
        balance_case(
            "freezes_cut_short",
            ALICE_SS58,
            [
                funded(),
                None,
                raw(vec![(44u8, 0u8, TOKEN)].encode()[..5].to_vec()),
                None,
            ],
            Expect::error_at(FREEZES),
        )
        .await,
        balance_case(
            "lock_reasons_the_sdk_does_not_know",
            ALICE_SS58,
            [
                funded(),
                None,
                None,
                raw(vec![(*b"staking ", TOKEN, 3u8)].encode()),
            ],
            Expect::error_at(LOCKS),
        )
        .await,
        // Sources decode in request order, so every binding names the same one.
        balance_case(
            "two_malformed_sources_name_the_first",
            ALICE_SS58,
            [
                funded(),
                raw(vec![(99u8, 0u8, TOKEN)].encode()),
                None,
                raw(vec![(*b"staking ", TOKEN, 3u8)].encode()),
            ],
            Expect::error_at(HOLDS),
        )
        .await,
    ];

    let reason = json!({ "reason": "string", "amount": "u128" });
    json!({
        "facade": "accounts",
        "method": "balance",
        "summary": "What an account holds and how much of it can move.",
        "args": [{ "name": "who", "type": "account" }],
        "sources": [
            { "kind": "storage", "name": ACCOUNT.target() },
            { "kind": "storage", "name": HOLDS.target() },
            { "kind": "storage", "name": FREEZES.target() },
            { "kind": "storage", "name": LOCKS.target() },
            { "kind": "constant", "name": "Balances.ExistentialDeposit" },
        ],
        "result": "AccountBalance",
        "pinnable": true,
        "nullable": false,
        "shape": {
            "account": "address",
            "exists": "bool",
            "free": "u128",
            "reserved": "u128",
            "frozen": "u128",
            "total": "u128",
            "transferable": "u128",
            "transferable_keep_alive": "u128",
            "holds": [reason],
            "freezes": [reason],
            "locks": [{ "id": "text", "amount": "u128", "reasons": "Fee|Misc|All" }],
        },
        "cases": cases,
    })
}

/// Account text every binding must accept, text it must refuse, and the one
/// form it must emit.
fn account_vectors() -> Json {
    let alice = AccountId(ALICE);
    let address = |prefix: u16| Address::new(alice, prefix).to_string();
    let account_hex = bare_hex(&ALICE);
    // A well-formed address in every respect but the body it is built from.
    let forged = |prefix: &[u8], payload: &[u8]| ss58_with_checksum(&[prefix, payload].concat());

    let accepted = [
        hex0x(&ALICE),
        account_hex.clone(),
        account_hex.to_uppercase(),
        address(42),
        address(0),
        address(64),
        address(SS58_MAX_PREFIX),
        format!("  {}\n", address(42)),
        format!("\t{}\r\n", hex0x(&ALICE)),
    ];
    let refused = [
        String::new(),
        "not an account".to_string(),
        "0x1234".to_string(),
        // Short strings that are valid base58: too little to be an address.
        "33".to_string(),
        "27".to_string(),
        // One character changed: the checksum no longer holds.
        address(42).replacen('G', "H", 1),
        address(42)[..40].to_string(),
        // A valid checksum over the wrong thing.
        forged(&[42], &[ALICE.as_slice(), &[0]].concat()),
        forged(&[42], &ALICE[..31]),
        forged(&[46], &ALICE),
        forged(&[47], &ALICE),
        forged(&[0x80], &ALICE),
        forged(&[0x80, 0x00], &ALICE),
        forged(&[0xc0], &ALICE),
        // Only spaces, tabs and line breaks are padding.
        format!("\u{feff}{}", address(42)),
        format!("{}\u{1c}", address(42)),
        format!("\u{a0}{}", address(42)),
        format!("{}\u{0b}", address(42)),
    ];
    for text in &refused {
        assert!(parse_account(text).is_err(), "{text:?} must be refused");
    }
    // Both one-byte and two-byte prefixes, and each side of the boundary.
    let prefixes = [42u16, 0, 63, 64, 255, 5_234, SS58_MAX_PREFIX];
    json!({
        "accepted": accepted
            .iter()
            .map(|text| {
                assert_eq!(parse_account(text).expect("accepted form"), alice);
                json!({ "text": text, "account_hex": account_hex })
            })
            .collect::<Vec<_>>(),
        "refused": refused,
        "addresses": prefixes
            .iter()
            .map(|prefix| json!({
                "account_hex": account_hex,
                "prefix": prefix,
                "address": address(*prefix),
            }))
            .collect::<Vec<_>>(),
    })
}

/// What the reference codec makes of `bytes` as a `kind`: the value as the
/// fixture writes it, or `None` when it refuses them.
fn reference_decode(kind: &str, bytes: &[u8]) -> Option<String> {
    fn whole<T: Decode>(bytes: &[u8]) -> Option<T> {
        T::decode_all(&mut &bytes[..]).ok()
    }
    match kind {
        "u8" => whole::<u8>(bytes).map(|v| v.to_string()),
        "u16" => whole::<u16>(bytes).map(|v| v.to_string()),
        "u32" => whole::<u32>(bytes).map(|v| v.to_string()),
        "u64" => whole::<u64>(bytes).map(|v| v.to_string()),
        "u128" => whole::<u128>(bytes).map(|v| v.to_string()),
        "bool" => whole::<bool>(bytes).map(|v| v.to_string()),
        "compact_u32" => whole::<Compact<u32>>(bytes).map(|v| v.0.to_string()),
        "compact_u64" => whole::<Compact<u64>>(bytes).map(|v| v.0.to_string()),
        "compact_u128" => whole::<Compact<u128>>(bytes).map(|v| v.0.to_string()),
        "bytes" => whole::<Vec<u8>>(bytes).map(|v| hex0x(&v)),
        other => panic!("no reference decoder for {other}"),
    }
}

/// SCALE primitives for the hand-written readers in the other bindings: what
/// each must decode, and what each must refuse. Both lists are what the
/// reference codec does, not what this module says it does. Values are decimal
/// strings so no reader's number type is in play.
fn scale_vectors() -> Json {
    let valid: Vec<(&str, Vec<u8>)> = vec![
        ("u8", 0xffu8.encode()),
        ("u16", 0x1234u16.encode()),
        ("u32", 0x1234_5678u32.encode()),
        ("u32", u32::MAX.encode()),
        ("u64", u64::MAX.encode()),
        ("u128", 1u128.encode()),
        ("u128", u128::MAX.encode()),
        ("bool", false.encode()),
        ("bool", true.encode()),
        // Each compact width, and both sides of each boundary.
        ("compact_u32", Compact(0u32).encode()),
        ("compact_u32", Compact(63u32).encode()),
        ("compact_u32", Compact(64u32).encode()),
        ("compact_u32", Compact(16_383u32).encode()),
        ("compact_u32", Compact(16_384u32).encode()),
        ("compact_u32", Compact((1u32 << 30) - 1).encode()),
        ("compact_u32", Compact(1u32 << 30).encode()),
        ("compact_u32", Compact(u32::MAX).encode()),
        ("compact_u64", Compact(1u64 << 32).encode()),
        ("compact_u64", Compact(u64::MAX).encode()),
        ("compact_u128", Compact(1u128 << 64).encode()),
        ("compact_u128", Compact(u128::MAX).encode()),
        ("bytes", Vec::<u8>::new().encode()),
        ("bytes", vec![1u8, 2, 3].encode()),
    ];
    let invalid: Vec<(&str, &str, &str)> = vec![
        ("bool", "02", "a bool is 0 or 1"),
        ("u32", "0000", "truncated"),
        ("u128", "00", "truncated"),
        ("u8", "0000", "bytes left over"),
        ("bytes", "0c0102", "length runs past the input"),
        ("compact_u32", "01", "truncated two-byte compact"),
        ("compact_u32", "0100", "zero in the two-byte form"),
        ("compact_u32", "fd00", "63 in the two-byte form"),
        ("compact_u32", "02000000", "zero in the four-byte form"),
        ("compact_u32", "feff0000", "16383 in the four-byte form"),
        ("compact_u32", "0300000000", "zero in the big-integer form"),
        (
            "compact_u32",
            "03ffffff3f",
            "2^30 - 1 in the big-integer form",
        ),
        ("compact_u32", "070000000001", "2^32 does not fit a u32"),
        (
            "compact_u64",
            "17000000000000000001",
            "2^64 does not fit a u64",
        ),
        ("compact_u64", "13ffffffffffffff00", "a leading zero byte"),
        (
            "compact_u128",
            "370000000000000000000000000000000001",
            "2^128 does not fit a u128",
        ),
        ("compact_u128", "13ffffffffffffff00", "a leading zero byte"),
    ];

    json!({
        "valid": valid
            .iter()
            .map(|(kind, bytes)| {
                let value = reference_decode(kind, bytes)
                    .unwrap_or_else(|| panic!("{kind} {} must decode", bare_hex(bytes)));
                json!({ "type": kind, "hex": bare_hex(bytes), "value": value })
            })
            .collect::<Vec<_>>(),
        "invalid": invalid
            .iter()
            .map(|(kind, hex_text, why)| {
                let bytes = hex::decode(hex_text).expect("invalid rows are hex");
                assert!(
                    reference_decode(kind, &bytes).is_none(),
                    "{kind} {hex_text} ({why}) must be refused by the reference codec"
                );
                json!({ "type": kind, "hex": hex_text, "why": why })
            })
            .collect::<Vec<_>>(),
    })
}

/// A runtime-composed reason enum, as every binding must hold it.
fn reason_table(source: StorageEntry, groups: &[ReasonGroup]) -> Json {
    json!({
        "source": source.target(),
        "groups": groups
            .iter()
            .map(|(index, pallet, reasons)| json!({
                "index": index,
                "pallet": pallet,
                "reasons": reasons
                    .iter()
                    .map(|(index, name)| json!({ "index": index, "name": name }))
                    .collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
    })
}

/// The enum tables decoders carry, so each binding's copy is compared with this
/// one instead of being trusted. Rust's own are checked against the metadata.
fn table_vectors() -> Json {
    json!({
        "hold_reasons": reason_table(HOLDS, HOLD_REASONS),
        "freeze_reasons": reason_table(FREEZES, FREEZE_REASONS),
        "lock_reasons": LOCK_REASONS,
        "dispatch_classes": fees::DISPATCH_CLASSES,
    })
}

/// Whether `value` has the canonical JSON form `shape` describes; the error
/// names the path that does not.
fn conforms(shape: &Json, value: &Json, path: &str) -> Result<(), String> {
    let fail = |why: &str| Err(format!("{path}: {why} (shape {shape}, value {value})"));
    let digits = |v: &Json| {
        v.as_str()
            .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
    };
    let hex = |v: &Json| v.as_str().is_some_and(|s| s.starts_with("0x"));
    match shape {
        // `{"?": shape}`: an object that may be null.
        Json::Object(fields) if fields.len() == 1 && fields.contains_key("?") => {
            if value.is_null() {
                return Ok(());
            }
            conforms(&fields["?"], value, path)
        }
        Json::Object(fields) => {
            let Some(object) = value.as_object() else {
                return fail("expected an object");
            };
            if !object.keys().eq(fields.keys()) {
                return fail("keys differ");
            }
            fields.iter().try_for_each(|(key, field)| {
                conforms(field, &object[key], &format!("{path}.{key}"))
            })
        }
        Json::Array(items) => {
            let Some(values) = value.as_array() else {
                return fail("expected an array");
            };
            values
                .iter()
                .enumerate()
                .try_for_each(|(i, item)| conforms(&items[0], item, &format!("{path}[{i}]")))
        }
        Json::String(token) => match token.as_str() {
            nullable if nullable.ends_with('?') => {
                if value.is_null() {
                    return Ok(());
                }
                conforms(&json!(nullable.trim_end_matches('?')), value, path)
            }
            "bool" if value.is_boolean() => Ok(()),
            "u32" if value.as_u64().is_some_and(|n| n <= u32::MAX.into()) => Ok(()),
            "u64" | "u128" if digits(value) => Ok(()),
            "address" if value.as_str().is_some_and(|s| !s.is_empty()) && !hex(value) => Ok(()),
            "hex" if hex(value) => Ok(()),
            "string" if value.is_string() => Ok(()),
            "text" if value.is_string() || value.get("hex").is_some_and(hex) => Ok(()),
            variants if variants.contains('|') => {
                if value
                    .as_str()
                    .is_some_and(|s| variants.split('|').any(|v| v == s))
                {
                    return Ok(());
                }
                fail("not one of the variants")
            }
            _ => fail("value does not have this form"),
        },
        _ => fail("a shape is an object, a one-item array, or a token"),
    }
}

/// Every returned `expected` must have its row's `shape`. A read that asks the
/// chain needs a typical case, a second (absent or boundary) case and a failing
/// case at least; one answered from facts already in hand cannot fail.
fn assert_rows_are_well_formed(reads: &[Json]) {
    for read in reads {
        let name = format!("{}.{}", read["facade"], read["method"]);
        let cases = read["cases"].as_array().expect("cases");
        let (failing, returning): (Vec<_>, Vec<_>) =
            cases.iter().partition(|case| case.get("error").is_some());
        let asks_the_chain = cases
            .iter()
            .any(|case| case["exchanges"].as_array().is_some_and(|e| !e.is_empty()));
        assert!(!returning.is_empty(), "{name} needs a returning case");
        if asks_the_chain {
            assert!(returning.len() >= 2, "{name} needs a second returning case");
            assert!(!failing.is_empty(), "{name} needs a failing case");
        }
        for case in returning {
            let path = format!("{name}[{}]", case["name"]);
            if case["expected"].is_null() {
                assert_eq!(
                    read["nullable"], true,
                    "{path}: only a nullable read returns null"
                );
                continue;
            }
            conforms(&read["shape"], &case["expected"], &path).unwrap_or_else(|e| panic!("{e}"));
        }
    }
}

/// A block header as `chain_getHeader` answers: more fields than a read uses.
fn header_json(number: u64, parent: [u8; 32]) -> Json {
    json!({
        "parentHash": hex0x(&parent),
        "number": format!("0x{number:x}"),
        "stateRoot": hex0x(&[0x51; 32]),
        "extrinsicsRoot": hex0x(&[0xe7; 32]),
        "digest": { "logs": [] },
    })
}

/// `state_getRuntimeVersion`'s answer for the fixture runtime.
fn runtime_version_json() -> Json {
    json!({
        "specName": "open-matter-runtime",
        "implName": "open-matter-runtime",
        "authoringVersion": 1,
        "specVersion": 330,
        "implVersion": 1,
        "apis": [],
        "transactionVersion": 10,
        "stateVersion": 1,
    })
}

fn block_param(hash: &[u8; 32]) -> Json {
    json!([hex0x(hash)])
}

async fn network_info() -> Json {
    let chain = FakeChain::new();
    let info = offline_client(&chain).network().info();
    json!({
        "facade": "network",
        "method": "info",
        "summary": "Which chain this is: its name, genesis hash, token and address format.",
        "args": [],
        "sources": [
            { "kind": "rpc", "name": "system_chain" },
            { "kind": "rpc", "name": "system_properties" },
            { "kind": "rpc", "name": network::GET_BLOCK_HASH },
            { "kind": "rpc", "name": network::GET_RUNTIME_VERSION },
            { "kind": "constant", "name": "Balances.ExistentialDeposit" },
            { "kind": "constant", "name": "System.SS58Prefix" },
        ],
        "result": "NetworkInfo",
        "pinnable": false,
        "nullable": false,
        "shape": {
            "chain_name": "string",
            "genesis_hash": "hex",
            "spec_version": "u32",
            "token_symbol": "string",
            "token_decimals": "u32",
            "ss58_prefix": "u32",
            "existential_deposit": "u128",
        },
        // Answered from what the client read at connect: no request to replay.
        "cases": [case("as_read_at_connect", json!({}), &chain, Ok(info), Expect::Result)],
    })
}

/// One `network.head` case, pinned at the case block.
async fn head_case(name: &str, chain: FakeChain, expect: Expect) -> Json {
    let result = offline_client(&chain).network().at(CASE_BLOCK).head().await;
    case(name, json!({}), &chain, result, expect)
}

async fn network_head() -> Json {
    let now_key = storage_key(&network::now_request()[0]);
    let at = block_param(&CASE_BLOCK);
    let with_header = |number: u64, parent: [u8; 32]| {
        FakeChain::new().with_rpc(network::GET_HEADER, at.clone(), header_json(number, parent))
    };
    let versioned = |chain: FakeChain| {
        chain.with_rpc(
            network::GET_RUNTIME_VERSION,
            at.clone(),
            runtime_version_json(),
        )
    };
    let stamped = |chain: FakeChain, ms: u128| chain.with_storage(now_key.clone(), ms.encode());

    let typical = versioned(stamped(
        with_header(3_038_951, [0xaa; 32]),
        1_763_371_200_000,
    ));
    assert_eq!(
        {
            let _ = offline_client(&typical)
                .network()
                .at(CASE_BLOCK)
                .head()
                .await;
            methods(&typical)
        },
        [
            network::GET_HEADER,
            "state_queryStorageAt",
            network::GET_RUNTIME_VERSION
        ],
        "the catalogue's sources are what a head read asks, in this order"
    );

    let cases = vec![
        head_case(
            "a_finalized_block",
            versioned(stamped(
                with_header(3_038_951, [0xaa; 32]),
                1_763_371_200_000,
            )),
            Expect::Result,
        )
        .await,
        // The genesis block stores no time: absent, not 1970.
        head_case(
            "a_block_that_records_no_time",
            versioned(with_header(0, [0; 32])),
            Expect::Result,
        )
        .await,
        head_case(
            "the_widest_number_and_time",
            versioned(stamped(with_header(u64::MAX, [0xff; 32]), u64::MAX.into())),
            Expect::Result,
        )
        .await,
        // A block the node never had, or has forgotten: nothing else is asked.
        head_case(
            "a_block_the_node_does_not_have",
            FakeChain::new().with_rpc(network::GET_HEADER, at.clone(), Json::Null),
            Expect::error_at_rpc(network::GET_HEADER),
        )
        .await,
        head_case(
            "state_the_node_has_pruned",
            stamped(with_header(7, [0xaa; 32]), 1).with_refusal(
                network::GET_RUNTIME_VERSION,
                at.clone(),
                "State already discarded",
            ),
            Expect::error_at_rpc(network::GET_RUNTIME_VERSION),
        )
        .await,
        head_case(
            "a_time_too_wide_to_be_one",
            versioned(stamped(with_header(7, [0xaa; 32]), u128::MAX)),
            Expect::error_at(network::NOW),
        )
        .await,
    ];

    json!({
        "facade": "network",
        "method": "head",
        "summary": "The latest finalized block, or the pinned one: height, hash, time and runtime version.",
        "args": [],
        "sources": [
            { "kind": "rpc", "name": network::GET_HEADER },
            { "kind": "storage", "name": network::NOW.target() },
            { "kind": "rpc", "name": network::GET_RUNTIME_VERSION },
        ],
        "result": "Block",
        "pinnable": true,
        "nullable": false,
        "shape": {
            "number": "u64",
            "hash": "hex",
            "parent_hash": "hex",
            "timestamp_ms": "u64?",
            "spec_version": "u32",
        },
        "cases": cases,
    })
}

/// One `network.block` case. The number travels as a decimal string: JSON
/// numbers cannot carry 64 bits.
async fn block_case(name: &str, number: u64, chain: FakeChain, expect: Expect) -> Json {
    let result = offline_client(&chain).network().block(number).await;
    case(
        name,
        json!({ "number": number.to_string() }),
        &chain,
        result,
        expect,
    )
}

async fn network_block() -> Json {
    let hash = [0xc3; 32];
    let asking = |number: u64, answer: Json| {
        FakeChain::new().with_rpc(
            network::GET_BLOCK_HASH,
            json!([network::block_number_param(number)]),
            answer,
        )
    };
    let cases = vec![
        block_case(
            "a_block_the_chain_has",
            1234,
            asking(1234, json!(hex0x(&hash))).with_rpc(
                network::GET_HEADER,
                block_param(&hash),
                header_json(1234, [0xaa; 32]),
            ),
            Expect::Result,
        )
        .await,
        block_case(
            "a_height_not_reached_yet",
            u32::MAX.into(),
            asking(u32::MAX.into(), Json::Null),
            Expect::Result,
        )
        .await,
        // The node's block numbers stop at 32 bits; it says so, and so does the read.
        block_case(
            "a_height_the_node_cannot_address",
            u64::MAX,
            FakeChain::new().with_refusal(
                network::GET_BLOCK_HASH,
                json!([network::block_number_param(u64::MAX)]),
                "the max block number is u32",
            ),
            Expect::error_at_rpc(network::GET_BLOCK_HASH),
        )
        .await,
        block_case(
            "a_hash_whose_header_is_gone",
            7,
            asking(7, json!(hex0x(&hash))).with_rpc(
                network::GET_HEADER,
                block_param(&hash),
                Json::Null,
            ),
            Expect::error_at_rpc(network::GET_HEADER),
        )
        .await,
    ];

    json!({
        "facade": "network",
        "method": "block",
        "summary": "The block at a height: its hash and parent, read from headers alone.",
        "args": [{ "name": "number", "type": "u64" }],
        "sources": [
            { "kind": "rpc", "name": network::GET_BLOCK_HASH },
            { "kind": "rpc", "name": network::GET_HEADER },
        ],
        "result": "BlockHeader",
        "pinnable": false,
        "nullable": true,
        "shape": { "number": "u64", "hash": "hex", "parent_hash": "hex" },
        "cases": cases,
    })
}

async fn node_case(name: &str, chain: FakeChain, expect: Expect) -> Json {
    let result = offline_client(&chain).network().node().await;
    case(name, json!({}), &chain, result, expect)
}

async fn network_node() -> Json {
    let best = [0xbe; 32];
    let no_params = || json!([]);
    // The fake's own finalized head is the block the node reports as final.
    let finalized = super::testing::FAKE_HEAD;
    let node =
        |peers: u32, syncing: bool, wants_peers: bool, best_number: u64, final_number: u64| {
            FakeChain::new()
                .with_rpc(network::SYSTEM_NAME, no_params(), json!("Matter Node"))
                .with_rpc(
                    network::SYSTEM_VERSION,
                    no_params(),
                    json!("1.61.1-dec11fc360a"),
                )
                .with_rpc(
                    network::SYSTEM_HEALTH,
                    no_params(),
                    json!({ "peers": peers, "isSyncing": syncing, "shouldHavePeers": wants_peers }),
                )
                .with_rpc(network::GET_BLOCK_HASH, no_params(), json!(hex0x(&best)))
                .with_rpc(
                    network::GET_HEADER,
                    block_param(&best),
                    header_json(best_number, finalized),
                )
                .with_rpc(
                    network::GET_HEADER,
                    block_param(&finalized),
                    header_json(final_number, [0xaa; 32]),
                )
        };
    let cases = vec![
        node_case(
            "a_synced_node",
            node(8, false, true, 3_038_953, 3_038_951),
            Expect::Result,
        )
        .await,
        node_case(
            "a_lone_node_still_syncing",
            node(0, true, false, 12, 0),
            Expect::Result,
        )
        .await,
        node_case(
            "a_node_that_will_not_say",
            FakeChain::new()
                .with_rpc(network::SYSTEM_NAME, no_params(), json!("Matter Node"))
                .with_rpc(network::SYSTEM_VERSION, no_params(), json!("1.61.1"))
                .with_refusal(network::SYSTEM_HEALTH, no_params(), "Method not found"),
            Expect::error_at_rpc(network::SYSTEM_HEALTH),
        )
        .await,
    ];

    json!({
        "facade": "network",
        "method": "node",
        "summary": "The node answering: its software, peers, sync state, and best and finalized blocks.",
        "args": [],
        "sources": [
            { "kind": "rpc", "name": network::SYSTEM_NAME },
            { "kind": "rpc", "name": network::SYSTEM_VERSION },
            { "kind": "rpc", "name": network::SYSTEM_HEALTH },
            { "kind": "rpc", "name": network::GET_BLOCK_HASH },
            { "kind": "rpc", "name": network::GET_HEADER },
            { "kind": "rpc", "name": "chain_getFinalizedHead" },
        ],
        "result": "NodeStatus",
        "pinnable": false,
        "nullable": false,
        "shape": {
            "name": "string",
            "version": "string",
            "peers": "u32",
            "is_syncing": "bool",
            "should_have_peers": "bool",
            "best_number": "u64",
            "best_hash": "hex",
            "finalized_number": "u64",
            "finalized_hash": "hex",
        },
        "cases": cases,
    })
}

async fn network_timing() -> Json {
    let chain = FakeChain::new();
    let timing = offline_client(&chain).network().timing();
    json!({
        "facade": "network",
        "method": "timing",
        "summary": "How the chain measures time: block time, and the length of a session, an era and unbonding.",
        "args": [],
        "sources": network::TIMING_CONSTANTS
            .iter()
            .map(|constant| json!({ "kind": "constant", "name": constant.target() }))
            .collect::<Vec<_>>(),
        "result": "NetworkTiming",
        "pinnable": false,
        "nullable": false,
        "shape": {
            "block_time_ms": "u64",
            "session_blocks": "u64",
            "sessions_per_era": "u32",
            "era_blocks": "u64",
            "bonding_duration_eras": "u32",
        },
        // Constants of the fixture runtime: no request to replay.
        "cases": [case("the_fixture_runtime", json!({}), &chain, timing, Expect::Result)],
    })
}

/// SCALE-encode `value` as the runtime API's return type in the fixture runtime.
fn encode_api_output(api: &str, value: &Value) -> Vec<u8> {
    let metadata = test_metadata();
    let (trait_name, method) = api.split_once('_').expect("Trait_method");
    let output = metadata
        .runtime_api_trait_by_name(trait_name)
        .and_then(|api| api.method_by_name(method))
        .unwrap_or_else(|| panic!("{api} is not in the fixture runtime"))
        .output_ty();
    value
        .encode_as_type(output, metadata.types())
        .unwrap_or_else(|e| panic!("sample {api} answer does not fit the runtime type: {e}"))
}

/// SCALE-encode `args` as the runtime API's declared inputs: what the read's own
/// argument encoding is checked against.
fn encode_api_args(api: &str, args: &[Value]) -> Vec<u8> {
    let metadata = test_metadata();
    let (trait_name, method) = api.split_once('_').expect("Trait_method");
    let inputs: Vec<u32> = metadata
        .runtime_api_trait_by_name(trait_name)
        .and_then(|api| api.method_by_name(method))
        .unwrap_or_else(|| panic!("{api} is not in the fixture runtime"))
        .inputs()
        .map(|input| input.ty)
        .collect();
    assert_eq!(
        inputs.len(),
        args.len(),
        "{api} takes {} arguments",
        inputs.len()
    );
    inputs
        .iter()
        .zip(args)
        .flat_map(|(ty, value)| {
            value
                .encode_as_type(*ty, metadata.types())
                .unwrap_or_else(|e| panic!("an argument of {api} does not fit: {e}"))
        })
        .collect()
}

/// The arguments the read passed to each runtime API it called, in order.
fn runtime_api_args(chain: &FakeChain) -> Vec<(String, Vec<u8>)> {
    chain
        .exchanges()
        .into_iter()
        .filter(|e| e.method == "state_call")
        .map(|e| {
            let api = e.params[0].as_str().expect("an API name").to_string();
            let args = e.params[1].as_str().expect("hex arguments");
            (
                api,
                hex::decode(args.trim_start_matches("0x")).expect("hex"),
            )
        })
        .collect()
}

fn dispatch_info(ref_time: u64, proof_size: u64, class: &str, partial_fee: u128) -> Value {
    Value::named_composite([
        (
            "weight",
            Value::named_composite([
                ("ref_time", Value::u128(ref_time.into())),
                ("proof_size", Value::u128(proof_size.into())),
            ]),
        ),
        ("class", Value::unnamed_variant(class, [])),
        ("partial_fee", Value::u128(partial_fee)),
    ])
}

/// What `fee_payer` may answer: nothing, the payer alone, or the payer and the
/// `(org, member)` the spend is booked against.
type PayerAnswer = Option<([u8; 32], Option<([u8; 32], [u8; 32])>)>;

/// A `fee_payer` answer as a value to encode.
fn payer(answer: PayerAnswer) -> Value {
    let some = |value: Value| Value::unnamed_variant("Some", [value]);
    let none = || Value::unnamed_variant("None", []);
    match answer {
        None => none(),
        Some((account, booked)) => some(Value::unnamed_composite([
            Value::from_bytes(account),
            match booked {
                None => none(),
                Some((org, member)) => some(Value::unnamed_composite([
                    Value::from_bytes(org),
                    Value::from_bytes(member),
                ])),
            },
        ])),
    }
}

/// Who a case's client is: who would sign, and for which member if any.
#[derive(Clone, Copy)]
struct Identity {
    signer: Option<[u8; 32]>,
    principal: Option<[u8; 32]>,
}

const READ_ONLY: Identity = Identity {
    signer: None,
    principal: None,
};

impl Identity {
    fn client(self, chain: &FakeChain) -> crate::chain::MatterClient {
        match (self.signer, self.principal) {
            (None, _) => offline_client(chain),
            (Some(signer), None) => offline_client_as(chain, AccountId(signer), Mode::Direct),
            (Some(signer), Some(principal)) => offline_client_as(
                chain,
                AccountId(signer),
                Mode::Delegated {
                    principal: AccountId(principal),
                    scopes: ScopeSet::ALL,
                },
            ),
        }
    }

    fn json(self) -> Json {
        json!({
            "signer": self.signer.map(|id| bare_hex(&id)),
            "principal": self.principal.map(|id| bare_hex(&id)),
        })
    }
}

/// A call as a case names it: pallet, call, and its arguments as named `u128`s.
type CallSpec<'a> = (&'a str, &'a str, &'a [(&'a str, u128)]);

/// One `fees.estimate` case. A call's arguments are written once, and each
/// binding turns them into its own `tx` argument form.
async fn estimate_case(
    name: &str,
    who: Identity,
    (pallet, call, args): CallSpec<'_>,
    chain: FakeChain,
    expect: Expect,
) -> Json {
    // Bindings that pass call arguments by name rely on these being the
    // runtime's own field names.
    if let Some(variant) = test_metadata()
        .pallet_by_name(pallet)
        .and_then(|pallet| pallet.call_variant_by_name(call))
    {
        let declared: Vec<_> = variant.fields.iter().map(|f| f.name.as_deref()).collect();
        let named: Vec<_> = args.iter().map(|(name, _)| Some(*name)).collect();
        assert_eq!(named, declared, "{pallet}.{call}'s argument names");
    }
    let values = args.iter().map(|(_, value)| Value::u128(*value)).collect();
    let result = who
        .client(&chain)
        .fees()
        .at(CASE_BLOCK)
        .estimate(pallet, call, values)
        .await;
    let call_args: Vec<Json> = args
        .iter()
        .map(|(name, value)| json!({ "name": name, "type": "u128", "value": value.to_string() }))
        .collect();
    let mut case = case(
        name,
        json!({ "pallet": pallet, "call": call, "args": call_args }),
        &chain,
        result,
        expect,
    );
    case["client"] = who.json();
    case
}

async fn fees_estimate() -> Json {
    const KEY: [u8; 32] = [0x0b; 32];
    const TREASURY: [u8; 32] = [0x77; 32];
    const ORG: [u8; 32] = [0x0a; 32];
    const FEE: u128 = 1_234_500_000_000_000;
    let chill: CallSpec<'_> = ("Staking", "chill", &[]);
    let cancel: CallSpec<'_> = ("Jobs", "cancel_deployment", &[("deployment", 42)]);
    let alice = Identity {
        signer: Some(ALICE),
        principal: None,
    };
    let key_for_alice = Identity {
        signer: Some(KEY),
        principal: Some(ALICE),
    };
    let priced = |fee: u128| {
        FakeChain::new().with_runtime_api(
            fees::QUERY_CALL_INFO,
            encode_api_output(
                fees::QUERY_CALL_INFO,
                &dispatch_info(187_000_000, 3_593, "Normal", fee),
            ),
        )
    };
    let paid_by = |chain: FakeChain, answer| {
        chain.with_runtime_api(
            fees::FEE_PAYER,
            encode_api_output(fees::FEE_PAYER, &payer(answer)),
        )
    };

    // The read encodes its runtime-API arguments by hand; check them against the
    // runtime's declared inputs once, for the case that exercises the most: a
    // scoped key, whose call is wrapped before it is priced.
    {
        use subxt::tx::Payload;
        let chain = paid_by(priced(FEE), Some((ALICE, None)));
        let _ = key_for_alice
            .client(&chain)
            .fees()
            .at(CASE_BLOCK)
            .estimate(cancel.0, cancel.1, vec![Value::u128(42)])
            .await;
        let wrapped = || {
            let inner = subxt::dynamic::tx(cancel.0, cancel.1, vec![Value::u128(42)]);
            subxt::dynamic::tx(
                "Proxy",
                "proxy",
                vec![
                    Value::unnamed_variant("Id", [Value::from_bytes(ALICE)]),
                    Value::unnamed_variant("None", []),
                    inner.into_value(),
                ],
            )
        };
        let call_bytes = wrapped()
            .encode_call_data(&test_metadata())
            .expect("the call encodes");
        let len = u128::try_from(call_bytes.len()).expect("a length")
            + u128::from(fees::EXTRINSIC_OVERHEAD_BYTES);
        let expected = vec![
            (
                fees::QUERY_CALL_INFO.to_string(),
                encode_api_args(
                    fees::QUERY_CALL_INFO,
                    &[wrapped().into_value(), Value::u128(len)],
                ),
            ),
            (
                fees::FEE_PAYER.to_string(),
                encode_api_args(
                    fees::FEE_PAYER,
                    &[
                        Value::from_bytes(KEY),
                        Value::from_bytes(&call_bytes),
                        Value::u128(FEE),
                        Value::u128(0),
                    ],
                ),
            ),
        ];
        assert_eq!(
            runtime_api_args(&chain),
            expected,
            "an estimate's runtime-API arguments are what the runtime declares"
        );
    }

    let cases = vec![
        // No signer: the fee is known, the payer is not asked about.
        estimate_case(
            "a_read_only_client_learns_the_fee",
            READ_ONLY,
            chill,
            priced(FEE),
            Expect::Result,
        )
        .await,
        estimate_case(
            "the_signer_pays",
            alice,
            cancel,
            paid_by(priced(FEE), Some((ALICE, None))),
            Expect::Result,
        )
        .await,
        estimate_case(
            "an_organization_pays_for_its_member",
            alice,
            cancel,
            paid_by(priced(FEE), Some((TREASURY, Some((ORG, ALICE))))),
            Expect::Result,
        )
        .await,
        // A scoped key: the call is priced as it is submitted, wrapped to run as
        // the member, and the question is who pays for the key's extrinsic.
        estimate_case(
            "a_scoped_key_acting_for_a_member",
            key_for_alice,
            cancel,
            paid_by(priced(FEE), Some((ALICE, None))),
            Expect::Result,
        )
        .await,
        // Not "the signer pays": the runtime declined to answer.
        estimate_case(
            "the_runtime_cannot_say_who_pays",
            alice,
            chill,
            paid_by(priced(FEE), None),
            Expect::Result,
        )
        .await,
        estimate_case(
            "the_widest_fee_and_weight",
            READ_ONLY,
            chill,
            FakeChain::new().with_runtime_api(
                fees::QUERY_CALL_INFO,
                encode_api_output(
                    fees::QUERY_CALL_INFO,
                    &dispatch_info(u64::MAX, u64::MAX, "Mandatory", u128::MAX),
                ),
            ),
            Expect::Result,
        )
        .await,
        // A name the runtime does not have fails before anything is asked.
        estimate_case(
            "a_call_the_runtime_does_not_have",
            READ_ONLY,
            ("Staking", "chil", &[]),
            FakeChain::new(),
            Expect::ErrorAt("Staking.chil".to_string()),
        )
        .await,
        estimate_case(
            "a_runtime_that_will_not_price_the_call",
            READ_ONLY,
            chill,
            FakeChain::new().refusing_runtime_api(fees::QUERY_CALL_INFO, "Execution failed"),
            Expect::error_at_rpc(fees::QUERY_CALL_INFO),
        )
        .await,
        estimate_case(
            "a_fee_with_a_byte_left_over",
            READ_ONLY,
            chill,
            FakeChain::new().with_runtime_api(
                fees::QUERY_CALL_INFO,
                [
                    encode_api_output(fees::QUERY_CALL_INFO, &dispatch_info(1, 2, "Normal", 3)),
                    vec![0],
                ]
                .concat(),
            ),
            Expect::error_at_rpc(fees::QUERY_CALL_INFO),
        )
        .await,
        estimate_case(
            "a_dispatch_class_the_sdk_does_not_know",
            READ_ONLY,
            chill,
            FakeChain::new().with_runtime_api(
                fees::QUERY_CALL_INFO,
                (Compact(1u64), Compact(2u64), 3u8, 3u128).encode(),
            ),
            Expect::error_at_rpc(fees::QUERY_CALL_INFO),
        )
        .await,
        estimate_case(
            "a_payer_answer_cut_short",
            alice,
            chill,
            priced(FEE).with_runtime_api(fees::FEE_PAYER, vec![1, 2, 3]),
            Expect::error_at_rpc(fees::FEE_PAYER),
        )
        .await,
    ];

    json!({
        "facade": "fees",
        "method": "estimate",
        "summary": "What a call would cost this client, and who would be charged for it.",
        "args": [
            { "name": "pallet", "type": "string" },
            { "name": "call", "type": "string" },
            { "name": "args", "type": "call_args" },
        ],
        "sources": [
            { "kind": "runtime_api", "name": fees::QUERY_CALL_INFO },
            { "kind": "runtime_api", "name": fees::FEE_PAYER },
        ],
        "result": "FeeEstimate",
        "pinnable": true,
        "nullable": false,
        "shape": {
            "pallet": "string",
            "call": "string",
            "partial_fee": "u128",
            "weight": { "ref_time": "u64", "proof_size": "u64" },
            "dispatch_class": "Normal|Operational|Mandatory",
            "encoded_len": "u32",
            "wrapped_in_proxy": "bool",
            "signer": "address?",
            "payer": "address?",
            "billed_to": { "?": { "org": "hex", "member": "address" } },
        },
        "cases": cases,
    })
}

async fn build_fixture() -> Json {
    let reads = vec![
        accounts_balance().await,
        fees_estimate().await,
        network_info().await,
        network_head().await,
        network_block().await,
        network_node().await,
        network_timing().await,
    ];
    assert_rows_are_well_formed(&reads);
    let properties = test_properties();
    json!({
        "comment": "The read catalogue and its decode vectors. Every binding with a \
                    chain client must expose exactly these (facade, method) reads, \
                    plus `pin_method` on each façade that has one. A case is a \
                    transcript: `exchanges` lists every JSON-RPC request the read \
                    makes, in order, each with the node's `result` (which may be \
                    null) or the `error` it refused with. A `pinnable` read is \
                    recorded pinned at `at`; unpinned it first asks for the \
                    finalized head, which is `at`, and then makes the same \
                    requests. A read that is not pinnable makes the same requests \
                    either way, and so does a case that fails with no exchanges: \
                    it is refused before the chain is asked anything. The read must make exactly those requests and then \
                    either return \
                    `expected` (the JSON value) serialized as exactly \
                    `expected_json` (the canonical bytes: no whitespace, fields in \
                    declared order, only quotes, backslashes and control characters \
                    escaped; `null` for a `nullable` read with nothing to \
                    return), or fail with a chain error naming `error.target`. \
                    `args` are what a caller passes, by the row's argument names; \
                    argument types are account, string, u32, u64, u128, hash, \
                    bytes, page and call_args (a call's arguments as an ordered \
                    list of {name, type, value}, which each binding turns into \
                    the form its `tx` takes). A case with a `client` is read by \
                    a client that would sign as `client.signer`, for the member \
                    `client.principal` if any; any other case by a read-only one. `shape` names each field's form: address (SS58), u32 \
                    (number), u64/u128 (decimal string), text (string, or {hex} \
                    when not UTF-8), hex, bool, string, A|B|C (one variant name); \
                    `?` marks a field that may be null, and {\"?\": shape} an \
                    object that may be. Raw bytes are bare hex \
                    except inside exchanges and results, which are verbatim. \
                    Method names are snake_case here; bindings apply their own \
                    convention.",
        "schema_version": SCHEMA_VERSION,
        "pin_method": PIN_METHOD,
        "chain": {
            "ss58_prefix": properties.ss58_prefix,
            "existential_deposit": properties.existential_deposit.to_string(),
        },
        "accounts": account_vectors(),
        "scale": scale_vectors(),
        "tables": table_vectors(),
        "reads": reads,
    })
}

#[tokio::test]
async fn the_checked_in_read_vectors_are_current() {
    let checked_in: Json = serde_json::from_str(
        &std::fs::read_to_string(FIXTURE).expect("testvectors/facade_reads.json exists"),
    )
    .expect("the fixture is JSON");
    assert!(
        checked_in == build_fixture().await,
        "testvectors/facade_reads.json is stale; regenerate it (see this module's header)"
    );
}

#[test]
fn a_shape_rejects_a_value_that_does_not_have_it() {
    let shape =
        json!({ "free": "u128", "label": "text", "state": "Open|Closed", "owner": "address?" });
    let good = json!({ "free": "1", "label": {"hex": "0xff"}, "state": "Open", "owner": null });
    assert_eq!(conforms(&shape, &good, "r"), Ok(()));

    for (field, bad) in [
        ("free", json!(1)),
        ("label", json!(7)),
        ("state", json!("Ajar")),
        ("owner", json!("0xabcd")),
    ] {
        let mut value = good.clone();
        value[field] = bad;
        assert!(
            conforms(&shape, &value, "r").is_err(),
            "{field} should not conform"
        );
    }
    let extra = json!({ "free": "1", "label": "x", "state": "Open", "owner": null, "more": 1 });
    assert!(
        conforms(&shape, &extra, "r").is_err(),
        "an undeclared key should not conform"
    );
}

#[tokio::test]
#[ignore = "writes testvectors/facade_reads.json; run explicitly to regenerate"]
async fn emit_read_vectors() {
    let fixture = build_fixture().await;
    let text = serde_json::to_string_pretty(&fixture).expect("the fixture serializes");
    std::fs::write(FIXTURE, format!("{text}\n")).unwrap();
    println!("wrote {FIXTURE}");
}
