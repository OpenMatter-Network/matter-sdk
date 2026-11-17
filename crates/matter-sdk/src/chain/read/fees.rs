//! Fee reads: what a call would cost, and who would be charged for it.

use matter_sdk_key::AccountId;
use parity_scale_codec::{Compact, Decode, Encode};
use serde::Serialize;

use super::decode_strict;
use super::leaf::{decimal, hex, Address};
use crate::error::{Result, SdkError};

pub(in crate::chain) const QUERY_CALL_INFO: &str = "TransactionPaymentCallApi_query_call_info";
pub(in crate::chain) const FEE_PAYER: &str = "PaymasterApi_fee_payer";

/// What signing adds around a call: the length prefix, version byte, signer
/// address, signature, and the signed extensions' bytes. An upper bound for an
/// sr25519 signature on a mortal extrinsic with no tip, so an estimate never
/// undercounts the length fee.
pub(in crate::chain) const EXTRINSIC_OVERHEAD_BYTES: u32 = 112;

/// An estimate assumes no tip: the SDK never adds one.
const NO_TIP: u128 = 0;

/// `frame_support::dispatch::DispatchClass`, by enum index.
pub(in crate::chain) const DISPATCH_CLASSES: [DispatchClass; 3] = [
    DispatchClass::Normal,
    DispatchClass::Operational,
    DispatchClass::Mandatory,
];

/// `pallet_transaction_payment::RuntimeDispatchInfo`; `class` is an index into
/// [`DISPATCH_CLASSES`].
#[derive(Decode)]
struct DispatchInfoWire {
    ref_time: Compact<u64>,
    proof_size: Compact<u64>,
    class: u8,
    partial_fee: u128,
}

/// `PaymasterApi::fee_payer`'s answer: the payer, and the `(org, member)` the
/// spend is booked against when an organization pays.
type PayerWire = Option<([u8; 32], Option<([u8; 32], [u8; 32])>)>;

/// How the runtime schedules a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub enum DispatchClass {
    /// An ordinary call.
    Normal,
    /// An operational call, which has space reserved in every block.
    Operational,
    /// A call the block cannot be built without.
    Mandatory,
}

/// The computation a call is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Weight {
    /// Execution time, in picoseconds on reference hardware.
    #[serde(with = "decimal")]
    pub ref_time: u64,
    /// Bytes of state proof the call may need.
    #[serde(with = "decimal")]
    pub proof_size: u64,
}

/// The organization a fee is booked against, and for which member.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct BilledTo {
    /// The organization whose treasury pays.
    #[serde(with = "hex")]
    pub org: [u8; 32],
    /// The member the spend counts against.
    pub member: Address,
}

/// What a call would cost, and who would be charged for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct FeeEstimate {
    /// The pallet of the call priced.
    pub pallet: String,
    /// The call priced.
    pub call: String,
    /// The fee the chain would charge, in plancks, with no tip. Governance fee
    /// overrides are already applied.
    #[serde(with = "decimal")]
    pub partial_fee: u128,
    /// The computation the call is allowed.
    pub weight: Weight,
    /// How the runtime schedules the call.
    pub dispatch_class: DispatchClass,
    /// The extrinsic length the fee was computed for: the encoded call plus an
    /// upper bound on what signing adds.
    pub encoded_len: u32,
    /// Whether the call was priced as this client would submit it for a member:
    /// wrapped in `Proxy.proxy`.
    pub wrapped_in_proxy: bool,
    /// The account that would sign: this client's. `None` for a read-only client.
    pub signer: Option<Address>,
    /// The account the fee would be taken from. `None` when the runtime cannot
    /// say: the client has no signer, or the call is one whose sponsorship the
    /// runtime does not answer for. Never read `None` as "the signer pays".
    pub payer: Option<Address>,
    /// The organization the fee is booked against, when one pays.
    pub billed_to: Option<BilledTo>,
}

fn unexpected(target: &str, detail: impl std::fmt::Display) -> SdkError {
    SdkError::Chain {
        target: target.to_string(),
        detail: detail.to_string(),
    }
}

/// The length the fee is computed for, and `query_call_info`'s arguments: the
/// call as the runtime decodes it, then that length.
pub(in crate::chain) fn call_info_args(call: &[u8]) -> Result<(u32, Vec<u8>)> {
    let encoded_len = u32::try_from(call.len())
        .ok()
        .and_then(|len| len.checked_add(EXTRINSIC_OVERHEAD_BYTES))
        .ok_or_else(|| unexpected(QUERY_CALL_INFO, "the call is too long to be an extrinsic"))?;
    Ok((encoded_len, [call, &encoded_len.encode()].concat()))
}

/// `fee_payer`'s arguments: who signs, the call as bytes, the fee and the tip.
pub(in crate::chain) fn fee_payer_args(signer: AccountId, call: &[u8], fee: u128) -> Vec<u8> {
    (signer.0, call, fee, NO_TIP).encode()
}

/// What the client knows about the call before asking the chain.
pub(in crate::chain) struct Priced<'a> {
    pub pallet: &'a str,
    pub call: &'a str,
    pub encoded_len: u32,
    pub wrapped_in_proxy: bool,
    pub signer: Option<Address>,
}

/// The fee and weight from `query_call_info`'s answer. Pure.
pub(in crate::chain) fn decode_dispatch_info(raw: &[u8]) -> Result<(u128, Weight, DispatchClass)> {
    let info: DispatchInfoWire = decode_strict(QUERY_CALL_INFO, raw)?;
    let class = DISPATCH_CLASSES
        .get(usize::from(info.class))
        .ok_or_else(|| {
            unexpected(
                QUERY_CALL_INFO,
                format!(
                    "dispatch class {} is not a variant this SDK knows",
                    info.class
                ),
            )
        })?;
    let weight = Weight {
        ref_time: info.ref_time.0,
        proof_size: info.proof_size.0,
    };
    Ok((info.partial_fee, weight, *class))
}

/// Build the estimate from what was priced and the runtime's two answers.
/// `payer` is `fee_payer`'s raw answer, absent when there was no signer to ask
/// about. Pure.
pub(in crate::chain) fn decode_estimate(
    priced: Priced<'_>,
    (partial_fee, weight, class): (u128, Weight, DispatchClass),
    payer: Option<&[u8]>,
    address: impl Fn(AccountId) -> Address,
) -> Result<FeeEstimate> {
    let payer: PayerWire = payer
        .map(|raw| decode_strict(FEE_PAYER, raw))
        .transpose()?
        .flatten();
    Ok(FeeEstimate {
        pallet: priced.pallet.to_string(),
        call: priced.call.to_string(),
        partial_fee,
        weight,
        dispatch_class: class,
        encoded_len: priced.encoded_len,
        wrapped_in_proxy: priced.wrapped_in_proxy,
        signer: priced.signer,
        payer: payer.map(|(account, _)| address(AccountId(account))),
        billed_to: payer
            .and_then(|(_, booked)| booked)
            .map(|(org, member)| BilledTo {
                org,
                member: address(AccountId(member)),
            }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(id: AccountId) -> Address {
        Address::new(id, 42)
    }

    fn priced() -> Priced<'static> {
        Priced {
            pallet: "Staking",
            call: "chill",
            encoded_len: 114,
            wrapped_in_proxy: false,
            signer: None,
        }
    }

    fn info() -> (u128, Weight, DispatchClass) {
        let raw = (Compact(7u64), Compact(9u64), 0u8, 1_000u128).encode();
        decode_dispatch_info(&raw).unwrap()
    }

    #[test]
    fn the_fee_is_computed_for_the_call_plus_what_signing_adds() {
        let (len, args) = call_info_args(&[10, 6]).unwrap();
        assert_eq!(len, 2 + EXTRINSIC_OVERHEAD_BYTES);
        // The call as it stands, then the length: no prefix on the call.
        assert_eq!(args, [vec![10, 6], len.to_le_bytes().to_vec()].concat());
    }

    #[test]
    fn no_answer_about_the_payer_is_not_the_signer_paying() {
        let never_asked = decode_estimate(priced(), info(), None, address).unwrap();
        assert_eq!((never_asked.payer, never_asked.billed_to), (None, None));

        let cannot_say = decode_estimate(priced(), info(), Some(&[0]), address).unwrap();
        assert_eq!((cannot_say.payer, cannot_say.billed_to), (None, None));
    }

    #[test]
    fn an_organization_paying_is_named_with_the_member_it_is_booked_against() {
        let raw: PayerWire = Some(([1; 32], Some(([2; 32], [3; 32]))));
        let estimate = decode_estimate(priced(), info(), Some(&raw.encode()), address).unwrap();
        assert_eq!(estimate.payer, Some(address(AccountId([1; 32]))));
        let billed = estimate.billed_to.unwrap();
        assert_eq!(
            (billed.org, billed.member),
            ([2; 32], address(AccountId([3; 32])))
        );
    }

    #[test]
    fn a_class_the_sdk_does_not_know_is_an_error_naming_the_api() {
        let raw = (Compact(7u64), Compact(9u64), 3u8, 1_000u128).encode();
        let err = decode_dispatch_info(&raw).unwrap_err();
        assert!(
            matches!(&err, SdkError::Chain { target, .. } if target == QUERY_CALL_INFO),
            "{err:?}"
        );
    }
}
