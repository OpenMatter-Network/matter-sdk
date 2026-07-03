// MatterVault end-to-end test against a LIVE chain + committee — the Rust analogue
// of examples/e2e/run.ts, and the "golden sample" the other languages reproduce.
//
// Flow: connect -> derive signer -> fetch committee context -> encrypt ->
// secrets.storeSecret (pays a fee) -> read the secret back from chain ->
// threshold-decrypt via the live committee -> assert the round trip. The seal +
// quorum live in `matter-vault`; the chain half (state-call reads + the extrinsic)
// is subxt, exactly as @polkadot/api drives the TypeScript example.
//
// You provide a FUNDED account. The key never leaves this process: subxt holds it
// for the extrinsic, and `matter_vault::Sr25519Signer` holds it for the signed
// /partial-decrypt requests.
//
// Env:
//   MATTER_RPC_URL      ws(s) endpoint                          (default: testnet)
//   MATTER_SIGNER_SEED  0x-hex seed or mnemonic / sr25519 SURI  (falls back to TEST_KEY)
//   MATTER_SECRET       plaintext to seal                       (default: a sample env line)

use std::str::FromStr;

use matter_vault::{decrypt, Aad, CommitteeNode, DecryptRequest, ReqwestTransport, Sr25519Signer};
use parity_scale_codec::{Decode, Encode};
use subxt::backend::legacy::LegacyRpcMethods;
use subxt::backend::rpc::RpcClient;
use subxt::dynamic::{At, Value};
use subxt::{OnlineClient, PolkadotConfig};
use subxt_signer::{sr25519::Keypair, SecretUri};

const DEFAULT_RPC: &str = "wss://node2.testnet.openmatter.network";
const DEFAULT_SECRET: &str = "API_KEY=swordfish\nDATABASE_URL=postgres://prod";

// Runtime-API entry points (same names examples/e2e/run.ts state-calls).
const RT_JOINT_PK: &str = "KgcApi_joint_pk";
const RT_DKG_EPOCH: &str = "KgcApi_dkg_epoch";
const RT_KGC_NODES: &str = "KgcApi_kgc_nodes";
const RT_SHARED_A: &str = "KgcApi_shared_a";
const RT_THRESHOLD: &str = "KgcApi_threshold_params_at_epoch";
const RT_SHARE_COMMITMENT: &str = "KgcApi_share_commitment";
const RT_SECRET_PAYLOAD: &str = "SecretsApi_secret_payload";
const RT_SECRET_EPOCH: &str = "SecretsApi_secret_epoch";

type AccountId32Bytes = [u8; 32];

/// `KgcNodeInfo` as returned by `KgcApi_kgc_nodes` (field order matches the chain).
#[derive(Decode)]
struct KgcNodeInfo {
    endpoint: Vec<u8>,
    dkg_index: u64,
}

/// The on-chain `EncryptedSecret` envelope (four SCALE `Vec<u8>` blobs).
///
/// `proof` is part of the wire shape but unused on the decrypt path — `open_secret`
/// verifies the committee's per-partial proofs, not the stored plaintext proof.
#[derive(Decode)]
struct EncSecretWire {
    binding_id: Vec<u8>,
    capsule: Vec<u8>,
    #[allow(dead_code)]
    proof: Vec<u8>,
    ct: Vec<u8>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("\nFAILED: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let rpc_url = std::env::var("MATTER_RPC_URL").unwrap_or_else(|_| DEFAULT_RPC.to_string());
    let seed_str = std::env::var("MATTER_SIGNER_SEED")
        .or_else(|_| std::env::var("TEST_KEY"))
        .map_err(|_| "set MATTER_SIGNER_SEED or TEST_KEY (0x-hex seed or mnemonic / SURI)")?;
    let secret = std::env::var("MATTER_SECRET").unwrap_or_else(|_| DEFAULT_SECRET.to_string());

    // The same secret URI (0x-hex seed, mnemonic, or SURI) drives both signers
    // (chain extrinsic + committee auth).
    let uri = SecretUri::from_str(seed_str.trim())?;
    let keypair = Keypair::from_uri(&uri)?;
    let committee_signer = Sr25519Signer::from_uri_insecure_dev_only(seed_str.trim())?;
    let account_id = keypair.public_key().to_account_id();
    println!("Account: {account_id}");

    // Connect once; share the RPC connection between the typed client and the
    // legacy state-call methods.
    let rpc = RpcClient::from_url(&rpc_url).await?;
    let api = OnlineClient::<PolkadotConfig>::from_rpc_client(rpc.clone()).await?;
    let legacy = LegacyRpcMethods::<PolkadotConfig>::new(rpc.clone());
    println!("Connected to {rpc_url}");

    // Best-effort balance line (the extrinsic below is the real crash-early guard
    // if the account is unfunded).
    if let Ok(at) = api.storage().at_latest().await {
        let addr = subxt::dynamic::storage("System", "Account", vec![Value::from_bytes(account_id.0)]);
        if let Ok(Some(v)) = at.fetch(&addr).await {
            if let Ok(val) = v.to_value() {
                if let Some(free) = val.at("data").and_then(|d| d.at("free")) {
                    println!("Balance: {free:?}");
                }
            }
        }
    }

    // 1. Encryption context (joint_pk + current epoch).
    let joint_pk = decode_opt_bytes(&call(&legacy, RT_JOINT_PK, None).await?)
        .ok_or("KGC DKG not finalised on chain (joint_pk is None)")?;
    let epoch: u32 = decode(&call(&legacy, RT_DKG_EPOCH, None).await?)?;
    println!("Committee epoch={epoch}, joint_pk={}B", joint_pk.len());

    // 2. Seal locally, then publish with secrets.storeSecret (the gas-paying step).
    let env = matter_vault::encrypt(&joint_pk, epoch, secret.as_bytes(), Aad::EnvV1.as_bytes(), None)?;
    println!(
        "Sealed {}B -> capsule {}B, proof {}B, ct {}B",
        secret.len(),
        env.capsule.len(),
        env.proof.len(),
        env.ct.len()
    );

    let payload = Value::named_composite([
        ("binding_id", Value::from_bytes(&env.binding_id)),
        ("capsule", Value::from_bytes(&env.capsule)),
        ("proof", Value::from_bytes(&env.proof)),
        ("ct", Value::from_bytes(&env.ct)),
    ]);
    let store = subxt::dynamic::tx(
        "Secrets",
        "store_secret",
        vec![
            payload,
            Value::u128(epoch as u128),
            Value::from_bytes(Vec::<u8>::new()),         // label (empty)
            Value::from_bytes(Aad::EnvV1.as_bytes()),    // aad
        ],
    );

    println!("Submitting secrets.storeSecret ...");
    let events = api
        .tx()
        .sign_and_submit_then_watch_default(&store, &keypair)
        .await?
        .wait_for_finalized_success()
        .await?;

    let secret_id = secret_id_from_events(&events)?;
    println!("Stored on chain: secret_id={secret_id}");

    // 3. Read the persisted envelope + its epoch back from chain.
    let sid_arg = secret_id.encode();
    let secret_epoch: u32 = decode_opt(&call(&legacy, RT_SECRET_EPOCH, Some(&sid_arg)).await?)?
        .ok_or("stored secret has no epoch")?;
    let wire: EncSecretWire = decode_opt(&call(&legacy, RT_SECRET_PAYLOAD, Some(&sid_arg)).await?)?
        .ok_or("stored secret not found on chain")?;

    // 4. Gather committee state for the secret's epoch.
    let shared_a = decode_opt_bytes(&call(&legacy, RT_SHARED_A, None).await?)
        .ok_or("KGC shared_a unavailable (DKG not finalised)")?;
    let (_, threshold): (u64, u64) =
        decode(&call(&legacy, RT_THRESHOLD, Some(&secret_epoch.encode())).await?)?;
    let nodes_raw: Vec<(AccountId32Bytes, KgcNodeInfo)> =
        decode(&call(&legacy, RT_KGC_NODES, None).await?)?;
    println!("Committee: {} nodes, threshold t={threshold}", nodes_raw.len());

    let mut nodes = Vec::with_capacity(nodes_raw.len());
    for (account, info) in &nodes_raw {
        let arg = (secret_epoch, account).encode();
        let commitment = decode_opt_bytes(&call(&legacy, RT_SHARE_COMMITMENT, Some(&arg)).await?)
            .ok_or("missing share commitment for a node")?;
        nodes.push(CommitteeNode {
            index: info.dkg_index,
            endpoint: normalize_endpoint(&String::from_utf8_lossy(&info.endpoint)),
            share_commitment: commitment,
        });
    }

    // 5. Threshold-decrypt. The signer wraps the keypair; the key stays here.
    let block_hash = legacy.chain_get_finalized_head().await?.0;
    println!("Collecting partial decryptions ...");
    let recovered = decrypt(
        &ReqwestTransport::new(),
        &committee_signer,
        &DecryptRequest {
            secret_id,
            epoch: secret_epoch,
            binding_id: &wire.binding_id,
            aad: Aad::EnvV1.as_bytes(),
            capsule: &wire.capsule,
            ct: &wire.ct,
            shared_a: &shared_a,
            block_hash,
            threshold: threshold as usize,
            nodes: &nodes,
        },
    )
    .await?;

    let recovered = String::from_utf8_lossy(recovered.expose()).to_string();
    println!("\nRecovered: {recovered}");
    if recovered != secret {
        return Err("MISMATCH: recovered plaintext != original".into());
    }
    println!("Round trip verified ✔");

    // Capture the golden sample for the other languages to re-decrypt.
    let golden = serde_json::json!({
        "secret_id": secret_id.to_string(),
        "address": account_id.to_string(),
        "epoch": secret_epoch,
        "aad": "env",
        "plaintext": recovered,
        "rpc_url": rpc_url,
    });
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../golden.json");
    std::fs::write(path, serde_json::to_string_pretty(&golden)? + "\n")?;
    println!("Golden sample written to examples/golden.json");
    Ok(())
}

/// One runtime-API state call, returning the raw SCALE-encoded result.
async fn call(
    legacy: &LegacyRpcMethods<PolkadotConfig>,
    method: &str,
    args: Option<&[u8]>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(legacy.state_call(method, args, None).await?)
}

fn decode<T: Decode>(bytes: &[u8]) -> Result<T, Box<dyn std::error::Error>> {
    Ok(T::decode(&mut &bytes[..])?)
}

fn decode_opt<T: Decode>(bytes: &[u8]) -> Result<Option<T>, Box<dyn std::error::Error>> {
    Ok(Option::<T>::decode(&mut &bytes[..])?)
}

fn decode_opt_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    Option::<Vec<u8>>::decode(&mut &bytes[..]).ok().flatten()
}

fn secret_id_from_events(
    events: &subxt::blocks::ExtrinsicEvents<PolkadotConfig>,
) -> Result<u128, Box<dyn std::error::Error>> {
    for ev in events.iter() {
        let ev = ev?;
        if ev.pallet_name() == "Secrets" && ev.variant_name() == "SecretStored" {
            // Field 0 is the chain-assigned secret_id (u128, SCALE little-endian).
            return Ok(u128::decode(&mut ev.field_bytes())?);
        }
    }
    Err("storeSecret landed but emitted no Secrets.SecretStored event".into())
}

fn normalize_endpoint(raw: &str) -> String {
    let s = raw.trim();
    let with_scheme = if s.contains("://") { s.to_string() } else { format!("https://{s}") };
    with_scheme.trim_end_matches('/').to_string()
}
