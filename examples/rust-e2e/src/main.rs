// Live Secrets round trip against a chain + committee: seal -> secrets.storeSecret
// (pays a fee) -> read back -> threshold-decrypt -> verify. Writes
// examples/golden.json for the other languages to re-decrypt.
//
// Needs a FUNDED account. The key never leaves this process: subxt signs the
// extrinsic, `Sr25519Signer` signs the /partial-decrypt requests. Environment
// variables: examples/README.md.

use std::str::FromStr;

use matter_sdk::{decrypt, Aad, CommitteeNode, DecryptRequest, ReqwestTransport, Sr25519Signer};
use parity_scale_codec::{Decode, Encode};
use subxt::backend::legacy::LegacyRpcMethods;
use subxt::backend::rpc::RpcClient;
use subxt::dynamic::{At, Value};
use subxt::{OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::Keypair;
use subxt_signer::SecretUri;

const DEFAULT_SECRET: &str = "API_KEY=swordfish\nDATABASE_URL=postgres://prod";

const RT_JOINT_PK: &str = "KgcApi_joint_pk";
const RT_DKG_EPOCH: &str = "KgcApi_dkg_epoch";
const RT_KGC_NODES: &str = "KgcApi_kgc_nodes";
const RT_SHARED_A: &str = "KgcApi_shared_a";
const RT_THRESHOLD: &str = "KgcApi_threshold_params_at_epoch";
const RT_SHARE_COMMITMENT: &str = "KgcApi_share_commitment";
const RT_SECRET_PAYLOAD: &str = "SecretsApi_secret_payload";
const RT_SECRET_EPOCH: &str = "SecretsApi_secret_epoch";

type AccountId32Bytes = [u8; 32];

/// `KgcNodeInfo` from `KgcApi_kgc_nodes`; field order must match the chain.
#[derive(Decode)]
struct KgcNodeInfo {
    endpoint: Vec<u8>,
    dkg_index: u64,
}

/// The on-chain `EncryptedSecret` envelope (four SCALE `Vec<u8>` blobs).
///
/// `proof` is unused on decrypt: the committee's per-partial proofs are verified instead.
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

/// Refuse mainnet without `MATTER_CONFIRM=yes`.
///
/// Checks the URL as well as `MATTER_NETWORK`: a mistyped `MATTER_RPC_URL` is the
/// likelier mistake.
fn guard_mainnet(rpc_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let network = std::env::var("MATTER_NETWORK").unwrap_or_else(|_| "testnet".to_string());
    let looks_like_mainnet = network == "mainnet" || rpc_url.contains("mainnet");
    if !looks_like_mainnet {
        return Ok(());
    }
    if std::env::var("MATTER_CONFIRM").is_ok_and(|v| v == "yes") {
        eprintln!("WARNING: running against MAINNET with real funds (MATTER_CONFIRM=yes).");
        return Ok(());
    }
    Err(format!(
        "refusing to run a gas-paying harness against mainnet ({rpc_url}) without \
         explicit confirmation: set MATTER_CONFIRM=yes. This spends real funds."
    )
    .into())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // Default endpoint per network: testvectors/networks.json.
    let network = match std::env::var("MATTER_NETWORK").as_deref() {
        Ok("mainnet") => matter_sdk::chain::Network::Mainnet,
        Ok("testnet") | Err(_) => matter_sdk::chain::Network::Testnet,
        Ok(other) => {
            return Err(format!("MATTER_NETWORK must be testnet or mainnet, got {other}").into())
        }
    };
    let default_rpc = network
        .default_rpc_url()
        .expect("named networks have a default endpoint");
    let rpc_url = std::env::var("MATTER_RPC_URL").unwrap_or_else(|_| default_rpc.to_string());
    guard_mainnet(&rpc_url)?;
    let seed_str = std::env::var("MATTER_SIGNER_SEED")
        .or_else(|_| std::env::var("TEST_KEY"))
        .map_err(|_| "set MATTER_SIGNER_SEED or TEST_KEY (0x-hex seed or mnemonic / SURI)")?;
    let secret = std::env::var("MATTER_SECRET").unwrap_or_else(|_| DEFAULT_SECRET.to_string());

    // One secret URI drives both signers: chain extrinsic and committee auth.
    let uri = SecretUri::from_str(seed_str.trim())?;
    let keypair = Keypair::from_uri(&uri)?;
    let committee_signer = Sr25519Signer::from_uri_insecure_dev_only(seed_str.trim())?;
    let account_id = keypair.public_key().to_account_id();
    println!("Account: {account_id}");

    // One RPC connection shared by the typed client and legacy state calls.
    let rpc = RpcClient::from_url(&rpc_url).await?;
    let api = OnlineClient::<PolkadotConfig>::from_rpc_client(rpc.clone()).await?;
    let legacy = LegacyRpcMethods::<PolkadotConfig>::new(rpc.clone());
    println!("Connected to {rpc_url}");

    // Best-effort; an unfunded account fails at the extrinsic below.
    if let Ok(at) = api.storage().at_latest().await {
        let addr =
            subxt::dynamic::storage("System", "Account", vec![Value::from_bytes(account_id.0)]);
        if let Ok(Some(v)) = at.fetch(&addr).await {
            if let Ok(val) = v.to_value() {
                if let Some(free) = val.at("data").and_then(|d| d.at("free")) {
                    println!("Balance: {free:?}");
                }
            }
        }
    }

    let joint_pk = decode_opt_bytes(&call(&legacy, RT_JOINT_PK, None).await?)
        .ok_or("KGC DKG not finalised on chain (joint_pk is None)")?;
    let epoch: u32 = decode(&call(&legacy, RT_DKG_EPOCH, None).await?)?;
    println!("Committee epoch={epoch}, joint_pk={}B", joint_pk.len());

    // Seal locally, then publish (pays gas).
    let env = matter_sdk::encrypt(
        &joint_pk,
        epoch,
        secret.as_bytes(),
        Aad::EnvV1.as_bytes(),
        None,
    )?;
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
            Value::from_bytes(Vec::<u8>::new()), // label (empty)
            Value::from_bytes(Aad::EnvV1.as_bytes()), // aad
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

    let sid_arg = secret_id.encode();
    let secret_epoch: u32 = decode_opt(&call(&legacy, RT_SECRET_EPOCH, Some(&sid_arg)).await?)?
        .ok_or("stored secret has no epoch")?;
    let wire: EncSecretWire = decode_opt(&call(&legacy, RT_SECRET_PAYLOAD, Some(&sid_arg)).await?)?
        .ok_or("stored secret not found on chain")?;

    // Gather committee state for the secret's epoch.
    let shared_a = decode_opt_bytes(&call(&legacy, RT_SHARED_A, None).await?)
        .ok_or("KGC shared_a unavailable (DKG not finalised)")?;
    let (_, threshold): (u64, u64) =
        decode(&call(&legacy, RT_THRESHOLD, Some(&secret_epoch.encode())).await?)?;
    let nodes_raw: Vec<(AccountId32Bytes, KgcNodeInfo)> =
        decode(&call(&legacy, RT_KGC_NODES, None).await?)?;
    println!(
        "Committee: {} nodes, threshold t={threshold}",
        nodes_raw.len()
    );

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

    // Threshold-decrypt.
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

    // Recovered plaintext is compared in process, never printed.
    println!("\nRecovered {} bytes", recovered.expose().len());
    if recovered.expose() != secret.as_bytes() {
        return Err("MISMATCH: recovered plaintext != original".into());
    }
    println!("Round trip verified ✔");

    // The demo secret is public, so writing it to the golden sample leaks nothing.
    let golden = serde_json::json!({
        "secret_id": secret_id.to_string(),
        "address": account_id.to_string(),
        "epoch": secret_epoch,
        "aad": "env",
        "plaintext": secret,
        "rpc_url": rpc_url,
    });
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../golden.json");
    std::fs::write(path, serde_json::to_string_pretty(&golden)? + "\n")?;
    println!("Golden sample written to examples/golden.json");
    Ok(())
}

/// Runtime-API state call; returns the raw SCALE bytes.
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
            // Field 0: secret_id, u128 SCALE (little-endian).
            return Ok(u128::decode(&mut ev.field_bytes())?);
        }
    }
    Err("storeSecret landed but emitted no Secrets.SecretStored event".into())
}

fn normalize_endpoint(raw: &str) -> String {
    let s = raw.trim();
    let with_scheme = if s.contains("://") {
        s.to_string()
    } else {
        format!("https://{s}")
    };
    with_scheme.trim_end_matches('/').to_string()
}
