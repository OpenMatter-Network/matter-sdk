// Live Secrets round trip against a chain + committee, through `MatterClient`:
// seal -> `secrets().store` (pays a fee) -> read the id from the block's events ->
// `secrets().recover`. The other languages' harnesses can re-decrypt the stored
// secret with MATTER_SECRET_ID, and this one re-decrypts theirs.
//
// Needs a FUNDED account. The key never leaves this process: it stays in a
// subxt-signer keypair, and the SDK only receives `sign` calls through the same
// `KeySigner` seam an HSM or KMS would implement. The SDK hashes the (far over
// 256 bytes) extrinsic payload before `sign` sees it and signs committee requests
// raw; the signer below does neither. Environment variables: examples/README.md.

use std::str::FromStr;
use std::sync::Arc;

use matter_sdk::chain::{MatterClient, MatterConfig, Network};
use matter_sdk::{Aad, AccountId, KeyError, KeyScheme, KeySigner, StoreSecret};
use parity_scale_codec::Decode;
use subxt::utils::H256;
use subxt_signer::sr25519::Keypair;
use subxt_signer::SecretUri;

const DEFAULT_SECRET: &str = "API_KEY=swordfish\nDATABASE_URL=postgres://prod";
/// The label the stored secret carries on chain.
const SECRET_LABEL: &str = "rust-e2e";

const RT_JOINT_PK: &str = "KgcApi_joint_pk";
const RT_DKG_EPOCH: &str = "KgcApi_dkg_epoch";

const SECRETS_PALLET: &str = "Secrets";
const SECRET_STORED_EVENT: &str = "SecretStored";

/// The custom-signer seam, as an HSM or KMS would implement it: the SDK hands
/// over bytes and gets a raw 64-byte sr25519 signature back.
struct PairSigner {
    pair: Keypair,
}

impl KeySigner for PairSigner {
    fn scheme(&self) -> KeyScheme {
        KeyScheme::Sr25519
    }

    fn account_id(&self) -> AccountId {
        AccountId(self.pair.public_key().0)
    }

    fn sign(&self, message: &[u8]) -> Result<[u8; 64], KeyError> {
        Ok(self.pair.sign(message).0)
    }
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
/// likelier mistake. The client checks the chain's own identity on connect too.
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
        Ok("mainnet") => Network::Mainnet,
        Ok("testnet") | Err(_) => Network::Testnet,
        Ok(other) => {
            return Err(format!("MATTER_NETWORK must be testnet or mainnet, got {other}").into())
        }
    };
    let mut config = MatterConfig::for_network(network);
    config.rpc_url = std::env::var("MATTER_RPC_URL").ok();
    config.confirm_mainnet = std::env::var("MATTER_CONFIRM").is_ok_and(|v| v == "yes");
    let rpc_url = config.rpc_url.clone().unwrap_or_else(|| {
        network
            .default_rpc_url()
            .expect("named networks have a default endpoint")
            .to_string()
    });
    guard_mainnet(&rpc_url)?;

    let seed_str = std::env::var("MATTER_SIGNER_SEED")
        .or_else(|_| std::env::var("TEST_KEY"))
        .map_err(|_| "set MATTER_SIGNER_SEED or TEST_KEY (0x-hex seed or mnemonic / SURI)")?;
    let secret = std::env::var("MATTER_SECRET").unwrap_or_else(|_| DEFAULT_SECRET.to_string());
    let existing_id = std::env::var("MATTER_SECRET_ID")
        .ok()
        .map(|id| u128::from_str(id.trim()))
        .transpose()?;

    // One keypair drives both uses through one KeySigner: the extrinsic and the
    // committee requests.
    let pair = Keypair::from_uri(&SecretUri::from_str(seed_str.trim())?)?;
    let client = MatterClient::connect_with_signer(config, Arc::new(PairSigner { pair })).await?;
    println!(
        "Connected to {rpc_url} as {}",
        client.address().expect("a signing client has an address")
    );

    let joint_pk = decode_opt_bytes(&state_call(&client, RT_JOINT_PK).await?)
        .ok_or("KGC DKG not finalised on chain (joint_pk is None)")?;
    let epoch = u32::decode(&mut &state_call(&client, RT_DKG_EPOCH).await?[..])?;
    println!("Committee epoch={epoch}, joint_pk={}B", joint_pk.len());

    let secret_id = match existing_id {
        Some(id) => {
            println!("Using existing secret {id}.");
            id
        }
        None => {
            // Seal locally, then publish (pays gas) through the façade.
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
            println!("Submitting Secrets.store_secret through MatterClient ...");
            let receipt = client
                .secrets()
                .store(&StoreSecret::new(env, epoch, SECRET_LABEL, Aad::EnvV1))
                .await?;
            let id = secret_id_at(&client, receipt.block_hash).await?;
            println!(
                "Stored on chain: secret_id={id} in block {}",
                receipt.block_hash_hex()
            );
            id
        }
    };

    // Read the envelope, its epoch and that epoch's committee, then threshold-decrypt,
    // all in one call authorized by the client's signer.
    println!("Recovering through secrets().recover ...");
    let recovered = client.secrets().recover(secret_id, Aad::EnvV1).await?;

    // Recovered plaintext is compared in process, never printed.
    println!("\nRecovered {} bytes", recovered.expose().len());
    if existing_id.is_none() {
        if recovered.expose() != secret.as_bytes() {
            return Err("MISMATCH: recovered plaintext != original".into());
        }
        println!(
            "Round trip verified ✔ (re-decrypt from another language with MATTER_SECRET_ID={secret_id})"
        );
    }
    Ok(())
}

/// A runtime-API read as raw SCALE, through the client's RPC handle.
async fn state_call(
    client: &MatterClient,
    method: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(client.rpc().state_call(method, None, None).await?)
}

fn decode_opt_bytes(bytes: &[u8]) -> Option<Vec<u8>> {
    Option::<Vec<u8>>::decode(&mut &bytes[..]).ok().flatten()
}

/// The id `Secrets.SecretStored` carries, read from the finalized block the receipt
/// names through the underlying subxt client, as docs/secrets.md describes.
async fn secret_id_at(
    client: &MatterClient,
    block_hash: [u8; 32],
) -> Result<u128, Box<dyn std::error::Error>> {
    let events = client
        .subxt()
        .blocks()
        .at(H256(block_hash))
        .await?
        .events()
        .await?;
    for ev in events.iter() {
        let ev = ev?;
        if ev.pallet_name() == SECRETS_PALLET && ev.variant_name() == SECRET_STORED_EVENT {
            // Field 0: secret_id, u128 SCALE (little-endian).
            return Ok(u128::decode(&mut ev.field_bytes())?);
        }
    }
    Err("store_secret finalized but its block has no Secrets.SecretStored event".into())
}
