use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

#[cfg(target_os = "macos")]
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result, bail};
use bdk_esplora::EsploraExt;
use bdk_esplora::esplora_client::{BlockingClient, Builder};
use bdk_wallet::bitcoin::address::NetworkUnchecked;
use bdk_wallet::bitcoin::bip32::KeySource;
use bdk_wallet::bitcoin::secp256k1::PublicKey;
use bdk_wallet::bitcoin::{Address, Amount, FeeRate, Network, Psbt, Sequence};
use bdk_wallet::psbt::PsbtUtils;
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{KeychainKind, SignOptions, Wallet};
use clap::{Parser, Subcommand, ValueEnum};
use kiss_bdk::blindbit;
use kiss_bdk::qr::{render_psbt_bytes_png, scan_descriptor, scan_scan_key, scan_signed_psbt_bytes};
use kiss_bdk::sp::{self, SilentPaymentAddress};
use kiss_bdk::spreceive;
use kiss_bdk::spscan;
use kiss_bdk::spsend::{self, AnyPsbt};
use kiss_bdk::spspend;
use kiss_bdk::spstore;
use kiss_bdk::spverify;
use kiss_bdk::{
    kiss_fingerprint, read_psbt_bytes, split_kiss_descriptor, verify_psbt_signatures,
    write_new_file,
};
use serde::{Deserialize, Serialize};

const STOP_GAP: usize = 50;
const PARALLEL_REQUESTS: usize = 2;
const ESPLORA_TIMEOUT_SECS: u64 = 30;
const ESPLORA_MAX_RETRIES: usize = 3;
const KISS_MAX_PSBT_BYTES: usize = 4096;
const KISS_MAX_SIGNED_PSBT_BYTES: usize = 4680;
const KISS_MAX_QR_PSBT_BYTES: usize = 4096;
const KISS_MAX_PARTIAL_SIG_BYTES: usize = 110;
const KISS_MAX_INPUTS: usize = 16;
const KISS_MAX_OUTPUTS: usize = 16;
const KISS_MAX_SD_FILENAME_BYTES: usize = 63;
const MUTINYNET_FAUCET_URL: &str = "https://faucet.mutinynet.com/api/onchain";
const MUTINYNET_MAX_FAUCET_SATS: u64 = 1_000_000;
const DEFAULT_FAUCET_SATS: u64 = 100_000;
const FAUCET_TIMEOUT_SECS: u64 = 30;
const MUTINYNET_FAUCET_TOKEN_ENV: &str = "MUTINYNET_FAUCET_TOKEN";
const MUTINYNET_FAUCET_SIGN_IN: &str = "https://faucet.mutinynet.com/";

/// A supported test network, paired with its default backend and faucet.
///
/// KISS derives every one of these from the same account: BIP-44 coin type
/// `1h` is shared by the whole Bitcoin test family, which is why one KISS
/// descriptor works on all of them without any device change.
///
/// Mainnet and regtest are deliberately not variants, so an online wallet on
/// either is unrepresentable rather than merely rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Chain {
    #[value(name = "testnet4")]
    Testnet4,
    #[value(name = "signet")]
    Signet,
    #[value(name = "mutinynet")]
    Mutinynet,
}

impl Chain {
    fn network(self) -> Network {
        match self {
            Chain::Testnet4 => Network::Testnet4,
            // Mutinynet is a custom signet: same address format and same genesis
            // block as the default signet, but its own separate chain.
            Chain::Signet | Chain::Mutinynet => Network::Signet,
        }
    }

    fn default_esplora(self) -> &'static str {
        match self {
            Chain::Testnet4 => "https://mempool.space/testnet4/api",
            Chain::Signet => "https://mempool.space/signet/api",
            Chain::Mutinynet => "https://mutinynet.com/api",
        }
    }

    /// The tweak oracle a silent payment scan reads, where one is known.
    ///
    /// Only signet has a published server. Mutinynet is a different chain
    /// despite sharing signet's address format, so signet's oracle would answer
    /// confidently about blocks that are not Mutinynet's — which is worse than
    /// having no answer, and why this is `None` rather than a shared default.
    fn default_blindbit(self) -> Option<&'static str> {
        match self {
            Chain::Signet => Some("https://silentpayments.dev/blindbit/signet"),
            Chain::Testnet4 | Chain::Mutinynet => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Chain::Testnet4 => "Testnet4",
            Chain::Signet => "Signet",
            Chain::Mutinynet => "Mutinynet (custom signet)",
        }
    }

    fn faucet(self) -> FaucetKind {
        match self {
            Chain::Mutinynet => FaucetKind::Api,
            Chain::Signet => FaucetKind::Manual(&[
                "https://bitcoinsignetfaucet.com/",
                "https://signetfaucet.com/",
            ]),
            Chain::Testnet4 => FaucetKind::Manual(&["https://mempool.space/testnet4/faucet"]),
        }
    }

    /// The chain named by a config written before the `chain` field existed.
    fn from_network(network: Network) -> Option<Self> {
        match network {
            Network::Testnet4 => Some(Chain::Testnet4),
            Network::Signet => Some(Chain::Signet),
            _ => None,
        }
    }
}

/// How a chain's test coins are obtained.
enum FaucetKind {
    /// A JSON API this CLI can call directly.
    Api,
    /// Browser-only: the public faucets are all captcha-protected.
    Manual(&'static [&'static str]),
}

#[derive(Debug, Parser)]
#[command(
    name = "kiss-bdk",
    version,
    about = "KISS test-network coordinator (experimental)"
)]
struct Cli {
    /// Wallet state directory.
    #[arg(long, global = true, default_value = "kiss-bdk-wallet")]
    wallet_dir: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Create a watch-only wallet from KISS's DESKTOP descriptor.
    Init {
        /// Paste the descriptor directly.
        #[arg(
            long,
            conflicts_with_all = ["descriptor_file", "scan_qr"],
            required_unless_present_any = ["descriptor_file", "scan_qr"]
        )]
        descriptor: Option<String>,

        /// Read the descriptor from a text file.
        #[arg(long, conflicts_with_all = ["descriptor", "scan_qr"])]
        descriptor_file: Option<PathBuf>,

        /// Scan KISS's descriptor QR with the computer webcam.
        #[arg(long, conflicts_with_all = ["descriptor", "descriptor_file"])]
        scan_qr: bool,

        /// Webcam index used by --scan-qr.
        #[arg(long, default_value_t = 0)]
        camera: u32,

        /// Test network to coordinate. KISS needs no change for any of them.
        #[arg(long, value_enum, default_value = "testnet4")]
        network: Chain,

        /// Esplora API. Defaults to a public backend for the chosen network.
        /// HTTPS works on networks that block Electrum ports.
        #[arg(long)]
        esplora: Option<String>,
    },

    /// Scan the configured network and update wallet state.
    Sync,

    /// Reveal and save the next KISS receive address.
    Address,

    /// Show the locally stored balance (run sync first).
    Balance,

    /// Request test coins for the wallet's next unused receive address.
    Faucet {
        /// Amount to request in satoshis.
        #[arg(long, default_value_t = DEFAULT_FAUCET_SATS)]
        sats: u64,

        /// Top up this address instead of the wallet's next unused one.
        #[arg(long)]
        address: Option<String>,

        /// Mutinynet faucet token. Defaults to $MUTINYNET_FAUCET_TOKEN.
        #[arg(long)]
        token: Option<String>,
    },

    /// Build an unsigned PSBT for KISS to review and sign.
    Create {
        /// Destination address on the configured network.
        #[arg(long)]
        to: String,

        /// Amount to send in satoshis.
        #[arg(long)]
        sats: u64,

        /// Fee rate in whole sat/vB.
        #[arg(long, default_value_t = 2)]
        fee_rate: u64,

        /// Keep the original unsigned PSBT here (also used for the optional SD flow).
        #[arg(long, default_value = "unsigned.psbt")]
        out: PathBuf,

        /// Display the unsigned PSBT as a QR for KISS to scan.
        #[arg(long)]
        qr: bool,

        /// Spend received silent payments instead of the descriptor wallet's
        /// coins. KISS refuses a transaction that mixes the two, so this is a
        /// choice rather than a hint.
        #[arg(long)]
        from_sp: bool,
    },

    /// Scan KISS's animated signed-PSBT QR with the computer webcam.
    Scan {
        /// Save the reconstructed signed PSBT here.
        #[arg(long, default_value = "signed.psbt")]
        out: PathBuf,

        /// Original unsigned PSBT retained by create.
        #[arg(long, default_value = "unsigned.psbt")]
        original: PathBuf,

        /// Webcam index.
        #[arg(long, default_value_t = 0)]
        camera: u32,
    },

    /// Import KISS's silent payment scan key so payments can be found.
    SpPair {
        /// Read the scan key from KISS's export QR with the webcam.
        #[arg(long)]
        scan_qr: bool,

        /// Paste the export instead of scanning it.
        #[arg(long, conflicts_with = "scan_qr")]
        key: Option<String>,

        /// Webcam index.
        #[arg(long, default_value_t = 0)]
        camera: u32,
    },

    /// Show the silent payment address this wallet receives on.
    SpAddress,

    /// Search the chain for silent payments to this wallet.
    SpScan {
        /// Check one transaction instead of walking the chain. Works before it
        /// is mined, since the tweak is derived here rather than read from the
        /// oracle, which only publishes for blocks it has indexed.
        #[arg(long, value_name = "TXID", conflicts_with_all = ["from", "blindbit"])]
        tx: Option<String>,

        /// First block to search. Defaults to continuing where the last scan
        /// stopped, or the current tip on a wallet that has never scanned.
        #[arg(long)]
        from: Option<u32>,

        /// Tweak oracle to read, overriding the chain's default.
        #[arg(long)]
        blindbit: Option<String>,
    },

    /// Show the silent payment outputs found so far.
    SpBalance,

    /// Inspect a binary or base64 PSBT without broadcasting it.
    Inspect {
        #[arg(value_name = "PSBT")]
        psbt: PathBuf,
    },

    /// Finalize a KISS-signed PSBT and broadcast it.
    Broadcast {
        #[arg(value_name = "SIGNED_PSBT")]
        psbt: PathBuf,

        /// Original unsigned PSBT, used to verify and complete KISS's response.
        #[arg(long)]
        original: PathBuf,

        /// Validate and finalize, but do not send anything to the network.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    network: String,
    /// Absent in wallets initialized before this coordinator supported Signet.
    #[serde(default)]
    chain: Option<Chain>,
    esplora: String,
    descriptor: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Init {
            descriptor,
            descriptor_file,
            scan_qr,
            camera,
            network,
            esplora,
        } => init(
            &cli.wallet_dir,
            descriptor,
            descriptor_file,
            scan_qr,
            camera,
            network,
            esplora,
        ),
        Command::Sync => sync(&cli.wallet_dir),
        Command::Address => next_address(&cli.wallet_dir),
        Command::Balance => balance(&cli.wallet_dir),
        Command::Faucet {
            sats,
            address,
            token,
        } => faucet(&cli.wallet_dir, sats, address, token),
        Command::Create {
            to,
            sats,
            fee_rate,
            out,
            qr,
            from_sp,
        } => create_psbt(&cli.wallet_dir, &to, sats, fee_rate, &out, qr, from_sp),
        Command::Scan {
            out,
            original,
            camera,
        } => scan_psbt(&cli.wallet_dir, &out, &original, camera),
        Command::SpPair {
            scan_qr,
            key,
            camera,
        } => sp_pair(&cli.wallet_dir, scan_qr, key, camera),
        Command::SpAddress => sp_address(&cli.wallet_dir),
        Command::SpScan { tx, from, blindbit } => match tx {
            Some(txid) => sp_scan_tx(&cli.wallet_dir, &txid),
            None => sp_scan(&cli.wallet_dir, from, blindbit),
        },
        Command::SpBalance => sp_balance(&cli.wallet_dir),
        Command::Inspect { psbt } => inspect_psbt(&psbt),
        Command::Broadcast {
            psbt,
            original,
            dry_run,
        } => broadcast(&cli.wallet_dir, &psbt, &original, dry_run),
    }
}

fn init(
    wallet_dir: &Path,
    descriptor_arg: Option<String>,
    descriptor_file: Option<PathBuf>,
    scan_qr: bool,
    camera: u32,
    chain: Chain,
    esplora: Option<String>,
) -> Result<()> {
    let config_path = wallet_dir.join("config.json");
    if config_path.exists() {
        bail!(
            "{} already exists; refusing to overwrite this wallet",
            config_path.display()
        );
    }

    let descriptor = match (descriptor_arg, descriptor_file, scan_qr) {
        (Some(value), None, false) => value,
        (None, Some(path), false) => fs::read_to_string(&path)
            .with_context(|| format!("reading descriptor from {}", path.display()))?,
        (None, None, true) => {
            println!("Hold KISS's DESKTOP descriptor QR in front of camera {camera}...");
            scan_descriptor(camera)?
        }
        _ => bail!("provide exactly one of --descriptor, --descriptor-file, or --scan-qr"),
    };
    let descriptor = descriptor.trim().to_owned();
    let (external, internal) = split_kiss_descriptor(&descriptor)?;
    let esplora = esplora.unwrap_or_else(|| chain.default_esplora().to_owned());

    fs::create_dir_all(wallet_dir).with_context(|| format!("creating {}", wallet_dir.display()))?;
    let mut connection = Connection::open(wallet_dir.join("wallet.sqlite"))?;
    Wallet::create(external, internal)
        .network(chain.network())
        .create_wallet(&mut connection)
        .context("creating BDK wallet; check that this is KISS's testnet descriptor")?;

    let config = Config {
        network: chain.network().to_string(),
        chain: Some(chain),
        esplora,
        descriptor,
    };
    fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;

    println!("initialized {}", wallet_dir.display());
    println!("network: {}", chain.label());
    println!("esplora: {}", config.esplora);
    println!("private keys: none (KISS remains the signer)");
    println!("next: kiss-bdk --wallet-dir {} sync", wallet_dir.display());
    Ok(())
}

fn load_config(wallet_dir: &Path) -> Result<(Config, Chain)> {
    let path = wallet_dir.join("config.json");
    let bytes =
        fs::read(&path).with_context(|| format!("reading {}; run init first", path.display()))?;
    let config: Config = serde_json::from_slice(&bytes)?;
    let network = Network::from_str(&config.network).with_context(|| {
        format!(
            "wallet config names an unknown network {:?}",
            config.network
        )
    })?;
    if network == Network::Bitcoin {
        bail!("wallet config names mainnet; this coordinator is for test networks only");
    }
    let chain = match config.chain {
        Some(chain) => chain,
        None => Chain::from_network(network)
            .with_context(|| format!("{network} is not a supported test network"))?,
    };
    // A hand-edited config must not be able to point a wallet at another chain.
    if chain.network() != network {
        bail!(
            "wallet config network {:?} does not match its {:?} chain",
            config.network,
            chain
        );
    }
    Ok((config, chain))
}

fn open_wallet(
    wallet_dir: &Path,
    config: &Config,
    chain: Chain,
) -> Result<(Connection, bdk_wallet::PersistedWallet<Connection>)> {
    let (external, internal) = split_kiss_descriptor(&config.descriptor)?;
    let mut connection = Connection::open(wallet_dir.join("wallet.sqlite"))?;
    let wallet = Wallet::load()
        .descriptor(KeychainKind::External, Some(external))
        .descriptor(KeychainKind::Internal, Some(internal))
        .check_network(chain.network())
        .load_wallet(&mut connection)?
        .context("wallet database is empty; run init first")?;
    Ok((connection, wallet))
}

fn esplora(config: &Config) -> BlockingClient {
    Builder::new(&config.esplora)
        .timeout(ESPLORA_TIMEOUT_SECS)
        .max_retries(ESPLORA_MAX_RETRIES)
        .build_blocking()
}

fn sync(wallet_dir: &Path) -> Result<()> {
    let (config, chain) = load_config(wallet_dir)?;
    let (mut connection, mut wallet) = open_wallet(wallet_dir, &config, chain)?;
    println!("scanning {} via {}...", chain.label(), config.esplora);
    let update = esplora(&config)
        .full_scan(wallet.start_full_scan(), STOP_GAP, PARALLEL_REQUESTS)
        .context("Esplora full scan failed")?;
    wallet.apply_update(update)?;
    wallet.persist(&mut connection)?;
    print_balance(&wallet);
    Ok(())
}

fn next_address(wallet_dir: &Path) -> Result<()> {
    let (config, chain) = load_config(wallet_dir)?;
    let (mut connection, mut wallet) = open_wallet(wallet_dir, &config, chain)?;
    let info = wallet.next_unused_address(KeychainKind::External);
    wallet.persist(&mut connection)?;
    println!("{}", info.address);
    println!("index: {}", info.index);
    println!("network: {}", chain.label());
    println!("compare this address on KISS before funding it");
    Ok(())
}

fn balance(wallet_dir: &Path) -> Result<()> {
    let (config, chain) = load_config(wallet_dir)?;
    let (_connection, wallet) = open_wallet(wallet_dir, &config, chain)?;
    println!("network: {}", chain.label());
    print_balance(&wallet);
    Ok(())
}

/// Import the scan key KISS exports.
///
/// This is the one command that puts a secret in the wallet directory, so it
/// says so rather than leaving that to the documentation.
fn sp_pair(wallet_dir: &Path, scan_qr: bool, key: Option<String>, camera: u32) -> Result<()> {
    let (config, chain) = load_config(wallet_dir)?;
    let export = match (scan_qr, key) {
        (true, _) => {
            println!("hold KISS's scan key QR in front of camera {camera}...");
            scan_scan_key(camera)?
        }
        (false, Some(key)) => key,
        (false, None) => bail!("pass --scan-qr to read KISS's export, or --key to paste it"),
    };

    let keys = spreceive::parse_scan_export(&export)?;
    let (mut connection, _wallet) = open_wallet(wallet_dir, &config, chain)?;
    spstore::migrate(&mut connection)?;
    spstore::put_keys(&mut connection, &keys)?;

    println!("{}", keys.code(chain.network()));
    println!("network: {}", chain.label());
    println!("compare this address on KISS before receiving to it");
    println!();
    println!("this wallet directory now holds the scan private key, which can");
    println!("see payments to that address but never spend them; the spend key");
    println!("stays on KISS");
    Ok(())
}

fn sp_address(wallet_dir: &Path) -> Result<()> {
    let (config, chain) = load_config(wallet_dir)?;
    let (mut connection, _wallet) = open_wallet(wallet_dir, &config, chain)?;
    spstore::migrate(&mut connection)?;
    let keys = spstore::keys(&connection)?
        .context("no silent payment keys; run sp-pair with KISS's export first")?;
    println!("{}", keys.code(chain.network()));
    println!("network: {}", chain.label());
    Ok(())
}

/// Check one transaction for payments to this wallet, mined or not.
///
/// The oracle cannot answer for a transaction still in the mempool, which is
/// exactly the moment someone watching a demo wants an answer. For a single
/// known transaction the tweak can be derived here from its inputs' previous
/// scripts instead, at a few requests rather than a chain walk.
fn sp_scan_tx(wallet_dir: &Path, txid: &str) -> Result<()> {
    let (config, chain) = load_config(wallet_dir)?;
    let txid: bdk_wallet::bitcoin::Txid = txid.parse().context("that is not a transaction id")?;

    let (mut connection, _wallet) = open_wallet(wallet_dir, &config, chain)?;
    spstore::migrate(&mut connection)?;
    let keys = spstore::keys(&connection)?
        .context("no silent payment keys; run sp-pair with KISS's export first")?;

    let esplora = esplora(&config);
    let tx = esplora
        .get_tx(&txid)
        .with_context(|| format!("fetching {txid}"))?
        .with_context(|| format!("{txid} is not known to the backend"))?;

    // BIP-352 sums the inputs' keys, so every input's previous script is
    // needed; the amounts are not, which is why only the script is read.
    let mut prevouts = Vec::with_capacity(tx.input.len());
    for input in &tx.input {
        let previous = esplora
            .get_tx(&input.previous_output.txid)
            .with_context(|| format!("fetching input {}", input.previous_output))?
            .with_context(|| format!("input {} is unknown", input.previous_output))?;
        let vout = input.previous_output.vout as usize;
        let txout = previous.output.get(vout).with_context(|| {
            format!(
                "input {} points past its transaction",
                input.previous_output
            )
        })?;
        prevouts.push(txout.clone());
    }

    let height = esplora
        .get_tx_status(&txid)
        .ok()
        .and_then(|status| status.block_height)
        .unwrap_or(spscan::UNCONFIRMED);

    let found = spscan::scan_transaction(&spscan::scanner(&keys), &tx, &prevouts, height)?;
    for item in &found {
        let where_ = if item.height == spscan::UNCONFIRMED {
            "unconfirmed".to_string()
        } else {
            format!("block {}", item.height)
        };
        println!(
            "found {} sats at {} ({where_})",
            item.out.amount.to_sat(),
            item.out.outpoint
        );
    }
    if found.is_empty() {
        println!("{txid} pays nothing to this wallet's silent payment address");
    }
    // Stored so sp-balance shows it immediately; a later chain scan finds the
    // same outpoint and updates the row with its real height rather than
    // adding a second one.
    spstore::put_found(&mut connection, &found)?;
    Ok(())
}

/// Search the chain for payments to this wallet's silent payment address.
fn sp_scan(wallet_dir: &Path, from: Option<u32>, blindbit_url: Option<String>) -> Result<()> {
    let (config, chain) = load_config(wallet_dir)?;
    let url = blindbit_url
        .or_else(|| chain.default_blindbit().map(str::to_string))
        .with_context(|| {
            format!(
                "no tweak oracle is known for {}; pass --blindbit URL",
                chain.label()
            )
        })?;

    let (mut connection, _wallet) = open_wallet(wallet_dir, &config, chain)?;
    spstore::migrate(&mut connection)?;
    let keys = spstore::keys(&connection)?
        .context("no silent payment keys; run sp-pair with KISS's export first")?;

    let blindbit = blindbit::BlindbitClient::new(&url);
    let info = blindbit
        .info()
        .context("the tweak oracle did not answer; check --blindbit")?;
    // A signet oracle will answer confidently about heights that mean nothing
    // on another chain, so refuse rather than scan the wrong chain's blocks.
    if !info
        .network
        .eq_ignore_ascii_case(&chain.network().to_string())
    {
        bail!(
            "the oracle at {url} serves {:?}, but this wallet is on {}",
            info.network,
            chain.label()
        );
    }

    // The oracle's own height is the ceiling, not the chain tip: scanning past
    // what it has indexed would skip payments without saying so.
    let tip = blindbit.block_height()?;
    let start = match from.or_else(|| spstore::watermark(&connection).ok().flatten()) {
        Some(height) => height,
        // A wallet that has never scanned has no history worth walking; a
        // full-chain scan should be an explicit --from, not a surprise.
        None => tip,
    };
    if start > tip {
        bail!("the oracle has only indexed to {tip}, below the requested start {start}");
    }

    let scanner = spscan::scanner(&keys);
    let esplora = esplora(&config);
    println!("scanning {} to {tip} via {url}...", start);

    let mut total = 0_usize;
    for height in start..=tip {
        let tweaks = blindbit.tweaks(height)?;
        if tweaks.is_empty() {
            spstore::set_watermark(&mut connection, height)?;
            continue;
        }

        let hash = esplora
            .get_block_hash(height)
            .with_context(|| format!("looking up block {height}"))?;
        let block = esplora
            .get_block_by_hash(&hash)
            .with_context(|| format!("fetching block {height}"))?
            .with_context(|| format!("block {height} is missing from the backend"))?;

        let found = spscan::scan_block(&keys, &scanner, &tweaks, &block, height)?;
        for item in &found {
            println!(
                "found {} sats at {} in block {height}",
                item.out.amount.to_sat(),
                item.out.outpoint
            );
        }
        total += found.len();
        spstore::put_found(&mut connection, &found)?;
        spstore::set_watermark(&mut connection, height)?;
    }

    // Not "new": a rescan of the same range finds the same outputs again, and
    // storing them is idempotent. Counting them as new would misreport that.
    println!("scanned to {tip}; {total} silent payment output(s) in range");
    Ok(())
}

fn sp_balance(wallet_dir: &Path) -> Result<()> {
    let (config, chain) = load_config(wallet_dir)?;
    let (mut connection, _wallet) = open_wallet(wallet_dir, &config, chain)?;
    spstore::migrate(&mut connection)?;

    let outputs = spstore::outputs(&connection)?;
    let total: u64 = outputs.iter().map(|out| out.amount.to_sat()).sum();
    println!("network: {}", chain.label());
    match spstore::watermark(&connection)? {
        Some(height) => println!("scanned to: {height}"),
        None => println!("scanned to: never (run sp-scan)"),
    }
    for out in &outputs {
        let seen = if out.height == spscan::UNCONFIRMED {
            "unconfirmed".to_string()
        } else {
            format!("block {}", out.height)
        };
        println!("{} sats at {} ({seen})", out.amount.to_sat(), out.outpoint);
    }
    println!("silent payment total: {total} sats");
    // Worth saying here rather than only in the error: these coins are spent on
    // their own, so a reader comparing this total against the wallet balance
    // does not conclude the two add up.
    if !outputs.is_empty() {
        println!("spend with: create --from-sp (silent payments are never mixed");
        println!("            with ordinary coins in one transaction)");
    }
    Ok(())
}

fn print_balance(wallet: &Wallet) {
    let balance = wallet.balance();
    println!("confirmed: {} sats", balance.confirmed.to_sat());
    println!("trusted pending: {} sats", balance.trusted_pending.to_sat());
    println!(
        "untrusted pending: {} sats",
        balance.untrusted_pending.to_sat()
    );
    println!("total: {} sats", balance.total().to_sat());
}

fn faucet(
    wallet_dir: &Path,
    sats: u64,
    address: Option<String>,
    token: Option<String>,
) -> Result<()> {
    let (config, chain) = load_config(wallet_dir)?;
    check_faucet_sats(chain, sats)?;
    let (mut connection, mut wallet) = open_wallet(wallet_dir, &config, chain)?;
    let address = match address {
        Some(value) => Address::<NetworkUnchecked>::from_str(&value)
            .context("invalid address")?
            .require_network(chain.network())
            .with_context(|| format!("address is not valid for {}", chain.label()))?,
        None => {
            let info = wallet.next_unused_address(KeychainKind::External);
            wallet.persist(&mut connection)?;
            info.address
        }
    };

    println!("network: {}", chain.label());
    println!("address: {address}");
    match chain.faucet() {
        FaucetKind::Api => {
            let token = token
                .or_else(|| std::env::var(MUTINYNET_FAUCET_TOKEN_ENV).ok())
                .map(|token| token.trim().to_owned())
                .filter(|token| !token.is_empty())
                .with_context(|| {
                    format!(
                        "the Mutinynet faucet requires a token. Sign in with GitHub at \
                         {MUTINYNET_FAUCET_SIGN_IN} to get one, then pass --token <TOKEN> or set \
                         {MUTINYNET_FAUCET_TOKEN_ENV}. You can also paste the address above into \
                         that page by hand."
                    )
                })?;
            request_mutinynet_coins(&address, sats, &token)?;
        }
        FaucetKind::Manual(urls) => print_manual_faucet(chain, sats, urls),
    }
    println!("next: kiss-bdk --wallet-dir {} sync", wallet_dir.display());
    Ok(())
}

#[derive(Serialize)]
struct FaucetRequest<'a> {
    sats: u64,
    address: &'a str,
}

#[derive(Deserialize)]
struct FaucetResponse {
    txid: String,
}

fn request_mutinynet_coins(address: &Address, sats: u64, token: &str) -> Result<()> {
    let body = faucet_request_body(sats, &address.to_string())?;
    println!("POST {MUTINYNET_FAUCET_URL}");
    // The token authenticates the request and is deliberately never printed.
    println!("body: {}", String::from_utf8_lossy(&body));
    let response = minreq::post(MUTINYNET_FAUCET_URL)
        .with_header("content-type", "application/json")
        .with_header("authorization", format!("Bearer {token}"))
        .with_body(body)
        .with_timeout(FAUCET_TIMEOUT_SECS)
        .send()
        .context("contacting the Mutinynet faucet")?;
    let status = response.status_code;
    let text = response.as_str().unwrap_or("<non-UTF-8 response>").trim();
    if status == 401 {
        bail!(
            "the faucet rejected the token (HTTP 401): {text}. Sign in again at \
             {MUTINYNET_FAUCET_SIGN_IN} for a fresh one."
        );
    }
    if !(200..300).contains(&status) {
        bail!("faucet returned HTTP {status}: {text}");
    }
    let parsed: FaucetResponse =
        serde_json::from_str(text).context("parsing the faucet response")?;
    println!("faucet txid: {}", parsed.txid);
    println!("https://mutinynet.com/tx/{}", parsed.txid);
    println!("Mutinynet blocks are about 30 seconds apart.");
    Ok(())
}

/// Reject amounts the faucet would refuse anyway, before revealing an address.
fn check_faucet_sats(chain: Chain, sats: u64) -> Result<()> {
    if sats == 0 {
        bail!("--sats must be greater than zero");
    }
    if matches!(chain.faucet(), FaucetKind::Api) && sats > MUTINYNET_MAX_FAUCET_SATS {
        bail!("the Mutinynet faucet sends at most {MUTINYNET_MAX_FAUCET_SATS} sats per request");
    }
    Ok(())
}

fn faucet_request_body(sats: u64, address: &str) -> Result<Vec<u8>> {
    check_faucet_sats(Chain::Mutinynet, sats)?;
    serde_json::to_vec(&FaucetRequest { sats, address }).context("encoding the faucet request")
}

fn print_manual_faucet(chain: Chain, sats: u64, urls: &[&str]) {
    println!("requested amount: {sats} sats");
    println!(
        "{} faucets are captcha-protected, so this CLI cannot claim for you.",
        chain.label()
    );
    println!("Paste the address above into one of:");
    for url in urls {
        println!("  {url}");
    }
}

fn create_psbt(
    wallet_dir: &Path,
    destination: &str,
    sats: u64,
    fee_rate: u64,
    out: &Path,
    qr: bool,
    from_sp: bool,
) -> Result<()> {
    if sats == 0 {
        bail!("--sats must be greater than zero");
    }
    if fee_rate == 0 {
        bail!("--fee-rate must be greater than zero");
    }
    if !qr {
        validate_sd_psbt_path(out)?;
    }
    if out.exists() {
        bail!("{} already exists; refusing to overwrite it", out.display());
    }
    let qr_path = qr.then(|| qr_image_path(out));
    if let Some(path) = &qr_path
        && path.exists()
    {
        bail!(
            "{} already exists; refusing to overwrite it",
            path.display()
        );
    }
    let (config, chain) = load_config(wallet_dir)?;
    let recipient = parse_destination(destination, chain)?;
    let fee_rate = FeeRate::from_sat_per_vb(fee_rate).context("fee rate is too large")?;

    let (mut connection, mut wallet) = open_wallet(wallet_dir, &config, chain)?;
    let sp_spend = if from_sp {
        spstore::migrate(&mut connection)?;
        Some(prepare_sp_spend(
            &connection,
            &config,
            Amount::from_sat(sats),
            fee_rate,
        )?)
    } else {
        None
    };
    let sp_coins: &[spspend::SpCoin] = sp_spend.as_ref().map_or(&[], |sp| &sp.coins);

    let mut builder = wallet.build_tx();
    if let Some(sp) = &sp_spend {
        for coin in &sp.coins {
            // Everything handed to the builder this way becomes a *required*
            // input (bdk_wallet wallet/mod.rs:1431), which is why the selection
            // above chose rather than offered: adding every candidate would
            // sweep the whole silent payment balance into one transaction.
            //
            // The sequence is explicit because `add_foreign_utxo` defaults to
            // Sequence::MAX and the foreign value wins over the one BDK would
            // otherwise set -- which would quietly turn RBF off and disable
            // this input's nLockTime while the transaction still carried one.
            builder
                .add_foreign_utxo_with_sequence(
                    coin.outpoint,
                    spspend::psbt_input(coin, &sp.spend, &sp.origin),
                    spspend::SATISFACTION_WEIGHT,
                    Sequence::ENABLE_RBF_NO_LOCKTIME,
                )
                .with_context(|| format!("adding silent payment {}", coin.outpoint))?;
        }
        // Without this BDK tops the transaction up from the descriptor wallet,
        // and a transaction mixing silent payment inputs with ordinary ones is
        // one KISS refuses outright.
        builder.manually_selected_only();
    }
    // Every input carries its full previous transaction, which is what lets the
    // signer prove each input amount by hashing it back to its outpoint.
    //
    // Witness UTXOs alone are cheaper and were used here first, but a witness
    // UTXO states an amount nothing commits to. With two or more inputs a
    // coordinator can understate one and the difference becomes fee, invisible
    // on the device and unrecoverable after signing -- so KISS refuses to sign
    // that shape rather than warn about it. Attaching the previous transactions
    // is BIP-174's own recommendation and what Core, Sparrow and Electrum send.
    //
    // It costs about 116 bytes per input, which the QR still carries; and if a
    // transaction ever does outgrow the QR, `create` says so here rather than
    // the device refusing it after the walk across the room.
    builder
        .add_recipient(recipient.script_pubkey(), Amount::from_sat(sats))
        .fee_rate(fee_rate);
    let psbt = builder.finish().context("building transaction")?;
    // A silent payment leaves as a PSBTv2: only the signer can derive the
    // output script, so v0's fixed unsigned transaction cannot carry it.
    // A silent payment output leaves as a PSBTv2 because only the signer can
    // derive its script. A silent payment *input* leaves as one too, for a
    // different reason: the signer computes its taproot sighash only from the
    // transaction view it extracts from a v2's own fields, so a v0 carrying
    // tweaks loads green and then fails to sign.
    let sp_outputs = match &recipient {
        Destination::Address(_) => Vec::new(),
        Destination::SilentPayment(sp) => vec![spsend::SpOutput {
            index: spsend::placeholder_index(&psbt, sp)?,
            recipient: *sp,
        }],
    };
    let want_v2 = !sp_outputs.is_empty() || !sp_coins.is_empty();
    let serialized = if want_v2 {
        spsend::build_v2(&psbt, &sp_outputs)?
    } else {
        psbt.serialize()
    };
    let psbt_size = serialized.len();
    if psbt.inputs.len() > KISS_MAX_INPUTS {
        bail!(
            "transaction has {} inputs; KISS supports at most {KISS_MAX_INPUTS}",
            psbt.inputs.len()
        );
    }
    if psbt.outputs.len() > KISS_MAX_OUTPUTS {
        bail!(
            "transaction has {} outputs; KISS supports at most {KISS_MAX_OUTPUTS}",
            psbt.outputs.len()
        );
    }
    if psbt_size > KISS_MAX_PSBT_BYTES {
        bail!("unsigned PSBT is {psbt_size} bytes; KISS accepts at most {KISS_MAX_PSBT_BYTES}");
    }
    let estimated_signed_size = estimated_signed_psbt_size(
        psbt_size,
        psbt.inputs.len() - sp_coins.len(),
        sp_coins.len(),
    )?;
    if qr && estimated_signed_size > KISS_MAX_QR_PSBT_BYTES {
        bail!(
            "KISS's signed QR encoder holds at most {KISS_MAX_QR_PSBT_BYTES} bytes; this PSBT may grow to {estimated_signed_size} bytes"
        );
    }
    if estimated_signed_size > KISS_MAX_SIGNED_PSBT_BYTES {
        bail!(
            "KISS-signed PSBT may grow to {estimated_signed_size} bytes; its signing buffer holds at most {KISS_MAX_SIGNED_PSBT_BYTES}"
        );
    }
    let qr_png = qr.then(|| render_psbt_bytes_png(&serialized)).transpose()?;
    // finish() reserves a change address; persist before handing the PSBT out.
    wallet.persist(&mut connection)?;
    write_new_file(out, &serialized)?;
    if let (Some(path), Some(png)) = (&qr_path, qr_png) {
        write_new_file(path, &png)?;
    }

    // `calculate_fee` walks the wallet's own tx graph, which has never seen a
    // silent payment output. The documented remedy is `insert_txout`, but that
    // stages a floating txout into the graph and persists it on the next save,
    // so the sum is done here instead from the amounts the store already holds.
    let fee = if sp_coins.is_empty() {
        wallet.calculate_fee(&psbt.unsigned_tx)?
    } else {
        let inputs: Amount = sp_coins.iter().map(|coin| coin.amount).sum();
        let outputs: Amount = psbt.unsigned_tx.output.iter().map(|out| out.value).sum();
        inputs
            .checked_sub(outputs)
            .context("silent payment inputs do not cover the outputs")?
    };
    println!("wrote {}", out.display());
    println!("network: {}", chain.label());
    if let Destination::SilentPayment(_) = recipient {
        println!("silent payment: BIP-375 PSBTv2; KISS derives the output script");
    }
    if !sp_coins.is_empty() {
        println!(
            "spending {} received silent payment(s): BIP-376 PSBTv2",
            sp_coins.len()
        );
        for coin in sp_coins {
            println!("  {} ({} sats)", coin.outpoint, coin.amount.to_sat());
        }
    }
    println!("send: {} sats", sats);
    println!("fee: {} sats", fee.to_sat());
    println!("PSBT size: {psbt_size} bytes");
    println!("worst-case signed size: {estimated_signed_size} bytes");
    if let Some(path) = qr_path {
        println!("On KISS: SIGN → SCAN QR. Scan the QR opened on the computer:");
        open_qr_image(&path);
        println!(
            "After KISS signs: kiss-bdk --wallet-dir {} scan --original {} --out signed.psbt",
            wallet_dir.display(),
            out.display()
        );
    } else {
        println!("next: copy the PSBT to SD, review/sign it on KISS, then run:");
        println!(
            "kiss-bdk --wallet-dir {} broadcast <signed.psbt> --original {} --dry-run",
            wallet_dir.display(),
            out.display()
        );
    }
    Ok(())
}

/// The silent payment coins a spend will use, and what the PSBT needs to name
/// them.
struct SpSpend {
    coins: Vec<spspend::SpCoin>,
    spend: PublicKey,
    origin: KeySource,
}

/// Choose which received silent payments to spend.
///
/// Four things can be wrong with a stored row, and only the first is mere
/// staleness: it can be unconfirmed, its funding transaction can have been
/// reorged away, the coin can already be spent, or the tweak can no longer
/// reproduce the script -- which is what a wallet re-paired to a different KISS
/// looks like from here. The store answers the first, Esplora the next two, and
/// re-derivation the last.
fn prepare_sp_spend(
    connection: &Connection,
    config: &Config,
    target: Amount,
    fee_rate: FeeRate,
) -> Result<SpSpend> {
    let keys = spstore::keys(connection)?
        .context("no silent payment keys; run sp-pair with KISS's export first")?;
    let stored = spstore::candidates(connection)?;
    if stored.is_empty() {
        bail!(
            "no confirmed silent payments to spend; run sp-scan first, and note that \
             a payment cannot be seen until it is mined"
        );
    }

    let client = esplora(config);
    let mut candidates = Vec::new();
    let mut spent = 0_usize;
    let mut missing = 0_usize;
    for out in &stored {
        // Re-derive before asking the network: a coin this wallet cannot prove
        // it owns should say so by name, not turn into a lookup.
        let coin = spspend::SpCoin::checked(out, &keys.spend)?;
        match client
            .get_output_status(&out.outpoint.txid, u64::from(out.outpoint.vout))
            .with_context(|| format!("asking Esplora about {}", out.outpoint))?
        {
            // Esplora answers `None` both for a transaction it has never seen
            // and for a vout past the end of one it has, so this covers a
            // funding transaction reorged out from under a stored row --
            // sp-scan's watermark only walks forward and would never notice.
            None => missing += 1,
            Some(status) if status.spent => spent += 1,
            Some(_) => candidates.push(coin),
        }
    }
    if spent > 0 {
        println!("skipping {spent} silent payment(s) already spent");
    }
    if missing > 0 {
        println!(
            "skipping {missing} silent payment(s) {} no longer knows about; \
             their funding transaction may have been reorged out",
            config.esplora
        );
    }

    let coins = spspend::select(candidates, target, fee_rate, KISS_MAX_INPUTS)?;
    Ok(SpSpend {
        origin: spspend::spend_origin(kiss_fingerprint(&config.descriptor)?),
        spend: keys.spend,
        coins,
    })
}

/// Where a `create` is being sent.
enum Destination {
    Address(Address),
    SilentPayment(SilentPaymentAddress),
}

impl Destination {
    /// The script BDK selects coins and computes the fee against. A silent
    /// payment's real script is not known until signing, so this is a taproot
    /// placeholder of exactly the size the real one will be.
    fn script_pubkey(&self) -> bdk_wallet::bitcoin::ScriptBuf {
        match self {
            Destination::Address(address) => address.script_pubkey(),
            Destination::SilentPayment(sp) => spsend::placeholder_script(sp),
        }
    }
}

fn parse_destination(destination: &str, chain: Chain) -> Result<Destination> {
    if sp::looks_like_silent_payment(destination) {
        let recipient = sp::decode(destination)?;
        // Every chain this coordinator speaks is a test network, so a mainnet
        // `sp1` address is always the wrong one.
        if recipient.mainnet {
            bail!(
                "that is a mainnet silent payment address; this wallet is on {}",
                chain.label()
            );
        }
        return Ok(Destination::SilentPayment(recipient));
    }
    let unchecked = Address::<NetworkUnchecked>::from_str(destination)
        .context("invalid destination address")?;
    let address = unchecked
        .require_network(chain.network())
        .with_context(|| format!("destination is not valid for {}", chain.label()))?;
    Ok(Destination::Address(address))
}

fn qr_image_path(psbt_path: &Path) -> PathBuf {
    let stem = psbt_path
        .file_stem()
        .filter(|stem| !stem.is_empty())
        .unwrap_or_else(|| std::ffi::OsStr::new("unsigned"));
    let mut name = stem.to_os_string();
    name.push("-qr.png");
    psbt_path.with_file_name(name)
}

fn open_qr_image(path: &Path) {
    #[cfg(target_os = "macos")]
    if ProcessCommand::new("open")
        .arg(path)
        .status()
        .is_ok_and(|status| status.success())
    {
        println!("opened {}", path.display());
        return;
    }
    println!("open {}", path.display());
}

fn scan_psbt(wallet_dir: &Path, out: &Path, original_path: &Path, camera: u32) -> Result<()> {
    if out.exists() {
        bail!("{} already exists; refusing to overwrite it", out.display());
    }
    let original = AnyPsbt::parse(&read_psbt_bytes(original_path)?)?;
    println!("Hold KISS's animated signed QR in front of camera {camera}...");
    let scanned = scan_signed_psbt_bytes(camera)?;
    match (&original, AnyPsbt::parse(&scanned)?) {
        (AnyPsbt::V0(original), AnyPsbt::V0(psbt)) => {
            if psbt.unsigned_tx != original.unsigned_tx {
                bail!(
                    "scanned signed PSBT does not match {}",
                    original_path.display()
                );
            }
        }
        (AnyPsbt::V2(original), AnyPsbt::V2(psbt)) => {
            // A silent payment signer is expected to change the output scripts;
            // verify() allows exactly that and nothing else. A BIP-376 spend
            // pays an ordinary address, so it has no such output and the check
            // that matters is the one broadcast makes on the signature.
            let verified = spverify::verify(original, &psbt)?;
            if verified.is_empty() {
                let signed = psbt
                    .inputs
                    .iter()
                    .filter(|input| input.tap_key_sig.is_some())
                    .count();
                println!("silent payment inputs signed: {signed}");
            } else {
                println!("silent payment outputs verified: {}", verified.len());
            }
        }
        _ => bail!(
            "the scanned PSBT is a different version from {}",
            original_path.display()
        ),
    }
    write_new_file(out, &scanned)?;
    println!("wrote {}", out.display());
    println!(
        "next: kiss-bdk --wallet-dir {} broadcast {} --original {} --dry-run",
        wallet_dir.display(),
        out.display(),
        original_path.display()
    );
    Ok(())
}

fn inspect_psbt(path: &Path) -> Result<()> {
    let psbt = match AnyPsbt::parse(&read_psbt_bytes(path)?)? {
        AnyPsbt::V0(psbt) => psbt,
        AnyPsbt::V2(v2) => {
            // Report the silent payment recipients before flattening to v0,
            // because that is the part a v0 view cannot show.
            println!("version: PSBTv2 (BIP-375 silent payment)");
            for (index, output) in v2.outputs.iter().enumerate() {
                if output.sp_v0_info.is_some() {
                    let state = if output.script_pubkey.is_empty() {
                        "awaiting the signer's derivation"
                    } else {
                        "derived by the signer"
                    };
                    println!("output {index}: silent payment, {state}");
                }
            }
            println!(
                "ECDH shares: {}, DLEQ proofs: {}",
                v2.global.sp_ecdh_shares.len(),
                v2.global.sp_dleq_proofs.len()
            );
            spsend::to_v0(&v2)?
        }
    };
    println!("inputs: {}", psbt.inputs.len());
    println!("outputs: {}", psbt.outputs.len());
    // Every Bitcoin test network shares one address HRP, so this renders the same
    // string for Testnet4, Signet, and Mutinynet. Inspect therefore needs no
    // initialized wallet directory to summarize a bare PSBT.
    print_transaction_summary(&psbt, Network::Testnet4)?;
    let signed = psbt
        .inputs
        .iter()
        .filter(|input| {
            input.final_script_sig.is_some()
                || input.final_script_witness.is_some()
                || !input.partial_sigs.is_empty()
                // A BIP-376 input's signature is schnorr and lives here, so a
                // fully signed silent payment spend read 0/1 without it.
                || input.tap_key_sig.is_some()
        })
        .count();
    println!("inputs carrying signatures: {signed}/{}", psbt.inputs.len());
    Ok(())
}

fn broadcast(wallet_dir: &Path, path: &Path, original_path: &Path, dry_run: bool) -> Result<()> {
    let (config, chain) = load_config(wallet_dir)?;
    let (mut connection, wallet) = open_wallet(wallet_dir, &config, chain)?;
    spstore::migrate(&mut connection)?;
    let signed = AnyPsbt::parse(&read_psbt_bytes(path)?)?;
    let original = AnyPsbt::parse(&read_psbt_bytes(original_path)?)?;

    let mut psbt = match (original, signed) {
        (AnyPsbt::V0(mut original), AnyPsbt::V0(signed)) => {
            original
                .combine(signed)
                .context("signed PSBT does not match the original transaction")?;
            original
        }
        (AnyPsbt::V2(original), AnyPsbt::V2(signed)) => {
            // The coordinator cannot build a silent payment output, so instead
            // of trusting the one it got back it proves the signer derived it
            // from these inputs and that it pays the intended address. A
            // BIP-376 spend has no such output and verifies nothing here; its
            // own check is the signature, below.
            let verified = spverify::verify(&original, &signed)?;
            for output in &verified {
                println!("silent payment output {} verified", output.index);
            }
            if !verified.is_empty() {
                println!("BIP-374 DLEQ proof: verified");
            }
            // Every script is known now, so the rest of the path is unchanged.
            spsend::to_v0(&signed)?
        }
        _ => bail!("the signed PSBT is a different version from the original"),
    };

    // A silent payment is not in BDK's UTXO set and never will be, so an input
    // belongs to this wallet if BDK knows it *or* the silent payment store
    // does. Rebuilding the coins here rather than trusting the PSBT also
    // re-runs the ownership derivation against the currently paired keys.
    let sp_coins = signed_sp_coins(&connection, &psbt)?;
    for txin in &psbt.unsigned_tx.input {
        let known = wallet.get_utxo(txin.previous_output).is_some()
            || sp_coins
                .iter()
                .any(|coin| coin.outpoint == txin.previous_output);
        if !known {
            bail!(
                "input {} is neither a current {} wallet UTXO nor a silent payment this wallet found; run sync and use the original PSBT created by this wallet",
                txin.previous_output,
                chain.label()
            );
        }
    }

    let sp_inputs = spspend::sp_inputs(&psbt, &sp_coins)?;
    verify_psbt_signatures(&psbt, &sp_inputs)?;
    if sp_inputs.is_empty() {
        println!("KISS ECDSA signatures: verified");
    } else {
        println!(
            "KISS signatures: verified ({} silent payment, {} ECDSA)",
            sp_inputs.len(),
            psbt.inputs.len() - sp_inputs.len()
        );
    }
    print_transaction_summary(&psbt, chain.network())?;
    // BDK finalizes through a descriptor and no descriptor matches a silent
    // payment script, so these are turned into witnesses here. Its own
    // finalizer skips an input that already has one, so the two compose.
    spspend::finalize(&mut psbt, &sp_inputs)?;
    if !wallet.finalize_psbt(&mut psbt, SignOptions::default())? {
        bail!("PSBT is not fully signed/finalizable; sign it on KISS first");
    }
    let tx = psbt
        .extract_tx()
        .context("extracting finalized transaction")?;
    let txid = tx.compute_txid();
    if dry_run {
        println!("verified and structurally finalized transaction: {txid}");
        println!(
            "dry run only; {} chain/consensus acceptance happens on broadcast",
            chain.label()
        );
        return Ok(());
    }
    esplora(&config)
        .broadcast(&tx)
        .context("broadcast failed")?;
    println!("broadcast: {txid}");
    Ok(())
}

/// The silent payment coins a signed PSBT spends, rebuilt from the store.
///
/// Deliberately not read from the PSBT's own tweak fields. The tweak names a
/// key, and verifying a signature against the key a returned PSBT asked for
/// would prove only that the signer was self-consistent. These come from the
/// store and are re-derived against the currently paired spend key, so the
/// signature is checked against a key this coordinator worked out for itself.
fn signed_sp_coins(connection: &Connection, psbt: &Psbt) -> Result<Vec<spspend::SpCoin>> {
    let mut mine = Vec::new();
    for txin in &psbt.unsigned_tx.input {
        if !spstore::contains(connection, txin.previous_output)? {
            continue;
        }
        let keys = spstore::keys(connection)?
            .context("this PSBT spends a silent payment but the wallet is not paired")?;
        let stored = spstore::outputs(connection)?
            .into_iter()
            .find(|out| out.outpoint == txin.previous_output)
            .with_context(|| {
                format!(
                    "silent payment {} vanished from the store",
                    txin.previous_output
                )
            })?;
        mine.push(spspend::SpCoin::checked(&stored, &keys.spend)?);
    }
    Ok(mine)
}

fn validate_sd_psbt_path(path: &Path) -> Result<()> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("--out must have a UTF-8 filename")?;
    let lower = name.to_ascii_lowercase();
    if name.len() >= 6
        && name.len() <= KISS_MAX_SD_FILENAME_BYTES
        && lower.ends_with(".psbt")
        && !lower.ends_with("-signed.psbt")
    {
        return Ok(());
    }
    bail!(
        "--out filename must end in .psbt, be at most {KISS_MAX_SD_FILENAME_BYTES} bytes, and not end in -signed.psbt so KISS can list it"
    )
}

/// How large the signed PSBT may come back.
///
/// The two input kinds grow by different amounts, and pricing a taproot input
/// at the ECDSA figure refuses transactions the device would sign happily. An
/// ECDSA input gains a key, a length and a signature with room to spare; a
/// BIP-376 input gains exactly PSBT_IN_TAP_KEY_SIG: two key bytes, one length
/// byte and a 64-byte signature.
fn estimated_signed_psbt_size(
    unsigned_size: usize,
    ecdsa_inputs: usize,
    taproot_inputs: usize,
) -> Result<usize> {
    const TAPROOT_SIG_BYTES: usize = 2 + 1 + 64;
    ecdsa_inputs
        .checked_mul(KISS_MAX_PARTIAL_SIG_BYTES)
        .and_then(|growth| growth.checked_add(taproot_inputs.checked_mul(TAPROOT_SIG_BYTES)?))
        .and_then(|growth| unsigned_size.checked_add(growth))
        .context("PSBT size overflow")
}

fn print_transaction_summary(psbt: &Psbt, network: Network) -> Result<()> {
    println!("unsigned txid: {}", psbt.unsigned_tx.compute_txid());
    for (index, output) in psbt.unsigned_tx.output.iter().enumerate() {
        let destination = Address::from_script(&output.script_pubkey, network)
            .map(|address| address.to_string())
            .unwrap_or_else(|_| "non-address script".to_owned());
        println!(
            "output {index}: {} sats -> {destination}",
            output.value.to_sat()
        );
    }

    let input_sats = (0..psbt.inputs.len()).try_fold(0_u64, |sum, index| {
        let value = psbt
            .get_utxo_for(index)
            .with_context(|| format!("PSBT input {index} is missing its previous output"))?
            .value
            .to_sat();
        sum.checked_add(value).context("input amount overflow")
    })?;
    let output_sats = psbt
        .unsigned_tx
        .output
        .iter()
        .try_fold(0_u64, |sum, output| {
            sum.checked_add(output.value.to_sat())
                .context("output amount overflow")
        })?;
    let fee = input_sats
        .checked_sub(output_sats)
        .context("transaction outputs exceed its inputs")?;
    println!("fee: {fee} sats");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_kiss_visible_sd_filenames() {
        assert!(validate_sd_psbt_path(Path::new("unsigned.psbt")).is_ok());
        assert!(validate_sd_psbt_path(Path::new("UNSIGNED.PSBT")).is_ok());
        assert!(validate_sd_psbt_path(Path::new("unsigned.bin")).is_err());
        assert!(validate_sd_psbt_path(Path::new("unsigned-signed.psbt")).is_err());
        assert!(validate_sd_psbt_path(Path::new(&format!("{}.psbt", "x".repeat(59)))).is_err());
    }

    #[test]
    fn estimates_kiss_signature_growth_conservatively() {
        assert_eq!(estimated_signed_psbt_size(300, 2, 0).unwrap(), 520);
        // A taproot input grows by exactly its 67-byte PSBT_IN_TAP_KEY_SIG,
        // not the ECDSA allowance -- pricing it at the larger figure refuses
        // transactions KISS would sign.
        assert_eq!(estimated_signed_psbt_size(300, 0, 2).unwrap(), 434);
        assert!(estimated_signed_psbt_size(4096, 6, 0).unwrap() > KISS_MAX_SIGNED_PSBT_BYTES);
    }

    #[test]
    fn every_chain_preset_is_a_distinct_test_network_backend() {
        assert_eq!(Chain::Testnet4.network(), Network::Testnet4);
        assert_eq!(Chain::Signet.network(), Network::Signet);
        // Mutinynet is a separate chain that shares signet's address format.
        assert_eq!(Chain::Mutinynet.network(), Network::Signet);
        assert_ne!(
            Chain::Signet.default_esplora(),
            Chain::Mutinynet.default_esplora()
        );
        for chain in [Chain::Testnet4, Chain::Signet, Chain::Mutinynet] {
            assert_ne!(chain.network(), Network::Bitcoin);
            assert!(Chain::from_network(chain.network()).is_some());
        }
    }

    fn write_config(directory: &Path, json: &str) {
        fs::write(directory.join("config.json"), json).unwrap();
    }

    #[test]
    fn loads_wallets_initialized_before_the_chain_field() {
        let directory = tempfile::tempdir().unwrap();
        write_config(
            directory.path(),
            r#"{"network":"testnet4","esplora":"https://example.invalid","descriptor":"d"}"#,
        );
        let (config, chain) = load_config(directory.path()).unwrap();
        assert_eq!(chain, Chain::Testnet4);
        assert_eq!(config.esplora, "https://example.invalid");
    }

    #[test]
    fn rejects_mainnet_and_mismatched_chain_configs() {
        let directory = tempfile::tempdir().unwrap();
        write_config(
            directory.path(),
            r#"{"network":"bitcoin","esplora":"e","descriptor":"d"}"#,
        );
        assert!(load_config(directory.path()).is_err());

        write_config(
            directory.path(),
            r#"{"network":"testnet4","chain":"signet","esplora":"e","descriptor":"d"}"#,
        );
        assert!(load_config(directory.path()).is_err());

        write_config(
            directory.path(),
            r#"{"network":"nonsense","esplora":"e","descriptor":"d"}"#,
        );
        assert!(load_config(directory.path()).is_err());
    }

    #[test]
    fn signet_and_mutinynet_configs_round_trip_through_serde() {
        for chain in [Chain::Testnet4, Chain::Signet, Chain::Mutinynet] {
            let config = Config {
                network: chain.network().to_string(),
                chain: Some(chain),
                esplora: chain.default_esplora().to_owned(),
                descriptor: "d".to_owned(),
            };
            let directory = tempfile::tempdir().unwrap();
            write_config(directory.path(), &serde_json::to_string(&config).unwrap());
            assert_eq!(load_config(directory.path()).unwrap().1, chain);
        }
    }

    #[test]
    fn builds_and_bounds_the_faucet_request() {
        let body = faucet_request_body(10_000, "tb1qexample").unwrap();
        let text = String::from_utf8(body).unwrap();
        assert!(text.contains("\"sats\":10000"), "{text}");
        assert!(text.contains("\"address\":\"tb1qexample\""), "{text}");
        assert!(faucet_request_body(0, "tb1qexample").is_err());
        assert!(faucet_request_body(MUTINYNET_MAX_FAUCET_SATS, "tb1qexample").is_ok());
        assert!(faucet_request_body(MUTINYNET_MAX_FAUCET_SATS + 1, "tb1qexample").is_err());
    }
}
