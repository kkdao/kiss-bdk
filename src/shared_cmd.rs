//! The `shared` commands: one silent payment paid by two wallets.
//!
//! `start` and `join` are the whole demo, one long running command per
//! wallet. The other subcommands are the same steps one at a time, with files
//! in and files out, for tests and for finishing a send by hand when the
//! channel or the camera is not there.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use bdk_esplora::esplora_client::BlockingClient;
use bdk_wallet::bitcoin::consensus::encode::serialize_hex;
use bdk_wallet::bitcoin::{Amount, FeeRate, Psbt, Transaction};
use bdk_wallet::coin_selection::LargestFirstCoinSelection;
use clap::Subcommand;
use kiss_bdk::dirtransport::DirTransport;
use kiss_bdk::qr::{render_psbt_bytes_animated_gif, render_psbt_bytes_png, scan_signed_psbt_bytes};
use kiss_bdk::shared::{self, Message, Pass, Received, Role, Session, Stage};
use kiss_bdk::sharedflow::{
    self, DEFAULT_GRACE, Flow, Progress, SignerLink, Store, Terms, Visit, WalletLink,
};
use kiss_bdk::sp::SilentPaymentAddress;
use kiss_bdk::spsend;
use kiss_bdk::transport::Transport;
use kiss_bdk::{kiss_fingerprint, read_psbt_bytes, write_new_file};

use crate::{Chain, Config, Destination, esplora, load_config, open_qr_image, open_wallet};

/// How long one wait on the channel lasts before the loop looks again.
const LISTEN: Duration = Duration::from_secs(2);
/// How many answers in a row from the signer may fail a check before the
/// command gives up.
const SIGNER_TRIES: u32 = 3;

#[derive(Debug, Subcommand)]
pub enum SharedCommand {
    /// Wallet A: propose a shared send and see it through to the broadcast.
    Start {
        /// The recipient's silent payment address (tsp1...).
        #[arg(long)]
        to: String,
        /// What the recipient gets, in satoshis. Each wallet pays half.
        #[arg(long)]
        sats: u64,
        /// Fee rate in whole sat/vB. Defaults to the next block estimate.
        #[arg(long)]
        fee_rate: Option<u64>,
        /// How the two wallets talk: dir:PATH (a shared folder) or marmot.
        #[arg(long)]
        channel: String,
        #[command(flatten)]
        signer: SignerArgs,
    },

    /// Wallet B: wait for a proposal, join it and see it through.
    Join {
        /// How the two wallets talk: dir:PATH (a shared folder) or marmot.
        #[arg(long)]
        channel: String,
        /// Only join a proposal that pays this address.
        #[arg(long)]
        to: Option<String>,
        /// Only join a proposal that pays this many satoshis.
        #[arg(long)]
        sats: Option<u64>,
        #[command(flatten)]
        signer: SignerArgs,
    },

    /// Where this wallet's shared send stands.
    Status,

    /// File step, wallet A: write the proposal message for the other wallet.
    Propose {
        #[arg(long)]
        to: String,
        #[arg(long)]
        sats: u64,
        #[arg(long)]
        fee_rate: Option<u64>,
        /// Write the proposal message here.
        #[arg(long)]
        out: PathBuf,
    },

    /// File step, wallet B: join the proposal in MESSAGE. The other wallet
    /// hears of it with this wallet's first answer.
    Accept {
        #[arg(value_name = "MESSAGE")]
        message: PathBuf,
    },

    /// File step: write the PSBT this wallet's signer is to scan.
    Request {
        /// Write the binary PSBT here.
        #[arg(long)]
        out: PathBuf,
        /// Also show it as a QR.
        #[arg(long)]
        qr: bool,
        /// Show the QR as an animated code in small parts.
        #[arg(long, requires = "qr")]
        animated: bool,
    },

    /// File step: check the signer's answer and keep what it added.
    Answer {
        /// The signer's PSBT (binary or base64). Omit it to read the
        /// signer's QR with the webcam instead.
        #[arg(value_name = "RESPONSE")]
        response: Option<PathBuf>,
        /// Webcam index, when RESPONSE is omitted.
        #[arg(long, default_value_t = 0)]
        camera: u32,
        /// Write the message for the other wallet here.
        #[arg(long)]
        out: PathBuf,
    },

    /// File step: apply the other wallet's messages in MESSAGES.
    Receive {
        /// A file of messages, one JSON object per line.
        #[arg(value_name = "MESSAGES")]
        messages: PathBuf,
        /// Write any message for the other wallet here.
        #[arg(long)]
        out: Option<PathBuf>,
    },

    /// File step: finalize the fully signed transaction and broadcast it.
    Broadcast {
        /// Write the "done" message for the other wallet here.
        #[arg(long)]
        out: PathBuf,
        /// Finalize and print the transaction, but do not send it.
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, clap::Args)]
pub struct SignerArgs {
    /// Webcam index for reading the signer's QR.
    #[arg(long, default_value_t = 0)]
    camera: u32,
    /// Always show the QR as an animated code in small parts.
    #[arg(long)]
    animated: bool,
}

pub fn run(wallet_dir: &Path, command: SharedCommand) -> Result<()> {
    let store = Store::in_wallet(wallet_dir);
    match command {
        SharedCommand::Start {
            to,
            sats,
            fee_rate,
            channel,
            signer,
        } => {
            channel_folder(&channel)?;
            let mut transport = open_channel(&channel, &me(wallet_dir)?, wallet_dir)?;
            let wallet = &mut BdkWallet::open(wallet_dir)?;
            let fee_rate = fee_rate_or_estimate(&wallet.config, fee_rate)?;
            check_recipient(&to, wallet.chain)?;
            let me = me(wallet_dir)?;
            let seed = format!("{me}:{to}:{sats}:{}", now_nanos());
            if sharedflow::begin(&store, wallet, &me, &to, sats, fee_rate, seed.as_bytes())? {
                println!("proposed a shared send of {sats} sats to {to}");
            } else {
                println!("carrying on with the shared send already in this wallet");
            }
            drive(
                &store,
                me,
                transport.as_mut(),
                wallet,
                signer,
                wallet_dir,
                None,
            )
        }
        SharedCommand::Join {
            channel,
            to,
            sats,
            signer,
        } => {
            channel_folder(&channel)?;
            let me = me(wallet_dir)?;
            let mut saved = store.load()?;
            if let Some(session) = saved.unfinished()
                && session.role != Role::Join
            {
                bail!(
                    "this wallet started shared send {}; finish it with shared start, or \
                     delete {} to give it up",
                    session.session,
                    store.path().display()
                );
            }
            store.retire(&mut saved)?;
            let mut transport = open_channel(&channel, &me, wallet_dir)?;
            let wallet = &mut BdkWallet::open(wallet_dir)?;
            if let Some(to) = &to {
                check_recipient(to, wallet.chain)?;
            }
            if saved.session.is_none() {
                println!("waiting for a proposal on {channel}");
            }
            let terms = Terms { to, sats };
            drive(
                &store,
                me,
                transport.as_mut(),
                wallet,
                signer,
                wallet_dir,
                Some(terms),
            )
        }
        SharedCommand::Status => {
            let saved = store.load()?;
            match &saved.session {
                None => println!("no shared send in {}", wallet_dir.display()),
                Some(session) => {
                    for line in session.describe()? {
                        println!("{line}");
                    }
                }
            }
            if !saved.inbox.is_empty() {
                println!(
                    "{} message(s) received and not acted on yet",
                    saved.inbox.len()
                );
            }
            Ok(())
        }
        SharedCommand::Propose {
            to,
            sats,
            fee_rate,
            out,
        } => {
            refuse_existing(&out)?;
            let wallet = &mut BdkWallet::open(wallet_dir)?;
            let fee_rate = fee_rate_or_estimate(&wallet.config, fee_rate)?;
            check_recipient(&to, wallet.chain)?;
            let me = me(wallet_dir)?;
            let seed = format!("{me}:{to}:{sats}:{}", now_nanos());
            if !sharedflow::begin(&store, wallet, &me, &to, sats, fee_rate, seed.as_bytes())? {
                println!("carrying on with the shared send already in this wallet");
            }
            let mut saved = store.load()?;
            let session = saved.session.as_mut().context("no shared send was made")?;
            if session.outbox.is_empty() {
                session.outbox.push(session.proposal_message()?.encode());
            }
            write_outbox(&store, &mut saved, &out)?;
            println!("next: give {} to the other wallet", out.display());
            Ok(())
        }
        SharedCommand::Accept { message } => {
            let mut saved = store.load()?;
            if let Some(session) = saved.unfinished() {
                bail!(
                    "this wallet is already in shared send {}; delete {} to give it up",
                    session.session,
                    store.path().display()
                );
            }
            store.retire(&mut saved)?;
            let text = fs::read_to_string(&message)
                .with_context(|| format!("reading {}", message.display()))?;
            let message = Message::parse(text.trim())?;
            let wallet = &mut BdkWallet::open(wallet_dir)?;
            let session = match sharedflow::join(wallet, &me(wallet_dir)?, &message, None) {
                Ok(session) => session,
                Err(sharedflow::NotJoined::Refused(error)) => {
                    return Err(error.context("refused the proposal"));
                }
                Err(sharedflow::NotJoined::Failed(error)) => {
                    return Err(error.context("building this wallet's half of the shared send"));
                }
            };
            println!(
                "joined shared send {}: {} sats to {}, of which this wallet pays {} plus its \
                 part of the fee",
                session.session,
                session.sats,
                session.to,
                shared::share_of(session.sats, Role::Join)
            );
            saved.session = Some(session);
            store.save(&saved)?;
            println!("next: shared request, for this wallet's signer");
            Ok(())
        }
        SharedCommand::Request { out, qr, animated } => {
            let saved = store.load()?;
            let session = active(&saved.session)?;
            if !session.my_turn()? {
                bail!("it is not this wallet's turn; shared status says what it waits for");
            }
            let request = session.request()?;
            write_new_file(&out, &request)?;
            println!("wrote {}", out.display());
            println!("{}", pass_text(session.pass()?));
            if qr {
                let image = show_qr(&request, &out, animated)?;
                open_qr_image(&image);
            }
            Ok(())
        }
        SharedCommand::Answer {
            response,
            camera,
            out,
        } => {
            refuse_existing(&out)?;
            let answer = match &response {
                Some(path) => read_psbt_bytes(path)?,
                None => {
                    println!("Hold the signer's QR in front of camera {camera}...");
                    scan_signed_psbt_bytes(camera)?
                }
            };
            let mut saved = store.load()?;
            let session = active_mut(&mut saved.session)?;
            for line in session.respond(&answer)? {
                println!("{line}");
            }
            write_outbox(&store, &mut saved, &out)?;
            println!("next: give {} to the other wallet", out.display());
            Ok(())
        }
        SharedCommand::Receive { messages, out } => {
            if let Some(out) = &out {
                refuse_existing(out)?;
            }
            let text = fs::read_to_string(&messages)
                .with_context(|| format!("reading {}", messages.display()))?;
            let mut saved = store.load()?;
            let session = saved
                .session
                .as_mut()
                .context("this wallet has no shared send; join one with shared accept")?;
            for line in text.lines().filter(|line| !line.trim().is_empty()) {
                let message = Message::parse(line.trim())?;
                match session.receive(&message)? {
                    Received::Applied(lines) => {
                        for line in lines {
                            println!("{line}");
                        }
                    }
                    Received::Done(txid) => {
                        println!("the other wallet broadcast the payment: {txid}");
                    }
                    Received::Ignored(reason) => println!("ignored a message: {reason}"),
                }
            }
            match &out {
                Some(out) if !session.outbox.is_empty() => write_outbox(&store, &mut saved, out)?,
                _ => store.save(&saved)?,
            }
            Ok(())
        }
        SharedCommand::Broadcast { out, dry_run } => {
            refuse_existing(&out)?;
            let mut saved = store.load()?;
            let session = active_mut(&mut saved.session)?;
            if !session.ready()? {
                bail!("not every input is signed yet; shared status says what is missing");
            }
            let tx = session.finalize()?;
            let txid = tx.compute_txid();
            if dry_run {
                println!("{}", serialize_hex(&tx));
                println!("dry run: {txid} was not sent");
                return Ok(());
            }
            let wallet = &mut BdkWallet::open(wallet_dir)?;
            wallet.broadcast(&tx)?;
            session.finish(&txid)?;
            write_outbox(&store, &mut saved, &out)?;
            println!("broadcast: {txid}");
            Ok(())
        }
    }
}

/// The long running loop behind `start` and `join`.
fn drive(
    store: &Store,
    me: String,
    transport: &mut dyn Transport,
    wallet: &mut BdkWallet,
    signer: SignerArgs,
    wallet_dir: &Path,
    terms: Option<Terms>,
) -> Result<()> {
    let mut signer = CameraSigner {
        wallet_dir: wallet_dir.to_path_buf(),
        camera: signer.camera,
        animated: signer.animated,
        refusals: 0,
    };
    let mut say = |line: &str| println!("{line}");
    let mut flow = Flow {
        store,
        me,
        transport,
        wallet,
        signer: &mut signer,
        say: &mut say,
        grace: DEFAULT_GRACE,
        terms,
        waited: false,
    };
    let mut waiting_said = false;
    loop {
        match flow.step(LISTEN)? {
            Progress::Waiting => {
                if !waiting_said {
                    println!("waiting for the other wallet...");
                    waiting_said = true;
                }
            }
            Progress::Moved => waiting_said = false,
            Progress::Done(txid) => {
                println!("done: {txid}");
                return Ok(());
            }
        }
    }
}

/// `--channel`: which transport carries the messages.
enum Channel<'a> {
    /// A folder both wallets can write to.
    Dir(&'a str),
    /// The Marmot group set up beforehand with `kiss-marmot`.
    Marmot,
}

/// Checked before anything else is touched, so a channel that cannot work
/// fails at once.
fn channel_folder(channel: &str) -> Result<Channel<'_>> {
    if let Some(path) = channel.strip_prefix("dir:") {
        if path.is_empty() {
            bail!("--channel dir: needs a folder, for example dir:/path/to/folder");
        }
        return Ok(Channel::Dir(path));
    }
    if channel == "marmot" {
        if cfg!(feature = "marmot") {
            return Ok(Channel::Marmot);
        }
        bail!("--channel marmot needs kiss-bdk built with --features marmot");
    }
    bail!("unknown --channel {channel:?}; use dir:PATH or marmot");
}

fn open_channel(channel: &str, me: &str, wallet_dir: &Path) -> Result<Box<dyn Transport>> {
    match channel_folder(channel)? {
        Channel::Dir(path) => Ok(Box::new(DirTransport::open(path, me)?)),
        Channel::Marmot => open_marmot(wallet_dir),
    }
}

#[cfg(feature = "marmot")]
fn open_marmot(wallet_dir: &Path) -> Result<Box<dyn Transport>> {
    let marmot = kiss_bdk::marmot::Marmot::open(wallet_dir, &[])?;
    Ok(Box::new(marmot))
}

#[cfg(not(feature = "marmot"))]
fn open_marmot(_wallet_dir: &Path) -> Result<Box<dyn Transport>> {
    bail!("--channel marmot needs kiss-bdk built with --features marmot")
}

fn me(wallet_dir: &Path) -> Result<String> {
    let (config, _) = load_config(wallet_dir)?;
    Ok(kiss_fingerprint(&config.descriptor)?.to_string())
}

fn check_recipient(to: &str, chain: Chain) -> Result<()> {
    match crate::parse_destination(to, chain)? {
        Destination::SilentPayment(_) => Ok(()),
        Destination::Address(_) => bail!("a shared send pays a silent payment address (tsp1...)"),
    }
}

fn fee_rate_or_estimate(config: &Config, fee_rate: Option<u64>) -> Result<u64> {
    match fee_rate {
        Some(0) => bail!("--fee-rate must be greater than zero"),
        Some(rate) => Ok(rate),
        None => Ok(crate::next_block_fee_rate(&config.esplora).to_sat_per_vb_ceil()),
    }
}

fn now_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos())
}

fn refuse_existing(path: &Path) -> Result<()> {
    if path.exists() {
        bail!(
            "{} already exists; refusing to overwrite it",
            path.display()
        );
    }
    Ok(())
}

fn active(session: &Option<Session>) -> Result<&Session> {
    match session {
        Some(session) if session.stage != Stage::Done => Ok(session),
        Some(_) => bail!("this wallet's shared send is already broadcast"),
        None => bail!("this wallet has no shared send"),
    }
}

fn active_mut(session: &mut Option<Session>) -> Result<&mut Session> {
    match session {
        Some(session) if session.stage != Stage::Done => Ok(session),
        Some(_) => bail!("this wallet's shared send is already broadcast"),
        None => bail!("this wallet has no shared send"),
    }
}

/// Write every waiting message to `out`, one per line, and only then forget
/// them, so a failed write loses nothing.
fn write_outbox(store: &Store, saved: &mut sharedflow::Saved, out: &Path) -> Result<()> {
    let session = saved.session.as_mut().context("no shared send")?;
    let mut text = String::new();
    for message in &session.outbox {
        text.push_str(message);
        text.push('\n');
    }
    write_new_file(out, text.as_bytes())?;
    session.outbox.clear();
    store.save(saved)?;
    println!("wrote {}", out.display());
    Ok(())
}

fn pass_text(pass: Pass) -> &'static str {
    match pass {
        Pass::ShareOnly => {
            "This step only adds your signer's share. Nothing is signed yet; the signer \
             scans the payment a second time to sign it."
        }
        Pass::Sign => "This step reviews and signs the payment on your signer.",
    }
}

/// Render `request` beside `near` as a PNG, or a GIF when one frame is too
/// dense or `animated` asks for it.
fn show_qr(request: &[u8], near: &Path, animated: bool) -> Result<PathBuf> {
    let stem = near
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_else(|| "shared".to_string());
    let (path, bytes) = match render_psbt_bytes_png(request) {
        Ok(png) if !animated => (near.with_file_name(format!("{stem}-qr.png")), png),
        _ => (
            near.with_file_name(format!("{stem}-qr.gif")),
            render_psbt_bytes_animated_gif(request)?,
        ),
    };
    fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// Test only: a desktop signer bridge (contract section 6) to run in place
/// of the QR and the webcam, as a command line split on spaces.
const TEST_SIGNER: &str = "KISS_BDK_TEST_SIGNER";
/// Test only: when set, the long running commands print the finished
/// transaction instead of sending it.
const TEST_NO_BROADCAST: &str = "KISS_BDK_TEST_NO_BROADCAST";

/// Run the bridge in `command` on the request file `request`, the way the
/// tests reach the real signing code without a device.
fn test_signer(command: &str, request: &Path) -> Result<Vec<u8>> {
    let response = request.with_extension("answer.psbt");
    // A run stopped after the bridge answered leaves this behind, and the
    // bridge refuses to write over it.
    if response.exists() {
        fs::remove_file(&response).with_context(|| format!("removing {}", response.display()))?;
    }
    let mut words = command.split(' ').filter(|word| !word.is_empty());
    let program = words
        .next()
        .with_context(|| format!("{TEST_SIGNER} is empty"))?;
    let status = std::process::Command::new(program)
        .args(words)
        .arg(request)
        .arg(&response)
        .status()
        .with_context(|| format!("running {TEST_SIGNER} {command:?}"))?;
    if !status.success() {
        bail!("{TEST_SIGNER} {command:?} failed: {status}");
    }
    fs::read(&response).with_context(|| format!("reading {}", response.display()))
}

/// This wallet's signer, reached by a QR on screen and the webcam.
struct CameraSigner {
    wallet_dir: PathBuf,
    camera: u32,
    animated: bool,
    refusals: u32,
}

impl SignerLink for CameraSigner {
    fn sign(&mut self, request: &[u8], visit: &Visit) -> Result<Vec<u8>> {
        let near = self.wallet_dir.join(format!(
            "shared-{}-visit{}.psbt",
            visit.session, visit.number
        ));
        fs::write(&near, request).with_context(|| format!("writing {}", near.display()))?;
        let image = show_qr(request, &near, self.animated)?;
        println!("your signer's turn (visit {})", visit.number);
        println!("{}", pass_text(visit.pass));
        if let Ok(command) = std::env::var(TEST_SIGNER) {
            return test_signer(&command, &near);
        }
        println!("On the signer: SIGN, then SCAN QR, and scan the QR opened on the computer.");
        open_qr_image(&image);
        println!(
            "Then hold the signer's QR in front of camera {}...",
            self.camera
        );
        scan_signed_psbt_bytes(self.camera)
    }

    fn refused(&mut self, error: &anyhow::Error) -> bool {
        self.refusals += 1;
        eprintln!("the signer's answer was refused: {error:#}");
        if self.refusals < SIGNER_TRIES {
            eprintln!("scan the signer's QR again");
            true
        } else {
            false
        }
    }
}

/// This wallet's coins and its Esplora backend.
struct BdkWallet {
    wallet_dir: PathBuf,
    config: Config,
    chain: Chain,
}

impl BdkWallet {
    fn open(wallet_dir: &Path) -> Result<Self> {
        let (config, chain) = load_config(wallet_dir)?;
        Ok(BdkWallet {
            wallet_dir: wallet_dir.to_path_buf(),
            config,
            chain,
        })
    }

    fn esplora(&self) -> BlockingClient {
        esplora(&self.config)
    }
}

impl WalletLink for BdkWallet {
    fn fund(&mut self, recipient: &SilentPaymentAddress, sats: u64, fee_rate: u64) -> Result<Psbt> {
        let (mut connection, mut wallet) = open_wallet(&self.wallet_dir, &self.config, self.chain)?;
        let fee_rate = FeeRate::from_sat_per_vb(fee_rate).context("fee rate is too large")?;
        // Largest first, as create --qr does: the fewest inputs keep the
        // signer's QR small, and every input carries its previous transaction.
        let mut builder = wallet.build_tx().coin_selection(LargestFirstCoinSelection);
        builder
            .add_recipient(
                spsend::placeholder_script(recipient),
                Amount::from_sat(sats),
            )
            .fee_rate(fee_rate);
        let psbt = builder.finish().context("building this wallet's half")?;
        // finish() reserves a change address; keep it reserved.
        wallet.persist(&mut connection)?;
        Ok(psbt)
    }

    fn broadcast(&mut self, tx: &Transaction) -> Result<()> {
        if std::env::var_os(TEST_NO_BROADCAST).is_some() {
            println!("{}", serialize_hex(tx));
            println!("dry run: {} was not sent", tx.compute_txid());
            return Ok(());
        }
        self.esplora().broadcast(tx).context("broadcast failed")
    }
}
