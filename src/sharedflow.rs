//! A shared send as it actually runs: the session file, the channel to the
//! other wallet, this wallet's coins and its signer.
//!
//! [`shared`](crate::shared) decides what is true. This module only moves
//! things: it loads the session, asks `shared` what comes next, and calls
//! whichever of the four outside parties that step needs. Each of them sits
//! behind a small trait, so the same loop serves the command line (a QR and a
//! webcam, Esplora, a channel folder) and a test (a signer in Rust, a list of
//! broadcasts).
//!
//! Everything is saved before it is acted on. A message handed over by the
//! channel is written into the session file first, and a message for the
//! other wallet stays in the file until it has been sent, so a command that is
//! stopped at any point picks up where it was. The price is that a message
//! may be sent twice, which the other side has to tolerate anyway.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use bdk_wallet::bitcoin::{Psbt, Transaction};
use serde::{Deserialize, Serialize};

use crate::shared::{self, Kind, Message, Pass, Received, Role, Session, Stage};
use crate::sp::{self, SilentPaymentAddress};
use crate::transport::Transport;

/// The session file's name inside the wallet folder.
pub const SESSION_FILE: &str = "shared-send.json";

/// How long the side that did not make the last signature waits for the
/// other side's "done" before it broadcasts the same transaction itself.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(20);

/// What the session file holds.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Saved {
    /// Messages the channel handed over that have not been acted on yet.
    #[serde(default)]
    pub inbox: Vec<String>,
    /// The shared send this wallet is part of, if any.
    #[serde(default)]
    pub session: Option<Session>,
}

impl Saved {
    /// The session, unless it is already broadcast.
    pub fn unfinished(&self) -> Option<&Session> {
        self.session
            .as_ref()
            .filter(|session| session.stage != Stage::Done)
    }
}

/// The session file in one wallet folder.
pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn in_wallet(wallet_dir: &Path) -> Self {
        Store {
            path: wallet_dir.join(SESSION_FILE),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read the file. A wallet that never took part in a shared send has
    /// none, which reads as empty.
    pub fn load(&self) -> Result<Saved> {
        match fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| {
                format!("{} is not a shared send session file", self.path.display())
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Saved::default()),
            Err(error) => Err(error).with_context(|| format!("reading {}", self.path.display())),
        }
    }

    /// Replace the file in one step, so a crash leaves the old one or the new
    /// one and never half of either.
    pub fn save(&self, saved: &Saved) -> Result<()> {
        write_replacing(&self.path, &serde_json::to_vec_pretty(saved)?)
    }

    /// Move a broadcast session out of the way of a new one.
    ///
    /// It is kept beside the session file under its own name rather than
    /// dropped: it is the only record of which transaction that send became.
    pub fn retire(&self, saved: &mut Saved) -> Result<Option<PathBuf>> {
        let Some(session) = saved
            .session
            .take_if(|session| session.stage == Stage::Done)
        else {
            return Ok(None);
        };
        let kept = self
            .path
            .with_file_name(format!("shared-send-{}.json", session.session));
        let record = Saved {
            inbox: Vec::new(),
            session: Some(session),
        };
        write_replacing(&kept, &serde_json::to_vec_pretty(&record)?)?;
        self.save(saved)?;
        Ok(Some(kept))
    }
}

fn write_replacing(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating a temporary file beside {}", path.display()))?;
    temp.write_all(bytes)
        .and_then(|()| temp.as_file().sync_all())
        .with_context(|| format!("writing {}", path.display()))?;
    temp.persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("replacing {}", path.display()))?;
    Ok(())
}

/// This wallet's signing device, however it is reached.
pub trait SignerLink {
    /// Show `request` to the signer and bring back its answer.
    fn sign(&mut self, request: &[u8], visit: &Visit) -> Result<Vec<u8>>;

    /// Called when an answer failed a check. Return `true` to ask the signer
    /// again with the same request, `false` to give up with that error.
    fn refused(&mut self, _error: &anyhow::Error) -> bool {
        false
    }
}

/// What a shared send needs from the wallet and its backend.
pub trait WalletLink {
    /// Build this wallet's half: an ordinary transaction that pays `sats` to
    /// the recipient's placeholder script at `fee_rate` sat/vB, with every
    /// coin carrying its previous transaction.
    fn fund(&mut self, recipient: &SilentPaymentAddress, sats: u64, fee_rate: u64) -> Result<Psbt>;

    /// Send the finished transaction to the network.
    fn broadcast(&mut self, tx: &Transaction) -> Result<()>;
}

/// One trip to the signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Visit {
    pub session: String,
    /// 1 for this wallet's first trip, 2 for its second.
    pub number: u32,
    /// Whether the signer can only add its share, or will sign.
    pub pass: Pass,
}

/// What wallet B insists a proposal says before it joins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Terms {
    pub to: Option<String>,
    pub sats: Option<u64>,
}

impl Terms {
    fn refuse(&self, proposal: &shared::Proposal) -> Result<()> {
        if let Some(to) = &self.to
            && sp::decode(to)? != proposal.recipient
        {
            bail!(
                "it pays {}, not the address this wallet expects",
                proposal.to
            );
        }
        if let Some(sats) = self.sats
            && sats != proposal.sats
        {
            bail!(
                "it pays {} sats, not the {sats} this wallet expects",
                proposal.sats
            );
        }
        Ok(())
    }
}

/// Why a proposal was not joined.
pub enum NotJoined {
    /// The proposal failed a check. Nothing is wrong on this side.
    Refused(anyhow::Error),
    /// This wallet could not do its part, for example for lack of coins.
    Failed(anyhow::Error),
}

/// Wallet A: start a shared send, leaving the proposal in the outbox.
///
/// A wallet folder holds one shared send at a time. An unfinished one with
/// the same recipient and amount is simply carried on, so running the same
/// command again is how it resumes. Returns `true` when a new one was made.
///
/// `fee_rate` is asked only when a new send is made. A resumed one already
/// has its rate, agreed with the other wallet, and a fresh estimate could
/// only stop it: a backend asking for more than it may name would make the
/// send that is half done impossible to finish.
pub fn begin(
    store: &Store,
    wallet: &mut dyn WalletLink,
    me: &str,
    to: &str,
    sats: u64,
    fee_rate: impl FnOnce() -> Result<u64>,
    seed: &[u8],
) -> Result<bool> {
    let mut saved = store.load()?;
    if let Some(session) = saved.unfinished() {
        let same = session.role == Role::Start
            && session.sats == sats
            && sp::decode(&session.to)? == sp::decode(to)?;
        if same {
            return Ok(false);
        }
        bail!(
            "this wallet is already in shared send {} ({} sats to {}); finish that one \
             first, or delete {} to give it up",
            session.session,
            session.sats,
            session.to,
            store.path().display()
        );
    }
    store.retire(&mut saved)?;

    let recipient = sp::decode(to)?;
    shared::check_amount(sats)?;
    let fee_rate = fee_rate()?;
    let half = wallet.fund(&recipient, shared::share_of(sats, Role::Start), fee_rate)?;
    let session = Session::propose(me, &shared::session_id(seed), &half, to, sats, fee_rate)?;
    saved.session = Some(session);
    store.save(&saved)?;
    Ok(true)
}

/// Wallet B: check a proposal, add this wallet's half, and return the session.
pub fn join(
    wallet: &mut dyn WalletLink,
    me: &str,
    message: &Message,
    terms: Option<&Terms>,
) -> std::result::Result<Session, NotJoined> {
    let proposal = shared::read_proposal(message, me).map_err(NotJoined::Refused)?;
    if let Some(terms) = terms {
        terms.refuse(&proposal).map_err(NotJoined::Refused)?;
    }
    let half = wallet
        .fund(
            &proposal.recipient,
            shared::share_of(proposal.sats, Role::Join),
            proposal.fee_rate,
        )
        .map_err(NotJoined::Failed)?;
    Session::join(me, &proposal, &half).map_err(NotJoined::Refused)
}

/// How one call to [`Flow::step`] ended.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Progress {
    /// Nothing arrived in the time allowed. Call again.
    Waiting,
    /// Something happened. Call again.
    Moved,
    /// The transaction with this id is broadcast and the other wallet has
    /// been told. There is nothing left to do.
    Done(String),
}

/// One wallet's side of a shared send, driven a step at a time.
pub struct Flow<'a> {
    pub store: &'a Store,
    /// This wallet's master fingerprint.
    pub me: String,
    pub transport: &'a mut dyn Transport,
    pub wallet: &'a mut dyn WalletLink,
    pub signer: &'a mut dyn SignerLink,
    /// Where progress is reported, one line at a time.
    pub say: &'a mut dyn FnMut(&str),
    /// See [`DEFAULT_GRACE`].
    pub grace: Duration,
    /// What a proposal must say for this wallet to join it.
    pub terms: Option<Terms>,
    /// Whether the grace period was already spent in this run.
    pub waited: bool,
}

impl Flow<'_> {
    /// Do the one next thing, waiting up to `wait` if that thing is to listen.
    pub fn step(&mut self, wait: Duration) -> Result<Progress> {
        let mut saved = self.store.load()?;

        // What is owed to the other wallet goes out before anything else.
        if let Some(session) = saved.session.as_mut()
            && !session.outbox.is_empty()
        {
            for message in &session.outbox {
                self.transport.send(message)?;
            }
            session.outbox.clear();
            self.store.save(&saved)?;
            return Ok(Progress::Moved);
        }

        // Then what the channel already handed over.
        if !saved.inbox.is_empty() {
            let next = self.next_in_inbox(&saved);
            let text = saved.inbox[next].clone();
            self.handle(&mut saved, &text)?;
            saved.inbox.remove(next);
            self.store.save(&saved)?;
            return Ok(Progress::Moved);
        }

        if let Some(session) = saved.session.as_mut() {
            if session.stage == Stage::Done {
                return Ok(Progress::Done(session.txid.clone().unwrap_or_default()));
            }
            if session.ready()? {
                if session.newest == shared::Newest::Theirs && !self.waited {
                    // The other signer made the last signature, so the other
                    // wallet is about to broadcast. Give its news a moment
                    // rather than send the same transaction a second time.
                    self.waited = true;
                    return self.listen(saved, self.grace);
                }
                let tx = session.finalize()?;
                let txid = tx.compute_txid();
                self.wallet.broadcast(&tx)?;
                session.finish(&txid)?;
                self.store.save(&saved)?;
                (self.say)(&format!("broadcast: {txid}"));
                return Ok(Progress::Moved);
            }
            if session.my_turn()? {
                let request = session.request()?;
                let visit = Visit {
                    session: session.session.clone(),
                    number: session.visits + 1,
                    pass: session.pass()?,
                };
                loop {
                    let answer = self.signer.sign(&request, &visit)?;
                    match session.respond(&answer) {
                        Ok(lines) => {
                            for line in lines {
                                (self.say)(&line);
                            }
                            break;
                        }
                        Err(error) => {
                            if !self.signer.refused(&error) {
                                return Err(error);
                            }
                        }
                    }
                }
                self.store.save(&saved)?;
                return Ok(Progress::Moved);
            }
        }
        self.listen(saved, wait)
    }

    /// Ask the channel for news and put it in the session file.
    fn listen(&mut self, mut saved: Saved, wait: Duration) -> Result<Progress> {
        let batch = self.transport.receive(wait)?;
        if batch.is_empty() {
            return Ok(Progress::Waiting);
        }
        saved.inbox.extend(batch);
        self.store.save(&saved)?;
        Ok(Progress::Moved)
    }

    /// Which waiting message to act on. Oldest first, except that a wallet
    /// with no shared send yet takes the newest proposal: an older one is
    /// more likely to be left over from a send that was given up.
    fn next_in_inbox(&self, saved: &Saved) -> usize {
        if saved.session.is_some() {
            return 0;
        }
        saved
            .inbox
            .iter()
            .rposition(|text| {
                Message::parse(text).is_ok_and(|message| message.kind == Kind::Proposal)
            })
            .unwrap_or(0)
    }

    /// Act on one message. An error means trouble on this side; a message
    /// that fails a check is reported and dropped, and the send goes on.
    fn handle(&mut self, saved: &mut Saved, text: &str) -> Result<()> {
        let message = match Message::parse(text) {
            Ok(message) => message,
            Err(error) => {
                (self.say)(&format!("ignored a message on the channel: {error:#}"));
                return Ok(());
            }
        };
        let Some(session) = saved.session.as_mut() else {
            return self.consider(saved, &message);
        };
        match session.receive(&message) {
            Ok(Received::Applied(lines)) => {
                for line in lines {
                    (self.say)(&line);
                }
            }
            Ok(Received::Done(txid)) => {
                (self.say)(&format!("the other wallet broadcast the payment: {txid}"));
            }
            Ok(Received::Ignored(reason)) => {
                (self.say)(&format!(
                    "ignored a message from {}: {reason}",
                    message.from
                ));
            }
            Err(error) => {
                (self.say)(&format!(
                    "refused a message from {}: {error:#}",
                    message.from
                ));
            }
        }
        Ok(())
    }

    /// A message while this wallet has no shared send: join it if it is a
    /// proposal that passes.
    fn consider(&mut self, saved: &mut Saved, message: &Message) -> Result<()> {
        if message.kind != Kind::Proposal {
            (self.say)(&format!(
                "ignored a message from {}: it is for a shared send this wallet is not part of",
                message.from
            ));
            return Ok(());
        }
        match join(self.wallet, &self.me, message, self.terms.as_ref()) {
            Ok(session) => {
                (self.say)(&format!(
                    "joined shared send {}: {} sats to {}, of which this wallet pays {} plus \
                     its part of the fee",
                    session.session,
                    session.sats,
                    session.to,
                    shared::share_of(session.sats, Role::Join)
                ));
                saved.session = Some(session);
                Ok(())
            }
            Err(NotJoined::Refused(error)) => {
                (self.say)(&format!(
                    "refused a proposal from {}: {error:#}",
                    message.from
                ));
                Ok(())
            }
            Err(NotJoined::Failed(error)) => {
                Err(error.context("building this wallet's half of the shared send"))
            }
        }
    }
}
