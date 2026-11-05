//! Set up and test by hand the Marmot group two wallets use for a shared
//! send. Built only with `--features marmot`.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use clap::{Parser, Subcommand};
use kiss_bdk::marmot::{LocalRelay, Marmot};
use kiss_bdk::transport::Transport;

#[derive(Parser)]
#[command(
    name = "kiss-marmot",
    about = "Marmot (MLS over nostr) channel between two kiss-bdk wallets"
)]
struct Cli {
    /// Wallet folder; the Marmot state lives in its marmot/ subfolder.
    #[arg(long, global = true, default_value = "kiss-bdk-wallet")]
    wallet_dir: PathBuf,
    /// Nostr relay to use (repeatable). Saved in the wallet folder; the
    /// saved list is used when none is given.
    #[arg(long = "relay", global = true, value_name = "URL")]
    relays: Vec<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Make the identity, publish a key package and print the npub.
    Init,
    /// Print this wallet's npub.
    Id,
    /// Create the group with the wallet whose npub is given.
    Invite { npub: String },
    /// Join the group another wallet invited this one to.
    Accept {
        /// Seconds to wait for the invitation.
        #[arg(long, default_value_t = 60)]
        wait: u64,
    },
    /// Send one message to the other wallet.
    Send { text: String },
    /// Print messages from the other wallet not printed before.
    Recv {
        /// Seconds to wait when there are none.
        #[arg(long, default_value_t = 30)]
        wait: u64,
    },
    /// Show the identity, relays and group.
    Status,
    /// Run a nostr relay on 127.0.0.1 until stopped, for a demo that must
    /// not depend on the venue network.
    Relay {
        #[arg(long, default_value_t = 7777)]
        port: u16,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if let Command::Relay { port } = cli.command {
        let relay = LocalRelay::start(port)?;
        println!("relay running at {}; stop it with Ctrl-C", relay.url());
        println!("use it with: --relay {}", relay.url());
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
    let mut m = Marmot::open(&cli.wallet_dir, &cli.relays)?;
    match cli.command {
        Command::Init => {
            m.publish_key_package()?;
            println!("{}", m.npub());
        }
        Command::Id => println!("{}", m.npub()),
        Command::Invite { npub } => {
            m.invite(&npub)?;
            println!("group created and invitation sent to {npub}");
        }
        Command::Accept { wait } => match m.accept(Duration::from_secs(wait))? {
            Some(from) => println!("joined the group of {from}"),
            None => anyhow::bail!("no invitation arrived in {wait} seconds"),
        },
        Command::Send { text } => {
            m.send(&text)?;
            println!("sent");
        }
        Command::Recv { wait } => {
            for message in m.receive(Duration::from_secs(wait))? {
                println!("{message}");
            }
        }
        Command::Status => {
            let s = m.status();
            println!("npub:    {}", s.npub);
            println!("relays:  {}", s.relays.join(" "));
            println!("group:   {}", s.group.as_deref().unwrap_or("none yet"));
            println!("peer:    {}", s.peer.as_deref().unwrap_or("none yet"));
            println!("handled: {} group events", s.handled);
        }
        Command::Relay { .. } => unreachable!("handled above"),
    }
    Ok(())
}
