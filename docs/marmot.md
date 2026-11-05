# Marmot channel for shared sends

In a shared send, two wallets, each with its own airgapped signer, pay
one silent payment together. They pass the transaction in progress back
and forth as one JSON message per step. In the demo that message goes
through a Marmot group: MLS end to end encrypted group messaging carried
by nostr relays, the protocol behind White Noise. kiss-bdk uses MDK, the
Marmot Development Kit, so this is the real protocol, not a look-alike.

All of it is behind the `marmot` cargo feature. The default build has
none of it.

## Build

    cargo build --features marmot

This builds `target/debug/kiss-marmot` next to `kiss-bdk`.

## Set up a group between two wallets

Every command takes `--wallet-dir` (default `kiss-bdk-wallet`, the same
default as kiss-bdk) and `--relay URL`, which can be given more than
once. The relays given are saved in the wallet folder and used from then
on; with none given or saved, the defaults are `wss://relay.damus.io`,
`wss://nos.lol` and `wss://relay.primal.net`. They are White Noise's
defaults, so they are known to carry the Marmot event kinds.

On wallet B (the one being invited):

    kiss-marmot --wallet-dir walletB init

This makes the nostr identity, publishes a key package and prints B's
npub. Give that npub to wallet A.

On wallet A:

    kiss-marmot --wallet-dir walletA init
    kiss-marmot --wallet-dir walletA invite npub1...B

On wallet B:

    kiss-marmot --wallet-dir walletB accept

It prints the npub of the wallet that invited it. Check that it is A.
`accept` takes the newest invitation addressed to this wallet.

Exchange a message:

    kiss-marmot --wallet-dir walletA send "hello"
    kiss-marmot --wallet-dir walletB recv --wait 30
    kiss-marmot --wallet-dir walletB send "hello back"
    kiss-marmot --wallet-dir walletA recv --wait 30

`recv` prints only messages it has not printed before, oldest first.
`id` prints the npub, `status` shows the npub, relays, group and peer.

## Without the venue network

    kiss-marmot relay --port 7777

runs a nostr relay on 127.0.0.1 that keeps events in memory until it is
stopped. Then give every command `--relay ws://127.0.0.1:7777`. It only
listens on this computer, so both wallets must run here.

## From code

`kiss_bdk::marmot::Marmot` implements `kiss_bdk::transport::Transport`:

    let mut channel = Marmot::open(wallet_dir, &[])?; // saved relays
    channel.send(&json)?;
    let messages = channel.receive(Duration::from_secs(30))?;

The group must have been set up first (with the commands above, or with
`publish_key_package`, `invite` and `accept`).

## What is stored where

Everything is in `<wallet dir>/marmot/` (the folder is mode 0700):

- `identity.key`: the nostr secret key, hex, mode 0600. Whoever has it
  can act as this wallet in the group.
- `mls.json`: the MLS group state, the key package private keys and the
  group's message keys, mode 0600, rewritten after every step that
  changes them. MDK's SQLite store cannot be used next to bdk_wallet
  (they need different rusqlite versions), so this file takes its place.
  It is not encrypted: anyone who can read it can read this group's
  messages, including old ones captured from a relay.
- `state.json`: relays, group id, the other member's npub, the list of
  group events already handled (so a restart never returns a message
  twice) and the send counter.

Delete the `marmot` folder to start over with a new identity.

## What a relay sees, and what it does not

A relay sees:

- the key package (kinds 30443 and 443) and key package relay list (kind
  10051) of each wallet, signed by its npub. These are public: anyone can
  see that this npub can be invited to Marmot groups.
- the invitation as a NIP-59 gift wrap (kind 1059) addressed to the
  invited npub. The sender is hidden behind a throwaway key and the time
  is randomised, but the relay sees that this npub was sent something.
- each group message (kind 445): signed by a fresh throwaway key, tagged
  with the group's nostr id, with its size and the time it was sent.
- the network addresses that connect to it, and when. Two wallets that
  post to the same group from the same address are easy to link.

A relay cannot read any message, cannot tell which npub sent a group
message, and cannot tell which npubs are in the group from the group
messages alone.

The messages carry the bitcoin transaction in progress: the inputs each
wallet brings, the outputs, the amounts, the silent payment address and
the per input ECDH shares. Only the two members can read them. Once the
transaction is broadcast its inputs and outputs are public anyway. What
stays private is that the inputs belong to two different wallets and
which npubs took part, unless the relay's view of addresses and timing
gives it away.

## Limits

- One group with one other member per wallet folder.
- The key package used to join is not rotated and no self update is made
  after joining, which Marmot recommends.
- The MLS state is written after each step; a crash in the moment
  between decrypting a message and returning it can lose that one
  message. The shared send resends its full state, so it recovers.
- When two commits race, MDK rolls the group back to a snapshot; that
  snapshot does not cover the MLS half of the saved state. With two
  members and no commits after the group is made this does not happen.
