//! How the wallets taking part in one shared send talk to each other.
//!
//! The coordinator logic only ever sees this trait, so a test can use a
//! folder on disk and the demo can use a Marmot group without either
//! knowing about the other.

use std::time::Duration;

use anyhow::Result;

/// A message channel between the wallets taking part in one shared send.
///
/// Messages are opaque UTF-8 strings (the shared send puts JSON in them).
/// Delivery is at least once and in order per sender, so a receiver must
/// tolerate a duplicate.
pub trait Transport {
    /// Deliver one message to every other participant.
    fn send(&mut self, message: &str) -> Result<()>;

    /// Messages from other participants that this instance has not returned
    /// before, oldest first. Waits up to `wait` when there are none; an empty
    /// list means nothing arrived in that time.
    fn receive(&mut self, wait: Duration) -> Result<Vec<String>>;
}
