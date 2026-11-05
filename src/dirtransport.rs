//! A [`Transport`] that is a folder on disk.
//!
//! Every message is one file, so two coordinators sharing a folder (the same
//! machine in a test, a synced folder otherwise) can talk without a network,
//! and a person can read what was said with `ls` and `cat`. It is what
//! `--channel dir:PATH` uses.
//!
//! A message file is named `<time>-<sender>-<number>.msg`:
//!
//! * `number` counts that sender's messages from 1. A receiver hands a
//!   sender's messages over strictly in that order and never skips one, so a
//!   file that has not arrived yet holds back the ones after it instead of
//!   being lost.
//! * `time` is milliseconds since 1970 and only orders messages of different
//!   senders against each other. A sender never reuses or goes below its own
//!   last value, so sorting by name also keeps each sender's own order.
//!
//! What a participant has already been handed is recorded in
//! `cursor-<participant>.json` in the same folder, written before the
//! messages are returned. A restarted command therefore does not see them
//! again, and a caller that must not lose one has to store what it received
//! before acting on it.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

use crate::transport::Transport;

const MESSAGE_EXTENSION: &str = "msg";
/// How often a waiting `receive` looks at the folder again.
const POLL: Duration = Duration::from_millis(100);
/// Two processes sending under one name race for the same number; the loser
/// takes the next one. More collisions than this is not a race.
const SEND_ATTEMPTS: u32 = 16;

/// One participant's view of a channel folder.
pub struct DirTransport {
    dir: PathBuf,
    me: String,
}

/// A message file's name, taken apart.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Entry {
    time: u64,
    sender: String,
    number: u64,
    path: PathBuf,
}

impl DirTransport {
    /// Open `dir` as `participant`, creating the folder when it is missing.
    ///
    /// The name ends up inside file names, so it is limited to letters,
    /// digits and underscores. A wallet's master fingerprint fits.
    pub fn open(dir: impl AsRef<Path>, participant: &str) -> Result<Self> {
        if participant.is_empty()
            || !participant
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            bail!(
                "channel participant name {participant:?} must be letters, digits or underscores"
            );
        }
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)
            .with_context(|| format!("creating the channel folder {}", dir.display()))?;
        Ok(DirTransport {
            dir,
            me: participant.to_owned(),
        })
    }

    fn cursor_path(&self) -> PathBuf {
        self.dir.join(format!("cursor-{}.json", self.me))
    }

    /// The next message number expected from each sender.
    fn cursor(&self) -> Result<BTreeMap<String, u64>> {
        let path = self.cursor_path();
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("{} is not a channel cursor", path.display())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
        }
    }

    fn save_cursor(&self, cursor: &BTreeMap<String, u64>) -> Result<()> {
        let path = self.cursor_path();
        let mut temp = tempfile::NamedTempFile::new_in(&self.dir)
            .with_context(|| format!("creating a temporary file in {}", self.dir.display()))?;
        temp.write_all(&serde_json::to_vec(cursor)?)
            .and_then(|()| temp.as_file().sync_all())
            .with_context(|| format!("writing {}", path.display()))?;
        temp.persist(&path)
            .map_err(|error| error.error)
            .with_context(|| format!("replacing {}", path.display()))?;
        Ok(())
    }

    /// Every message file in the folder, oldest first.
    fn entries(&self) -> Result<Vec<Entry>> {
        let mut entries = Vec::new();
        let listing = fs::read_dir(&self.dir)
            .with_context(|| format!("listing the channel folder {}", self.dir.display()))?;
        for item in listing {
            let path = item
                .with_context(|| format!("listing the channel folder {}", self.dir.display()))?
                .path();
            if let Some(entry) = parse_name(&path) {
                entries.push(entry);
            }
        }
        entries.sort();
        Ok(entries)
    }

    /// The messages not handed over yet, with the cursor that follows them.
    fn pending(&self) -> Result<(Vec<Entry>, BTreeMap<String, u64>)> {
        let mut cursor = self.cursor()?;
        let mut ready = Vec::new();
        // Sorted by name, which keeps every sender's own numbers ascending.
        for entry in self.entries()? {
            if entry.sender == self.me {
                continue;
            }
            let expected = cursor.entry(entry.sender.clone()).or_insert(1);
            if entry.number == *expected {
                *expected += 1;
                ready.push(entry);
            }
        }
        Ok((ready, cursor))
    }
}

impl Transport for DirTransport {
    fn send(&mut self, message: &str) -> Result<()> {
        let mine: Vec<Entry> = self
            .entries()?
            .into_iter()
            .filter(|entry| entry.sender == self.me)
            .collect();
        let last_time = mine.iter().map(|entry| entry.time).max();
        let mut number = mine.iter().map(|entry| entry.number).max().unwrap_or(0) + 1;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("the system clock is before 1970")?
            .as_millis() as u64;
        // Never below this sender's last message, whatever the clock did.
        let time = last_time.map_or(now, |last| now.max(last + 1));

        for _ in 0..SEND_ATTEMPTS {
            let path = self.dir.join(format!(
                "{time:014}-{}-{number:06}.{MESSAGE_EXTENSION}",
                self.me
            ));
            // Written beside its final name and moved into place, so a reader
            // never sees half a message; refusing to replace a file is what
            // tells two senders with one name apart.
            let mut temp = tempfile::NamedTempFile::new_in(&self.dir)
                .with_context(|| format!("creating a temporary file in {}", self.dir.display()))?;
            temp.write_all(message.as_bytes())
                .and_then(|()| temp.as_file().sync_all())
                .with_context(|| format!("writing {}", path.display()))?;
            match temp.persist_noclobber(&path) {
                Ok(_) => return Ok(()),
                Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                    number += 1;
                }
                Err(error) => {
                    return Err(error.error)
                        .with_context(|| format!("creating {}", path.display()));
                }
            }
        }
        bail!(
            "could not find a free message number for {} in {}",
            self.me,
            self.dir.display()
        )
    }

    fn receive(&mut self, wait: Duration) -> Result<Vec<String>> {
        let deadline = Instant::now() + wait;
        loop {
            let (ready, cursor) = self.pending()?;
            if !ready.is_empty() {
                let mut messages = Vec::with_capacity(ready.len());
                for entry in &ready {
                    let bytes = fs::read(&entry.path)
                        .with_context(|| format!("reading {}", entry.path.display()))?;
                    let text = String::from_utf8(bytes)
                        .with_context(|| format!("{} is not UTF-8", entry.path.display()))?;
                    messages.push(text);
                }
                self.save_cursor(&cursor)?;
                return Ok(messages);
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(Vec::new());
            }
            thread::sleep(POLL.min(deadline - now));
        }
    }
}

/// `<time>-<sender>-<number>.msg`, or `None` for any other file.
fn parse_name(path: &Path) -> Option<Entry> {
    if path.extension()?.to_str()? != MESSAGE_EXTENSION {
        return None;
    }
    let stem = path.file_stem()?.to_str()?;
    let mut parts = stem.split('-');
    let time = parts.next()?.parse().ok()?;
    let sender = parts.next()?;
    let number = parts.next()?.parse().ok()?;
    if parts.next().is_some() || sender.is_empty() {
        return None;
    }
    Some(Entry {
        time,
        sender: sender.to_owned(),
        number,
        path: path.to_path_buf(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_only_its_own_kind_of_file_name() {
        let entry = parse_name(Path::new("/x/00001700000000-73c5da0a-000002.msg")).unwrap();
        assert_eq!(entry.time, 1_700_000_000);
        assert_eq!(entry.sender, "73c5da0a");
        assert_eq!(entry.number, 2);

        for other in [
            "/x/cursor-73c5da0a.json",
            "/x/.tmpAbCd",
            "/x/00001700000000-73c5da0a.msg",
            "/x/00001700000000-73c5da0a-2-extra.msg",
            "/x/time-73c5da0a-000002.msg",
            "/x/00001700000000--000002.msg",
        ] {
            assert!(parse_name(Path::new(other)).is_none(), "{other}");
        }
    }

    #[test]
    fn sorts_by_time_and_keeps_a_senders_numbers_ascending() {
        let mut entries = [
            parse_name(Path::new("/x/00000000000300-b-000001.msg")).unwrap(),
            parse_name(Path::new("/x/00000000000200-a-000002.msg")).unwrap(),
            parse_name(Path::new("/x/00000000000100-a-000001.msg")).unwrap(),
        ];
        entries.sort();
        let order: Vec<(&str, u64)> = entries
            .iter()
            .map(|entry| (entry.sender.as_str(), entry.number))
            .collect();
        assert_eq!(order, [("a", 1), ("a", 2), ("b", 1)]);
    }

    #[test]
    fn refuses_a_participant_name_that_cannot_be_a_file_name() {
        for bad in ["", "a-b", "a/b", "a b", "a.b"] {
            assert!(DirTransport::open(".", bad).is_err(), "{bad:?}");
        }
    }
}
