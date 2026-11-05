//! The desktop test bridges of the two real signers.
//!
//! Each signer has a small program that runs its real signing code with a
//! test seed, so the coordinator can be tested against both without a device:
//!
//! ```text
//! bridge --descriptor                     print the signer's descriptor
//! bridge <request.psbt> <response.psbt>   sign; the response must not exist
//! ```
//!
//! The last line on stdout is `SHARE` (own shares added, nothing signed) or
//! `SIGNED`. Exit code 0 is success, 3 a refusal with the reason on stderr,
//! 2 anything else. These only run when a test is given the bridge to use.

#![allow(dead_code)]

use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

/// The seed each bridge uses when none is given. They differ on purpose: with
/// one seed on both sides every input is the signer's own and the single
/// signer path runs instead.
const KISS_MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
                             abandon abandon abandon about";
const KRUX_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner \
                             thank yellow";

pub struct Bridge {
    pub name: &'static str,
    program: OsString,
    arguments: Vec<OsString>,
    mnemonic: &'static str,
    /// The KISS bridge keeps its simulator state in `KISS_SIM_TMP`, which
    /// must be a fresh empty directory for every call.
    needs_scratch: bool,
}

/// What one call to a bridge did.
#[derive(Debug)]
pub struct Answer {
    pub code: Option<i32>,
    /// The last line on stdout: `SHARE` or `SIGNED` on success.
    pub last_line: String,
    pub stderr: String,
    /// The response file, when one was written.
    pub response: Option<Vec<u8>>,
}

impl Bridge {
    /// The KISS-signer bridge: `KISS_INTEROP_SIGNER` is the path to the binary.
    pub fn kiss() -> Self {
        let program = std::env::var_os("KISS_INTEROP_SIGNER")
            .expect("set KISS_INTEROP_SIGNER to the KISS bridge binary");
        Bridge {
            name: "KISS",
            program,
            arguments: Vec::new(),
            mnemonic: KISS_MNEMONIC,
            needs_scratch: true,
        }
    }

    /// The Krux bridge: `KRUX_INTEROP_SIGNER` is a whole command line, split
    /// on spaces.
    pub fn krux() -> Self {
        let line = std::env::var("KRUX_INTEROP_SIGNER")
            .expect("set KRUX_INTEROP_SIGNER to the Krux bridge command line");
        let mut words = line.split(' ').filter(|word| !word.is_empty());
        let program = words
            .next()
            .expect("KRUX_INTEROP_SIGNER names no program")
            .into();
        Bridge {
            name: "Krux",
            program,
            arguments: words.map(OsString::from).collect(),
            mnemonic: KRUX_MNEMONIC,
            needs_scratch: false,
        }
    }

    fn command(&self, scratch: &Path) -> Command {
        let mut command = Command::new(&self.program);
        command
            .args(&self.arguments)
            .env("SP_BRIDGE_MNEMONIC", self.mnemonic);
        if self.needs_scratch {
            let simulator = scratch.join("sim");
            std::fs::create_dir(&simulator).unwrap();
            command.env("KISS_SIM_TMP", simulator);
        }
        command
    }

    /// The signer's native segwit testnet descriptor.
    pub fn descriptor(&self) -> String {
        let scratch = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let output = self
            .command(scratch.path())
            .arg("--descriptor")
            .output()
            .unwrap_or_else(|error| panic!("running the {} bridge: {error}", self.name));
        assert_eq!(
            output.status.code(),
            Some(0),
            "{} bridge --descriptor: {}",
            self.name,
            String::from_utf8_lossy(&output.stderr)
        );
        last_line(&output.stdout)
    }

    /// A shell script in `dir` that runs this bridge with its seed, for a
    /// program that only takes a command line, such as `kiss-bdk` under
    /// `KISS_BDK_TEST_SIGNER`. Each run of the KISS bridge gets its own
    /// fresh `KISS_SIM_TMP`.
    pub fn script(&self, dir: &Path) -> std::path::PathBuf {
        let quote = |text: &std::ffi::OsStr| format!("'{}'", text.to_string_lossy());
        let mut line = quote(&self.program);
        for argument in &self.arguments {
            line.push(' ');
            line.push_str(&quote(argument));
        }
        let scratch = if self.needs_scratch {
            format!(
                "KISS_SIM_TMP=$(mktemp -d '{}/sim.XXXXXX') || exit 2\nexport KISS_SIM_TMP\n",
                dir.display()
            )
        } else {
            String::new()
        };
        let text = format!(
            "#!/bin/sh\nSP_BRIDGE_MNEMONIC='{}'\nexport SP_BRIDGE_MNEMONIC\n{scratch}exec {line} \"$@\"\n",
            self.mnemonic
        );
        let path = dir.join(format!("{}-bridge.sh", self.name.to_lowercase()));
        std::fs::write(&path, text).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        path
    }

    /// Hand the signer one request.
    pub fn run(&self, request: &[u8]) -> Answer {
        let scratch = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let request_path = scratch.path().join("request.psbt");
        let response_path = scratch.path().join("response.psbt");
        std::fs::write(&request_path, request).unwrap();
        let output = self
            .command(scratch.path())
            .arg(&request_path)
            .arg(&response_path)
            .output()
            .unwrap_or_else(|error| panic!("running the {} bridge: {error}", self.name));
        Answer {
            code: output.status.code(),
            last_line: last_line(&output.stdout),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            response: std::fs::read(&response_path).ok(),
        }
    }
}

fn last_line(stdout: &[u8]) -> String {
    String::from_utf8_lossy(stdout)
        .lines()
        .map(str::trim)
        .rfind(|line| !line.is_empty())
        .unwrap_or_default()
        .to_owned()
}

/// A bridge's descriptor in the one form `split_kiss_descriptor` reads:
/// `h` for hardened steps and both branches as `<0;1>`.
///
/// A checksum is dropped when the text had to be changed, since it no longer
/// matches; an untouched descriptor keeps it and has it verified.
pub fn kiss_form(descriptor: &str) -> String {
    let descriptor = descriptor.trim();
    let (body, checksum) = match descriptor.split_once('#') {
        Some((body, checksum)) => (body, Some(checksum)),
        None => (descriptor, None),
    };
    let mut changed = body.replace('\'', "h");
    if !changed.contains("<0;1>") {
        changed = changed.replacen("/0/*", "/<0;1>/*", 1);
    }
    match checksum {
        Some(checksum) if changed == body => format!("{body}#{checksum}"),
        _ => changed,
    }
}
