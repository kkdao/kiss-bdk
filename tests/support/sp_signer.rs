//! Runs only an explicitly supplied, freshly built test signer.
pub fn sign(request: &[u8], expected_exit: i32) -> Option<Vec<u8>> {
    let signer = std::env::var_os("KISS_INTEROP_SIGNER")
        .expect("set KISS_INTEROP_SIGNER to the binary built by sim/build_sp_interop.sh");
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("request.psbt");
    let output = dir.path().join("signed.psbt");
    std::fs::write(&input, request).unwrap();
    let result = std::process::Command::new(signer)
        .env("KISS_SIM_TMP", dir.path())
        .arg(&input)
        .arg(&output)
        .output()
        .expect("run KISS test signer");
    assert_eq!(
        result.status.code(),
        Some(expected_exit),
        "signer: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    if expected_exit == 0 {
        Some(std::fs::read(output).expect("signer must produce a PSBT"))
    } else {
        assert!(!output.exists(), "refusal must not produce signed output");
        assert!(String::from_utf8_lossy(&result.stderr).starts_with("STOP:"));
        None
    }
}
