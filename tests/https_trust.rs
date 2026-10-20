//! Live trust-store regression check; never contacts a wallet endpoint.
//! Run with `cargo test --test https_trust -- --ignored` after updating OS CAs.
//! DNS errors, timeouts and HTTP/parser failures are not certificate rejection.

fn certificate_rejection(error: minreq::Error) {
    let minreq::Error::IoError(error) = error else {
        panic!("expected a certificate rejection, got {error:?}");
    };
    let detail = error.to_string().to_lowercase();
    assert!(
        detail.contains("certificate") || detail.contains("not trusted"),
        "expected a certificate rejection, got {error:?}"
    );
}

#[test]
#[ignore = "requires network access to the public CA incident test servers"]
fn rejects_compromised_intermediates_and_accepts_healthy_https() {
    for url in ["https://github.com/", "https://pypi.org/"] {
        assert_eq!(
            minreq::get(url)
                .with_timeout(20)
                .send()
                .unwrap()
                .status_code,
            200
        );
    }
    for kind in ["dv", "ov", "ev"] {
        for series in ["b", "c"] {
            for cross in ["", "-aaa"] {
                let url = format!("https://{kind}-g3{series}{cross}-emudhra.we-have-a-problem.com");
                certificate_rejection(minreq::get(&url).with_timeout(20).send().unwrap_err());
                let client = bdk_esplora::esplora_client::Builder::new(&url)
                    .timeout(20)
                    .build_blocking();
                match client.get_height().unwrap_err() {
                    bdk_esplora::esplora_client::Error::Minreq(error) => {
                        certificate_rejection(error)
                    }
                    other => panic!("Esplora did not reject the certificate: {other:?}"),
                }
            }
        }
    }
}
