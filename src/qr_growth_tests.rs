use super::*;

// These exercise transport byte boundaries; they are not semantic PSBTs.
// The C-signed fixture below separately checks an actual transaction.
fn transport_bytes(len: usize) -> Vec<u8> {
    let mut bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
    bytes[..5].copy_from_slice(b"psbt\xff");
    bytes
}

#[test]
fn signed_size_boundaries_cover_static_and_single_part_ur() {
    for len in [4096, 4097, 9108, 9109] {
        let raw = transport_bytes(len);
        let cbor = cbor_byte_string(&raw);
        for payload in [
            base64::engine::general_purpose::STANDARD.encode(&raw),
            ur::ur::encode(&cbor, &ur::Type::Custom("crypto-psbt")),
        ] {
            let result = SignedPsbtDecoder::default().receive(&payload);
            if len <= 9108 {
                assert_eq!(result.unwrap().unwrap(), raw);
            } else {
                assert!(result.is_err(), "accepted {len}-byte signed reply");
            }
        }
    }
}

#[test]
fn maximum_signed_reply_recovers_in_every_device_fragment_mode() {
    let raw = transport_bytes(9108);
    let cbor = cbor_byte_string(&raw);
    for fragment in [120, 60, 42, 20] {
        let mut encoder = UrEncoder::new(&cbor, fragment, "crypto-psbt").unwrap();
        let count = encoder.fragment_count();
        if fragment == 20 {
            assert_eq!(count, 456, "narrow easy-scan boundary");
        }
        let mut parts: Vec<_> = (0..count)
            .map(|_| encoder.next_part().unwrap().to_ascii_uppercase())
            .collect();
        parts.reverse();
        let mut decoder = SignedPsbtDecoder::default();
        let mut recovered = None;
        for part in &parts {
            let result = receive_camera_payload(&mut decoder, part).unwrap();
            if result.is_some() {
                recovered = result;
                break;
            }
            // A camera can deliver the same visible frame repeatedly.
            assert!(
                receive_camera_payload(&mut decoder, part)
                    .unwrap()
                    .is_none()
            );
        }
        assert_eq!(recovered.unwrap(), raw, "fragment size {fragment}");
    }
}

#[test]
fn large_easy_scan_recovers_missing_source_frames_from_fountain_frames() {
    let raw = transport_bytes(9108);
    let cbor = cbor_byte_string(&raw);
    let mut encoder = UrEncoder::new(&cbor, 20, "crypto-psbt").unwrap();
    let mut decoder = SignedPsbtDecoder::default();
    let mut recovered = None;
    for index in 0..1824 {
        let part = encoder.next_part().unwrap();
        if index < 5 {
            continue;
        }
        if let Some(result) = receive_camera_payload(&mut decoder, &part).unwrap() {
            recovered = Some(result);
            break;
        }
    }
    assert_eq!(recovered.unwrap(), raw);
}

#[test]
fn oversized_multipart_reply_is_terminal_before_assembly() {
    let cbor = cbor_byte_string(&transport_bytes(9109));
    let mut encoder = UrEncoder::new(&cbor, 120, "crypto-psbt").unwrap();
    let error = receive_camera_payload(
        &mut SignedPsbtDecoder::default(),
        &encoder.next_part().unwrap(),
    )
    .unwrap_err();
    assert!(error.downcast_ref::<SafetyViolation>().is_some());
}

#[test]
fn bounded_frame_work_stops_a_transfer_that_never_finishes() {
    let cbor = cbor_byte_string(&transport_bytes(9108));
    let mut encoder = UrEncoder::new(&cbor, 20, "crypto-psbt").unwrap();
    let first = encoder.next_part().unwrap();
    let second = encoder.next_part().unwrap();
    let mut decoder = SignedPsbtDecoder::default();
    // Non-consecutive repeats still count as work. Two pieces of a
    // 456-piece message must not keep the decoder alive indefinitely.
    for index in 0..1824 {
        let part = if index % 2 == 0 { &first } else { &second };
        assert!(
            receive_camera_payload(&mut decoder, part)
                .unwrap()
                .is_none()
        );
    }
    let error = receive_camera_payload(&mut decoder, &first).unwrap_err();
    assert!(error.downcast_ref::<SafetyViolation>().is_some());
}

#[test]
fn different_large_transfers_never_combine_and_scanning_can_restart() {
    let a = transport_bytes(6000);
    let mut b = a.clone();
    b[100] ^= 1;
    let a_cbor = cbor_byte_string(&a);
    let b_cbor = cbor_byte_string(&b);
    let mut a_encoder = UrEncoder::new(&a_cbor, 60, "crypto-psbt").unwrap();
    let mut b_encoder = UrEncoder::new(&b_cbor, 60, "crypto-psbt").unwrap();
    let mut decoder = SignedPsbtDecoder::default();
    assert!(
        receive_camera_payload(&mut decoder, &a_encoder.next_part().unwrap())
            .unwrap()
            .is_none()
    );
    // Same sizes, different checksum: the foreign part is refused and
    // the camera path resets the assembly, not the scan's fixed deadline.
    assert!(
        receive_camera_payload(&mut decoder, &b_encoder.next_part().unwrap())
            .unwrap()
            .is_none()
    );
    let mut recovered = None;
    for _ in 0..b_encoder.fragment_count() * 4 {
        if let Some(raw) =
            receive_camera_payload(&mut decoder, &b_encoder.next_part().unwrap()).unwrap()
        {
            recovered = Some(raw);
            break;
        }
    }
    assert_eq!(recovered.unwrap(), b);
}

// Real C signer and C UR encoder output; public development keys only.
const GROWTH_REQUEST: &str = include_str!("../tests/fixtures/qr-growth/request.b64");
const GROWTH_SIGNED: &str = include_str!("../tests/fixtures/qr-growth/signed.b64");
const GROWTH_PARTS: &str = include_str!("../tests/fixtures/qr-growth/signed-20.parts");

fn verify_growth_reply(recovered: &[u8]) {
    use psbt_v2::v2::Psbt as PsbtV2;
    use std::collections::BTreeMap;

    let request = base64::engine::general_purpose::STANDARD
        .decode(GROWTH_REQUEST.trim())
        .unwrap();
    let signed_bytes = base64::engine::general_purpose::STANDARD
        .decode(GROWTH_SIGNED.trim())
        .unwrap();
    assert_eq!(request.len(), 4096);
    assert_eq!(signed_bytes.len(), 4405);
    assert_eq!(recovered, signed_bytes);
    let original = PsbtV2::deserialize(&request).unwrap();
    let signed = PsbtV2::deserialize(recovered).unwrap();
    assert_eq!(
        crate::spverify::verify(&original, &signed).unwrap().len(),
        1
    );
    let v0 = crate::spsend::to_v0(&signed).unwrap();
    crate::verify_psbt_signatures(&v0, &BTreeMap::new()).unwrap();
}

#[test]
fn c_signed_silent_payment_growth_round_trips_through_qr_images() {
    let mut decoder = SignedPsbtDecoder::default();
    let mut camera_decoder = QrDecoder::new().unwrap();
    let mut recovered = None;
    for part in GROWTH_PARTS.lines() {
        let code = QrCode::with_error_correction_level(part.as_bytes(), EcLevel::L).unwrap();
        let image = code
            .render::<Luma<u8>>()
            .quiet_zone(true)
            .max_dimensions(288, 288)
            .build();
        let payloads = camera_decoder.decode(&image).unwrap();
        assert_eq!(payloads, [part]);
        if let Some(raw) = receive_camera_payload(&mut decoder, &payloads[0]).unwrap() {
            recovered = Some(raw);
            break;
        }
    }
    verify_growth_reply(&recovered.expect("complete C-signed QR reply"));
}

#[test]
fn c_signed_growth_recovers_when_initial_source_frames_are_missing() {
    let mut decoder = SignedPsbtDecoder::default();
    let recovered = GROWTH_PARTS
        .lines()
        .skip(5)
        .find_map(|part| receive_camera_payload(&mut decoder, part).unwrap())
        .expect("C fountain frames recover the omitted source frames");
    verify_growth_reply(&recovered);
}
