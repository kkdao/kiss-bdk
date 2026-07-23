use std::sync::mpsc;
use std::time::{Duration, Instant};
use std::{error, fmt};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use bdk_wallet::bitcoin::Psbt;
use image::codecs::png::PngEncoder;
use image::{ColorType, ImageEncoder, Luma};
use nokhwa::pixel_format::LumaFormat;
use nokhwa::utils::{CameraFormat, CameraIndex, FrameFormat, RequestedFormat, RequestedFormatType};
use nokhwa::{Camera, nokhwa_initialize};
use qrcode::QrCode;
use qrcode::types::{EcLevel, Version};
use ur::ur::Kind as UrKind;
use ur::{Decoder as UrDecoder, decode as decode_ur};

use crate::k_quirc::Decoder as QrDecoder;

const CAMERA_TIMEOUT: Duration = Duration::from_secs(120);
const SCAN_MAX_WIDTH: u32 = 1280;
const SCAN_MAX_HEIGHT: u32 = 720;
const CAMERA_FRAME_FORMATS: &[FrameFormat] = &[
    FrameFormat::YUYV,
    FrameFormat::NV12,
    FrameFormat::GRAY,
    FrameFormat::RAWRGB,
];
const MAX_PSBT_BYTES: usize = 4096;
const MAX_STATIC_BASE64_BYTES: usize = MAX_PSBT_BYTES.div_ceil(3) * 4;
const MAX_KISS_QR_VERSION: i16 = 25;
const MAX_UR_MESSAGE_BYTES: usize = MAX_PSBT_BYTES + 3;
const MAX_UR_FRAGMENTS: u32 = 128;
const MAX_UR_FRAGMENT_BYTES: usize = 256;
const MAX_UR_FRAMES: usize = 512;
const CRYPTO_PSBT_PREFIX: &str = "ur:crypto-psbt/";

/// Render a PSBT as one static, base64 QR in a PNG image.
pub fn render_psbt_png(psbt: &Psbt) -> Result<Vec<u8>> {
    let payload = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());
    render_payload_png(&payload)
}

/// Scan the first static QR from the selected webcam and return its text.
pub fn scan_descriptor(camera: u32) -> Result<String> {
    scan_camera(camera, |payload| {
        let descriptor = payload.trim();
        if descriptor.contains("<0;1>")
            && (descriptor.starts_with("wpkh(")
                || descriptor.starts_with("sh(wpkh(")
                || descriptor.starts_with("pkh("))
        {
            Ok(Some(descriptor.to_owned()))
        } else {
            Ok(None)
        }
    })
}

/// Scan a KISS-signed PSBT from a static base64 or BC-UR `crypto-psbt` QR.
pub fn scan_signed_psbt(camera: u32) -> Result<Psbt> {
    let mut decoder = SignedPsbtDecoder::default();
    scan_camera(camera, move |payload| {
        receive_camera_payload(&mut decoder, payload)
    })
}

fn receive_camera_payload(decoder: &mut SignedPsbtDecoder, payload: &str) -> Result<Option<Psbt>> {
    match decoder.receive(payload) {
        Ok(value) => Ok(value),
        Err(error) if error.downcast_ref::<SafetyViolation>().is_some() => Err(error),
        Err(error) => {
            eprintln!("ignored unreadable signed-QR frame: {error:#}");
            *decoder = SignedPsbtDecoder::default();
            Ok(None)
        }
    }
}

fn render_payload_png(payload: &str) -> Result<Vec<u8>> {
    let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::M)
        .context("encoding PSBT as QR")?;
    match code.version() {
        Version::Normal(version) if version <= MAX_KISS_QR_VERSION => {}
        Version::Normal(version) => bail!(
            "PSBT needs QR version {version}; KISS's camera supports at most version {MAX_KISS_QR_VERSION}"
        ),
        Version::Micro(_) => bail!("PSBT unexpectedly encoded as a Micro QR"),
    }

    let image = code
        .render::<Luma<u8>>()
        .quiet_zone(true)
        .min_dimensions(1024, 1024)
        .build();
    let mut png = Vec::new();
    PngEncoder::new(&mut png)
        .write_image(
            image.as_raw(),
            image.width(),
            image.height(),
            ColorType::L8.into(),
        )
        .context("encoding PSBT QR as PNG")?;
    Ok(png)
}

fn initialize_camera() -> Result<()> {
    let (sender, receiver) = mpsc::sync_channel(1);
    nokhwa_initialize(move |granted| {
        let _ = sender.send(granted);
    });
    let granted = receiver
        .recv_timeout(CAMERA_TIMEOUT)
        .context("timed out waiting for camera permission")?;
    if !granted {
        bail!(
            "camera permission denied; enable it in System Settings > Privacy & Security > Camera"
        );
    }
    Ok(())
}

fn scan_camera<T>(
    camera_index: u32,
    mut receive_payload: impl FnMut(&str) -> Result<Option<T>>,
) -> Result<T> {
    initialize_camera()?;
    let mut camera = open_camera(camera_index)?;
    camera.open_stream().context("starting camera stream")?;

    eprintln!("Camera ready. Hold the KISS QR in view...");
    let mut qr_decoder = QrDecoder::new()?;
    let deadline = Instant::now() + CAMERA_TIMEOUT;
    while Instant::now() < deadline {
        let frame = camera.frame().context("reading camera frame")?;
        let greyscale = frame
            .decode_image::<LumaFormat>()
            .context("converting camera frame to greyscale")?;
        let greyscale = bound_scan_frame(greyscale);
        for payload in qr_decoder.decode(&greyscale)? {
            if let Some(value) = receive_payload(&payload)? {
                return Ok(value);
            }
        }
    }
    bail!("no complete QR was scanned within 120 seconds")
}

#[cfg(target_os = "macos")]
fn open_camera(camera_index: u32) -> Result<Camera> {
    let index = CameraIndex::Index(camera_index);
    let device = nokhwa_bindings_macos::AVCaptureDevice::new(&index)
        .with_context(|| format!("querying camera {camera_index}"))?;
    let formats = device
        .supported_formats()
        .with_context(|| format!("listing formats for camera {camera_index}"))?;
    let selected = choose_camera_format(&formats).context("camera has no usable raw video mode")?;
    eprintln!("Using camera mode {selected}");
    let requested =
        RequestedFormat::with_formats(RequestedFormatType::Exact(selected), CAMERA_FRAME_FORMATS);
    Camera::new(index, requested)
        .with_context(|| format!("opening camera {camera_index} in mode {selected}"))
}

#[cfg(not(target_os = "macos"))]
fn open_camera(camera_index: u32) -> Result<Camera> {
    let requested = RequestedFormat::with_formats(RequestedFormatType::None, CAMERA_FRAME_FORMATS);
    Camera::new(CameraIndex::Index(camera_index), requested)
        .with_context(|| format!("opening camera {camera_index}"))
}

fn choose_camera_format(formats: &[CameraFormat]) -> Option<CameraFormat> {
    formats
        .iter()
        .filter(|format| CAMERA_FRAME_FORMATS.contains(&format.format()))
        .min_by_key(|format| {
            let resolution = format.resolution();
            let distance = u64::from(resolution.width().abs_diff(SCAN_MAX_WIDTH))
                + u64::from(resolution.height().abs_diff(SCAN_MAX_HEIGHT));
            (distance, std::cmp::Reverse(format.frame_rate()))
        })
        .copied()
}

fn bound_scan_frame(image: image::GrayImage) -> image::GrayImage {
    let (width, height) = image.dimensions();
    if width <= SCAN_MAX_WIDTH && height <= SCAN_MAX_HEIGHT {
        return image;
    }
    let (new_width, new_height) = if u64::from(width) * u64::from(SCAN_MAX_HEIGHT)
        > u64::from(height) * u64::from(SCAN_MAX_WIDTH)
    {
        let scaled_height = u64::from(height) * u64::from(SCAN_MAX_WIDTH) / u64::from(width);
        (
            SCAN_MAX_WIDTH,
            u32::try_from(scaled_height).expect("scaled height is bounded"),
        )
    } else {
        let scaled_width = u64::from(width) * u64::from(SCAN_MAX_HEIGHT) / u64::from(height);
        (
            u32::try_from(scaled_width).expect("scaled width is bounded"),
            SCAN_MAX_HEIGHT,
        )
    };
    image::imageops::resize(
        &image,
        new_width.max(1),
        new_height.max(1),
        image::imageops::FilterType::Triangle,
    )
}

#[derive(Default)]
struct SignedPsbtDecoder {
    ur: UrDecoder,
    last_resolved: usize,
    last_ur: Option<String>,
    ur_frames: usize,
}

#[derive(Debug)]
struct SafetyViolation(String);

impl fmt::Display for SafetyViolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl error::Error for SafetyViolation {}

fn safety_violation(message: impl Into<String>) -> anyhow::Error {
    SafetyViolation(message.into()).into()
}

impl SignedPsbtDecoder {
    fn receive(&mut self, payload: &str) -> Result<Option<Psbt>> {
        let payload = payload.trim();
        if payload.starts_with("cHNidP") {
            if payload.len() > MAX_STATIC_BASE64_BYTES {
                bail!("static PSBT QR exceeds KISS's {MAX_PSBT_BYTES}-byte limit");
            }
            let raw = base64::engine::general_purpose::STANDARD
                .decode(payload)
                .context("decoding static base64 PSBT QR")?;
            return parse_raw_psbt(&raw).map(Some);
        }

        let is_ur = payload
            .as_bytes()
            .get(..3)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"ur:"));
        if !is_ur {
            return Ok(None);
        }
        let normalized = payload.to_ascii_lowercase();
        if !normalized.starts_with(CRYPTO_PSBT_PREFIX) {
            return Ok(None);
        }
        if self.last_ur.as_deref() == Some(&normalized) {
            return Ok(None);
        }
        self.last_ur = Some(normalized.clone());
        self.ur_frames += 1;
        if self.ur_frames > MAX_UR_FRAMES {
            return Err(safety_violation(format!(
                "signed QR exceeded the {MAX_UR_FRAMES}-frame safety limit"
            )));
        }

        let (kind, decoded) =
            decode_ur(&normalized).map_err(|error| anyhow!("decoding crypto-psbt UR: {error}"))?;
        match kind {
            UrKind::SinglePart => parse_crypto_psbt_cbor(&decoded).map(Some),
            UrKind::MultiPart => {
                validate_fountain_part(&decoded)?;
                self.ur
                    .receive(&normalized)
                    .map_err(|error| anyhow!("assembling crypto-psbt UR fragments: {error}"))?;
                let resolved = self.ur.resolved_fragment_count().unwrap_or(0);
                if resolved > self.last_resolved {
                    self.last_resolved = resolved;
                    eprintln!(
                        "signed QR: {resolved}/{} fragments",
                        self.ur.fragment_count()
                    );
                }
                if !self.ur.complete() {
                    return Ok(None);
                }
                let cbor = self
                    .ur
                    .message()
                    .map_err(|error| anyhow!("recovering crypto-psbt UR message: {error}"))?
                    .context("complete UR decoder has no message")?;
                parse_crypto_psbt_cbor(&cbor).map(Some)
            }
        }
    }
}

fn validate_fountain_part(cbor: &[u8]) -> Result<()> {
    let mut decoder = minicbor::Decoder::new(cbor);
    if decoder.array().context("reading fountain-part CBOR")? != Some(5) {
        bail!("fountain part must be a five-item CBOR array");
    }
    let sequence = decoder.u32().context("reading fountain sequence")?;
    let sequence_count = decoder.u32().context("reading fountain fragment count")?;
    let message_length = usize::try_from(decoder.u32().context("reading fountain message length")?)
        .context("fountain message length does not fit this platform")?;
    let _checksum = decoder.u32().context("reading fountain checksum")?;
    let fragment = decoder.bytes().context("reading fountain fragment")?;

    if decoder.position() != cbor.len() {
        bail!("fountain part has trailing CBOR data");
    }
    if sequence == 0 || sequence_count == 0 || message_length == 0 || fragment.is_empty() {
        bail!("fountain part contains a zero value");
    }
    if sequence_count > MAX_UR_FRAGMENTS {
        return Err(safety_violation("signed QR declares too many fragments"));
    }
    if message_length > MAX_UR_MESSAGE_BYTES {
        return Err(safety_violation(
            "signed QR declares an oversized PSBT message",
        ));
    }
    if fragment.len() > MAX_UR_FRAGMENT_BYTES {
        return Err(safety_violation("signed QR fragment is too large"));
    }

    let count = usize::try_from(sequence_count).context("fragment count does not fit")?;
    let capacity = count
        .checked_mul(fragment.len())
        .context("fountain capacity overflow")?;
    let minimum = capacity.saturating_sub(fragment.len());
    if message_length > capacity || message_length <= minimum {
        bail!("fountain metadata has inconsistent message and fragment lengths");
    }
    Ok(())
}

fn parse_crypto_psbt_cbor(cbor: &[u8]) -> Result<Psbt> {
    let raw = unwrap_cbor_byte_string(cbor).context("crypto-psbt must be one CBOR byte string")?;
    parse_raw_psbt(raw)
}

fn parse_raw_psbt(raw: &[u8]) -> Result<Psbt> {
    if raw.len() > MAX_PSBT_BYTES {
        bail!(
            "signed PSBT is {} bytes; KISS supports at most {MAX_PSBT_BYTES}",
            raw.len()
        );
    }
    if !raw.starts_with(b"psbt\xff") {
        bail!("scanned payload does not contain PSBT magic bytes");
    }
    Psbt::deserialize(raw).context("parsing scanned signed PSBT")
}

fn unwrap_cbor_byte_string(cbor: &[u8]) -> Result<&[u8]> {
    let first = *cbor.first().context("empty CBOR")?;
    if first >> 5 != 2 {
        bail!("CBOR value is not a byte string");
    }

    let additional = first & 0x1f;
    let (header_len, value_len): (usize, usize) = match additional {
        value @ 0..=23 => (1, usize::from(value)),
        24 => {
            let value = usize::from(*cbor.get(1).context("truncated CBOR byte-string length")?);
            if value < 24 {
                bail!("non-canonical CBOR byte-string length");
            }
            (2, value)
        }
        25 => {
            let bytes: [u8; 2] = cbor
                .get(1..3)
                .context("truncated CBOR byte-string length")?
                .try_into()
                .expect("slice length checked");
            let value = usize::from(u16::from_be_bytes(bytes));
            if value <= u8::MAX as usize {
                bail!("non-canonical CBOR byte-string length");
            }
            (3, value)
        }
        26 => {
            let bytes: [u8; 4] = cbor
                .get(1..5)
                .context("truncated CBOR byte-string length")?
                .try_into()
                .expect("slice length checked");
            let value = usize::try_from(u32::from_be_bytes(bytes))
                .context("CBOR byte-string length does not fit this platform")?;
            if value <= u16::MAX as usize {
                bail!("non-canonical CBOR byte-string length");
            }
            (5, value)
        }
        27 => {
            let bytes: [u8; 8] = cbor
                .get(1..9)
                .context("truncated CBOR byte-string length")?
                .try_into()
                .expect("slice length checked");
            let value = usize::try_from(u64::from_be_bytes(bytes))
                .context("CBOR byte-string length does not fit this platform")?;
            if value <= u32::MAX as usize {
                bail!("non-canonical CBOR byte-string length");
            }
            (9, value)
        }
        31 => bail!("indefinite-length CBOR byte strings are not accepted"),
        _ => bail!("invalid CBOR byte-string length"),
    };

    let end = header_len
        .checked_add(value_len)
        .context("CBOR byte-string length overflow")?;
    if end != cbor.len() {
        bail!("CBOR byte string is truncated or has trailing data");
    }
    Ok(&cbor[header_len..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use bdk_wallet::bitcoin::{Transaction, absolute, transaction};
    use nokhwa::utils::Resolution;
    use qrcode::types::Color;
    use ur::Encoder as UrEncoder;

    fn sample_psbt() -> Psbt {
        Psbt::from_unsigned_tx(Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        })
        .unwrap()
    }

    fn wrap_cbor_byte_string(bytes: &[u8]) -> Vec<u8> {
        let mut wrapped = match bytes.len() {
            len @ 0..=23 => vec![0x40 | len as u8],
            len @ 24..=255 => vec![0x58, len as u8],
            len @ 256..=65535 => {
                let mut header = vec![0x59];
                header.extend_from_slice(&(len as u16).to_be_bytes());
                header
            }
            len => {
                let mut header = vec![0x5a];
                header.extend_from_slice(&(len as u32).to_be_bytes());
                header
            }
        };
        wrapped.extend_from_slice(bytes);
        wrapped
    }

    fn fountain_part_cbor(
        sequence: u32,
        sequence_count: u32,
        message_length: u32,
        fragment_length: usize,
    ) -> Vec<u8> {
        let fragment = vec![0xa5; fragment_length];
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder
            .array(5)
            .unwrap()
            .u32(sequence)
            .unwrap()
            .u32(sequence_count)
            .unwrap()
            .u32(message_length)
            .unwrap()
            .u32(0x1234_5678)
            .unwrap()
            .bytes(&fragment)
            .unwrap();
        encoder.into_writer()
    }

    #[test]
    fn rendered_psbt_png_decodes_to_exact_base64() {
        let psbt = sample_psbt();
        let expected = base64::engine::general_purpose::STANDARD.encode(psbt.serialize());
        let png = render_psbt_png(&psbt).unwrap();
        assert!(png.starts_with(b"\x89PNG\r\n\x1a\n"));

        let image = image::load_from_memory_with_format(&png, image::ImageFormat::Png)
            .unwrap()
            .into_luma8();
        let decoded = QrDecoder::new().unwrap().decode(&image).unwrap();
        assert_eq!(decoded, [expected]);
    }

    #[test]
    fn bounds_camera_frames_without_changing_aspect_ratio() {
        let landscape = bound_scan_frame(image::GrayImage::new(2560, 1440));
        assert_eq!(landscape.dimensions(), (1280, 720));
        let portrait = bound_scan_frame(image::GrayImage::new(1440, 2560));
        assert_eq!(portrait.dimensions(), (405, 720));
        let already_small = bound_scan_frame(image::GrayImage::new(640, 480));
        assert_eq!(already_small.dimensions(), (640, 480));
    }

    #[test]
    fn selects_max_fps_for_the_nearest_raw_camera_resolution() {
        let formats = [
            CameraFormat::new(Resolution::new(1280, 720), FrameFormat::YUYV, 15),
            CameraFormat::new(Resolution::new(1280, 720), FrameFormat::YUYV, 30),
            CameraFormat::new(Resolution::new(1280, 720), FrameFormat::MJPEG, 120),
            CameraFormat::new(Resolution::new(1920, 1080), FrameFormat::YUYV, 60),
        ];
        let selected = choose_camera_format(&formats).unwrap();
        assert_eq!(selected.resolution(), Resolution::new(1280, 720));
        assert_eq!(selected.format(), FrameFormat::YUYV);
        assert_eq!(selected.frame_rate(), 30);
    }

    #[test]
    fn rejects_payload_at_the_version_25_boundary() {
        let version = |length: usize| {
            QrCode::with_error_correction_level(vec![b'a'; length], EcLevel::M)
                .unwrap()
                .version()
        };
        let mut accepted = 0_usize;
        let mut rejected = 4096_usize;
        while accepted + 1 < rejected {
            let candidate = accepted + (rejected - accepted) / 2;
            match version(candidate) {
                Version::Normal(value) if value <= MAX_KISS_QR_VERSION => {
                    accepted = candidate;
                }
                _ => rejected = candidate,
            }
        }
        assert_eq!(version(accepted), Version::Normal(25));
        assert_eq!(version(rejected), Version::Normal(26));
        assert!(render_payload_png(&"a".repeat(accepted)).is_ok());
        assert!(render_payload_png(&"a".repeat(rejected)).is_err());
    }

    #[test]
    fn k_quirc_decodes_a_generated_static_qr() {
        const PAYLOAD: &str = "kiss-wallet-testnet4";
        const QUIET: usize = 4;
        const SCALE: usize = 6;

        let code = QrCode::new(PAYLOAD.as_bytes()).unwrap();
        let qr_width = code.width();
        let image_width = (qr_width + 2 * QUIET) * SCALE;
        let image = image::GrayImage::from_fn(image_width as u32, image_width as u32, |x, y| {
            let x = x as usize;
            let y = y as usize;
            let module_x = x / SCALE;
            let module_y = y / SCALE;
            let in_qr = module_x >= QUIET
                && module_y >= QUIET
                && module_x < qr_width + QUIET
                && module_y < qr_width + QUIET;
            let dark = in_qr && code[(module_x - QUIET, module_y - QUIET)] == Color::Dark;
            Luma([if dark { 0 } else { 255 }])
        });

        let decoded = QrDecoder::new().unwrap().decode(&image).unwrap();
        assert_eq!(decoded, [PAYLOAD]);
    }

    #[test]
    fn k_quirc_decodes_an_actual_kiss_animated_payload_at_device_size() {
        let payload = include_str!("../tests/fixtures/kiss-signed-qr-12.parts")
            .lines()
            .next()
            .unwrap();
        let code = QrCode::with_error_correction_level(payload.as_bytes(), EcLevel::L).unwrap();
        let qr = code
            .render::<Luma<u8>>()
            .dark_color(Luma([0]))
            .light_color(Luma([255]))
            .quiet_zone(true)
            .max_dimensions(288, 288)
            .build();
        let mut card = image::GrayImage::from_pixel(316, 316, Luma([255]));
        let offset = i64::from((316 - qr.width()) / 2);
        image::imageops::overlay(&mut card, &qr, offset, offset);

        let decoded = QrDecoder::new().unwrap().decode(&card).unwrap();
        assert_eq!(decoded, [payload]);
    }

    #[test]
    fn accepts_only_canonical_bounded_cbor_byte_strings() {
        for length in [0, 23, 24, 255, 256, 4096] {
            let bytes = vec![0xa5; length];
            let wrapped = wrap_cbor_byte_string(&bytes);
            assert_eq!(unwrap_cbor_byte_string(&wrapped).unwrap(), bytes);
        }
        assert!(unwrap_cbor_byte_string(&[0x58, 0x01, 0xa5]).is_err());
        assert!(unwrap_cbor_byte_string(&[0x5f, 0xff]).is_err());
        assert!(unwrap_cbor_byte_string(&[0x41, 0xa5, 0x00]).is_err());
        assert!(unwrap_cbor_byte_string(&[0x81, 0x00]).is_err());
    }

    #[test]
    fn bounds_fountain_metadata_before_ur_allocation() {
        assert!(validate_fountain_part(&fountain_part_cbor(1, 2, 10, 5)).is_ok());
        let error = validate_fountain_part(&fountain_part_cbor(1, MAX_UR_FRAGMENTS + 1, 10, 5))
            .unwrap_err();
        assert!(error.downcast_ref::<SafetyViolation>().is_some());
        assert!(
            validate_fountain_part(&fountain_part_cbor(
                1,
                2,
                (MAX_UR_MESSAGE_BYTES + 1) as u32,
                5,
            ))
            .is_err()
        );
        assert!(
            validate_fountain_part(&fountain_part_cbor(1, 2, 10, MAX_UR_FRAGMENT_BYTES + 1,))
                .is_err()
        );
        assert!(validate_fountain_part(&fountain_part_cbor(1, 2, 4, 5)).is_err());
    }

    #[test]
    fn camera_scan_ignores_a_bad_frame_then_recovers() {
        let mut decoder = SignedPsbtDecoder::default();
        assert!(
            receive_camera_payload(&mut decoder, "UR:CRYPTO-PSBT/NOTBYTEWORDS")
                .unwrap()
                .is_none()
        );
        let expected = sample_psbt();
        let encoded = base64::engine::general_purpose::STANDARD.encode(expected.serialize());
        let decoded = receive_camera_payload(&mut decoder, &encoded)
            .unwrap()
            .unwrap();
        assert_eq!(decoded.serialize(), expected.serialize());
    }

    #[test]
    fn ur_decoder_accepts_uppercase_shuffled_duplicates() {
        let expected = sample_psbt();
        let cbor = wrap_cbor_byte_string(&expected.serialize());
        let mut encoder = UrEncoder::new(&cbor, 8, "crypto-psbt").unwrap();
        let mut parts: Vec<String> = (0..encoder.fragment_count())
            .map(|_| encoder.next_part().unwrap().to_ascii_uppercase())
            .collect();
        assert!(parts.len() > 1);
        parts.reverse();
        parts.insert(1, parts[0].clone());

        let mut decoder = SignedPsbtDecoder::default();
        let mut decoded = None;
        for part in parts {
            if let Some(psbt) = decoder.receive(&part).unwrap() {
                decoded = Some(psbt);
                break;
            }
        }
        assert_eq!(decoded.unwrap().serialize(), expected.serialize());
    }

    #[test]
    fn decodes_actual_kiss_cur_firmware_frames() {
        let expected = base64::engine::general_purpose::STANDARD
            .decode(include_str!("../tests/fixtures/kiss-signed-qr.b64").trim())
            .unwrap();
        let parts: Vec<&str> = include_str!("../tests/fixtures/kiss-signed-qr-12.parts")
            .lines()
            .collect();

        for start in [0, 4] {
            let mut decoder = SignedPsbtDecoder::default();
            let decoded = parts[start..]
                .iter()
                .find_map(|part| decoder.receive(part).unwrap())
                .unwrap();
            assert_eq!(decoded.serialize(), expected);
        }
    }

    #[test]
    fn static_base64_round_trips_and_is_bounded() {
        let expected = sample_psbt();
        let encoded = base64::engine::general_purpose::STANDARD.encode(expected.serialize());
        let mut decoder = SignedPsbtDecoder::default();
        let decoded = decoder.receive(&encoded).unwrap().unwrap();
        assert_eq!(decoded.serialize(), expected.serialize());

        let mut oversized_raw = vec![0_u8; MAX_PSBT_BYTES + 1];
        oversized_raw[..5].copy_from_slice(b"psbt\xff");
        let oversized = base64::engine::general_purpose::STANDARD.encode(oversized_raw);
        assert!(decoder.receive(&oversized).is_err());
    }
}
