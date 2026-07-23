use std::ffi::{c_int, c_uchar};
use std::ptr::NonNull;

use anyhow::{Context, Result, bail};
use image::GrayImage;

const MAX_PAYLOAD: usize = 2560;
const MAX_GRIDS: c_int = 8;

#[repr(C)]
struct KQuirc {
    _private: [u8; 0],
}

unsafe extern "C" {
    fn k_quirc_new() -> *mut KQuirc;
    fn k_quirc_destroy(quirc: *mut KQuirc);
    fn k_quirc_resize(quirc: *mut KQuirc, width: c_int, height: c_int) -> c_int;
    fn k_quirc_begin(quirc: *mut KQuirc, width: *mut c_int, height: *mut c_int) -> *mut c_uchar;
    fn k_quirc_end(quirc: *mut KQuirc, find_inverted: bool);
    fn k_quirc_count(quirc: *const KQuirc) -> c_int;
    fn kiss_k_quirc_decode_payload(
        quirc: *mut KQuirc,
        index: c_int,
        payload: *mut c_uchar,
        capacity: usize,
    ) -> c_int;
}

pub(crate) struct Decoder {
    quirc: NonNull<KQuirc>,
    dimensions: Option<(u32, u32)>,
}

impl Decoder {
    pub(crate) fn new() -> Result<Self> {
        // SAFETY: The constructor takes no arguments and returns either a valid owned context or
        // null. The context is released by Drop.
        let quirc = NonNull::new(unsafe { k_quirc_new() }).context("allocating k_quirc decoder")?;
        Ok(Self {
            quirc,
            dimensions: None,
        })
    }

    pub(crate) fn decode(&mut self, image: &GrayImage) -> Result<Vec<String>> {
        let (width, height) = image.dimensions();
        let width_i32 = c_int::try_from(width).context("camera width does not fit k_quirc")?;
        let height_i32 = c_int::try_from(height).context("camera height does not fit k_quirc")?;
        if self.dimensions != Some((width, height)) {
            // SAFETY: self.quirc owns a live context and the dimensions were checked above.
            if unsafe { k_quirc_resize(self.quirc.as_ptr(), width_i32, height_i32) } != 0 {
                bail!("resizing k_quirc decoder to {width}x{height}");
            }
            self.dimensions = Some((width, height));
        }

        let mut decoder_width = 0;
        let mut decoder_height = 0;
        // SAFETY: self.quirc is live and has been resized. The returned buffer belongs to the
        // context and remains valid until resize or destroy.
        let buffer =
            unsafe { k_quirc_begin(self.quirc.as_ptr(), &mut decoder_width, &mut decoder_height) };
        let buffer = NonNull::new(buffer).context("starting k_quirc frame")?;
        if decoder_width != width_i32 || decoder_height != height_i32 {
            bail!("k_quirc returned an unexpected frame size");
        }
        let frame_len = usize::try_from(width)
            .ok()
            .and_then(|width| {
                usize::try_from(height)
                    .ok()
                    .and_then(|height| width.checked_mul(height))
            })
            .context("camera frame size overflow")?;
        if image.as_raw().len() != frame_len {
            bail!("camera frame is not tightly packed grayscale data");
        }
        // SAFETY: k_quirc allocated frame_len bytes during resize and image contains exactly that
        // many initialized bytes. The source and destination cannot overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(image.as_raw().as_ptr(), buffer.as_ptr(), frame_len);
            k_quirc_end(self.quirc.as_ptr(), false);
        }

        // SAFETY: self.quirc remains live after k_quirc_end.
        let grid_count = unsafe { k_quirc_count(self.quirc.as_ptr()) }.clamp(0, MAX_GRIDS);
        let mut payloads = Vec::with_capacity(grid_count as usize);
        for index in 0..grid_count {
            let mut decoded = [0; MAX_PAYLOAD];
            // SAFETY: index is below k_quirc_count. The C bridge checks the supplied capacity
            // before copying into decoded.
            let length = unsafe {
                kiss_k_quirc_decode_payload(
                    self.quirc.as_ptr(),
                    index,
                    decoded.as_mut_ptr(),
                    decoded.len(),
                )
            };
            let Ok(length) = usize::try_from(length) else {
                continue;
            };
            if length == 0 || length > decoded.len() {
                continue;
            }
            let bytes = &decoded[..length];
            if let Ok(payload) = std::str::from_utf8(bytes) {
                payloads.push(payload.to_owned());
            }
        }
        Ok(payloads)
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        // SAFETY: Decoder exclusively owns this live context.
        unsafe { k_quirc_destroy(self.quirc.as_ptr()) };
    }
}
