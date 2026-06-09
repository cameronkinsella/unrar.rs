//! Key-injection RAR3 decompression.
//!
//! [`decompress_rar3_block`] decrypts + decompresses a single RAR3 file body from
//! memory using a **pre-derived** AES-128 key + CBC IV (supplied directly, not
//! derived from a password here) and returns the CRC-32 of the output. Useful
//! when the key has already been computed elsewhere and a single file body is
//! held in memory rather than read from an archive on disk.
//!
//! The underlying C++ shim reads packed input chunked, so archives of any size
//! work.

use core::ffi::c_uint;

use crate::native;

/// Result of [`decompress_rar3_block`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rar3Decompressed {
    /// CRC-32 of the decompressed output. Compare against the file header's CRC.
    pub crc32: u32,
    /// Whether decompression produced exactly `unpack_size` bytes. A wrong key
    /// usually yields `false` (or a non-matching `crc32`).
    pub ok: bool,
}

/// Decrypt + decompress a RAR3 file body with a pre-derived key/IV.
///
/// - `key` / `iv`: the 16-byte AES-128 key and CBC IV (from the RAR3 SHA-1 KDF).
/// - `packed`: the stored (AES-CBC-encrypted) file body; length must be a whole
///   number of 16-byte blocks.
/// - `unpack_size`: the expected decompressed size (from the file header).
///
/// Returns the CRC-32 of the decompressed bytes and whether the size matched.
/// Safe to call with a wrong key: a corrupt/garbage stream is caught internally
/// and reported as `ok: false` (never unwinds across the FFI boundary).
pub fn decompress_rar3_block(
    key: &[u8; 16],
    iv: &[u8; 16],
    packed: &[u8],
    unpack_size: usize,
) -> Rar3Decompressed {
    // The shim always writes `unpack_size` bytes on success; provide the buffer.
    let mut out = vec![0u8; unpack_size];
    let mut unpack_failed: c_uint = 1;
    // SAFETY: all pointers are valid for the lengths passed; `out` holds
    // `unpack_size` bytes, `packed` holds `packed.len()` bytes, and `key`/`iv`
    // are 16 bytes each. The shim catches C++ exceptions internally.
    let crc = unsafe {
        native::hc_decompress_rar(
            out.as_mut_ptr(),
            packed.as_ptr(),
            packed.len() as c_uint,
            unpack_size as c_uint,
            key.as_ptr(),
            iv.as_ptr(),
            &mut unpack_failed,
        )
    };
    Rar3Decompressed {
        crc32: crc,
        ok: unpack_failed == 0,
    }
}
