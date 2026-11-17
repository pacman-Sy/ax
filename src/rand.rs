//! OS randomness without pulling a crate.

#[cfg(unix)]
pub fn fill(buf: &mut [u8]) -> Result<(), String> {
    use std::io::Read;
    let mut f =
        std::fs::File::open("/dev/urandom").map_err(|e| format!("open /dev/urandom: {e}"))?;
    f.read_exact(buf)
        .map_err(|e| format!("read /dev/urandom: {e}"))
}

#[cfg(windows)]
pub fn fill(buf: &mut [u8]) -> Result<(), String> {
    use std::ffi::c_void;

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptGenRandom(algorithm: *mut c_void, buffer: *mut u8, len: u32, flags: u32) -> i32;
    }

    const USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;

    if buf.is_empty() {
        return Ok(());
    }
    let len = u32::try_from(buf.len()).map_err(|_| "random buffer too large".to_string())?;
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            len,
            USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(format!("BCryptGenRandom failed: 0x{status:08x}"));
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub fn fill(_buf: &mut [u8]) -> Result<(), String> {
    Err("no OS random source on this platform".into())
}

pub fn bytes<const N: usize>() -> Result<[u8; N], String> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}
