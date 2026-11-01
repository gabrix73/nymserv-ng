use secrecy::{DebugSecret, Zeroize};
use std::fmt;

/// LockedBuffer allocates memory and locks it into RAM physical pages (mlock)
/// to prevent it from ever being swapped to disk.
pub struct LockedBuffer {
    data: Vec<u8>,
}

impl LockedBuffer {
    /// Creates a new locked buffer filled with the provided bytes.
    pub fn new(source: &[u8]) -> Self {
        let mut data = source.to_vec();
        // Lock pages in memory if OS allows
        unsafe {
            let ptr = data.as_mut_ptr();
            let len = data.len();
            if len > 0 {
                let _ = memsec::mlock(ptr, len);
            }
        }
        Self { data }
    }

    /// Access the raw slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Access the mutable slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl Clone for LockedBuffer {
    fn clone(&self) -> Self {
        Self::new(&self.data)
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        unsafe {
            let ptr = self.data.as_mut_ptr();
            let len = self.data.len();
            if len > 0 {
                // Secure zero wipe
                memsec::memzero(ptr, len);
                // Unlock pages
                let _ = memsec::munlock(ptr, len);
            }
        }
    }
}

impl Zeroize for LockedBuffer {
    fn zeroize(&mut self) {
        unsafe {
            let ptr = self.data.as_mut_ptr();
            let len = self.data.len();
            if len > 0 {
                memsec::memzero(ptr, len);
            }
        }
    }
}

impl DebugSecret for LockedBuffer {}

impl fmt::Debug for LockedBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED_LOCKED_MEMORY]")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locked_buffer() {
        let secret_bytes = b"super_secret_nym_server_key";
        let buf = LockedBuffer::new(secret_bytes);
        assert_eq!(buf.as_slice(), secret_bytes);
        assert_eq!(format!("{:?}", buf), "[REDACTED_LOCKED_MEMORY]");
    }
}
