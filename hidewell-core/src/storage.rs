//! Byte storage behind the container: a file on device, or memory in tests.

use std::sync::{Arc, Mutex};

use crate::error::{Error, Result};

/// Random-access byte storage. Implementations must not log offsets or sizes.
pub trait Storage: Send {
    /// Current length in bytes.
    fn len(&self) -> Result<u64>;
    /// Whether the storage is empty.
    fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
    /// Read exactly `buf.len()` bytes at `offset`.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()>;
    /// Write all of `data` at `offset` (may extend the storage).
    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()>;
    /// Durability barrier (fsync).
    fn sync(&mut self) -> Result<()>;
}

/// File-backed storage (Unix: iOS, Android, macOS, Linux).
#[cfg(unix)]
pub struct FileStorage {
    file: std::fs::File,
}

#[cfg(unix)]
impl FileStorage {
    /// Wrap an open read/write file. The caller must exclusively own this file for
    /// the lifetime of its Device and all vault/writer handles (e.g. hold a platform
    /// file lock); independent Devices cannot share one container safely.
    pub fn new(file: std::fs::File) -> Self {
        FileStorage { file }
    }
}

#[cfg(unix)]
impl Storage for FileStorage {
    fn len(&self) -> Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        use std::os::unix::fs::FileExt;
        Ok(self.file.read_exact_at(buf, offset)?)
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        use std::os::unix::fs::FileExt;
        Ok(self.file.write_all_at(data, offset)?)
    }

    fn sync(&mut self) -> Result<()> {
        Ok(self.file.sync_data()?)
    }
}

/// In-memory storage; clones share the same bytes (tests inspect raw container bytes).
#[derive(Clone, Default)]
pub struct MemStorage {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl MemStorage {
    /// Empty storage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Storage initialised with `bytes`.
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        MemStorage {
            bytes: Arc::new(Mutex::new(bytes)),
        }
    }

    /// Copy of the raw bytes.
    pub fn snapshot(&self) -> Vec<u8> {
        self.bytes.lock().expect("poisoned").clone()
    }

    /// Overwrite raw bytes (tamper tests).
    pub fn poke(&self, offset: usize, data: &[u8]) {
        self.bytes.lock().expect("poisoned")[offset..offset + data.len()].copy_from_slice(data);
    }
}

impl Storage for MemStorage {
    fn len(&self) -> Result<u64> {
        Ok(self.bytes.lock().map_err(|_| Error::Corrupt)?.len() as u64)
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let b = self.bytes.lock().map_err(|_| Error::Corrupt)?;
        let start = usize::try_from(offset).map_err(|_| Error::InvalidArgument)?;
        let end = start.checked_add(buf.len()).ok_or(Error::InvalidArgument)?;
        if end > b.len() {
            return Err(Error::Io(std::io::ErrorKind::UnexpectedEof));
        }
        buf.copy_from_slice(&b[start..end]);
        Ok(())
    }

    fn write_at(&mut self, offset: u64, data: &[u8]) -> Result<()> {
        let mut b = self.bytes.lock().map_err(|_| Error::Corrupt)?;
        let start = usize::try_from(offset).map_err(|_| Error::InvalidArgument)?;
        let end = start
            .checked_add(data.len())
            .ok_or(Error::InvalidArgument)?;
        if end > b.len() {
            b.resize(end, 0);
        }
        b[start..end].copy_from_slice(data);
        Ok(())
    }

    fn sync(&mut self) -> Result<()> {
        Ok(())
    }
}
