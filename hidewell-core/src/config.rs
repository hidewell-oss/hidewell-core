//! Container geometry. Production values are constants; tests use tiny geometries.

use crate::crypto::AEAD_OVERHEAD;
use crate::error::{Error, Result};
use crate::slots::TABLE_LEN;

const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;

/// Container geometry and behaviour knobs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerConfig {
    /// Allocation unit of the global bitmap (production: 4 MiB).
    pub chunk_size: u32,
    /// Sub-allocation unit inside a vault-owned chunk (production: 64 KiB).
    /// `chunk_size / block_size` must be in 2..=64.
    pub block_size: u32,
    /// Blocks per file segment; segment ciphertext = `segment_blocks * block_size`
    /// (production: 16 → 1 MiB on disk, 1 MiB − 28 B plaintext).
    pub segment_blocks: u32,
    /// Allowed container sizes in bytes, ascending (production: 1, 4, 16, 64 GiB).
    pub buckets: Vec<u64>,
    /// Free chunks rewritten with fresh random bytes on every commit.
    pub cover_chunks_per_commit: u32,
    /// Filler fraction range in permille (production: 5–15 %).
    pub filler_permille: (u32, u32),
    /// Inclusive range of filler key-slot reservations made at setup.
    pub filler_slots: (u32, u32),
}

impl ContainerConfig {
    /// Production geometry.
    pub fn production() -> Self {
        ContainerConfig {
            chunk_size: (4 * MIB) as u32,
            block_size: 64 * 1024,
            segment_blocks: 16,
            buckets: vec![GIB, 4 * GIB, 16 * GIB, 64 * GIB],
            cover_chunks_per_commit: 2,
            filler_permille: (50, 150),
            filler_slots: (1, 8),
        }
    }

    /// Tiny geometry for tests (4 KiB chunks, 256 B blocks).
    #[cfg(any(test, feature = "mock-oracle"))]
    pub fn tiny() -> Self {
        ContainerConfig {
            chunk_size: 4096,
            block_size: 256,
            segment_blocks: 4,
            buckets: vec![64 * 4096, 128 * 4096, 256 * 4096],
            cover_chunks_per_commit: 2,
            filler_permille: (50, 150),
            filler_slots: (1, 8),
        }
    }

    /// Blocks per chunk.
    pub fn blocks_per_chunk(&self) -> u32 {
        self.chunk_size / self.block_size
    }

    /// Plaintext bytes per file segment.
    pub fn segment_plain_len(&self) -> u64 {
        u64::from(self.segment_blocks) * u64::from(self.block_size) - AEAD_OVERHEAD as u64
    }

    /// Maximum number of chunks (largest bucket).
    pub fn max_chunks(&self) -> u32 {
        (self.buckets.last().copied().unwrap_or(0) / u64::from(self.chunk_size)) as u32
    }

    /// Bytes of the allocation bitmap (sized for the largest bucket).
    pub fn bitmap_len(&self) -> usize {
        self.max_chunks().div_ceil(8) as usize
    }

    /// Plaintext length of the (padded) device state.
    pub fn device_state_plain_len(&self) -> usize {
        256 + self.bitmap_len()
    }

    /// Sealed length of one device state copy.
    pub fn device_state_len(&self) -> usize {
        self.device_state_plain_len() + AEAD_OVERHEAD
    }

    /// Bytes of the superblock: two slot tables (A/B), two device-state copies and the
    /// 16 local manifest entries.
    pub fn superblock_len(&self) -> usize {
        2 * TABLE_LEN
            + 2 * self.device_state_len()
            + crate::slots::SLOT_COUNT * crate::backup::LOCAL_ENTRY_LEN
    }

    /// Chunks reserved for the superblock at the start of the container.
    pub fn superblock_chunks(&self) -> u32 {
        (self.superblock_len() as u64).div_ceil(u64::from(self.chunk_size)) as u32
    }

    /// Plaintext length of one anchor record (fixed; holds the logical→physical map).
    pub fn anchor_plain_len(&self) -> usize {
        // header (≤ 128 B of varints) + 5 B per map entry (u32 varint worst case).
        128 + 5 * self.max_chunks() as usize
    }

    /// Validate geometry invariants.
    pub fn validate(&self) -> Result<()> {
        let chunk = u64::from(self.chunk_size);
        let block = u64::from(self.block_size);
        // Sizes first: every derived quantity below divides by them, and
        // `max_chunks()` truncates to u32, so the bucket bound is checked in u64.
        if self.block_size < 128 || chunk < 2 * block || chunk % block != 0 {
            return Err(Error::InvalidArgument);
        }
        let bpc = self.blocks_per_chunk();
        let ok = bpc <= 64
            && (1..=bpc).contains(&self.segment_blocks)
            && u64::from(self.segment_blocks) * block > AEAD_OVERHEAD as u64
            && !self.buckets.is_empty()
            && self.buckets.windows(2).all(|w| w[0] < w[1])
            && self.buckets.iter().all(|b| b % chunk == 0)
            && self.buckets[self.buckets.len() - 1] / chunk <= 1 << 24
            && self.buckets[0] / chunk > u64::from(self.superblock_chunks()) + 2
            && self.anchor_plain_len() + AEAD_OVERHEAD <= (self.chunk_size / 2) as usize
            && self.filler_permille.0 <= self.filler_permille.1
            && self.filler_permille.1 < 500
            && self.filler_slots.0 <= self.filler_slots.1
            && (self.filler_slots.1 as usize) < crate::slots::SLOT_COUNT - 1;
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidArgument)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometries_are_valid() {
        let p = ContainerConfig::production();
        p.validate().unwrap();
        assert_eq!(p.blocks_per_chunk(), 64);
        assert_eq!(p.segment_plain_len(), 1024 * 1024 - 28);
        assert_eq!(p.superblock_chunks(), 1);
        assert_eq!(p.max_chunks(), 16384);
        ContainerConfig::tiny().validate().unwrap();
    }

    #[test]
    fn validate_rejects_degenerate_sizes_without_panicking() {
        type Mutate = fn(&mut ContainerConfig);
        let base = ContainerConfig::tiny();
        let cases: &[(&str, Mutate)] = &[
            ("zero block", |c| c.block_size = 0),
            ("zero chunk", |c| c.chunk_size = 0),
            ("tiny block", |c| c.block_size = 64),
            ("one block per chunk", |c| c.chunk_size = c.block_size),
            ("unaligned chunk", |c| c.chunk_size += 1),
            ("huge block", |c| c.block_size = u32::MAX),
            ("zero segment", |c| c.segment_blocks = 0),
            ("segment over chunk", |c| c.segment_blocks = 17),
            ("no buckets", |c| c.buckets.clear()),
            ("bucket too small", |c| c.buckets = vec![4096]),
            ("unsorted buckets", |c| c.buckets.reverse()),
            ("unaligned bucket", |c| c.buckets[0] += 1),
            ("bucket beyond u32 chunks", |c| {
                c.buckets.push(u64::MAX - 4095)
            }),
            ("filler range", |c| c.filler_permille = (200, 100)),
            ("filler slots", |c| c.filler_slots = (1, 15)),
        ];
        for &(name, mutate) in cases {
            let mut c = base.clone();
            mutate(&mut c);
            assert_eq!(c.validate(), Err(Error::InvalidArgument), "{name}");
        }
    }
}
