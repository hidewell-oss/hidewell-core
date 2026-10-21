//! An unlocked vault: index, sub-chunk allocation, crash-safe commits and segmented
//! file streams.
//!
//! Keys (all `HKDF-SHA256(master_key, ∅, info)`; independent of the pattern/KEK, so
//! they survive restore with a new pattern):
//! `vault_id = …"hidewell/vault-id/v1"[..16]`, `anchor = …"hidewell/anchor-key/v1"`,
//! `index = …"hidewell/index-key/v1"`, `content = …"hidewell/content-key/v1"`,
//! `names = …"hidewell/object-names/v1"`.
//!
//! AADs bind every blob to its vault and role:
//! - anchor copy:  `"hidewell/anchor/v1" || vault_id || u8(copy)`
//! - root:         `"hidewell/root/v1" || vault_id || u64be(generation)`
//! - page:         `"hidewell/page/v1" || vault_id || u64be(first_id) || u64be(generation)`
//! - segment:      `"hidewell/seg/v1" || vault_id || u64be(item) || u8(kind) || u32be(index)
//!                  || u32be(count) || u64be(size)` (kind 0 = content, 1 = thumbnail)
//!
//! Commit protocol (write-new-then-switch):
//! 1. new blobs (segments, dirty pages, root) go to blocks free in BOTH the committed and
//!    the new state; superseded blobs stay intact until after the switch;
//! 2. device state (bitmap incl. newly allocated chunks) persisted, fsync;
//! 3. anchor record written to the older A/B copy with generation + 1, fsync — the switch;
//! 4. superseded blocks scrubbed with random bytes, emptied chunks released (bitmap +
//!    random overwrite), cover traffic, device state persisted, fsync.
//!
//! A crash before (3) leaves the previous commit intact (allocations made for the lost
//! commit stay marked in the bitmap and are indistinguishable from filler); a crash
//! after (3) at worst skips scrubbing/release.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use zeroize::Zeroize;

use crate::backup::{self, ObjectSource, SyncPlan};
use crate::crypto::{self, AEAD_OVERHEAD};
use crate::device::{DeviceInner, lock};
use crate::error::{Error, Result};
use crate::index::{
    self, AnchorRecord, BlobRef, DecoyLink, EntryKey, INDEX_VERSION, Item, NO_CHUNK, PAGE_ITEMS,
    PageRef, Root, RootPtr, Stream,
};
use crate::pattern::Pattern;
use crate::rng;
use crate::secret::{SecretKey, SecretVec};
use crate::slots::{self, FLAG_DURESS, SlotPayload};

const KIND_CONTENT: u8 = 0;
const KIND_THUMBNAIL: u8 = 1;

/// Keys derived from a vault master key.
pub(crate) struct VaultKeys {
    pub(crate) id: [u8; 16],
    anchor: SecretKey,
    index: SecretKey,
    content: SecretKey,
    pub(crate) names: SecretKey,
    pub(crate) master: SecretKey,
}

impl VaultKeys {
    pub(crate) fn derive(master: &SecretKey) -> Self {
        let h = |info: &[u8]| crypto::hkdf32(master.expose(), &[info]);
        let mut id = [0u8; 16];
        id.copy_from_slice(&h(b"hidewell/vault-id/v1").expose()[..16]);
        VaultKeys {
            id,
            anchor: h(b"hidewell/anchor-key/v1"),
            index: h(b"hidewell/index-key/v1"),
            content: h(b"hidewell/content-key/v1"),
            names: h(b"hidewell/object-names/v1"),
            master: master.duplicate(),
        }
    }

    fn anchor_aad(&self, copy: u64) -> Vec<u8> {
        crypto::label(b"hidewell/anchor/v1", &[&self.id, &[copy as u8]])
    }

    pub(crate) fn root_aad(&self, generation: u64) -> Vec<u8> {
        crypto::label(b"hidewell/root/v1", &[&self.id, &generation.to_be_bytes()])
    }

    fn page_aad(&self, first_id: u64, generation: u64) -> Vec<u8> {
        crypto::label(
            b"hidewell/page/v1",
            &[&self.id, &first_id.to_be_bytes(), &generation.to_be_bytes()],
        )
    }

    /// Segment AAD; `count`/`size` are `None` for streams written without a known size
    /// (sentinels u32::MAX / u64::MAX).
    fn stream_seg_aad(&self, item: u64, kind: u8, index: u32, size: Option<(u32, u64)>) -> Vec<u8> {
        let (count, size) = size.unwrap_or((u32::MAX, u64::MAX));
        self.seg_aad(item, kind, index, count, size)
    }

    fn seg_aad(&self, item: u64, kind: u8, index: u32, count: u32, size: u64) -> Vec<u8> {
        crypto::label(
            b"hidewell/seg/v1",
            &[
                &self.id,
                &item.to_be_bytes(),
                &[kind],
                &index.to_be_bytes(),
                &count.to_be_bytes(),
                &size.to_be_bytes(),
            ],
        )
    }
}

/// Page of the in-memory index.
#[derive(Clone, Copy)]
struct PageMem {
    first_id: u64,
    /// `None` = dirty (to be written at the next commit).
    blob: Option<BlobRef>,
    generation: u64,
}

/// Mask with `n` bits set starting at `start`.
fn run_mask(start: u32, n: u32) -> u64 {
    debug_assert!(n >= 1 && start + n <= 64);
    let bits = if n == 64 { u64::MAX } else { (1u64 << n) - 1 };
    bits << start
}

/// In-memory state of an unlocked vault.
pub(crate) struct VaultState {
    pub(crate) slot: u8,
    pub(crate) flags: u8,
    pub(crate) keys: VaultKeys,
    pub(crate) anchor_phys: u32,
    anchor_gen: u64,
    /// Last committed root (counters, albums and tags are edited in place and persisted
    /// at the next commit).
    root: Root,
    root_ptr: Option<RootPtr>,
    pub(crate) uploaded: Option<RootPtr>,
    /// Logical → physical chunk.
    map: Vec<u32>,
    /// Logical → used block mask (committed ∪ written-since-commit ∪ pending-free).
    used: Vec<u64>,
    items: BTreeMap<u64, Item>,
    pages: Vec<PageMem>,
    /// Logical chunks written since the last commit.
    touched: BTreeSet<u32>,
    /// Blobs superseded since the last commit (freed after the next commit point).
    pending_free: Vec<BlobRef>,
    pub(crate) epoch: u64,
    handle_generation: u64,
    poisoned: bool,
}

impl Drop for VaultState {
    fn drop(&mut self) {
        // Items are not ZeroizeOnDrop; `root` and the keys zeroize themselves.
        for it in self.items.values_mut() {
            it.zeroize();
        }
    }
}

fn empty_root() -> Root {
    Root {
        version: INDEX_VERSION,
        generation: 0,
        next_item_id: 1,
        next_album_id: 1,
        next_tag_id: 1,
        chunks: Vec::new(),
        pages: Vec::new(),
        albums: Vec::new(),
        tags: Vec::new(),
        next_decoy_id: 1,
        decoys: Vec::new(),
        entry_keys: Vec::new(),
        name: String::new(),
    }
}

/// Entry keys a new vault in slot `slot` receives from its creator: a non-duress
/// child of a vault holding all 16 keys gets all 16; a duress child gets only its own;
/// otherwise nothing (the child is then not backed up).
pub(crate) fn child_entry_keys(parent: &[EntryKey], slot: u8, duress: bool) -> Vec<EntryKey> {
    let full = parent.len() == crate::slots::SLOT_COUNT;
    if duress {
        parent.iter().filter(|k| k.index == slot).cloned().collect()
    } else if full {
        parent.to_vec()
    } else {
        Vec::new()
    }
}

impl VaultState {
    fn blank(slot: u8, payload: &SlotPayload, epoch: u64) -> Self {
        VaultState {
            slot,
            flags: payload.flags,
            keys: VaultKeys::derive(&payload.master_key),
            anchor_phys: payload.anchor_chunk,
            anchor_gen: 0,
            root: empty_root(),
            root_ptr: None,
            uploaded: None,
            map: Vec::new(),
            used: Vec::new(),
            items: BTreeMap::new(),
            pages: Vec::new(),
            touched: BTreeSet::new(),
            pending_free: Vec::new(),
            epoch,
            handle_generation: 0,
            poisoned: false,
        }
    }

    /// New empty vault: commits an empty root and the first anchor record.
    pub(crate) fn create(
        d: &mut DeviceInner,
        slot: u8,
        payload: &SlotPayload,
        entry_keys: Vec<EntryKey>,
    ) -> Result<Self> {
        let mut s = Self::blank(slot, payload, d.epoch);
        s.root.entry_keys = entry_keys;
        s.commit(d)?;
        s.claim_handle(d);
        Ok(s)
    }

    pub(crate) fn claim_handle(&mut self, d: &mut DeviceInner) {
        self.handle_generation = d.claim_vault_handle(self.slot);
    }

    /// This vault's copy of entry key `i`, if it holds it.
    pub(crate) fn entry_key(&self, i: u8) -> Option<SecretKey> {
        self.root
            .entry_keys
            .iter()
            .find(|k| k.index == i)
            .and_then(|k| SecretKey::from_slice(&k.key))
    }

    pub(crate) fn entry_keys(&self) -> &[EntryKey] {
        &self.root.entry_keys
    }

    /// Physical chunks owned by this vault (anchor + mapped data chunks).
    pub(crate) fn physical_chunks(&self) -> Vec<u32> {
        std::iter::once(self.anchor_phys)
            .chain(self.map.iter().copied().filter(|&p| p != NO_CHUNK))
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn blob_abs(&self, d: &DeviceInner, b: &BlobRef) -> u64 {
        self.blob_offset(d, b).unwrap()
    }

    #[cfg(test)]
    pub(crate) fn blob_refs(&self, id: u64) -> Vec<BlobRef> {
        self.items[&id].content.segments.clone()
    }

    #[cfg(test)]
    pub(crate) fn page_count(&self) -> usize {
        self.pages.len()
    }

    /// Serialized root and single-page item list (fuzz seed corpus).
    #[cfg(all(test, feature = "fuzzing"))]
    pub(crate) fn encoded_root_and_page(&self) -> (SecretVec, SecretVec) {
        let items: Vec<&Item> = self.items.values().collect();
        (index::to_bytes(&self.root), index::to_bytes(&items))
    }

    /// The slot payload of this vault (for re-sealing under a new pattern).
    fn slot_payload(&self) -> SlotPayload {
        SlotPayload {
            flags: self.flags,
            anchor_chunk: self.anchor_phys,
            master_key: self.keys.master.duplicate(),
        }
    }

    pub(crate) fn root_ptr(&self) -> Option<RootPtr> {
        self.root_ptr
    }

    /// Live logical chunks with their content versions.
    pub(crate) fn chunk_versions(&self) -> Vec<(u32, u64)> {
        self.root
            .chunks
            .iter()
            .enumerate()
            .filter_map(|(l, v)| v.map(|v| (l as u32, v)))
            .collect()
    }

    pub(crate) fn read_physical_chunk(&self, d: &DeviceInner, logical: u32) -> Result<Vec<u8>> {
        let phys = *self.map.get(logical as usize).ok_or(Error::Corrupt)?;
        if phys == NO_CHUNK {
            return Err(Error::Corrupt);
        }
        let mut buf = vec![0u8; d.cfg.chunk_size as usize];
        d.storage
            .read_at(u64::from(phys) * u64::from(d.cfg.chunk_size), &mut buf)?;
        Ok(buf)
    }

    // ---------------------------------------------------------------- blocks

    fn blob_offset(&self, d: &DeviceInner, b: &BlobRef) -> Result<u64> {
        let phys = *self.map.get(b.chunk as usize).ok_or(Error::Corrupt)?;
        if phys == NO_CHUNK {
            return Err(Error::Corrupt);
        }
        Ok(u64::from(phys) * u64::from(d.cfg.chunk_size)
            + u64::from(b.block) * u64::from(d.cfg.block_size))
    }

    fn read_blob(&self, d: &DeviceInner, b: &BlobRef) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; b.len as usize];
        d.storage.read_at(self.blob_offset(d, b)?, &mut buf)?;
        Ok(buf)
    }

    /// Validate a blob reference and mark its blocks used (load time).
    fn mark_loaded(&mut self, d: &DeviceInner, b: &BlobRef) -> Result<()> {
        let bpc = d.cfg.blocks_per_chunk();
        let ok = (b.chunk as usize) < self.map.len()
            && self.map[b.chunk as usize] != NO_CHUNK
            && b.nblocks >= 1
            && u32::from(b.block) + u32::from(b.nblocks) <= bpc
            && b.len as u64 <= u64::from(b.nblocks) * u64::from(d.cfg.block_size)
            && (b.len as u64) > (u64::from(b.nblocks) - 1) * u64::from(d.cfg.block_size);
        if !ok {
            return Err(Error::Corrupt);
        }
        let m = run_mask(u32::from(b.block), u32::from(b.nblocks));
        let u = &mut self.used[b.chunk as usize];
        if *u & m != 0 {
            return Err(Error::Corrupt);
        }
        *u |= m;
        Ok(())
    }

    /// Allocate `len` bytes of contiguous blocks (first fit in owned chunks, else a new
    /// random physical chunk).
    fn alloc(&mut self, d: &mut DeviceInner, len: usize) -> Result<BlobRef> {
        let bs = d.cfg.block_size as usize;
        let bpc = d.cfg.blocks_per_chunk();
        let n = len.div_ceil(bs) as u32;
        if n == 0 || n > bpc {
            return Err(Error::NoSpace);
        }
        let mut found = None;
        'outer: for (l, &phys) in self.map.iter().enumerate() {
            if phys == NO_CHUNK {
                continue;
            }
            for start in 0..=bpc - n {
                if self.used[l] & run_mask(start, n) == 0 {
                    found = Some((l as u32, start));
                    break 'outer;
                }
            }
        }
        let (l, start) = match found {
            Some(x) => x,
            None => {
                let phys = d.alloc_chunk()?;
                let l = match self.map.iter().position(|&p| p == NO_CHUNK) {
                    Some(l) => l,
                    None => {
                        self.map.push(NO_CHUNK);
                        self.used.push(0);
                        self.root.chunks.push(None);
                        self.map.len() - 1
                    }
                };
                self.map[l] = phys;
                self.used[l] = 0;
                self.root.chunks[l] = None;
                (l as u32, 0)
            }
        };
        self.used[l as usize] |= run_mask(start, n);
        self.touched.insert(l);
        Ok(BlobRef {
            chunk: l,
            block: start as u16,
            nblocks: n as u16,
            len: len as u32,
        })
    }

    fn write_blob(&mut self, d: &mut DeviceInner, sealed: &[u8]) -> Result<BlobRef> {
        let b = self.alloc(d, sealed.len())?;
        let off = self.blob_offset(d, &b)?;
        d.storage.write_at(off, sealed)?;
        Ok(b)
    }

    fn max_blob(d: &DeviceInner) -> usize {
        d.cfg.chunk_size as usize
    }

    // ---------------------------------------------------------------- pages

    fn page_index(&self, id: u64) -> Option<usize> {
        let i = self.pages.partition_point(|p| p.first_id <= id);
        i.checked_sub(1)
    }

    fn mark_dirty(&mut self, page: usize) {
        if let Some(b) = self.pages[page].blob.take() {
            self.pending_free.push(b);
        }
    }

    fn page_len(&self, page: usize) -> usize {
        let first = self.pages[page].first_id;
        let end = self.pages.get(page + 1).map_or(u64::MAX, |p| p.first_id);
        self.items.range(first..end).count()
    }

    /// Insert an item. Ids are usually the largest so far, but concurrent writers may
    /// finish out of order, so any id is placed in the page covering it.
    fn insert_item(&mut self, item: Item) {
        let id = item.id;
        self.items.insert(id, item);
        match self.page_index(id) {
            Some(p)
                if p + 1 == self.pages.len()
                    && self.page_len(p) > PAGE_ITEMS
                    && self.items.keys().next_back() == Some(&id) =>
            {
                self.pages.push(PageMem {
                    first_id: id,
                    blob: None,
                    generation: 0,
                })
            }
            Some(p) => self.mark_dirty(p),
            None if self.pages.is_empty() => self.pages.push(PageMem {
                first_id: id,
                blob: None,
                generation: 0,
            }),
            None => {
                // Below the first page: extend it downwards (rewritten with the new
                // first_id bound into its AAD).
                self.mark_dirty(0);
                self.pages[0].first_id = id;
            }
        }
    }

    fn touch_item(&mut self, id: u64) -> Result<&mut Item> {
        let p = self.page_index(id).ok_or(Error::NotFound)?;
        if !self.items.contains_key(&id) {
            return Err(Error::NotFound);
        }
        self.mark_dirty(p);
        self.items.get_mut(&id).ok_or(Error::NotFound)
    }

    fn remove_item(&mut self, id: u64) -> Result<Item> {
        let p = self.page_index(id).ok_or(Error::NotFound)?;
        let item = self.items.remove(&id).ok_or(Error::NotFound)?;
        self.mark_dirty(p);
        if self.page_len(p) == 0 {
            self.pages.remove(p);
        }
        Ok(item)
    }

    // ---------------------------------------------------------------- commit

    fn build_root(&self, generation: u64, live: &[bool], freed: &BTreeSet<u32>) -> Result<Root> {
        let mut chunks = Vec::with_capacity(self.map.len());
        for (l, &is_live) in live.iter().enumerate() {
            chunks.push(if !is_live {
                None
            } else if self.touched.contains(&(l as u32)) || freed.contains(&(l as u32)) {
                Some(generation)
            } else {
                Some(
                    self.root
                        .chunks
                        .get(l)
                        .copied()
                        .flatten()
                        .ok_or(Error::Corrupt)?,
                )
            });
        }
        while chunks.last() == Some(&None) {
            chunks.pop();
        }
        let pages = self
            .pages
            .iter()
            .map(|p| {
                Ok(PageRef {
                    first_id: p.first_id,
                    blob: p.blob.ok_or(Error::Corrupt)?,
                    generation: p.generation,
                })
            })
            .collect::<Result<_>>()?;
        Ok(Root {
            version: INDEX_VERSION,
            generation,
            next_item_id: self.root.next_item_id,
            next_album_id: self.root.next_album_id,
            next_tag_id: self.root.next_tag_id,
            chunks,
            pages,
            albums: self.root.albums.clone(),
            tags: self.root.tags.clone(),
            next_decoy_id: self.root.next_decoy_id,
            decoys: self.root.decoys.clone(),
            entry_keys: self.root.entry_keys.clone(),
            name: self.root.name.clone(),
        })
    }

    /// Persist all in-memory changes (see module docs for the protocol).
    pub(crate) fn commit(&mut self, d: &mut DeviceInner) -> Result<()> {
        let g = self.root_ptr.map_or(0, |r| r.generation) + 1;

        // 1. Dirty pages (split pages that would not fit one chunk).
        let mut i = 0;
        while i < self.pages.len() {
            if self.pages[i].blob.is_some() {
                i += 1;
                continue;
            }
            let first = self.pages[i].first_id;
            let end = self.pages.get(i + 1).map_or(u64::MAX, |p| p.first_id);
            let items: Vec<&Item> = self.items.range(first..end).map(|(_, v)| v).collect();
            let pt = index::to_bytes(&items);
            if pt.len() + AEAD_OVERHEAD > Self::max_blob(d) {
                if items.len() < 2 {
                    return Err(Error::NoSpace);
                }
                let mid = items[items.len() / 2].id;
                self.pages.insert(
                    i + 1,
                    PageMem {
                        first_id: mid,
                        blob: None,
                        generation: 0,
                    },
                );
                continue;
            }
            let sealed = crypto::seal(&self.keys.index, &self.keys.page_aad(first, g), &pt);
            let b = self.write_blob(d, &sealed)?;
            self.pages[i].blob = Some(b);
            self.pages[i].generation = g;
            i += 1;
        }

        // 2. Root. Superseded root is freed after the switch.
        if let Some(old) = self.root_ptr {
            self.pending_free.push(old.blob);
        }
        let mut freed_mask = vec![0u64; self.map.len()];
        let mut freed_chunks = BTreeSet::new();
        for b in &self.pending_free {
            freed_mask[b.chunk as usize] |= run_mask(u32::from(b.block), u32::from(b.nblocks));
            freed_chunks.insert(b.chunk);
        }
        let mut est = index::to_bytes(&self.build_root_estimate(g)).len() + AEAD_OVERHEAD;
        let (root, root_blob) = loop {
            let blob = self.alloc(d, est)?;
            freed_mask.resize(self.map.len(), 0);
            let live: Vec<bool> = (0..self.map.len())
                .map(|l| self.map[l] != NO_CHUNK && self.used[l] & !freed_mask[l] != 0)
                .collect();
            let root = self.build_root(g, &live, &freed_chunks)?;
            let pt = index::to_bytes(&root);
            let sealed = crypto::seal(&self.keys.index, &self.keys.root_aad(g), &pt);
            if sealed.len() <= usize::from(blob.nblocks) * d.cfg.block_size as usize {
                // The estimate can cross a block boundary even when the final root
                // does not. BlobRefs must describe exactly the blocks their bytes
                // occupy, as enforced by mark_loaded on reopen and restore.
                let nblocks = sealed.len().div_ceil(d.cfg.block_size as usize) as u16;
                if nblocks < blob.nblocks {
                    self.used[blob.chunk as usize] &= !run_mask(
                        u32::from(blob.block) + u32::from(nblocks),
                        u32::from(blob.nblocks - nblocks),
                    );
                }
                let blob = BlobRef {
                    len: sealed.len() as u32,
                    nblocks,
                    ..blob
                };
                d.storage.write_at(self.blob_offset(d, &blob)?, &sealed)?;
                break (root, blob);
            }
            // Estimate too small: give the blocks back (never written) and retry.
            self.used[blob.chunk as usize] &=
                !run_mask(u32::from(blob.block), u32::from(blob.nblocks));
            est = sealed.len() + d.cfg.block_size as usize;
        };

        // 3. Anchor (the commit point), after the bitmap is durable.
        // The root's chunk table and the anchor map always have the same length:
        // both drop trailing unused ids.
        let new_map: Vec<u32> = (0..root.chunks.len())
            .map(|l| {
                if root.chunks[l].is_some() {
                    self.map[l]
                } else {
                    NO_CHUNK
                }
            })
            .collect();
        let root_ptr = RootPtr {
            generation: g,
            blob: root_blob,
        };
        d.persist()?;
        d.storage.sync()?;
        self.write_anchor(d, root_ptr, self.uploaded, new_map.clone())?;
        d.storage.sync()?;

        // Switched: adopt the new state.
        let old_map = std::mem::replace(&mut self.map, new_map);
        self.root = root;
        self.root_ptr = Some(root_ptr);

        // 4. Scrub superseded blocks, release emptied chunks, cover traffic.
        for b in std::mem::take(&mut self.pending_free) {
            let m = run_mask(u32::from(b.block), u32::from(b.nblocks));
            if (b.chunk as usize) < self.map.len() && self.map[b.chunk as usize] != NO_CHUNK {
                self.used[b.chunk as usize] &= !m;
                let mut junk = vec![0u8; usize::from(b.nblocks) * d.cfg.block_size as usize];
                rng::fill_bulk(&mut junk);
                let off = self.blob_offset(d, &b)?;
                d.storage.write_at(off, &junk)?;
            }
        }
        for (l, &phys) in old_map.iter().enumerate() {
            if phys != NO_CHUNK && self.map.get(l).is_none_or(|&p| p == NO_CHUNK) {
                d.release_chunk(phys)?;
            }
        }
        self.used.truncate(self.map.len());
        for (l, u) in self.used.iter_mut().enumerate() {
            if self.map[l] == NO_CHUNK {
                *u = 0;
            }
        }
        self.touched.clear();
        d.cover_traffic()?;
        d.persist()?;
        d.storage.sync()
    }

    fn build_root_estimate(&self, g: u64) -> Root {
        let mut r = self.root.clone();
        r.generation = g;
        r.chunks.resize(self.map.len() + 1, Some(g));
        r.pages = self
            .pages
            .iter()
            .map(|p| PageRef {
                first_id: p.first_id,
                blob: p.blob.unwrap_or(BlobRef {
                    chunk: u32::MAX,
                    block: u16::MAX,
                    nblocks: u16::MAX,
                    len: u32::MAX,
                }),
                generation: g,
            })
            .collect();
        r
    }

    pub(crate) fn write_anchor(
        &mut self,
        d: &mut DeviceInner,
        root: RootPtr,
        uploaded: Option<RootPtr>,
        map: Vec<u32>,
    ) -> Result<()> {
        let gen_ = self.anchor_gen + 1;
        let rec = AnchorRecord {
            version: index::ANCHOR_VERSION,
            generation: gen_,
            root,
            uploaded,
            map,
        };
        let copy = gen_ % 2;
        let pt = index::to_padded(&rec, d.cfg.anchor_plain_len())?;
        let mut out = vec![0u8; pt.len() + AEAD_OVERHEAD];
        crypto::seal_into(
            &self.keys.anchor,
            &self.keys.anchor_aad(copy),
            &pt,
            &mut out,
        );
        let off = u64::from(self.anchor_phys) * u64::from(d.cfg.chunk_size)
            + copy * u64::from(d.cfg.chunk_size / 2);
        d.storage.write_at(off, &out)?;
        self.anchor_gen = gen_;
        self.uploaded = uploaded;
        Ok(())
    }

    // ---------------------------------------------------------------- load

    /// Find a live vault's anchor chunk from its master key by trial-decrypting the
    /// anchor records of all allocated chunks.
    pub(crate) fn locate_anchor(d: &DeviceInner, master: &SecretKey) -> Option<u32> {
        let keys = VaultKeys::derive(master);
        (d.cfg.superblock_chunks()..d.state.total_chunks)
            .filter(|&c| d.is_allocated(c))
            .find(|&c| VaultState::read_anchor(d, &keys, c).is_ok())
    }

    pub(crate) fn read_anchor(
        d: &DeviceInner,
        keys: &VaultKeys,
        phys: u32,
    ) -> Result<AnchorRecord> {
        let len = d.cfg.anchor_plain_len() + AEAD_OVERHEAD;
        let mut best: Option<AnchorRecord> = None;
        for copy in 0..2u64 {
            let mut buf = vec![0u8; len];
            let off = u64::from(phys) * u64::from(d.cfg.chunk_size)
                + copy * u64::from(d.cfg.chunk_size / 2);
            d.storage.read_at(off, &mut buf)?;
            let Ok(pt) = crypto::open(&keys.anchor, &keys.anchor_aad(copy), &buf) else {
                continue;
            };
            let rec: AnchorRecord = index::from_padded(&pt)?;
            if rec.generation % 2 != copy || rec.version != index::ANCHOR_VERSION {
                return Err(Error::Corrupt);
            }
            if best.as_ref().is_none_or(|b| rec.generation > b.generation) {
                best = Some(rec);
            }
        }
        best.ok_or(Error::Corrupt)
    }

    /// Load an existing vault from its anchor.
    pub(crate) fn load(d: &DeviceInner, slot: u8, payload: &SlotPayload) -> Result<Self> {
        let mut s = Self::blank(slot, payload, d.epoch);
        let total = d.state.total_chunks;
        let sb = d.cfg.superblock_chunks();
        if s.anchor_phys < sb || s.anchor_phys >= total || !d.is_allocated(s.anchor_phys) {
            return Err(Error::Corrupt);
        }
        let rec = Self::read_anchor(d, &s.keys, s.anchor_phys)?;
        let mut seen = BTreeSet::from([s.anchor_phys]);
        for &p in rec.map.iter().filter(|&&p| p != NO_CHUNK) {
            if p < sb || p >= total || !d.is_allocated(p) || !seen.insert(p) {
                return Err(Error::Corrupt);
            }
        }
        s.anchor_gen = rec.generation;
        s.uploaded = rec.uploaded;
        s.map = rec.map;
        s.used = vec![0; s.map.len()];
        s.load_index(d, rec.root)?;
        Ok(s)
    }

    fn load_index(&mut self, d: &DeviceInner, ptr: RootPtr) -> Result<()> {
        self.mark_loaded(d, &ptr.blob)?;
        let sealed = self.read_blob(d, &ptr.blob)?;
        let pt = crypto::open(
            &self.keys.index,
            &self.keys.root_aad(ptr.generation),
            &sealed,
        )?;
        let root: Root = index::from_bytes(&pt)?;
        let live_ok = root.chunks.len() == self.map.len()
            && root
                .chunks
                .iter()
                .zip(&self.map)
                .all(|(v, &p)| v.is_some() == (p != NO_CHUNK));
        if root.version != INDEX_VERSION || root.generation != ptr.generation || !live_ok {
            return Err(Error::Corrupt);
        }
        let mut prev_first = None;
        for (i, pr) in root.pages.iter().enumerate() {
            if prev_first.is_some_and(|p| pr.first_id <= p) || pr.generation > root.generation {
                return Err(Error::Corrupt);
            }
            prev_first = Some(pr.first_id);
            self.mark_loaded(d, &pr.blob)?;
            let sealed = self.read_blob(d, &pr.blob)?;
            let pt = crypto::open(
                &self.keys.index,
                &self.keys.page_aad(pr.first_id, pr.generation),
                &sealed,
            )?;
            let items: Vec<Item> = index::from_bytes(&pt)?;
            let end = root.pages.get(i + 1).map_or(u64::MAX, |p| p.first_id);
            if items.is_empty() {
                return Err(Error::Corrupt);
            }
            for it in items {
                let in_range = it.id >= pr.first_id && it.id < end && it.id < root.next_item_id;
                if !in_range || self.items.keys().next_back().is_some_and(|&l| l >= it.id) {
                    return Err(Error::Corrupt);
                }
                self.check_stream(d, &it.content)?;
                if let Some(t) = &it.thumbnail {
                    self.check_stream(d, t)?;
                }
                self.items.insert(it.id, it);
            }
            self.pages.push(PageMem {
                first_id: pr.first_id,
                blob: Some(pr.blob),
                generation: pr.generation,
            });
        }
        self.root = root;
        self.root_ptr = Some(ptr);
        Ok(())
    }

    fn check_stream(&mut self, d: &DeviceInner, s: &Stream) -> Result<()> {
        let sp = d.cfg.segment_plain_len();
        if s.segments.len() as u64 != s.size.div_ceil(sp) {
            return Err(Error::Corrupt);
        }
        for (i, b) in s.segments.iter().enumerate() {
            if u64::from(b.len) != seg_plain_len(s.size, sp, i as u64) + AEAD_OVERHEAD as u64 {
                return Err(Error::Corrupt);
            }
            self.mark_loaded(d, b)?;
        }
        Ok(())
    }

    /// Restore from cloud objects into fresh chunks and write the first anchor.
    pub(crate) fn restore(
        d: &mut DeviceInner,
        slot: u8,
        payload: &SlotPayload,
        root_ptr: RootPtr,
        listing: &[String],
        source: &dyn ObjectSource,
    ) -> Result<()> {
        let mut s = Self::blank(slot, payload, d.epoch);
        // Bound everything taken from the (authenticated, but still external) entry by
        // the geometry before allocating.
        let max_chunks = d.cfg.max_chunks();
        let b = root_ptr.blob;
        let bs = u64::from(d.cfg.block_size);
        let ptr_ok = b.chunk < max_chunks
            && b.nblocks >= 1
            && u32::from(b.block) + u32::from(b.nblocks) <= d.cfg.blocks_per_chunk()
            && u64::from(b.len) <= u64::from(b.nblocks) * bs
            && u64::from(b.len) > (u64::from(b.nblocks) - 1) * bs;
        if !ptr_ok {
            return Err(Error::Corrupt);
        }
        let names = backup::our_objects(&s.keys, listing);
        let chunk_size = d.cfg.chunk_size as usize;
        let place = |s: &mut Self, d: &mut DeviceInner, l: u32, v: u64| -> Result<()> {
            if l >= max_chunks {
                return Err(Error::Corrupt);
            }
            let name = names.get(&(l, v)).ok_or(Error::NotFound)?;
            let bytes = source.get(name)?;
            if bytes.len() != chunk_size {
                return Err(Error::Corrupt);
            }
            let phys = d.alloc_chunk()?;
            if s.map.len() <= l as usize {
                s.map.resize(l as usize + 1, NO_CHUNK);
            }
            if s.map[l as usize] != NO_CHUNK {
                return Err(Error::Corrupt);
            }
            s.map[l as usize] = phys;
            d.storage
                .write_at(u64::from(phys) * chunk_size as u64, &bytes)?;
            Ok(())
        };
        // Root chunk first, to learn the chunk table.
        let rl = root_ptr.blob.chunk;
        place(&mut s, d, rl, root_ptr.generation)?;
        let sealed = {
            s.used = vec![0; s.map.len()];
            s.read_blob(d, &root_ptr.blob)?
        };
        let pt = crypto::open(
            &s.keys.index,
            &s.keys.root_aad(root_ptr.generation),
            &sealed,
        )?;
        let root: Root = index::from_bytes(&pt)?;
        if root.chunks.len() > max_chunks as usize
            || root.chunks.get(rl as usize).copied().flatten() != Some(root_ptr.generation)
        {
            return Err(Error::Corrupt);
        }
        for (l, v) in root.chunks.iter().enumerate() {
            if let Some(v) = *v
                && l as u32 != rl
            {
                place(&mut s, d, l as u32, v)?;
            }
        }
        s.map.resize(root.chunks.len(), NO_CHUNK);
        // Fully verify before committing anything.
        let map = s.map.clone();
        s.used = vec![0; s.map.len()];
        s.load_index(d, root_ptr)?;
        d.persist()?;
        d.storage.sync()?;
        s.write_anchor(d, root_ptr, Some(root_ptr), map)?;
        d.storage.sync()
    }

    // ---------------------------------------------------------------- streams

    fn write_segment(&mut self, d: &mut DeviceInner, aad: &[u8], plain: &[u8]) -> Result<BlobRef> {
        let sealed = crypto::seal(&self.keys.content, aad, plain);
        self.write_blob(d, &sealed)
    }

    fn read_segment(
        &self,
        d: &DeviceInner,
        item: u64,
        kind: u8,
        s: &Stream,
        index: usize,
    ) -> Result<SecretVec> {
        let sp = d.cfg.segment_plain_len();
        let b = s.segments.get(index).ok_or(Error::Corrupt)?;
        let bound = (!s.streamed).then_some((s.segments.len() as u32, s.size));
        let aad = self.keys.stream_seg_aad(item, kind, index as u32, bound);
        let pt = crypto::open(&self.keys.content, &aad, &self.read_blob(d, b)?)?;
        if pt.len() as u64 != seg_plain_len(s.size, sp, index as u64) {
            return Err(Error::Corrupt);
        }
        Ok(pt)
    }

    fn read_range(
        &self,
        d: &DeviceInner,
        item: u64,
        kind: u8,
        s: &Stream,
        offset: u64,
        len: u64,
    ) -> Result<Vec<u8>> {
        let sp = d.cfg.segment_plain_len();
        if offset >= s.size || len == 0 {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(len).min(s.size);
        let mut out = Vec::with_capacity((end - offset) as usize);
        for i in offset / sp..=(end - 1) / sp {
            let seg = self.read_segment(d, item, kind, s, i as usize)?;
            let seg_start = i * sp;
            let a = (offset.max(seg_start) - seg_start) as usize;
            let b = (end.min(seg_start + sp) - seg_start) as usize;
            out.extend_from_slice(&seg[a..b]);
        }
        Ok(out)
    }

    fn write_whole_stream(
        &mut self,
        d: &mut DeviceInner,
        item: u64,
        kind: u8,
        data: &[u8],
    ) -> Result<Stream> {
        let sp = d.cfg.segment_plain_len() as usize;
        let count = data.len().div_ceil(sp) as u32;
        let mut segments = Vec::with_capacity(count as usize);
        for (i, part) in data.chunks(sp).enumerate() {
            let aad = self
                .keys
                .seg_aad(item, kind, i as u32, count, data.len() as u64);
            segments.push(self.write_segment(d, &aad, part)?);
        }
        Ok(Stream {
            size: data.len() as u64,
            segments,
            streamed: false,
        })
    }

    fn free_stream(&mut self, s: &Stream) {
        self.pending_free.extend_from_slice(&s.segments);
    }

    fn check_live(&self, d: &DeviceInner) -> Result<()> {
        if self.poisoned
            || self.epoch != d.epoch
            || self.handle_generation != d.vault_handle_generations[self.slot as usize]
        {
            return Err(Error::Locked);
        }
        Ok(())
    }
}

/// Item, album and tag names are capped before any state is touched, so an
/// oversize name is a plain `InvalidArgument` and never poisons the handle.
fn check_name(name: &str) -> Result<()> {
    if name.len() > index::MAX_NAME_LEN {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

/// Plaintext length of segment `i` of a stream of `size` bytes.
fn seg_plain_len(size: u64, sp: u64, i: u64) -> u64 {
    (size - i * sp).min(sp)
}

// =========================================================================== public API

/// Metadata for a new item.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct NewItem {
    /// File name.
    pub name: String,
    /// MIME type.
    pub mime: String,
    /// Creation time (Unix seconds).
    pub created: i64,
    /// Modification time (Unix seconds).
    pub modified: i64,
    /// Album ids.
    pub albums: Vec<u32>,
    /// Tag ids.
    pub tags: Vec<u32>,
    /// Opaque app metadata, ≤ 4096 bytes.
    pub extra: Vec<u8>,
}

impl fmt::Debug for NewItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NewItem([REDACTED])")
    }
}

/// Item metadata as returned to the app.
#[derive(Clone, PartialEq, Eq)]
pub struct ItemInfo {
    /// Id.
    pub id: u64,
    /// File name.
    pub name: String,
    /// MIME type.
    pub mime: String,
    /// Plaintext size.
    pub size: u64,
    /// Creation time.
    pub created: i64,
    /// Modification time.
    pub modified: i64,
    /// Album ids.
    pub albums: Vec<u32>,
    /// Tag ids.
    pub tags: Vec<u32>,
    /// Whether a thumbnail is stored.
    pub has_thumbnail: bool,
    /// Opaque app metadata.
    pub extra: Vec<u8>,
}

impl fmt::Debug for ItemInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemInfo")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl From<&Item> for ItemInfo {
    fn from(i: &Item) -> Self {
        ItemInfo {
            id: i.id,
            name: i.name.clone(),
            mime: i.mime.clone(),
            size: i.content.size,
            created: i.created,
            modified: i.modified,
            albums: i.albums.clone(),
            tags: i.tags.clone(),
            has_thumbnail: i.thumbnail.is_some(),
            extra: i.extra.clone(),
        }
    }
}

/// A duress vault linked to its owner, as returned to the app.
#[derive(Clone, PartialEq, Eq)]
pub struct DecoyInfo {
    /// Link id (for [`Vault::open_managed_decoy`]).
    pub id: u32,
    /// Cached display name; empty if unset.
    pub name: String,
}

impl fmt::Debug for DecoyInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecoyInfo")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Album or tag as returned to the app.
#[derive(Clone, PartialEq, Eq)]
pub struct Label {
    /// Id.
    pub id: u32,
    /// Name.
    pub name: String,
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Label")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

pub(crate) struct VaultShared {
    dev: Arc<Mutex<DeviceInner>>,
    state: Mutex<VaultState>,
    /// For a decoy opened via [`Vault::open_managed_decoy`]: the owner and link id.
    owner: Option<(Arc<VaultShared>, u32)>,
}

/// An unlocked vault. Dropping it zeroizes its keys and in-memory index.
/// All methods take `&self` and are thread-safe.
pub struct Vault {
    shared: Arc<VaultShared>,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Vault([REDACTED])")
    }
}

fn lock_state(s: &Mutex<VaultState>) -> Result<MutexGuard<'_, VaultState>> {
    s.lock().map_err(|_| Error::Locked)
}

impl VaultShared {
    /// Run a read-only operation.
    fn read<T>(&self, f: impl FnOnce(&VaultState, &DeviceInner) -> Result<T>) -> Result<T> {
        let s = lock_state(&self.state)?;
        let d = lock(&self.dev)?;
        s.check_live(&d)?;
        f(&s, &d)
    }

    /// Run a mutating operation. Validation errors (`NotFound`, `InvalidArgument`)
    /// must be raised before any state change; any other error poisons the handle so
    /// the in-memory state can never diverge from disk (re-unlock to recover).
    fn write<T>(
        &self,
        f: impl FnOnce(&mut VaultState, &mut DeviceInner) -> Result<T>,
    ) -> Result<T> {
        let mut s = lock_state(&self.state)?;
        let mut d = lock(&self.dev)?;
        s.check_live(&d)?;
        let r = f(&mut s, &mut d);
        if let Err(e) = &r
            && !matches!(
                e,
                Error::NotFound
                    | Error::InvalidArgument
                    | Error::Pattern(_)
                    | Error::PatternBlocklisted
                    | Error::PatternInUse
                    | Error::NoFreeSlot
                    | Error::RetryLater
                    | Error::InvalidPhrase
            )
        {
            s.poisoned = true;
        }
        r
    }
}

impl Vault {
    pub(crate) fn new(dev: Arc<Mutex<DeviceInner>>, state: VaultState) -> Self {
        Self::with_owner(dev, state, None)
    }

    fn with_owner(
        dev: Arc<Mutex<DeviceInner>>,
        state: VaultState,
        owner: Option<(Arc<VaultShared>, u32)>,
    ) -> Self {
        Vault {
            shared: Arc::new(VaultShared {
                dev,
                state: Mutex::new(state),
                owner,
            }),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_internals<T>(
        &self,
        f: impl FnOnce(&mut VaultState, &mut DeviceInner) -> T,
    ) -> T {
        let mut s = self.shared.state.lock().unwrap();
        let mut d = self.shared.dev.lock().unwrap();
        f(&mut s, &mut d)
    }

    /// Lock now: zeroize the in-memory index and replace the keys, independent of when
    /// the last reference (e.g. a foreign-language handle) is dropped. Further calls on
    /// this handle (and its writers) return `Locked`.
    pub fn lock(&self) {
        if let Ok(mut s) = self.shared.state.lock() {
            s.poisoned = true;
            for it in s.items.values_mut() {
                it.zeroize();
            }
            s.items.clear();
            let st = &mut *s;
            st.root.albums.iter_mut().for_each(Zeroize::zeroize);
            st.root.tags.iter_mut().for_each(Zeroize::zeroize);
            st.root.decoys.iter_mut().for_each(Zeroize::zeroize);
            st.root.entry_keys.iter_mut().for_each(Zeroize::zeroize);
            st.root.name.zeroize();
            st.keys = VaultKeys::derive(&SecretKey::random());
        }
    }

    /// All items, ordered by id.
    pub fn list_items(&self) -> Result<Vec<ItemInfo>> {
        self.shared
            .read(|s, _| Ok(s.items.values().map(ItemInfo::from).collect()))
    }

    /// Number of items.
    pub fn item_count(&self) -> Result<u64> {
        self.shared.read(|s, _| Ok(s.items.len() as u64))
    }

    /// One item.
    pub fn item(&self, id: u64) -> Result<ItemInfo> {
        self.shared
            .read(|s, _| s.items.get(&id).map(ItemInfo::from).ok_or(Error::NotFound))
    }

    /// Random-access read of item content (for streaming): up to `len` bytes at `offset`.
    /// Only the covering segments are read and authenticated.
    pub fn read(&self, id: u64, offset: u64, len: u64) -> Result<Vec<u8>> {
        self.shared.read(|s, d| {
            let it = s.items.get(&id).ok_or(Error::NotFound)?;
            s.read_range(d, id, KIND_CONTENT, &it.content, offset, len)
        })
    }

    /// The item's thumbnail, if any.
    pub fn thumbnail(&self, id: u64) -> Result<Option<Vec<u8>>> {
        self.shared.read(|s, d| {
            let it = s.items.get(&id).ok_or(Error::NotFound)?;
            it.thumbnail
                .as_ref()
                .map(|t| s.read_range(d, id, KIND_THUMBNAIL, t, 0, t.size))
                .transpose()
        })
    }

    /// Import a whole file held in memory.
    pub fn import(&self, meta: NewItem, data: &[u8], thumbnail: Option<&[u8]>) -> Result<u64> {
        let mut w = self.begin_import(meta, data.len() as u64)?;
        w.write(data)?;
        w.finish(thumbnail)
    }

    /// Start a streaming import of exactly `size` bytes.
    pub fn begin_import(&self, meta: NewItem, size: u64) -> Result<ItemWriter> {
        self.start_import(meta, Some(size))
    }

    /// Start a streaming import whose size is only known at `finish` (camera
    /// recording).
    pub fn begin_import_unsized(&self, meta: NewItem) -> Result<ItemWriter> {
        self.start_import(meta, None)
    }

    fn start_import(&self, meta: NewItem, size: Option<u64>) -> Result<ItemWriter> {
        if meta.extra.len() > index::MAX_EXTRA || meta.mime.len() > index::MAX_MIME_LEN {
            return Err(Error::InvalidArgument);
        }
        check_name(&meta.name)?;
        let (id, sp) = self.shared.write(|s, d| {
            let id = s.root.next_item_id;
            s.root.next_item_id += 1;
            Ok((id, d.cfg.segment_plain_len() as usize))
        })?;
        Ok(ItemWriter {
            shared: self.shared.clone(),
            id,
            meta,
            size,
            written: 0,
            // Fixed capacity of one segment: the buffer never reallocates, so no
            // plaintext copies are left behind in freed memory.
            buf: SecretVec::new(Vec::with_capacity(sp)),
            segments: Vec::new(),
            finished: false,
        })
    }

    /// Store or replace an item's thumbnail after import, e.g. one generated
    /// later for a document. Same encryption and AAD binding as import-time thumbnails;
    /// the old thumbnail is scrubbed after the commit. Empty `bytes` removes it.
    /// At most [`index::MAX_THUMBNAIL_LEN`] bytes.
    pub fn set_thumbnail(&self, id: u64, bytes: &[u8]) -> Result<()> {
        if bytes.len() > index::MAX_THUMBNAIL_LEN {
            return Err(Error::InvalidArgument);
        }
        self.shared.write(|s, d| {
            if !s.items.contains_key(&id) {
                return Err(Error::NotFound);
            }
            let new = if bytes.is_empty() {
                None
            } else {
                Some(s.write_whole_stream(d, id, KIND_THUMBNAIL, bytes)?)
            };
            let old = std::mem::replace(&mut s.touch_item(id)?.thumbnail, new);
            if let Some(t) = old {
                s.free_stream(&t);
            }
            s.commit(d)
        })
    }

    /// Replace an item's content in place, e.g. a text file edited in the app.
    /// Id, name, MIME type, albums, tags, `extra`, created time and thumbnail are kept;
    /// size is updated and `modified` is set to the caller's `modified` (Unix seconds,
    /// caller-defined like [`NewItem::modified`]).
    /// New segments are written like a sized import (same keys and AAD binding) to
    /// blocks free in the committed state; the switch is one commit, so a crash leaves
    /// either the old or the new content, never a mix. The old segments are scrubbed
    /// after the commit, as on delete. At most [`index::MAX_REPLACE_LEN`] (16 MiB)
    /// bytes, else `InvalidArgument`.
    ///
    /// Each [`Vault::read`] call sees either the old or the new content in full. A
    /// reader spanning several calls may see the old content in some and the new in
    /// others (or a short read at the new end); compare [`Vault::item`] before and
    /// after to detect that.
    pub fn replace_content(&self, id: u64, bytes: &[u8], modified: i64) -> Result<()> {
        if bytes.len() > index::MAX_REPLACE_LEN {
            return Err(Error::InvalidArgument);
        }
        self.shared.write(|s, d| {
            if !s.items.contains_key(&id) {
                return Err(Error::NotFound);
            }
            let new = s.write_whole_stream(d, id, KIND_CONTENT, bytes)?;
            let it = s.touch_item(id)?;
            let old = std::mem::replace(&mut it.content, new);
            it.modified = modified;
            s.free_stream(&old);
            s.commit(d)
        })
    }

    /// Replace an item's opaque metadata (≤ 4096 bytes).
    pub fn set_item_extra(&self, id: u64, extra: &[u8]) -> Result<()> {
        if extra.len() > index::MAX_EXTRA {
            return Err(Error::InvalidArgument);
        }
        self.shared.write(|s, d| {
            let it = s.touch_item(id)?;
            it.extra.zeroize();
            it.extra = extra.to_vec();
            s.commit(d)
        })
    }

    /// Whether this vault can publish an authentic backup entry (holds its entry key).
    /// Vaults created inside a duress vault start without one, so a coercer in the
    /// decoy cannot forge entries for other indices.
    pub fn backup_enabled(&self) -> Result<bool> {
        self.shared.read(|s, _| Ok(s.entry_key(s.slot).is_some()))
    }

    /// Give this vault its backup entry keys using the phrase: all 16 for a normal
    /// vault (so vaults it creates are backed up too), only its own for a duress vault.
    /// Also refreshes its local manifest entry for phrase recovery.
    pub fn enable_backup(&self, phrase: &crate::RecoveryPhrase) -> Result<()> {
        let pk = phrase.backup_keypair().pk;
        self.shared.write(|s, d| {
            if pk != d.state.backup_pk {
                return Err(Error::InvalidPhrase);
            }
            let all: Vec<EntryKey> = (0..crate::slots::SLOT_COUNT as u8)
                .map(|i| EntryKey {
                    index: i,
                    key: *phrase.entry_auth_key(i).expose(),
                })
                .collect();
            s.root.entry_keys = child_entry_keys(&all, s.slot, s.flags & FLAG_DURESS != 0);
            s.commit(d)?;
            let root = s.root_ptr().ok_or(Error::Corrupt)?;
            let entry = backup::vault_entry(&pk, s, root)?;
            d.write_local_entry(s.slot, &entry)?;
            d.storage.sync()
        })
    }

    /// Current wipe-after-N-failures setting (0 = off).
    pub fn wipe_after(&self) -> Result<u32> {
        self.shared.read(|_, d| Ok(d.state.wipe_after))
    }

    /// Rename an item (≤ [`index::MAX_NAME_LEN`] bytes, else `InvalidArgument`).
    pub fn rename_item(&self, id: u64, name: &str) -> Result<()> {
        check_name(name)?;
        self.shared.write(|s, d| {
            s.touch_item(id)?.name = name.to_owned();
            s.commit(d)
        })
    }

    /// Replace an item's albums and tags.
    pub fn set_item_labels(&self, id: u64, albums: &[u32], tags: &[u32]) -> Result<()> {
        self.shared.write(|s, d| {
            let it = s.touch_item(id)?;
            it.albums = albums.to_vec();
            it.tags = tags.to_vec();
            s.commit(d)
        })
    }

    /// Delete an item; its blocks are scrubbed after the commit.
    pub fn delete_item(&self, id: u64) -> Result<()> {
        self.shared.write(|s, d| {
            let mut it = s.remove_item(id)?;
            s.free_stream(&it.content);
            if let Some(t) = &it.thumbnail {
                s.free_stream(t);
            }
            it.zeroize();
            s.commit(d)
        })
    }

    /// Create an album (name ≤ [`index::MAX_NAME_LEN`] bytes, else `InvalidArgument`).
    pub fn create_album(&self, name: &str, created: i64) -> Result<u32> {
        check_name(name)?;
        self.shared.write(|s, d| {
            let id = s.root.next_album_id;
            s.root.next_album_id += 1;
            s.root.albums.push(index::Album {
                id,
                name: name.to_owned(),
                created,
            });
            s.commit(d)?;
            Ok(id)
        })
    }

    /// Create a tag (name ≤ [`index::MAX_NAME_LEN`] bytes, else `InvalidArgument`).
    pub fn create_tag(&self, name: &str) -> Result<u32> {
        check_name(name)?;
        self.shared.write(|s, d| {
            let id = s.root.next_tag_id;
            s.root.next_tag_id += 1;
            s.root.tags.push(index::Tag {
                id,
                name: name.to_owned(),
            });
            s.commit(d)?;
            Ok(id)
        })
    }

    /// Albums.
    pub fn albums(&self) -> Result<Vec<Label>> {
        self.shared.read(|s, _| {
            Ok(s.root
                .albums
                .iter()
                .map(|a| Label {
                    id: a.id,
                    name: a.name.clone(),
                })
                .collect())
        })
    }

    /// Tags.
    pub fn tags(&self) -> Result<Vec<Label>> {
        self.shared.read(|s, _| {
            Ok(s.root
                .tags
                .iter()
                .map(|t| Label {
                    id: t.id,
                    name: t.name.clone(),
                })
                .collect())
        })
    }

    /// Delete an album or tag (`album = true` for albums) and remove it from all items.
    pub fn delete_label(&self, album: bool, id: u32) -> Result<()> {
        self.shared.write(|s, d| {
            let pos = if album {
                s.root.albums.iter().position(|a| a.id == id)
            } else {
                s.root.tags.iter().position(|t| t.id == id)
            }
            .ok_or(Error::NotFound)?;
            if album {
                s.root.albums.remove(pos).zeroize();
            } else {
                s.root.tags.remove(pos).zeroize();
            }
            let affected: Vec<u64> = s
                .items
                .values()
                .filter(|it| if album { &it.albums } else { &it.tags }.contains(&id))
                .map(|it| it.id)
                .collect();
            for item in affected {
                let it = s.touch_item(item)?;
                if album {
                    it.albums.retain(|&a| a != id);
                } else {
                    it.tags.retain(|&t| t != id);
                }
            }
            s.commit(d)
        })
    }

    /// Rename an album or tag (≤ [`index::MAX_NAME_LEN`] bytes, else `InvalidArgument`).
    pub fn rename_label(&self, album: bool, id: u32, name: &str) -> Result<()> {
        check_name(name)?;
        self.shared.write(|s, d| {
            let slot = if album {
                s.root
                    .albums
                    .iter_mut()
                    .find(|a| a.id == id)
                    .map(|a| &mut a.name)
            } else {
                s.root
                    .tags
                    .iter_mut()
                    .find(|t| t.id == id)
                    .map(|t| &mut t.name)
            }
            .ok_or(Error::NotFound)?;
            slot.zeroize();
            *slot = name.to_owned();
            s.commit(d)
        })
    }

    /// Create another vault with its own pattern (requires an unlocked vault) and return
    /// it open. With `duress = true` the new vault is a decoy: unlocking it by pattern
    /// destroys all other slots. This vault records a link to it, so its content
    /// can later be managed via [`Vault::open_managed_decoy`] without the wipe.
    pub fn create_vault(&self, pattern: &Pattern, duress: bool) -> Result<Vault> {
        let flags = if duress { FLAG_DURESS } else { 0 };
        let (state, link) = self.shared.write(|s, d| {
            let parent_keys = s.entry_keys().to_vec();
            let st = d.create_vault(pattern, flags, &parent_keys)?;
            if !duress {
                return Ok((st, None));
            }
            let id = s.root.next_decoy_id;
            s.root.next_decoy_id += 1;
            s.root.decoys.push(DecoyLink {
                id,
                slot: st.slot,
                anchor: st.anchor_phys,
                master_key: *st.keys.master.expose(),
                name: String::new(),
            });
            s.commit(d)?;
            Ok((st, Some(id)))
        })?;
        let owner = link.map(|id| (self.shared.clone(), id));
        Ok(Vault::with_owner(self.shared.dev.clone(), state, owner))
    }

    /// Ids of duress vaults created from this vault.
    pub fn decoy_vaults(&self) -> Result<Vec<u32>> {
        self.shared
            .read(|s, _| Ok(s.root.decoys.iter().map(|l| l.id).collect()))
    }

    /// Duress vaults created from this vault with their cached names.
    pub fn decoys(&self) -> Result<Vec<DecoyInfo>> {
        self.shared.read(|s, _| {
            Ok(s.root
                .decoys
                .iter()
                .map(|l| DecoyInfo {
                    id: l.id,
                    name: l.name.clone(),
                })
                .collect())
        })
    }

    /// This vault's display name; empty if unset. Stored only in this vault's
    /// encrypted index.
    pub fn name(&self) -> Result<String> {
        self.shared.read(|s, _| Ok(s.root.name.clone()))
    }

    /// Set this vault's display name: surrounding whitespace is trimmed; at most
    /// [`index::MAX_VAULT_NAME_CHARS`] Unicode scalar values, else `InvalidArgument`;
    /// empty clears it. On a handle from [`Vault::open_managed_decoy`] the owner's
    /// cached copy is updated too (skipped if the owner is locked; refreshed on the
    /// next `open_managed_decoy`).
    pub fn set_name(&self, name: &str) -> Result<()> {
        let name = name.trim();
        if name.chars().count() > index::MAX_VAULT_NAME_CHARS {
            return Err(Error::InvalidArgument);
        }
        self.shared.write(|s, d| {
            s.root.name.zeroize();
            s.root.name = name.to_owned();
            s.commit(d)
        })?;
        if let Some((owner, id)) = &self.shared.owner {
            let r = owner.write(
                |os, d| match os.root.decoys.iter_mut().find(|l| l.id == *id) {
                    Some(l) if l.name != name => {
                        l.name.zeroize();
                        l.name = name.to_owned();
                        os.commit(d)
                    }
                    _ => Ok(()),
                },
            );
            if let Err(e) = r
                && e != Error::Locked
            {
                return Err(e);
            }
        }
        Ok(())
    }

    /// Open a linked duress vault WITHOUT running the duress wipe. After a restore the
    /// decoy's anchor moved; it is re-located by trial-decrypting anchor records of
    /// allocated chunks and the link is updated. `NotFound` if the decoy is not on
    /// this device. Invalidates any earlier handle to this decoy and its writers.
    pub fn open_managed_decoy(&self, id: u32) -> Result<Vault> {
        let state = self.shared.write(|s, d| {
            let i = s
                .root
                .decoys
                .iter()
                .position(|l| l.id == id)
                .ok_or(Error::NotFound)?;
            let link = s.root.decoys[i].clone();
            let mut payload = SlotPayload {
                flags: FLAG_DURESS,
                anchor_chunk: link.anchor,
                master_key: SecretKey::from_slice(&link.master_key).ok_or(Error::Corrupt)?,
            };
            let mut st = match VaultState::load(d, link.slot, &payload) {
                Err(Error::Corrupt) => {
                    let found =
                        VaultState::locate_anchor(d, &payload.master_key).ok_or(Error::NotFound)?;
                    payload.anchor_chunk = found;
                    let st = VaultState::load(d, link.slot, &payload)?;
                    s.root.decoys[i].anchor = found;
                    s.commit(d)?;
                    st
                }
                other => other?,
            };
            // Refresh the cached name, e.g. after a rename while this was locked.
            if s.root.decoys[i].name != st.root.name {
                s.root.decoys[i].name.zeroize();
                s.root.decoys[i].name = st.root.name.clone();
                s.commit(d)?;
            }
            st.claim_handle(d);
            Ok(st)
        })?;
        Ok(Vault::with_owner(
            self.shared.dev.clone(),
            state,
            Some((self.shared.clone(), id)),
        ))
    }

    /// Change this vault's pattern: same slot and master key, new KEK, atomic.
    pub fn change_pattern(&self, pattern: &Pattern) -> Result<()> {
        self.shared.write(|s, d| {
            let key = d.new_pattern_key(pattern, true)?;
            let sealed = slots::seal_slot(&key, s.slot, &s.slot_payload());
            d.replace_slot_atomic(s.slot, &sealed)
        })
    }

    /// Delete this vault from the device: its slot is overwritten with random
    /// bytes, its reservation dropped, its anchor chunk randomised and its other chunks
    /// freed lazily. Returns the cloud cleanup plan (filler entry, then deletion of all
    /// of its objects found in `listing`); execute it right away, since once this
    /// returns the keys needed to rebuild it are gone. Do not call `sync_complete` on
    /// it. The handle is dead afterwards; a linked owner forgets the decoy link.
    pub fn delete(&self, listing: &[String]) -> Result<SyncPlan> {
        let plan = self.shared.write(|s, d| {
            let plan = backup::delete_plan(s, d, listing)?;
            d.write_slot(s.slot, &slots::random_slot())?;
            d.randomize_inactive_table()?;
            d.write_local_filler(s.slot)?;
            d.storage.sync()?;
            // The reservation is kept until `Device::confirm_vault_deleted`, so
            // no new vault can take this slot while the cloud entry is still real.
            d.release_chunk(s.anchor_phys)?;
            for &p in s.map.iter().filter(|&&p| p != NO_CHUNK) {
                d.free_chunk_lazy(p);
            }
            d.persist()?;
            d.storage.sync()?;
            s.poisoned = true;
            Ok(plan)
        })?;
        if let Some((owner, id)) = &self.shared.owner {
            let r = owner.write(|os, d| {
                if let Some(i) = os.root.decoys.iter().position(|l| l.id == *id) {
                    os.root.decoys.remove(i).zeroize();
                    os.commit(d)?;
                }
                Ok(())
            });
            // A locked owner keeps a stale link, which resolves to NotFound (the
            // decoy's anchor chunk was randomised).
            if let Err(e) = r
                && e != Error::Locked
            {
                return Err(e);
            }
        }
        Ok(plan)
    }

    /// Wipe the key-slot table after `n` consecutive failed unlocks (0 disables).
    pub fn set_wipe_after(&self, n: u32) -> Result<()> {
        self.shared.write(|_, d| {
            d.state.wipe_after = n;
            d.persist()?;
            d.storage.sync()
        })
    }

    /// Build a backup sync plan from the current cloud `listing` (object names in the
    /// backup namespace). At most `max_puts` chunk uploads per plan; call repeatedly
    /// until the plan is empty, executing ops in order and stopping at the first
    /// failure, then call [`Vault::sync_complete`].
    pub fn sync_plan(&self, listing: &[String], max_puts: u32) -> Result<SyncPlan> {
        self.shared
            .read(|s, d| backup::plan(s, d, listing, max_puts as usize))
    }

    /// Record that every op of `plan` succeeded.
    pub fn sync_complete(&self, plan: &SyncPlan) -> Result<()> {
        self.shared.write(|s, d| {
            let Some(root) = plan.entry_root() else {
                return Ok(());
            };
            let map = s.map.clone();
            let cur = s.root_ptr.ok_or(Error::Corrupt)?;
            s.write_anchor(d, cur, Some(root), map)?;
            d.storage.sync()
        })
    }
}

/// Streaming import of one item. Dropping without [`ItemWriter::finish`] discards the
/// written segments (scrubbed at the next commit).
pub struct ItemWriter {
    shared: Arc<VaultShared>,
    id: u64,
    meta: NewItem,
    /// `None` for unsized imports.
    size: Option<u64>,
    written: u64,
    buf: SecretVec,
    segments: Vec<BlobRef>,
    finished: bool,
}

impl fmt::Debug for ItemWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ItemWriter")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl ItemWriter {
    /// Id the item will have.
    pub fn id(&self) -> u64 {
        self.id
    }

    fn flush(&mut self, s: &mut VaultState, d: &mut DeviceInner, all: bool) -> Result<()> {
        let sp = d.cfg.segment_plain_len() as usize;
        let bound = self
            .size
            .map(|size| (size.div_ceil(sp as u64) as u32, size));
        while self.buf.len() >= sp || (all && !self.buf.is_empty()) {
            let n = self.buf.len().min(sp);
            let index = self.segments.len() as u32;
            let aad = s.keys.stream_seg_aad(self.id, KIND_CONTENT, index, bound);
            let b = s.write_segment(d, &aad, &self.buf[..n])?;
            self.segments.push(b);
            self.buf.drain(..n);
        }
        Ok(())
    }

    /// Append bytes.
    pub fn write(&mut self, data: &[u8]) -> Result<()> {
        let over = self
            .size
            .is_some_and(|size| self.written + data.len() as u64 > size);
        if self.finished || over {
            return Err(Error::InvalidArgument);
        }
        self.written += data.len() as u64;
        let shared = self.shared.clone();
        let cap = self.buf.capacity();
        let mut rest = data;
        while !rest.is_empty() {
            let n = rest.len().min(cap - self.buf.len());
            self.buf.extend_from_slice(&rest[..n]);
            rest = &rest[n..];
            shared.write(|s, d| self.flush(s, d, false))?;
        }
        Ok(())
    }

    /// Finish: write the thumbnail (≤ 4 MiB), add the item to the index and commit.
    pub fn finish(mut self, thumbnail: Option<&[u8]>) -> Result<u64> {
        if thumbnail.is_some_and(|t| t.len() > index::MAX_THUMBNAIL_LEN) {
            return Err(Error::InvalidArgument);
        }
        if self.size.is_some_and(|size| self.written != size) {
            return Err(Error::InvalidArgument);
        }
        let shared = self.shared.clone();
        shared.write(|s, d| {
            self.flush(s, d, true)?;
            let thumb = thumbnail
                .map(|t| s.write_whole_stream(d, self.id, KIND_THUMBNAIL, t))
                .transpose()?;
            let meta = std::mem::take(&mut self.meta);
            s.insert_item(Item {
                id: self.id,
                name: meta.name,
                mime: meta.mime,
                created: meta.created,
                modified: meta.modified,
                albums: meta.albums,
                tags: meta.tags,
                content: Stream {
                    size: self.written,
                    segments: std::mem::take(&mut self.segments),
                    streamed: self.size.is_none(),
                },
                thumbnail: thumb,
                extra: meta.extra,
            });
            self.finished = true;
            s.commit(d)
        })?;
        Ok(self.id)
    }
}

impl Drop for ItemWriter {
    fn drop(&mut self) {
        self.meta.name.zeroize();
        if !self.finished
            && let Ok(mut s) = self.shared.state.lock()
        {
            s.pending_free.append(&mut self.segments);
        }
    }
}
