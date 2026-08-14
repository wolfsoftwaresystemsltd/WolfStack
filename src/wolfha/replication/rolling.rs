// Written by Paul Clevett
// (C)Copyright Wolf Software Systems Ltd
// https://wolf.uk.com

//! Rolling-checksum block deltas — the universal replication driver.
//!
//! WolfHA Phase 1 ships whole files: a rootfs manifest records size and
//! mtime per path, and any path that differs is tarred in full. For a
//! rootfs of configuration files that is fine. For a container holding a
//! database, a mail spool or a log, it is close to worst-case — a 10 GB
//! file that took a 4 KB write is retransmitted in its entirety, every
//! round, forever.
//!
//! This module implements the rsync algorithm so only changed *blocks*
//! travel. The replica describes what it already has (a weak rolling
//! checksum plus a strong hash per fixed-size block); the primary rolls a
//! window over its own copy, and wherever the window matches a block the
//! replica already holds it emits a reference instead of the bytes.
//!
//! It needs no particular filesystem, no snapshots and no extra tooling,
//! so unlike the snapshot drivers it is available to every install. It is
//! not crash-consistent — it still reads files while they are being
//! written — so it is a rung below the snapshot drivers, not a substitute.
//!
//! ## What is taken from the primary source, and what is not
//!
//! The weak checksum is rsync's `get_checksum1` (checksum.c, v3.3.0):
//!
//! ```text
//! s1 = s2 = 0;
//! for (i = 0; i < len; i++) { s1 += (buf[i]+CHAR_OFFSET); s2 += s1; }
//! return (s1 & 0xffff) + (s2 << 16);
//! ```
//!
//! with `CHAR_OFFSET 0` (rsync.h). We are not wire-compatible with rsync
//! and do not try to be — this protocol runs between two WolfStack nodes
//! — so the vectorised 4-at-a-time variant and the signed-char detail are
//! deliberately not reproduced; the scalar definition above is the whole
//! specification, and [`weak_checksum`] implements exactly it over
//! unsigned bytes.
//!
//! The rolling update is **not** copied from anywhere. It is derived from
//! that definition and then proved by test: `rolling_matches_recompute`
//! asserts that the rolled value equals a freshly computed checksum at
//! every offset of a pseudo-random buffer. A recalled formula that is
//! subtly wrong would still "work" — it would just silently stop matching
//! blocks and quietly degrade to sending everything — so the property is
//! pinned rather than trusted.

use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};

/// Block size for signatures and matching.
///
/// 64 KiB is a deliberate middle: smaller blocks find more matches in
/// heavily-rewritten files but cost 20 bytes of signature per block (a
/// 100 GB disk image at 4 KiB blocks would need ~500 MB of signatures
/// just to start), while larger blocks make a single changed byte
/// invalidate more data.
pub const BLOCK_SIZE: usize = 64 * 1024;

/// Below this size, delta-encoding a file costs more than sending it.
///
/// A signature exchange plus rolling scan has real overhead, and a fleet
/// whose containers hold thousands of small config files would spend more
/// on the negotiation than the transfer. Files under this threshold are
/// sent whole, which is why this driver helps the "few huge files" fleet
/// without hurting the "many small files" one — neither operator has to
/// know which they are.
pub const MIN_DELTA_SIZE: u64 = 1024 * 1024;

/// Bytes of SHA-256 kept per block as the strong hash.
///
/// The weak checksum is only a filter; the strong hash decides. 16 bytes
/// (128 bits) makes a false match vanishingly unlikely across any
/// plausible number of blocks, at a fifth of the signature size of the
/// full digest.
pub const STRONG_LEN: usize = 16;

/// One block of the replica's existing file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockSig {
    pub weak: u32,
    pub strong: [u8; STRONG_LEN],
}

/// Everything the sender needs to know about the replica's copy.
///
/// `base_len` is carried because the final block of a file is usually
/// short, and a short block can only be matched if its exact length is
/// known. Without it the tail of every file — up to `block_size - 1`
/// bytes — would be resent on every single round even when nothing
/// changed, which is precisely the waste this driver exists to remove.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSignature {
    pub block_size: usize,
    pub base_len: u64,
    pub blocks: Vec<BlockSig>,
}

impl FileSignature {
    /// Length of block `i`, accounting for a short final block.
    fn block_len(&self, i: usize) -> usize {
        let start = i as u64 * self.block_size as u64;
        let remaining = self.base_len.saturating_sub(start);
        (remaining as usize).min(self.block_size)
    }
}

/// rsync's `get_checksum1`, scalar form, `CHAR_OFFSET = 0`.
pub fn weak_checksum(buf: &[u8]) -> u32 {
    let mut s1: u32 = 0;
    let mut s2: u32 = 0;
    for &b in buf {
        s1 = s1.wrapping_add(b as u32);
        s2 = s2.wrapping_add(s1);
    }
    (s1 & 0xffff) | (s2 << 16)
}

/// Incremental form of [`weak_checksum`], kept as explicit state so a
/// window can be advanced one byte at a time without rescanning it.
///
/// Derivation (proved by `rolling_matches_recompute`): for a window of
/// length `L`, `s1 = Σ b[i]` and `s2 = Σ (L-i)·b[i]`, both mod 2^16.
/// Sliding off `out` and on `in` gives
/// `s1' = s1 - out + in` and `s2' = s2 - L·out + s1'`.
#[derive(Debug, Clone, Copy)]
pub struct Rolling {
    s1: u32,
    s2: u32,
    len: u32,
}

impl Rolling {
    pub fn new(buf: &[u8]) -> Self {
        let mut s1: u32 = 0;
        let mut s2: u32 = 0;
        for &b in buf {
            s1 = (s1 + b as u32) & 0xffff;
            s2 = (s2 + s1) & 0xffff;
        }
        Rolling { s1, s2, len: buf.len() as u32 }
    }

    pub fn digest(&self) -> u32 {
        (self.s1 & 0xffff) | (self.s2 << 16)
    }

    /// Slide the window: `out` leaves the front, `inb` joins the back.
    pub fn roll(&mut self, out: u8, inb: u8) {
        // Wrapping arithmetic then a 16-bit mask. This is exact rather
        // than merely convenient: 2^16 divides 2^32, so reducing mod 2^32
        // first and masking after gives the same result as working mod
        // 2^16 throughout — and it avoids inventing a bias constant to
        // keep an intermediate subtraction non-negative.
        let l = self.len;
        self.s1 = self.s1.wrapping_sub(out as u32).wrapping_add(inb as u32) & 0xffff;
        self.s2 = self
            .s2
            .wrapping_sub(l.wrapping_mul(out as u32))
            .wrapping_add(self.s1)
            & 0xffff;
    }
}

fn strong_hash(buf: &[u8]) -> [u8; STRONG_LEN] {
    let mut h = Sha256::new();
    h.update(buf);
    let full = h.finalize();
    let mut out = [0u8; STRONG_LEN];
    out.copy_from_slice(&full[..STRONG_LEN]);
    out
}

/// Describe a file the replica already holds, one entry per block.
pub fn signatures(path: &str, block_size: usize) -> Result<FileSignature, String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("open {}: {}", path, e))?;
    let mut blocks = Vec::new();
    let mut buf = vec![0u8; block_size];
    let mut base_len: u64 = 0;
    loop {
        let mut filled = 0;
        // A short read is not EOF; fill the block before hashing or the
        // signatures would describe blocks the sender never forms.
        while filled < block_size {
            match f.read(&mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) => return Err(format!("read {}: {}", path, e)),
            }
        }
        if filled == 0 {
            break;
        }
        let block = &buf[..filled];
        blocks.push(BlockSig { weak: weak_checksum(block), strong: strong_hash(block) });
        base_len += filled as u64;
        if filled < block_size {
            break;
        }
    }
    Ok(FileSignature { block_size, base_len, blocks })
}

/// One instruction in a delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeltaOp {
    /// Take `count` consecutive blocks from the replica's copy, starting
    /// at block `index`. Runs are merged, so an unchanged region costs one
    /// op regardless of length.
    Copy { index: u32, count: u32 },
    /// Bytes that exist nowhere in the replica's copy.
    Literal(Vec<u8>),
}

/// Build the instructions that turn the replica's copy into ours.
pub fn compute_delta(path: &str, sig: &FileSignature) -> Result<Vec<DeltaOp>, String> {
    let data = std::fs::read(path).map_err(|e| format!("read {}: {}", path, e))?;
    Ok(delta_from_bytes(&data, sig))
}

/// Pure core of [`compute_delta`], separated so it can be tested without
/// touching the filesystem.
///
/// Only full-length blocks take part in the rolling scan: a short block
/// cannot match a full-length window. The replica's final short block, if
/// it has one, is therefore matched separately against the tail — see
/// `identical_files_produce_only_copies`, which exists because the first
/// version of this function silently resent that tail on every round.
pub fn delta_from_bytes(data: &[u8], sig: &FileSignature) -> Vec<DeltaOp> {
    let block_size = sig.block_size;
    let sigs = &sig.blocks;
    let mut ops: Vec<DeltaOp> = Vec::new();
    let mut literal: Vec<u8> = Vec::new();

    let flush_literal = |ops: &mut Vec<DeltaOp>, literal: &mut Vec<u8>| {
        if !literal.is_empty() {
            ops.push(DeltaOp::Literal(std::mem::take(literal)));
        }
    };
    let push_copy = |ops: &mut Vec<DeltaOp>, index: u32| {
        // Merge with the previous op when this block directly follows it.
        if let Some(DeltaOp::Copy { index: pi, count }) = ops.last_mut()
            && *pi + *count == index
        {
            *count += 1;
            return;
        }
        ops.push(DeltaOp::Copy { index, count: 1 });
    };

    if block_size == 0 || sigs.is_empty() {
        if !data.is_empty() {
            ops.push(DeltaOp::Literal(data.to_vec()));
        }
        return ops;
    }

    // Index only the full-length blocks. weak -> candidate indices; a weak
    // collision is expected and cheap, and the strong hash resolves it.
    let mut table: HashMap<u32, Vec<u32>> = HashMap::new();
    for (i, bs) in sigs.iter().enumerate() {
        if sig.block_len(i) == block_size {
            table.entry(bs.weak).or_default().push(i as u32);
        }
    }

    // The replica's trailing short block, if any: (index, length).
    let tail_block: Option<(u32, usize)> = sigs
        .len()
        .checked_sub(1)
        .map(|last| (last as u32, sig.block_len(last)))
        .filter(|(_, len)| *len > 0 && *len < block_size);

    let mut pos = 0usize;
    if data.len() >= block_size {
        let mut roll = Rolling::new(&data[0..block_size]);
        loop {
            let weak = roll.digest();
            let mut matched: Option<u32> = None;
            if let Some(cands) = table.get(&weak) {
                let window = &data[pos..pos + block_size];
                let strong = strong_hash(window);
                for &ci in cands {
                    if sigs[ci as usize].strong == strong {
                        matched = Some(ci);
                        break;
                    }
                }
            }

            if let Some(ci) = matched {
                flush_literal(&mut ops, &mut literal);
                push_copy(&mut ops, ci);
                pos += block_size;
                if pos + block_size > data.len() {
                    break;
                }
                roll = Rolling::new(&data[pos..pos + block_size]);
            } else {
                literal.push(data[pos]);
                if pos + block_size >= data.len() {
                    pos += 1;
                    break;
                }
                roll.roll(data[pos], data[pos + block_size]);
                pos += 1;
            }
        }
    }

    // Whatever the full-length window could not cover. Try the replica's
    // short final block against it before giving up and sending bytes.
    let rest = &data[pos.min(data.len())..];
    if let Some((idx, len)) = tail_block
        && rest.len() == len
        && strong_hash(rest) == sigs[idx as usize].strong
    {
        flush_literal(&mut ops, &mut literal);
        push_copy(&mut ops, idx);
    } else {
        literal.extend_from_slice(rest);
        flush_literal(&mut ops, &mut literal);
    }
    ops
}

/// Reconstruct the new file from the replica's copy plus the delta.
///
/// Writes to `out_path` rather than in place: a crash midway through must
/// not leave a half-rewritten file where the old one was, and the caller
/// renames into place only once this returns.
pub fn apply_delta(
    base_path: &str,
    ops: &[DeltaOp],
    out_path: &str,
    block_size: usize,
) -> Result<(), String> {
    let mut base = std::fs::File::open(base_path)
        .map_err(|e| format!("open base {}: {}", base_path, e))?;
    let mut out = std::fs::File::create(out_path)
        .map_err(|e| format!("create {}: {}", out_path, e))?;
    let mut buf = vec![0u8; block_size];
    for op in ops {
        match op {
            DeltaOp::Literal(bytes) => {
                out.write_all(bytes).map_err(|e| format!("write literal: {}", e))?;
            }
            DeltaOp::Copy { index, count } => {
                for k in 0..*count {
                    let off = (*index as u64 + k as u64) * block_size as u64;
                    base.seek(SeekFrom::Start(off))
                        .map_err(|e| format!("seek base: {}", e))?;
                    let mut filled = 0;
                    while filled < block_size {
                        match base.read(&mut buf[filled..]) {
                            Ok(0) => break,
                            Ok(n) => filled += n,
                            Err(e) => return Err(format!("read base: {}", e)),
                        }
                    }
                    if filled == 0 {
                        return Err(format!(
                            "delta references block {} which is past the end of {} — \
                             the replica's copy is not the one the delta was built \
                             against; a full resync is required",
                            index + k,
                            base_path
                        ));
                    }
                    out.write_all(&buf[..filled])
                        .map_err(|e| format!("write block: {}", e))?;
                }
            }
        }
    }
    out.flush().map_err(|e| format!("flush {}: {}", out_path, e))?;
    // The replica must survive a crash right after a sync, so the
    // reconstructed data has to be on the platter before the caller
    // renames it over the previous copy.
    out.sync_all().map_err(|e| format!("fsync {}: {}", out_path, e))?;
    Ok(())
}

// ─── Wire encoding ───────────────────────────────────────────────────
//
// Binary rather than JSON: literals are arbitrary bytes (base64 would add
// a third again), and a large file's signature list runs to hundreds of
// thousands of entries where per-entry JSON punctuation dominates.
// All integers are little-endian and explicitly sized.

/// Encode a signature as `[u32 block_size][u64 base_len][u32 count]`
/// then `count` records of `[u32 weak][16 bytes strong]`.
pub fn encode_signatures(sig: &FileSignature) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + sig.blocks.len() * (4 + STRONG_LEN));
    out.extend_from_slice(&(sig.block_size as u32).to_le_bytes());
    out.extend_from_slice(&sig.base_len.to_le_bytes());
    out.extend_from_slice(&(sig.blocks.len() as u32).to_le_bytes());
    for b in &sig.blocks {
        out.extend_from_slice(&b.weak.to_le_bytes());
        out.extend_from_slice(&b.strong);
    }
    out
}

pub fn decode_signatures(buf: &[u8]) -> Result<FileSignature, String> {
    const HDR: usize = 4 + 8 + 4;
    if buf.len() < HDR {
        return Err("signature payload truncated".to_string());
    }
    let block_size = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let base_len = u64::from_le_bytes([
        buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
    ]);
    let count = u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]) as usize;
    if block_size == 0 {
        return Err("signature payload declares a zero block size".to_string());
    }
    let rec = 4 + STRONG_LEN;
    // Check against the buffer BEFORE allocating: `count` is attacker-
    // influenced, and `Vec::with_capacity` on a bogus value is an
    // out-of-memory abort rather than a returned error.
    let need = HDR.checked_add(count.checked_mul(rec).ok_or("signature count overflows")?)
        .ok_or("signature length overflows")?;
    if buf.len() < need {
        return Err(format!(
            "signature payload truncated: {} bytes for {} blocks (need {})",
            buf.len(),
            count,
            need
        ));
    }
    let mut blocks = Vec::with_capacity(count);
    for i in 0..count {
        let o = HDR + i * rec;
        let weak = u32::from_le_bytes([buf[o], buf[o + 1], buf[o + 2], buf[o + 3]]);
        let mut strong = [0u8; STRONG_LEN];
        strong.copy_from_slice(&buf[o + 4..o + 4 + STRONG_LEN]);
        blocks.push(BlockSig { weak, strong });
    }
    Ok(FileSignature { block_size, base_len, blocks })
}

/// Encode ops as a sequence of `[u8 tag]` records: tag 0 is
/// `[u32 index][u32 count]`, tag 1 is `[u32 len][len bytes]`.
pub fn encode_delta(ops: &[DeltaOp]) -> Vec<u8> {
    let mut out = Vec::new();
    for op in ops {
        match op {
            DeltaOp::Copy { index, count } => {
                out.push(0u8);
                out.extend_from_slice(&index.to_le_bytes());
                out.extend_from_slice(&count.to_le_bytes());
            }
            DeltaOp::Literal(bytes) => {
                out.push(1u8);
                out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
                out.extend_from_slice(bytes);
            }
        }
    }
    out
}

pub fn decode_delta(buf: &[u8]) -> Result<Vec<DeltaOp>, String> {
    let mut ops = Vec::new();
    let mut i = 0usize;
    while i < buf.len() {
        let tag = buf[i];
        i += 1;
        match tag {
            0 => {
                if i + 8 > buf.len() {
                    return Err("delta truncated in a copy record".to_string());
                }
                let index = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]);
                let count =
                    u32::from_le_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);
                if count == 0 {
                    return Err("delta contains a zero-length copy".to_string());
                }
                ops.push(DeltaOp::Copy { index, count });
                i += 8;
            }
            1 => {
                if i + 4 > buf.len() {
                    return Err("delta truncated in a literal header".to_string());
                }
                let len =
                    u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
                i += 4;
                if i + len > buf.len() {
                    return Err("delta truncated in a literal body".to_string());
                }
                ops.push(DeltaOp::Literal(buf[i..i + len].to_vec()));
                i += len;
            }
            other => {
                return Err(format!("unknown delta op tag {}", other));
            }
        }
    }
    Ok(ops)
}

/// One file's delta inside a multi-file payload.
pub struct FileDelta {
    /// Rootfs-relative path.
    pub path: String,
    pub ops: Vec<DeltaOp>,
}

/// Pack per-file deltas into one blob for a single upload.
///
/// Framing is `[u32 path_len][path][u64 ops_len][ops]` per file. Lengths
/// are explicit and checked on decode: this blob arrives from a peer, and
/// a truncated or hostile frame must produce an error rather than a panic
/// that takes down the sync worker.
pub fn pack_file_deltas(items: &[FileDelta]) -> Vec<u8> {
    let mut out = Vec::new();
    for it in items {
        let ops = encode_delta(&it.ops);
        out.extend_from_slice(&(it.path.len() as u32).to_le_bytes());
        out.extend_from_slice(it.path.as_bytes());
        out.extend_from_slice(&(ops.len() as u64).to_le_bytes());
        out.extend_from_slice(&ops);
    }
    out
}

pub fn unpack_file_deltas(buf: &[u8]) -> Result<Vec<FileDelta>, String> {
    let mut items = Vec::new();
    let mut i = 0usize;
    while i < buf.len() {
        if i + 4 > buf.len() {
            return Err("delta bundle truncated in a path header".to_string());
        }
        let plen = u32::from_le_bytes([buf[i], buf[i + 1], buf[i + 2], buf[i + 3]]) as usize;
        i += 4;
        if i + plen > buf.len() {
            return Err("delta bundle truncated in a path".to_string());
        }
        let path = String::from_utf8(buf[i..i + plen].to_vec())
            .map_err(|_| "delta bundle contains a non-UTF-8 path".to_string())?;
        i += plen;
        if i + 8 > buf.len() {
            return Err("delta bundle truncated in an ops header".to_string());
        }
        let olen = u64::from_le_bytes([
            buf[i], buf[i + 1], buf[i + 2], buf[i + 3],
            buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7],
        ]) as usize;
        i += 8;
        if i + olen > buf.len() {
            return Err("delta bundle truncated in an ops body".to_string());
        }
        let ops = decode_delta(&buf[i..i + olen])?;
        i += olen;
        items.push(FileDelta { path, ops });
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic pseudo-random bytes — no rand dependency, and a
    /// failure is reproducible.
    fn pseudo(n: usize, seed: u64) -> Vec<u8> {
        let mut s = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        (0..n)
            .map(|_| {
                s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (s >> 33) as u8
            })
            .collect()
    }

    /// THE test this module rests on. The rolling update is derived, not
    /// copied, so it is proved: at every offset the incrementally-rolled
    /// checksum must equal one computed from scratch. If this fails, block
    /// matching silently stops working and every sync degrades to sending
    /// the whole file — a performance cliff with no error message.
    #[test]
    fn rolling_matches_recompute() {
        let data = pseudo(8192, 42);
        let win = 512;
        let mut roll = Rolling::new(&data[0..win]);
        for pos in 0..(data.len() - win) {
            let fresh = weak_checksum(&data[pos..pos + win]);
            assert_eq!(
                roll.digest(),
                fresh,
                "rolled checksum diverged from a fresh one at offset {}",
                pos
            );
            roll.roll(data[pos], data[pos + win]);
        }
    }

    /// The scalar definition from rsync's checksum.c, transcribed
    /// independently of the implementation, must agree with it.
    #[test]
    fn weak_checksum_matches_the_rsync_definition() {
        for seed in [1u64, 7, 99] {
            let data = pseudo(1000, seed);
            let (mut s1, mut s2) = (0u32, 0u32);
            for &b in &data {
                s1 = s1.wrapping_add(b as u32);
                s2 = s2.wrapping_add(s1);
            }
            let expect = (s1 & 0xffff) | (s2 << 16);
            assert_eq!(weak_checksum(&data), expect);
        }
    }

    fn roundtrip(base: &[u8], target: &[u8], block_size: usize) -> Vec<DeltaOp> {
        // Unique per call: deriving the directory from the buffer sizes
        // let two concurrently-running tests collide, and one deleted the
        // other's fixture mid-run.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "wolfha-rolling-{}-{}",
            std::process::id(),
            n
        ));
        let _ = std::fs::create_dir_all(&dir);
        let base_p = dir.join("base.bin");
        let out_p = dir.join("out.bin");
        std::fs::write(&base_p, base).unwrap();

        let sig = signatures(base_p.to_str().unwrap(), block_size).unwrap();
        // Exercise the wire encoding on every roundtrip — a delta is only
        // useful if the signature survives the trip to the primary.
        let sig = decode_signatures(&encode_signatures(&sig)).unwrap();
        let ops = delta_from_bytes(target, &sig);
        apply_delta(base_p.to_str().unwrap(), &ops, out_p.to_str().unwrap(), block_size).unwrap();

        let got = std::fs::read(&out_p).unwrap();
        assert_eq!(got, target, "reconstruction differed from the target");
        let _ = std::fs::remove_dir_all(&dir);
        ops
    }

    /// Correctness first: whatever the delta contains, applying it must
    /// reproduce the target byte for byte.
    #[test]
    fn small_edit_in_a_large_file_reconstructs_exactly() {
        let base = pseudo(300_000, 5);
        let mut target = base.clone();
        target[150_000] ^= 0xff;
        roundtrip(&base, &target, 4096);
    }

    /// And efficiency, which is the entire point: a one-byte change must
    /// not resend the file. Without this the module could "work" while
    /// delivering nothing.
    #[test]
    fn a_one_byte_change_sends_almost_no_literal_data() {
        let base = pseudo(300_000, 11);
        let mut target = base.clone();
        target[200_000] ^= 0xff;
        let ops = roundtrip(&base, &target, 4096);
        let literal: usize = ops
            .iter()
            .map(|o| match o {
                DeltaOp::Literal(b) => b.len(),
                _ => 0,
            })
            .sum();
        // One changed byte can invalidate at most the block containing it
        // plus the unaligned remainder around it. Anything near the file
        // size means matching has failed.
        assert!(
            literal < 4096 * 4,
            "expected a tiny literal payload, got {} bytes of {}",
            literal,
            target.len()
        );
    }

    #[test]
    fn insertion_still_matches_the_shifted_remainder() {
        // Insertion shifts every following block out of alignment, which
        // is exactly what a rolling checksum exists to handle — a
        // block-aligned differ would resend the entire tail.
        let base = pseudo(200_000, 3);
        let mut target = base.clone();
        target.splice(50_000..50_000, b"a-freshly-inserted-run-of-bytes".iter().copied());
        let ops = roundtrip(&base, &target, 4096);
        let literal: usize = ops
            .iter()
            .map(|o| match o {
                DeltaOp::Literal(b) => b.len(),
                _ => 0,
            })
            .sum();
        assert!(
            literal < 20_000,
            "insertion should not invalidate the tail; {} literal bytes",
            literal
        );
    }

    #[test]
    fn identical_files_produce_only_copies() {
        let base = pseudo(100_000, 8);
        let ops = roundtrip(&base, &base.clone(), 4096);
        assert!(
            ops.iter().all(|o| matches!(o, DeltaOp::Copy { .. })),
            "an unchanged file should ship no literals: {:?}",
            ops.iter().take(4).collect::<Vec<_>>()
        );
    }

    #[test]
    fn truncation_and_growth_reconstruct_exactly() {
        let base = pseudo(100_000, 2);
        roundtrip(&base, &base[..30_000], 4096);
        let mut grown = base.clone();
        grown.extend_from_slice(&pseudo(50_000, 77));
        roundtrip(&base, &grown, 4096);
    }

    #[test]
    fn empty_and_tiny_files_are_handled() {
        roundtrip(&pseudo(10, 1), &[], 4096);
        roundtrip(&[], &pseudo(10, 1), 4096);
        roundtrip(&pseudo(100, 1), &pseudo(50, 2), 4096);
    }

    #[test]
    fn signature_wire_roundtrips() {
        let sig = FileSignature {
            block_size: 4096,
            base_len: 4096 + 17,
            blocks: vec![
                BlockSig { weak: 0xdead_beef, strong: [7u8; STRONG_LEN] },
                BlockSig { weak: 1, strong: [9u8; STRONG_LEN] },
            ],
        };
        assert_eq!(decode_signatures(&encode_signatures(&sig)).unwrap(), sig);
    }

    /// The short final block must be reported with its real length, or the
    /// tail match cannot fire.
    #[test]
    fn block_len_accounts_for_a_short_final_block() {
        let sig = FileSignature {
            block_size: 4096,
            base_len: 4096 + 17,
            blocks: vec![
                BlockSig { weak: 0, strong: [0; STRONG_LEN] },
                BlockSig { weak: 0, strong: [0; STRONG_LEN] },
            ],
        };
        assert_eq!(sig.block_len(0), 4096);
        assert_eq!(sig.block_len(1), 17);
    }

    #[test]
    fn file_delta_bundle_roundtrips() {
        let items = vec![
            FileDelta {
                path: "var/lib/db/data.mdb".to_string(),
                ops: vec![DeltaOp::Copy { index: 0, count: 5 }, DeltaOp::Literal(vec![1, 2, 3])],
            },
            FileDelta { path: "etc/x".to_string(), ops: vec![DeltaOp::Literal(vec![9])] },
        ];
        let back = unpack_file_deltas(&pack_file_deltas(&items)).unwrap();
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].path, "var/lib/db/data.mdb");
        assert_eq!(back[0].ops, items[0].ops);
        assert_eq!(back[1].path, "etc/x");
    }

    /// The bundle arrives from a peer, so every truncation point must
    /// error rather than panic.
    #[test]
    fn truncated_bundles_error_at_every_point() {
        let full = pack_file_deltas(&[FileDelta {
            path: "a/b".to_string(),
            ops: vec![DeltaOp::Copy { index: 1, count: 1 }],
        }]);
        for cut in 1..full.len() {
            assert!(
                unpack_file_deltas(&full[..cut]).is_err(),
                "truncating to {} bytes should error",
                cut
            );
        }
        assert!(unpack_file_deltas(&full).is_ok());
    }

    #[test]
    fn delta_wire_roundtrips() {
        let ops = vec![
            DeltaOp::Copy { index: 3, count: 9 },
            DeltaOp::Literal(b"some literal bytes".to_vec()),
            DeltaOp::Copy { index: 40, count: 1 },
        ];
        assert_eq!(decode_delta(&encode_delta(&ops)).unwrap(), ops);
    }

    /// A peer's payload is untrusted input: a truncated or malformed one
    /// must produce an error, never a panic that takes the sync thread.
    #[test]
    fn malformed_wire_payloads_error_rather_than_panic() {
        assert!(decode_signatures(&[1, 2, 3]).is_err());
        // Header claims a huge block count the buffer cannot hold.
        let mut lying = Vec::new();
        lying.extend_from_slice(&4096u32.to_le_bytes());
        lying.extend_from_slice(&0u64.to_le_bytes());
        lying.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_signatures(&lying).is_err());
        assert!(decode_delta(&[0, 1, 2]).is_err());
        assert!(decode_delta(&[1, 255, 255, 255, 255]).is_err());
        assert!(decode_delta(&[42]).is_err());
        // Zero block size would be a divide/step of zero downstream.
        let bad = encode_signatures(&FileSignature {
            block_size: 0,
            base_len: 0,
            blocks: Vec::new(),
        });
        assert!(decode_signatures(&bad).is_err());
    }

    /// A delta built against a different base must be refused, not
    /// silently applied to produce a corrupt file.
    #[test]
    fn copy_past_the_end_of_the_base_is_refused() {
        let dir = std::env::temp_dir().join(format!("wolfha-rolling-oob-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let base_p = dir.join("base.bin");
        let out_p = dir.join("out.bin");
        std::fs::write(&base_p, pseudo(4096, 1)).unwrap();
        let ops = vec![DeltaOp::Copy { index: 999, count: 1 }];
        let err = apply_delta(base_p.to_str().unwrap(), &ops, out_p.to_str().unwrap(), 4096)
            .expect_err("must refuse an out-of-range copy");
        assert!(err.contains("full resync"), "should demand a resync: {}", err);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
