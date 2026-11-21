//! Shopping Sessions, Track B: Rust pipeline.
//!
//! Rule IDs (R-C2, R-E5, ...) refer to RULES_DIGEST.md; rules.md is authoritative.
//! Reads $DATA_DIR, writes $OUTPUT_DIR/{user_daily,campaign_daily}/part-0.parquet.
//! Logs go to stderr only.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use hashbrown::hash_table::Entry;
use hashbrown::{HashMap, HashTable};
use memchr::memchr;
use parquet::basic::Compression;
use parquet::data_type::{ByteArray, ByteArrayType, Int32Type, Int64Type};
use parquet::file::properties::{EnabledStatistics, WriterProperties};
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;
use rayon::prelude::*;

#[cfg(all(feature = "mi", not(feature = "prof")))]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Profiling build only: counts allocation calls and bytes on top of the real allocator.
#[cfg(feature = "prof")]
mod prof_alloc {
    use std::alloc::{GlobalAlloc, Layout};
    use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
    pub static CALLS: AtomicU64 = AtomicU64::new(0);
    pub static BYTES: AtomicU64 = AtomicU64::new(0);
    pub struct Counting;
    #[cfg(feature = "mi")]
    static INNER: mimalloc::MiMalloc = mimalloc::MiMalloc;
    #[cfg(not(feature = "mi"))]
    static INNER: std::alloc::System = std::alloc::System;
    unsafe impl GlobalAlloc for Counting {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            CALLS.fetch_add(1, Relaxed);
            BYTES.fetch_add(l.size() as u64, Relaxed);
            INNER.alloc(l)
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            INNER.dealloc(p, l)
        }
        unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
            CALLS.fetch_add(1, Relaxed);
            BYTES.fetch_add(n.saturating_sub(l.size()) as u64, Relaxed);
            INNER.realloc(p, l, n)
        }
    }
}
#[cfg(feature = "prof")]
#[global_allocator]
static GLOBAL: prof_alloc::Counting = prof_alloc::Counting;

/// Page faults and peak memory from /proc, printed when PROF is set.
fn proc_stats() -> String {
    let stat = fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let after = stat.rsplit(')').next().unwrap_or("");
    let f: Vec<&str> = after.split_whitespace().collect();
    let (minflt, majflt) = (f.get(7).copied().unwrap_or("?"), f.get(9).copied().unwrap_or("?"));
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let hwm = status.lines().find(|l| l.starts_with("VmHWM")).unwrap_or("VmHWM ?").replace('\t', " ");
    #[cfg(feature = "prof")]
    let alloc = format!(
        ", alloc calls={} bytes={:.0}MB",
        prof_alloc::CALLS.load(std::sync::atomic::Ordering::Relaxed),
        prof_alloc::BYTES.load(std::sync::atomic::Ordering::Relaxed) as f64 / 1048576.0
    );
    #[cfg(not(feature = "prof"))]
    let alloc = String::new();
    format!("minflt={minflt} majflt={majflt} {hwm}{alloc}")
}

/// A byte slice into a memory-mapped input file. The maps are leaked on purpose:
/// they live for the whole run, so fields can be kept as zero-copy slices.
type S = &'static [u8];

const DAY_MS: i64 = 86_400_000;
const GAP_MS: i64 = 1_800_000; // R-E5
const LATE_MS: i64 = DAY_MS; // R-E4
const WEEK_MS: i64 = 7 * DAY_MS; // R-T8, R-K4
const NSHARD: usize = 256;
const CHUNK_BYTES: usize = 8 << 20;

const T_VIEW: u8 = 0;
const T_CART: u8 = 1;
const T_PURCHASE: u8 = 2;

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------

struct Clock {
    t0: Instant,
    last: Instant,
}

impl Clock {
    fn new() -> Self {
        let now = Instant::now();
        Clock { t0: now, last: now }
    }
    fn log(&mut self, msg: &str) {
        let now = Instant::now();
        eprintln!(
            "[{:8.3}s +{:7.3}s] {}",
            now.duration_since(self.t0).as_secs_f64(),
            now.duration_since(self.last).as_secs_f64(),
            msg
        );
        self.last = now;
    }
}

#[inline]
fn hash_bytes(b: &[u8]) -> u64 {
    const K: u64 = 0x9FB2_1C65_1E98_DF25;
    let mut h: u64 = 0x9E37_79B9_7F4A_7C15 ^ (b.len() as u64);
    let mut chunks = b.chunks_exact(8);
    for w in &mut chunks {
        let v = u64::from_le_bytes(w.try_into().unwrap());
        h = (h ^ v).wrapping_mul(K);
        h ^= h >> 32;
    }
    let r = chunks.remainder();
    if !r.is_empty() {
        let mut t = [0u8; 8];
        t[..r.len()].copy_from_slice(r);
        h = (h ^ u64::from_le_bytes(t)).wrapping_mul(K);
        h ^= h >> 32;
    }
    h = (h ^ (h >> 29)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    h ^ (h >> 32)
}

/// A second hash, independent of `hash_bytes` (different seed, multiplier and finaliser).
/// (hash_bytes, hash_bytes2) together are a 96-bit fingerprint of an ID.
#[inline]
fn hash_bytes2(b: &[u8]) -> u32 {
    const K: u64 = 0xD6E8_FEB8_6659_FD93;
    let mut h: u64 = 0xA076_1D64_78BD_642F ^ ((b.len() as u64) << 32);
    let mut chunks = b.chunks_exact(8);
    for w in &mut chunks {
        let v = u64::from_le_bytes(w.try_into().unwrap());
        h = (h.rotate_left(23) ^ v).wrapping_mul(K);
    }
    let r = chunks.remainder();
    if !r.is_empty() {
        let mut t = [0u8; 8];
        t[..r.len()].copy_from_slice(r);
        h = (h.rotate_left(23) ^ u64::from_le_bytes(t)).wrapping_mul(K);
    }
    h ^= h >> 31;
    h = h.wrapping_mul(0x94D0_49BB_1331_11EB);
    (h >> 32) as u32
}

/// Shard from the middle bits: hashbrown uses the low bits for the bucket and the
/// top 7 bits for its control bytes, so neither may be constant within a shard.
#[inline]
fn shard_of(h: u64) -> usize {
    ((h >> 40) & (NSHARD as u64 - 1)) as usize
}

fn map_file(path: &Path) -> S {
    let f = fs::File::open(path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    if f.metadata().map(|m| m.len()).unwrap_or(0) == 0 {
        return &[];
    }
    let m = unsafe { memmap2::Mmap::map(&f) }.unwrap_or_else(|e| panic!("mmap {}: {e}", path.display()));
    let m: &'static memmap2::Mmap = Box::leak(Box::new(m));
    &m[..]
}

/// R-C1: every `*.csv` in a directory (or the single file itself), sorted by name.
fn csv_files(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    let mut v: Vec<PathBuf> = match fs::read_dir(path) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with(".csv")))
            .collect(),
        Err(_) => Vec::new(),
    };
    v.sort();
    v
}

/// Maps every file and cuts it into chunks that end on a line boundary.
/// R-C2: the first line of each file is the header and is skipped by position.
/// R-C3: only `\n` ends a line.
fn load_chunks(path: &Path) -> Vec<S> {
    let mut out = Vec::new();
    for file in csv_files(path) {
        let data = map_file(&file);
        let body: S = match memchr(b'\n', data) {
            Some(i) => &data[i + 1..],
            None => continue, // header only, no newline
        };
        let mut s = 0;
        while s < body.len() {
            let mut e = (s + CHUNK_BYTES).min(body.len());
            if e < body.len() {
                e = match memchr(b'\n', &body[e..]) {
                    Some(i) => e + i + 1,
                    None => body.len(),
                };
            }
            out.push(&body[s..e]);
            s = e;
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Numbers and timestamps (R-T). Digits are ASCII 0-9 only (R-C9).
// ---------------------------------------------------------------------------

#[inline]
fn d2(b: &[u8], i: usize) -> Option<i64> {
    let a = b[i].wrapping_sub(b'0');
    let c = b[i + 1].wrapping_sub(b'0');
    if a > 9 || c > 9 {
        None
    } else {
        Some((a as i64) * 10 + c as i64)
    }
}

/// Days since 1970-01-01 for a civil date (Hinnant's days_from_civil).
#[inline]
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// R-T1..R-T6: epoch milliseconds, or None for a bad timestamp.
#[inline]
fn parse_ts(b: &[u8]) -> Option<i64> {
    let n = b.len();
    // F1 (20 bytes, ends in Z) and F2 (25 bytes, ends in +HH:MM / -HH:MM).
    if (n == 20 || n == 25) && b[4] == b'-' && b[7] == b'-' && b[10] == b'T' && b[13] == b':' && b[16] == b':' {
        let y = d2(b, 0)? * 100 + d2(b, 2)?;
        let mo = d2(b, 5)?;
        let d = d2(b, 8)?;
        let h = d2(b, 11)?;
        let mi = d2(b, 14)?;
        let s = d2(b, 17)?;
        let off = if n == 20 {
            if b[19] != b'Z' {
                return None;
            }
            0
        } else {
            let sign = match b[19] {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            if b[22] != b':' {
                return None;
            }
            let oh = d2(b, 20)?;
            let om = d2(b, 23)?;
            if oh > 23 || om > 59 {
                return None; // R-T2
            }
            sign * (oh * 3600 + om * 60)
        };
        if !(1..=12).contains(&mo) || d < 1 || h > 23 || mi > 59 || s > 59 {
            return None; // R-T5
        }
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let dim = match mo {
            2 => {
                if leap {
                    29
                } else {
                    28
                }
            }
            4 | 6 | 9 | 11 => 30,
            _ => 31,
        };
        if d > dim {
            return None;
        }
        return Some((days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + s - off) * 1000);
    }
    // F3: digits only, leading zeros allowed (R-T3). More than 18 significant digits can
    // never be inside a window, so it is bad either way (R-T6).
    if n == 0 {
        return None;
    }
    let mut i = 0;
    while i < n && b[i] == b'0' {
        i += 1;
    }
    if n - i > 18 {
        return None;
    }
    let mut v: i64 = 0;
    for &c in &b[i..] {
        let d = c.wrapping_sub(b'0');
        if d > 9 {
            return None;
        }
        v = v * 10 + d as i64;
    }
    Some(v)
}

/// R-E3: digits only, value 1..=10,000,000; leading zeros allowed.
#[inline]
fn parse_price(b: &[u8]) -> Option<u32> {
    if b.is_empty() {
        return None;
    }
    let mut i = 0;
    while i < b.len() && b[i] == b'0' {
        i += 1;
    }
    if b.len() - i > 8 {
        return None;
    }
    let mut v: u32 = 0;
    for &c in &b[i..] {
        let d = c.wrapping_sub(b'0');
        if d > 9 {
            return None;
        }
        v = v * 10 + d as u32;
    }
    if (1..=10_000_000).contains(&v) {
        Some(v)
    } else {
        None
    }
}

fn manifest_value(text: &str, key: &str) -> i64 {
    let k = format!("\"{key}\"");
    let at = text.find(&k).unwrap_or_else(|| panic!("manifest.json: no {key}"));
    let rest = &text[at + k.len()..];
    let q1 = rest.find('"').expect("manifest.json: value");
    let rest = &rest[q1 + 1..];
    let q2 = rest.find('"').expect("manifest.json: value end");
    parse_ts(rest[..q2].as_bytes()).unwrap_or_else(|| panic!("manifest.json: bad {key}"))
}

// ---------------------------------------------------------------------------
// SIMD scanner: one pass over a chunk finds every comma, newline and quote.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
mod simd {
    use core::arch::x86_64::*;
    /// log2 of the number of mask bits per input byte.
    pub const SHIFT: u32 = 0;
    /// Bit i is set when byte i of the 16 bytes at `p` is `,`, `\n` or `"`.
    #[inline(always)]
    pub unsafe fn mask16(p: *const u8) -> u64 {
        let v = _mm_loadu_si128(p as *const __m128i);
        let m = _mm_or_si128(
            _mm_or_si128(_mm_cmpeq_epi8(v, _mm_set1_epi8(b',' as i8)), _mm_cmpeq_epi8(v, _mm_set1_epi8(b'\n' as i8))),
            _mm_cmpeq_epi8(v, _mm_set1_epi8(b'"' as i8)),
        );
        _mm_movemask_epi8(m) as u32 as u64
    }
}

#[cfg(target_arch = "aarch64")]
mod simd {
    use core::arch::aarch64::*;
    pub const SHIFT: u32 = 2;
    /// Bit 4*i+3 is set when byte i of the 16 bytes at `p` is `,`, `\n` or `"`.
    #[inline(always)]
    pub unsafe fn mask16(p: *const u8) -> u64 {
        let v = vld1q_u8(p);
        let m = vorrq_u8(
            vorrq_u8(vceqq_u8(v, vdupq_n_u8(b',')), vceqq_u8(v, vdupq_n_u8(b'\n'))),
            vceqq_u8(v, vdupq_n_u8(b'"')),
        );
        let n = vshrn_n_u16::<4>(vreinterpretq_u16_u8(m));
        vget_lane_u64::<0>(vreinterpret_u64_u8(n)) & 0x8888_8888_8888_8888
    }
}

/// Calls `on_row` with the N fields of every well-formed line of a chunk.
/// R-C3: only `\n` ends a line; a last line without `\n` is a line (Q1).
/// R-C4: every comma separates fields; the count must be exactly N.
/// R-C5..R-C7: a field may be wrapped in quotes as a whole (stripped here); any other
/// quote, a wrong field count or an empty line makes the line malformed and it is skipped.
/// An empty slice is a null field (R-C6).
#[inline(always)]
fn scan_rows<const N: usize>(chunk: S, mut on_row: impl FnMut(&[S; N])) {
    let len = chunk.len();
    let base = chunk.as_ptr();
    let mut fields: [S; N] = [&[]; N];
    let mut nf = 0usize; // fields closed so far in this line
    let mut bad = false;
    let mut fstart = 0usize; // start of the current field
    let mut nq = 0u32; // quotes seen in the current field
    let mut q_first = false; // the first quote was the field's first byte
    let mut last_q = 0usize;

    macro_rules! special {
        ($pos:expr, $c:expr) => {{
            let pos: usize = $pos;
            let c: u8 = $c;
            if c == b'"' {
                if nq == 0 {
                    q_first = pos == fstart;
                }
                nq += 1;
                last_q = pos;
            } else {
                // `,` or `\n`: the current field ends at pos.
                let (s, e) = if nq == 0 {
                    (fstart, pos)
                } else if nq == 2 && q_first && last_q + 1 == pos {
                    (fstart + 1, pos - 1)
                } else {
                    bad = true;
                    (fstart, pos)
                };
                if nf < N {
                    fields[nf] = unsafe { core::slice::from_raw_parts(base.add(s), e - s) };
                }
                nf += 1;
                fstart = pos + 1;
                nq = 0;
                if c == b'\n' {
                    if nf == N && !bad {
                        on_row(&fields);
                    }
                    nf = 0;
                    bad = false;
                }
            }
        }};
    }

    let mut i = 0usize;
    while i + 16 <= len {
        let mut m = unsafe { simd::mask16(base.add(i)) };
        while m != 0 {
            let pos = i + (m.trailing_zeros() >> simd::SHIFT) as usize;
            m &= m - 1;
            special!(pos, unsafe { *base.add(pos) });
        }
        i += 16;
    }
    while i < len {
        let c = chunk[i];
        if c == b',' || c == b'\n' || c == b'"' {
            special!(i, c);
        }
        i += 1;
    }
    if fstart < len || nf > 0 {
        special!(len, b'\n'); // last line without a trailing newline
    }
}

// ---------------------------------------------------------------------------
// ID interning: user ID -> u32. The id is (index within shard << 8) | shard, where the
// shard comes from the ID's hash. An ID is identified by a 96-bit fingerprint
// (hash_bytes, hash_bytes2) so that the hot paths never go back to the file bytes;
// with a few million IDs the chance of any two colliding is below 1e-14.
// Links intern from many threads (one lock per call); events and clicks are resolved
// one whole shard at a time by a single thread.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct InternShard {
    table: HashTable<(u64, u32, u32)>, // (h1, h2, index within shard)
    strs: Vec<S>,
    prefs: Vec<u64>, // first 8 bytes, big-endian, zero padded: orders like the bytes do
}

#[inline]
fn prefix_be(b: &[u8]) -> u64 {
    let mut t = [0u8; 8];
    let n = b.len().min(8);
    t[..n].copy_from_slice(&b[..n]);
    u64::from_be_bytes(t)
}

impl InternShard {
    #[inline]
    fn intern(&mut self, h1: u64, h2: u32, ptr: usize, len: u32, sh: usize) -> u32 {
        match self.table.entry(h1, |e| e.0 == h1 && e.1 == h2, |e| e.0) {
            Entry::Occupied(o) => (o.get().2 << 8) | sh as u32,
            Entry::Vacant(v) => {
                let local = self.strs.len() as u32;
                v.insert((h1, h2, local));
                let s: S = unsafe { core::slice::from_raw_parts(ptr as *const u8, len as usize) };
                self.strs.push(s);
                self.prefs.push(prefix_be(s));
                (local << 8) | sh as u32
            }
        }
    }
}

struct Interner {
    shards: Vec<Mutex<InternShard>>,
}

impl Interner {
    fn new() -> Self {
        Interner { shards: (0..NSHARD).map(|_| Mutex::new(InternShard::default())).collect() }
    }

    #[inline]
    fn intern(&self, b: S) -> u32 {
        let h1 = hash_bytes(b);
        let sh = shard_of(h1);
        self.shards[sh].lock().unwrap().intern(h1, hash_bytes2(b), b.as_ptr() as usize, b.len() as u32, sh)
    }

    /// Size of the id space: every id handed out so far is below this.
    fn id_space(&self) -> usize {
        let max_local = self.shards.iter().map(|s| s.lock().unwrap().strs.len()).max().unwrap_or(0);
        max_local << 8
    }
}

#[inline]
fn uf_find(parent: &mut [u32], mut x: u32) -> u32 {
    while parent[x as usize] != x {
        let g = parent[parent[x as usize] as usize];
        parent[x as usize] = g; // path halving
        x = g;
    }
    x
}

/// A value that tasks may mutate through a shared reference. Callers guarantee that
/// every value is touched by one task at a time.
struct Shared<T>(std::cell::UnsafeCell<T>);
unsafe impl<T: Send> Sync for Shared<T> {}
impl<T> Shared<T> {
    fn new(t: T) -> Self {
        Shared(std::cell::UnsafeCell::new(t))
    }
    #[allow(clippy::mut_from_ref)]
    unsafe fn get(&self) -> &mut T {
        &mut *self.0.get()
    }
    unsafe fn peek(&self) -> &T {
        &*self.0.get()
    }
}

#[inline(always)]
fn prefetch<T>(p: *const T) {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::x86_64::_mm_prefetch::<{ core::arch::x86_64::_MM_HINT_T0 }>(p as *const i8);
    }
    #[cfg(target_arch = "aarch64")]
    unsafe {
        core::arch::asm!("prfm pldl1keep, [{0}]", in(reg) p, options(nostack, preserves_flags, readonly));
    }
}

/// A byte slice of a mapped file packed into 64 bits: 48-bit address, 16-bit length.
#[inline(always)]
fn pack_ref(b: S) -> u64 {
    assert!(b.len() < 65_536, "ID longer than 64 KiB");
    (b.as_ptr() as u64) | ((b.len() as u64) << 48)
}

#[inline(always)]
fn unpack_ref(r: u64) -> S {
    unsafe { core::slice::from_raw_parts((r & 0xFFFF_FFFF_FFFF) as *const u8, (r >> 48) as usize) }
}

// ---------------------------------------------------------------------------
// Link table: read-only map from a linked user ID (by fingerprint) to its person,
// probed while parsing. 256 independent regions, one per hash shard, so it is built
// in parallel and a lookup touches one region.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct LinkSlot {
    h1: u64,
    canon: u32, // id of the ID that names the person; u32::MAX = empty slot
    h2: u32,
}

struct LinkTable {
    slots: Vec<LinkSlot>,
    rbits: u32, // each region has 1 << rbits slots
}

impl LinkTable {
    #[inline(always)]
    fn start(&self, h1: u64) -> (usize, usize, usize) {
        let mask = (1usize << self.rbits) - 1;
        (shard_of(h1) << self.rbits, ((h1 >> 8) as usize) & mask, mask)
    }

    #[inline(always)]
    fn prefetch(&self, h1: u64) {
        let (base, i, _) = self.start(h1);
        prefetch(unsafe { self.slots.as_ptr().add(base | i) });
    }

    #[inline(always)]
    fn get(&self, h1: u64, h2: u32) -> Option<u32> {
        let (base, mut i, mask) = self.start(h1);
        loop {
            let s = unsafe { self.slots.get_unchecked(base | i) };
            if s.canon == u32::MAX {
                return None;
            }
            if s.h1 == h1 && s.h2 == h2 {
                return Some(s.canon);
            }
            i = (i + 1) & mask;
        }
    }
}

// ---------------------------------------------------------------------------
// Rows. A person is identified by (pkey, h2):
//   linked ID   -> pkey = 1 << 63 | id of the naming ID, h2 = 0
//   other user  -> pkey = hash_bytes(user) with bit 63 cleared, h2 = hash_bytes2(user)
// k2 = h2 << 32 | ts_rel, so sorting by (pkey, k2) groups a person and orders by time.
// Timestamps are relative to `base` = window_start - 7 days (the earliest valid click).
// ---------------------------------------------------------------------------

const LINKED: u64 = 1 << 63;

/// A valid event, written once while parsing into its person's partition. 32 bytes.
#[derive(Clone, Copy)]
#[repr(C)]
struct Row {
    pkey: u64,
    k2: u64,
    name: u64, // packed user ID bytes (unused for linked persons)
    price: u32,
    cat: u16,
    typ: u8,
    dead: u8, // set by dedup when another copy of the event wins (R-E2)
}

/// A valid click. 32 bytes.
#[derive(Clone, Copy)]
#[repr(C)]
struct CRow {
    pkey: u64,
    k2: u64,
    cid: u64, // packed click_id bytes, for the R-K4 tie-break
    camp: u16,
    dead: u8, // set by dedup for every copy after the first (R-K2)
}

/// Dedup key of one well-formed event line (R-E1, R-E2). 24 bytes.
/// (h1, h2) is the 96-bit fingerprint of event_id.
#[derive(Clone, Copy)]
struct EKey {
    h1: u64,
    row: usize, // address of its Row, 0 when this copy is invalid (R-E3, R-E4)
    h2: u32,
    ingest: i32, // seconds relative to window_start; i32::MAX when unparseable
}

/// Dedup key of one valid click line (R-K2).
#[derive(Clone, Copy)]
struct CKey {
    h1: u64,
    row: usize,
    h2: u32,
}

/// Append-only buffer made of fixed-size blocks: element addresses stay valid, and
/// nothing is reserved beyond the current block.
struct BlockBuf<T> {
    blocks: Vec<Vec<T>>,
}

impl<T> BlockBuf<T> {
    const BLOCK: usize = 512;
    fn new() -> Self {
        BlockBuf { blocks: Vec::new() }
    }
    #[inline(always)]
    fn push(&mut self, v: T) -> *mut T {
        if self.blocks.last().map_or(true, |b| b.len() == b.capacity()) {
            self.blocks.push(Vec::with_capacity(Self::BLOCK));
        }
        let b = self.blocks.last_mut().unwrap();
        let n = b.len();
        unsafe {
            let p = b.as_mut_ptr().add(n);
            p.write(v);
            b.set_len(n + 1);
            p
        }
    }
    fn len(&self) -> usize {
        self.blocks.iter().map(|b| b.len()).sum()
    }
}

/// Everything one parser thread produces, bucketed by shard.
struct ThreadOut {
    ev_keys: Vec<BlockBuf<EKey>>, // by event_id shard
    ev_rows: Vec<BlockBuf<Row>>,  // by person shard
    cl_keys: Vec<BlockBuf<CKey>>, // by click_id shard
    cl_rows: Vec<BlockBuf<CRow>>, // by person shard
}

impl ThreadOut {
    fn new() -> Self {
        ThreadOut {
            ev_keys: (0..NSHARD).map(|_| BlockBuf::new()).collect(),
            ev_rows: (0..NSHARD).map(|_| BlockBuf::new()).collect(),
            cl_keys: (0..NSHARD).map(|_| BlockBuf::new()).collect(),
            cl_rows: (0..NSHARD).map(|_| BlockBuf::new()).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Parquet output (R-O1)
// ---------------------------------------------------------------------------

enum Col<'a> {
    Str(&'a [S]),
    OptStr(&'a [Option<S>]),
    Date(&'a [i32]),
    I64(&'a [i64]),
}

fn write_parquet(path: &Path, schema: &str, cols: &[Col], nrows: usize) {
    let schema = Arc::new(parse_message_type(schema).expect("schema"));
    let props = Arc::new(
        WriterProperties::builder()
            .set_compression(Compression::UNCOMPRESSED)
            .set_dictionary_enabled(false)
            .set_statistics_enabled(EnabledStatistics::None)
            .build(),
    );
    let file = fs::File::create(path).unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
    let mut w = SerializedFileWriter::new(file, schema, props).expect("parquet writer");
    if nrows > 0 {
        let mut rg = w.next_row_group().expect("row group");
        for c in cols {
            let mut cw = rg.next_column().expect("column").expect("column present");
            match c {
                Col::Str(v) => {
                    let vals: Vec<ByteArray> = v.iter().map(|s| ByteArray::from(*s)).collect();
                    cw.typed::<ByteArrayType>().write_batch(&vals, None, None).expect("write");
                }
                Col::OptStr(v) => {
                    let defs: Vec<i16> = v.iter().map(|s| s.is_some() as i16).collect();
                    let vals: Vec<ByteArray> = v.iter().flatten().map(|s| ByteArray::from(*s)).collect();
                    cw.typed::<ByteArrayType>().write_batch(&vals, Some(&defs), None).expect("write");
                }
                Col::Date(v) => {
                    cw.typed::<Int32Type>().write_batch(v, None, None).expect("write");
                }
                Col::I64(v) => {
                    cw.typed::<Int64Type>().write_batch(v, None, None).expect("write");
                }
            }
            cw.close().expect("close column");
        }
        rg.close().expect("close row group");
    }
    w.close().expect("close file");
}

const USER_SCHEMA: &str = "message user_daily {
    REQUIRED BYTE_ARRAY user_id (STRING);
    REQUIRED INT32 day (DATE);
    REQUIRED INT64 sessions;
    REQUIRED INT64 events;
    REQUIRED INT64 revenue_cents;
    OPTIONAL BYTE_ARRAY top_category (STRING);
}";

const CAMPAIGN_SCHEMA: &str = "message campaign_daily {
    REQUIRED BYTE_ARRAY campaign_id (STRING);
    REQUIRED BYTE_ARRAY channel (STRING);
    REQUIRED INT32 day (DATE);
    REQUIRED INT64 sessions;
    REQUIRED INT64 purchasing_sessions;
    REQUIRED INT64 revenue_cents;
    REQUIRED INT64 assisted_sessions;
}";

// ---------------------------------------------------------------------------
// Per-worker accumulator for the sessions / credit / assists pass
// ---------------------------------------------------------------------------

struct Acc {
    // campaign_daily cells, index = campaign * ndays + day
    c_sessions: Vec<i64>,
    c_purchasing: Vec<i64>,
    c_revenue: Vec<i64>,
    c_assisted: Vec<i64>,
    // user_daily rows
    u_user: Vec<S>,
    u_day: Vec<i32>,
    u_sessions: Vec<i64>,
    u_events: Vec<i64>,
    u_revenue: Vec<i64>,
    u_top: Vec<Option<S>>,
    // scratch: sliding 7-day click window (R-K7) and per-day category sums (R-O2)
    win_count: Vec<u32>,
    win_pos: Vec<u32>,
    active: Vec<u16>,
    cat_sum: Vec<i64>,
    events: Vec<Row>,
    clicks: Vec<CRow>,
    n_sessions: u64,
}

struct Dims<'a> {
    ndays: usize,
    day0: i64,
    base: i64, // ts = base + ts_rel
    organic: usize,
    cat_names: &'a [S],
    names: &'a [Vec<S>], // linked IDs: names[shard][index within shard]
}

impl Acc {
    fn new(ncamp: usize, ndays: usize, ncat: usize) -> Self {
        Acc {
            c_sessions: vec![0; ncamp * ndays],
            c_purchasing: vec![0; ncamp * ndays],
            c_revenue: vec![0; ncamp * ndays],
            c_assisted: vec![0; ncamp * ndays],
            u_user: Vec::new(),
            u_day: Vec::new(),
            u_sessions: Vec::new(),
            u_events: Vec::new(),
            u_revenue: Vec::new(),
            u_top: Vec::new(),
            win_count: vec![0; ncamp],
            win_pos: vec![0; ncamp],
            active: Vec::new(),
            cat_sum: vec![0; ncat],
            events: Vec::new(),
            clicks: Vec::new(),
            n_sessions: 0,
        }
    }

    /// R-O2: close one (person, day) row. top_category = highest summed purchase price,
    /// tie -> byte-wise smallest name, null without purchases.
    #[inline]
    fn flush_day(&mut self, d: &Dims, name: S, day: i64, sessions: i64, events: i64, revenue: i64) {
        let mut top: Option<usize> = None;
        if revenue > 0 {
            for c in 0..self.cat_sum.len() {
                let v = self.cat_sum[c];
                if v > 0 {
                    top = match top {
                        Some(t) if self.cat_sum[t] > v || (self.cat_sum[t] == v && d.cat_names[t] <= d.cat_names[c]) => {
                            Some(t)
                        }
                        _ => Some(c),
                    };
                }
            }
            self.cat_sum.fill(0);
        }
        self.u_user.push(name);
        self.u_day.push((d.day0 + day) as i32);
        self.u_sessions.push(sessions);
        self.u_events.push(events);
        self.u_revenue.push(revenue);
        self.u_top.push(top.map(|t| d.cat_names[t]));
    }

    /// Sessions (R-E5, R-E6), credit (R-K4, R-K5) and assists (R-K7) for the events and
    /// clicks currently in self.events / self.clicks (one partition of persons).
    fn process(&mut self, d: &Dims) {
        let mut events = std::mem::take(&mut self.events);
        let mut clicks = std::mem::take(&mut self.clicks);
        // Ties in ts need no order: one pass decides the sessions, so tied events cannot split.
        events.sort_unstable_by_key(|e| (e.pkey, e.k2));
        // Within a ts, click_id DESCENDING: the last click at or before a session start is
        // then the latest one with the smallest click_id (R-K4).
        clicks.sort_unstable_by(|a, b| {
            (a.pkey, a.k2).cmp(&(b.pkey, b.k2)).then_with(|| unpack_ref(b.cid).cmp(unpack_ref(a.cid)))
        });

        const TS: u64 = 0xFFFF_FFFF;
        let ndays = d.ndays;
        let n = events.len();
        let (mut i, mut ci) = (0usize, 0usize);
        while i < n {
            // One person = one (pkey, h2); h2 is the high half of k2.
            let pid = (events[i].pkey, events[i].k2 >> 32);
            let mut j = i;
            while j < n && (events[j].pkey, events[j].k2 >> 32) == pid {
                j += 1;
            }
            while ci < clicks.len() && (clicks[ci].pkey, clicks[ci].k2 >> 32) < pid {
                ci += 1;
            }
            let cs = ci;
            while ci < clicks.len() && (clicks[ci].pkey, clicks[ci].k2 >> 32) == pid {
                ci += 1;
            }
            let ev = &events[i..j];
            let pc = &clicks[cs..ci];
            i = j;
            let name: S = if pid.0 & LINKED != 0 {
                let id = pid.0 as u32;
                d.names[(id & 0xFF) as usize][(id >> 8) as usize] // R-L3
            } else {
                unpack_ref(ev[0].name) // R-L4
            };

            let (mut lo, mut hi) = (0usize, 0usize);
            let mut cur_day: i64 = -1;
            let (mut d_sessions, mut d_events, mut d_revenue) = (0i64, 0i64, 0i64);
            let mut k = 0;
            while k < ev.len() {
                // R-E5: a session runs while the gap to the previous event is <= 30 min.
                let start = (ev[k].k2 & TS) as i64;
                let day = (d.base + start).div_euclid(DAY_MS) - d.day0; // R-E6
                if day != cur_day {
                    if cur_day >= 0 {
                        self.flush_day(d, name, cur_day, d_sessions, d_events, d_revenue);
                    }
                    cur_day = day;
                    d_sessions = 0;
                    d_events = 0;
                    d_revenue = 0;
                }
                let mut prev = start;
                let (mut s_events, mut s_revenue, mut s_purchase) = (0i64, 0i64, false);
                while k < ev.len() && (ev[k].k2 & TS) as i64 - prev <= GAP_MS {
                    let e = &ev[k];
                    prev = (e.k2 & TS) as i64;
                    s_events += 1;
                    if e.typ == T_PURCHASE {
                        s_revenue += e.price as i64;
                        s_purchase = true;
                        self.cat_sum[e.cat as usize] += e.price as i64;
                    }
                    k += 1;
                }
                d_sessions += 1;
                d_events += s_events;
                d_revenue += s_revenue;
                self.n_sessions += 1;

                if !pc.is_empty() {
                    // R-K4: clicks with start - 7d <= ts <= start.
                    while hi < pc.len() && (pc[hi].k2 & TS) as i64 <= start {
                        let c = pc[hi].camp as usize;
                        self.win_count[c] += 1;
                        if self.win_count[c] == 1 {
                            self.win_pos[c] = self.active.len() as u32;
                            self.active.push(c as u16);
                        }
                        hi += 1;
                    }
                    while lo < hi && ((pc[lo].k2 & TS) as i64) < start - WEEK_MS {
                        let c = pc[lo].camp as usize;
                        self.win_count[c] -= 1;
                        if self.win_count[c] == 0 {
                            let p = self.win_pos[c] as usize;
                            let last = self.active.pop().unwrap();
                            if last as usize != c {
                                self.active[p] = last;
                                self.win_pos[last as usize] = p as u32;
                            }
                        }
                        lo += 1;
                    }
                }
                let credited = if hi > lo { pc[hi - 1].camp as usize } else { d.organic }; // R-K5
                let cell = credited * ndays + day as usize;
                self.c_sessions[cell] += 1;
                self.c_purchasing[cell] += s_purchase as i64;
                self.c_revenue[cell] += s_revenue;
                for &c in &self.active {
                    self.c_assisted[c as usize * ndays + day as usize] += 1; // R-K7
                }
            }
            if cur_day >= 0 {
                self.flush_day(d, name, cur_day, d_sessions, d_events, d_revenue);
            }
            for &c in &self.active {
                self.win_count[c as usize] = 0;
            }
            self.active.clear();
        }
        events.clear();
        clicks.clear();
        self.events = events; // keep the allocations for the next partition
        self.clicks = clicks;
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() {
    let mut clock = Clock::new();
    let data = PathBuf::from(std::env::var("DATA_DIR").unwrap_or_else(|_| "/data".into()));
    let out = PathBuf::from(std::env::var("OUTPUT_DIR").unwrap_or_else(|_| "/output".into()));
    let ncpu: usize = std::env::var("NCPU").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    if ncpu > 0 {
        let _ = rayon::ThreadPoolBuilder::new().num_threads(ncpu).build_global();
    }

    let manifest = fs::read_to_string(data.join("manifest.json")).expect("manifest.json");
    let ws = manifest_value(&manifest, "window_start"); // R-T9
    let we = manifest_value(&manifest, "window_end");
    let base = ws - WEEK_MS; // earliest valid click (R-T8); all stored timestamps are relative to it
    assert!(we > base && we - base <= u32::MAX as i64, "window too long for 32-bit relative timestamps");

    // --- products.csv: product_id -> category index (R-E7) ----------------------
    let mut cat_names: Vec<S> = Vec::new();
    let mut cat_index: HashMap<S, u16> = HashMap::new();
    let mut products: HashTable<(u64, S, u16)> = HashTable::new();
    for chunk in load_chunks(&data.join("products.csv")) {
        scan_rows::<2>(chunk, |&[pid, cat]| {
            if pid.is_empty() {
                return;
            }
            let idx = *cat_index.entry(cat).or_insert_with(|| {
                cat_names.push(cat);
                (cat_names.len() - 1) as u16
            });
            let h = hash_bytes(pid);
            if let Entry::Vacant(v) = products.entry(h, |e| e.0 == h && e.1 == pid, |e| e.0) {
                v.insert((h, pid, idx));
            }
        });
    }
    let cat_unknown = cat_names.len() as u16;
    cat_names.push(b"unknown");
    let ncat = cat_names.len();

    // --- campaigns.csv: campaign_id -> dense index, channel ----------------------
    let mut camp_ids: Vec<S> = Vec::new();
    let mut camp_channels: Vec<S> = Vec::new();
    let mut campaigns: HashTable<(u64, S, u16)> = HashTable::new();
    for chunk in load_chunks(&data.join("campaigns.csv")) {
        scan_rows::<2>(chunk, |&[cid, channel]| {
            if cid.is_empty() {
                return;
            }
            let h = hash_bytes(cid);
            if let Entry::Vacant(v) = campaigns.entry(h, |e| e.0 == h && e.1 == cid, |e| e.0) {
                v.insert((h, cid, camp_ids.len() as u16));
                camp_ids.push(cid);
                camp_channels.push(channel);
            }
        });
    }
    let organic = camp_ids.len(); // R-K5
    camp_ids.push(b"organic");
    camp_channels.push(b"organic");
    let ncamp = camp_ids.len();

    // --- links: union-find, person name = byte-wise smallest ID (R-L) -------------
    let interner = Interner::new();
    let link_pairs: Vec<(u32, u32)> = load_chunks(&data.join("links"))
        .into_par_iter()
        .flat_map_iter(|chunk| {
            let mut v = Vec::with_capacity(chunk.len() / 16);
            scan_rows::<2>(chunk, |&[a, b]| {
                if !a.is_empty() && !b.is_empty() {
                    v.push((interner.intern(a), interner.intern(b))); // R-L1
                }
            });
            v
        })
        .collect();
    let link_space = interner.id_space();
    let mut parent: Vec<u32> = (0..link_space as u32).collect();
    for &(a, b) in &link_pairs {
        let ra = uf_find(&mut parent, a);
        let rb = uf_find(&mut parent, b);
        if ra != rb {
            parent[ra.max(rb) as usize] = ra.min(rb); // R-L2
        }
    }
    // best[root] = id whose string is the byte-wise smallest in the component (R-L3);
    // canon[id] = the id that names the person.
    let mut canon: Vec<u32> = (0..link_space as u32).collect();
    let shards: Vec<InternShard> =
        interner.shards.into_iter().map(|s| s.into_inner().unwrap()).collect();
    {
        // Compare 8-byte prefixes first; only equal prefixes need the full strings.
        let less = |a: u32, b: u32| -> bool {
            let (ga, gb) = (&shards[(a & 0xFF) as usize], &shards[(b & 0xFF) as usize]);
            let (pa, pb) = (ga.prefs[(a >> 8) as usize], gb.prefs[(b >> 8) as usize]);
            pa < pb || (pa == pb && ga.strs[(a >> 8) as usize] < gb.strs[(b >> 8) as usize])
        };
        let mut best: Vec<u32> = (0..link_space as u32).collect();
        for (sh, g) in shards.iter().enumerate() {
            for local in 0..g.strs.len() {
                let id = ((local as u32) << 8) | sh as u32;
                let r = uf_find(&mut parent, id) as usize;
                if best[r] != id && less(id, best[r]) {
                    best[r] = id;
                }
            }
        }
        for (sh, g) in shards.iter().enumerate() {
            for local in 0..g.strs.len() {
                let id = ((local as u32) << 8) | sh as u32;
                canon[id as usize] = best[uf_find(&mut parent, id) as usize];
            }
        }
    }
    drop(parent);
    // Read-only lookup table, one region per shard, built in parallel.
    let max_shard = shards.iter().map(|s| s.strs.len()).max().unwrap_or(0);
    let rbits = (2 * max_shard.max(8)).next_power_of_two().trailing_zeros();
    let mut link_table =
        LinkTable { slots: vec![LinkSlot { h1: 0, canon: u32::MAX, h2: 0 }; NSHARD << rbits], rbits };
    link_table.slots.par_chunks_mut(1 << rbits).zip(shards.par_iter()).enumerate().for_each(|(sh, (region, shard))| {
        let mask = (1usize << rbits) - 1;
        for &(h1, h2, local) in shard.table.iter() {
            let mut i = ((h1 >> 8) as usize) & mask;
            while region[i].canon != u32::MAX {
                i = (i + 1) & mask;
            }
            region[i] = LinkSlot { h1, canon: canon[((local << 8) | sh as u32) as usize], h2 };
        }
    });
    let names: Vec<Vec<S>> = shards.into_iter().map(|s| s.strs).collect();
    clock.log(&format!("links: {} pairs, {} linked ids", link_pairs.len(), names.iter().map(|v| v.len()).sum::<usize>()));

    // --- parse events and clicks together, every chunk of every file (R-C1) -------------
    // Each valid row is written once, straight into its person's partition; each line's
    // dedup key goes to its event_id / click_id partition.
    #[derive(Clone, Copy)]
    enum Kind {
        Events,
        Clicks,
    }
    let mut work: Vec<(Kind, S)> = Vec::new();
    work.extend(load_chunks(&data.join("events")).into_iter().map(|c| (Kind::Events, c)));
    work.extend(load_chunks(&data.join("clicks")).into_iter().map(|c| (Kind::Clicks, c)));
    let nthreads = rayon::current_num_threads();
    // One output set per pool thread, plus one for the calling thread (rayon runs tiny jobs inline).
    let outs: Vec<Shared<ThreadOut>> = (0..nthreads + 1).map(|_| Shared::new(ThreadOut::new())).collect();
    work.par_iter().for_each(|&(kind, chunk)| {
        // Safety: a pool thread runs one of these closures at a time and never yields inside it.
        let out = unsafe { outs[rayon::current_thread_index().unwrap_or(nthreads)].get() };
        match kind {
            Kind::Events => scan_rows::<7>(chunk, |f| {
                let eid = f[0];
                if eid.is_empty() {
                    return; // R-E1
                }
                let user = f[1];
                let uh1 = hash_bytes(user);
                link_table.prefetch(uh1);
                let h1 = hash_bytes(eid);
                let ingest = parse_ts(f[3]); // R-T10
                let mut key = EKey {
                    h1,
                    row: 0,
                    h2: hash_bytes2(eid),
                    ingest: match ingest {
                        Some(t) => (t - ws).div_euclid(1000).clamp(i32::MIN as i64, i32::MAX as i64 - 1) as i32,
                        None => i32::MAX,
                    },
                };
                'validate: {
                    let Some(ingest) = ingest else { break 'validate };
                    if user.is_empty() || f[5].is_empty() {
                        break 'validate; // R-E3: user_id and product_id non-empty
                    }
                    let Some(ts) = parse_ts(f[2]) else { break 'validate };
                    if ts < ws || ts >= we {
                        break 'validate; // R-T7
                    }
                    if ingest - ts > LATE_MS {
                        break 'validate; // R-E4
                    }
                    let typ = match f[4] {
                        b"view" => T_VIEW,
                        b"cart" => T_CART,
                        b"purchase" => T_PURCHASE,
                        _ => break 'validate,
                    };
                    let price = if typ == T_PURCHASE {
                        match parse_price(f[6]) {
                            Some(p) => p,
                            None => break 'validate,
                        }
                    } else {
                        0 // price ignored for view/cart
                    };
                    let ph = hash_bytes(f[5]);
                    let cat = products.find(ph, |e| e.0 == ph && e.1 == f[5]).map_or(cat_unknown, |e| e.2); // R-E7
                    let uh2 = hash_bytes2(user);
                    let ts_rel = (ts - base) as u64;
                    // R-L4/R-L6: a linked ID belongs to its person, any other ID is its own person.
                    let (pkey, k2, name, shard) = match link_table.get(uh1, uh2) {
                        Some(c) => (LINKED | c as u64, ts_rel, 0, (c & 0xFF) as usize),
                        None => (uh1 & !LINKED, ((uh2 as u64) << 32) | ts_rel, pack_ref(user), shard_of(uh1)),
                    };
                    key.row = out.ev_rows[shard].push(Row { pkey, k2, name, price, cat, typ, dead: 0 }) as usize;
                }
                out.ev_keys[shard_of(h1)].push(key);
            }),
            Kind::Clicks => scan_rows::<4>(chunk, |&[cid, user, camp, ts]| {
                // R-K1..R-K3. Copies of a click are identical, so an invalid line can never
                // be the kept copy of a valid click: only valid lines need a dedup key.
                if cid.is_empty() || user.is_empty() {
                    return;
                }
                let uh1 = hash_bytes(user);
                link_table.prefetch(uh1);
                let Some(t) = parse_ts(ts) else { return };
                if t < base || t >= we {
                    return; // R-T8
                }
                let ch = hash_bytes(camp);
                let Some(e) = campaigns.find(ch, |e| e.0 == ch && e.1 == camp) else { return }; // R-K3: exact match
                let uh2 = hash_bytes2(user);
                let ts_rel = (t - base) as u64;
                let (pkey, k2, shard) = match link_table.get(uh1, uh2) {
                    Some(c) => (LINKED | c as u64, ts_rel, (c & 0xFF) as usize),
                    None => (uh1 & !LINKED, ((uh2 as u64) << 32) | ts_rel, shard_of(uh1)),
                };
                let row = out.cl_rows[shard].push(CRow { pkey, k2, cid: pack_ref(cid), camp: e.2, dead: 0 }) as usize;
                let h1 = hash_bytes(cid);
                out.cl_keys[shard_of(h1)].push(CKey { h1, row, h2: hash_bytes2(cid) });
            }),
        }
    });
    let outs: Vec<ThreadOut> = outs.into_iter().map(|s| s.0.into_inner()).collect();
    clock.log("events and clicks parsed");

    // --- dedup, one event_id / click_id shard per task. Losing rows are flagged dead.
    (0..NSHARD).into_par_iter().for_each(|s| {
        // R-E2: dedup on event_id BEFORE validation: the copy with the smallest ingest_ts is
        // kept, valid or not; every other copy's row dies.
        let n: usize = outs.iter().map(|o| o.ev_keys[s].len()).sum();
        let mut table: HashTable<EKey> = HashTable::with_capacity(n);
        for o in &outs {
            for block in &o.ev_keys[s].blocks {
                for k in block {
                    match table.entry(k.h1, |e| e.h1 == k.h1 && e.h2 == k.h2, |e| e.h1) {
                        Entry::Occupied(mut occ) => {
                            let cur = occ.get_mut();
                            let loser = if k.ingest < cur.ingest { std::mem::replace(cur, *k).row } else { k.row };
                            if loser != 0 {
                                // Safety: a row is referenced by exactly one key, and its key
                                // lives in this shard only.
                                unsafe { core::ptr::addr_of_mut!((*(loser as *mut Row)).dead).write(1) };
                            }
                        }
                        Entry::Vacant(v) => {
                            v.insert(*k);
                        }
                    }
                }
            }
        }
        drop(table);
        // R-K2: keep the first copy of a click, flag the rest.
        let n: usize = outs.iter().map(|o| o.cl_keys[s].len()).sum();
        let mut table: HashTable<(u64, u32)> = HashTable::with_capacity(n);
        for o in &outs {
            for block in &o.cl_keys[s].blocks {
                for k in block {
                    match table.entry(k.h1, |e| e.0 == k.h1 && e.1 == k.h2, |e| e.0) {
                        Entry::Occupied(_) => unsafe {
                            core::ptr::addr_of_mut!((*(k.row as *mut CRow)).dead).write(1)
                        },
                        Entry::Vacant(v) => {
                            v.insert((k.h1, k.h2));
                        }
                    }
                }
            }
        }
    });
    clock.log("deduped");

    // --- sessions, credit, assists: a fixed number of tasks, each with one accumulator
    // and a spread of person partitions.
    let day0 = ws.div_euclid(DAY_MS);
    let ndays = ((we - 1).div_euclid(DAY_MS) - day0 + 1).max(1) as usize;
    let dims = Dims { ndays, day0, base, organic, cat_names: &cat_names, names: &names };
    let ntask = (nthreads * 2).clamp(1, NSHARD);
    let accs: Vec<Acc> = (0..ntask)
        .into_par_iter()
        .map(|t| {
            let mut acc = Acc::new(ncamp, ndays, ncat);
            for p in (t..NSHARD).step_by(ntask) {
                for o in &outs {
                    for block in &o.ev_rows[p].blocks {
                        acc.events.extend(block.iter().filter(|r| r.dead == 0));
                    }
                    for block in &o.cl_rows[p].blocks {
                        acc.clicks.extend(block.iter().filter(|r| r.dead == 0));
                    }
                }
                acc.process(&dims);
            }
            acc
        })
        .collect();
    let n_sessions: u64 = accs.iter().map(|a| a.n_sessions).sum();
    let n_user_rows: usize = accs.iter().map(|a| a.u_user.len()).sum();
    clock.log(&format!("sessions: {n_sessions}, user_daily rows: {n_user_rows}"));

    // --- outputs (R-O): one user_daily file per task, written in parallel --------------
    let ud = out.join("user_daily");
    let cd = out.join("campaign_daily");
    fs::create_dir_all(&ud).unwrap_or_else(|e| panic!("mkdir {}: {e}", ud.display()));
    fs::create_dir_all(&cd).unwrap_or_else(|e| panic!("mkdir {}: {e}", cd.display()));
    accs.par_iter().enumerate().for_each(|(i, a)| {
        if i > 0 && a.u_user.is_empty() {
            return; // part-0 is always written, so the table has a schema even when empty
        }
        write_parquet(
            &ud.join(format!("part-{i}.parquet")),
            USER_SCHEMA,
            &[
                Col::Str(&a.u_user),
                Col::Date(&a.u_day),
                Col::I64(&a.u_sessions),
                Col::I64(&a.u_events),
                Col::I64(&a.u_revenue),
                Col::OptStr(&a.u_top),
            ],
            a.u_user.len(),
        );
    });

    let (mut k_id, mut k_channel, mut k_day) = (Vec::new(), Vec::new(), Vec::new());
    let (mut k_sessions, mut k_purchasing, mut k_revenue, mut k_assisted) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for c in 0..ncamp {
        for d in 0..ndays {
            let cell = c * ndays + d;
            let sessions: i64 = accs.iter().map(|a| a.c_sessions[cell]).sum();
            let assisted: i64 = accs.iter().map(|a| a.c_assisted[cell]).sum();
            if sessions > 0 || assisted > 0 {
                // R-O3
                k_id.push(camp_ids[c]);
                k_channel.push(camp_channels[c]);
                k_day.push((day0 + d as i64) as i32);
                k_sessions.push(sessions);
                k_purchasing.push(accs.iter().map(|a| a.c_purchasing[cell]).sum());
                k_revenue.push(accs.iter().map(|a| a.c_revenue[cell]).sum());
                k_assisted.push(assisted);
            }
        }
    }
    let n_camp_rows = k_id.len();
    write_parquet(
        &cd.join("part-0.parquet"),
        CAMPAIGN_SCHEMA,
        &[
            Col::Str(&k_id),
            Col::Str(&k_channel),
            Col::Date(&k_day),
            Col::I64(&k_sessions),
            Col::I64(&k_purchasing),
            Col::I64(&k_revenue),
            Col::I64(&k_assisted),
        ],
        n_camp_rows,
    );
    clock.log(&format!("written: {n_user_rows} user rows, {n_camp_rows} campaign rows"));
    if std::env::var_os("PROF").is_some() {
        eprintln!("PROF {}", proc_stats());
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
        eprintln!("PROF exit_called_at_ns={}", now.as_nanos());
    }
    // Everything is flushed and closed; skip destructors and unmapping.
    std::process::exit(0);
}
