//! Shopping Sessions, Track B: Rust pipeline.
//!
//! Rule IDs (R-C2, R-E5, ...) refer to RULES_DIGEST.md; rules.md is authoritative.
//! Reads $DATA_DIR, writes $OUTPUT_DIR/{user_daily,campaign_daily}/part-0.parquet.
//! Logs go to stderr only.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use hashbrown::hash_table::Entry;
use hashbrown::{HashMap, HashTable};
use memchr::memchr;
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
const CHUNK_BYTES: usize = 1 << 20;

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

#[inline(always)]
fn mum(a: u64, b: u64) -> u64 {
    let r = (a as u128) * (b as u128);
    (r as u64) ^ ((r >> 64) as u64)
}

/// 96-bit fingerprint (h1, h2) of an ID in one pass (wyhash-style folded multiplies).
/// For IDs up to 16 bytes, (a, c) below is an exact encoding of the bytes, and h1 and h2
/// are two different mixes of it; longer IDs run two independent lanes.
#[cfg_attr(feature = "prof", inline(never))]
#[cfg_attr(not(feature = "prof"), inline(always))]
fn fingerprint(b: &[u8]) -> (u64, u32) {
    const S0: u64 = 0xA076_1D64_78BD_642F;
    const S1: u64 = 0xE703_7ED1_A0B4_28DB;
    const S2: u64 = 0x8EBC_6AF0_9C88_C6E3;
    const S3: u64 = 0x5899_65CC_7537_4CC3;
    let n = b.len();
    let p = b.as_ptr();
    unsafe {
        let r4 = |o: usize| (p.add(o) as *const u32).read_unaligned() as u64;
        let r8 = |o: usize| (p.add(o) as *const u64).read_unaligned();
        let (a, c, s1, s2);
        if n <= 16 {
            if n >= 4 {
                let d = (n >> 3) << 2;
                a = (r4(0) << 32) | r4(d);
                c = (r4(n - 4) << 32) | r4(n - 4 - d);
            } else if n > 0 {
                a = ((*p as u64) << 16) | ((*p.add(n >> 1) as u64) << 8) | (*p.add(n - 1) as u64);
                c = 0;
            } else {
                a = 0;
                c = 0;
            }
            s1 = S0;
            s2 = S2;
        } else {
            let (mut t1, mut t2) = (S0, S2);
            let mut i = 0;
            while i + 16 < n {
                let (x, y) = (r8(i), r8(i + 8));
                t1 = mum(x ^ S1, y ^ t1);
                t2 = mum(x ^ S3, y ^ t2);
                i += 16;
            }
            a = r8(n - 16);
            c = r8(n - 8);
            s1 = t1;
            s2 = t2;
        }
        let h1 = mum(S1 ^ (n as u64), mum(a ^ S1, c ^ s1));
        let h2 = mum(S3 ^ (n as u64), mum(a ^ S3, c ^ s2));
        (h1, (h2 >> 32) as u32)
    }
}

#[inline(always)]
fn hash_bytes(b: &[u8]) -> u64 {
    fingerprint(b).0
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
    let len = f.metadata().map(|m| m.len()).unwrap() as usize;
    // MAP_POPULATE maps every page now, from the page cache, so parsing takes no page faults.
    // Files are mapped from many threads at once (see load_chunks). The mapping is never unmapped.
    let p = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ,
            libc::MAP_PRIVATE | libc::MAP_POPULATE,
            std::os::fd::AsRawFd::as_raw_fd(&f),
            0,
        )
    };
    assert!(p != libc::MAP_FAILED, "mmap {}: {}", path.display(), std::io::Error::last_os_error());
    unsafe { core::slice::from_raw_parts(p as *const u8, len) }
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
    let maps: Vec<S> = csv_files(path).par_iter().map(|f| map_file(f)).collect();
    for data in maps {
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

/// (year, month, day) for days since 1970-01-01 (Hinnant's civil_from_days).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + if m <= 2 { 1 } else { 0 }, m, d)
}

/// Fast paths for the common timestamp shapes; anything else goes to `parse_ts`, so the
/// result is always exactly what `parse_ts` returns.
struct TsFast {
    /// The months around the window: ("YYYY-MM-" as a little-endian u64, days since the
    /// epoch of day 0 of that month, days in the month).
    months: Vec<(u64, i64, i64)>,
}

impl TsFast {
    fn new(ws: i64, we: i64) -> Self {
        let mut months: Vec<(u64, i64, i64)> = Vec::new();
        let (d0, d1) = ((ws - 9 * DAY_MS).div_euclid(DAY_MS), (we + 9 * DAY_MS).div_euclid(DAY_MS));
        for day in d0..=d1 {
            let (y, m, _) = civil_from_days(day);
            if !(0..=9999).contains(&y) {
                continue;
            }
            let text = format!("{y:04}-{m:02}-");
            let key = u64::from_le_bytes(text.as_bytes().try_into().unwrap());
            if months.iter().all(|e| e.0 != key) {
                let first = days_from_civil(y, m, 1);
                let (ny, nm) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
                months.push((key, first - 1, days_from_civil(ny, nm, 1) - first));
            }
        }
        TsFast { months }
    }

    #[cfg_attr(feature = "prof", inline(never))]
    #[cfg_attr(not(feature = "prof"), inline(always))]
    fn parse(&self, b: &[u8]) -> Option<i64> {
        const ZEROS: u64 = 0x3030_3030_3030_3030;
        let n = b.len();
        let p = b.as_ptr();
        unsafe {
            if n == 20 {
                // F1: YYYY-MM-DDTHH:MM:SSZ with the month taken from the table.
                let pre = (p as *const u64).read_unaligned();
                for &(key, day0, dim) in &self.months {
                    if key == pre {
                        let (d0, d1) = ((*p.add(8)).wrapping_sub(b'0'), (*p.add(9)).wrapping_sub(b'0'));
                        let v = (p.add(11) as *const u64).read_unaligned() ^ 0x3030_3A30_303A_3030; // HH:MM:SS
                        if d0 > 9
                            || d1 > 9
                            || *p.add(10) != b'T'
                            || *p.add(19) != b'Z'
                            || v & 0xF0F0_FFF0_F0FF_F0F0 != 0
                            || (v + 0x0606_0006_0600_0606) & 0xF0F0_00F0_F000_F0F0 != 0
                        {
                            break;
                        }
                        let dd = (d0 * 10 + d1) as i64;
                        let h = ((v & 0xFF) * 10 + ((v >> 8) & 0xFF)) as i64;
                        let mi = (((v >> 24) & 0xFF) * 10 + ((v >> 32) & 0xFF)) as i64;
                        let sec = (((v >> 48) & 0xFF) * 10 + (v >> 56)) as i64;
                        if dd < 1 || dd > dim || h > 23 || mi > 59 || sec > 59 {
                            return None; // R-T5
                        }
                        return Some(((day0 + dd) * 86_400 + h * 3600 + mi * 60 + sec) * 1000);
                    }
                }
            } else if n == 13 {
                // F3 with 13 digits: 8 digits at once, then 5.
                let v = (p as *const u64).read_unaligned() ^ ZEROS;
                if v & 0xF0F0_F0F0_F0F0_F0F0 == 0 && (v + 0x0606_0606_0606_0606) & 0xF0F0_F0F0_F0F0_F0F0 == 0 {
                    let v = (v * 10 + (v >> 8)) & 0x00FF_00FF_00FF_00FF;
                    let v = (v * 100 + (v >> 16)) & 0x0000_FFFF_0000_FFFF;
                    let mut x = ((v * 10_000 + (v >> 32)) & 0xFFFF_FFFF) as i64;
                    let mut ok = true;
                    for k in 8..13 {
                        let d = (*p.add(k)).wrapping_sub(b'0');
                        ok &= d <= 9;
                        x = x * 10 + d as i64;
                    }
                    if ok {
                        return Some(x);
                    }
                }
            }
        }
        parse_ts(b)
    }
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
// Scanner. Stage 1 turns a chunk into a structural index with 64-byte SIMD masks:
// the positions of every `,` and `\n`, and a bitmap of every `"`. Stage 2 cuts
// lines out of the index.
// ---------------------------------------------------------------------------

#[cfg(target_arch = "x86_64")]
mod simd {
    use core::arch::x86_64::*;
    /// (commas, newlines, quotes): bit i set when byte i of the 64 bytes at `p` is that byte.
    #[cfg(target_feature = "avx2")]
    #[inline(always)]
    pub unsafe fn masks3(p: *const u8) -> (u64, u64, u64) {
        let (comma, nl, quote) =
            (_mm256_set1_epi8(b',' as i8), _mm256_set1_epi8(b'\n' as i8), _mm256_set1_epi8(b'"' as i8));
        let a = _mm256_loadu_si256(p as *const __m256i);
        let b = _mm256_loadu_si256(p.add(32) as *const __m256i);
        let m = |x: __m256i, c: __m256i| _mm256_movemask_epi8(_mm256_cmpeq_epi8(x, c)) as u32 as u64;
        (m(a, comma) | (m(b, comma) << 32), m(a, nl) | (m(b, nl) << 32), m(a, quote) | (m(b, quote) << 32))
    }
    #[cfg(not(target_feature = "avx2"))]
    #[inline(always)]
    pub unsafe fn masks3(p: *const u8) -> (u64, u64, u64) {
        let (comma, nl, quote) = (_mm_set1_epi8(b',' as i8), _mm_set1_epi8(b'\n' as i8), _mm_set1_epi8(b'"' as i8));
        let (mut c, mut n, mut q) = (0u64, 0u64, 0u64);
        for k in 0..4 {
            let v = _mm_loadu_si128(p.add(16 * k) as *const __m128i);
            c |= (_mm_movemask_epi8(_mm_cmpeq_epi8(v, comma)) as u32 as u64) << (16 * k);
            n |= (_mm_movemask_epi8(_mm_cmpeq_epi8(v, nl)) as u32 as u64) << (16 * k);
            q |= (_mm_movemask_epi8(_mm_cmpeq_epi8(v, quote)) as u32 as u64) << (16 * k);
        }
        (c, n, q)
    }
}

#[cfg(target_arch = "aarch64")]
mod simd {
    use core::arch::aarch64::*;
    #[inline(always)]
    unsafe fn bitmask(m: [uint8x16_t; 4]) -> u64 {
        let bits = vld1q_u8([1u8, 2, 4, 8, 16, 32, 64, 128, 1, 2, 4, 8, 16, 32, 64, 128].as_ptr());
        let s0 = vpaddq_u8(vandq_u8(m[0], bits), vandq_u8(m[1], bits));
        let s1 = vpaddq_u8(vandq_u8(m[2], bits), vandq_u8(m[3], bits));
        let s = vpaddq_u8(s0, s1);
        let s = vpaddq_u8(s, s);
        vgetq_lane_u64::<0>(vreinterpretq_u64_u8(s))
    }
    /// (commas, newlines, quotes): bit i set when byte i of the 64 bytes at `p` is that byte.
    #[inline(always)]
    pub unsafe fn masks3(p: *const u8) -> (u64, u64, u64) {
        let v = [vld1q_u8(p), vld1q_u8(p.add(16)), vld1q_u8(p.add(32)), vld1q_u8(p.add(48))];
        let m = |c: u8| {
            let d = vdupq_n_u8(c);
            bitmask([vceqq_u8(v[0], d), vceqq_u8(v[1], d), vceqq_u8(v[2], d), vceqq_u8(v[3], d)])
        };
        (m(b','), m(b'\n'), m(b'"'))
    }
}

/// Kept for the call signature; the fused scanner needs no per-thread state.
#[derive(Default)]
struct Scan;

/// Calls `on_row` with the N fields of every well-formed line of a chunk.
/// One pass: every 64-byte block becomes three bitmasks (commas, newlines, quotes) and
/// lines are cut straight from them; nothing is written to memory in between.
/// R-C3: only `\n` ends a line; a last line without `\n` is a line (Q1).
/// R-C4: every comma separates fields; the count must be exactly N.
/// R-C5..R-C7: a field may be wrapped in quotes as a whole (stripped here); any other
/// quote, a wrong field count or an empty line makes the line malformed and it is skipped.
/// An empty slice is a null field (R-C6).
#[cfg_attr(feature = "prof", inline(never))]
#[cfg_attr(not(feature = "prof"), inline(always))]
fn scan_rows<const N: usize>(chunk: S, _sc: &mut Scan, mut on_row: impl FnMut(&[S; N])) {
    let len = chunk.len();
    assert!(len < u32::MAX as usize - 128);
    let base = chunk.as_ptr();
    let mut emit = |line_start: usize, commas: &[u32; N], end: usize, nq: u32| {
        let mut fields: [S; N] = [&[]; N];
        let mut s = line_start;
        for k in 0..N {
            let e = if k + 1 < N { commas[k] as usize } else { end };
            fields[k] = unsafe { core::slice::from_raw_parts(base.add(s), e - s) };
            s = e + 1;
        }
        if nq != 0 {
            // Every quote must be the first or last byte of a field that has both.
            let mut wrapped = 0u32;
            for f in fields.iter_mut() {
                if !f.is_empty() && f[0] == b'"' {
                    let l = f.len();
                    if l < 2 || f[l - 1] != b'"' {
                        return; // R-C7
                    }
                    *f = &f[1..l - 1];
                    wrapped += 2;
                }
            }
            if wrapped != nq {
                return; // R-C7
            }
        }
        on_row(&fields);
    };
    let mut commas = [0u32; N]; // commas of the current line; the last slot is never used
    let mut nc = 0usize; // commas of the current line so far; N means "too many"
    let mut nq = 0u32; // quotes of the current line so far
    let mut line_start = 0usize;
    let mut tail = [0u8; 64]; // zero padding: never a structural byte
    let mut i = 0usize;
    while i < len {
        let (mut cm, mut nm, mut qm) = unsafe {
            if i + 64 <= len {
                simd::masks3(base.add(i))
            } else {
                tail[..len - i].copy_from_slice(&chunk[i..]);
                simd::masks3(tail.as_ptr())
            }
        };
        while nm != 0 {
            let bit = nm.trailing_zeros();
            let below = (1u64 << bit) - 1;
            let cs = cm & below;
            let k = cs.count_ones() as usize;
            nq += (qm & below).count_ones();
            let end = i + bit as usize;
            if nc + k == N - 1 {
                let mut m = cs;
                for slot in commas.iter_mut().take(N - 1).skip(nc) {
                    *slot = i as u32 + m.trailing_zeros();
                    m &= m.wrapping_sub(1);
                }
                emit(line_start, &commas, end, nq);
            }
            let upto = below | (1u64 << bit);
            cm &= !upto;
            qm &= !upto;
            nm &= nm - 1;
            nc = 0;
            nq = 0;
            line_start = end + 1;
        }
        // What is left of the block continues the current line.
        let k = cm.count_ones() as usize;
        if nc + k <= N - 1 {
            while cm != 0 {
                commas[nc] = i as u32 + cm.trailing_zeros();
                nc += 1;
                cm &= cm - 1;
            }
        } else {
            nc = N;
        }
        nq += qm.count_ones();
        i += 64;
    }
    if line_start < len && nc == N - 1 {
        emit(line_start, &commas, len, nq); // a last line without `\n` (Q1)
    }
}

// ---------------------------------------------------------------------------
// ID interning: user ID -> u32. The id is (index within shard << 8) | shard, where the
// shard comes from the ID's hash. An ID is identified by a 96-bit fingerprint
// (see fingerprint) so that the hot paths never go back to the file bytes;
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
        let (h1, h2) = fingerprint(b);
        let sh = shard_of(h1);
        self.shards[sh].lock().unwrap().intern(h1, h2, b.as_ptr() as usize, b.len() as u32, sh)
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

    #[cfg_attr(feature = "prof", inline(never))]
    #[cfg_attr(not(feature = "prof"), inline(always))]
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
//   other user  -> (pkey, h2) = fingerprint(user), pkey with bit 63 cleared, top 23 bits of h2
// Timestamps are relative to `base` = window_start - 7 days (the earliest valid click).
// Byte strings (user ID, click ID) are kept as 40-bit offsets from the lowest mapped
// input address; their end is the next `,` or `"`.
// ---------------------------------------------------------------------------

const LINKED: u64 = 1 << 63;

/// Person keys are stored rotated right by ROT bits: the top BUCKET_BITS of a stored key are
/// then bits 8..18 of the original, which are well spread inside one person partition both
/// for linked persons (low bits of the naming ID's index) and for other users (hash bits).
/// Sorting by the stored key is therefore "bucket first", and each bucket is tiny.
const ROT: u32 = 18;
const BUCKET_BITS: u32 = 10;
const NBUCKET: usize = 1 << BUCKET_BITS;

#[inline(always)]
fn bucket_of(stored_pkey: u64) -> usize {
    (stored_pkey >> (64 - BUCKET_BITS)) as usize
}

const TS_MASK: u64 = 0xFFFF_FFFF;

/// A valid event or click, written once while parsing into its person's partition. 24 bytes.
///   w0 = person key, rotated
///   w1 = h2 (23 bits) << 41 | ts_rel (32 bits) << 9 | low 9 bits
///        events: category (8 bits) << 1 | is_purchase;  clicks: 0
///   w2 = events: user ID offset (40 bits) << 24 | price (24 bits)
///        clicks: click_id offset (40 bits) << 16 | campaign (16 bits)
/// Sorting by (w0, w1) groups a person and orders its rows by time.
#[derive(Clone, Copy)]
#[repr(C)]
struct Row {
    w0: u64,
    w1: u64,
    w2: u64,
}

impl Row {
    #[inline(always)]
    fn person(&self) -> (u64, u64) {
        (self.w0, self.w1 >> 41)
    }
    #[inline(always)]
    fn ts(&self) -> i64 {
        ((self.w1 >> 9) & TS_MASK) as i64
    }
}

/// Dedup key of one line. 16 bytes.
///   events (R-E1, R-E2): w = h2 (10 bits) << 54 | ingest (22 bits) << 32 | row id
///   clicks (R-K2):       w = h2 (32 bits) << 32 | row id
/// (h1, h2) is the fingerprint of event_id / click_id. The row id locates the line's Row
/// (thread 4 bits, block 19 bits, slot 8 bits); NO_ROW when this copy is invalid.
#[derive(Clone, Copy)]
struct Key {
    h1: u64,
    w: u64,
}

const NO_ROW: u32 = u32::MAX;
const INGEST_BITS: u64 = 0x3F_FFFF;
const BLK: usize = 256;

/// A fixed-size block of rows or keys. `dead` has one bit per slot, set by dedup when
/// another copy of the line wins.
#[repr(C)]
struct Block<T> {
    dead: [std::sync::atomic::AtomicU64; 4],
    len: u32,
    items: [std::mem::MaybeUninit<T>; BLK],
}

impl<T> Block<T> {
    #[inline(always)]
    fn items(&self) -> &[T] {
        unsafe { core::slice::from_raw_parts(self.items.as_ptr() as *const T, self.len as usize) }
    }
    #[inline(always)]
    fn is_dead(&self, slot: usize) -> bool {
        self.dead[slot >> 6].load(std::sync::atomic::Ordering::Relaxed) >> (slot & 63) & 1 != 0
    }
}

/// Bump allocator over 2 MiB slabs that ask for transparent huge pages: one page fault
/// per slab instead of one per 4 KiB.
struct Slabs {
    cur: usize,
    end: usize,
}

const SLAB: usize = 2 << 20;

impl Slabs {
    fn alloc<T>(&mut self) -> *mut Block<T> {
        let size = (std::mem::size_of::<Block<T>>() + 63) & !63;
        if self.cur + size > self.end {
            let layout = std::alloc::Layout::from_size_align(SLAB, SLAB).unwrap();
            let p = unsafe { std::alloc::alloc(layout) };
            assert!(!p.is_null(), "out of memory");
            unsafe { libc::madvise(p as *mut libc::c_void, SLAB, libc::MADV_HUGEPAGE) };
            self.cur = p as usize;
            self.end = self.cur + SLAB;
        }
        let b = self.cur as *mut Block<T>;
        self.cur += size;
        unsafe {
            core::ptr::addr_of_mut!((*b).dead).write(Default::default());
            core::ptr::addr_of_mut!((*b).len).write(0);
        }
        b
    }
}

/// The blocks of one shard, in the order they were filled.
struct Bucket<T> {
    blocks: Vec<*mut Block<T>>,
    cur: *mut Block<T>,
    cur_no: u32, // number of `cur` in the thread's block table (rows only)
}

impl<T> Bucket<T> {
    fn new() -> Self {
        Bucket { blocks: Vec::new(), cur: core::ptr::null_mut(), cur_no: 0 }
    }
    /// Appends a value; `table` numbers the thread's blocks so that a row id can find them.
    /// Returns (block number, slot).
    #[inline(always)]
    fn push(&mut self, v: T, slabs: &mut Slabs, table: &mut Vec<*mut Block<T>>) -> (u32, u32) {
        unsafe {
            if self.cur.is_null() || (*self.cur).len as usize == BLK {
                self.cur = slabs.alloc::<T>();
                self.cur_no = table.len() as u32;
                table.push(self.cur);
                self.blocks.push(self.cur);
            }
            let b = &mut *self.cur;
            let slot = b.len;
            b.items.as_mut_ptr().add(slot as usize).write(std::mem::MaybeUninit::new(v));
            b.len = slot + 1;
            (self.cur_no, slot)
        }
    }
    fn len(&self) -> usize {
        self.blocks.iter().map(|&b| unsafe { (*b).len as usize }).sum()
    }
}

/// A valid event waiting for its link-table lookup (the slot was prefetched when it was parsed).
#[derive(Clone, Copy)]
struct PendEv {
    uh1: u64,
    uh2: u32,
    name: u64, // user ID offset
    w1: u64,   // ts_rel << 9 | cat << 1 | purchase
    price: u64,
    h1: u64, // event_id fingerprint
    kw: u64, // key word without the row id
}

/// A valid click waiting for its link-table lookup.
#[derive(Clone, Copy)]
struct PendCl {
    uh1: u64,
    uh2: u32,
    w1: u64, // ts_rel << 9
    w2: u64, // click_id offset << 16 | campaign
    h1: u64, // click_id fingerprint
    ch2: u32,
}

const PEND: usize = 32;

/// Everything one parser thread produces, bucketed by shard.
struct ThreadOut {
    pend_ev: Vec<PendEv>,
    pend_cl: Vec<PendCl>,
    scan: Scan,
    slabs: Slabs,
    ev_keys: Vec<Bucket<Key>>, // by event_id shard
    ev_rows: Vec<Bucket<Row>>, // by person shard
    cl_keys: Vec<Bucket<Key>>, // by click_id shard
    cl_rows: Vec<Bucket<Row>>, // by person shard
    ev_blocks: Vec<*mut Block<Row>>, // every event row block of this thread, by number
    cl_blocks: Vec<*mut Block<Row>>,
    key_blocks: Vec<*mut Block<Key>>, // unused numbering for key blocks
}

// Safety: the raw pointers are to blocks owned by this ThreadOut for the whole run; after
// parsing they are only read, apart from the atomic dead bits.
unsafe impl Send for ThreadOut {}
unsafe impl Sync for ThreadOut {}

impl ThreadOut {
    fn new() -> Self {
        ThreadOut {
            pend_ev: Vec::with_capacity(PEND),
            pend_cl: Vec::with_capacity(PEND),
            scan: Scan::default(),
            slabs: Slabs { cur: 0, end: 0 },
            ev_keys: (0..NSHARD).map(|_| Bucket::new()).collect(),
            ev_rows: (0..NSHARD).map(|_| Bucket::new()).collect(),
            cl_keys: (0..NSHARD).map(|_| Bucket::new()).collect(),
            cl_rows: (0..NSHARD).map(|_| Bucket::new()).collect(),
            ev_blocks: Vec::new(),
            cl_blocks: Vec::new(),
            key_blocks: Vec::new(),
        }
    }
}

/// Resolves queued events against the link table and stores them (R-L4/R-L6: a linked ID
/// belongs to its person, any other ID is its own person).
#[inline(always)]
fn flush_ev(out: &mut ThreadOut, me: usize, lt: &LinkTable) {
    let pend = std::mem::take(&mut out.pend_ev);
    for p in &pend {
        let (pkey, h2, name, shard) = match lt.get(p.uh1, p.uh2) {
            Some(c) => (LINKED | c as u64, 0u64, 0u64, (c & 0xFF) as usize),
            None => (p.uh1 & !LINKED, (p.uh2 >> 9) as u64, p.name, shard_of(p.uh1)),
        };
        let row = Row { w0: pkey.rotate_right(ROT), w1: (h2 << 41) | p.w1, w2: (name << 24) | p.price };
        let (block, slot) = out.ev_rows[shard].push(row, &mut out.slabs, &mut out.ev_blocks);
        let key = Key { h1: p.h1, w: p.kw | row_id(me, block, slot) as u64 };
        out.ev_keys[shard_of(p.h1)].push(key, &mut out.slabs, &mut out.key_blocks);
    }
    out.pend_ev = pend;
    out.pend_ev.clear();
}

#[inline(always)]
fn flush_cl(out: &mut ThreadOut, me: usize, lt: &LinkTable) {
    let pend = std::mem::take(&mut out.pend_cl);
    for p in &pend {
        let (pkey, h2, shard) = match lt.get(p.uh1, p.uh2) {
            Some(c) => (LINKED | c as u64, 0u64, (c & 0xFF) as usize),
            None => (p.uh1 & !LINKED, (p.uh2 >> 9) as u64, shard_of(p.uh1)),
        };
        let row = Row { w0: pkey.rotate_right(ROT), w1: (h2 << 41) | p.w1, w2: p.w2 };
        let (block, slot) = out.cl_rows[shard].push(row, &mut out.slabs, &mut out.cl_blocks);
        let key = Key { h1: p.h1, w: ((p.ch2 as u64) << 32) | row_id(me, block, slot) as u64 };
        out.cl_keys[shard_of(p.h1)].push(key, &mut out.slabs, &mut out.key_blocks);
    }
    out.pend_cl = pend;
    out.pend_cl.clear();
}

#[inline(always)]
fn row_id(thread: usize, block: u32, slot: u32) -> u32 {
    debug_assert!(thread < 16 && block < (1 << 19) && slot < 256);
    ((thread as u32) << 27) | (block << 8) | slot
}

/// Marks the row behind a row id dead.
#[inline(always)]
fn kill(tables: &[&Vec<*mut Block<Row>>], id: u32) {
    let (t, b, slot) = ((id >> 27) as usize, ((id >> 8) & 0x7_FFFF) as usize, (id & 0xFF) as usize);
    unsafe {
        (*tables[t][b]).dead[slot >> 6].fetch_or(1 << (slot & 63), std::sync::atomic::Ordering::Relaxed);
    }
}

/// The bytes of an ID stored as an offset: from the offset up to the next `,` or `"`.
#[inline(always)]
fn id_at(map_base: usize, off: u64) -> S {
    unsafe {
        let p = (map_base + off as usize) as *const u8;
        let mut n = 0usize;
        while *p.add(n) != b',' && *p.add(n) != b'"' {
            n += 1;
        }
        core::slice::from_raw_parts(p, n)
    }
}

// ---------------------------------------------------------------------------
// Parquet output (R-O1), written by hand: one row group, one PLAIN data page (v1) per
// column, no compression, no statistics. Metadata is Thrift compact protocol.
// ---------------------------------------------------------------------------

enum Col<'a> {
    Str(&'a [S]),
    OptStr(&'a [Option<S>]),
    Date(&'a [i32]),
    I64(&'a [i64]),
}

/// Thrift compact protocol writer.
struct Thrift {
    b: Vec<u8>,
    last: Vec<i16>, // last field id of each open struct
}

impl Thrift {
    const I32: u8 = 5;
    const I64: u8 = 6;
    const BINARY: u8 = 8;
    const LIST: u8 = 9;
    const STRUCT: u8 = 12;

    fn new() -> Self {
        Thrift { b: Vec::new(), last: vec![0] }
    }
    fn varint(&mut self, mut v: u64) {
        while v >= 0x80 {
            self.b.push((v as u8) | 0x80);
            v >>= 7;
        }
        self.b.push(v as u8);
    }
    fn zigzag(&mut self, v: i64) {
        self.varint(((v << 1) ^ (v >> 63)) as u64);
    }
    fn field(&mut self, id: i16, ty: u8) {
        let last = *self.last.last().unwrap();
        let delta = id - last;
        if (1..=15).contains(&delta) {
            self.b.push(((delta as u8) << 4) | ty);
        } else {
            self.b.push(ty);
            self.zigzag(id as i64);
        }
        *self.last.last_mut().unwrap() = id;
    }
    fn i32(&mut self, id: i16, v: i32) {
        self.field(id, Self::I32);
        self.zigzag(v as i64);
    }
    fn i64(&mut self, id: i16, v: i64) {
        self.field(id, Self::I64);
        self.zigzag(v);
    }
    fn bytes(&mut self, v: &[u8]) {
        self.varint(v.len() as u64);
        self.b.extend_from_slice(v);
    }
    fn string(&mut self, id: i16, v: &[u8]) {
        self.field(id, Self::BINARY);
        self.bytes(v);
    }
    fn list(&mut self, id: i16, elem: u8, n: usize) {
        self.field(id, Self::LIST);
        if n < 15 {
            self.b.push(((n as u8) << 4) | elem);
        } else {
            self.b.push(0xF0 | elem);
            self.varint(n as u64);
        }
    }
    /// Opens a struct that is a list element (no field header).
    fn begin(&mut self) {
        self.last.push(0);
    }
    /// Opens a struct that is a field of the current struct.
    fn begin_field(&mut self, id: i16) {
        self.field(id, Self::STRUCT);
        self.last.push(0);
    }
    fn end(&mut self) {
        self.b.push(0);
        self.last.pop();
    }
}

const PQ_INT32: i32 = 1;
const PQ_INT64: i32 = 2;
const PQ_BYTE_ARRAY: i32 = 6;
const PQ_UTF8: i32 = 0; // ConvertedType
const PQ_DATE: i32 = 6; // ConvertedType

fn write_parquet(path: &Path, cols: &[(&str, Col)], nrows: usize) {
    let mut f: Vec<u8> = Vec::with_capacity(64 + nrows * 48);
    f.extend_from_slice(b"PAR1");
    let mut chunks: Vec<(usize, usize)> = Vec::new(); // (offset, total size) of each column chunk
    if nrows > 0 {
        for (_, col) in cols {
            let offset = f.len();
            // Definition levels of an OPTIONAL column: one bit-packed run, 1 bit per value.
            let def: Option<Vec<u8>> = match col {
                Col::OptStr(v) => {
                    let groups = v.len().div_ceil(8);
                    let mut t = Thrift::new();
                    t.varint(((groups as u64) << 1) | 1);
                    let mut d = t.b;
                    let at = d.len();
                    d.resize(at + groups, 0);
                    for (i, x) in v.iter().enumerate() {
                        d[at + (i >> 3)] |= (x.is_some() as u8) << (i & 7);
                    }
                    Some(d)
                }
                _ => None,
            };
            let payload: usize = match col {
                Col::Str(v) => v.iter().map(|x| x.len() + 4).sum(),
                Col::OptStr(v) => 4 + def.as_ref().unwrap().len() + v.iter().flatten().map(|x| x.len() + 4).sum::<usize>(),
                Col::Date(v) => v.len() * 4,
                Col::I64(v) => v.len() * 8,
            };
            assert!(payload <= i32::MAX as usize, "column page too large");
            let mut h = Thrift::new(); // PageHeader
            h.i32(1, 0); // DATA_PAGE
            h.i32(2, payload as i32); // uncompressed_page_size
            h.i32(3, payload as i32); // compressed_page_size
            h.begin_field(5); // DataPageHeader
            h.i32(1, nrows as i32); // num_values
            h.i32(2, 0); // encoding PLAIN
            h.i32(3, 3); // definition_level_encoding RLE
            h.i32(4, 3); // repetition_level_encoding RLE
            h.end();
            h.end();
            f.extend_from_slice(&h.b);
            f.reserve(payload);
            match col {
                Col::Str(v) => {
                    for x in v.iter() {
                        f.extend_from_slice(&(x.len() as u32).to_le_bytes());
                        f.extend_from_slice(x);
                    }
                }
                Col::OptStr(v) => {
                    let d = def.as_ref().unwrap();
                    f.extend_from_slice(&(d.len() as u32).to_le_bytes());
                    f.extend_from_slice(d);
                    for x in v.iter().flatten() {
                        f.extend_from_slice(&(x.len() as u32).to_le_bytes());
                        f.extend_from_slice(x);
                    }
                }
                Col::Date(v) => {
                    for x in v.iter() {
                        f.extend_from_slice(&x.to_le_bytes());
                    }
                }
                Col::I64(v) => {
                    for x in v.iter() {
                        f.extend_from_slice(&x.to_le_bytes());
                    }
                }
            }
            chunks.push((offset, f.len() - offset));
        }
    }

    let kind = |c: &Col| -> (i32, i32, Option<i32>) {
        // (physical type, repetition: 0 REQUIRED / 1 OPTIONAL, converted type)
        match c {
            Col::Str(_) => (PQ_BYTE_ARRAY, 0, Some(PQ_UTF8)),
            Col::OptStr(_) => (PQ_BYTE_ARRAY, 1, Some(PQ_UTF8)),
            Col::Date(_) => (PQ_INT32, 0, Some(PQ_DATE)),
            Col::I64(_) => (PQ_INT64, 0, None),
        }
    };
    let mut m = Thrift::new(); // FileMetaData
    m.i32(1, 1); // version
    m.list(2, Thrift::STRUCT, cols.len() + 1); // schema
    m.begin();
    m.string(4, b"schema");
    m.i32(5, cols.len() as i32); // num_children
    m.end();
    for (name, col) in cols {
        let (ty, rep, conv) = kind(col);
        m.begin();
        m.i32(1, ty);
        m.i32(3, rep);
        m.string(4, name.as_bytes());
        if let Some(c) = conv {
            m.i32(6, c);
        }
        m.end();
    }
    m.i64(3, nrows as i64); // num_rows
    m.list(4, Thrift::STRUCT, usize::from(nrows > 0)); // row_groups
    if nrows > 0 {
        m.begin(); // RowGroup
        m.list(1, Thrift::STRUCT, cols.len());
        for ((name, col), &(offset, size)) in cols.iter().zip(&chunks) {
            m.begin(); // ColumnChunk
            m.i64(2, offset as i64); // file_offset
            m.begin_field(3); // ColumnMetaData
            m.i32(1, kind(col).0);
            m.list(2, Thrift::I32, 2); // encodings
            m.zigzag(0); // PLAIN
            m.zigzag(3); // RLE
            m.list(3, Thrift::BINARY, 1); // path_in_schema
            m.bytes(name.as_bytes());
            m.i32(4, 0); // codec UNCOMPRESSED
            m.i64(5, nrows as i64); // num_values
            m.i64(6, size as i64); // total_uncompressed_size
            m.i64(7, size as i64); // total_compressed_size
            m.i64(9, offset as i64); // data_page_offset
            m.end();
            m.end();
        }
        m.i64(2, chunks.iter().map(|c| c.1 as i64).sum()); // total_byte_size
        m.i64(3, nrows as i64); // num_rows
        m.end();
    }
    m.string(6, b"shopping-sessions track-b"); // created_by
    m.end();
    f.extend_from_slice(&m.b);
    f.extend_from_slice(&(m.b.len() as u32).to_le_bytes());
    f.extend_from_slice(b"PAR1");
    fs::write(path, &f).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

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
    clicks: Vec<Row>,
    ev_start: Vec<u32>, // bucket b of `events` is ev_start[b]..ev_start[b + 1]
    cl_start: Vec<u32>,
    n_sessions: u64,
}

struct Dims<'a> {
    ndays: usize,
    day0: i64,
    base: i64, // ts = base + ts_rel
    organic: usize,
    cat_names: &'a [S],
    names: &'a [Vec<S>], // linked IDs: names[shard][index within shard]
    map_base: usize,     // base address of the 40-bit ID offsets
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
            ev_start: vec![0; NBUCKET + 1],
            cl_start: vec![0; NBUCKET + 1],
            n_sessions: 0,
        }
    }

    /// Loads one person partition: every live row of every thread, scattered by bucket
    /// with a counting pass (no comparison sort over the whole partition).
    #[cfg_attr(feature = "prof", inline(never))]
    fn load(&mut self, outs: &[ThreadOut], p: usize) {
        fn scatter(blocks: &[*mut Block<Row>], dst: &mut Vec<Row>, start: &mut [u32]) {
            let mut count = [0u32; NBUCKET];
            for &b in blocks {
                let b = unsafe { &*b };
                for (i, r) in b.items().iter().enumerate() {
                    if !b.is_dead(i) {
                        count[bucket_of(r.w0)] += 1;
                    }
                }
            }
            let mut next = [0u32; NBUCKET];
            let mut total = 0u32;
            for k in 0..NBUCKET {
                start[k] = total;
                next[k] = total;
                total += count[k];
            }
            start[NBUCKET] = total;
            dst.clear();
            dst.reserve(total as usize);
            let out = dst.as_mut_ptr();
            for &b in blocks {
                let b = unsafe { &*b };
                for (i, r) in b.items().iter().enumerate() {
                    if !b.is_dead(i) {
                        let k = bucket_of(r.w0);
                        unsafe { out.add(next[k] as usize).write(*r) };
                        next[k] += 1;
                    }
                }
            }
            unsafe { dst.set_len(total as usize) };
        }
        let ev: Vec<*mut Block<Row>> = outs.iter().flat_map(|o| o.ev_rows[p].blocks.iter().copied()).collect();
        scatter(&ev, &mut self.events, &mut self.ev_start);
        let cl: Vec<*mut Block<Row>> = outs.iter().flat_map(|o| o.cl_rows[p].blocks.iter().copied()).collect();
        scatter(&cl, &mut self.clicks, &mut self.cl_start);
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
    #[cfg_attr(feature = "prof", inline(never))]
    fn process(&mut self, d: &Dims) {
        let mut events = std::mem::take(&mut self.events);
        let mut clicks = std::mem::take(&mut self.clicks);
        // `load` left both arrays grouped by bucket (the top bits of pkey); sorting each small
        // bucket completes the order by (pkey, k2).
        // Ties in ts need no order: one pass decides the sessions, so tied events cannot split.
        for b in 0..NBUCKET {
            events[self.ev_start[b] as usize..self.ev_start[b + 1] as usize].sort_unstable_by_key(|e| (e.w0, e.w1));
            // Within a ts, click_id DESCENDING: the last click at or before a session start is
            // then the latest one with the smallest click_id (R-K4).
            clicks[self.cl_start[b] as usize..self.cl_start[b + 1] as usize].sort_unstable_by(|a, b| {
                (a.w0, a.w1)
                    .cmp(&(b.w0, b.w1))
                    .then_with(|| id_at(d.map_base, b.w2 >> 16).cmp(id_at(d.map_base, a.w2 >> 16)))
            });
        }

        let ndays = d.ndays;
        let n = events.len();
        let (mut i, mut ci) = (0usize, 0usize);
        while i < n {
            // One person = one (pkey, h2).
            let pid = events[i].person();
            let mut j = i;
            while j < n && events[j].person() == pid {
                j += 1;
            }
            while ci < clicks.len() && clicks[ci].person() < pid {
                ci += 1;
            }
            let cs = ci;
            while ci < clicks.len() && clicks[ci].person() == pid {
                ci += 1;
            }
            let ev = &events[i..j];
            let pc = &clicks[cs..ci];
            i = j;
            let person = pid.0.rotate_left(ROT);
            let name: S = if person & LINKED != 0 {
                let id = person as u32;
                d.names[(id & 0xFF) as usize][(id >> 8) as usize] // R-L3
            } else {
                id_at(d.map_base, ev[0].w2 >> 24) // R-L4
            };

            let (mut lo, mut hi) = (0usize, 0usize);
            let mut cur_day: i64 = -1;
            let (mut d_sessions, mut d_events, mut d_revenue) = (0i64, 0i64, 0i64);
            let mut k = 0;
            while k < ev.len() {
                // R-E5: a session runs while the gap to the previous event is <= 30 min.
                let start = ev[k].ts();
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
                while k < ev.len() && ev[k].ts() - prev <= GAP_MS {
                    let e = &ev[k];
                    prev = e.ts();
                    s_events += 1;
                    if e.w1 & 1 != 0 {
                        let price = (e.w2 & 0xFF_FFFF) as i64;
                        s_revenue += price;
                        s_purchase = true;
                        self.cat_sum[((e.w1 >> 1) & 0xFF) as usize] += price;
                    }
                    k += 1;
                }
                d_sessions += 1;
                d_events += s_events;
                d_revenue += s_revenue;
                self.n_sessions += 1;

                if !pc.is_empty() {
                    // R-K4: clicks with start - 7d <= ts <= start.
                    while hi < pc.len() && pc[hi].ts() <= start {
                        let c = (pc[hi].w2 & 0xFFFF) as usize;
                        self.win_count[c] += 1;
                        if self.win_count[c] == 1 {
                            self.win_pos[c] = self.active.len() as u32;
                            self.active.push(c as u16);
                        }
                        hi += 1;
                    }
                    while lo < hi && pc[lo].ts() < start - WEEK_MS {
                        let c = (pc[lo].w2 & 0xFFFF) as usize;
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
                let credited = if hi > lo { (pc[hi - 1].w2 & 0xFFFF) as usize } else { d.organic }; // R-K5
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
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    if !std::arch::is_x86_feature_detected!("avx2") || !std::arch::is_x86_feature_detected!("bmi2") {
        eprintln!("this binary is built for x86-64-v3 (AVX2, BMI2), which this CPU does not have");
        std::process::exit(2);
    }
    let mut clock = Clock::new();
    let data = PathBuf::from(std::env::var("DATA_DIR").unwrap_or_else(|_| "/data".into()));
    let out = PathBuf::from(std::env::var("OUTPUT_DIR").unwrap_or_else(|_| "/output".into()));
    let ncpu: usize = std::env::var("NCPU").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    // Row ids carry a 4-bit thread number: at most 15 pool threads plus the calling thread.
    let want = if ncpu > 0 { ncpu } else { std::thread::available_parallelism().map_or(8, |n| n.get()) };
    let _ = rayon::ThreadPoolBuilder::new().num_threads(want.min(15)).build_global();

    // Diagnostic only: SS_REPEAT=N runs the whole pipeline N times in one process, each run
    // writing the same output. The scorer's time for N=2 minus N=1 is one run's compute; the
    // rest is fixed cost (container start, exit, VM). Unset (the default) runs once.
    let repeat: usize = std::env::var("SS_REPEAT").ok().and_then(|v| v.parse().ok()).unwrap_or(1).max(1);
    for i in 0..repeat {
        run(&data, &out, &mut clock);
        if repeat > 1 {
            clock.log(&format!("run {} of {repeat} done", i + 1));
        }
    }
    if std::env::var_os("PROF").is_some() {
        eprintln!("PROF {}", proc_stats());
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap();
        eprintln!("PROF exit_called_at_ns={}", now.as_nanos());
    }
    // Everything is flushed and closed; skip destructors and unmapping.
    std::process::exit(0);
}

fn run(data: &Path, out: &Path, clock: &mut Clock) {
    let manifest = fs::read_to_string(data.join("manifest.json")).expect("manifest.json");
    let ws = manifest_value(&manifest, "window_start"); // R-T9
    let we = manifest_value(&manifest, "window_end");
    let base = ws - WEEK_MS; // earliest valid click (R-T8); all stored timestamps are relative to it
    assert!(we > base && we - base <= u32::MAX as i64, "window too long for 32-bit relative timestamps");
    let tsf = TsFast::new(ws, we);

    // --- products.csv: product_id -> category index (R-E7) ----------------------
    let mut cat_names: Vec<S> = Vec::new();
    let mut cat_index: HashMap<S, u16> = HashMap::new();
    let mut products: HashTable<(u64, S, u16)> = HashTable::new();
    let mut scan0 = Scan::default();
    for chunk in load_chunks(&data.join("products.csv")) {
        scan_rows::<2>(chunk, &mut scan0, |&[pid, cat]| {
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
    assert!(ncat <= 256, "more than 255 categories: the row layout keeps a category in 8 bits");

    // --- campaigns.csv: campaign_id -> dense index, channel ----------------------
    let mut camp_ids: Vec<S> = Vec::new();
    let mut camp_channels: Vec<S> = Vec::new();
    let mut campaigns: HashTable<(u64, S, u16)> = HashTable::new();
    for chunk in load_chunks(&data.join("campaigns.csv")) {
        scan_rows::<2>(chunk, &mut scan0, |&[cid, channel]| {
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
            let mut sc = Scan::default();
            scan_rows::<2>(chunk, &mut sc, |&[a, b]| {
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
    // Region load factor between 1/3 and 2/3: dense enough to stay cache-friendly.
    let rbits = (max_shard + max_shard / 2).max(16).next_power_of_two().trailing_zeros();
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
    // IDs are kept as 40-bit offsets from the lowest mapped input byte.
    let map_base = work.iter().map(|w| w.1.as_ptr() as usize).min().unwrap_or(0);
    let map_end = work.iter().map(|w| w.1.as_ptr() as usize + w.1.len()).max().unwrap_or(0);
    assert!(map_end - map_base < 1 << 40, "input mappings span more than 1 TiB");
    let ingest_base = ws - 12 * DAY_MS;
    work.par_iter().for_each(|&(kind, chunk)| {
        // Safety: a pool thread runs one of these closures at a time and never yields inside it.
        let me = rayon::current_thread_index().unwrap_or(nthreads);
        let out = unsafe { outs[me].get() };
        let mut scan = std::mem::take(&mut out.scan);
        match kind {
            Kind::Events => scan_rows::<7>(chunk, &mut scan, |f| {
                let eid = f[0];
                if eid.is_empty() {
                    return; // R-E1
                }
                let user = f[1];
                let (uh1, uh2) = fingerprint(user);
                link_table.prefetch(uh1);
                let (h1, eh2) = fingerprint(eid);
                let ingest = tsf.parse(f[3]); // R-T10
                // R-E2 orders copies by ingest_ts: 22 bits of whole seconds from 12 days before
                // the window (F1 has no fractions, R-T10); all-ones when unparseable.
                let ingest22 = match ingest {
                    Some(t) => (t - ingest_base).div_euclid(1000).clamp(0, INGEST_BITS as i64 - 1) as u64,
                    None => INGEST_BITS,
                };
                let kw = ((eh2 as u64 >> 22) << 54) | (ingest22 << 32);
                'validate: {
                    let Some(ingest) = ingest else { break 'validate };
                    if user.is_empty() || f[5].is_empty() {
                        break 'validate; // R-E3: user_id and product_id non-empty
                    }
                    let Some(ts) = tsf.parse(f[2]) else { break 'validate };
                    if ts < ws || ts >= we {
                        break 'validate; // R-T7
                    }
                    if ingest - ts > LATE_MS {
                        break 'validate; // R-E4
                    }
                    let (purchase, price, cat) = match f[4] {
                        b"view" | b"cart" => (0u64, 0u64, 0u64), // price ignored, category not needed
                        b"purchase" => {
                            let Some(p) = parse_price(f[6]) else { break 'validate };
                            // R-E7: the category only matters for purchases (R-O2).
                            let ph = hash_bytes(f[5]);
                            (1, p as u64, products.find(ph, |e| e.0 == ph && e.1 == f[5]).map_or(cat_unknown, |e| e.2) as u64)
                        }
                        _ => break 'validate,
                    };
                    let ts_rel = (ts - base) as u64;
                    out.pend_ev.push(PendEv {
                        uh1,
                        uh2,
                        name: (user.as_ptr() as usize - map_base) as u64,
                        w1: (ts_rel << 9) | (cat << 1) | purchase,
                        price,
                        h1,
                        kw,
                    });
                    if out.pend_ev.len() == PEND {
                        flush_ev(out, me, &link_table);
                    }
                    return;
                }
                // An invalid copy still takes part in dedup (R-E2), without a row.
                out.ev_keys[shard_of(h1)].push(Key { h1, w: kw | NO_ROW as u64 }, &mut out.slabs, &mut out.key_blocks);
            }),
            Kind::Clicks => scan_rows::<4>(chunk, &mut scan, |&[cid, user, camp, ts]| {
                // R-K1..R-K3. Copies of a click are identical, so an invalid line can never
                // be the kept copy of a valid click: only valid lines need a dedup key.
                if cid.is_empty() || user.is_empty() {
                    return;
                }
                let (uh1, uh2) = fingerprint(user);
                link_table.prefetch(uh1);
                let Some(t) = tsf.parse(ts) else { return };
                if t < base || t >= we {
                    return; // R-T8
                }
                let ch = hash_bytes(camp);
                let Some(e) = campaigns.find(ch, |e| e.0 == ch && e.1 == camp) else { return }; // R-K3: exact match
                let ts_rel = (t - base) as u64;
                let (h1, ch2) = fingerprint(cid);
                out.pend_cl.push(PendCl {
                    uh1,
                    uh2,
                    w1: ts_rel << 9,
                    w2: (((cid.as_ptr() as usize - map_base) as u64) << 16) | e.2 as u64,
                    h1,
                    ch2,
                });
                if out.pend_cl.len() == PEND {
                    flush_cl(out, me, &link_table);
                }
            }),
        }
        flush_ev(out, me, &link_table);
        flush_cl(out, me, &link_table);
        out.scan = scan;
    });
    let outs: Vec<ThreadOut> = outs.into_iter().map(|s| s.0.into_inner()).collect();
    clock.log("events and clicks parsed");

    // --- dedup, one event_id / click_id shard per task. Losing rows are flagged dead.
    let ev_tables: Vec<&Vec<*mut Block<Row>>> = outs.iter().map(|o| &o.ev_blocks).collect();
    let cl_tables: Vec<&Vec<*mut Block<Row>>> = outs.iter().map(|o| &o.cl_blocks).collect();
    struct Tables<'a>(&'a [&'a Vec<*mut Block<Row>>]);
    unsafe impl Sync for Tables<'_> {}
    let (ev_tables, cl_tables) = (Tables(&ev_tables), Tables(&cl_tables));
    // One pair of tables per worker, cleared and reused for each shard: no fresh memory per shard.
    (0..NSHARD).into_par_iter().for_each_init(
        || (HashTable::<Key>::new(), HashTable::<(u64, u32)>::new()),
        |(ev_table, cl_table), s| {
        let (ev_tables, cl_tables) = (&ev_tables, &cl_tables);
        // R-E2: dedup on event_id BEFORE validation: the copy with the smallest ingest_ts is
        // kept, valid or not; every other copy's row dies.
        let n: usize = outs.iter().map(|o| o.ev_keys[s].len()).sum();
        let table = ev_table;
        table.clear();
        table.reserve(n, |e| e.h1);
        for o in &outs {
            for &block in &o.ev_keys[s].blocks {
                for k in unsafe { (*block).items() } {
                    match table.entry(k.h1, |e| e.h1 == k.h1 && e.w >> 54 == k.w >> 54, |e| e.h1) {
                        Entry::Occupied(mut occ) => {
                            let cur = occ.get_mut();
                            let earlier = (k.w >> 32) & INGEST_BITS < (cur.w >> 32) & INGEST_BITS;
                            let loser = if earlier { std::mem::replace(cur, *k).w as u32 } else { k.w as u32 };
                            if loser != NO_ROW {
                                kill(ev_tables.0, loser);
                            }
                        }
                        Entry::Vacant(v) => {
                            v.insert(*k);
                        }
                    }
                }
            }
        }
        // R-K2: keep the first copy of a click, flag the rest.
        let n: usize = outs.iter().map(|o| o.cl_keys[s].len()).sum();
        let table = cl_table;
        table.clear();
        table.reserve(n, |e| e.0);
        for o in &outs {
            for &block in &o.cl_keys[s].blocks {
                for k in unsafe { (*block).items() } {
                    let h2 = (k.w >> 32) as u32;
                    match table.entry(k.h1, |e| e.0 == k.h1 && e.1 == h2, |e| e.0) {
                        Entry::Occupied(_) => kill(cl_tables.0, k.w as u32),
                        Entry::Vacant(v) => {
                            v.insert((k.h1, h2));
                        }
                    }
                }
            }
        }
        },
    );
    clock.log("deduped");

    // --- sessions, credit, assists: a fixed number of tasks, each with one accumulator
    // and a spread of person partitions.
    let day0 = ws.div_euclid(DAY_MS);
    let ndays = ((we - 1).div_euclid(DAY_MS) - day0 + 1).max(1) as usize;
    let dims = Dims { ndays, day0, base, organic, cat_names: &cat_names, names: &names, map_base };
    let ntask = (nthreads * 2).clamp(1, NSHARD);
    let accs: Vec<Acc> = (0..ntask)
        .into_par_iter()
        .map(|t| {
            let mut acc = Acc::new(ncamp, ndays, ncat);
            for p in (t..NSHARD).step_by(ntask) {
                acc.load(&outs, p);
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
            &[
                ("user_id", Col::Str(&a.u_user)),
                ("day", Col::Date(&a.u_day)),
                ("sessions", Col::I64(&a.u_sessions)),
                ("events", Col::I64(&a.u_events)),
                ("revenue_cents", Col::I64(&a.u_revenue)),
                ("top_category", Col::OptStr(&a.u_top)),
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
        &[
            ("campaign_id", Col::Str(&k_id)),
            ("channel", Col::Str(&k_channel)),
            ("day", Col::Date(&k_day)),
            ("sessions", Col::I64(&k_sessions)),
            ("purchasing_sessions", Col::I64(&k_purchasing)),
            ("revenue_cents", Col::I64(&k_revenue)),
            ("assisted_sessions", Col::I64(&k_assisted)),
        ],
        n_camp_rows,
    );
    clock.log(&format!("written: {n_user_rows} user rows, {n_camp_rows} campaign rows"));
    // Leak the big structures, as process::exit did before run() existed: no run pays for
    // freeing, so repeated runs time the same work as a single one.
    std::mem::forget((outs, accs, link_table, link_pairs, canon, names, products, campaigns, work));
}
