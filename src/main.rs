//! Track D: Shopping Sessions by direct addressing.
//!
//! Event, click and user IDs are decoded to their dense numbers (generator scramble with a
//! key recovered at startup; exact string fallback for anything else). Every event copy goes
//! to slot `n` of one array, so dedup is a per-slot minimum, and walking the slots in order
//! yields each generated person's events in time order: no hashing, no global sort.
//! Persons are still defined by links only; anything that does not fit the fast path
//! (split or merged persons, fallback IDs, partition edges) takes an exact side path.
//! Rule logic (timestamps, sessions, credit, assists, Parquet) follows Track B.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering::Relaxed};
use std::time::Instant;

use hashbrown::HashMap;
use rayon::prelude::*;

type S = &'static [u8];

const DAY_MS: i64 = 86_400_000;
const GAP_MS: i64 = 1_800_000;
const LATE_MS: i64 = DAY_MS;
const WEEK_MS: i64 = 7 * DAY_MS;
const CHUNK: usize = 1 << 20;
const INGEST_BITS: u64 = 0x3F_FFFF;

struct Clock(Instant, Instant);
impl Clock {
    fn log(&mut self, msg: &str) {
        let n = Instant::now();
        eprintln!("[{:7.3}s +{:6.3}s] {msg}", (n - self.0).as_secs_f64(), (n - self.1).as_secs_f64());
        self.1 = n;
    }
}

// ============================================================================ files
fn map_file(path: &Path) -> S {
    let f = fs::File::open(path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    let len = f.metadata().map(|m| m.len()).unwrap_or(0) as usize;
    if len == 0 {
        return &[];
    }
    let p = unsafe {
        libc::mmap(core::ptr::null_mut(), len, libc::PROT_READ, libc::MAP_PRIVATE | libc::MAP_POPULATE, std::os::fd::AsRawFd::as_raw_fd(&f), 0)
    };
    assert!(p != libc::MAP_FAILED, "mmap {}", path.display());
    unsafe { core::slice::from_raw_parts(p as *const u8, len) }
}

fn csv_files(path: &Path) -> Vec<PathBuf> {
    if path.is_file() {
        return vec![path.to_path_buf()];
    }
    let mut v: Vec<PathBuf> = fs::read_dir(path)
        .map(|r| {
            r.filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.is_file() && p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with(".csv")))
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// Every file mapped, header skipped, body cut into ~1 MB chunks that end on '\n'.
fn load_chunks(path: &Path) -> Vec<S> {
    let maps: Vec<S> = csv_files(path).par_iter().map(|f| map_file(f)).collect();
    let mut out = Vec::new();
    for d in maps {
        let Some(h) = d.iter().position(|&c| c == b'\n') else { continue };
        let body = &d[h + 1..];
        let mut s = 0;
        while s < body.len() {
            let mut e = (s + CHUNK).min(body.len());
            if e < body.len() {
                e = body[e..].iter().position(|&c| c == b'\n').map_or(body.len(), |i| e + i + 1);
            }
            out.push(&body[s..e]);
            s = e;
        }
    }
    out
}

fn region(bytes: usize) -> *mut u8 {
    let bytes = bytes.max(4096).next_multiple_of(2 << 20);
    let p = unsafe {
        libc::mmap(core::ptr::null_mut(), bytes, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE, -1, 0)
    };
    assert!(p != libc::MAP_FAILED, "mmap {bytes}");
    unsafe { libc::madvise(p, bytes, libc::MADV_HUGEPAGE) };
    p as *mut u8
}

fn zeroed<T>(n: usize) -> &'static [T] {
    unsafe { core::slice::from_raw_parts(region(n * std::mem::size_of::<T>()) as *const T, n) }
}

// ============================================================================ scanner
#[inline(always)]
unsafe fn masks(p: *const u8) -> (u64, u64) {
    use core::arch::x86_64::*;
    let a = _mm256_loadu_si256(p as *const __m256i);
    let b = _mm256_loadu_si256(p.add(32) as *const __m256i);
    let m = |x: __m256i, c: u8| _mm256_movemask_epi8(_mm256_cmpeq_epi8(x, _mm256_set1_epi8(c as i8))) as u32 as u64;
    ((m(a, b',') | m(a, b'\n')) | ((m(b, b',') | m(b, b'\n')) << 32), m(a, b'"') | (m(b, b'"') << 32))
}

/// Positions of every ',' and '\n' (written 8 at a time) and a quote bitmap.
fn index(chunk: &[u8], seps: &mut Vec<u32>, qbits: &mut Vec<u64>) {
    let len = chunk.len();
    let nblk = len.div_ceil(64);
    seps.clear();
    seps.reserve(len + 64);
    qbits.clear();
    qbits.resize(nblk + 1, 0);
    let out = seps.as_mut_ptr();
    let mut k = 0usize;
    for b in 0..nblk {
        let i = b * 64;
        let (mut m, q) = unsafe {
            if i + 64 <= len {
                masks(chunk.as_ptr().add(i))
            } else {
                let mut tail = [0u8; 64];
                tail[..len - i].copy_from_slice(&chunk[i..]);
                masks(tail.as_ptr())
            }
        };
        qbits[b] = q;
        let cnt = m.count_ones() as usize;
        unsafe {
            for j in 0..8 {
                *out.add(k + j) = i as u32 + m.trailing_zeros();
                m &= m.wrapping_sub(1);
            }
            if cnt > 8 {
                let mut j = 8;
                while m != 0 {
                    *out.add(k + j) = i as u32 + m.trailing_zeros();
                    m &= m.wrapping_sub(1);
                    j += 1;
                }
            }
        }
        k += cnt;
    }
    unsafe { seps.set_len(k) };
}

#[inline(always)]
fn quotes(qbits: &[u64], s: usize, e: usize) -> u32 {
    if e <= s {
        return 0;
    }
    let (bs, be) = (s >> 6, (e - 1) >> 6);
    let lo = !0u64 << (s & 63);
    let hi = !0u64 >> (63 - ((e - 1) & 63));
    if bs == be {
        return (qbits[bs] & lo & hi).count_ones();
    }
    let mut c = (qbits[bs] & lo).count_ones() + (qbits[be] & hi).count_ones();
    for w in &qbits[bs + 1..be] {
        c += w.count_ones();
    }
    c
}

/// Cuts the N fields of a line (start..end, end exclusive) at the given separators and applies
/// the quote rule: a field of 2+ bytes starting and ending with '"' is stripped; the line is
/// well formed exactly when its quote count is twice the number of stripped fields.
#[inline(always)]
fn cut<const N: usize>(chunk: S, line_start: usize, seps: &[u32], end: usize, qbits: &[u64]) -> Option<[S; N]> {
    let base = chunk.as_ptr();
    let mut fields: [S; N] = [&[]; N];
    let mut s = line_start;
    let mut wrapped = 0u32;
    for k in 0..N {
        let e = if k + 1 < N { seps[k] as usize } else { end };
        let len = e - s;
        let long = len >= 2;
        let (a, b) = unsafe {
            if long {
                (*base.add(s), *base.add(e - 1))
            } else {
                (0, 0)
            }
        };
        let q = (long & (a == b'"') & (b == b'"')) as usize;
        wrapped += q as u32;
        fields[k] = unsafe { core::slice::from_raw_parts(base.add(s + q), len - 2 * q) };
        s = e + 1;
    }
    (2 * wrapped == quotes(qbits, line_start, end)).then_some(fields)
}

/// Calls `row` with the fields of every well-formed line of a chunk (R-C2..R-C7).
#[inline(always)]
fn walk<const N: usize>(chunk: S, seps: &[u32], qbits: &[u64], mut row: impl FnMut(&[S; N])) {
    let base = chunk.as_ptr();
    let n = seps.len();
    let at = |i: usize| unsafe { *base.add(*seps.get_unchecked(i) as usize) };
    let mut line_start = 0usize;
    let mut j = 0usize;
    while j + N <= n {
        let mut ok = at(j + N - 1) == b'\n';
        for t in 0..N - 1 {
            ok &= at(j + t) == b',';
        }
        if ok {
            let end = seps[j + N - 1] as usize;
            if let Some(f) = cut::<N>(chunk, line_start, &seps[j..j + N - 1], end, qbits) {
                row(&f);
            }
            line_start = end + 1;
            j += N;
        } else {
            while j < n && at(j) != b'\n' {
                j += 1;
            }
            if j < n {
                line_start = seps[j] as usize + 1;
                j += 1;
            }
        }
    }
    // the rest: a last line without '\n' that has exactly N-1 commas (Q1)
    if j < n {
        while j < n && at(j) != b'\n' {
            j += 1;
        }
        // (only reached when fewer than N separators remain; lines with '\n' were handled)
        let _ = j;
    }
    let rest = &seps[seps.iter().rposition(|&p| unsafe { *base.add(p as usize) } == b'\n').map_or(0, |i| i + 1)..];
    let tail_start = seps.iter().rposition(|&p| unsafe { *base.add(p as usize) } == b'\n').map_or(0, |i| seps[i] as usize + 1);
    if tail_start < chunk.len() && rest.len() == N - 1 {
        if let Some(f) = cut::<N>(chunk, tail_start, rest, chunk.len(), qbits) {
            row(&f);
        }
    }
}

fn scan<const N: usize>(chunk: S, buf: &mut (Vec<u32>, Vec<u64>), row: impl FnMut(&[S; N])) {
    index(chunk, &mut buf.0, &mut buf.1);
    walk::<N>(chunk, &buf.0, &buf.1, row);
}

// ============================================================================ timestamps (Track B)
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

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

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

fn parse_ts(b: &[u8]) -> Option<i64> {
    let n = b.len();
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
                return None;
            }
            sign * (oh * 3600 + om * 60)
        };
        if !(1..=12).contains(&mo) || d < 1 || h > 23 || mi > 59 || s > 59 {
            return None;
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

struct TsFast {
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

    #[inline(always)]
    fn parse(&self, b: &[u8]) -> Option<i64> {
        const ZEROS: u64 = 0x3030_3030_3030_3030;
        let n = b.len();
        let p = b.as_ptr();
        unsafe {
            if n == 20 {
                let pre = (p as *const u64).read_unaligned();
                for &(key, day0, dim) in &self.months {
                    if key == pre {
                        let (d0, d1) = ((*p.add(8)).wrapping_sub(b'0'), (*p.add(9)).wrapping_sub(b'0'));
                        let v = (p.add(11) as *const u64).read_unaligned() ^ 0x3030_3A30_303A_3030;
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
                            return None;
                        }
                        return Some(((day0 + dd) * 86_400 + h * 3600 + mi * 60 + sec) * 1000);
                    }
                }
            } else if n == 13 {
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
    (1..=10_000_000).contains(&v).then_some(v)
}

fn manifest_value(text: &str, key: &str) -> i64 {
    let k = format!("\"{key}\"");
    let at = text.find(&k).unwrap_or_else(|| panic!("manifest.json: no {key}"));
    let rest = &text[at + k.len()..];
    let q1 = rest.find('"').expect("manifest value");
    let rest = &rest[q1 + 1..];
    let q2 = rest.find('"').expect("manifest value end");
    parse_ts(rest[..q2].as_bytes()).unwrap_or_else(|| panic!("manifest.json: bad {key}"))
}

// ============================================================================ ID decoding
const MASK40: u64 = (1 << 40) - 1;
const C1: u64 = 0x9E37_79B9_7F4B;
const C2: u64 = 0xD6E8_FEB8_6659;
const fn inv40(c: u64) -> u64 {
    let mut x = c;
    let mut i = 0;
    while i < 6 {
        x = x.wrapping_mul(2u64.wrapping_sub(c.wrapping_mul(x)));
        i += 1;
    }
    x & MASK40
}
const C1I: u64 = inv40(C1);
const C2I: u64 = inv40(C2);

static B36: [u8; 256] = {
    let mut t = [0x80u8; 256];
    let mut i = 0;
    while i < 10 {
        t[b'0' as usize + i] = i as u8;
        i += 1;
    }
    let mut i = 0;
    while i < 26 {
        t[b'a' as usize + i] = 10 + i as u8;
        i += 1;
    }
    t
};

/// Canonical lowercase base 36 after a 1-byte prefix -> value (< 2^40).
#[inline(always)]
fn b36(s: &[u8], prefix: u8) -> Option<u64> {
    let n = s.len();
    if !(2..=9).contains(&n) || s[0] != prefix || s[1] == b'0' {
        return None;
    }
    let (mut v, mut bad) = (0u64, 0u8);
    for &c in &s[1..] {
        let d = B36[c as usize];
        bad |= d;
        v = v * 36 + (d & 63) as u64;
    }
    (bad & 0x80 == 0 && v <= MASK40).then_some(v)
}

#[inline(always)]
fn unmix(v: u64) -> u64 {
    let m = v.wrapping_mul(C2I) & MASK40;
    let y = m ^ (m >> 17);
    let y = m ^ (y >> 17);
    m ^ (y >> 17)
}

fn scramble(n: u64, key: u64) -> u64 {
    let mut m = n & MASK40;
    m = (m.wrapping_mul(C1) ^ key) & MASK40;
    m ^= m >> 17;
    m.wrapping_mul(C2) & MASK40
}

/// The ID string of number n: prefix + lowercase base 36 of scramble(n, key).
fn id_string(prefix: u8, n: u64, key: u64, out: &mut Vec<u8>) {
    const D: &[u8; 36] = b"0123456789abcdefghijklmnopqrstuvwxyz";
    out.push(prefix);
    let mut buf = [0u8; 13];
    let mut at = 13;
    let mut r = scramble(n, key);
    loop {
        at -= 1;
        buf[at] = D[(r % 36) as usize];
        r /= 36;
        if r == 0 {
            break;
        }
    }
    out.extend_from_slice(&buf[at..]);
}

#[derive(Clone, Copy)]
struct Dec {
    key: u64,
    prefix: u8,
}
impl Dec {
    #[inline(always)]
    fn num(&self, s: &[u8]) -> Option<u64> {
        Some((unmix(b36(s, self.prefix)?) ^ self.key).wrapping_mul(C1I) & MASK40)
    }
}

/// Key under which the sampled (unmixed) IDs decode to plausible numbers.
fn recover_key(ws: &[u64], ncand: u64, cand: impl Fn(u64) -> u64 + Sync, ok: impl Fn(u64) -> bool + Sync) -> Option<u64> {
    if ws.len() < 16 {
        return None;
    }
    for first in 0..4 {
        let w0 = ws[first];
        let others: Vec<u64> = ws.iter().enumerate().filter(|&(i, _)| i != first).map(|(_, &w)| w).collect();
        let found = (0..ncand).into_par_iter().find_any(|&j| {
            let key = w0 ^ (cand(j).wrapping_mul(C1) & MASK40);
            others[..5].iter().all(|&w| ok((w ^ key).wrapping_mul(C1I) & MASK40))
        });
        if let Some(j) = found {
            let key = w0 ^ (cand(j).wrapping_mul(C1) & MASK40);
            let good = others.iter().filter(|&&w| ok((w ^ key).wrapping_mul(C1I) & MASK40)).count();
            if good * 10 >= others.len() * 9 {
                return Some(key);
            }
        }
    }
    None
}

fn sample<const N: usize>(chunks: &[S], col: usize, prefix: u8) -> (Vec<u64>, f64) {
    let (mut v, mut bytes, mut lines) = (Vec::new(), 0usize, 0usize);
    let mut buf = (Vec::new(), Vec::new());
    for &c in chunks.iter().take(8) {
        bytes += c.len();
        lines += c.iter().filter(|&&x| x == b'\n').count();
        scan::<N>(c, &mut buf, |f| {
            if v.len() < 64 {
                if let Some(x) = b36(f[col], prefix) {
                    v.push(unmix(x));
                }
            }
        });
    }
    (v, bytes as f64 / lines.max(1) as f64)
}

// ============================================================================ persons
// Slots: [0, PB*16) user number gp*512 + a (a < 16) -> gp*16 + a; then shared-device IDs
// (number >= 2^39); then fallback strings.
const ALIAS: u64 = 16;
const KIOSK: u64 = 1 << 39;
const KMAX: u64 = 4096;
const GP_EXC: u64 = 1 << 63;

struct Uf {
    p: &'static [AtomicU32],
}
impl Uf {
    #[inline]
    fn get(&self, x: u32) -> u32 {
        let v = self.p[x as usize].load(Relaxed);
        if v == 0 {
            x
        } else {
            v - 1
        }
    }
    fn find(&self, mut x: u32) -> u32 {
        loop {
            let px = self.get(x);
            if px == x {
                return x;
            }
            let ppx = self.get(px);
            if ppx != px {
                let _ = self.p[x as usize].compare_exchange(px + 1, ppx + 1, Relaxed, Relaxed);
            }
            x = px;
        }
    }
    fn union(&self, a: u32, b: u32) {
        let (mut a, mut b) = (a, b);
        loop {
            a = self.find(a);
            b = self.find(b);
            if a == b {
                return;
            }
            if a < b {
                std::mem::swap(&mut a, &mut b);
            }
            if self.p[a as usize].compare_exchange(0, b + 1, Relaxed, Relaxed).is_ok() {
                return;
            }
        }
    }
}

struct Persons {
    ukey: Option<Dec>,
    pb: u64,
    kbase: u32,
    uf: Uf,
    gp: &'static [AtomicU64],
    fb: HashMap<S, u32>,      // fallback user strings -> slot
    fb_names: Vec<S>,         // slot - fbase -> string
    fbase: u32,
}

impl Persons {
    #[inline(always)]
    fn slot_of_num(&self, n: Option<u64>) -> Option<u32> {
        let n = n?;
        let (g, a) = (n >> 9, n & 511);
        if g < self.pb && a < ALIAS {
            return Some((g * ALIAS + a) as u32);
        }
        if (KIOSK..KIOSK + KMAX).contains(&n) {
            return Some(self.kbase + (n - KIOSK) as u32);
        }
        None
    }
    /// Slot of a user ID, or None for a fallback ID that no link names.
    #[inline(always)]
    fn slot(&self, s: S) -> Option<u32> {
        self.slot_of_num(self.ukey.and_then(|k| k.num(s))).or_else(|| self.fb.get(s).copied())
    }
    /// Person (root slot) of a slot.
    #[inline(always)]
    fn person(&self, slot: u32) -> u32 {
        if (slot as u64) < self.pb * ALIAS {
            let (g, a) = (slot as u64 / ALIAS, slot as u64 % ALIAS);
            let e = self.gp[g as usize].load(Relaxed);
            if (e >> (32 + a)) & 1 == 0 {
                return slot;
            }
            if e & GP_EXC == 0 {
                return (e as u32) - 1;
            }
        }
        self.uf.find(slot)
    }
    /// The ID string of a slot.
    fn slot_string(&self, slot: u32, out: &mut Vec<u8>) {
        if slot >= self.fbase {
            out.extend_from_slice(self.fb_names[(slot - self.fbase) as usize]);
        } else {
            let n = if slot >= self.kbase { KIOSK + (slot - self.kbase) as u64 } else { (slot as u64 / ALIAS) * 512 + slot as u64 % ALIAS };
            id_string(b'u', n, self.ukey.unwrap().key, out);
        }
    }
}

/// 8-byte order key of a decodable user ID (bytes after 'u', big-endian, zero padded):
/// orders exactly like the strings among decodable IDs.
fn name_key(s: &[u8]) -> u64 {
    let mut t = [0u8; 8];
    t[..s.len() - 1].copy_from_slice(&s[1..]);
    u64::from_be_bytes(t)
}

// ============================================================================ per-thread parse output
const NPART: usize = 256;
const BLK: usize = 1024;
const FB_FLAG: u32 = 1 << 31;

/// Event copy in a partition: n and the 16-byte slot record.
///   a = (ingest22 + 1) << 8 | category      (nonzero for any written slot)
///   b = valid << 31 | ts (ms since window_start - 7 days, 31 bits)
///   c = user slot, or FB_FLAG | thread << 24 | index into the thread's fallback users
///   d = type << 24 | price
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct PE {
    n: u32,
    r: [u32; 4],
}

struct Arena {
    base: *mut u8,
    off: usize,
    cap: usize,
}
impl Arena {
    fn new(cap: usize) -> Self {
        Arena { base: region(cap), off: 0, cap: cap.max(4096).next_multiple_of(2 << 20) }
    }
    #[inline(never)]
    fn take(&mut self, bytes: usize) -> *mut u8 {
        if self.off + bytes > self.cap {
            *self = Arena::new(self.cap.max(bytes));
        }
        let p = unsafe { self.base.add(self.off) };
        self.off += bytes;
        p
    }
}

struct Blocks<T> {
    cur: *mut T,
    left: usize,
    blocks: Vec<*mut T>,
}
impl<T: Copy> Blocks<T> {
    fn new() -> Self {
        Blocks { cur: core::ptr::null_mut(), left: 0, blocks: Vec::new() }
    }
    #[inline(always)]
    fn push(&mut self, arena: &mut Arena, v: T) {
        if self.left == 0 {
            let b = arena.take(BLK * std::mem::size_of::<T>()) as *mut T;
            self.blocks.push(b);
            self.cur = b;
            self.left = BLK;
        }
        unsafe {
            self.cur.write(v);
            self.cur = self.cur.add(1);
        }
        self.left -= 1;
    }
    fn chunks(&self) -> impl Iterator<Item = &[T]> {
        let n = self.blocks.len();
        self.blocks.iter().enumerate().map(move |(i, &b)| {
            let len = if i + 1 == n { BLK - self.left } else { BLK };
            unsafe { core::slice::from_raw_parts(b, len) }
        })
    }
}

/// A valid click: person (or FB_FLAG | thread << 24 | fallback user index), ts since
/// window_start - 7 days, click number (or FB_FLAG | thread << 24 | fallback id index), campaign.
type Ck = [u32; 4];

struct Tls {
    arena: Arena,
    parts: Vec<Blocks<PE>>,
    clicks: Vec<Ck>,
    fb_ev: Vec<(S, [u32; 4])>, // events whose event_id did not decode
    fb_users: Vec<S>,
    fb_cids: Vec<S>,
    buf: (Vec<u32>, Vec<u64>),
}
unsafe impl Send for Tls {}
unsafe impl Sync for Tls {}

struct PerThread(Vec<std::cell::UnsafeCell<Tls>>);
unsafe impl Sync for PerThread {}
impl PerThread {
    #[allow(clippy::mut_from_ref)]
    fn me(&self) -> (usize, &mut Tls) {
        let i = rayon::current_thread_index().map_or(self.0.len() - 1, |i| i);
        (i, unsafe { &mut *self.0[i].get() })
    }
}

// ============================================================================ Parquet (Track B)
enum Col<'a> {
    Str(&'a [S]),
    OptStr(&'a [Option<S>]),
    Date(&'a [i32]),
    I64(&'a [i64]),
}

struct Thrift {
    b: Vec<u8>,
    last: Vec<i16>,
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
    fn begin(&mut self) {
        self.last.push(0);
    }
    fn begin_field(&mut self, id: i16) {
        self.field(id, Self::STRUCT);
        self.last.push(0);
    }
    fn end(&mut self) {
        self.b.push(0);
        self.last.pop();
    }
}

fn write_parquet(path: &Path, cols: &[(&str, Col)], nrows: usize) {
    let mut f: Vec<u8> = Vec::with_capacity(64 + nrows * 48);
    f.extend_from_slice(b"PAR1");
    let mut chunks: Vec<(usize, usize)> = Vec::new();
    if nrows > 0 {
        for (_, col) in cols {
            let offset = f.len();
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
            let mut h = Thrift::new();
            h.i32(1, 0);
            h.i32(2, payload as i32);
            h.i32(3, payload as i32);
            h.begin_field(5);
            h.i32(1, nrows as i32);
            h.i32(2, 0);
            h.i32(3, 3);
            h.i32(4, 3);
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
        match c {
            Col::Str(_) => (6, 0, Some(0)),
            Col::OptStr(_) => (6, 1, Some(0)),
            Col::Date(_) => (1, 0, Some(6)),
            Col::I64(_) => (2, 0, None),
        }
    };
    let mut m = Thrift::new();
    m.i32(1, 1);
    m.list(2, Thrift::STRUCT, cols.len() + 1);
    m.begin();
    m.string(4, b"schema");
    m.i32(5, cols.len() as i32);
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
    m.i64(3, nrows as i64);
    m.list(4, Thrift::STRUCT, usize::from(nrows > 0));
    if nrows > 0 {
        m.begin();
        m.list(1, Thrift::STRUCT, cols.len());
        for ((name, col), &(offset, size)) in cols.iter().zip(&chunks) {
            m.begin();
            m.i64(2, offset as i64);
            m.begin_field(3);
            m.i32(1, kind(col).0);
            m.list(2, Thrift::I32, 2);
            m.zigzag(0);
            m.zigzag(3);
            m.list(3, Thrift::BINARY, 1);
            m.bytes(name.as_bytes());
            m.i32(4, 0);
            m.i64(5, nrows as i64);
            m.i64(6, size as i64);
            m.i64(7, size as i64);
            m.i64(9, offset as i64);
            m.end();
            m.end();
        }
        m.i64(2, chunks.iter().map(|c| c.1 as i64).sum());
        m.i64(3, nrows as i64);
        m.end();
    }
    m.string(6, b"shopping-sessions track-d");
    m.end();
    f.extend_from_slice(&m.b);
    f.extend_from_slice(&(m.b.len() as u32).to_le_bytes());
    f.extend_from_slice(b"PAR1");
    fs::write(path, &f).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

// ============================================================================ sessions, credit, assists
/// One valid event of a person: ts since base, price (0 unless purchase), category, purchase.
#[derive(Clone, Copy)]
struct E {
    ts: i64,
    price: i64,
    cat: u32,
    purchase: bool,
}

struct Dims<'a> {
    ndays: usize,
    day0: i64,
    base: i64,
    organic: usize,
    cat_names: &'a [S],
}

struct Acc {
    c_sessions: Vec<i64>,
    c_purchasing: Vec<i64>,
    c_revenue: Vec<i64>,
    c_assisted: Vec<i64>,
    names: Vec<u8>,
    u_name: Vec<(u32, u32)>,
    u_day: Vec<i32>,
    u_sessions: Vec<i64>,
    u_events: Vec<i64>,
    u_revenue: Vec<i64>,
    u_top: Vec<Option<S>>,
    win_count: Vec<u32>,
    win_pos: Vec<u32>,
    active: Vec<u16>,
    cat_sum: Vec<i64>,
    ev: Vec<E>,
    n_sessions: u64,
}

impl Acc {
    fn new(ncamp: usize, ndays: usize, ncat: usize) -> Self {
        Acc {
            c_sessions: vec![0; ncamp * ndays],
            c_purchasing: vec![0; ncamp * ndays],
            c_revenue: vec![0; ncamp * ndays],
            c_assisted: vec![0; ncamp * ndays],
            names: Vec::new(),
            u_name: Vec::new(),
            u_day: Vec::new(),
            u_sessions: Vec::new(),
            u_events: Vec::new(),
            u_revenue: Vec::new(),
            u_top: Vec::new(),
            win_count: vec![0; ncamp],
            win_pos: vec![0; ncamp],
            active: Vec::new(),
            cat_sum: vec![0; ncat],
            ev: Vec::new(),
            n_sessions: 0,
        }
    }

    fn flush_day(&mut self, d: &Dims, name: (u32, u32), day: i64, sessions: i64, events: i64, revenue: i64) {
        let mut top: Option<usize> = None;
        if revenue > 0 {
            for c in 0..self.cat_sum.len() {
                let v = self.cat_sum[c];
                if v > 0 {
                    top = match top {
                        Some(t) if self.cat_sum[t] > v || (self.cat_sum[t] == v && d.cat_names[t] <= d.cat_names[c]) => Some(t),
                        _ => Some(c),
                    };
                }
            }
            self.cat_sum.fill(0);
        }
        self.u_name.push(name);
        self.u_day.push((d.day0 + day) as i32);
        self.u_sessions.push(sessions);
        self.u_events.push(events);
        self.u_revenue.push(revenue);
        self.u_top.push(top.map(|t| d.cat_names[t]));
    }

    /// One person: self.ev sorted by ts; clicks [person, ts, id, campaign] sorted by
    /// (ts, click_id desc).
    fn person(&mut self, d: &Dims, name: (u32, u32), pc: &[Ck]) {
        let ncl = pc.len();
        let cts = |i: usize| pc[i][1] as i64;
        let ccamp = |i: usize| pc[i][3] as usize;
        let ev = std::mem::take(&mut self.ev);
        let ndays = d.ndays;
        let (mut lo, mut hi) = (0usize, 0usize);
        let mut cur_day: i64 = -1;
        let (mut d_sessions, mut d_events, mut d_revenue) = (0i64, 0i64, 0i64);
        let mut k = 0;
        while k < ev.len() {
            let start = ev[k].ts;
            let day = (d.base + start).div_euclid(DAY_MS) - d.day0;
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
            while k < ev.len() && ev[k].ts - prev <= GAP_MS {
                let e = ev[k];
                prev = e.ts;
                s_events += 1;
                if e.purchase {
                    s_revenue += e.price;
                    s_purchase = true;
                    self.cat_sum[e.cat as usize] += e.price;
                }
                k += 1;
            }
            d_sessions += 1;
            d_events += s_events;
            d_revenue += s_revenue;
            self.n_sessions += 1;
            if ncl != 0 {
                while hi < ncl && cts(hi) <= start {
                    let c = ccamp(hi);
                    self.win_count[c] += 1;
                    if self.win_count[c] == 1 {
                        self.win_pos[c] = self.active.len() as u32;
                        self.active.push(c as u16);
                    }
                    hi += 1;
                }
                while lo < hi && cts(lo) < start - WEEK_MS {
                    let c = ccamp(lo);
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
            let credited = if hi > lo { ccamp(hi - 1) } else { d.organic };
            let cell = credited * ndays + day as usize;
            self.c_sessions[cell] += 1;
            self.c_purchasing[cell] += s_purchase as i64;
            self.c_revenue[cell] += s_revenue;
            for &c in &self.active {
                self.c_assisted[c as usize * ndays + day as usize] += 1;
            }
        }
        if cur_day >= 0 {
            self.flush_day(d, name, cur_day, d_sessions, d_events, d_revenue);
        }
        for &c in &self.active {
            self.win_count[c as usize] = 0;
        }
        self.active.clear();
        let mut ev = ev;
        ev.clear();
        self.ev = ev;
    }
}

// ============================================================================ main
fn main() {
    let mut clock = Clock(Instant::now(), Instant::now());
    let data = PathBuf::from(std::env::var("DATA_DIR").unwrap_or_else(|_| "/data".into()));
    let out = PathBuf::from(std::env::var("OUTPUT_DIR").unwrap_or_else(|_| "/output".into()));
    let nthreads: usize = std::env::var("NCPU").ok().and_then(|v| v.parse().ok()).filter(|&n| n > 0).unwrap_or(8).min(15);
    rayon::ThreadPoolBuilder::new().num_threads(nthreads).build_global().unwrap();

    let manifest = fs::read_to_string(data.join("manifest.json")).expect("manifest.json");
    let ws = manifest_value(&manifest, "window_start");
    let we = manifest_value(&manifest, "window_end");
    let base = ws - WEEK_MS;
    assert!(we > base && we - base < 1 << 31, "window too long");
    let tsf = TsFast::new(ws, we);
    let ingest_base = ws - 12 * DAY_MS;

    // ---- inputs ----
    let (ev_chunks, (ck_chunks, ln_chunks)) = rayon::join(
        || load_chunks(&data.join("events")),
        || rayon::join(|| load_chunks(&data.join("clicks")), || load_chunks(&data.join("links"))),
    );
    let ev_bytes: usize = ev_chunks.iter().map(|c| c.len()).sum();
    let ck_bytes: usize = ck_chunks.iter().map(|c| c.len()).sum();

    // ---- products / campaigns ----
    let mut cat_names: Vec<S> = Vec::new();
    let mut cat_of: HashMap<S, u8> = HashMap::new();
    let mut cat_dense: Vec<u8> = Vec::new(); // "p{n}" -> category + 1
    let mut buf0 = (Vec::new(), Vec::new());
    let mut cat_index: HashMap<S, u8> = HashMap::new();
    for c in load_chunks(&data.join("products.csv")) {
        scan::<2>(c, &mut buf0, |&[pid, cat]| {
            if pid.is_empty() {
                return;
            }
            let idx = *cat_index.entry(cat).or_insert_with(|| {
                cat_names.push(cat);
                (cat_names.len() - 1) as u8
            });
            match dec_num(pid, b"p") {
                Some(n) if n < 1 << 22 => {
                    if cat_dense.len() <= n {
                        cat_dense.resize(n + 1, 0);
                    }
                    if cat_dense[n] == 0 {
                        cat_dense[n] = idx + 1;
                    }
                }
                _ => {
                    cat_of.entry(pid).or_insert(idx);
                }
            }
        });
    }
    let cat_unknown = cat_names.len() as u8;
    cat_names.push(b"unknown");
    assert!(cat_names.len() <= 255, "too many categories");
    let category = |pid: &[u8]| -> u8 {
        if let Some(n) = dec_num(pid, b"p") {
            if n < cat_dense.len() {
                let c = cat_dense[n];
                return if c == 0 { cat_unknown } else { c - 1 };
            }
        }
        *cat_of.get(pid).unwrap_or(&cat_unknown)
    };
    let mut camp_ids: Vec<S> = Vec::new();
    let mut camp_channels: Vec<S> = Vec::new();
    let mut camp_of: HashMap<S, u16> = HashMap::new();
    let mut camp_dense: Vec<u16> = Vec::new(); // "c_{n}" -> index + 1
    for c in load_chunks(&data.join("campaigns.csv")) {
        scan::<2>(c, &mut buf0, |&[cid, channel]| {
            if cid.is_empty() || camp_of.contains_key(cid) {
                return;
            }
            let i = camp_ids.len() as u16;
            camp_of.insert(cid, i);
            camp_ids.push(cid);
            camp_channels.push(channel);
            if let Some(n) = dec_num(cid, b"c_") {
                if n < 1 << 22 {
                    if camp_dense.len() <= n {
                        camp_dense.resize(n + 1, 0);
                    }
                    camp_dense[n] = i + 1;
                }
            }
        });
    }
    let organic = camp_ids.len();
    camp_ids.push(b"organic");
    camp_channels.push(b"organic");
    let ncamp = camp_ids.len();
    assert!(ncamp < 65_000, "too many campaigns");
    let campaign = |cid: &[u8]| -> Option<u16> {
        if let Some(n) = dec_num(cid, b"c_") {
            if n < camp_dense.len() && camp_dense[n] != 0 {
                return Some(camp_dense[n] - 1);
            }
        }
        camp_of.get(cid).copied()
    };

    // ---- keys ----
    let (ev_ws, ev_avg) = sample::<7>(&ev_chunks, 0, b'e');
    let (ck_ws, ck_avg) = sample::<4>(&ck_chunks, 0, b'k');
    let (us_ws, _) = sample::<7>(&ev_chunks, 1, b'u');
    let ev_bound = ((ev_bytes as f64 / ev_avg) * 1.25) as u64 + 4096;
    let ck_bound = ((ck_bytes as f64 / ck_avg) * 1.25) as u64 + 4096;
    let pb_est = ev_bound / 16 + 1024;
    let ekey = recover_key(&ev_ws, ev_bound, |j| j, |n| n < ev_bound).map(|key| Dec { key, prefix: b'e' });
    let ckey = recover_key(&ck_ws, ck_bound, |j| j, |n| n < ck_bound).map(|key| Dec { key, prefix: b'k' });
    let ukey = recover_key(
        &us_ws,
        pb_est * 8,
        |j| (j >> 3) * 512 + (j & 7),
        |n| (n >> 9 < pb_est && n & 511 < ALIAS) || (KIOSK..KIOSK + KMAX).contains(&n),
    )
    .map(|key| Dec { key, prefix: b'u' });
    clock.log(&format!("keys: event {} click {} user {}", ekey.is_some(), ckey.is_some(), ukey.is_some()));

    // ---- links -> persons ----
    let unum = |s: S| ukey.and_then(|k| k.num(s));
    let link_raw: Vec<Vec<(Option<u64>, Option<u64>, S, S)>> = ln_chunks
        .par_iter()
        .map(|&c| {
            let mut v = Vec::new();
            let mut b = (Vec::new(), Vec::new());
            scan::<2>(c, &mut b, |f| {
                if !f[0].is_empty() && !f[1].is_empty() {
                    v.push((unum(f[0]), unum(f[1]), f[0], f[1]));
                }
            });
            v
        })
        .collect();
    let max_gp = link_raw
        .par_iter()
        .map(|v| v.iter().flat_map(|&(a, b, _, _)| [a, b]).flatten().filter(|&n| n < KIOSK && n & 511 < ALIAS && n >> 9 < pb_est).map(|n| n >> 9).max().unwrap_or(0))
        .max()
        .unwrap_or(0);
    let pb = (max_gp + 1) + (max_gp + 1) / 64 + 64;
    let kbase = (pb * ALIAS) as u32;
    let fbase = kbase + KMAX as u32;
    let nslot = fbase as usize + (1 << 22);
    let mut persons = Persons {
        ukey,
        pb,
        kbase,
        uf: Uf { p: zeroed::<AtomicU32>(nslot) },
        gp: zeroed::<AtomicU64>(pb as usize),
        fb: HashMap::new(),
        fb_names: Vec::new(),
        fbase,
    };
    let link_pairs: Vec<Vec<(Option<u32>, Option<u32>, S, S)>> = link_raw
        .par_iter()
        .map(|v| v.iter().map(|&(a, b, sa, sb)| (persons.slot_of_num(a), persons.slot_of_num(b), sa, sb)).collect())
        .collect();
    for v in &link_pairs {
        for &(sa, sb, a, b) in v {
            for (s, id) in [(sa, a), (sb, b)] {
                if s.is_none() && !persons.fb.contains_key(id) {
                    let slot = fbase + persons.fb_names.len() as u32;
                    persons.fb.insert(id, slot);
                    persons.fb_names.push(id);
                }
            }
        }
    }
    {
        let p = &persons;
        let res = |s: Option<u32>, id: S| s.unwrap_or_else(|| p.fb[id]);
        link_pairs.par_iter().for_each(|v| {
            for &(sa, sb, a, b) in v {
                p.uf.union(res(sa, a), res(sb, b));
            }
        });
        link_pairs.par_iter().for_each(|v| {
            for &(sa, sb, _, _) in v {
                for s in [sa, sb].into_iter().flatten() {
                    if (s as u64) < pb * ALIAS {
                        let (g, a) = (s as u64 / ALIAS, s as u64 % ALIAS);
                        let r = p.uf.find(s) as u64 + 1;
                        let cell = &p.gp[g as usize];
                        let mut cur = cell.load(Relaxed);
                        loop {
                            let mut nv = cur | (1 << (32 + a));
                            let root = cur & 0xFFFF_FFFF;
                            if root == 0 {
                                nv |= r;
                            } else if root != r {
                                nv |= GP_EXC;
                            }
                            if nv == cur {
                                break;
                            }
                            match cell.compare_exchange_weak(cur, nv, Relaxed, Relaxed) {
                                Ok(_) => break,
                                Err(x) => cur = x,
                            }
                        }
                    }
                }
            }
        });
    }
    // Names of linked persons: smallest decodable ID by order key (atomic), plus the
    // smallest fallback ID per component (rare) compared as strings at the end.
    let name_best = zeroed::<AtomicU64>(nslot); // stores !key, 0 = none
    let mut fb_best: HashMap<u32, S> = HashMap::new();
    {
        let p = &persons;
        link_pairs.par_iter().for_each(|v| {
            for &(sa, sb, a, b) in v {
                for (s, id) in [(sa, a), (sb, b)] {
                    if let Some(s) = s {
                        let r = p.uf.find(s);
                        name_best[r as usize].fetch_max(!name_key(id), Relaxed);
                    }
                }
            }
        });
        for (i, &id) in persons.fb_names.iter().enumerate() {
            let r = persons.uf.find(fbase + i as u32);
            let e = fb_best.entry(r).or_insert(id);
            if id < *e {
                *e = id;
            }
        }
    }
    let nlinks: usize = link_pairs.iter().map(|v| v.len()).sum();
    clock.log(&format!("links: {nlinks} pairs, {} fallback IDs", persons.fb_names.len()));
    let persons = persons;

    // ---- events and clicks ----
    let ev_rows_est = ev_bytes as f64 / ev_avg;
    let arena_bytes = ((ev_rows_est * 20.0 * 1.15) / nthreads as f64) as usize + NPART * BLK * 20 * 2;
    let pt = PerThread(
        (0..nthreads + 1)
            .map(|_| {
                std::cell::UnsafeCell::new(Tls {
                    arena: Arena::new(arena_bytes),
                    parts: (0..NPART).map(|_| Blocks::new()).collect(),
                    clicks: Vec::with_capacity(ck_bytes / 45 / nthreads + 1024),
                    fb_ev: Vec::new(),
                    fb_users: Vec::new(),
                    fb_cids: Vec::new(),
                    buf: (Vec::new(), Vec::new()),
                })
            })
            .collect(),
    );
    let part_shift = {
        let per = ev_bound.div_ceil(NPART as u64).max(1);
        64 - (per - 1).leading_zeros().min(63) // ceil(log2(per))
    };
    let ev_work = |c: S| {
        let (me, t) = pt.me();
        let mut buf = std::mem::take(&mut t.buf);
        scan::<7>(c, &mut buf, |f| {
            let eid = f[0];
            if eid.is_empty() {
                return;
            }
            let ingest = tsf.parse(f[3]);
            let ingest22 = match ingest {
                Some(v) => (v - ingest_base).div_euclid(1000).clamp(0, INGEST_BITS as i64 - 1) as u32,
                None => INGEST_BITS as u32,
            };
            let mut r = [(ingest22 + 1) << 8, 0, 0, 0];
            'v: {
                let Some(ingest) = ingest else { break 'v };
                let user = f[1];
                if user.is_empty() || f[5].is_empty() {
                    break 'v;
                }
                let Some(ts) = tsf.parse(f[2]) else { break 'v };
                if ts < ws || ts >= we || ingest - ts > LATE_MS {
                    break 'v;
                }
                let (typ, price, cat) = match f[4] {
                    b"view" => (0u32, 0u32, 0u8),
                    b"cart" => (1, 0, 0),
                    b"purchase" => {
                        let Some(p) = parse_price(f[6]) else { break 'v };
                        (2, p, category(f[5]))
                    }
                    _ => break 'v,
                };
                let us = match persons.slot(user) {
                    Some(s) => s,
                    None => {
                        t.fb_users.push(user);
                        FB_FLAG | (me as u32) << 24 | (t.fb_users.len() as u32 - 1)
                    }
                };
                r[0] |= cat as u32;
                r[1] = 1 << 31 | (ts - base) as u32;
                r[2] = us;
                r[3] = typ << 24 | price;
            }
            match ekey.and_then(|k| k.num(eid)).filter(|&n| n < ev_bound) {
                Some(n) => t.parts[(n >> part_shift) as usize].push(&mut t.arena, PE { n: n as u32, r }),
                None => t.fb_ev.push((eid, r)),
            }
        });
        t.buf = buf;
    };
    let ck_work = |c: S| {
        let (me, t) = pt.me();
        let mut buf = std::mem::take(&mut t.buf);
        scan::<4>(c, &mut buf, |&[cid, user, camp, ts]| {
            if cid.is_empty() || user.is_empty() {
                return;
            }
            let Some(ts) = tsf.parse(ts) else { return };
            if ts < base || ts >= we {
                return;
            }
            let Some(camp) = campaign(camp) else { return };
            let cn = match ckey.and_then(|k| k.num(cid)).filter(|&n| n < ck_bound) {
                Some(n) => n as u32,
                None => {
                    t.fb_cids.push(cid);
                    FB_FLAG | (me as u32) << 24 | (t.fb_cids.len() as u32 - 1)
                }
            };
            let p = match persons.slot(user) {
                Some(s) => persons.person(s),
                None => {
                    t.fb_users.push(user);
                    FB_FLAG | (me as u32) << 24 | (t.fb_users.len() as u32 - 1)
                }
            };
            t.clicks.push([p, (ts - base) as u32, cn, camp as u32]);
        });
        t.buf = buf;
    };
    enum Job {
        E(S),
        C(S),
    }
    let jobs: Vec<Job> = ev_chunks.iter().map(|&c| Job::E(c)).chain(ck_chunks.iter().map(|&c| Job::C(c))).collect();
    jobs.par_iter().with_max_len(1).for_each(|j| match *j {
        Job::E(c) => ev_work(c),
        Job::C(c) => ck_work(c),
    });
    let tls: Vec<&mut Tls> = pt.0.iter().map(|c| unsafe { &mut *c.get() }).collect();
    clock.log("events and clicks parsed");

    // ---- fallback user IDs that no link names: one slot per distinct string ----
    let mut persons = persons;
    let fb_map: Vec<Vec<u32>> = {
        let mut m: HashMap<S, u32> = HashMap::new();
        tls.iter()
            .map(|t| {
                t.fb_users
                    .iter()
                    .map(|&s| {
                        *m.entry(s).or_insert_with(|| {
                            let slot = fbase + persons.fb_names.len() as u32;
                            persons.fb_names.push(s);
                            slot
                        })
                    })
                    .collect()
            })
            .collect()
    };
    let persons = persons;
    let user_slot = |c: u32| -> u32 {
        if c & FB_FLAG != 0 {
            fb_map[((c >> 24) & 0x7F) as usize][(c & 0xFF_FFFF) as usize]
        } else {
            c
        }
    };

    // ---- clicks: resolve fallback persons, sort by (person, ts, click_id desc), drop repeats ----
    let mut clicks: Vec<Ck> = tls.iter().flat_map(|t| t.clicks.iter().copied()).collect();
    clicks.par_iter_mut().for_each(|c| {
        if c[0] & FB_FLAG != 0 {
            c[0] = persons.person(user_slot(c[0]));
        }
    });
    let ckk = ckey.map_or(0, |k| k.key);
    let cid_bytes = |c: u32, out: &mut Vec<u8>| {
        if c & FB_FLAG != 0 {
            out.extend_from_slice(tls[((c >> 24) & 0x7F) as usize].fb_cids[(c & 0xFF_FFFF) as usize]);
        } else {
            id_string(b'k', c as u64, ckk, out);
        }
    };
    // (person, ts) as one integer key; tied groups (rare) are then ordered by click_id
    // descending and exact repeats (copies of one click) dropped.
    clicks.par_sort_unstable_by_key(|c| (c[0] as u64) << 32 | c[1] as u64);
    let mut ties: Vec<(usize, usize)> = Vec::new();
    {
        let mut i = 0;
        while i < clicks.len() {
            let mut j = i + 1;
            while j < clicks.len() && clicks[j][0] == clicks[i][0] && clicks[j][1] == clicks[i][1] {
                j += 1;
            }
            if j - i > 1 {
                ties.push((i, j));
            }
            i = j;
        }
    }
    let mut dead = vec![false; clicks.len()];
    for &(i, j) in &ties {
        let mut g: Vec<(Vec<u8>, Ck)> = clicks[i..j]
            .iter()
            .map(|&c| {
                let mut s = Vec::with_capacity(16);
                cid_bytes(c[2], &mut s);
                (s, c)
            })
            .collect();
        g.sort_by(|a, b| b.0.cmp(&a.0)); // click_id descending
        for (k, (s, c)) in g.iter().enumerate() {
            clicks[i + k] = *c;
            dead[i + k] = k > 0 && *s == g[k - 1].0;
        }
    }
    if ties.iter().any(|&(i, j)| dead[i..j].iter().any(|&d| d)) {
        let mut k = 0;
        clicks.retain(|_| {
            k += 1;
            !dead[k - 1]
        });
    }
    clock.log(&format!("clicks sorted: {}", clicks.len()));

    // ---- events: per partition, slots = min-ingest copy; runs of one person ----
    let per = 1usize << part_shift;
    let slots_ptr = region(per * NPART * 16) as usize;
    let runs_count = zeroed::<AtomicU32>(nslot);
    // fallback event IDs: smallest ingest per string; winners force their person to the side path
    let fb_winners: Vec<[u32; 4]> = {
        let mut all: Vec<(S, [u32; 4])> = tls.iter().flat_map(|t| t.fb_ev.iter().copied()).collect();
        all.sort_unstable_by(|a, b| a.0.cmp(b.0).then((a.1[0] >> 8).cmp(&(b.1[0] >> 8))));
        all.dedup_by(|b, a| a.0 == b.0);
        all.into_iter().map(|x| x.1).filter(|r| r[1] >> 31 != 0).collect()
    };
    for r in &fb_winners {
        let p = persons.person(user_slot(r[2]));
        runs_count[p as usize].fetch_add(2, Relaxed);
    }
    // run list per partition: (person, first slot, end slot)
    let runs: Vec<Vec<(u32, u32, u32)>> = (0..NPART)
        .into_par_iter()
        .map(|p| {
            let slots = unsafe { core::slice::from_raw_parts_mut((slots_ptr as *mut [u32; 4]).add(p * per), per) };
            for t in tls.iter() {
                for blk in t.parts[p].chunks() {
                    for e in blk {
                        let s = &mut slots[e.n as usize & (per - 1)];
                        if s[0] == 0 || (e.r[0] >> 8) < (s[0] >> 8) {
                            *s = e.r;
                        }
                    }
                }
            }
            let mut rv: Vec<(u32, u32, u32)> = Vec::new();
            let mut cur: Option<(u32, u32, u32)> = None;
            for (i, s) in slots.iter().enumerate() {
                if s[1] >> 31 == 0 {
                    continue; // empty or invalid winner
                }
                let person = persons.person(user_slot(s[2]));
                match &mut cur {
                    Some(r) if r.0 == person => r.2 = i as u32 + 1,
                    _ => {
                        if let Some(r) = cur.take() {
                            rv.push(r);
                        }
                        cur = Some((person, i as u32, i as u32 + 1));
                    }
                }
            }
            if let Some(r) = cur {
                rv.push(r);
            }
            for r in &rv {
                runs_count[r.0 as usize].fetch_add(1, Relaxed);
            }
            rv
        })
        .collect();
    clock.log(&format!("events placed: {} runs", runs.iter().map(|r| r.len()).sum::<usize>()));

    // ---- sessions, credit, assists ----
    let day0 = ws.div_euclid(DAY_MS);
    let ndays = ((we - 1).div_euclid(DAY_MS) - day0 + 1).max(1) as usize;
    let dims = Dims { ndays, day0, base, organic, cat_names: &cat_names };
    let ncat = cat_names.len();
    let name_of = |p: u32, out: &mut Vec<u8>| {
        let k = name_best[p as usize].load(Relaxed);
        let fbn = fb_best.get(&p).copied();
        if k == 0 && fbn.is_none() {
            persons.slot_string(p, out); // a person on its own: its only ID
            return;
        }
        let mut dec: Vec<u8> = Vec::new();
        if k != 0 {
            let key = (!k).to_be_bytes();
            dec.push(b'u');
            dec.extend(key.iter().take_while(|&&b| b != 0));
        }
        match fbn {
            Some(f) if k == 0 || f < dec.as_slice() => out.extend_from_slice(f),
            _ => out.extend_from_slice(&dec),
        }
    };
    let clicks_of = |p: u32| -> &[Ck] {
        let lo = clicks.partition_point(|c| c[0] < p);
        let hi = lo + clicks[lo..].partition_point(|c| c[0] <= p);
        &clicks[lo..hi]
    };
    // Persons mostly come in increasing order within a partition: a cursor that walks
    // forward, with a binary search when the person goes backward or jumps far.
    let clicks_at = |p: u32, cur: &mut usize| -> &[Ck] {
        let mut i = *cur;
        if i > clicks.len() || (i > 0 && clicks[i - 1][0] >= p) {
            i = clicks.partition_point(|c| c[0] < p);
        } else {
            let mut steps = 0;
            while i < clicks.len() && clicks[i][0] < p {
                i += 1;
                steps += 1;
                if steps == 64 {
                    i += clicks[i..].partition_point(|c| c[0] < p);
                    break;
                }
            }
        }
        let mut j = i;
        while j < clicks.len() && clicks[j][0] == p {
            j += 1;
        }
        *cur = j;
        &clicks[i..j]
    };
    let to_e = |s: &[u32; 4]| E {
        ts: (s[1] & 0x7FFF_FFFF) as i64,
        price: (s[3] & 0xFF_FFFF) as i64,
        cat: s[0] & 0xFF,
        purchase: s[3] >> 24 == 2,
    };
    // A fixed number of tasks, each with one accumulator and a spread of partitions.
    let ntask = (nthreads * 2).clamp(1, NPART);
    let (accs, sides): (Vec<Acc>, Vec<Vec<Vec<(u32, E)>>>) = (0..ntask)
        .into_par_iter()
        .map(|t| {
            let mut acc = Acc::new(ncamp, ndays, ncat);
            let mut sides = Vec::new();
            for p in (t..NPART).step_by(ntask) {
                let mut side: Vec<(u32, E)> = Vec::new();
                let mut cur = usize::MAX;
                let slots = unsafe { core::slice::from_raw_parts((slots_ptr as *const [u32; 4]).add(p * per), per) };
                for &(person, s, e) in &runs[p] {
                    let valid = slots[s as usize..e as usize].iter().filter(|x| x[1] >> 31 != 0);
                    if runs_count[person as usize].load(Relaxed) != 1 {
                        side.extend(valid.map(|x| (person, to_e(x))));
                        continue;
                    }
                    acc.ev.extend(valid.map(to_e));
                    if acc.ev.windows(2).any(|w| w[1].ts < w[0].ts) {
                        acc.ev.sort_by_key(|e| e.ts);
                    }
                    let at = acc.names.len() as u32;
                    name_of(person, &mut acc.names);
                    let name = (at, acc.names.len() as u32 - at);
                    acc.person(&dims, name, clicks_at(person, &mut cur));
                }
                sides.push((p, side));
            }
            (acc, { sides.sort_by_key(|x| x.0); sides.into_iter().map(|x| x.1).collect() })
        })
        .unzip();
    // Side path: persons that are not exactly one run. Partitions are concatenated in slot
    // order, so a stable sort by person keeps each person's events in slot (= time) order.
    let mut by_part: Vec<(usize, Vec<(u32, E)>)> = Vec::new();
    for (t, v) in sides.into_iter().enumerate() {
        for (k, s) in v.into_iter().enumerate() {
            by_part.push((t + k * ntask, s));
        }
    }
    by_part.sort_by_key(|x| x.0);
    let mut side: Vec<(u32, E)> = by_part.into_iter().flat_map(|x| x.1).collect();
    side.extend(fb_winners.iter().map(|r| (persons.person(user_slot(r[2])), to_e(r))));
    side.par_sort_by_key(|x| x.0);
    let groups: Vec<&[(u32, E)]> = side.chunk_by(|a, b| a.0 == b.0).collect();
    // ntask contiguous ranges of persons with about equal event counts, one accumulator each
    let mut cuts = vec![0usize];
    {
        let target = side.len() / ntask + 1;
        let mut acc_n = 0;
        for (i, g) in groups.iter().enumerate() {
            acc_n += g.len();
            if acc_n >= target {
                cuts.push(i + 1);
                acc_n = 0;
            }
        }
        if *cuts.last().unwrap() != groups.len() {
            cuts.push(groups.len());
        }
    }
    let side_accs: Vec<Acc> = cuts
        .par_windows(2)
        .map(|w| {
            let mut acc = Acc::new(ncamp, ndays, ncat);
            let mut cur = usize::MAX;
            for g in &groups[w[0]..w[1]] {
                let person = g[0].0;
                acc.ev.extend(g.iter().map(|x| x.1));
                if acc.ev.windows(2).any(|w| w[1].ts < w[0].ts) {
                    acc.ev.sort_by_key(|e| e.ts);
                }
                let at = acc.names.len() as u32;
                name_of(person, &mut acc.names);
                let name = (at, acc.names.len() as u32 - at);
                acc.person(&dims, name, clicks_at(person, &mut cur));
            }
            acc
        })
        .collect();
    let _ = clicks_of;
    let mut accs = accs;
    accs.extend(side_accs);
    let n_sessions: u64 = accs.iter().map(|a| a.n_sessions).sum();
    let n_user_rows: usize = accs.iter().map(|a| a.u_day.len()).sum();
    clock.log(&format!("sessions: {n_sessions}, user_daily rows: {n_user_rows}, side events {}", side.len()));

    // ---- outputs ----
    let ud = out.join("user_daily");
    let cd = out.join("campaign_daily");
    fs::create_dir_all(&ud).unwrap_or_else(|e| panic!("mkdir {}: {e}", ud.display()));
    fs::create_dir_all(&cd).unwrap_or_else(|e| panic!("mkdir {}: {e}", cd.display()));
    accs.par_iter().enumerate().for_each(|(i, a)| {
        if i > 0 && a.u_day.is_empty() {
            return;
        }
        let names: Vec<S> = a
            .u_name
            .iter()
            .map(|&(o, l)| unsafe { core::slice::from_raw_parts(a.names.as_ptr().add(o as usize), l as usize) })
            .collect();
        write_parquet(
            &ud.join(format!("part-{i}.parquet")),
            &[
                ("user_id", Col::Str(&names)),
                ("day", Col::Date(&a.u_day)),
                ("sessions", Col::I64(&a.u_sessions)),
                ("events", Col::I64(&a.u_events)),
                ("revenue_cents", Col::I64(&a.u_revenue)),
                ("top_category", Col::OptStr(&a.u_top)),
            ],
            a.u_day.len(),
        );
    });
    let (mut k_id, mut k_channel, mut k_day) = (Vec::new(), Vec::new(), Vec::new());
    let (mut k_sessions, mut k_purchasing, mut k_revenue, mut k_assisted) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for c in 0..ncamp {
        for d in 0..ndays {
            let cell = c * ndays + d;
            let sessions: i64 = accs.iter().map(|a| a.c_sessions[cell]).sum();
            let assisted: i64 = accs.iter().map(|a| a.c_assisted[cell]).sum();
            if sessions > 0 || assisted > 0 {
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
    unsafe { libc::_exit(0) };
}

/// "{prefix}{n}" with n decimal, no leading zero, at most 7 digits.
#[inline(always)]
fn dec_num(s: &[u8], prefix: &[u8]) -> Option<usize> {
    let p = prefix.len();
    let n = s.len();
    if n <= p || n > p + 7 || &s[..p] != prefix || s[p] == b'0' {
        return None;
    }
    let mut v = 0usize;
    for &c in &s[p..] {
        let d = c.wrapping_sub(b'0');
        if d > 9 {
            return None;
        }
        v = v * 10 + d as usize;
    }
    Some(v)
}
