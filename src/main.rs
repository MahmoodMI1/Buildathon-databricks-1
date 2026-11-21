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
use memchr::{memchr, memchr_iter};
use parquet::basic::Compression;
use parquet::data_type::{ByteArray, ByteArrayType, Int32Type, Int64Type};
use parquet::file::properties::{EnabledStatistics, WriterProperties};
use parquet::file::writer::SerializedFileWriter;
use parquet::schema::parser::parse_message_type;
use rayon::prelude::*;

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

/// Calls `f` for every line of a chunk. A last line without a trailing `\n` is a line (Q1).
#[inline]
fn for_each_line(chunk: S, mut f: impl FnMut(S)) {
    let mut start = 0;
    for i in memchr_iter(b'\n', chunk) {
        f(&chunk[start..i]);
        start = i + 1;
    }
    if start < chunk.len() {
        f(&chunk[start..]);
    }
}

/// R-C4..R-C7: split on every comma into exactly N fields; a field may be wrapped in
/// quotes as a whole, any other quote makes the line malformed. Quotes are stripped;
/// an empty slice is a null field (R-C6). Returns None for a malformed line,
/// including the empty line.
#[inline]
fn split_fields<const N: usize>(line: S) -> Option<[S; N]> {
    let mut out: [S; N] = [&[]; N];
    let mut n = 0;
    let mut start = 0;
    for i in memchr_iter(b',', line) {
        if n >= N - 1 {
            return None;
        }
        out[n] = &line[start..i];
        n += 1;
        start = i + 1;
    }
    if n != N - 1 {
        return None;
    }
    out[N - 1] = &line[start..];
    if memchr(b'"', line).is_some() {
        for f in out.iter_mut() {
            if memchr(b'"', f).is_some() {
                let l = f.len();
                if l < 2 || f[0] != b'"' || f[l - 1] != b'"' || memchr(b'"', &f[1..l - 1]).is_some() {
                    return None;
                }
                *f = &f[1..l - 1];
            }
        }
    }
    Some(out)
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
// ID interning: byte string -> u32, safe to call from many threads.
// The id is (index within shard << 8) | shard, so ids are not dense but stay small.
// ---------------------------------------------------------------------------

struct Interner {
    shards: Vec<Mutex<(HashTable<(u64, S, u32)>, u32)>>,
}

impl Interner {
    fn new() -> Self {
        Interner { shards: (0..NSHARD).map(|_| Mutex::new((HashTable::new(), 0))).collect() }
    }

    #[inline]
    fn intern(&self, b: S) -> u32 {
        let h = hash_bytes(b);
        let sh = shard_of(h);
        let mut g = self.shards[sh].lock().unwrap();
        let (table, next) = &mut *g;
        match table.entry(h, |e| e.0 == h && e.1 == b, |e| e.0) {
            Entry::Occupied(o) => o.get().2,
            Entry::Vacant(v) => {
                let id = (*next << 8) | sh as u32;
                *next += 1;
                v.insert((h, b, id));
                id
            }
        }
    }

    /// Size of the id space: every id handed out so far is below this.
    fn id_space(&self) -> usize {
        let max_local = self.shards.iter().map(|s| s.lock().unwrap().1).max().unwrap_or(0);
        (max_local as usize) << 8
    }

    /// id -> string. Unused ids map to the empty slice (an ID is never empty).
    fn strings(&self) -> Vec<S> {
        let mut out: Vec<S> = vec![&[]; self.id_space()];
        for s in &self.shards {
            for e in s.lock().unwrap().0.iter() {
                out[e.2 as usize] = e.1;
            }
        }
        out
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

// ---------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------

/// One well-formed event line with a non-empty event_id, before dedup (R-E1).
#[derive(Clone, Copy)]
struct ERec {
    hash: u64,
    eid: S,
    ingest: i64,
    ts: i64,
    uid: u32,
    price: u32,
    cat: u16,
    typ: u8,
    valid: bool, // passes R-E3 and R-E4
}

/// A surviving event.
#[derive(Clone, Copy)]
struct Ev {
    person: u32,
    ts: i64,
    price: u32,
    cat: u16,
    typ: u8,
}

/// One well-formed click line with a non-empty click_id, before dedup (R-K1).
#[derive(Clone, Copy)]
struct CRec {
    hash: u64,
    cid: S,
    ts: i64,
    uid: u32,
    camp: u16,
    valid: bool, // passes R-K3
}

/// A valid click.
#[derive(Clone, Copy)]
struct Click {
    person: u32,
    ts: i64,
    cid: S,
    camp: u16,
}

// ---------------------------------------------------------------------------
// Parquet output (R-O1)
// ---------------------------------------------------------------------------

enum Col {
    Str(Vec<S>),
    OptStr(Vec<Option<S>>),
    Date(Vec<i32>),
    I64(Vec<i64>),
}

fn write_parquet(dir: &Path, schema: &str, cols: &[Col], nrows: usize) {
    fs::create_dir_all(dir).unwrap_or_else(|e| panic!("mkdir {}: {e}", dir.display()));
    let path = dir.join("part-0.parquet");
    let schema = Arc::new(parse_message_type(schema).expect("schema"));
    let props = Arc::new(
        WriterProperties::builder()
            .set_compression(Compression::UNCOMPRESSED)
            .set_dictionary_enabled(false)
            .set_statistics_enabled(EnabledStatistics::None)
            .build(),
    );
    let file = fs::File::create(&path).unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
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
    let click_lo = ws - WEEK_MS; // R-T8

    // --- products.csv: product_id -> category index (R-E7) ----------------------
    let mut cat_names: Vec<S> = Vec::new();
    let mut cat_index: HashMap<S, u16> = HashMap::new();
    let mut products: HashMap<S, u16> = HashMap::new();
    for chunk in load_chunks(&data.join("products.csv")) {
        for_each_line(chunk, |line| {
            if let Some([pid, cat]) = split_fields::<2>(line) {
                if pid.is_empty() {
                    return;
                }
                let idx = *cat_index.entry(cat).or_insert_with(|| {
                    cat_names.push(cat);
                    (cat_names.len() - 1) as u16
                });
                products.insert(pid, idx);
            }
        });
    }
    let cat_unknown = cat_names.len() as u16;
    cat_names.push(b"unknown");
    let ncat = cat_names.len();

    // --- campaigns.csv: campaign_id -> dense index, channel ----------------------
    let mut camp_ids: Vec<S> = Vec::new();
    let mut camp_channels: Vec<S> = Vec::new();
    let mut campaigns: HashMap<S, u16> = HashMap::new();
    for chunk in load_chunks(&data.join("campaigns.csv")) {
        for_each_line(chunk, |line| {
            if let Some([cid, channel]) = split_fields::<2>(line) {
                if cid.is_empty() || campaigns.contains_key(cid) {
                    return;
                }
                campaigns.insert(cid, camp_ids.len() as u16);
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
            let mut v = Vec::new();
            for_each_line(chunk, |line| {
                if let Some([a, b]) = split_fields::<2>(line) {
                    if !a.is_empty() && !b.is_empty() {
                        v.push((interner.intern(a), interner.intern(b))); // R-L1
                    }
                }
            });
            v
        })
        .collect();
    let link_space = interner.id_space();
    let link_strs = interner.strings();
    let mut parent: Vec<u32> = (0..link_space as u32).collect();
    for &(a, b) in &link_pairs {
        let ra = uf_find(&mut parent, a);
        let rb = uf_find(&mut parent, b);
        if ra != rb {
            parent[ra.max(rb) as usize] = ra.min(rb); // R-L2
        }
    }
    // best[root] = id whose string is the byte-wise smallest in the component (R-L3).
    let mut best: Vec<u32> = (0..link_space as u32).collect();
    for i in 0..link_space as u32 {
        if link_strs[i as usize].is_empty() {
            continue; // id not used by any link
        }
        let r = uf_find(&mut parent, i) as usize;
        if link_strs[i as usize] < link_strs[best[r] as usize] || link_strs[best[r] as usize].is_empty() {
            best[r] = i;
        }
    }
    // canon[id] = the id that names the person. IDs outside the links are their own person (R-L4).
    let canon: Vec<u32> = (0..link_space as u32)
        .map(|i| if link_strs[i as usize].is_empty() { i } else { best[uf_find(&mut parent, i) as usize] })
        .collect();
    drop(parent);
    drop(best);
    let person_of = |uid: u32| -> u32 { canon.get(uid as usize).copied().unwrap_or(uid) };
    clock.log(&format!("links: {} pairs", link_pairs.len()));

    // --- events: parse (R-E1), validate each copy (R-E3, R-E4) ---------------------
    let event_parts: Vec<Vec<Vec<ERec>>> = load_chunks(&data.join("events"))
        .into_par_iter()
        .map(|chunk| {
            let mut buckets: Vec<Vec<ERec>> = (0..NSHARD).map(|_| Vec::new()).collect();
            for_each_line(chunk, |line| {
                let Some(f) = split_fields::<7>(line) else { return };
                let eid = f[0];
                if eid.is_empty() {
                    return; // R-E1
                }
                let hash = hash_bytes(eid);
                let ingest = parse_ts(f[3]); // R-T10
                let mut r = ERec {
                    hash,
                    eid,
                    ingest: ingest.unwrap_or(i64::MAX),
                    ts: 0,
                    uid: 0,
                    price: 0,
                    cat: 0,
                    typ: 0,
                    valid: false,
                };
                'validate: {
                    let Some(ingest) = ingest else { break 'validate };
                    if f[1].is_empty() || f[5].is_empty() {
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
                    r.ts = ts;
                    r.typ = typ;
                    r.price = price;
                    r.cat = products.get(f[5]).copied().unwrap_or(cat_unknown);
                    r.uid = interner.intern(f[1]);
                    r.valid = true;
                }
                buckets[shard_of(hash)].push(r);
            });
            buckets
        })
        .collect();
    clock.log(&format!(
        "events parsed: {} well-formed lines",
        event_parts.iter().flatten().map(|b| b.len()).sum::<usize>()
    ));

    // --- R-E2: dedup on event_id BEFORE validation, keep the smallest ingest_ts ------
    let mut events: Vec<Ev> = (0..NSHARD)
        .into_par_iter()
        .flat_map_iter(|s| {
            let n: usize = event_parts.iter().map(|p| p[s].len()).sum();
            let mut table: HashTable<ERec> = HashTable::with_capacity(n);
            for part in &event_parts {
                for r in &part[s] {
                    match table.entry(r.hash, |e| e.hash == r.hash && e.eid == r.eid, |e| e.hash) {
                        Entry::Occupied(mut o) => {
                            if r.ingest < o.get().ingest {
                                *o.get_mut() = *r;
                            }
                        }
                        Entry::Vacant(v) => {
                            v.insert(*r);
                        }
                    }
                }
            }
            table
                .into_iter()
                .filter(|r| r.valid)
                .map(|r| Ev { person: person_of(r.uid), ts: r.ts, price: r.price, cat: r.cat, typ: r.typ })
                .collect::<Vec<_>>()
        })
        .collect();
    drop(event_parts);
    clock.log(&format!("events: {} surviving", events.len()));

    // Sort by (person, ts). Ties in ts need no order: one pass decides the sessions (R-E5).
    events.par_sort_unstable_by_key(|e| (e.person, e.ts));
    clock.log("events sorted");

    // --- clicks: parse (R-K1), validate (R-K3), dedup (R-K2) -------------------------
    let click_parts: Vec<Vec<Vec<CRec>>> = load_chunks(&data.join("clicks"))
        .into_par_iter()
        .map(|chunk| {
            let mut buckets: Vec<Vec<CRec>> = (0..NSHARD).map(|_| Vec::new()).collect();
            for_each_line(chunk, |line| {
                let Some([cid, user, camp, ts]) = split_fields::<4>(line) else { return };
                if cid.is_empty() {
                    return; // R-K1
                }
                let hash = hash_bytes(cid);
                let mut r = CRec { hash, cid, ts: 0, uid: 0, camp: 0, valid: false };
                'validate: {
                    if user.is_empty() {
                        break 'validate;
                    }
                    let Some(t) = parse_ts(ts) else { break 'validate };
                    if t < click_lo || t >= we {
                        break 'validate; // R-T8
                    }
                    let Some(&c) = campaigns.get(camp) else { break 'validate }; // R-K3: exact match
                    r.ts = t;
                    r.camp = c;
                    r.uid = interner.intern(user);
                    r.valid = true;
                }
                buckets[shard_of(hash)].push(r);
            });
            buckets
        })
        .collect();
    let mut clicks: Vec<Click> = (0..NSHARD)
        .into_par_iter()
        .flat_map_iter(|s| {
            let n: usize = click_parts.iter().map(|p| p[s].len()).sum();
            let mut table: HashTable<CRec> = HashTable::with_capacity(n);
            for part in &click_parts {
                for r in &part[s] {
                    // R-K2: copies are identical, keep the first one seen.
                    if let Entry::Vacant(v) = table.entry(r.hash, |e| e.hash == r.hash && e.cid == r.cid, |e| e.hash) {
                        v.insert(*r);
                    }
                }
            }
            table
                .into_iter()
                .filter(|r| r.valid)
                .map(|r| Click { person: person_of(r.uid), ts: r.ts, cid: r.cid, camp: r.camp })
                .collect::<Vec<_>>()
        })
        .collect();
    drop(click_parts);
    // Per person by ts, and within a ts by click_id DESCENDING: the last click at or before a
    // session start is then the latest one with the smallest click_id (R-K4).
    clicks.par_sort_unstable_by(|a, b| a.person.cmp(&b.person).then(a.ts.cmp(&b.ts)).then(b.cid.cmp(a.cid)));
    clock.log(&format!("clicks: {} valid, sorted", clicks.len()));

    // --- sessions, credit, assists, aggregation ------------------------------------
    let names = interner.strings();
    let day0 = ws.div_euclid(DAY_MS);
    let ndays = ((we - 1).div_euclid(DAY_MS) - day0 + 1).max(1) as usize;

    let mut c_sessions = vec![0i64; ncamp * ndays];
    let mut c_purchasing = vec![0i64; ncamp * ndays];
    let mut c_revenue = vec![0i64; ncamp * ndays];
    let mut c_assisted = vec![0i64; ncamp * ndays];

    let mut u_user: Vec<S> = Vec::new();
    let mut u_day: Vec<i32> = Vec::new();
    let mut u_sessions: Vec<i64> = Vec::new();
    let mut u_events: Vec<i64> = Vec::new();
    let mut u_revenue: Vec<i64> = Vec::new();
    let mut u_top: Vec<Option<S>> = Vec::new();

    // Sliding 7-day click window per person: how many clicks of each campaign are inside,
    // and the list of campaigns with at least one (R-K7).
    let mut win_count = vec![0u32; ncamp];
    let mut win_pos = vec![0u32; ncamp];
    let mut active: Vec<u16> = Vec::new();
    let mut cat_sum = vec![0i64; ncat];
    let mut total_sessions = 0u64;

    let n_events = events.len();
    let mut i = 0;
    let mut ci = 0;
    while i < n_events {
        let person = events[i].person;
        let mut j = i;
        while j < n_events && events[j].person == person {
            j += 1;
        }
        while ci < clicks.len() && clicks[ci].person < person {
            ci += 1;
        }
        let cs = ci;
        while ci < clicks.len() && clicks[ci].person == person {
            ci += 1;
        }
        let ev = &events[i..j];
        let pc = &clicks[cs..ci];
        i = j;

        let (mut lo, mut hi) = (0usize, 0usize);
        let mut cur_day: i64 = -1;
        let (mut d_sessions, mut d_events, mut d_revenue) = (0i64, 0i64, 0i64);

        let mut flush_day = |day: i64, sessions: i64, evs: i64, revenue: i64, cat_sum: &mut [i64]| {
            // R-O2: top_category = highest summed purchase price, tie -> byte-wise smallest name.
            let mut top: Option<usize> = None;
            for c in 0..ncat {
                if cat_sum[c] > 0 {
                    top = match top {
                        Some(t) if cat_sum[t] > cat_sum[c] || (cat_sum[t] == cat_sum[c] && cat_names[t] <= cat_names[c]) => {
                            Some(t)
                        }
                        _ => Some(c),
                    };
                }
            }
            cat_sum.fill(0);
            u_user.push(names[person as usize]);
            u_day.push((day0 + day) as i32);
            u_sessions.push(sessions);
            u_events.push(evs);
            u_revenue.push(revenue);
            u_top.push(top.map(|t| cat_names[t]));
        };

        let mut k = 0;
        while k < ev.len() {
            // R-E5: a session runs while the gap to the previous event is <= 30 min.
            let start = ev[k].ts;
            let day = start.div_euclid(DAY_MS) - day0; // R-E6
            if day != cur_day {
                if cur_day >= 0 {
                    flush_day(cur_day, d_sessions, d_events, d_revenue, &mut cat_sum);
                }
                cur_day = day;
                d_sessions = 0;
                d_events = 0;
                d_revenue = 0;
            }
            let mut prev = start;
            let (mut s_events, mut s_revenue, mut s_purchase) = (0i64, 0i64, false);
            while k < ev.len() && ev[k].ts - prev <= GAP_MS {
                let e = &ev[k];
                prev = e.ts;
                s_events += 1;
                if e.typ == T_PURCHASE {
                    s_revenue += e.price as i64;
                    s_purchase = true;
                    cat_sum[e.cat as usize] += e.price as i64;
                }
                k += 1;
            }
            d_sessions += 1;
            d_events += s_events;
            d_revenue += s_revenue;
            total_sessions += 1;

            // R-K4: clicks with start - 7d <= ts <= start.
            while hi < pc.len() && pc[hi].ts <= start {
                let c = pc[hi].camp as usize;
                win_count[c] += 1;
                if win_count[c] == 1 {
                    win_pos[c] = active.len() as u32;
                    active.push(c as u16);
                }
                hi += 1;
            }
            while lo < hi && pc[lo].ts < start - WEEK_MS {
                let c = pc[lo].camp as usize;
                win_count[c] -= 1;
                if win_count[c] == 0 {
                    let p = win_pos[c] as usize;
                    let last = active.pop().unwrap();
                    if last as usize != c {
                        active[p] = last;
                        win_pos[last as usize] = p as u32;
                    }
                }
                lo += 1;
            }
            let credited = if hi > lo { pc[hi - 1].camp as usize } else { organic }; // R-K5
            let cell = credited * ndays + day as usize;
            c_sessions[cell] += 1;
            c_purchasing[cell] += s_purchase as i64;
            c_revenue[cell] += s_revenue;
            for &c in &active {
                c_assisted[c as usize * ndays + day as usize] += 1; // R-K7
            }
        }
        if cur_day >= 0 {
            flush_day(cur_day, d_sessions, d_events, d_revenue, &mut cat_sum);
        }
        for &c in &active {
            win_count[c as usize] = 0;
        }
        active.clear();
    }
    clock.log(&format!("sessions: {total_sessions}, user_daily rows: {}", u_user.len()));

    // --- outputs (R-O) ---------------------------------------------------------------
    let n_user_rows = u_user.len();
    write_parquet(
        &out.join("user_daily"),
        "message user_daily {
            REQUIRED BYTE_ARRAY user_id (STRING);
            REQUIRED INT32 day (DATE);
            REQUIRED INT64 sessions;
            REQUIRED INT64 events;
            REQUIRED INT64 revenue_cents;
            OPTIONAL BYTE_ARRAY top_category (STRING);
        }",
        &[
            Col::Str(u_user),
            Col::Date(u_day),
            Col::I64(u_sessions),
            Col::I64(u_events),
            Col::I64(u_revenue),
            Col::OptStr(u_top),
        ],
        n_user_rows,
    );

    let (mut k_id, mut k_channel, mut k_day) = (Vec::new(), Vec::new(), Vec::new());
    let (mut k_sessions, mut k_purchasing, mut k_revenue, mut k_assisted) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for c in 0..ncamp {
        for d in 0..ndays {
            let cell = c * ndays + d;
            if c_sessions[cell] > 0 || c_assisted[cell] > 0 {
                // R-O3
                k_id.push(camp_ids[c]);
                k_channel.push(camp_channels[c]);
                k_day.push((day0 + d as i64) as i32);
                k_sessions.push(c_sessions[cell]);
                k_purchasing.push(c_purchasing[cell]);
                k_revenue.push(c_revenue[cell]);
                k_assisted.push(c_assisted[cell]);
            }
        }
    }
    let n_camp_rows = k_id.len();
    write_parquet(
        &out.join("campaign_daily"),
        "message campaign_daily {
            REQUIRED BYTE_ARRAY campaign_id (STRING);
            REQUIRED BYTE_ARRAY channel (STRING);
            REQUIRED INT32 day (DATE);
            REQUIRED INT64 sessions;
            REQUIRED INT64 purchasing_sessions;
            REQUIRED INT64 revenue_cents;
            REQUIRED INT64 assisted_sessions;
        }",
        &[
            Col::Str(k_id),
            Col::Str(k_channel),
            Col::Date(k_day),
            Col::I64(k_sessions),
            Col::I64(k_purchasing),
            Col::I64(k_revenue),
            Col::I64(k_assisted),
        ],
        n_camp_rows,
    );
    clock.log(&format!("written: {n_user_rows} user rows, {n_camp_rows} campaign rows"));
}
