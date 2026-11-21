#!/usr/bin/env python3
"""
Shopping Sessions, Track A: DuckDB pipeline.

All parsing and logic run in DuckDB SQL. Python is only glue, plus the
union-find for linked IDs (scipy connected_components, C speed).
Rule IDs refer to RULES_DIGEST.md; rules.md is authoritative.

Reads  $DATA_DIR, writes $OUTPUT_DIR/{user_daily,campaign_daily}/ as Parquet,
temp files under $SCRATCH_DIR. Logs go to stderr only.
"""
import json
import os
import resource
import sys
import time
from datetime import datetime, timezone

import duckdb
import numpy as np
from scipy.sparse import coo_matrix
from scipy.sparse.csgraph import connected_components

T0 = time.time()
_T_LAST = [T0]


def peak_rss_gb():
    r = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return r / (1 << 30) if sys.platform == "darwin" else r / (1 << 20)  # bytes on macOS, KiB on Linux


def log(msg):
    now = time.time()
    print(f"[{now - T0:7.2f}s +{now - _T_LAST[0]:6.2f}s rss_peak={peak_rss_gb():5.2f}GB] {msg}",
          file=sys.stderr, flush=True)
    _T_LAST[0] = now


DATA = os.environ.get("DATA_DIR", "/data")
OUT = os.environ.get("OUTPUT_DIR", "/output")
SCRATCH = os.environ.get("SCRATCH_DIR", "/scratch")
NCPU = int(os.environ.get("NCPU", os.cpu_count() or 1))
MEM_GB = int(os.environ.get("MEM_GB", "8"))

DAY_MS = 86_400_000
GAP_MS = 1_800_000              # R-E5
LATE_MS = DAY_MS                # R-E4
CLICK_LOOKBACK_MS = 7 * DAY_MS  # R-T8, R-K4

con = duckdb.connect()
con.execute(f"SET threads = {NCPU}")
con.execute(f"SET memory_limit = '{max(1, int(MEM_GB * 0.75))}GB'")
con.execute(f"SET temp_directory = '{os.path.join(SCRATCH, 'duckdb_tmp')}'")
con.execute("SET preserve_insertion_order = false")


def sql_str(s):
    return "'" + s.replace("'", "''") + "'"


def iso_to_ms(s):
    # manifest.json is trusted input in F1 form.
    return int(datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()) * 1000


def count(table):
    return con.execute(f"SELECT count(*) FROM {table}").fetchone()[0]


with open(os.path.join(DATA, "manifest.json")) as f:
    manifest = json.load(f)
WS = iso_to_ms(manifest["window_start"])  # R-T9
WE = iso_to_ms(manifest["window_end"])
log(f"window {manifest['window_start']} .. {manifest['window_end']}")

# ---------------------------------------------------------------------------
# Macros
# ---------------------------------------------------------------------------
con.execute(r"""
-- R-C5/R-C6: strip the wrapping quotes; an empty field (quoted or not) is NULL.
CREATE MACRO uq(x) AS nullif(CASE WHEN x[1] = '"' THEN x[2:-2] ELSE x END, '');

-- R-C7: a field is either fully wrapped in quotes or holds no quote at all.
CREATE MACRO field_ok(x) AS regexp_full_match(x, '"[^"]*"|[^"]*');

-- Civil date -> days since 1970-01-01 (Hinnant's days_from_civil), pure integer math.
CREATE MACRO civil_days(y, m, d) AS (
    ((y - (m <= 2)::INT) // 400) * 146097
    + ((y - (m <= 2)::INT) % 400) * 365
    + ((y - (m <= 2)::INT) % 400) // 4
    - ((y - (m <= 2)::INT) % 400) // 100
    + (153 * (CASE WHEN m > 2 THEN m - 3 ELSE m + 9 END) + 2) // 5
    + d - 1 - 719468
);

CREATE MACRO is_leap(y) AS ((y % 4 = 0 AND y % 100 <> 0) OR y % 400 = 0);

CREATE MACRO days_in_month(y, m) AS CASE
    WHEN m = 2 THEN CASE WHEN is_leap(y) THEN 29 ELSE 28 END
    WHEN m IN (4, 6, 9, 11) THEN 30
    ELSE 31 END;

-- R-T1/R-T2 with explicit range checks (R-T5). Called only after the shape regex matched.
CREATE MACRO f12_ms(y, mo, d, h, mi, s, z) AS CASE
    WHEN mo BETWEEN 1 AND 12
     AND d BETWEEN 1 AND days_in_month(y, mo)
     AND h <= 23 AND mi <= 59 AND s <= 59
     AND (z = 'Z' OR (TRY_CAST(z[2:3] AS INT) <= 23 AND TRY_CAST(z[5:6] AS INT) <= 59))
    THEN (civil_days(y, mo, d)::BIGINT * 86400 + h * 3600 + mi * 60 + s
          - CASE WHEN z = 'Z' THEN 0
                 ELSE (CASE WHEN z[1] = '-' THEN -1 ELSE 1 END)
                      * (TRY_CAST(z[2:3] AS INT) * 3600 + TRY_CAST(z[5:6] AS INT) * 60) END
         ) * 1000
    END;

-- R-T1..R-T6: timestamp string -> epoch ms, or NULL when bad. Digits are ASCII [0-9] only (R-C9).
CREATE MACRO ts_ms(t) AS CASE
    WHEN t IS NULL THEN NULL
    -- R-T3/R-T6: F3 digits only, leading zeros fine; > 18 significant digits is never in a window.
    WHEN regexp_full_match(t, '[0-9]+') THEN CASE
        WHEN length(ltrim(t, '0')) = 0 THEN 0::BIGINT
        WHEN length(ltrim(t, '0')) <= 18 THEN ltrim(t, '0')::BIGINT
        ELSE NULL END
    WHEN regexp_full_match(t, '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(Z|[+-][0-9]{2}:[0-9]{2})')
    THEN f12_ms(t[1:4]::INT, t[6:7]::INT, t[9:10]::INT,
                t[12:13]::INT, t[15:16]::INT, t[18:19]::INT, t[20:])
    ELSE NULL END;
""")


def load_lines(subdir, nfields, name):
    """R-C1..R-C7: every *.csv in DATA/subdir as raw lines, header skipped by position,
    split on every comma, malformed lines dropped. Creates table `name` with column p VARCHAR[]."""
    path = os.path.join(DATA, subdir)
    if os.path.isdir(path):
        files = sorted(os.path.join(path, f) for f in os.listdir(path) if f.endswith(".csv"))
    else:
        files = [path] if os.path.isfile(path) else []
    if not files:
        con.execute(f"CREATE TABLE {name} (p VARCHAR[])")
        return
    file_list = "[" + ",".join(sql_str(f) for f in files) + "]"
    con.execute(f"""
        CREATE TABLE {name} AS
        WITH f AS (SELECT string_split(content, chr(10)) AS ls FROM read_text({file_list})),  -- R-C3: only \\n ends a line
             l AS (SELECT unnest(ls[2:]) AS line FROM f)                                        -- R-C2: skip line 1 by position
        SELECT p FROM (SELECT string_split(line, ',') AS p FROM l WHERE line <> '')            -- R-C7: empty line is malformed
        WHERE len(p) = {nfields}                                                                -- R-C4/R-C7: exact field count
          AND list_bool_and(list_transform(p, x -> field_ok(x)))                                -- R-C7: quotes only around a whole field
    """)
    log(f"read {subdir}: {len(files)} files, {count(name)} well-formed lines")


# ---------------------------------------------------------------------------
# Small clean tables
# ---------------------------------------------------------------------------
load_lines("products.csv", 2, "products_raw")
con.execute("CREATE TABLE products AS SELECT uq(p[1]) AS product_id, uq(p[2]) AS category FROM products_raw")
load_lines("campaigns.csv", 2, "campaigns_raw")
con.execute("CREATE TABLE campaigns AS SELECT uq(p[1]) AS campaign_id, uq(p[2]) AS channel FROM campaigns_raw")

# ---------------------------------------------------------------------------
# Linked IDs (R-L)
# ---------------------------------------------------------------------------
load_lines("links", 2, "links_raw")
con.execute("""
    CREATE TABLE links AS
    SELECT a, b FROM (SELECT uq(p[1]) AS a, uq(p[2]) AS b FROM links_raw)
    WHERE a IS NOT NULL AND b IS NOT NULL                 -- R-L1
""")
# Integer-encode IDs in byte-wise order, so the smallest index in a component is the
# byte-wise smallest ID (R-L3). DuckDB's default VARCHAR ordering is byte-wise.
con.execute("""
    CREATE TABLE link_ids AS
    SELECT id, (row_number() OVER (ORDER BY id) - 1)::BIGINT AS n
    FROM (SELECT a AS id FROM links UNION SELECT b FROM links)
""")
n_ids = count("link_ids")
edges = con.execute("""
    SELECT x.n AS a, y.n AS b
    FROM links JOIN link_ids x ON links.a = x.id JOIN link_ids y ON links.b = y.id
""").fetchnumpy()
if n_ids:
    g = coo_matrix((np.ones(len(edges["a"]), dtype=np.int8), (edges["a"], edges["b"])), shape=(n_ids, n_ids))
    ncomp, labels = connected_components(g, directed=False)  # R-L2: transitive, either direction
    root = np.full(ncomp, n_ids, dtype=np.int64)
    np.minimum.at(root, labels, np.arange(n_ids, dtype=np.int64))
    person_n = root[labels]
else:
    person_n = np.zeros(0, dtype=np.int64)
con.register("uf", {"n": np.arange(n_ids, dtype=np.int64), "pn": person_n})
con.execute("""
    CREATE TABLE id_person AS
    SELECT i.id, p.id AS person
    FROM link_ids i JOIN uf ON i.n = uf.n JOIN link_ids p ON p.n = uf.pn
""")
con.unregister("uf")
log(f"links: {n_ids} linked ids")

# ---------------------------------------------------------------------------
# Events (R-E)
# ---------------------------------------------------------------------------
load_lines("events", 7, "events_raw")
con.execute(f"""
    CREATE TABLE events AS
    WITH parsed AS (
        SELECT uq(p[1]) AS event_id, uq(p[2]) AS user_id, uq(p[3]) AS ts_raw, uq(p[4]) AS ingest_raw,
               uq(p[5]) AS event_type, uq(p[6]) AS product_id, uq(p[7]) AS price_raw
        FROM events_raw
    ),
    kept AS (                                                  -- R-E2: dedup BEFORE validation, smallest ingest_ts
        SELECT *, ts_ms(ingest_raw) AS ingest_ms               -- R-T10
        FROM parsed
        WHERE event_id IS NOT NULL                             -- R-E1
        QUALIFY row_number() OVER (PARTITION BY event_id ORDER BY ingest_ms) = 1
    ),
    typed AS (
        SELECT *, ts_ms(ts_raw) AS ts,
               CASE WHEN regexp_full_match(price_raw, '[0-9]+') AND length(ltrim(price_raw, '0')) <= 8
                    THEN coalesce(nullif(ltrim(price_raw, '0'), ''), '0')::BIGINT END AS price_val
        FROM kept
    )
    SELECT coalesce(ip.person, t.user_id) AS person,           -- R-L4/R-L6
           t.ts, t.event_type,
           CASE WHEN t.event_type = 'purchase' THEN t.price_val ELSE 0 END AS price,
           coalesce(pr.category, 'unknown') AS category        -- R-E7
    FROM typed t
    LEFT JOIN id_person ip ON ip.id = t.user_id
    LEFT JOIN products pr ON pr.product_id = t.product_id
    WHERE t.user_id IS NOT NULL                                -- R-E3
      AND t.ts IS NOT NULL AND t.ts >= {WS} AND t.ts < {WE}    -- R-E3, R-T7
      AND t.event_type IN ('view', 'cart', 'purchase')         -- R-E3: exact, case-sensitive
      AND t.product_id IS NOT NULL
      AND (t.event_type <> 'purchase' OR t.price_val BETWEEN 1 AND 10000000)
      AND t.ingest_ms - t.ts <= {LATE_MS}                      -- R-E4: exactly 24h kept, ingest < ts kept
""")
log(f"events: {count('events')} surviving")

# R-E5: sessionize per person. The gap is measured between DISTINCT timestamps, so the
# windows run over distinct (person, ts): the order is then strict and the result cannot
# depend on how a parallel sort happens to order tied events (E16). Two separate window
# passes over the raw events could order ties differently and put a tied event into the
# previous session.
con.execute(f"""
    CREATE TABLE ev_sess AS
    WITH d AS (SELECT DISTINCT person, ts FROM events),
    g AS (SELECT person, ts, lag(ts) OVER (PARTITION BY person ORDER BY ts) AS prev FROM d),
    s AS (
        SELECT person, ts,
               max(CASE WHEN prev IS NULL OR ts - prev > {GAP_MS} THEN ts END)
                   OVER (PARTITION BY person ORDER BY ts ROWS UNBOUNDED PRECEDING) AS start
        FROM g
    )
    SELECT e.person, e.price, e.event_type, e.category, s.start
    FROM events e JOIN s ON s.person = e.person AND s.ts = e.ts
""")
con.execute("""
    CREATE TABLE sessions AS
    SELECT person, start,
           (epoch_ms(start))::DATE AS day,                     -- R-E6
           count(*) AS n_events,
           sum(price) AS revenue,
           bool_or(event_type = 'purchase') AS has_purchase
    FROM ev_sess GROUP BY person, start
""")
log(f"sessions: {count('sessions')}")

# ---------------------------------------------------------------------------
# Clicks (R-K)
# ---------------------------------------------------------------------------
load_lines("clicks", 4, "clicks_raw")
con.execute(f"""
    CREATE TABLE clicks AS
    WITH c AS (
        SELECT uq(p[1]) AS click_id, uq(p[2]) AS user_id, uq(p[3]) AS campaign_id, uq(p[4]) AS ts_raw
        FROM clicks_raw
    ),
    d AS (                                                     -- R-K1, R-K2: copies identical, keep any
        SELECT click_id, any_value(user_id) AS user_id, any_value(campaign_id) AS campaign_id,
               any_value(ts_raw) AS ts_raw
        FROM c WHERE click_id IS NOT NULL GROUP BY click_id
    ),
    v AS (SELECT *, ts_ms(ts_raw) AS ts FROM d)
    SELECT v.click_id, coalesce(ip.person, v.user_id) AS person, v.campaign_id, v.ts
    FROM v
    JOIN campaigns cp ON cp.campaign_id = v.campaign_id        -- R-K3: exact match
    LEFT JOIN id_person ip ON ip.id = v.user_id
    WHERE v.user_id IS NOT NULL
      AND v.ts IS NOT NULL AND v.ts >= {WS - CLICK_LOOKBACK_MS} AND v.ts < {WE}   -- R-T8
""")
log(f"clicks: {count('clicks')} valid")

# R-K4/R-K7: candidate clicks per session, start - 7d <= click.ts <= start.
# TODO(speed): plain range join. Whale and shared-device persons make it quadratic;
# replace with a per-person sliding window over ts-sorted clicks.
con.execute(f"""
    CREATE TABLE cand AS
    SELECT s.person, s.start, s.day, c.click_id, c.campaign_id, c.ts
    FROM sessions s JOIN clicks c
      ON c.person = s.person AND c.ts <= s.start AND c.ts >= s.start - {CLICK_LOOKBACK_MS}
""")
con.execute("""
    CREATE TABLE credit AS
    SELECT s.day, s.revenue, s.has_purchase,
           coalesce(k.campaign_id, 'organic') AS campaign_id   -- R-K5
    FROM sessions s LEFT JOIN (
        SELECT person, start,
               first(campaign_id ORDER BY ts DESC, click_id ASC) AS campaign_id  -- R-K4: latest, tie smallest click_id
        FROM cand GROUP BY person, start
    ) k USING (person, start)
""")
log(f"candidate clicks: {count('cand')}")

# ---------------------------------------------------------------------------
# Outputs (R-O)
# ---------------------------------------------------------------------------
ud_dir = os.path.join(OUT, "user_daily")
cd_dir = os.path.join(OUT, "campaign_daily")
os.makedirs(ud_dir, exist_ok=True)
os.makedirs(cd_dir, exist_ok=True)

con.execute(f"""
    COPY (
        WITH sd AS (
            SELECT person, day, count(*) AS sessions, sum(n_events) AS events, sum(revenue) AS revenue_cents
            FROM sessions GROUP BY person, day
        ),
        cat AS (                                               -- R-O2: top_category, tie -> byte-wise smallest
            SELECT person, day, first(category ORDER BY rev DESC, category ASC) AS top_category
            FROM (
                SELECT e.person, (epoch_ms(e.start))::DATE AS day, e.category, sum(e.price) AS rev
                FROM ev_sess e WHERE e.event_type = 'purchase'
                GROUP BY ALL
            ) GROUP BY person, day
        )
        SELECT sd.person AS user_id, sd.day, sd.sessions::BIGINT AS sessions, sd.events::BIGINT AS events,
               sd.revenue_cents::BIGINT AS revenue_cents, cat.top_category
        FROM sd LEFT JOIN cat USING (person, day)
    ) TO '{os.path.join(ud_dir, "part-0.parquet")}' (FORMAT parquet)
""")

con.execute(f"""
    COPY (
        WITH cr AS (                                           -- R-O3: credited columns
            SELECT campaign_id, day, count(*) AS sessions,
                   count(*) FILTER (WHERE has_purchase) AS purchasing_sessions,
                   sum(revenue) AS revenue_cents
            FROM credit GROUP BY campaign_id, day
        ),
        asst AS (                                              -- R-K7: each campaign assists a session once
            SELECT campaign_id, day, count(*) AS assisted_sessions
            FROM (SELECT DISTINCT person, start, day, campaign_id FROM cand)
            GROUP BY campaign_id, day
        )
        SELECT campaign_id,
               CASE WHEN campaign_id = 'organic' THEN 'organic' ELSE cp.channel END AS channel,
               day,
               coalesce(cr.sessions, 0)::BIGINT AS sessions,
               coalesce(cr.purchasing_sessions, 0)::BIGINT AS purchasing_sessions,
               coalesce(cr.revenue_cents, 0)::BIGINT AS revenue_cents,
               coalesce(asst.assisted_sessions, 0)::BIGINT AS assisted_sessions
        FROM cr FULL OUTER JOIN asst USING (campaign_id, day)
        LEFT JOIN campaigns cp USING (campaign_id)
    ) TO '{os.path.join(cd_dir, "part-0.parquet")}' (FORMAT parquet)
""")
log("done")
