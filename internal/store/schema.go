// Package store persists everything WARP learns.
//
// sqlite is authoritative; the flat CSV files are regenerated projections kept only for
// interoperability with other tools. All writers go through this package.
//
// The central schema decision is that **observations and conclusions live in different
// tables**. A report must be able to show the evidence independently of the label, and a
// classification that turns out to be wrong must be correctable without touching a single
// observed fact. Nothing in the aps or observations tables says whether a device is the
// client's, a neighbour's, or an impostor.
package store

// schema is applied at open. Every statement is idempotent so reopening an engagement
// directory mid-run is safe.
const schema = `
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- Observed access points. Every column here is a fact read off the air.
CREATE TABLE IF NOT EXISTS aps (
    bssid            TEXT PRIMARY KEY,
    essid            TEXT NOT NULL DEFAULT '',
    hidden           INTEGER NOT NULL DEFAULT 0,
    essid_source     TEXT NOT NULL DEFAULT '',
    channel          INTEGER NOT NULL DEFAULT 0,
    freq             INTEGER NOT NULL DEFAULT 0,
    band             TEXT NOT NULL DEFAULT '',
    security_class   TEXT NOT NULL DEFAULT '',
    mfp              TEXT NOT NULL DEFAULT '',
    wps              INTEGER NOT NULL DEFAULT 0,
    wps_locked       INTEGER NOT NULL DEFAULT 0,
    ciphers          TEXT NOT NULL DEFAULT '',
    akms             TEXT NOT NULL DEFAULT '',
    transition_mode  INTEGER NOT NULL DEFAULT 0,
    -- The fingerprint is stored both as a hash (for cheap grouping) and in full (so a
    -- finding can name the specific attributes that differed).
    fingerprint_hash TEXT NOT NULL DEFAULT '',
    fingerprint      TEXT NOT NULL DEFAULT '',
    oui              TEXT NOT NULL DEFAULT '',
    local_mac        INTEGER NOT NULL DEFAULT 0,
    best_rssi        INTEGER,
    best_rssi_radio  TEXT NOT NULL DEFAULT '',
    last_rssi        INTEGER,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    beacons          INTEGER NOT NULL DEFAULT 0,
    probe_responses  INTEGER NOT NULL DEFAULT 0,
    data_frames      INTEGER NOT NULL DEFAULT 0,
    radios_seen      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS aps_essid ON aps(essid);
CREATE INDEX IF NOT EXISTS aps_last_seen ON aps(last_seen);

-- Observed client stations.
CREATE TABLE IF NOT EXISTS stations (
    mac           TEXT PRIMARY KEY,
    bssid         TEXT NOT NULL DEFAULT '',
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    best_rssi     INTEGER,
    last_rssi     INTEGER,
    randomised    INTEGER NOT NULL DEFAULT 0,
    oui           TEXT NOT NULL DEFAULT '',
    frames        INTEGER NOT NULL DEFAULT 0,
    probed_essids TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS stations_bssid ON stations(bssid);
CREATE INDEX IF NOT EXISTS stations_last_seen ON stations(last_seen);

-- Signal observations.
--
-- radio_id is mandatory. RSSI is not comparable across chipsets or antennas, so a query that
-- mixes radios produces a coverage picture that looks correct and is meaningless. Carrying
-- the radio on every row is what makes that enforceable at query time.
--
-- Walkthroughs are associated BY TIME RANGE, not by a label copied onto each row: the
-- operator will name one sloppily on site, and rename/split must be post-processing that
-- never touches observation data.
CREATE TABLE IF NOT EXISTS observations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    addr       TEXT NOT NULL,
    is_ap      INTEGER NOT NULL DEFAULT 0,
    rssi       INTEGER NOT NULL,
    freq       INTEGER NOT NULL DEFAULT 0,
    channel    INTEGER NOT NULL DEFAULT 0,
    ts         TEXT NOT NULL,
    radio_id   TEXT NOT NULL,
    frame_type TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS observations_addr_ts ON observations(addr, ts);
CREATE INDEX IF NOT EXISTS observations_ts ON observations(ts);
CREATE INDEX IF NOT EXISTS observations_radio ON observations(radio_id);

-- Walkthroughs are separate records associated with observations by time range.
CREATE TABLE IF NOT EXISTS walkthroughs (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT NOT NULL,
    start_ts TEXT NOT NULL,
    end_ts   TEXT,
    notes    TEXT NOT NULL DEFAULT '',
    -- implicit marks the walkthrough the daemon opens at startup so that every observation
    -- always has one, whether or not an operator ever declares any.
    implicit INTEGER NOT NULL DEFAULT 0,
    -- pcap_path is the per-walkthrough raw archive written for the span it was open, so a walk
    -- can be replayed in isolation from the engagement-wide capture. Empty until one is written.
    pcap_path TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS walkthroughs_start ON walkthroughs(start_ts);

-- Emitted hash lines, mirroring the flat 22000 files.
--
-- The flat files are the deliverable that goes to the cracking rig; this table exists so the
-- REPL can report counts and so a cracked result can be mapped back to a BSSID for the report.
CREATE TABLE IF NOT EXISTS hashes (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    kind     TEXT NOT NULL,
    line     TEXT NOT NULL UNIQUE,
    essid    TEXT NOT NULL,
    ap       TEXT NOT NULL,
    sta      TEXT NOT NULL,
    channel  INTEGER NOT NULL DEFAULT 0,
    radio_id TEXT NOT NULL DEFAULT '',
    detail   TEXT NOT NULL DEFAULT '',
    ts       TEXT NOT NULL,
    -- Whether the network this came from was in scope when it was captured.
    --
    -- Capture is passive, so WARP records every handshake it happens to hear, including from
    -- networks the engagement has no authority over. That material must never be mistaken for
    -- part of the deliverable: cracking a neighbour's handshake is unauthorized work, and a
    -- 22000 file has no comment syntax to mark a line with.
    in_scope INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS hashes_ap ON hashes(ap);

-- CONCLUSIONS. Deliberately a separate table from aps.
--
-- A finding references a BSSID but never modifies its observed record, so the evidence can
-- always be shown independently of the label, and a reclassification changes nothing about
-- what was seen.
CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    bssid       TEXT NOT NULL,
    essid       TEXT NOT NULL DEFAULT '',
    tier        TEXT NOT NULL,
    label       TEXT NOT NULL,
    rationale   TEXT NOT NULL DEFAULT '',
    -- differences carries the specific fingerprint attributes that diverged, so the report
    -- writes itself rather than citing an opaque score.
    differences TEXT NOT NULL DEFAULT '',
    score       REAL,
    first_ts    TEXT NOT NULL,
    last_ts     TEXT NOT NULL,
    UNIQUE(bssid, label)
);
CREATE INDEX IF NOT EXISTS findings_tier ON findings(tier);
CREATE INDEX IF NOT EXISTS findings_bssid ON findings(bssid);

-- Certificates harvested from enterprise networks (Phase 3).
CREATE TABLE IF NOT EXISTS certificates (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    essid        TEXT NOT NULL,
    bssid        TEXT NOT NULL DEFAULT '',
    subject      TEXT NOT NULL DEFAULT '',
    issuer       TEXT NOT NULL DEFAULT '',
    sans         TEXT NOT NULL DEFAULT '',
    not_before   TEXT NOT NULL DEFAULT '',
    not_after    TEXT NOT NULL DEFAULT '',
    serial       TEXT NOT NULL DEFAULT '',
    key_algo     TEXT NOT NULL DEFAULT '',
    key_bits     INTEGER NOT NULL DEFAULT 0,
    sig_algo     TEXT NOT NULL DEFAULT '',
    fingerprint  TEXT NOT NULL DEFAULT '',
    chain_pem    TEXT NOT NULL DEFAULT '',
    ts           TEXT NOT NULL,
    UNIQUE(fingerprint)
);

-- Credentials captured by the RADIUS/EAP server (Phase 3).
--
-- Inner and outer identity are stored separately: the difference (an anonymous outer
-- identity, i.e. identity privacy) is itself reportable.
CREATE TABLE IF NOT EXISTS credentials (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    essid          TEXT NOT NULL,
    outer_identity TEXT NOT NULL DEFAULT '',
    inner_identity TEXT NOT NULL DEFAULT '',
    method         TEXT NOT NULL DEFAULT '',
    hash_line      TEXT NOT NULL DEFAULT '',
    cleartext      TEXT NOT NULL DEFAULT '',
    sta            TEXT NOT NULL DEFAULT '',
    ts             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS credentials_essid ON credentials(essid);

-- Per-method negotiation outcomes. Which methods a supplicant accepts or rejects is itself
-- a finding, including when it rejects everything - that is a pass and must be recorded.
CREATE TABLE IF NOT EXISTS eap_attempts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    essid     TEXT NOT NULL,
    sta       TEXT NOT NULL DEFAULT '',
    method    TEXT NOT NULL,
    outcome   TEXT NOT NULL,
    detail    TEXT NOT NULL DEFAULT '',
    ts        TEXT NOT NULL
);
`
