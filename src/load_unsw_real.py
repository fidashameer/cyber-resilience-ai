"""
Loader for the REAL UNSW-NB15 dataset (raw connection-record CSVs), aggregated
into the same entity/5-minute-window schema the rest of this project expects
(FEATURE_COLUMNS in generate_dataset.py) -- so the anomaly engine, evaluator,
and orchestrator run against it completely unchanged.

WHERE THIS DATA CAME FROM AND WHAT'S MISSING:
The user supplied the full UNSW-NB15 dataset folder. Several files in it are
OneDrive placeholder stubs that never actually synced (`NUSW-NB15_features.csv`,
`UNSW_NB15_training-set.csv`, and `The UNSW-NB15 description.pdf` all exist only
as zero-byte "_Error.txt" stand-ins) -- notably the official column-name file
for the raw CSVs. The 49-column layout below is reconstructed from the
well-documented public schema for this dataset, NOT read from that missing
file, and cross-checked against the actual data: sbytes/spkts == smean and
dbytes/dpkts == dmean hold exactly for the first several rows under this
column assignment, which is a strong (not certain) consistency check. If you
have the real NUSW-NB15_features.csv, verify against it.

WHAT'S A DIRECT MAPPING VS. AN APPROXIMATION:
- entity_id = srcip, window = 5-minute bucket of `stime` -- direct, no guessing.
- packet/byte/port/ip counts -- direct aggregation of real fields.
- novel_peer_ratio -- computed properly from real srcip/dstip identities,
  tracked causally per entity exactly like the synthetic generator does.
- internal_dst_ratio -- APPROXIMATED as "destination is in 149.171.126.0/24",
  the documented static server/victim subnet in this testbed. This dataset's
  topology isn't a generic corporate internal/external split, so this is a
  dataset-specific proxy, not a general classifier.
- admin_proto_ratio -- APPROXIMATED as destination port in {22, 3389, 445}
  (ssh/RDP/SMB) or service label in {'ssh'}.
- failed_auth_count -- APPROXIMATED as count of connections with TCP state
  'RST' (reset/aborted) in the window. This dataset has no application-layer
  authentication log, so this is a rough proxy, weaker than the synthetic
  version's explicit brute-force signal -- said plainly, not glossed over.
- off_hours_flag -- derived from hour-of-day of `stime` (capture timezone not
  independently confirmed), thresholded at <6 or >=22.
- attack_type -- kept as this dataset's OWN categories (Generic, Exploits,
  Fuzzers, Reconnaissance, DoS, Backdoors, Analysis, Shellcode, Worms), NOT
  force-mapped onto the synthetic generator's 5 categories (port_scan,
  brute_force, dos, exfiltration, lateral_movement) -- those are a different,
  real taxonomy and pretending otherwise would be less honest, not more useful.
- severity ("loud"/"stealthy") is a synthetic-data-only construct; set to
  "n/a" here since UNSW-NB15 doesn't label attacks that way.
"""

import glob
import os

import numpy as np
import pandas as pd

RAW_COLUMNS = [
    "srcip", "sport", "dstip", "dsport", "proto", "state", "dur", "sbytes", "dbytes",
    "sttl", "dttl", "sloss", "dloss", "service", "sload", "dload", "spkts", "dpkts",
    "swin", "stcpb", "dtcpb", "dwin", "smean", "dmean", "trans_depth", "res_bdy_len",
    "sjit", "djit", "stime", "ltime", "sinpkt", "dinpkt", "tcprtt", "synack", "ackdat",
    "is_sm_ips_ports", "ct_state_ttl", "ct_flw_http_mthd", "is_ftp_login", "ct_ftp_cmd",
    "ct_srv_src", "ct_srv_dst", "ct_dst_ltm", "ct_src_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "attack_cat", "label",
]

WINDOW_SECONDS = 300  # 5 minutes, matching the synthetic generator's cadence
ADMIN_PORTS = {22, 3389, 445}
INTERNAL_PREFIX = "149.171.126."  # documented static server/victim subnet in this testbed


def _load_raw(csv_dir: str) -> pd.DataFrame:
    paths = sorted(glob.glob(os.path.join(csv_dir, "UNSW-NB15_*.csv")))
    paths = [p for p in paths if os.path.basename(p).split("_")[1].split(".")[0].isdigit()]
    if not paths:
        raise FileNotFoundError(f"No UNSW-NB15_<n>.csv files found under {csv_dir}")
    frames = [pd.read_csv(p, names=RAW_COLUMNS, encoding="utf-8-sig", low_memory=False) for p in paths]
    df = pd.concat(frames, ignore_index=True)
    df["label"] = df["label"].fillna(0).astype(int)
    df["attack_cat"] = df["attack_cat"].astype(str).str.strip().replace({"nan": "none", "": "none"})
    return df


def _window_aggregate(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["window_bucket"] = (df["stime"] // WINDOW_SECONDS) * WINDOW_SECONDS
    df["is_rst"] = (df["state"] == "RST").astype(int)
    df["is_admin"] = (df["dsport"].isin(ADMIN_PORTS) | (df["service"] == "ssh")).astype(int)
    df["is_internal_dst"] = df["dstip"].astype(str).str.startswith(INTERNAL_PREFIX).astype(int)
    df["hour"] = pd.to_datetime(df["stime"], unit="s").dt.hour
    df["is_off_hours"] = ((df["hour"] < 6) | (df["hour"] >= 22)).astype(int)
    df["total_pkts"] = df["spkts"] + df["dpkts"]
    df["total_bytes"] = df["sbytes"] + df["dbytes"]

    grouped = df.groupby(["srcip", "window_bucket"], sort=True)

    agg = grouped.agg(
        duration_s=("dur", "mean"),
        packet_count=("total_pkts", "sum"),
        src_bytes=("sbytes", "sum"),
        dst_bytes=("dbytes", "sum"),
        unique_dst_ports=("dsport", "nunique"),
        unique_dst_ips=("dstip", "nunique"),
        failed_auth_count=("is_rst", "sum"),
        avg_off_hours=("is_off_hours", "mean"),
        internal_dst_ratio=("is_internal_dst", "mean"),
        admin_proto_ratio=("is_admin", "mean"),
        total_bytes=("total_bytes", "sum"),
        n_conns=("dur", "size"),
        max_label=("label", "max"),
    ).reset_index()

    agg["conn_rate_per_min"] = agg["n_conns"] / (WINDOW_SECONDS / 60)
    agg["avg_packet_size"] = agg["total_bytes"] / agg["packet_count"].replace(0, 1)
    agg["off_hours_flag"] = (agg["avg_off_hours"] >= 0.5).astype(int)
    agg["label"] = agg["max_label"]
    agg["window_start"] = pd.to_datetime(agg["window_bucket"], unit="s")
    agg["entity_id"] = agg["srcip"]

    # dominant attack category per window, for labeled (attack) windows only
    attack_rows = df[df["label"] == 1]
    if len(attack_rows):
        cat_mode = (
            attack_rows.groupby(["srcip", "window_bucket"])["attack_cat"]
            .agg(lambda s: s.value_counts().idxmax())
            .reset_index()
            .rename(columns={"attack_cat": "attack_type"})
        )
        agg = agg.merge(cat_mode, on=["srcip", "window_bucket"], how="left")
    else:
        agg["attack_type"] = "none"
    agg["attack_type"] = agg["attack_type"].fillna("none")
    agg["severity"] = "n/a"  # not a concept in this dataset's labels

    return agg


def _add_novel_peer_ratio(df: pd.DataFrame, raw: pd.DataFrame) -> pd.DataFrame:
    """Causal peer-novelty: for each (entity, window), what fraction of this
    window's distinct destination IPs has this entity never contacted in any
    STRICTLY EARLIER window. Processed in time order per entity -- no leakage.
    """
    dst_by_group = (
        raw.groupby(["srcip", (raw["stime"] // WINDOW_SECONDS) * WINDOW_SECONDS])["dstip"]
        .apply(lambda s: set(s))
    )
    dst_by_group.index.set_names(["srcip", "window_bucket"], inplace=True)

    ratios = {}
    for entity, sub in df.sort_values("window_bucket").groupby("srcip"):
        seen = set()
        for _, row in sub.iterrows():
            key = (entity, row["window_bucket"])
            dst_ips = dst_by_group.get(key, set())
            novel = dst_ips - seen
            ratio = len(novel) / max(len(dst_ips), 1)
            ratios[key] = ratio
            seen |= dst_ips

    df["novel_peer_ratio"] = [ratios[(r.srcip, r.window_bucket)] for r in df.itertuples()]
    return df


def build_real_dataset(csv_dir: str) -> pd.DataFrame:
    raw = _load_raw(csv_dir)
    windows = _window_aggregate(raw)
    windows = _add_novel_peer_ratio(windows, raw)

    from generate_dataset import FEATURE_COLUMNS
    keep = ["entity_id", "window_start", "label", "attack_type", "severity"] + FEATURE_COLUMNS
    return windows[keep].sort_values(["entity_id", "window_start"]).reset_index(drop=True)


if __name__ == "__main__":
    CSV_DIR = "/sessions/serene-friendly-newton/mnt/OneDrive_2026-07-16/UNSW-NB15 dataset/CSV Files"
    OUT_PATH = "/sessions/serene-friendly-newton/mnt/outputs/cyber-resilience-ai/data/network_windows_real.csv"

    df = build_real_dataset(CSV_DIR)
    df.to_csv(OUT_PATH, index=False)
    print(f"Wrote {len(df)} real-data windows ({df['label'].sum()} attack windows, "
          f"{df['label'].mean()*100:.2f}% positive rate) to {OUT_PATH}")
    print(df["attack_type"].value_counts())
