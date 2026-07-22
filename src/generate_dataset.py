"""
Synthetic behavioral network-traffic dataset generator.

IMPORTANT / HONESTY NOTE:
This sandbox environment has no outbound access to Kaggle, UCI, HuggingFace,
or GitHub raw content, so the real CICIDS2017 / UNSW-NB15 benchmark CSVs could
not be downloaded here. This module generates a labeled, entity-level,
flow-aggregated dataset that mimics the feature families used in those real
benchmarks (duration, byte/packet counts, port/host fan-out, auth failures,
protocol mix, time-of-day) so the anomaly engine and its evaluation are
structurally realistic and swappable for real data later.

TO SWAP IN REAL DATA: replace `build_dataset()` with a loader that reads the
UNSW-NB15 or CICIDS2017 CSV (downloaded on your own machine) and maps its
columns onto the FEATURE_COLUMNS below. Everything downstream (engine, eval,
dashboard) reads a plain pandas DataFrame with those column names, so no other
code needs to change.
"""

import numpy as np
import pandas as pd

RNG = np.random.default_rng(42)

FEATURE_COLUMNS = [
    "duration_s",
    "packet_count",
    "src_bytes",
    "dst_bytes",
    "unique_dst_ports",
    "unique_dst_ips",
    "failed_auth_count",
    "conn_rate_per_min",
    "avg_packet_size",
    "off_hours_flag",
    "internal_dst_ratio",
    "admin_proto_ratio",
    "novel_peer_ratio",  # fraction of this window's destinations this entity has never contacted before
]

ENTITIES = [f"host-{i:03d}" for i in range(1, 61)]  # 60 monitored endpoints
N_WINDOWS_PER_ENTITY = 120  # ~10 hrs of 5-min windows per entity
ATTACK_FRACTION = 0.06  # ~6% of windows are attack windows, spread across types

ATTACK_TYPES = ["port_scan", "brute_force", "dos", "exfiltration", "lateral_movement"]


def _normal_window(entity_baseline):
    """One normal 5-minute traffic window for a given entity's baseline profile."""
    b = entity_baseline
    return {
        "duration_s": max(0.5, RNG.normal(b["duration"], b["duration"] * 0.25)),
        "packet_count": max(1, RNG.poisson(b["packets"])),
        "src_bytes": max(0, RNG.normal(b["src_bytes"], b["src_bytes"] * 0.3)),
        "dst_bytes": max(0, RNG.normal(b["dst_bytes"], b["dst_bytes"] * 0.3)),
        "unique_dst_ports": max(1, RNG.poisson(b["ports"])),
        "unique_dst_ips": max(1, RNG.poisson(b["ips"])),
        "failed_auth_count": RNG.poisson(0.05),
        "conn_rate_per_min": max(0.1, RNG.normal(b["conn_rate"], b["conn_rate"] * 0.2)),
        "avg_packet_size": max(40, RNG.normal(b["pkt_size"], 60)),
        "off_hours_flag": int(RNG.random() < 0.08),
        "internal_dst_ratio": float(np.clip(RNG.normal(b["internal_ratio"], 0.08), 0, 1)),
        "admin_proto_ratio": float(np.clip(RNG.normal(b["admin_ratio"], 0.03), 0, 0.5)),
    }


def _attack_window(attack_type, entity_baseline, stealthy=False):
    """One attack-window feature vector, fingerprinted by attack type.

    stealthy=True models the "low-and-slow" APT variant explicitly called out
    in the problem statement: parameters are dampened toward the entity's own
    baseline so the fingerprint is present but muted, which is what makes
    real APT detection hard and is what should suppress this engine's recall
    down from "perfect" to "strong but honest".
    """
    b = entity_baseline
    base = _normal_window(b)
    d = 0.35 if stealthy else 1.0  # damping factor toward baseline for stealthy variant

    if attack_type == "port_scan":
        base.update(
            unique_dst_ports=int(b["ports"] + d * (RNG.integers(80, 400) - b["ports"])),
            unique_dst_ips=int(b["ips"] + d * (RNG.integers(5, 40) - b["ips"])),
            duration_s=max(0.2, RNG.normal(3, 1) if not stealthy else RNG.normal(b["duration"] * 0.7, 2)),
            src_bytes=RNG.normal(200, 60),
            dst_bytes=RNG.normal(50, 20),
            conn_rate_per_min=b["conn_rate"] + d * (RNG.uniform(80, 300) - b["conn_rate"]),
            avg_packet_size=RNG.normal(64, 8) if not stealthy else RNG.normal(b["pkt_size"] * 0.6, 40),
        )
    elif attack_type == "brute_force":
        base.update(
            failed_auth_count=int(RNG.integers(25, 200) * d) + int(RNG.poisson(1)),
            unique_dst_ports=int(RNG.integers(1, 3)),
            admin_proto_ratio=float(b["admin_ratio"] + d * (RNG.uniform(0.6, 1.0) - b["admin_ratio"])),
            conn_rate_per_min=b["conn_rate"] + d * (RNG.uniform(20, 90) - b["conn_rate"]),
            duration_s=max(0.5, RNG.normal(2, 1)),
        )
    elif attack_type == "dos":
        base.update(
            packet_count=int(b["packets"] + d * (RNG.integers(5000, 40000) - b["packets"])),
            conn_rate_per_min=b["conn_rate"] + d * (RNG.uniform(300, 1200) - b["conn_rate"]),
            src_bytes=b["src_bytes"] + d * (RNG.normal(2_000_000, 500_000) - b["src_bytes"]),
            unique_dst_ips=int(RNG.integers(1, 2)),
            duration_s=max(1, RNG.normal(15, 5)),
        )
    elif attack_type == "exfiltration":
        base.update(
            dst_bytes=RNG.normal(150, 40),
            src_bytes=b["src_bytes"] + d * (RNG.normal(8_000_000, 2_000_000) - b["src_bytes"]),
            off_hours_flag=1 if not stealthy else int(RNG.random() < 0.5),
            internal_dst_ratio=float(b["internal_ratio"] + d * (RNG.uniform(0.0, 0.05) - b["internal_ratio"])),
            unique_dst_ips=int(RNG.integers(1, 2)),
            duration_s=max(30, b["duration"] + d * (RNG.normal(600, 200) - b["duration"])),
        )
    elif attack_type == "lateral_movement":
        base.update(
            internal_dst_ratio=float(b["internal_ratio"] + d * (RNG.uniform(0.9, 1.0) - b["internal_ratio"])),
            unique_dst_ips=int(b["ips"] + d * (RNG.integers(6, 25) - b["ips"])),
            admin_proto_ratio=float(b["admin_ratio"] + d * (RNG.uniform(0.7, 1.0) - b["admin_ratio"])),
            off_hours_flag=int(RNG.random() < 0.5),
            conn_rate_per_min=b["conn_rate"] + d * (RNG.uniform(15, 60) - b["conn_rate"]),
        )

    for k in ["duration_s", "packet_count", "src_bytes", "dst_bytes",
              "unique_dst_ports", "unique_dst_ips", "conn_rate_per_min", "avg_packet_size"]:
        if base[k] < 0:
            base[k] = abs(base[k])
    return base


def _noisy_normal_window(entity_baseline):
    """Benign-but-unusual window: legit backup job, patch night, big download,
    admin doing real maintenance. Superficially resembles an attack fingerprint
    but is not one -- this is what keeps precision honest (a model with zero
    false positives on data like this hasn't been tested hard enough)."""
    b = entity_baseline
    base = _normal_window(b)
    kind = RNG.choice(["big_transfer", "admin_night", "scan_like_saas", "burst_conns"])
    if kind == "big_transfer":
        base["src_bytes"] = RNG.normal(3_000_000, 800_000)
        base["duration_s"] = max(20, RNG.normal(180, 60))
        base["off_hours_flag"] = int(RNG.random() < 0.6)
    elif kind == "admin_night":
        base["admin_proto_ratio"] = float(RNG.uniform(0.4, 0.8))
        base["off_hours_flag"] = 1
        base["internal_dst_ratio"] = float(RNG.uniform(0.8, 1.0))
    elif kind == "scan_like_saas":
        # e.g. vulnerability scanner / SaaS health-checker legitimately hitting many ports
        base["unique_dst_ports"] = int(RNG.integers(15, 45))
        base["unique_dst_ips"] = int(RNG.integers(3, 10))
    elif kind == "burst_conns":
        base["conn_rate_per_min"] = RNG.uniform(30, 70)
        base["packet_count"] = int(RNG.poisson(b["packets"] * 3))
    for k in ["duration_s", "packet_count", "src_bytes", "dst_bytes",
              "unique_dst_ports", "unique_dst_ips", "conn_rate_per_min", "avg_packet_size"]:
        if base[k] < 0:
            base[k] = abs(base[k])
    return base


def _make_entity_baseline():
    return {
        "duration": RNG.uniform(2, 30),
        "packets": RNG.uniform(5, 60),
        "src_bytes": RNG.uniform(2_000, 40_000),
        "dst_bytes": RNG.uniform(2_000, 40_000),
        "ports": RNG.uniform(1, 4),
        "ips": RNG.uniform(1, 5),
        "conn_rate": RNG.uniform(1, 12),
        "pkt_size": RNG.uniform(300, 900),
        "internal_ratio": RNG.uniform(0.5, 0.95),
        "admin_ratio": RNG.uniform(0.0, 0.1),
    }


def _novel_peer_fraction(label, attack_type, severity):
    """What fraction of this window's destination identities should be drawn
    from OUTSIDE the entity's known peer pool -- i.e. hosts it's never talked
    to before. This is the graph/novelty signal that closes (part of) the
    stealthy-lateral-movement gap: an attacker moving between machines using
    valid credentials doesn't necessarily move enough *volume* to look
    anomalous, but reaching hosts this entity has never touched before is a
    much sparser, sharper signal than "internal traffic ratio went up a bit".
    """
    if label == 0:
        # legitimate slow growth of an entity's peer set (new teammate's laptop,
        # a server added to a cluster, etc.) -- small and usually near zero,
        # kept nonzero so the feature isn't a trivial "any novelty = attack" rule.
        return float(RNG.uniform(0, 0.05))
    if attack_type == "lateral_movement":
        return float(RNG.uniform(0.6, 0.95)) if severity == "loud" else float(RNG.uniform(0.25, 0.45))
    if attack_type == "port_scan":
        # scanning inherently reaches hosts/ports never contacted before
        return float(RNG.uniform(0.7, 0.95)) if severity == "loud" else float(RNG.uniform(0.4, 0.6))
    # brute_force / dos / exfiltration are characterized by other signals
    # (auth failures, volume, byte counts), not peer novelty -- keep this
    # feature at the same low baseline as normal traffic for those, rather
    # than artificially inflating recall on attack types it shouldn't help.
    return float(RNG.uniform(0, 0.05))


class _PeerIdentitySimulator:
    """Tracks, per entity, which destination identities have been seen before
    (causally -- only using windows strictly prior to the current one, so
    there's no label leakage), and generates novel_peer_ratio accordingly.
    """

    def __init__(self):
        self._next_id = 1_000_000  # global counter for "brand new" identities, never reused
        self._entity_pools = {}    # entity -> its normal/known peer id set
        self._seen = {}            # entity -> cumulative set of ids ever contacted

    def _fresh_ids(self, n):
        ids = list(range(self._next_id, self._next_id + n))
        self._next_id += n
        return ids

    def init_entity(self, entity, baseline):
        pool_size = max(8, int(baseline["ips"] * 4))
        pool = self._fresh_ids(pool_size)
        self._entity_pools[entity] = pool
        self._seen[entity] = set(pool)  # peers known since before monitoring started

    def novel_ratio_for_window(self, entity, unique_dst_ips, novel_fraction):
        count = max(1, int(round(unique_dst_ips)))
        n_novel = min(count, int(round(count * novel_fraction)))
        n_repeat = count - n_novel

        pool = self._entity_pools[entity]
        repeats = list(RNG.choice(pool, size=n_repeat, replace=True)) if n_repeat > 0 else []
        novel_ids = self._fresh_ids(n_novel)
        window_ips = repeats + novel_ids

        seen_before = self._seen[entity]
        actually_novel = sum(1 for ip in window_ips if ip not in seen_before)
        ratio = actually_novel / count

        seen_before.update(window_ips)  # update AFTER computing ratio -- causal, no leakage
        return ratio


def build_dataset(seed: int = 42) -> pd.DataFrame:
    global RNG
    RNG = np.random.default_rng(seed)

    peer_sim = _PeerIdentitySimulator()

    rows = []
    for entity in ENTITIES:
        baseline = _make_entity_baseline()
        peer_sim.init_entity(entity, baseline)
        n_attack_windows = int(N_WINDOWS_PER_ENTITY * ATTACK_FRACTION * RNG.uniform(0.4, 1.6))
        attack_indices = set(RNG.choice(N_WINDOWS_PER_ENTITY, size=min(n_attack_windows, N_WINDOWS_PER_ENTITY), replace=False))

        for w in range(N_WINDOWS_PER_ENTITY):
            ts = pd.Timestamp("2026-07-14 00:00:00") + pd.Timedelta(minutes=5 * w)
            if w in attack_indices:
                atype = RNG.choice(ATTACK_TYPES)
                stealthy = bool(RNG.random() < 0.45)  # ~45% of attacks are low-and-slow variants
                feats = _attack_window(atype, baseline, stealthy=stealthy)
                label, attack_type = 1, atype
                severity = "stealthy" if stealthy else "loud"
            elif RNG.random() < 0.05:
                # benign-but-unusual window (~5% of normal windows): keeps precision honest
                feats = _noisy_normal_window(baseline)
                label, attack_type, severity = 0, "none", "none"
            else:
                feats = _normal_window(baseline)
                label, attack_type, severity = 0, "none", "none"

            # Windows are processed in time order per entity (w increasing), so
            # this causally reflects only what's been seen in prior windows.
            novel_fraction = _novel_peer_fraction(label, attack_type, severity)
            feats["novel_peer_ratio"] = peer_sim.novel_ratio_for_window(
                entity, feats["unique_dst_ips"], novel_fraction
            )

            row = {"entity_id": entity, "window_start": ts, "label": label,
                   "attack_type": attack_type, "severity": severity}
            row.update(feats)
            rows.append(row)

    df = pd.DataFrame(rows)
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)  # shuffle window order per entity for realism
    df = df.sort_values(["entity_id", "window_start"]).reset_index(drop=True)
    return df


if __name__ == "__main__":
    df = build_dataset()
    out_path = "/sessions/serene-friendly-newton/mnt/outputs/cyber-resilience-ai/data/network_windows.csv"
    df.to_csv(out_path, index=False)
    print(f"Wrote {len(df)} rows ({df['label'].sum()} attack windows, "
          f"{df['label'].mean()*100:.2f}% positive rate) to {out_path}")
    print(df["attack_type"].value_counts())
