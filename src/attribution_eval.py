"""
Attribution accuracy evaluation -- closes a real gap: the hackathon's own
evaluation focus for this problem statement names "APT attribution accuracy
at MITRE ATT&CK technique level" as a judging signal, and until now this
project never actually measured it.

TWO METRICS, DIFFERENT HONEST SCOPES:

1. Tactic-level accuracy (both datasets could support this, only run on
   synthetic -- see below): does the top candidate's TACTIC match what an
   analyst would expect for the known attack type. A looser check.

2. Technique-level accuracy (SYNTHETIC ONLY, and this is the real answer to
   "why not measure technique-level directly"): it initially looked
   unmeasurable because no dataset has a red-team-verified ATT&CK
   technique-ID label per record. But that reasoning only holds for THIRD-
   PARTY data (real UNSW-NB15, where we didn't choose what technique each
   connection represents). For the SYNTHETIC data, that excuse doesn't
   apply -- generate_dataset.py's attack simulators were explicitly written
   to model specific named techniques (see EXPECTED_TECHNIQUE below, each
   one traceable to a specific block of simulation logic). That design
   intent IS a legitimate ground truth for the data we generated ourselves,
   so technique-level accuracy is measured directly against it.

   Where our simulator doesn't distinguish between sibling sub-techniques
   (e.g. it models "credential brute-forcing" in general, not specifically
   password-guessing vs. password-spraying), the expected label is the
   PARENT technique, and a retrieved sub-technique under that same parent
   counts as correct -- we're not claiming precision the simulator doesn't
   actually have.

Only run on the SYNTHETIC dataset for both metrics: the real UNSW-NB15
data's categories (Exploits, Fuzzers, Generic, ...) aren't ATT&CK labels at
all and don't map onto our curated KB's coverage cleanly enough to make
either check meaningful there -- forcing that mapping would look precise
without being honest.
"""

import json

import pandas as pd

from orchestrator import run_pipeline

DATA_PATH = "/sessions/serene-friendly-newton/mnt/outputs/cyber-resilience-ai/data/network_windows.csv"
OUT_PATH = "/sessions/serene-friendly-newton/mnt/outputs/cyber-resilience-ai/eval/attribution_accuracy.json"

# Which ATT&CK tactic(s) a competent analyst would expect for each known
# attack type. Multiple acceptable tactics reflect that real attacks
# genuinely span tactics (e.g. lateral movement techniques are tagged both
# "Lateral Movement" and sometimes "Discovery" as a precursor).
EXPECTED_TACTICS = {
    "port_scan": {"Reconnaissance", "Discovery"},
    "brute_force": {"Credential Access", "Defense Evasion, Persistence, Privilege Escalation, Initial Access"},
    "dos": {"Impact"},
    "exfiltration": {"Exfiltration"},
    "lateral_movement": {"Lateral Movement", "Discovery"},
}

# The SPECIFIC technique each attack simulator in generate_dataset.py was
# written to model -- this is our own design intent, used as ground truth
# only for the data we ourselves generated. Parent-level IDs where the
# simulator doesn't distinguish sub-techniques (see docstring).
EXPECTED_TECHNIQUE = {
    "port_scan": "T1595",         # Active Scanning -- high unique_dst_ports/ips, low bytes-per-conn
    "brute_force": "T1110",       # Brute Force (parent) -- high failed_auth_count; sub-technique not modeled
    "dos": "T1498",                # Network Denial of Service -- volume/rate against one dst, not endpoint-specific
    "exfiltration": "T1041",       # Exfiltration Over C2 Channel -- sustained outbound to one external host
    "lateral_movement": "T1021",   # Remote Services (parent) -- internal admin-protocol spread; protocol not modeled
}


def _tactic_matches(candidate_tactic: str, expected: set) -> bool:
    parts = {p.strip() for p in candidate_tactic.split(",")}
    return bool(parts & expected)


def _technique_matches(candidate_id: str, expected_id: str) -> bool:
    return candidate_id == expected_id or candidate_id.startswith(expected_id + ".")


def main():
    df = pd.read_csv(DATA_PATH)
    df["window_start"] = pd.to_datetime(df["window_start"])

    alerts, _ = run_pipeline(df, use_llm=False)  # attribution retrieval logic is LLM-independent
    true_positive_alerts = [a for a in alerts if a["true_label"] == 1 and a["true_attack_type"] in EXPECTED_TACTICS]

    tactic_top1, tactic_top3 = 0, 0
    tech_top1, tech_top3 = 0, 0
    per_type = {}
    for a in true_positive_alerts:
        atype = a["true_attack_type"]
        expected_tactics = EXPECTED_TACTICS[atype]
        expected_tech = EXPECTED_TECHNIQUE[atype]
        candidates = a["candidate_techniques"]

        tt1 = bool(candidates) and _tactic_matches(candidates[0]["tactic"], expected_tactics)
        tt3 = any(_tactic_matches(c["tactic"], expected_tactics) for c in candidates[:3])
        ct1 = bool(candidates) and _technique_matches(candidates[0]["id"], expected_tech)
        ct3 = any(_technique_matches(c["id"], expected_tech) for c in candidates[:3])

        tactic_top1 += int(tt1); tactic_top3 += int(tt3)
        tech_top1 += int(ct1); tech_top3 += int(ct3)

        bucket = per_type.setdefault(atype, {"n": 0, "tactic_top1": 0, "tactic_top3": 0, "tech_top1": 0, "tech_top3": 0})
        bucket["n"] += 1
        bucket["tactic_top1"] += int(tt1); bucket["tactic_top3"] += int(tt3)
        bucket["tech_top1"] += int(ct1); bucket["tech_top3"] += int(ct3)

    n = len(true_positive_alerts)
    result = {
        "tactic_level": {
            "description": "proxy metric -- does top candidate's TACTIC match what's expected for the known attack type",
            "top1_accuracy": round(tactic_top1 / n, 4) if n else None,
            "top3_accuracy": round(tactic_top3 / n, 4) if n else None,
        },
        "technique_level": {
            "description": "does top candidate's exact TECHNIQUE ID match the technique our own simulator was "
                            "written to model for that attack type (see EXPECTED_TECHNIQUE in this file) -- "
                            "ground truth is our own design intent, valid for synthetic data only",
            "top1_accuracy": round(tech_top1 / n, 4) if n else None,
            "top3_accuracy": round(tech_top3 / n, 4) if n else None,
        },
        "n_true_positive_alerts_evaluated": n,
        "by_attack_type": {
            atype: {
                "n": b["n"],
                "expected_technique": EXPECTED_TECHNIQUE[atype],
                "tactic_top1_accuracy": round(b["tactic_top1"] / b["n"], 4),
                "tactic_top3_accuracy": round(b["tactic_top3"] / b["n"], 4),
                "technique_top1_accuracy": round(b["tech_top1"] / b["n"], 4),
                "technique_top3_accuracy": round(b["tech_top3"] / b["n"], 4),
            }
            for atype, b in per_type.items()
        },
    }

    with open(OUT_PATH, "w") as f:
        json.dump(result, f, indent=2)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
