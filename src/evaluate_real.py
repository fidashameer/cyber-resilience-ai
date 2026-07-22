"""
Benchmark evaluation on the REAL UNSW-NB15 data (see load_unsw_real.py).

Run separately from evaluate.py (which covers the synthetic set) so neither
run's outputs clobber the other. Contamination is set to this dataset's own
observed attack rate rather than the synthetic default (0.06), since using
the wrong assumed base rate would systematically under- or over-flag and
give a misleading operating-point read; ROC-AUC/PR-AUC are threshold-free
and unaffected either way.
"""

import json

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import (
    precision_recall_curve, roc_curve, roc_auc_score,
    average_precision_score, precision_score, recall_score, f1_score,
)

from anomaly_engine import BehavioralAnomalyEngine

DATA_PATH = "/sessions/serene-friendly-newton/mnt/outputs/cyber-resilience-ai/data/network_windows_real.csv"
OUT_DIR = "/sessions/serene-friendly-newton/mnt/outputs/cyber-resilience-ai/eval"


def main():
    df = pd.read_csv(DATA_PATH)
    base_rate = df["label"].mean()

    engine = BehavioralAnomalyEngine(contamination=base_rate).fit(df)
    result = engine.score(df)

    y_true = df["label"].values
    y_score = result.scores.values
    y_pred = result.is_anomaly.values.astype(int)

    fpr_at_op = ((y_pred == 1) & (y_true == 0)).sum() / max((y_true == 0).sum(), 1)

    metrics = {
        "dataset": "real UNSW-NB15 (see load_unsw_real.py for provenance/approximations)",
        "n_windows": int(len(df)),
        "n_entities": int(df["entity_id"].nunique()),
        "base_attack_rate": round(float(base_rate), 4),
        "roc_auc": round(roc_auc_score(y_true, y_score), 4),
        "pr_auc": round(average_precision_score(y_true, y_score), 4),
        "operating_point": {
            "precision": round(precision_score(y_true, y_pred), 4),
            "recall": round(recall_score(y_true, y_pred), 4),
            "f1": round(f1_score(y_true, y_pred), 4),
            "false_positive_rate": round(fpr_at_op, 4),
            "flagged_count": int(y_pred.sum()),
        },
    }

    df2 = df.copy()
    df2["pred"] = y_pred
    breakdown = (
        df2[df2["label"] == 1]
        .groupby("attack_type")["pred"]
        .agg(["mean", "count"])
        .rename(columns={"mean": "recall", "count": "n_windows"})
        .round(4)
    )
    metrics["recall_by_attack_type"] = {
        cat: {"recall": r, "n_windows": int(n)} for cat, (r, n) in breakdown.iterrows()
    }

    with open(f"{OUT_DIR}/metrics_real.json", "w") as f:
        json.dump(metrics, f, indent=2)

    fpr, tpr, _ = roc_curve(y_true, y_score)
    plt.figure(figsize=(5, 5))
    plt.plot(fpr, tpr, label=f"ROC-AUC = {metrics['roc_auc']:.3f}")
    plt.plot([0, 1], [0, 1], "--", color="gray", label="random baseline")
    plt.xlabel("False Positive Rate"); plt.ylabel("True Positive Rate")
    plt.title("Real UNSW-NB15 — ROC Curve"); plt.legend(); plt.tight_layout()
    plt.savefig(f"{OUT_DIR}/roc_curve_real.png", dpi=150); plt.close()

    prec, rec, _ = precision_recall_curve(y_true, y_score)
    plt.figure(figsize=(5, 5))
    plt.plot(rec, prec, label=f"PR-AUC = {metrics['pr_auc']:.3f}")
    plt.axhline(base_rate, linestyle="--", color="gray", label=f"random baseline ({base_rate:.3f})")
    plt.xlabel("Recall"); plt.ylabel("Precision")
    plt.title("Real UNSW-NB15 — Precision-Recall Curve"); plt.legend(); plt.tight_layout()
    plt.savefig(f"{OUT_DIR}/pr_curve_real.png", dpi=150); plt.close()

    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
