"""
Benchmark evaluation for the Behavioral Anomaly Detection Engine.

Produces threshold-independent metrics (ROC-AUC, PR-AUC) plus metrics at the
engine's chosen operating threshold (precision, recall, F1, false positive
rate), broken out by attack type AND by severity (loud vs. stealthy/low-and-
slow), because a single blended recall number hides the honest story: this
engine catches obvious attacks reliably and stealthy ones only partially,
which is a real and worth-stating limitation, not a bug to hide.

Also writes ROC and Precision-Recall curve PNGs to eval/ for use in the
presentation deck.
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

DATA_PATH = "/sessions/serene-friendly-newton/mnt/outputs/cyber-resilience-ai/data/network_windows.csv"
OUT_DIR = "/sessions/serene-friendly-newton/mnt/outputs/cyber-resilience-ai/eval"


def main():
    df = pd.read_csv(DATA_PATH)
    engine = BehavioralAnomalyEngine().fit(df)
    result = engine.score(df)

    y_true = df["label"].values
    y_score = result.scores.values
    y_pred = result.is_anomaly.values.astype(int)

    fpr_at_operating_point = ((y_pred == 1) & (y_true == 0)).sum() / max((y_true == 0).sum(), 1)

    metrics = {
        "roc_auc": round(roc_auc_score(y_true, y_score), 4),
        "pr_auc": round(average_precision_score(y_true, y_score), 4),
        "operating_point": {
            "precision": round(precision_score(y_true, y_pred), 4),
            "recall": round(recall_score(y_true, y_pred), 4),
            "f1": round(f1_score(y_true, y_pred), 4),
            "false_positive_rate": round(fpr_at_operating_point, 4),
            "flagged_count": int(y_pred.sum()),
            "total_windows": int(len(df)),
        },
    }

    # Recall broken out by attack type x severity -- the honest picture.
    df2 = df.copy()
    df2["pred"] = y_pred
    df2["score"] = y_score
    breakdown = (
        df2[df2["label"] == 1]
        .groupby(["attack_type", "severity"])["pred"]
        .agg(["mean", "count"])
        .rename(columns={"mean": "recall", "count": "n_windows"})
        .round(4)
    )
    metrics["recall_by_attack_type_and_severity"] = {
        f"{a}/{s}": {"recall": r, "n_windows": int(n)}
        for (a, s), (r, n) in breakdown.iterrows()
    }

    with open(f"{OUT_DIR}/metrics.json", "w") as f:
        json.dump(metrics, f, indent=2)

    # ROC curve
    fpr, tpr, _ = roc_curve(y_true, y_score)
    plt.figure(figsize=(5, 5))
    plt.plot(fpr, tpr, label=f"ROC-AUC = {metrics['roc_auc']:.3f}")
    plt.plot([0, 1], [0, 1], "--", color="gray", label="random baseline")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("Behavioral Anomaly Engine — ROC Curve")
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"{OUT_DIR}/roc_curve.png", dpi=150)
    plt.close()

    # PR curve
    prec, rec, _ = precision_recall_curve(y_true, y_score)
    plt.figure(figsize=(5, 5))
    plt.plot(rec, prec, label=f"PR-AUC = {metrics['pr_auc']:.3f}")
    base_rate = y_true.mean()
    plt.axhline(base_rate, linestyle="--", color="gray", label=f"random baseline ({base_rate:.3f})")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Behavioral Anomaly Engine — Precision-Recall Curve")
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"{OUT_DIR}/pr_curve.png", dpi=150)
    plt.close()

    print(json.dumps(metrics, indent=2))
    print(f"\nSaved metrics.json, roc_curve.png, pr_curve.png to {OUT_DIR}")


if __name__ == "__main__":
    main()
