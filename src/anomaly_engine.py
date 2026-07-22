"""
Behavioral Anomaly Detection Engine.

Design intent (mirrors problem statement #7's "Behavioural Anomaly Detection
Engine"): build a per-entity behavioral baseline, then score how far each new
observation window deviates from that entity's own normal behavior -- NOT
from a signature database. This is what lets it catch novel attack patterns
that don't match any known malware signature.

Method:
1. Per-entity baseline: mean/std of each raw feature, computed without using
   labels (unsupervised, as it would be in production where you don't know
   in advance which windows are attacks).
2. Per-window deviation features: z-score of each raw feature against the
   entity's own baseline. This normalizes "host-042 usually talks to 30
   internal IPs" vs "host-011 usually talks to 2" onto the same scale, so a
   single global model can be used across heterogeneous entities.
3. Ensemble of two complementary scorers on the deviation features:
     - Isolation Forest: catches multi-feature *combinations* that are
       jointly unusual even if no single feature looks extreme (compound
       anomalies -- e.g. slightly elevated auth failures + slightly unusual
       admin-protocol ratio + slightly odd hour, none extreme alone).
     - Statistical max-|z-score|: catches single-feature spikes fast and
       cheaply, which matters for "loud" attacks that should be caught
       immediately rather than waiting on a tree ensemble.
   (An earlier version of this engine also included Local Outlier Factor,
   but LOF is density-based and was empirically *hurting* recall here:
   when several entities are attacked with the same technique, those
   windows form a small dense cluster in feature space and LOF's local
   density comparison stops treating them as outliers. That's a real,
   documented LOF failure mode on clustered anomalies, not just a synthetic
   data artifact, so it was dropped rather than papered over.)
4. Contributing features: for each flagged window, report which raw features
   had the largest |z-score|, so the attribution agent has something concrete
   to reason over (this is what feeds MITRE ATT&CK technique matching).
"""

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from generate_dataset import FEATURE_COLUMNS


@dataclass
class AnomalyResult:
    scores: pd.Series          # higher = more anomalous, roughly 0-1
    is_anomaly: pd.Series      # bool, thresholded
    contributing_features: pd.Series  # list[str] per row, top deviating features


class BehavioralAnomalyEngine:
    def __init__(self, contamination: float = 0.06, top_k_features: int = 3, random_state: int = 42):
        self.contamination = contamination
        self.top_k_features = top_k_features
        self.random_state = random_state
        self._baseline = None  # per-entity mean/std, set by fit()

    def _entity_baseline(self, df: pd.DataFrame) -> pd.DataFrame:
        """Per-entity mean/std for each raw feature, unsupervised (no labels used)."""
        stats = df.groupby("entity_id")[FEATURE_COLUMNS].agg(["mean", "std"])
        stats.columns = ["__".join(c) for c in stats.columns]
        stats = stats.fillna(0.0)
        # avoid divide-by-zero for near-constant features
        for col in FEATURE_COLUMNS:
            std_col = f"{col}__std"
            stats[std_col] = stats[std_col].replace(0, 1e-6)
        return stats

    def _deviation_features(self, df: pd.DataFrame) -> pd.DataFrame:
        merged = df.merge(self._baseline, left_on="entity_id", right_index=True, how="left")
        dev = pd.DataFrame(index=df.index)
        for col in FEATURE_COLUMNS:
            dev[f"z_{col}"] = (merged[col] - merged[f"{col}__mean"]) / merged[f"{col}__std"]
        return dev

    def fit(self, df: pd.DataFrame):
        self._baseline = self._entity_baseline(df)
        dev = self._deviation_features(df)
        self._if_model = IsolationForest(
            n_estimators=300, contamination=self.contamination, random_state=self.random_state
        ).fit(dev.values)
        self._dev_columns = dev.columns.tolist()
        return self

    def score(self, df: pd.DataFrame) -> AnomalyResult:
        assert self._baseline is not None, "call fit() before score()"
        dev = self._deviation_features(df)

        # Isolation Forest: more negative decision_function = more anomalous.
        if_raw = -self._if_model.decision_function(dev.values)
        if_rank = pd.Series(if_raw).rank(pct=True)

        # Statistical scorer: largest single-feature deviation from this
        # entity's own baseline. Cheap, fast, and catches "loud" single-signal
        # spikes that a tree ensemble can occasionally under-weight.
        stat_raw = dev.abs().max(axis=1).values
        stat_rank = pd.Series(stat_raw).rank(pct=True)

        # Weighted ensemble: IF gets more weight because it models feature
        # *combinations* (the compound-risk pattern this engine is meant to
        # catch), the statistical scorer is a fast-path safety net.
        ensemble = (0.7 * if_rank.values + 0.3 * stat_rank.values)

        threshold = np.quantile(ensemble, 1 - self.contamination)
        is_anomaly = ensemble >= threshold

        contributing = []
        dev_abs = dev.abs()
        for i in range(len(df)):
            row = dev_abs.iloc[i]
            top = row.sort_values(ascending=False).head(self.top_k_features)
            contributing.append([c.replace("z_", "") for c in top.index.tolist()])

        return AnomalyResult(
            scores=pd.Series(ensemble, index=df.index, name="anomaly_score"),
            is_anomaly=pd.Series(is_anomaly, index=df.index, name="is_anomaly"),
            contributing_features=pd.Series(contributing, index=df.index, name="contributing_features"),
        )


if __name__ == "__main__":
    df = pd.read_csv("/sessions/serene-friendly-newton/mnt/outputs/cyber-resilience-ai/data/network_windows.csv")
    engine = BehavioralAnomalyEngine().fit(df)
    result = engine.score(df)
    print(f"Flagged {result.is_anomaly.sum()} / {len(df)} windows as anomalous")
    flagged = df[result.is_anomaly.values]
    print("Attack-type breakdown among flagged windows:")
    print(flagged["attack_type"].value_counts())
