"""
Streamlit demo dashboard for the Cyber Resilience prototype (ET AI Hackathon
2026, Problem Statement #7 -- scoped to the Behavioral Anomaly Detection
Engine + APT Attribution Agent sub-agents).

Run with: streamlit run dashboard.py
"""

import json
import os

import pandas as pd
import streamlit as st

from anomaly_engine import BehavioralAnomalyEngine
from orchestrator import run_pipeline, BASELINE_MTTD_DAYS, WINDOW_MINUTES

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "network_windows.csv")
EVAL_DIR = os.path.join(os.path.dirname(__file__), "..", "eval")

st.set_page_config(page_title="Cyber Resilience — Behavioral Anomaly + ATT&CK Attribution", layout="wide")


@st.cache_data(show_spinner="Scoring behavioral windows and running attribution...")
def load_and_run(use_llm: bool):
    df = pd.read_csv(DATA_PATH)
    df["window_start"] = pd.to_datetime(df["window_start"])
    alerts, summary = run_pipeline(df, use_llm=use_llm)
    return df, alerts, summary


st.title("AI-Driven Cyber Resilience — Behavioral Anomaly Detection + APT Attribution")
st.caption(
    "ET AI Hackathon 2026 · Problem Statement #7 · Scoped prototype: "
    "Behavioral Anomaly Detection Engine + APT Campaign Attribution Agent"
)

with st.expander("Data & honesty notes — read before judging the numbers", expanded=False):
    st.markdown(
        """
- **Dataset is synthetic, not a real benchmark.** This sandbox has no outbound access to
  Kaggle/UCI/HuggingFace/GitHub-raw, so the real UNSW-NB15/CICIDS2017 CSVs could not be
  downloaded. `src/generate_dataset.py` generates a labeled, entity-level, flow-aggregated
  dataset with the same feature families (duration, byte/packet counts, port/host fan-out,
  auth failures, protocol mix) and includes both "loud" and "low-and-slow / stealthy" attack
  variants plus benign-but-unusual normal traffic, specifically so the evaluation isn't
  artificially easy. It also simulates per-entity destination identities so a `novel_peer_ratio`
  feature (has this host ever talked to this destination before?) can be computed causally —
  this is what raised stealthy lateral-movement recall from 5.9% to 31%. Swap in real data by
  replacing `build_dataset()` — every downstream component just consumes a DataFrame with the
  documented column names.
- **MITRE ATT&CK knowledge base is hand-curated (18 techniques), not a live pull** — attack.mitre.org
  is also unreachable from this sandbox. Replace `attack_kb.py` with a live TAXII/STIX pull before
  real deployment.
- **LLM attribution narrative** uses the Anthropic API if `ANTHROPIC_API_KEY` is set in the
  environment; otherwise it falls back to a deterministic rule-based narrative automatically —
  the app never crashes for lack of a key, it just produces plainer prose.
"""
    )

use_llm = st.sidebar.toggle(
    "Use LLM for attribution narrative",
    value=True,
    help="Falls back to rule-based narrative automatically if no ANTHROPIC_API_KEY is set.",
)
llm_key_present = bool(os.environ.get("ANTHROPIC_API_KEY"))
st.sidebar.caption(
    f"ANTHROPIC_API_KEY detected: {'yes' if llm_key_present else 'no (rule-based fallback active)'}"
)

df, alerts, summary = load_and_run(use_llm)

# ---- Top-line metrics ----
col1, col2, col3, col4, col5 = st.columns(5)
col1.metric("Windows scored", f"{summary['total_windows_scored']:,}")
col2.metric("Flagged anomalous", f"{summary['windows_flagged']:,}")
col3.metric("True positive alerts", summary["true_positive_alerts"])
col4.metric("False positive alerts", summary["false_positive_alerts"])
col5.metric(
    "Detection latency",
    f"{WINDOW_MINUTES} min",
    help=f"vs. {BASELINE_MTTD_DAYS}-day cited industry baseline for public-sector breach discovery "
         "(CERT-In pattern referenced in the problem statement). This compares raw scoring latency "
         "on a fixed batch cadence, not an end-to-end SOC SLA — real deployments still need ingestion "
         "and analyst-triage time on top of this.",
)

if os.path.exists(f"{EVAL_DIR}/metrics.json"):
    with open(f"{EVAL_DIR}/metrics.json") as f:
        metrics = json.load(f)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("ROC-AUC", metrics["roc_auc"])
    m2.metric("PR-AUC", metrics["pr_auc"])
    m3.metric("Precision @ operating point", metrics["operating_point"]["precision"])
    m4.metric("False positive rate", metrics["operating_point"]["false_positive_rate"])

st.divider()

tab1, tab2, tab3, tab4 = st.tabs(["Alert feed", "Entity drill-down", "Benchmark metrics", "ATT&CK coverage"])

with tab1:
    st.subheader("Prioritized alerts (highest anomaly score first)")
    alert_rows = []
    for a in alerts[:100]:
        top_tech = a["candidate_techniques"][0]["id"] if a["candidate_techniques"] else "—"
        top_tech_name = a["candidate_techniques"][0]["name"] if a["candidate_techniques"] else "—"
        alert_rows.append(
            {
                "Anomaly score": round(a["anomaly_score"], 3),
                "Entity": a["entity_id"],
                "Window": a["window_start"],
                "Top ATT&CK match": f"{top_tech} — {top_tech_name}",
                "Confidence": a["confidence"],
                "Attribution source": a["source"],
                "Ground truth (demo only)": a["true_attack_type"],
            }
        )
    alert_df = pd.DataFrame(alert_rows)
    st.dataframe(alert_df, width='stretch', height=400)

    st.subheader("Alert detail")
    idx = st.selectbox(
        "Select an alert to inspect",
        options=range(len(alerts[:100])),
        format_func=lambda i: f"{alerts[i]['entity_id']} @ {alerts[i]['window_start']} (score {alerts[i]['anomaly_score']:.3f})",
    )
    a = alerts[idx]
    left, right = st.columns([2, 1])
    with left:
        st.markdown(f"**Narrative** _(source: {a['source']})_")
        st.info(a["narrative"])
        st.markdown("**Recommended immediate action**")
        st.success(a["recommended_action"])
        st.markdown("**Candidate ATT&CK techniques**")
        st.dataframe(pd.DataFrame(a["candidate_techniques"]), width='stretch')
    with right:
        st.markdown("**Contributing features**")
        for feat in a["contributing_features"]:
            st.write(f"- {feat}")
        st.markdown("**Ground truth (demo/eval only — not available in production)**")
        st.write(f"Attack type: `{a['true_attack_type']}`")
        st.write(f"Confidence: {a['confidence']}")

with tab2:
    st.subheader("Entity behavior over time")
    entity = st.selectbox("Entity", sorted(df["entity_id"].unique()))
    edf = df[df["entity_id"] == entity].sort_values("window_start")

    engine = BehavioralAnomalyEngine().fit(df)
    scored = engine.score(df)
    edf = edf.assign(anomaly_score=scored.scores.loc[edf.index].values,
                      is_anomaly=scored.is_anomaly.loc[edf.index].values)

    st.line_chart(edf.set_index("window_start")[["anomaly_score"]])
    st.caption("Red-flagged windows (is_anomaly=True) are where this entity crossed the ensemble's operating threshold.")
    st.dataframe(
        edf[["window_start", "anomaly_score", "is_anomaly", "label", "attack_type", "severity"]],
        width='stretch',
        height=300,
    )

with tab3:
    st.subheader("Benchmark evaluation")
    if os.path.exists(f"{EVAL_DIR}/metrics.json"):
        with open(f"{EVAL_DIR}/metrics.json") as f:
            metrics = json.load(f)
        c1, c2 = st.columns(2)
        with c1:
            if os.path.exists(f"{EVAL_DIR}/roc_curve.png"):
                st.image(f"{EVAL_DIR}/roc_curve.png")
        with c2:
            if os.path.exists(f"{EVAL_DIR}/pr_curve.png"):
                st.image(f"{EVAL_DIR}/pr_curve.png")

        st.markdown("**Recall by attack type and severity** — the honest picture, not a blended average")
        rb = metrics["recall_by_attack_type_and_severity"]
        rb_df = pd.DataFrame(
            [{"attack_type/severity": k, "recall": v["recall"], "n_windows": v["n_windows"]} for k, v in rb.items()]
        ).sort_values("recall", ascending=False)
        st.dataframe(rb_df, width='stretch', height=380)
        st.caption(
            "Stealthy/low-and-slow variants are meaningfully harder than loud ones by design — see the "
            "'Data & honesty notes' expander above. Stealthy lateral movement improved from 5.9% to 31% "
            "recall after adding a peer-novelty feature (has this host ever talked to this destination "
            "before?), but it's still the weakest category — closing the rest needs identity/credential-graph "
            "signals, which is exactly the roadmap item in the README. Also note: stealthy brute-force "
            "recall dropped (68% → 38%) as a side effect of the same change, since this engine flags a "
            "fixed alert budget per run and the ranking shifted — a documented trade-off, not an oversight."
        )
    else:
        st.warning("Run `python evaluate.py` first to generate metrics.")

with tab4:
    st.subheader("Curated MITRE ATT&CK knowledge base")
    from attack_kb import ATTACK_KB
    kb_df = pd.DataFrame(ATTACK_KB)[["id", "tactic", "name", "signal_features"]]
    st.dataframe(kb_df, width='stretch', height=500)
    st.caption(f"{len(ATTACK_KB)} techniques curated for this prototype. Not a live TAXII/STIX pull — see notes above.")
