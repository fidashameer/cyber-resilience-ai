"""
APT Campaign Attribution & Prediction Agent.

Retrieve-then-generate pipeline over the curated ATT&CK knowledge base
(attack_kb.py):

  1. RETRIEVE: given the anomaly engine's top contributing features for a
     flagged window, score every KB technique by overlap with those
     features (weighted so the single most-deviant feature counts more
     than the third-most-deviant one), and take the top-N candidates.
  2. GENERATE: hand those candidates + the raw anomaly context to an LLM
     (Claude) to synthesize a short analyst-readable narrative, a
     confidence-ranked technique list, and a recommended immediate action
     pulled from the KB's mitigation field.

GRACEFUL DEGRADATION: this agent must not crash a live demo just because no
ANTHROPIC_API_KEY is set in the environment, or the call fails/times out. If
the LLM step is unavailable for any reason, it falls back to a deterministic
rule-based narrative built directly from the retrieved KB entries -- lower
quality prose, same structured output shape, so the orchestrator and
dashboard never need to know which path was taken.
"""

import json
import os
from dataclasses import dataclass, field

from attack_kb import ATTACK_KB, techniques_by_feature

MODEL_DEFAULT = os.environ.get("ATTRIBUTION_MODEL", "claude-sonnet-5")


@dataclass
class Attribution:
    entity_id: str
    anomaly_score: float
    contributing_features: list
    candidate_techniques: list  # list of dicts: id, name, tactic, overlap_score
    narrative: str
    recommended_action: str
    confidence: float
    source: str  # "llm" or "rule_based"


def retrieve_candidates(contributing_features, top_n: int = 4):
    """Score KB techniques by weighted overlap with the anomaly's top
    contributing features. Feature at index 0 (most anomalous) gets weight
    3, index 1 gets weight 2, index 2+ gets weight 1."""
    weights = {feat: max(3 - i, 1) for i, feat in enumerate(contributing_features)}
    scored = []
    for tech in ATTACK_KB:
        overlap = set(tech["signal_features"]) & set(contributing_features)
        if not overlap:
            continue
        score = sum(weights[f] for f in overlap)
        scored.append({**tech, "overlap_score": score, "matched_features": sorted(overlap)})
    scored.sort(key=lambda t: t["overlap_score"], reverse=True)
    return scored[:top_n]


def _rule_based_narrative(entity_id, anomaly_score, contributing_features, candidates):
    if not candidates:
        return (
            f"{entity_id} flagged with anomaly score {anomaly_score:.2f}, driven by "
            f"{', '.join(contributing_features)}, but no ATT&CK technique in the current "
            f"knowledge base matches this feature combination -- needs manual triage.",
            "Escalate to analyst for manual review; knowledge base may need extension.",
            0.3,
        )
    top = candidates[0]
    tactic_chain = ", ".join(sorted({c["tactic"].split(",")[0].strip() for c in candidates}))
    narrative = (
        f"{entity_id} deviates from its behavioral baseline on {', '.join(contributing_features)} "
        f"(anomaly score {anomaly_score:.2f}). Feature pattern most closely matches "
        f"{top['id']} ({top['name']}, tactic: {top['tactic']}), with secondary matches "
        f"spanning {tactic_chain}. This combination of signals is consistent with early-to-mid "
        f"stage activity rather than a single isolated event."
    )
    action = f"{top['mitigations'][0]} — see {top['id']} for full technique context."
    confidence = round(min(0.55 + 0.08 * len(candidates), 0.9), 3)
    return narrative, action, confidence


def _llm_narrative(entity_id, anomaly_score, contributing_features, candidates, model=MODEL_DEFAULT):
    """Calls the Anthropic API to synthesize the retrieved candidates into an
    analyst narrative. Raises on any failure so the caller can fall back."""
    import anthropic  # imported lazily so the module still loads without the package/key

    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env

    kb_context = "\n".join(
        f"- {c['id']} ({c['name']}, tactic: {c['tactic']}): {c['description']} "
        f"[matched on: {', '.join(c['matched_features'])}] "
        f"[mitigation: {c['mitigations'][0]}]"
        for c in candidates
    )

    prompt = f"""You are a SOC analyst co-pilot for critical-infrastructure cyber defense.

An unsupervised behavioral anomaly engine flagged this entity:
- entity_id: {entity_id}
- anomaly_score (0-1, higher = more anomalous): {anomaly_score:.3f}
- top contributing features (most anomalous first): {', '.join(contributing_features)}

Candidate MITRE ATT&CK techniques retrieved by feature-overlap (already ranked, most likely first):
{kb_context}

Write a JSON object with exactly these keys:
- "narrative": 2-3 sentences, analyst-toned, explaining what's happening and why it matters. Reference the specific technique IDs.
- "recommended_action": one concrete, immediately actionable next step (pull from the mitigations given, phrased as an instruction).
- "confidence": a float 0-1 reflecting how confident this attribution is, given it's from behavioral signals only (not confirmed malware/IOC match) — be conservative, most real cases should be 0.4-0.75 unless the signal is very unambiguous.

Return ONLY the JSON object, no other text."""

    resp = client.messages.create(
        model=model,
        max_tokens=400,
        messages=[{"role": "user", "content": prompt}],
    )
    text = resp.content[0].text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        text = text[text.find("{"):text.rfind("}") + 1]
    parsed = json.loads(text)
    return parsed["narrative"], parsed["recommended_action"], float(parsed["confidence"])


def attribute(entity_id, anomaly_score, contributing_features, use_llm: bool = True) -> Attribution:
    candidates = retrieve_candidates(contributing_features)

    source = "rule_based"
    narrative, action, confidence = _rule_based_narrative(
        entity_id, anomaly_score, contributing_features, candidates
    )

    if use_llm and os.environ.get("ANTHROPIC_API_KEY"):
        try:
            narrative, action, confidence = _llm_narrative(
                entity_id, anomaly_score, contributing_features, candidates
            )
            source = "llm"
        except Exception as e:  # noqa: BLE001 - demo must never hard-crash on LLM failure
            print(f"[attribution_agent] LLM call failed ({e}); falling back to rule-based narrative.")

    return Attribution(
        entity_id=entity_id,
        anomaly_score=anomaly_score,
        contributing_features=contributing_features,
        candidate_techniques=[
            {"id": c["id"], "name": c["name"], "tactic": c["tactic"], "overlap_score": c["overlap_score"]}
            for c in candidates
        ],
        narrative=narrative,
        recommended_action=action,
        confidence=confidence,
        source=source,
    )


if __name__ == "__main__":
    result = attribute(
        entity_id="host-014",
        anomaly_score=0.91,
        contributing_features=["failed_auth_count", "admin_proto_ratio", "conn_rate_per_min"],
    )
    print(json.dumps(result.__dict__, indent=2))
