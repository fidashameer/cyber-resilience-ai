"""Generates assets/architecture_diagram.png. Built vs. roadmap components are
visually distinguished (solid vs. dashed) so it's honest about current scope."""

import graphviz

g = graphviz.Digraph("architecture", format="png")
g.attr(rankdir="LR", fontsize="11", fontname="Helvetica", bgcolor="white")
g.attr("node", fontname="Helvetica", fontsize="10")

# --- Data sources ---
with g.subgraph(name="cluster_sources") as c:
    c.attr(label="Data Sources", style="rounded", color="gray60")
    c.node("net", "Network flow data\n(synthetic, CICIDS/UNSW-style\nfeature schema)", shape="cylinder")
    c.node("attck", "MITRE ATT&CK KB\n(curated, 18 techniques)", shape="cylinder")

# --- Built components ---
with g.subgraph(name="cluster_built") as c:
    c.attr(label="Built (this prototype)", style="rounded", color="#2b6cb0")
    c.node("engine", "Behavioral Anomaly\nDetection Engine\n(per-entity baseline +\nIsolation Forest + stat scorer)",
           shape="box", style="filled", fillcolor="#ebf4ff", color="#2b6cb0")
    c.node("orch", "Orchestrator\n(flag -> attribute -> alert)",
           shape="box", style="filled", fillcolor="#ebf4ff", color="#2b6cb0")
    c.node("agent", "APT Attribution Agent\n(retrieve top ATT&CK\ntechniques, LLM narrative\nw/ rule-based fallback)",
           shape="box", style="filled", fillcolor="#ebf4ff", color="#2b6cb0")
    c.node("dash", "Streamlit Dashboard\n(alert feed, entity drill-down,\nbenchmark metrics, ATT&CK coverage)",
           shape="box", style="filled", fillcolor="#ebf4ff", color="#2b6cb0")

# --- Roadmap / not built ---
with g.subgraph(name="cluster_roadmap") as c:
    c.attr(label="Roadmap (not built — scope cut for solo/timeline)", style="rounded,dashed", color="gray50")
    c.node("soar", "Autonomous Incident\nResponse Orchestrator (SOAR)", shape="box", style="dashed", color="gray50", fontcolor="gray40")
    c.node("vuln", "Vulnerability\nPrioritization Agent", shape="box", style="dashed", color="gray50", fontcolor="gray40")
    c.node("twin", "Cyber Resilience\nDigital Twin", shape="box", style="dashed", color="gray50", fontcolor="gray40")
    c.node("graph", "Identity/Credential\nGraph AI (lateral movement)", shape="box", style="dashed", color="gray50", fontcolor="gray40")

g.edge("net", "engine")
g.edge("engine", "orch", label="anomaly score +\ncontributing features")
g.edge("attck", "agent")
g.edge("orch", "agent", label="flagged windows")
g.edge("agent", "orch", label="narrative +\nrecommended action")
g.edge("orch", "dash", label="structured alerts (JSON)")

g.edge("orch", "soar", style="dashed", color="gray50", label="high-confidence\ntrigger", fontcolor="gray40")
g.edge("engine", "graph", style="dashed", color="gray50", label="closes stealthy\nlateral-movement gap", fontcolor="gray40")
g.edge("dash", "vuln", style="dashed", color="gray50")
g.edge("dash", "twin", style="dashed", color="gray50")

import shutil

# Render to a scratch path first: the assets/ output directory in this
# environment doesn't allow deleting/overwriting files, and graphviz's
# cleanup=True step needs to delete its intermediate .gv source file.
g.render("/tmp/architecture_diagram", cleanup=True)
shutil.copy("/tmp/architecture_diagram.png",
            "/sessions/serene-friendly-newton/mnt/outputs/cyber-resilience-ai/assets/architecture_diagram.png")
print("Wrote architecture_diagram.png")
