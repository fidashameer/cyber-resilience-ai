# Demo Video Script — AI-Driven Cyber Resilience (Problem Statement #7)

**Target length: 2:45–3:15.** Hackathon judges skim; a tight 3 minutes that's confident and specific beats a rambling 6 minutes.

## Why you should record this yourself, not me

I could assemble a silent, captioned screen-capture video automatically (I have the tooling for it). I'm not going to, and here's the actual reasoning, not just a formality: judges — and later, recruiters looking at this project on your resume — are implicitly evaluating whether *you* understand what was built, not just whether a working app exists. A video where you narrate your own build, in your own words, occasionally stumbling on a word, is more credible evidence of that than a polished but voiceless walkthrough would be. This script exists so you don't have to improvise the whole thing — read it, internalize it, say it in your own words. Don't read it verbatim on camera; that reads as stiff.

If you genuinely don't want to be on camera or narrate, tell me and I'll build the automated captioned version as a fallback — but do that as a conscious choice, not a default.

## Before you record

1. `cd` into the `src/` folder and run `streamlit run dashboard.py`. Let it fully load once in your browser before you start recording — the first load is slower (model fitting + attribution retrieval on all 432 alerts).
2. Resize the browser window to something clean — hide bookmarks bar, close other tabs, turn off notifications (Do Not Disturb).
3. Use QuickTime Player → File → New Screen Recording (built into macOS). Select just the browser window, not your full screen.
4. Do one silent dry run of the click-path below before recording for real, so you're not discovering the UI live.
5. Record audio and screen together in one take if you can — it's more natural than syncing them after. If you stumble, pause, breathe, and continue; don't restart from scratch unless it's bad.

## Shot-by-shot script

### 1. Cold open (0:00–0:15) — face-to-camera or voiceover over title slide
> "I built an AI system that detects cyberattacks on critical infrastructure by learning what's *normal* for each computer on a network, and flags the moment something deviates — without needing to already know what the attack looks like. This is for the ET AI Hackathon, Problem Statement 7."

Show: the deck's title slide, or your face, whichever you're more comfortable leading with.

### 2. The problem, fast (0:15–0:35)
> "Right now, most breaches at Indian institutions — AIIMS, CBSE — are discovered weeks or months after the initial break-in, because detection relies on signature matching. Attackers know this, and deliberately move slowly to stay under the radar. What's missing is a behavioral layer that catches *deviation*, not just known bad patterns."

Show: deck slide 2 (the problem stats), or just talk over a blank moment.

### 3. Live dashboard — alert feed (0:35–1:10)
Switch to the running Streamlit app.

> "Here's the working prototype. This is the alert feed — every one of these rows is a five-minute window of network activity that my engine flagged as unusual, ranked by how anomalous it is."

Action: point at the **Alert feed** tab, scroll the table briefly.

> "Click into one —" [click a high-scoring alert] "— and here's the important part: it's not just a red flag. It tells you *why*. These are the specific behaviors that triggered it, and this is the matching MITRE ATT&CK technique — the actual, real framework security analysts use to classify attack methods — retrieved automatically and explained in plain language."

Action: point at the narrative text and the candidate ATT&CK techniques table in the alert detail view.

### 4. Live dashboard — entity drill-down (1:10–1:35)
Switch to **Entity drill-down** tab.

> "You can also drill into any single computer over time and see its anomaly score rise and fall — this is what lets a security team see the pattern building, not just get a one-off alert."

Action: pick an entity from the dropdown, point at the line chart.

### 5. The honest results (1:35–2:15) — this is the differentiator, don't rush it
Switch to **Benchmark metrics** tab, or cut to deck slides 7–9.

> "Here's where I want to be direct instead of just showing you a good number. On data I generated myself, this hits 99% ROC-AUC. But I didn't stop there — I also tested it against 2.5 million *real* network connections from the UNSW-NB15 research dataset, and there it drops to 81%. That's a real, honest gap: real attacks in that dataset are mostly exploits and fuzzing — single malicious packets — not the sustained behavior changes this engine is built to catch. I'm telling you that gap exists because a security tool that only shows you its best-case number isn't one you should trust."

Action: show the recall-by-attack-type table or the slide-8/slide-9 charts from the deck (screen-share the PDF/PPT if easier than digging through the dashboard for this part).

> "I also found and partially fixed a real weakness during this build: stealthy lateral movement — an attacker quietly moving between machines — was almost invisible to the original engine. Adding a feature that tracks whether a computer reaches somewhere it's never gone before raised detection on that specific attack from 6% to 31%."

### 6. Close (2:15–2:45)
> "This is scoped to two of the five sub-agents the problem statement suggested, deliberately — a behavioral detection engine and an attack-attribution agent — because I'd rather show you two things that actually work end to end than five things half-built. The rest — automated response, vulnerability prioritization, a full digital twin — is documented as roadmap, not hidden. Full source, architecture diagram, and both benchmark results are in the repo. Thanks for watching."

Show: closing deck slide (slide 12) or the GitHub repo page if it's live by then.

## Recording tips specific to this app

- The **Attribution source** column in the alert table will show `rule_based` unless you've set an `ANTHROPIC_API_KEY` — that's fine and expected, don't apologize for it on camera, it's a documented design choice (automatic graceful fallback).
- If you do want the LLM-generated narrative for a more natural-sounding demo line, set the key before starting `streamlit run` — but don't feel obligated; the rule-based narrative is coherent enough to demo as-is.
- Pick a **high anomaly-score alert with a clean top ATT&CK match** for step 3 — already pulled these for you from `eval/alerts.json` so you don't have to hunt live on camera:

  | Entity | Window | Score | True attack | Top ATT&CK match |
  |---|---|---|---|---|
  | host-056 | 2026-07-14 06:05 | 0.9995 | Port scan | T1595 Active Scanning |
  | host-052 | 2026-07-14 07:35 | 0.9978 | DoS | T1498 Network Denial of Service |
  | host-044 | 2026-07-14 08:40 | 0.9947 | Exfiltration | T1041 Exfiltration Over C2 Channel |
  | host-020 | 2026-07-14 08:50 | 0.9946 | Lateral movement | T1021 Remote Services |

  Use **host-056** for step 3 — it's the single highest-scoring alert in the whole run, and its top match is a clean, obvious one (port scan → Active Scanning) that's easy to explain in one sentence on camera.

- For step 4 (entity drill-down), select **host-020** — it's the lateral-movement example above, so its line chart will show a real flagged spike, and it lets you connect this moment back to the "we found and partially fixed a real weakness" point in step 5 if you want to tie the two together.
