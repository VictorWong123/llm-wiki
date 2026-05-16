# Team Submission

## Team

- Team name: Redline
- Participants: Victor Wong
- Wiki / project name: Redline

## Wiki Overview

Redline is a living safety wiki and preflight layer for coding agents. It ingests trusted security guidance into durable wiki rules, retrieves the most relevant rules before an agent writes code, checks proposed code or untrusted content before action, and records accepted catches as observed violations, regression tests, and learned findings. It self-improves by promoting human/agent feedback and novel security findings into the wiki so future agent runs can recall the new risk.

- Domain or data sources: secure coding rules from `raw_sources/`, generated wiki entries in `wiki/`, observed violations, regression tests, agent findings, and optional Redis/Cognee memory.
- Primary use case: stop coding agents from introducing known security flaws before code is finalized.
- What makes it stand out: it works as both a local deterministic demo and a connected memory system: Redis stores hot session traces and fast-path fingerprints, while Cognee stores durable cross-session safety knowledge.

## The Three Operations

### Ingest

- What goes in (documents, conversations, runs, ...): trusted Markdown safety notes, user-ingested rules, accepted preflight violations, safe rewrites, regression tests, feedback, and novel agent security findings.
- How it is captured (`cognee.remember(...)`, custom pipeline, ...): `POST /ingest` converts source text into a `SafetyRule`, writes local Markdown/JSON wiki files, mirrors rules into Redis when available, and calls the Cognee-compatible `MemoryAdapter.remember_durable(...)`.
- Code entry point: `backend/app/main.py` routes `/ingest`, `/accept-rewrite`, `/agent/finding`; wiki writes live in `backend/app/wiki_writer.py`.

### Query + Self-improve

- How users query the wiki: the React UI calls `/wiki`, `/wiki/recent`, `/preflight`, and `/memory/recall`; coding agents call `scripts/redline_context.py "<task>"` before editing.
- Where feedback comes from (user rating, agent critic, eval, ...): UI feedback on preflight results, accepted safe rewrites, and agent-discovered findings submitted through `scripts/redline_finding.py` or `/agent/finding`.
- How feedback updates the wiki (`SkillRunEntry`, edge re-weighting,
  graph rewrite, ...): low-score feedback creates an improvement proposal; accepted rewrites create observed violation and regression-test memories; novel findings are deduped against existing memory and logged as `wiki/agent_findings` plus learned safety rules for supported categories.
- Code entry point: `backend/app/main.py` routes `/agent/context`, `/preflight`, `/feedback`, `/feedback/{id}/apply-improvement`, `/agent/finding`; learned rule templates live in `backend/app/learned_rules.py`.

### Lint

- What "linting" means in your wiki (dedupe, conflict resolution, stale
  pruning, ...): checks duplicate safety rules, conflicting severities for the same risk type, and stale live memory when no recent Redis Stream events exist.
- How it runs (scheduled, on-write, on-demand): on demand through the UI or `POST /lint`, with dry-run support for safe demos.
- Concrete lint behavior: a clean run returns `PASS`; duplicate rule content produces a `duplicates` finding, mismatched severities for the same risk type produce a `conflicts` finding, and no recent Redis events produce a `stale` finding.
- Code entry point: `backend/app/main.py` route `/lint` and helper `_lint_wiki(...)`.

## Self-Improvement Evidence

Show that the wiki actually got smarter. Concrete before/after beats prose.

### Baseline Run

- Query / task: "Add a post-login redirect helper that reads `next` from the query string and redirects there."
- Result: Redline had seeded rules for SQL injection, prompt injection, secrets, unsafe execution, and authorization, but no open-redirect rule yet. The agent recognized the gap and logged `finding_99e9ffc827d0`, which is documented in `wiki/agent_findings/finding_99e9ffc827d0.md`.
- Score (your own metric, judge-readable): 0.35 coverage score. The wiki captured the issue as `NEEDS HUMAN REVIEW`, but did not yet have a durable open-redirect rule.
- Recorded feedback:

```text
error_type: missing_rule
error_message: User-controlled redirect target was not represented by a seeded rule.
feedback: Add durable guidance for open redirects and same-origin/allowlist validation.
success_score: 0.35
```

### Improved Run

- Query / task: "Add a post-login redirect helper that reads `next` from the query string and redirects there."
- Result: The wiki now contains `learned_open_redirect_001`, sourced to OWASP Unvalidated Redirects and Forwards guidance, with unsafe patterns and safe rewrites for redirect validation in `wiki/safety_rules/learned_open_redirect_001.md`.
- Score: 0.85 coverage score. The agent context can retrieve the learned rule before coding, and the Recently Added page shows the finding/rule pair.
- What changed in the wiki between runs:

```text
Before:
No open-redirect rule existed in wiki/safety_rules.
The issue could only be handled by general agent judgment.

After:
wiki/agent_findings/finding_99e9ffc827d0.md records the novel issue.
wiki/safety_rules/learned_open_redirect_001.md records a durable learned rule.
The rule explains unsafe redirect parameters and safe same-origin/allowlist patterns.
```

## Architecture

Redline uses a FastAPI backend, React/Vite frontend, local Markdown/JSON wiki, optional Redis Stack hot memory, and optional Cognee durable memory.

```text
[raw_sources / UI ingest / agent turns]
        |
        v
[FastAPI routes + deterministic detectors]
        |
        v
[ Redis  - session memory ]   <- hot, per-conversation
        |
        | promote accepted rules, findings, violations, regression tests
        v
[ Cognee - permanent graph ]  <- durable, cross-session
        |
        v
[agent context retrieval / preflight / memory recall]
        |
        v
[feedback + findings -> improve wiki]
```

### Redis-as-session-memory

- What the agent writes into Redis (raw turns, intermediate observations, ...): preflight proposals/results, trace events, rule retrieval events, safety memories, fingerprints, rewrites, violations, regression tests, and recent session activity.
- How and when content is distilled into the graph: when rules are ingested, findings are logged, feedback is recorded, or rewrites are accepted, Redline writes local wiki files and calls the Cognee-compatible durable memory adapter.
- What stays in Redis vs. what gets promoted: Redis keeps hot session context, streams, search indexes, vectors, and repeated-risk fingerprints; Cognee/wiki receive durable rules, feedback, learned findings, accepted violations, and regression tests.
- How distillation quality improved between baseline and improved run: the baseline open-redirect issue existed only as an agent judgment; after logging, Redline promoted it into an explicit learned rule with source, severity, unsafe patterns, and safe remediation guidance.

## Agents / Skills (if any)

If you used skill packs or multi-agent roles:

```text
Skill path(s):
  scripts/redline_context.py
  scripts/redline_preflight.py
  scripts/redline_finding.py
Roles:
  - Ingestor: /ingest converts trusted source notes into wiki safety rules.
  - Querier: /agent/context retrieves relevant rules and similar memories before coding.
  - Linter: /lint checks duplicate, conflicting, or stale wiki/memory state.
  - Critic: /preflight, /feedback, and /agent/finding detect issues, collect feedback, and log novel risks.
```

## Reproduction

Commands to reproduce your demo:

```bash
# Terminal 1: optional sponsor memory
docker run --rm --name redline-redis-stack \
  -p 6379:6379 -p 8001:8001 \
  redis/redis-stack:latest

# Terminal 2: backend
cd /Users/victorwong/Downloads/redline/backend
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app.main:app --host localhost --reload

# Terminal 3: frontend
cd /Users/victorwong/Downloads/redline/frontend
npm install
npm run dev

# Agent guard examples, from repo root
cd /Users/victorwong/Downloads/redline
python3 scripts/redline_context.py "implement a SQL-backed user lookup"
python3 scripts/redline_preflight.py \
  --content 'query = f"SELECT * FROM users WHERE email = {email}"'
python3 scripts/redline_finding.py \
  --title "Open redirect risk in post-login redirect helper" \
  --description "The route redirects to a user-controlled next URL without same-origin validation or an allowlist." \
  --evidence "/api/login/complete reads next from the query string and redirects directly."
```

Environment variables required:

```text
REDIS_URL=redis://localhost:6379/0
COGNEE_ENABLED=true
COGNEE_DATASET=redline-hackathon
COGNEE_SESSION_PREFIX=redline
REDLINE_REQUIRE_SPONSOR_MEMORY=true
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o-mini
LLM_API_KEY=<required only for Cognee-backed LLM work>
OPENAI_API_KEY=<optional OpenAI-compatible key>
```

## Demo

- Live demo link (Loom, YouTube, etc.) or local instructions: run the backend and frontend above, then open `http://localhost:5173`. Redis Insight is available at `http://localhost:8001` when Redis Stack is running.
- 3-minute pitch outline:

```text
1. Problem / idea: coding agents need a living safety memory, not one-off prompts.
2. Ingest demo: ingest or show seeded SQL/prompt/security rules in the wiki.
3. Query demo (before improvement): run a known unsafe SQL preflight and show REDLINE TRIGGERED.
4. Self-improve step: accept the safe rewrite or log an unknown issue such as open redirect / CSV formula injection.
5. Query demo (after improvement): refresh Recently Added and show the new finding plus learned safety rule.
6. What is next: add more learned-rule detectors, strengthen automatic evals, and expand Cognee graph recall.
```

## Links

- Repo: https://github.com/VictorWong123/llm-wiki
- Slides / writeup: project PDFs in `docs/`
- Anything else: local app at `http://localhost:5173`, recent learned entries at `http://localhost:5173/recently-added`
