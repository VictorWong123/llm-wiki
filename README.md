# Redline

Redline is a hackathon MVP for a living safety wiki and preflight layer for coding agents. It stores trusted safety rules, checks proposed code or untrusted content before the agent acts, returns a safety verdict, and saves accepted catches as observed violations plus regression tests.

The demo is deterministic without Redis, Cognee, or OpenAI. Redis Stack and Cognee are optional hackathon adapters; markdown and JSON files under `wiki/` remain the source of truth so the app can degrade cleanly during demos.

## Setup

Backend:

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app.main:app --host localhost --reload
```

Frontend:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

## Redis Stack Setup

Redis Stack enables the sponsor hot-memory path for the hackathon demo. Run it locally before starting the backend:

```bash
docker run --rm --name redline-redis-stack \
  -p 6379:6379 -p 8001:8001 \
  redis/redis-stack:latest
```

Redis Insight is available at `http://localhost:8001`.

The backend uses these Redis capabilities when they are available:

- RedisJSON for rules, violations, rewrites, regression tests, session events, preflight results, and fingerprints.
- RediSearch over `idx:safety_memories` for rule, violation, and regression memory search.
- Vector search with deterministic hash embeddings for similar-memory recall.
- Streams on `stream:redline_events` for traceable preflight, feedback, lint, and rewrite events.
- Fingerprint keys and indexes for fast-path detection of repeated unsafe patterns.

If Redis is missing, unreachable, or lacks a module, Redline falls back to local file-backed wiki behavior and in-process memory where supported. Preflight and wiki writeback continue to work; Redis search, vector recall, streams, and fingerprint acceleration are degraded rather than fatal.

For a sponsor-required demo, set `REDLINE_REQUIRE_SPONSOR_MEMORY=true`. Then `/health` and `/sponsor-status` report `required_not_ready` until both Redis and Cognee are available.

## Cognee Setup

Copy `backend/.env.example` to `backend/.env` if you want to configure optional services. Do not commit real secrets.

Cognee is used as durable cross-session memory when enabled. Redis remains the hot session layer, keyed by `session_id`; Cognee stores durable safety rules, accepted violations, regression tests, feedback, skill-run records, and inspected improvement proposals.

Safe environment names:

- `REDIS_URL`: Redis Stack connection string, for example `redis://localhost:6379/0`.
- `COGNEE_ENABLED`: set to `true` to enable durable Cognee memory.
- `COGNEE_DATASET`: dataset namespace for Redline memories.
- `COGNEE_SESSION_PREFIX`: optional prefix for session-scoped memory IDs.
- `REDLINE_REQUIRE_SPONSOR_MEMORY`: set to `true` for demos where Redis and Cognee must both be active.
- `LLM_PROVIDER`: provider identifier for Cognee-backed LLM work.
- `LLM_MODEL`: model name used by Cognee-backed LLM work.
- `LLM_API_KEY`: provider API key; leave empty in the example file.
- `OPENAI_API_KEY`: optional OpenAI-compatible key; leave empty in the example file.

Minimum sponsor demo `.env`:

```bash
REDIS_URL=redis://localhost:6379/0
COGNEE_ENABLED=true
COGNEE_DATASET=redline-hackathon
COGNEE_SESSION_PREFIX=redline
REDLINE_REQUIRE_SPONSOR_MEMORY=true
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o-mini
LLM_API_KEY=your-provider-key
```

## Hackathon Memory Pipeline

The intended pipeline has two memory tiers:

1. Redis session memory stores recent turns, preflight traces, scratch observations, fingerprints, and fast recall for a single `session_id`.
2. Cognee durable memory stores cross-session wiki knowledge, feedback, skill-run history, improvement proposals, and accepted long-term facts.

The demo flow exercises:

- Ingest: trusted rules are written to the local wiki and, when enabled, durable Cognee memory.
- Query and preflight: proposed code or untrusted content is checked against deterministic detectors, Redis fingerprints, and similar Redis memories.
- Feedback and self-improvement: feedback records a score and human-readable critique before any durable skill or memory improvement is applied.
- Lint: wiki cleanup checks for duplicates, conflicts, and stale memory, with dry-run behavior for safe demos.
- Promotion: accepted catches become observed violations and regression tests in the wiki, RedisJSON, Redis search memory, and Cognee durable memory when adapters are enabled.

## Agent Guard Demo

Redline is connected to coding agents through persistent repo instructions plus two CLI commands:

```bash
python3 scripts/redline_context.py "implement a project lookup endpoint"
python3 scripts/redline_preflight.py --diff
python3 scripts/redline_finding.py --title "Missing object authorization" --description "Endpoint reads project_id without an ownership check." --evidence "app/routes.py:42"
```

For the connected demo, start the backend first so the UI and event APIs can show `agent.context_retrieved` and `preflight.completed`:

```bash
cd backend
uvicorn app.main:app --host localhost --reload
```

To demo the same task without Redline, disable the guard:

```bash
REDLINE_AGENT_GUARD=off python3 scripts/redline_context.py "implement a project lookup endpoint"
REDLINE_AGENT_GUARD=off python3 scripts/redline_preflight.py --diff
REDLINE_AGENT_GUARD=off python3 scripts/redline_finding.py --title "Missing object authorization" --description "Endpoint reads project_id without an ownership check."
```

Leave `REDLINE_AGENT_GUARD` unset, or set it to `on`, for the normal connected flow. If the backend is not running, the scripts fall back to local wiki files and deterministic detectors; this still protects the agent, but it will not create backend demo events. Agent-discovered findings are written to `wiki/agent_findings` after Redline searches prior findings and memory for duplicates.

## Demo Script

1. Start backend and frontend.
2. Optionally start Redis Stack and enable Cognee in `backend/.env`.
3. Open Redis Insight and watch RedisJSON keys, RediSearch indexes, vectors, stream events, and fingerprint sets appear during the run.
4. Click `Ingest Safety Rule` to show rule-to-wiki ingestion and durable Cognee memory when enabled.
5. Click `Load SQL Injection Demo`.
6. Click `Run Preflight`.
7. Show `REDLINE TRIGGERED`, matched SQL rule, evidence, similar memories, trace IDs, and parameterized rewrite.
8. Run the same or a similar unsafe SQL example again to show the Redis fingerprint fast path.
9. Click `Accept Safe Rewrite`.
10. Show the wiki counts update for observed violations and regression tests.
11. Click `Load Prompt Injection Demo`.
12. Click `Run Preflight`.
13. Show Redline catches untrusted instruction override text and rewrites behavior to treat it as data only.
14. Submit feedback with a low score to show Cognee durable/session memory recording the critique and proposing improvement before apply.
15. Run lint in dry-run mode to show duplicate, conflict, and stale-memory checks without destructive cleanup.
16. Run `python3 scripts/redline_context.py "implement a SQL-backed user lookup"` to show the agent retrieving wiki rules before coding.
17. Run `python3 scripts/redline_preflight.py --content 'query = f"SELECT * FROM users WHERE email = {email}"'` to show the agent-side guard blocking unsafe code.
18. Run `python3 scripts/redline_finding.py --title "Missing object authorization" --description "Endpoint reads project_id without checking ownership." --evidence "demo endpoint"` to show Redline searching prior memory and logging a novel security issue.
19. Repeat any command with `REDLINE_AGENT_GUARD=off` to show the without-Redline baseline.

## What Works

- `GET /health`
- `POST /ingest`
- `POST /agent/context`
- `POST /agent/finding`
- `POST /preflight`
- `POST /accept-rewrite`
- `POST /feedback`
- `POST /lint`
- `GET /wiki`
- `GET /demo-data`
- `GET /events/recent`
- Seeded rules from trusted `raw_sources/`
- Deterministic SQL injection, prompt injection, secrets, unsafe execution, and missing-authorization heuristics
- Local markdown and JSON wiki writeback
- Optional RedisJSON, RediSearch, vector search, Streams, and fingerprint fast path
- Optional Cognee durable memory with Redis-backed session context
- React/Vite demo UI with live wiki refresh

## Validation

```bash
PYTHONPATH=backend pytest backend/tests

cd frontend
npm run build
```

Focused Redis/Cognee validation:

```bash
rg "REDIS_URL|COGNEE|LLM_PROVIDER|LLM_MODEL|LLM_API_KEY|OPENAI_API_KEY" backend
rg "RedisMemoryAdapter|json_available|FT.CREATE|VECTOR|xadd|fingerprint|session_id" backend/app
PYTHONPATH=backend pytest backend/tests/test_memory_pipeline.py
curl http://localhost:8000/health
curl "http://localhost:8000/events/recent?limit=10"
```

Redis Stack inspection commands:

```bash
redis-cli PING
redis-cli FT._LIST
redis-cli XLEN stream:redline_events
redis-cli KEYS 'fingerprint:*'
redis-cli KEYS 'memory:*'
```
# llm-wiki
