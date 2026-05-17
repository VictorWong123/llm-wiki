# How Redline Uses Cognee and Redis

This file is written as demo prep notes. The short version is:

- Redis Stack is the hot memory layer. It stores recent session activity, trace events, searchable safety memories, vector embeddings, preflight results, and unsafe-pattern fingerprints.
- Cognee is the durable cross-session memory layer. It stores long-lived safety knowledge, agent findings, feedback, accepted violations, regression tests, and improvement proposals.
- The local `wiki/` files remain the source of truth, so the demo still works if Redis or Cognee is unavailable.

## Memory Architecture

Redline has three memory tiers:

1. Local wiki files under `wiki/`
   - Canonical source of truth.
   - Stores safety rules, observed violations, regression tests, and agent findings as Markdown and JSON.

2. Redis Stack through `backend/app/redis_memory.py`
   - Fast, session-oriented memory.
   - Used for demo traceability, semantic lookup, repeated-risk fingerprints, and Redis Insight visibility.

3. Cognee through `backend/app/memory.py`
   - Durable memory adapter.
   - Used for cross-session recall, feedback, and longer-lived agent learning.

The backend wires both adapters in `backend/app/main.py`:

```python
cache = RedisMemoryAdapter()
memory = MemoryAdapter()
```

The helper `_call(...)` routes optional Redis work through `cache`, and `_memory_call(...)` routes optional Cognee work through `memory`. Both helpers treat adapter failures as non-fatal for the demo: if Redis or Cognee is missing, the local wiki and deterministic detectors still run.

## Redis: What We Used It For

Redis is implemented by `RedisMemoryAdapter` in `backend/app/redis_memory.py`.

The adapter connects with:

```python
redis.from_url(REDIS_URL, decode_responses=True)
```

The expected local setup is Redis Stack, not just basic Redis:

```bash
docker run --rm --name redline-redis-stack \
  -p 6379:6379 -p 8001:8001 \
  redis/redis-stack:latest
```

Redis Insight is then available at:

```text
http://localhost:8001
```

### Redis Capabilities Used

The adapter detects these capabilities in `_detect_capabilities()`:

- Redis Streams
  - Tested with `xadd(...)`.
  - Used for event traces under `stream:redline_events`.

- RedisJSON
  - Tested with `client.json().set(...)` and `client.json().get(...)`.
  - Used to store structured JSON documents for rules, memories, preflights, sessions, findings, violations, regressions, and fingerprints.

- RediSearch
  - Used through `client.ft(INDEX_NAME)`.
  - The index name is `idx:safety_memories`.

- Redis vector search
  - Created as part of the RediSearch JSON index.
  - Uses an HNSW vector field named `embedding`.
  - Embeddings are deterministic hash embeddings from `HashEmbeddingProvider`, so the demo does not require an external embedding API.

### Redis Functions and Tools

These are the main Redis functions we use:

#### `ensure_search_index()`

Creates the RediSearch index:

```text
idx:safety_memories
```

It indexes RedisJSON documents with the prefix:

```text
memory:
```

The schema includes:

- `id`
- `kind`
- `risk_type`
- `severity`
- `language`
- `title`
- `content`
- `unsafe_patterns`
- `safe_patterns`
- `active`
- `embedding`

The `embedding` field is configured as:

```text
VECTOR HNSW TYPE FLOAT32 DISTANCE_METRIC COSINE
```

Demo talking point:

> Redis is not just being used as a key-value cache. We create a searchable memory index with metadata filters and vector similarity over safety memories.

#### `store_document(key, value, ttl_seconds=None)`

Stores structured memory documents.

If RedisJSON is available, it uses:

```python
client.json().set(key, "$", value)
```

If RedisJSON is unavailable, it falls back to plain JSON strings with `set` or `setex`.

This is used by most higher-level memory functions.

#### `set_json(key, value, ttl_seconds=300)` and `get_json(key)`

General JSON helpers for short-lived API state, especially:

- preflight results
- cached objects
- fallback fingerprint lookups

#### `remember_rule(rule)`

Stores a safety rule in Redis:

```text
rule:{rule.id}
memory:rule:{rule.id}
```

The `rule:` key stores the full rule document.

The `memory:rule:` key stores a search-ready memory document with:

- title
- category
- severity
- rule text
- unsafe patterns
- safe patterns
- risk type
- deterministic embedding

This is used during startup seeding and rule ingestion.

#### `remember_violation(...)`

Stores accepted Redline catches:

```text
violation:{violation.id}
memory:violation:{violation.id}
```

This happens after the user accepts a safe rewrite. It lets future preflight runs find similar prior violations.

#### `remember_rewrite(...)`

Stores accepted safe rewrites:

```text
rewrite:{rewrite_id}
```

This captures:

- original unsafe content
- safe rewrite
- violation id
- why the rewrite was considered safe

#### `remember_regression(...)`

Stores regression tests created from accepted catches:

```text
regression:{regression.id}
memory:regression:{regression.id}
```

The `memory:regression:` record becomes searchable recall data.

#### `remember_security_finding(...)`

Stores novel findings discovered by an agent:

```text
finding:{finding.id}
memory:finding:{finding.id}
```

This is used by the agent-facing command:

```bash
python3 scripts/redline_finding.py --title "..." --description "..."
```

#### `remember_preflight(...)`

Stores a preflight result:

```text
preflight:{preflight_id}
```

This includes:

- session id
- input type
- language
- content hash
- status
- severity
- matched rule ids
- evidence
- explanation
- safe rewrite
- fast-path flag

#### `remember_session_event(session_id, event)`

Stores recent session-local events:

```text
session:{session_id}
```

The session document keeps the latest 50 events and uses a 24-hour TTL.

#### `search_similar(query, input_type, top_k=5)`

This is the Redis semantic recall path.

Flow:

1. Guess the risk type with `guess_risk_type(...)`.
2. Embed the query with `HashEmbeddingProvider`.
3. If RediSearch and vector search are available, run a KNN query against `idx:safety_memories`.
4. Filter by risk type when possible.
5. Return `MemoryMatch` objects.

The Redis query uses:

```text
(@risk_type:{...})=>[KNN top_k @embedding $vec AS vector_score]
```

Demo talking point:

> Before running deterministic detectors, Redline asks Redis whether this looks like something we have seen before.

#### `check_fingerprint(...)` and `save_fingerprint(...)`

These implement the Redis Reflex Memory fast path.

For repeated unsafe patterns, Redline stores fingerprints like:

```text
fingerprint:{hash}
fingerprints:recent
fingerprints:risk:{risk_type}
```

Example fingerprint patterns include:

- string-interpolated SQL query
- prompt injection phrase like "ignore previous instructions"
- hardcoded secret-like value
- dynamic or destructive execution

If a later preflight matches a stored fingerprint, Redline can return `REDLINE TRIGGERED` before running the full detector pipeline.

Demo talking point:

> The second time the same class of unsafe SQL appears, Redis can short-circuit the check with a remembered unsafe fingerprint.

#### `emit_event(...)` and `recent_events(...)`

These provide traceability for the UI and demo.

Events are written to:

```text
stream:redline_events
```

The API can read them through:

```text
GET /events/recent
GET /events/stream
```

Important event types include:

- `agent.context_retrieved`
- `preflight.started`
- `rules.retrieved`
- `detector.matched`
- `redline.triggered`
- `preflight.completed`
- `violation.saved`
- `regression.created`
- `agent.finding_logged`
- `feedback.recorded`

Demo talking point:

> Redis Streams make the memory system visible. During the demo, Redis Insight can show the event trail as Redline runs.

## Cognee: What We Used It For

Cognee is implemented by `MemoryAdapter` in `backend/app/memory.py`.

Cognee is optional and controlled by:

```bash
COGNEE_ENABLED=true
COGNEE_DATASET=redline-hackathon
COGNEE_SESSION_PREFIX=redline
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o-mini
LLM_API_KEY=...
```

The adapter imports Cognee dynamically:

```python
import_module("cognee")
```

If Cognee is unavailable or disabled, the adapter uses deterministic local fallback lists so the app still works.

### Cognee Functions and Tools

These are the main Cognee-facing functions:

#### `remember_durable(label, payload, metadata=None)`

This is the main durable-memory write path.

It stores a local memory entry, then calls Cognee:

```python
cognee.add(text, dataset_name=self.dataset_name)
cognee.cognify(datasets=[self.dataset_name])
```

The payload is serialized as JSON text with:

```python
_text_for(label, payload, metadata)
```

Labels we store durably include:

- `safety_rule`
- `observed_violation`
- `regression_test`
- `agent_security_finding`
- `feedback`
- `applied_improvement`

Demo talking point:

> Redis is optimized for live recall and traces; Cognee is where Redline promotes knowledge that should survive across sessions.

#### `remember(label, payload)`

Convenience wrapper around:

```python
remember_durable(label, payload)
```

Several backend flows call `remember(...)` first, then call `remember_durable(...)` with metadata when they want extra context.

#### `remember_session(session_id, label, payload)`

Stores session-scoped memory.

For Cognee, the session id is scoped with:

```text
{COGNEE_SESSION_PREFIX}:{session_id}
```

Then the adapter tries:

```python
cognee.add(
    text,
    dataset_name=self.dataset_name,
    node_set=[self.session_prefix, scoped_session_id, label],
)
```

If `node_set` is unsupported, it falls back to `cognee.add(text, dataset_name=...)`.

Session labels include:

- `agent_context`
- `preflight_proposal`
- `preflight_result`

Demo talking point:

> Cognee gets both durable safety knowledge and session-scoped memories, so we can explain what happened in this run without mixing it up with every other run.

#### `recall(query, session_id=None, top_k=5)`

This is the Cognee recall path.

If a session id is provided and Cognee supports `recall`, it tries:

```python
cognee.recall(
    query,
    datasets=[self.dataset_name],
    session_id=scoped_session_id,
)
```

Otherwise it uses Cognee search:

```python
cognee.search(
    query_text=query,
    datasets=[self.dataset_name],
    query_type=SearchType.GRAPH_COMPLETION,
)
```

The adapter has compatibility fallbacks for different Cognee call signatures:

- `datasets=[dataset]`
- `datasets=dataset`
- positional query plus datasets

The API endpoint that exposes both Redis and Cognee recall is:

```text
POST /memory/recall
```

That endpoint returns:

- `redis_matches`
- `cognee_results`
- `degraded`

#### `record_feedback(feedback_entry)`

Stores feedback locally and, when Cognee is enabled, writes:

```python
cognee.add(_text_for("feedback", feedback_entry), dataset_name=self.dataset_name)
```

This is called by:

```text
POST /feedback
```

#### `propose_improvement(feedback_entry)`

Creates an improvement proposal from feedback.

If Cognee exposes `improve`, the adapter calls:

```python
cognee.improve(dataset=self.dataset_name)
```

In the demo, low feedback scores trigger improvement proposal behavior.

#### `apply_improvement(proposal)`

Marks a proposal as applied and writes it back into Cognee:

```python
cognee.add(_text_for("applied_improvement", applied), dataset_name=self.dataset_name)
cognee.cognify(datasets=[self.dataset_name])
```

#### `lint()`

Returns Cognee adapter status and local fallback memory counts:

- available
- degraded
- last error
- dataset name
- memory count
- session count
- feedback count
- proposal count

The backend also has a `/lint` endpoint that checks wiki duplicates, severity conflicts, and stale Redis event memory.

### Cognee Configuration

`MemoryAdapter._configure_cognee()` reads:

```bash
LLM_PROVIDER
LLM_MODEL
```

When Cognee exposes config methods, Redline calls:

```python
cognee.config.set_llm_provider(provider)
cognee.config.set_llm_model(model)
```

This is covered by the test:

```text
backend/tests/test_memory_pipeline.py::test_cognee_adapter_configures_provider_model_and_session_nodes
```

## Main Demo Flows

### 1. Startup and health

When the backend starts:

1. `.env` is loaded by `_load_env_file()`.
2. Redis connects through `RedisMemoryAdapter()`.
3. Cognee connects through `MemoryAdapter()`.
4. `/health` and `/sponsor-status` report both adapter statuses.

Useful endpoints:

```text
GET /health
GET /sponsor-status
GET /demo-evidence
```

If `REDLINE_REQUIRE_SPONSOR_MEMORY=true`, `/sponsor-status` reports `required_not_ready` until both Redis and Cognee are available.

### 2. Wiki seeding into memory

`_seed_wiki_memory()` mirrors existing wiki safety rules into both memory systems:

```python
_call("remember_rule", rule)
_memory_call("remember_durable", "safety_rule", rule.model_dump(), metadata={...})
```

Redis gets searchable `memory:rule:*` records.

Cognee gets durable `safety_rule` memories.

### 3. Rule ingestion

Endpoint:

```text
POST /ingest
```

Flow:

1. Extract a `SafetyRule` from the submitted source text.
2. Save it to the local wiki.
3. Store it in Redis with `set_json(...)` and `remember_rule(...)`.
4. Store it in Cognee with `remember(...)` and `remember_durable(...)`.
5. Emit a Redis Stream event: `rule.ingested`.

Demo phrase:

> Ingest is the promotion path from trusted source notes into the wiki, Redis hot memory, and Cognee durable memory.

### 4. Agent context retrieval

Endpoint:

```text
POST /agent/context
```

CLI command:

```bash
python3 scripts/redline_context.py "implement a SQL-backed user lookup"
```

Flow:

1. Rank local wiki safety rules for the task.
2. Search similar Redis memories with `_search_similar(...)`.
3. Emit `agent.context_retrieved` to Redis Streams.
4. Store session context in Cognee with `remember_session(...)`.

Demo phrase:

> Before the coding agent writes code, Redline retrieves relevant wiki rules and memory from prior safety events.

### 5. Preflight

Endpoint:

```text
POST /preflight
```

CLI command:

```bash
python3 scripts/redline_preflight.py --content 'query = f"SELECT * FROM users WHERE email = {email}"'
```

Flow:

1. Emit `preflight.started`.
2. Store the proposal in Cognee session memory with `remember_session("preflight_proposal", ...)`.
3. Store the proposal in Redis session memory with `remember_session_event(...)`.
4. Check Redis fingerprints with `check_fingerprint(...)`.
5. If fingerprint matches, return the fast-path `REDLINE TRIGGERED` result.
6. If no fingerprint matches, search Redis similar memories with `search_similar(...)`.
7. Run deterministic detectors with `run_preflight(...)`.
8. If unsafe, save a Redis fingerprint with `save_fingerprint(...)`.
9. Store the preflight result in Redis with `remember_preflight(...)` and `set_json(...)`.
10. Emit `preflight.completed`.
11. Store the result in Cognee session memory with `remember_session("preflight_result", ...)`.

Demo phrase:

> Preflight combines three checks: remembered Redis fingerprints, Redis semantic recall, and deterministic detectors.

### 6. Accepting a safe rewrite

Endpoint:

```text
POST /accept-rewrite
```

Flow:

1. Write an observed violation to `wiki/observed_violations`.
2. Write a regression test to `wiki/regression_tests`.
3. Store rewrite, violation, and regression records in Redis.
4. Save or update the Redis fingerprint.
5. Store observed violation and regression test in Cognee durable memory.
6. Emit `violation.saved`, `regression.created`, and `wiki.updated`.

Demo phrase:

> Accepting the rewrite turns one catch into future memory: a violation example, a regression test, a Redis fingerprint, and Cognee durable knowledge.

### 7. Agent-discovered findings

Endpoint:

```text
POST /agent/finding
```

CLI command:

```bash
python3 scripts/redline_finding.py \
  --title "Missing object authorization" \
  --description "Endpoint reads project_id without checking ownership." \
  --evidence "demo endpoint"
```

Flow:

1. Search Redis and local findings for similar prior issues.
2. If a close match exists, skip duplicate logging.
3. If novel, write the finding to `wiki/agent_findings`.
4. Store it in Redis with `remember_security_finding(...)`.
5. Store it in Cognee with `remember(...)` and `remember_durable(...)`.
6. Emit `agent.finding_logged`.

Demo phrase:

> The agent does not just report a bug once. Redline checks whether the finding is novel, then promotes it into wiki, Redis, and Cognee memory.

### 8. Feedback and improvement

Endpoint:

```text
POST /feedback
```

Flow:

1. Save feedback in backend memory.
2. Store feedback in Cognee with `remember(...)` and `record_feedback(...)`.
3. Emit `feedback.recorded`.
4. If the score is low, create an improvement proposal.
5. Call Cognee improvement behavior through `propose_improvement(...)`.

Related endpoints:

```text
POST /feedback/{feedback_id}/improvement-proposal
POST /feedback/{feedback_id}/apply-improvement
```

Demo phrase:

> Feedback is routed to Cognee because it is long-term learning signal, not just a short-lived trace.

## Redis Keys to Show in Redis Insight

Open Redis Insight at:

```text
http://localhost:8001
```

Useful patterns to search:

```text
rule:*
memory:*
preflight:*
session:*
violation:*
rewrite:*
regression:*
finding:*
fingerprint:*
fingerprints:recent
fingerprints:risk:*
stream:redline_events
```

Useful CLI commands:

```bash
redis-cli PING
redis-cli FT._LIST
redis-cli FT.INFO idx:safety_memories
redis-cli XLEN stream:redline_events
redis-cli XREVRANGE stream:redline_events + - COUNT 10
redis-cli KEYS 'fingerprint:*'
redis-cli KEYS 'memory:*'
```

## What to Say in the Demo

Use this short explanation:

> Redline uses Redis and Cognee for different memory jobs. Redis Stack is the live operational memory: it stores JSON records, RediSearch indexes, vector embeddings, event streams, sessions, and fast unsafe-pattern fingerprints. Cognee is the durable memory layer: when a rule, finding, feedback item, accepted violation, or regression test should survive beyond the current run, we write it into Cognee and cognify the dataset. The local wiki remains the source of truth, so the product degrades cleanly if either sponsor service is unavailable.

For the Redis portion:

> Redis gives us inspectable real-time memory. During preflight, we search similar prior memories, check repeated-risk fingerprints, store the preflight result, and write stream events. Redis Insight can show those keys and events live.

For the Cognee portion:

> Cognee gives us durable cross-session agent memory. We call `cognee.add`, `cognee.cognify`, `cognee.recall` or `cognee.search`, and optionally `cognee.improve`. This is how Redline remembers safety rules, accepted catches, feedback, and improvement proposals across sessions.

For the pipeline:

> The flow is: trusted rule enters the wiki, Redis indexes it for fast recall, Cognee stores it as durable knowledge, preflight checks new code against both memory and deterministic detectors, and accepted catches are promoted back into all three layers.

## Files to Reference

- `backend/app/main.py`
  - API routes and memory orchestration.
  - Look for `_call`, `_memory_call`, `_seed_wiki_memory`, `/ingest`, `/agent/context`, `/preflight`, `/accept-rewrite`, `/agent/finding`, `/feedback`, and `/memory/recall`.

- `backend/app/redis_memory.py`
  - Redis Stack integration.
  - Look for `RedisMemoryAdapter`, `ensure_search_index`, `remember_rule`, `search_similar`, `save_fingerprint`, and `emit_event`.

- `backend/app/memory.py`
  - Cognee adapter.
  - Look for `MemoryAdapter`, `remember_durable`, `remember_session`, `recall`, `record_feedback`, `propose_improvement`, and `apply_improvement`.

- `backend/tests/test_memory_pipeline.py`
  - Tests that prove Redis/Cognee behavior.
  - Covers fingerprint fast path, durable rule memory, agent context trace events, novel finding logging, sponsor status, Cognee provider/model config, accepted rewrite memory, feedback, and lint.

## Validation Commands

Run backend tests:

```bash
PYTHONPATH=backend pytest backend/tests
```

Focused Redis/Cognee test:

```bash
PYTHONPATH=backend pytest backend/tests/test_memory_pipeline.py
```

Check adapter status:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/sponsor-status
curl http://localhost:8000/demo-evidence
```

Check recent Redis Stream events:

```bash
curl "http://localhost:8000/events/recent?limit=10"
```
