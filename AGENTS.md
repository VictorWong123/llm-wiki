# Repository Guidelines

## Mandatory Redline Agent Guard

This repository demos an LLM wiki that must inform coding agents before they write or change code. For every code change task, Codex, Claude, or any other coding agent must use Redline unless the user explicitly asks for the "without Redline" demo path.

Required connected flow:

1. Before editing code, run `python3 scripts/redline_context.py "<user task>"` from the repository root and use the returned wiki rules as security context.
2. After editing code, run `python3 scripts/redline_preflight.py --diff` from the repository root.
3. If you discover a security issue or vulnerability that is not already represented by the current preflight result, run `python3 scripts/redline_finding.py --title "<short title>" --description "<what was found>" --evidence "<file/line or reason>"`. This searches Redline memory first and logs a new `wiki/agent_findings` entry only when the issue appears novel.
4. If preflight returns `REDLINE TRIGGERED`, do not finalize the work until the unsafe code is fixed and preflight passes, or until the user explicitly accepts the risk.
5. If preflight returns `WARNING` or `NEEDS HUMAN REVIEW`, explain the warning and either fix it or state why it is acceptable for the requested scope.

Demo toggle:

- Connected demo: leave `REDLINE_AGENT_GUARD` unset, or set `REDLINE_AGENT_GUARD=on`.
- Without-Redline demo: set `REDLINE_AGENT_GUARD=off` before running the scripts. The scripts will print that Redline is disabled and exit successfully, making the baseline flow easy to show.

The scripts prefer the running backend at `REDLINE_API_BASE_URL` or `http://localhost:8000`, which records demo events such as `agent.context_retrieved` and `preflight.completed`. If the backend is not running, they fall back to local wiki and detector imports so the guard still works, but no backend event is recorded.

## Project Structure & Module Organization

This repository contains Redline planning material, a FastAPI backend, a React/Vite frontend, and trusted wiki source notes for a security-rule MVP.

- `raw_sources/` contains Markdown source notes for safety rules, detector patterns, safe rewrites, observed violations, and regression-test seeds.
- `raw_sources/README.md` identifies recommended MVP demo rules.
- `docs/` contains project PDFs used as source material.
- `backend/` contains FastAPI endpoints, detectors, memory adapters, and tests.
- `frontend/` contains the React/Vite demo UI.
- `wiki/` contains generated safety rules, observed violations, and regression tests.
- `scripts/` contains agent-facing Redline guardrail commands.

## Build, Test, and Development Commands

Useful validation commands are:

- `find . -maxdepth 2 -type f | sort` to review repository contents.
- `python -m pip install -r backend/requirements.txt` to install backend dependencies.
- `uvicorn app.main:app --reload` from `backend/` to run the API.
- `npm install && npm run dev` from `frontend/` to run the UI.
- `PYTHONPATH=backend pytest backend/tests` to run backend tests.
- `npm run build` from `frontend/` to validate the frontend.
- `python3 scripts/redline_context.py "<task>"` to retrieve LLM wiki context.
- `python3 scripts/redline_preflight.py --diff` to check proposed code changes.
- `python3 scripts/redline_finding.py --title "<title>" --description "<description>"` to search prior Redline findings and log a novel security issue.

Do not add new tooling unless it supports the stack already specified in `init-prompt.md`.

## Coding Style & Naming Conventions

Use Python for backend modules and TypeScript/React for frontend modules. Prefer small, explicit modules matching the planned names, such as `detectors.py`, `rule_store.py`, `RuleIngestPanel.tsx`, and `PreflightPanel.tsx`.

For Markdown source files, use lowercase snake_case filenames, concise headings, and direct rule language. Do not invent security rules beyond `docs/`, `raw_sources/`, or user-ingested rules.

## Testing Guidelines

When code is added, create focused tests under `tests/` or the relevant app test directory. Backend tests should cover rule ingestion, detector matching, preflight verdicts, safe rewrites, and fallback behavior when Redis or Cognee is unavailable. Regression tests should be seeded from `raw_sources/` and generated violation examples.

## Commit & Pull Request Guidelines

This directory is not currently a Git repository, so no local commit convention can be inferred. Use concise, imperative commit subjects such as `Add SQL injection detector` or `Document rule source workflow`.

Pull requests should include a summary, test results, linked issue or task context, and screenshots for UI changes. For security-rule changes, identify the exact source file or PDF section supporting the rule.

## Security & Configuration Tips

Keep secrets out of the repository. Use `.env.example` for required variables and local `.env` files for real values. If a security judgment is uncertain, return `NEEDS HUMAN REVIEW` rather than guessing.
