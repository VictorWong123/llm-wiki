# Repository Guidelines

## Project Structure & Module Organization

This repository currently contains Redline planning material and trusted source notes for a security-rule MVP.

- `init-prompt.md` defines the intended Redline product, stack, endpoints, and future app layout.
- `raw_sources/` contains Markdown source notes for safety rules, detector patterns, safe rewrites, observed violations, and regression-test seeds.
- `raw_sources/README.md` identifies recommended MVP demo rules.
- `docs/` contains project PDFs used as source material.

If implementation begins, follow the structure specified in `init-prompt.md`: `backend/` for FastAPI code, `frontend/` for React/Vite UI code, and `wiki/` for generated rule artifacts.

## Build, Test, and Development Commands

There is no executable app in the current repository, so there are no build or test commands yet. Useful validation commands are:

- `find . -maxdepth 2 -type f | sort` to review repository contents.
- `python -m pip install -r backend/requirements.txt` once `backend/` exists.
- `uvicorn app.main:app --reload` from `backend/` once FastAPI code exists.
- `npm install && npm run dev` from `frontend/` once the Vite app exists.

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
