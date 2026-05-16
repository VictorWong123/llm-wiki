# Redline Agent Guard

This repository demos an LLM wiki that must inform coding agents before they write or change code.

For every code change task, Claude must:

1. Run `python3 scripts/redline_context.py "<user task>"` from the repository root before editing code.
2. Use the returned Redline wiki rules as security context while implementing.
3. Run `python3 scripts/redline_preflight.py --diff` from the repository root after editing.
4. If Claude discovers a security issue or vulnerability that is not already represented by the current preflight result, run `python3 scripts/redline_finding.py --title "<short title>" --description "<what was found>" --evidence "<file/line or reason>"`. This searches Redline memory first and logs a new `wiki/agent_findings` entry only when the issue appears novel.
5. Fix any `REDLINE TRIGGERED` result before finalizing, unless the user explicitly accepts the risk.
6. Explain any `WARNING` or `NEEDS HUMAN REVIEW` result before finalizing.

Demo modes:

- Connected demo: leave `REDLINE_AGENT_GUARD` unset, or set `REDLINE_AGENT_GUARD=on`.
- Without-Redline demo: set `REDLINE_AGENT_GUARD=off`. The scripts will print that Redline is disabled and exit successfully.

The scripts prefer the running Redline backend at `REDLINE_API_BASE_URL` or `http://localhost:8000`, which records demo events such as `agent.context_retrieved` and `preflight.completed`. If the backend is not running, they fall back to local wiki and detector imports.
