# Redline Agent Guard Notes

Use this when you open Codex in or around `demo-site` and want to remember what the Redline guard commands do.

## `python3 scripts/redline_context.py "<user task>"`

Run this before an agent writes or changes code.

What it does:

- Takes the task description you give it.
- Searches the Redline wiki safety rules for rules that are relevant to that task.
- Prints the rules the coding agent should keep in mind before editing.
- Tries to call the Redline backend at `http://localhost:8000`.
- If the backend is not running, falls back to local wiki files under `wiki/safety_rules`.

Example:

```bash
python3 scripts/redline_context.py "Add a user lookup endpoint that queries by email"
```

For a SQL-related task, it should surface the SQL injection rule and remind the agent to use parameterized queries.

## `python3 scripts/redline_preflight.py --diff`

Run this after the agent edits code, before finalizing the work.

What it does:

- Reads the current git diff.
- Extracts added production-code lines.
- Sends those changes to Redline preflight.
- If the backend is not running, falls back to local deterministic detectors.
- Prints a verdict such as `PASS`, `WARNING`, `NEEDS HUMAN REVIEW`, or `REDLINE TRIGGERED`.
- Exits with a failing status code when Redline is triggered.

Example:

```bash
python3 scripts/redline_preflight.py --diff
```

If the diff adds code like this:

```python
query = f"SELECT * FROM users WHERE email = '{email}'"
```

Redline should return `REDLINE TRIGGERED` because the SQL query interpolates a user-controlled value. The agent should then fix it before finalizing.

## Important Caveats

Run these commands from the repository root:

```bash
cd /Users/victorwong/Downloads/redline
```

If you start Codex from `demo-site`, use:

```bash
cd .. && python3 scripts/redline_context.py "<user task>"
cd .. && python3 scripts/redline_preflight.py --diff
```

Normal `--diff` preflight skips docs, tests, wiki files, raw source examples, and Markdown. To intentionally scan those too, use:

```bash
python3 scripts/redline_preflight.py --diff --include-tests-docs
```

The guard can be disabled for the intentional without-Redline demo path:

```bash
REDLINE_AGENT_GUARD=off python3 scripts/redline_context.py "<user task>"
REDLINE_AGENT_GUARD=off python3 scripts/redline_preflight.py --diff
```

For real coding work, leave `REDLINE_AGENT_GUARD` unset or set it to `on`.
