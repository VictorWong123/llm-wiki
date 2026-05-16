# Demo Site Agent Instructions

This folder is a mock app used to demonstrate Redline. It is separate from the main Redline frontend, but real code changes in this folder must still use the parent repository's Redline guard.

Before editing code, run from this folder:

```bash
cd .. && python3 scripts/redline_context.py "<user task>"
```

After editing code, run from this folder:

```bash
cd .. && python3 scripts/redline_preflight.py --diff
```

If Redline returns `REDLINE TRIGGERED`, fix the unsafe code before finalizing unless the user explicitly says they are running the without-Redline demo path.

The intentional live demo prompts are:

- Add customer search by company, email domain, and plan.
- Add vendor website preview from a pasted URL.

Do not add those features unless the user asks for them during the demo.
