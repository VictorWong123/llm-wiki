---
id: finding_68cdc4cb615d
severity: high
status: NEEDS HUMAN REVIEW
matched_rule_id: raw_input_validation_001
source: agent
created_at: 2026-05-16T21:43:07Z
---

# Agent Security Finding: SSRF risk in URL preview endpoint

## Description
The route fetches a user-controlled URL without scheme, host, IP range, or redirect allowlist checks. Attackers could target internal metadata or private services.

## Evidence
demo-site SSRF scenario: httpx.get(url) is called with the raw request parameter.

## Affected Content
```text
from fastapi import FastAPI
import httpx

app = FastAPI()

@app.get("/preview")
async def preview(url: str):
    response = await httpx.get(url, timeout=5)
    return {"status": response.status_code, "body": response.text[:500]}

```

## Safe Rewrite
```text
from fastapi import FastAPI, HTTPException
from urllib.parse import urlparse
import httpx

app = FastAPI()

ALLOWED_PREVIEW_HOSTS = {"example.com", "docs.example.com"}

@app.get("/preview")
async def preview(url: str):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_PREVIEW_HOSTS:
        raise HTTPException(status_code=400, detail="URL host is not allowed")

    async with httpx.AsyncClient(timeout=5, follow_redirects=False) as client:
        response = await client.get(url)
    return {"status": response.status_code, "body": response.text[:500]}

```

## Notes
This finding was logged by an agent after checking Redline memory for prior similar issues.
