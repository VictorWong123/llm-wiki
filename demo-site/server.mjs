import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL(".", import.meta.url));
const port = Number.parseInt(process.env.DEMO_PORT ?? "5180", 10);
const host = process.env.DEMO_HOST ?? "127.0.0.1";
const apiBaseUrl = (process.env.REDLINE_API_BASE_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8"
};

function send(response, status, body, headers = {}) {
  response.writeHead(status, headers);
  response.end(body);
}

function safePath(pathname) {
  const requested = pathname === "/" ? "/index.html" : pathname;
  const normalized = normalize(requested).replace(/^(\.\.[/\\])+/, "");
  return join(root, normalized);
}

async function proxyApi(request, response, url) {
  const target = `${apiBaseUrl}${url.pathname.replace(/^\/redline/, "")}${url.search}`;
  const chunks = [];

  for await (const chunk of request) {
    chunks.push(chunk);
  }

  try {
    const upstream = await fetch(target, {
      method: request.method,
      headers: {
        "content-type": request.headers["content-type"] ?? "application/json"
      },
      body: chunks.length ? Buffer.concat(chunks) : undefined
    });

    const body = Buffer.from(await upstream.arrayBuffer());
    send(response, upstream.status, body, {
      "content-type": upstream.headers.get("content-type") ?? "application/json"
    });
  } catch (error) {
    send(
      response,
      502,
      JSON.stringify({
        error: "Redline backend unavailable",
        detail: error instanceof Error ? error.message : "Unknown proxy error",
        apiBaseUrl
      }),
      { "content-type": "application/json; charset=utf-8" }
    );
  }
}

async function serveStatic(_request, response, url) {
  if (url.pathname === "/__demo_health") {
    send(response, 200, JSON.stringify({ status: "ok", apiBaseUrl }), {
      "content-type": "application/json; charset=utf-8"
    });
    return;
  }

  const filePath = safePath(url.pathname);
  if (!filePath.startsWith(root)) {
    send(response, 403, "Forbidden", { "content-type": "text/plain; charset=utf-8" });
    return;
  }

  try {
    const body = await readFile(filePath);
    send(response, 200, body, {
      "content-type": contentTypes[extname(filePath)] ?? "application/octet-stream"
    });
  } catch {
    send(response, 404, "Not found", { "content-type": "text/plain; charset=utf-8" });
  }
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);

  if (url.pathname.startsWith("/redline/")) {
    await proxyApi(request, response, url);
    return;
  }

  await serveStatic(request, response, url);
});

server.listen(port, host, () => {
  console.log(`Redline demo site: http://${host}:${port}`);
  console.log(`Proxying /redline to ${apiBaseUrl}`);
});
