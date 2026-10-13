import { expect, test } from "bun:test";
import { gunzipSync } from "node:zlib";
import { createProxyHandler, type ProxyCredential, type ProxyObservation } from "./codex-proxy.ts";
import { mergeBetas, type ClaudeCredential } from "./claude-proxy.ts";
import { SignedOutError } from "./common.ts";

const codexAccount: ProxyCredential = { name: "c", accessToken: "codex-secret", accountId: "acct" };
const claude: Record<string, ClaudeCredential> = {
  main: { name: "main", accessToken: "mac-token-main" },
  other: { name: "other", accessToken: "mac-token-other" },
};
const PROMPT = "private prompt text";
const messages = (extra: Record<string, string> = {}, body = JSON.stringify({ model: "m", messages: [{ role: "user", content: PROMPT }] }), path = "/v1/messages?beta=true") =>
  new Request(`http://127.0.0.1:18789${path}`, { method: "POST", body, headers: {
    authorization: "Bearer local", "content-type": "application/json", "anthropic-version": "2023-06-01",
    "anthropic-beta": "claude-code-20250219,interleaved-thinking-2025-05-14", "x-app": "cli", "x-claude-code-session-id": "sess-1", ...extra } });

function setup(options: { upstream: typeof fetch; credential?: (name?: string, refresh?: boolean) => Promise<ClaudeCredential>; withClaude?: boolean }) {
  const observed: ProxyObservation[] = [];
  const handler = createProxyHandler({ token: "local", credential: async () => codexAccount, observe: (e) => observed.push(e),
    upstream: (async () => new Response("codex")) as typeof fetch,
    claude: options.withClaude === false ? undefined : { credential: options.credential ?? (async () => claude.main!), upstream: options.upstream } });
  return { handler, observed };
}

test("forwards messages to Anthropic with the Mac token, stripping every client credential", async () => {
  const seen: { url: string; headers: Headers }[] = [];
  const { handler, observed } = setup({ upstream: (async (url, init) => {
    seen.push({ url: String(url), headers: new Headers(init!.headers) });
    return new Response("data: {}\n\n", { headers: { "content-type": "text/event-stream", "set-cookie": "x=y" } });
  }) as typeof fetch });
  const ok = await handler(messages({ "x-api-key": "client-key", cookie: "c=1", "proxy-authorization": "p" }));
  expect(ok.status).toBe(200);
  expect(ok.headers.get("x-router-profile")).toBe("main");
  expect(ok.headers.get("set-cookie")).toBeNull();
  expect(seen).toHaveLength(1);
  expect(seen[0]!.url).toBe("https://api.anthropic.com/v1/messages?beta=true");
  const h = seen[0]!.headers;
  expect(h.get("authorization")).toBe("Bearer mac-token-main");
  expect(h.get("anthropic-beta")).toBe("claude-code-20250219,interleaved-thinking-2025-05-14,oauth-2025-04-20");
  expect(h.get("anthropic-version")).toBe("2023-06-01");
  expect(h.get("x-claude-code-session-id")).toBe("sess-1");
  for (const name of ["x-api-key", "cookie", "proxy-authorization", "x-router-token", "anthropic-dangerous-direct-browser-access"]) expect(h.get(name)).toBeNull();
  expect(observed.at(-1)).toMatchObject({ provider: "claude", profile: "main", path: "/v1/messages", status: 200, session: "sess-1" });
  const serialized = JSON.stringify(observed);
  expect(serialized).not.toContain("mac-token");
  expect(serialized).not.toContain(PROMPT);
});

test("x-router-token client auth works and the header never reaches Anthropic", async () => {
  let seen: Headers | undefined;
  const { handler } = setup({ upstream: (async (_url, init) => { seen = new Headers(init!.headers); return new Response("{}"); }) as typeof fetch });
  const request = messages({ "x-router-token": "local", authorization: "Bearer client-oauth-token" });
  expect((await handler(request)).status).toBe(200);
  expect(seen!.get("authorization")).toBe("Bearer mac-token-main");
  expect(seen!.get("x-router-token")).toBeNull();
});

test("count_tokens is routed; everything else on the Claude side stays denied", async () => {
  const urls: string[] = [];
  const { handler } = setup({ upstream: (async (url) => { urls.push(String(url)); return new Response("{}"); }) as typeof fetch });
  expect((await handler(messages({}, "{}", "/v1/messages/count_tokens?beta=true"))).status).toBe(200);
  expect(urls).toEqual(["https://api.anthropic.com/v1/messages/count_tokens?beta=true"]);
  for (const path of ["/v1/complete", "/api/oauth/usage", "/v1/oauth/token", "/v1/messages/batches", "/v1/files", "/api/hello"]) {
    expect((await handler(messages({}, "{}", path))).status).toBe(404);
  }
  expect((await handler(new Request("http://127.0.0.1/v1/messages", { method: "GET", headers: { authorization: "Bearer local" } }))).status).toBe(404);
  expect((await handler(messages({ upgrade: "websocket" }))).status).toBe(404);
  expect(urls).toHaveLength(1);
});

test("without a Claude source the proxy stays Codex-only", async () => {
  let calls = 0;
  const { handler } = setup({ withClaude: false, upstream: (async () => { calls++; return new Response("{}"); }) as typeof fetch });
  expect((await handler(messages())).status).toBe(404);
  expect(calls).toBe(0);
});

test("unauthenticated, wrongly authenticated and browser requests never reach Anthropic or read a credential", async () => {
  let calls = 0, reads = 0;
  const { handler } = setup({ credential: async () => { reads++; return claude.main!; },
    upstream: (async () => { calls++; return new Response("{}"); }) as typeof fetch });
  const anonymous = new Request("http://127.0.0.1/v1/messages", { method: "POST", body: "{}" });
  expect((await handler(anonymous)).status).toBe(401);
  expect((await handler(messages({ authorization: "Bearer guessed-token" }))).status).toBe(401);
  expect((await handler(messages({ origin: "https://example.com" }))).status).toBe(401);
  expect(calls).toBe(0);
  expect(reads).toBe(0);
});

test("streams SSE through immediately and unmodified", async () => {
  let controller!: ReadableStreamDefaultController<Uint8Array>;
  const { handler } = setup({ upstream: (async () => new Response(new ReadableStream({ start(c) {
    controller = c; c.enqueue(new TextEncoder().encode("event: message_start\ndata: {\"a\":1}\n\n"));
  } }), { headers: { "content-type": "text/event-stream" } })) as typeof fetch });
  const response = await handler(messages());
  expect(response.headers.get("content-type")).toBe("text/event-stream");
  const reader = response.body!.getReader();
  expect(new TextDecoder().decode((await reader.read()).value)).toBe("event: message_start\ndata: {\"a\":1}\n\n");
  controller.enqueue(new TextEncoder().encode("event: message_stop\ndata: {}\n\n"));
  controller.close();
  expect(new TextDecoder().decode((await reader.read()).value)).toBe("event: message_stop\ndata: {}\n\n");
});

test("429 passes through with its retry headers; no refresh, no other account", async () => {
  let calls = 0, refreshes = 0;
  const { handler } = setup({ credential: async (_n, refresh) => { if (refresh) refreshes++; return claude.main!; },
    upstream: (async () => { calls++; return new Response('{"type":"error"}', { status: 429, headers: { "retry-after": "17", "anthropic-ratelimit-unified-status": "rejected" } }); }) as typeof fetch });
  const response = await handler(messages());
  expect(response.status).toBe(429);
  expect(response.headers.get("retry-after")).toBe("17");
  expect(response.headers.get("anthropic-ratelimit-unified-status")).toBe("rejected");
  expect(calls).toBe(1);
  expect(refreshes).toBe(0);
});

test("a 401 renews the SAME profile once, even if the Mac's selection changed", async () => {
  let selected = "other";
  const tokens: string[] = [];
  const { handler } = setup({
    credential: async (name, refresh) => {
      if (refresh) { expect(name).toBe("other"); return { name: "other", accessToken: "mac-token-other-renewed" }; }
      return claude[name ?? selected]!;
    },
    upstream: (async (_url, init) => {
      tokens.push(new Headers(init!.headers).get("authorization")!);
      selected = "main";
      return new Response("{}", { status: tokens.length === 1 ? 401 : 200 });
    }) as typeof fetch });
  const response = await handler(messages());
  expect(response.status).toBe(200);
  expect(response.headers.get("x-router-profile")).toBe("other");
  expect(tokens).toEqual(["Bearer mac-token-other", "Bearer mac-token-other-renewed"]);
});

test("a 401 with nothing newer to offer passes Anthropic's own 401 through without replay", async () => {
  let calls = 0;
  const { handler } = setup({ credential: async () => claude.main!,
    upstream: (async () => { calls++; return new Response('{"error":"upstream reason"}', { status: 401 }); }) as typeof fetch });
  const response = await handler(messages());
  expect(response.status).toBe(401);
  expect(await response.text()).toContain("upstream reason");
  expect(calls).toBe(1);
});

test("signed-out or unavailable selections fail closed without reaching Anthropic", async () => {
  let calls = 0;
  const upstream = (async () => { calls++; return new Response("{}"); }) as typeof fetch;
  const signedOut = setup({ upstream, credential: async () => { throw new SignedOutError("other"); } });
  const r1 = await signedOut.handler(messages());
  expect(r1.status).toBe(401);
  expect((await r1.json()).error.message).toContain('"other" is signed out');
  const missing = setup({ upstream, credential: async () => { throw new Error("keychain locked: secret detail"); } });
  const r2 = await missing.handler(messages());
  expect(r2.status).toBe(503);
  expect(await r2.text()).not.toContain("secret detail");
  expect(calls).toBe(0);
});

test("large bodies are gzip-compressed losslessly; small ones are sent as-is", async () => {
  const bodies: { encoding: string | null; bytes: Uint8Array }[] = [];
  const { handler, observed } = setup({ upstream: (async (_url, init) => {
    bodies.push({ encoding: new Headers(init!.headers).get("content-encoding"), bytes: new Uint8Array(init!.body as ArrayBuffer) });
    return new Response("{}");
  }) as typeof fetch });
  const large = JSON.stringify({ messages: [{ role: "user", content: "x".repeat(20000) }] });
  await handler(messages({}, large));
  await handler(messages({}, "{}"));
  expect(bodies[0]!.encoding).toBe("gzip");
  expect(gunzipSync(bodies[0]!.bytes).toString()).toBe(large);
  expect(bodies[1]!.encoding).toBeNull();
  expect(observed[0]).toMatchObject({ bytes: large.length, encoding: "gzip" });
});

test("transport failures are a bounded 502 that never leaks the error message", async () => {
  const { handler, observed } = setup({ upstream: (async () => { throw Object.assign(new Error(`boom ${PROMPT}`), { code: "CURL_56" }); }) as typeof fetch });
  const response = await handler(messages());
  expect(response.status).toBe(502);
  expect(await response.text()).not.toContain(PROMPT);
  expect(observed[0]).toMatchObject({ status: 502, failure: "CURL_56", provider: "claude" });
});

test("health advertises the Claude route only when it is configured", async () => {
  const on = setup({ upstream: fetch });
  const off = setup({ upstream: fetch, withClaude: false });
  const get = () => new Request("http://127.0.0.1/health", { headers: { authorization: "Bearer local" } });
  expect((await (await on.handler(get())).json()).claudeRoute).toBe(true);
  expect((await (await off.handler(get())).json()).claudeRoute).toBe(false);
});

test("beta merging keeps client order and adds oauth exactly once", () => {
  expect(mergeBetas(null)).toBe("oauth-2025-04-20");
  expect(mergeBetas("a, b,oauth-2025-04-20,a")).toBe("a,b,oauth-2025-04-20");
});
