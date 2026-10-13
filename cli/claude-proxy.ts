// Claude route of the loopback Router proxy. Linux runners reach it through an
// authenticated reverse SSH tunnel, so Claude Code there can use the Mac's
// ACTIVE Claude subscription without ever holding its credentials.
//
// The client authenticates to Router with the proxy's separate client token
// (checked in codex-proxy.ts before this runs). Router then substitutes the
// selected profile's OAuth access token. The Mac stays the only refresh
// authority: no refresh token, and no access token, is ever sent to a client.
import { gzip } from "node:zlib";
import { promisify } from "node:util";
import { claudeTransport } from "./claude-transport.ts";
import { SignedOutError } from "./common.ts";
import type { ProxyObservation } from "./codex-proxy.ts";

const gzipAsync = promisify(gzip);

export type ClaudeCredential = { name: string; accessToken: string };
export type ClaudeRouteOptions = {
  // `refresh` is true only after Anthropic rejected `name`'s token. It returns
  // the same token when nothing newer exists; the 401 is then passed through.
  credential: (name?: string, refresh?: boolean) => Promise<ClaudeCredential>;
  upstream?: typeof fetch;
  meter?: (credential: ClaudeCredential, signal?: AbortSignal) => Promise<(response: Response) => Response>;
};

// The ONLY Claude endpoints a runner can reach. Claude Code 2.1.28x-2.1.29x
// sends inference to /v1/messages?beta=true and token counting to
// /v1/messages/count_tokens?beta=true (probed 2026-10-13). Everything else,
// including the OAuth profile/usage/token endpoints, stays denied.
export const CLAUDE_ROUTES = new Set(["/v1/messages", "/v1/messages/count_tokens"]);
const OAUTH_BETA = "oauth-2025-04-20";
const UPSTREAM = "https://api.anthropic.com";

// REASON: an allowlist, not a denylist. The client's own `authorization`,
// `x-api-key`, `x-router-token`, cookies and any future credential header
// must never reach Anthropic next to the substituted subscription token, and
// `host`/hop-by-hop headers belong to this hop. Copying "everything except
// auth" would leak whatever new auth header a client adds later.
const FORWARD = ["accept", "content-type", "content-encoding", "user-agent", "anthropic-version",
  "x-app", "x-claude-code-session-id", "x-client-request-id"];

// OAuth subscription tokens are only accepted on the Messages API with the
// oauth beta. A client using ANTHROPIC_AUTH_TOKEN (API mode) does not send it,
// so merge it into whatever betas the client asked for, keeping their order.
export function mergeBetas(client: string | null): string {
  const betas = (client ?? "").split(",").map((b) => b.trim()).filter(Boolean);
  if (!betas.includes(OAUTH_BETA)) betas.push(OAUTH_BETA);
  return [...new Set(betas)].join(",");
}

const anthropicError = (status: number, type: string, message: string) =>
  Response.json({ type: "error", error: { type, message } }, { status });

export async function forwardClaude(request: Request, url: URL, options: ClaudeRouteOptions & { observe: (event: ProxyObservation) => void }): Promise<Response> {
  const upstream = options.upstream ?? claudeTransport;
  let credential: ClaudeCredential;
  try { credential = await options.credential(); }
  catch (e) {
    if (e instanceof SignedOutError) return anthropicError(401, "authentication_error", `Router account ${e.message}; no other account was used`);
    return anthropicError(503, "api_error", "Selected Router Claude account is unavailable on the Mac; run router doctor there");
  }
  let metered = (response: Response) => response;
  if (url.pathname === "/v1/messages" && options.meter) {
    try { metered = await options.meter(credential, request.signal); }
    catch { return anthropicError(503, "api_error", "Router could not verify usage attribution. Open Router to refresh subscription access."); }
  }
  const headers = new Headers();
  for (const [name, value] of request.headers) {
    if (FORWARD.includes(name) || name.startsWith("x-stainless-")) headers.set(name, value);
  }
  headers.set("anthropic-beta", mergeBetas(request.headers.get("anthropic-beta")));
  const sessionHeader = request.headers.get("x-claude-code-session-id");
  const session = sessionHeader && /^[a-zA-Z0-9_-]{1,128}$/.test(sessionHeader) ? sessionHeader : null;
  let body: ArrayBuffer | Uint8Array | undefined;
  let bytes = 0;
  const started = Date.now();
  // Observations carry route, status, profile and sizes only: never prompts,
  // responses, headers or tokens.
  const metadata = () => ({ provider: "claude" as const, path: url.pathname, session, bytes, wireBytes: body?.byteLength ?? 0,
    elapsedMs: Date.now() - started, encoding: headers.get("content-encoding")?.slice(0, 24) ?? null, at: new Date().toISOString() });
  try {
    body = await request.arrayBuffer();
    bytes = body.byteLength;
    // REASON: Claude Code histories routinely exceed several MB and large
    // uploads over one long HTTP/2 stream reset intermittently. Anthropic
    // accepts gzip request bodies; compress losslessly (same as the metering
    // transport), never trim conversation data, keep a client's own encoding.
    if (bytes >= 4096 && !headers.has("content-encoding")) {
      const compressed = await gzipAsync(new Uint8Array(body));
      if (compressed.byteLength < bytes) { body = compressed; headers.set("content-encoding", "gzip"); }
    }
    // Fixed upstream origin; only the allowlisted path and its query (?beta=true) come from the client.
    const target = new URL(`${UPSTREAM}${url.pathname}${url.search}`);
    const send = (token: string) => {
      headers.set("authorization", `Bearer ${token}`);
      return upstream(target, { method: "POST", headers, body, redirect: "error", signal: request.signal });
    };
    request.signal.throwIfAborted();
    let response = await send(credential.accessToken);
    // Retry only an authentication rejection, before any byte is streamed, and
    // only on the SAME profile even if the Mac's selection changed meanwhile.
    // 429 and every other status pass through untouched: Claude Code honors
    // retry-after itself, and silently spending another account is not ours to do.
    if (response.status === 401) {
      let renewed: ClaudeCredential | null = null;
      try { renewed = await options.credential(credential.name, true); }
      catch (e) {
        await response.body?.cancel();
        options.observe({ profile: credential.name, ...metadata(), status: 401, failure: "renewal_failed" });
        return metered(e instanceof SignedOutError ? anthropicError(401, "authentication_error", `Router account ${e.message}; no other account was used`)
          : anthropicError(401, "authentication_error", `Router could not renew the Claude sign-in for "${credential.name}"; no other account was used`));
      }
      // REASON: an unchanged token means Router had nothing newer (e.g. the
      // main login is unexpired, so the rejection is not about expiry). Do not
      // replay; return Anthropic's own 401 so the real reason stays visible.
      if (renewed.accessToken !== credential.accessToken) {
        await response.body?.cancel();
        credential = renewed;
        response = await send(credential.accessToken);
      }
    }
    options.observe({ profile: credential.name, ...metadata(), status: response.status });
    const outgoing = new Headers(response.headers);
    // The transport requests identity response bytes; framing belongs to Bun.
    for (const name of ["content-encoding", "content-length", "transfer-encoding", "connection", "set-cookie", "x-router-upload-attempts"]) outgoing.delete(name);
    outgoing.set("cache-control", "no-store");
    outgoing.set("x-router-profile", credential.name);
    return metered(new Response(response.body, { status: response.status, headers: outgoing }));
  } catch (error) {
    // Store only a bounded error code, never error.message (it can contain request data).
    const code = (error as { code?: unknown })?.code;
    const failure = request.signal.aborted ? "client_canceled"
      : typeof code === "string" && /^[A-Z_0-9]{1,64}$/.test(code) ? code : "transport_error";
    const status = request.signal.aborted ? 499 : 502;
    options.observe({ profile: credential.name, ...metadata(), status, failure });
    return metered(anthropicError(status, "api_error", status === 499 ? "Router request canceled by client"
      : `Router could not reach Claude for "${credential.name}" (${failure}); retry this request. No other account was used.`));
  }
}
