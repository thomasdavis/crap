/**
 * @thomasdavis/crap-gateway — a reverse proxy that speaks CRAP in front of an
 * upstream API that does not.
 *
 * Every protocol mechanic — challenges, submissions, proofs, grants — is
 * `CrapServer` from `@thomasdavis/crap-server`; this package adds routing and
 * forwarding only. Challenges are issued and answered at the gateway, and a
 * request reaches the upstream only once the policy is satisfied (or never
 * asked anything of it).
 */

import { request as httpRequest } from 'node:http';
import { request as httpsRequest } from 'node:https';
import { pipeline } from 'node:stream';
import type { IncomingHttpHeaders, IncomingMessage, ServerResponse } from 'node:http';
import {
  CrapServer,
  HEADER_ACCEPT,
  HEADER_INPUT_PROOF,
  SUBMISSION_PATH_PREFIX,
  problemResponse,
  type CrapResponse,
  type CrapServerOptions,
  type RequestContext,
} from '@thomasdavis/crap-server';

export * from '@thomasdavis/crap-server';

/** Options for {@link createGateway}. Every `CrapServer` option passes through. */
export interface CrapGatewayOptions extends CrapServerOptions {
  /**
   * Origin of the API being fronted, e.g. `http://127.0.0.1:4001`. Scheme, host and port
   * only; the incoming request's path and query are appended verbatim.
   */
  upstream: string;
  /**
   * Which requests must satisfy CRAP before they are forwarded. Everything else is
   * proxied untouched. Submissions under /.well-known/input-challenges are always
   * handled locally regardless of this predicate.
   */
  protect(ctx: RequestContext): boolean;
  /**
   * What to do when the CRAP machinery itself fails (a store threw, the policy threw):
   * false (default) refuses with 502; true forwards upstream unchallenged. The live
   * deployment fails open (FINDINGS: "Everything fails open"); a library defaults
   * closed and makes open an explicit choice.
   */
  failOpen?: boolean;
  /** Resolve the authenticated principal, mirroring crapMiddleware's hook. */
  principal?(req: IncomingMessage): string | undefined;
}

/**
 * Hop-by-hop headers (RFC 9110 §7.6.1). They describe one connection, not the message,
 * so a proxy that forwards them is lying about the next hop.
 */
const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

/**
 * Copy `headers` without the fixed hop-by-hop set, anything the `connection` header
 * nominates as connection-scoped (RFC 9110 §7.6.1: split on commas, trim, lowercase),
 * and every `proxy-*` name — proxy-authenticate, proxy-authorization and the legacy
 * proxy-connection are all addressed to an intermediary, none meaningful past it.
 * Used on both directions.
 */
function stripHopByHop(headers: IncomingHttpHeaders): Record<string, string | string[]> {
  const nominated = new Set<string>();
  const connection = headers['connection'];
  const tokens = (Array.isArray(connection) ? connection.join(',') : connection ?? '').split(',');
  for (const token of tokens) {
    const name = token.trim().toLowerCase();
    if (name) nominated.add(name);
  }
  const cleaned: Record<string, string | string[]> = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    const lower = name.toLowerCase();
    if (HOP_BY_HOP.has(lower) || nominated.has(lower) || lower.startsWith('proxy-')) continue;
    cleaned[lower] = value;
  }
  return cleaned;
}

/**
 * Reduce a request target to its origin-form path and query, or null if the client
 * sent anything else.
 *
 * A gateway is the origin server as far as the client is concerned, so origin-form
 * (`/path?query`) is the only shape it has any business accepting. RFC 9112 §3.2.2
 * reserves absolute-form for requests addressed to a forward proxy — a client that
 * was configured to relay through this host — and a gateway is not that. Honouring
 * an authority from the request target would let any unauthenticated caller choose
 * which host we connect to, which is the whole difference between a gateway and an
 * open relay, so those targets are refused rather than rewritten.
 *
 * The prefix test alone is not a complete filter: WHATWG URL strips ASCII tab and
 * newline before parsing, so `/<tab>/evil.example/x` would parse with an authority
 * despite starting with a single slash. Parsing and then keeping only pathname and
 * search means no authority survives from client input, whatever is smuggled in.
 */
function originForm(rawTarget: string, base: string): string | null {
  if (!rawTarget.startsWith('/')) return null;
  if (rawTarget[1] === '/' || rawTarget[1] === '\\') return null;
  try {
    const parsed = new URL(rawTarget, base);
    const path = `${parsed.pathname}${parsed.search}`;
    // The raw prefix test is not enough: dot-segment removal can leave `parsed.pathname`
    // itself starting with `//` (an empty first segment), e.g. `/..//victim/x` collapses
    // to `//victim/x`. Re-based on the upstream with `new URL(path, upstream)`, a leading
    // `//` is a protocol-relative reference and the next token becomes the authority —
    // re-introducing exactly the host-steering this function exists to stop. So the
    // normalised RESULT is checked, not just the input.
    if (path.startsWith('//') || path.startsWith('/\\')) return null;
    return path;
  } catch {
    return null;
  }
}

/** Write one of CrapServer's rendered responses (or a problem document) to the wire. */
function writeCrapResponse(res: ServerResponse, response: CrapResponse): void {
  res.writeHead(response.status, response.headers);
  res.end(response.body);
}

/**
 * Build a request listener that fronts `options.upstream` with CRAP. `issuer` is the
 * GATEWAY's own public origin: challenges and transaction resources live at the
 * gateway, never upstream. Nothing here listens — callers do
 * `createServer(createGateway({...}))`.
 */
export function createGateway(
  options: CrapGatewayOptions,
): (req: IncomingMessage, res: ServerResponse) => void {
  // CrapServer's constructor spreads its options, so the gateway-only keys ride along
  // harmlessly and every server option passes straight through.
  const server = new CrapServer(options);

  const forward = (
    req: IncomingMessage,
    res: ServerResponse,
    body: Buffer,
    path: string,
  ): void => {
    // `path` has already been reduced to origin-form, so the upstream origin is the
    // configured one and nothing the client sent can move it.
    const target = new URL(path, options.upstream);
    const headers = stripHopByHop(req.headers);
    // The proof is the gateway's credential and the negotiation header was answered
    // here; neither means anything upstream and both would leak into upstream logs.
    delete headers[HEADER_INPUT_PROOF];
    delete headers[HEADER_ACCEPT];
    // Node derives host from the target URL; a forwarded Expect would stall upstream
    // waiting for a 100-continue on a body that is already fully in hand.
    delete headers['host'];
    delete headers['expect'];
    if (body.length > 0) {
      headers['content-length'] = String(body.length);
    } else {
      // A stale client content-length on a now-bodiless forward hangs upstream.
      delete headers['content-length'];
    }

    const requestOptions = { method: req.method ?? 'GET', headers };
    const onResponse = (upstreamRes: IncomingMessage): void => {
      // Responses stream; only requests are buffered. The decision needed the whole
      // request body — nothing needs the whole response.
      res.writeHead(upstreamRes.statusCode ?? 502, stripHopByHop(upstreamRes.headers));
      // An upstream that dies part-way through a body it promised does not raise an
      // error on the request, only on this stream. A half-delivered response is not a
      // response, and once the headers are out the only honest thing left is to break
      // the connection rather than leave the client waiting on bytes that will never
      // arrive.
      pipeline(upstreamRes, res, (err) => {
        if (err) res.destroy();
      });
    };
    const upstreamReq =
      target.protocol === 'https:'
        ? httpsRequest(target, requestOptions, onResponse)
        : httpRequest(target, requestOptions, onResponse);

    // A client that walks away takes the upstream leg with it; otherwise the gateway
    // keeps draining a response nobody is listening to.
    res.on('close', () => upstreamReq.destroy());

    upstreamReq.on('error', () => {
      // A dead upstream is always 502. `failOpen` never applies here: it governs
      // failures of the challenge machinery only, and when the origin itself is gone
      // there is nothing to serve either way.
      if (res.headersSent) {
        res.destroy();
      } else {
        writeCrapResponse(res, problemResponse(502, 'Bad Gateway', 'upstream unreachable'));
      }
    });
    upstreamReq.end(body);
  };

  const handle = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    // Settle the request target before anything else looks at it: the path decides
    // which origin is contacted and what `protect()` is shown, so a target carrying
    // its own authority is refused here rather than reinterpreted downstream.
    const path = originForm(req.url ?? '/', options.issuer);
    if (path === null) {
      writeCrapResponse(res, problemResponse(400, 'Bad Request', 'request target must be origin-form'));
      return;
    }

    // The protocol binds proofs to a content digest of the exact body (scope binding),
    // so a protected request cannot be streamed past the decision point: buffer it
    // once, decide, then replay it upstream byte-for-byte. There is deliberately no
    // size cap here — a gateway this small should not own that knob — so an operator
    // wants a body limit in front of it (see README, Failure policy).
    let body: Buffer;
    try {
      const chunks: Buffer[] = [];
      for await (const chunk of req) chunks.push(Buffer.from(chunk));
      body = Buffer.concat(chunks);
    } catch {
      // The client went away (or broke) before anything was decided; there is no
      // coherent response left to write.
      res.destroy();
      return;
    }

    const ctx: RequestContext = {
      method: req.method ?? 'GET',
      target: new URL(path, options.issuer).toString(),
      headers: req.headers,
      principal: options.principal?.(req),
      body: body.length ? body : undefined,
    };

    // The well-known space is the gateway's own: challenge transaction resources exist
    // here and nowhere upstream, so nothing under the prefix is ever proxied.
    const wellKnown = new URL(ctx.target).pathname.startsWith(`${SUBMISSION_PATH_PREFIX}/`);
    if (wellKnown && ctx.method.toUpperCase() !== 'POST') {
      writeCrapResponse(res, problemResponse(404, 'Not Found', 'not a challenge transaction resource'));
      return;
    }

    try {
      if (wellKnown || options.protect(ctx)) {
        const result = await server.handle(ctx);
        if (result.kind === 'respond') {
          // Every challenge, every submission outcome, every deny — all served
          // locally; upstream is untouched.
          writeCrapResponse(res, result.response);
          return;
        }
        // kind === 'allow': fall through to forward. `result.satisfied` is
        // deliberately dropped — nothing derived from the answers is forwarded,
        // because headers end up in upstream logs.
      }
    } catch {
      // The challenge machinery itself failed (a store threw, the policy or `protect`
      // threw). This — and only this — is what `failOpen` governs: true forwards
      // unchallenged; the default refuses without contacting upstream. Submissions
      // always fail closed: the transaction resource is the gateway's, so there is
      // nothing upstream to fail open to.
      if (!options.failOpen || wellKnown) {
        writeCrapResponse(res, problemResponse(502, 'Bad Gateway', 'challenge machinery unavailable'));
        return;
      }
    }

    forward(req, res, body, path);
  };

  return (req, res) => {
    void handle(req, res).catch(() => {
      // handle() only rejects if a write itself failed; tear the socket down rather
      // than guess at the response's state.
      res.destroy();
    });
  };
}
