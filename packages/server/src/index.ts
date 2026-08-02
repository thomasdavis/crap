/**
 * @crap-protocol/server — issue challenges, validate answers, mint scoped proofs.
 *
 * Transport-neutral core plus a thin Node `http` adapter. The core knows
 * nothing about frameworks: you hand it a description of the request and it
 * hands back a decision.
 */

import { createHmac, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import {
  ASSURANCE_ORDER,
  CRAP_VERSION,
  HEADER_ACCEPT,
  HEADER_CHALLENGE_ID,
  HEADER_INPUT_PROOF,
  PROBLEM_MEDIA_TYPE,
  PROBLEM_TYPE,
  RESPONSE_MEDIA_TYPE,
  STATUS_COMPAT,
  STATUS_INPUT_REQUIRED,
  assuranceAtLeast,
  isExpired,
  validateValue,
  type Assurance,
  type Challenge,
  type ChallengeResponse,
  type InputRequest,
  type ProblemDocument,
  type ValidationError,
} from '@crap-protocol/schema';

export * from '@crap-protocol/schema';

/** The request, reduced to what a policy decision actually needs. */
export interface RequestContext {
  method: string;
  /** Absolute URI of the target resource. */
  target: string;
  headers: Record<string, string | string[] | undefined>;
  /** Authenticated principal, if your auth layer resolved one. */
  principal?: string;
  /** Raw body, when there is one — used for request binding. */
  body?: Buffer | string;
}

export type Decision =
  | { kind: 'allow' }
  | { kind: 'deny'; reason: string }
  | { kind: 'input_required'; requests: InputRequest[]; detail?: string; ttlSeconds?: number };

export const allow = (): Decision => ({ kind: 'allow' });
export const deny = (reason: string): Decision => ({ kind: 'deny', reason });
export const inputRequired = (
  requests: InputRequest[],
  opts: { detail?: string; ttlSeconds?: number } = {},
): Decision => ({ kind: 'input_required', requests, ...opts });

/** An answer that survived validation, with how much it is worth. */
export interface GradedAnswer {
  value: unknown;
  assurance: Assurance;
}

export interface SatisfiedInput {
  challengeId: string;
  answers: Record<string, GradedAnswer>;
  declined: string[];
  principal?: string;
  round: number;
}

export interface ProofVerifier {
  /**
   * Verify one `proof` mode answer. Return the assurance it earns, or null to
   * reject. Default policy: reject everything, because an unverified proof is
   * just a string that says "proof".
   */
  (input: {
    request: InputRequest;
    answer: unknown;
    context: RequestContext;
    challenge: Challenge;
  }): Promise<Assurance | null> | Assurance | null;
}

export interface ChallengeStore {
  put(challenge: Challenge): Promise<void>;
  get(id: string): Promise<Challenge | undefined>;
  /** Mark consumed. Must return false if it was already consumed (replay). */
  consume(id: string): Promise<boolean>;
}

/** Default in-process store. Fine for one node; swap for Redis in a fleet. */
export class MemoryChallengeStore implements ChallengeStore {
  private live = new Map<string, { challenge: Challenge; consumed: boolean }>();

  async put(challenge: Challenge): Promise<void> {
    this.live.set(challenge.id, { challenge, consumed: false });
    this.sweep();
  }

  async get(id: string): Promise<Challenge | undefined> {
    return this.live.get(id)?.challenge;
  }

  async consume(id: string): Promise<boolean> {
    const entry = this.live.get(id);
    if (!entry || entry.consumed) return false;
    entry.consumed = true;
    return true;
  }

  private sweep(): void {
    const now = new Date();
    for (const [id, entry] of this.live) {
      if (isExpired(entry.challenge, now)) this.live.delete(id);
    }
  }
}

export interface CrapServerOptions {
  /** Absolute origin of this server, e.g. `https://data.example`. */
  issuer: string;
  /** Secret used to mint continuation proofs. Rotate it like any other key. */
  secret: string | Buffer;
  /** Your policy. Return allow / deny / input_required. */
  evaluate(ctx: RequestContext, satisfied?: SatisfiedInput): Promise<Decision> | Decision;
  store?: ChallengeStore;
  verifyProof?: ProofVerifier;
  /** Seconds a challenge stays answerable. Default 900. */
  ttlSeconds?: number;
  /** Consecutive challenges allowed for one operation before a hard 403. Default 3. */
  maxRounds?: number;
  /** Seconds an issued Input-Proof is good for. Default 300. */
  proofTtlSeconds?: number;
  policyVersion?: string;
}

export interface CrapResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** What `handle()` tells the caller to do next. */
export type HandleResult =
  | { kind: 'allow'; satisfied?: SatisfiedInput }
  | { kind: 'respond'; response: CrapResponse };

export class CrapServer {
  private readonly opts: Required<Omit<CrapServerOptions, 'policyVersion'>> & { policyVersion?: string };

  constructor(options: CrapServerOptions) {
    this.opts = {
      store: new MemoryChallengeStore(),
      verifyProof: () => null,
      ttlSeconds: 900,
      maxRounds: 3,
      proofTtlSeconds: 300,
      ...options,
    } as Required<Omit<CrapServerOptions, 'policyVersion'>> & { policyVersion?: string };
  }

  /**
   * The whole protocol, one call. Feed it every request to a protected
   * resource; it returns either "allow, carry on" or a response to send.
   */
  async handle(ctx: RequestContext): Promise<HandleResult> {
    const contentType = header(ctx.headers, 'content-type') ?? '';
    if (contentType.startsWith(RESPONSE_MEDIA_TYPE)) {
      return { kind: 'respond', response: await this.submit(ctx) };
    }

    const proof = header(ctx.headers, HEADER_INPUT_PROOF);
    let satisfied: SatisfiedInput | undefined;
    if (proof) {
      const verified = this.verifyInputProof(proof, ctx);
      if (!verified.ok) {
        return { kind: 'respond', response: problemResponse(STATUS_COMPAT, 'Invalid Input Proof', verified.reason) };
      }
      satisfied = verified.satisfied;
    }

    const decision = await this.opts.evaluate(ctx, satisfied);
    if (decision.kind === 'allow') return { kind: 'allow', satisfied };
    if (decision.kind === 'deny') {
      return { kind: 'respond', response: problemResponse(STATUS_COMPAT, 'Forbidden', decision.reason) };
    }

    const round = (satisfied?.round ?? 0) + 1;
    const maxRounds = this.opts.maxRounds;
    if (round > maxRounds) {
      return {
        kind: 'respond',
        response: problemResponse(
          STATUS_COMPAT,
          'Forbidden',
          `challenge limit reached after ${maxRounds} rounds`,
        ),
      };
    }

    const challenge = await this.issue(ctx, decision, round);
    return { kind: 'respond', response: this.challengeResponse(ctx, challenge, decision.detail) };
  }

  /** Build and persist a challenge bound to this exact request. */
  async issue(ctx: RequestContext, decision: Extract<Decision, { kind: 'input_required' }>, round = 1): Promise<Challenge> {
    const ttl = decision.ttlSeconds ?? this.opts.ttlSeconds;
    const now = new Date();
    const challenge: Challenge = {
      id: `ch_${randomBytes(12).toString('base64url')}`,
      version: CRAP_VERSION,
      issuer: this.opts.issuer,
      issued_at: now.toISOString(),
      expires_at: new Date(now.getTime() + ttl * 1000).toISOString(),
      request_state: randomBytes(24).toString('base64url'),
      scope: {
        method: ctx.method.toUpperCase(),
        target: ctx.target,
        principal: ctx.principal,
        ...(ctx.body !== undefined && ctx.body !== null && ctx.body.length
          ? { request_digest: digest(ctx.body) }
          : {}),
      },
      input_requests: decision.requests,
      submission: {
        method: 'POST',
        target: ctx.target,
        content_type: RESPONSE_MEDIA_TYPE,
      },
      continuation: { mode: 'retry-original-request' },
      max_rounds: this.opts.maxRounds,
      round,
      ...(this.opts.policyVersion ? { policy_version: this.opts.policyVersion } : {}),
    };
    await this.opts.store.put(challenge);
    return challenge;
  }

  /**
   * Render a challenge, honouring capability negotiation: native 430 only for
   * clients that said they understand it, 403 + problem+json for everyone else.
   */
  challengeResponse(ctx: RequestContext, challenge: Challenge, detail?: string): CrapResponse {
    const accepts = (header(ctx.headers, HEADER_ACCEPT) ?? '').includes(`v=${CRAP_VERSION}`);
    const status = accepts ? STATUS_INPUT_REQUIRED : STATUS_COMPAT;
    const problem: ProblemDocument = {
      type: PROBLEM_TYPE,
      title: 'Input Required',
      status,
      detail: detail ?? 'This resource has questions that must be answered before it can be served.',
      instance: ctx.target,
      challenge,
    };
    return {
      status,
      headers: {
        'content-type': PROBLEM_MEDIA_TYPE,
        'cache-control': 'no-store',
        [HEADER_CHALLENGE_ID]: challenge.id,
        link: `<${challenge.submission.target}>; rel="https://crap.donto.org/rels/submit-input"`,
      },
      body: JSON.stringify(problem, null, 2),
    };
  }

  /** Handle a POST of `application/crap-response+json`. */
  async submit(ctx: RequestContext): Promise<CrapResponse> {
    let parsed: ChallengeResponse;
    try {
      parsed = JSON.parse(typeof ctx.body === 'string' ? ctx.body : (ctx.body ?? Buffer.alloc(0)).toString('utf8'));
    } catch {
      return problemResponse(400, 'Bad Request', 'submission body is not valid JSON');
    }

    const challenge = await this.opts.store.get(parsed.challenge_id);
    if (!challenge) return problemResponse(STATUS_COMPAT, 'Unknown Challenge', 'no such challenge');
    if (isExpired(challenge)) return problemResponse(STATUS_COMPAT, 'Challenge Expired', 'challenge has expired');

    // Binding: the answers must come back for the same request, from the same
    // principal, with the nonce we handed out.
    if (!safeEqual(parsed.request_state, challenge.request_state)) {
      return problemResponse(STATUS_COMPAT, 'Invalid Submission', 'request_state mismatch');
    }
    if (challenge.scope.principal && challenge.scope.principal !== ctx.principal) {
      return problemResponse(STATUS_COMPAT, 'Invalid Submission', 'principal mismatch');
    }
    if (normaliseTarget(challenge.submission.target) !== normaliseTarget(ctx.target)) {
      return problemResponse(STATUS_COMPAT, 'Invalid Submission', 'submitted to the wrong target');
    }

    const declined = parsed.declined ?? [];
    const answers: Record<string, GradedAnswer> = {};
    const errors: ValidationError[] = [];

    for (const request of challenge.input_requests) {
      if (declined.includes(request.id)) {
        if (request.required) {
          errors.push({ path: `/${request.id}`, message: 'declined but required' });
        }
        continue;
      }
      const raw = parsed.input_responses?.[request.id];
      if (raw === undefined) {
        if (request.required) errors.push({ path: `/${request.id}`, message: 'missing required answer' });
        continue;
      }

      if (request.mode === 'form') {
        const schemaErrors = validateValue(raw, request.schema ?? {}, `/${request.id}`);
        if (schemaErrors.length) {
          errors.push(...schemaErrors);
          continue;
        }
        answers[request.id] = { value: raw, assurance: 'A0' };
      } else {
        const assurance = await this.opts.verifyProof({ request, answer: raw, context: ctx, challenge });
        if (!assurance) {
          errors.push({ path: `/${request.id}`, message: 'evidence rejected' });
          continue;
        }
        answers[request.id] = { value: raw, assurance };
      }

      const want = request.min_assurance;
      const got = answers[request.id]?.assurance;
      if (want && got && !assuranceAtLeast(got, want)) {
        errors.push({
          path: `/${request.id}`,
          message: `assurance ${got} below required ${want}`,
        });
        delete answers[request.id];
      }
    }

    if (errors.length) {
      return {
        ...problemResponse(422, 'Unprocessable Content', 'one or more answers were rejected'),
        body: JSON.stringify(
          {
            type: `${PROBLEM_TYPE}#rejected`,
            title: 'Unprocessable Content',
            status: 422,
            detail: 'one or more answers were rejected',
            errors,
          },
          null,
          2,
        ),
      };
    }

    // One-shot: a challenge cannot be answered twice.
    if (!(await this.opts.store.consume(challenge.id))) {
      return problemResponse(STATUS_COMPAT, 'Replay', 'challenge already answered');
    }

    const satisfied: SatisfiedInput = {
      challengeId: challenge.id,
      answers,
      declined,
      principal: ctx.principal,
      round: challenge.round,
    };
    const proof = this.mintInputProof(challenge, satisfied);

    return {
      status: 204,
      headers: {
        [HEADER_INPUT_PROOF]: proof,
        'cache-control': 'no-store',
      },
      body: '',
    };
  }

  /**
   * A continuation proof is a signed, scoped, expiring statement that these
   * answers were accepted for this exact request. It is not a session token
   * and must not be usable as one.
   */
  mintInputProof(challenge: Challenge, satisfied: SatisfiedInput): string {
    const payload = {
      v: CRAP_VERSION,
      cid: challenge.id,
      iss: this.opts.issuer,
      sub: satisfied.principal ?? null,
      method: challenge.scope.method,
      target: normaliseTarget(challenge.scope.target),
      digest: challenge.scope.request_digest ?? null,
      round: challenge.round,
      exp: Math.floor(Date.now() / 1000) + this.opts.proofTtlSeconds,
      ans: Object.fromEntries(
        Object.entries(satisfied.answers).map(([k, a]) => [k, { v: a.value, a: a.assurance }]),
      ),
      dec: satisfied.declined,
    };
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    return `${body}.${this.sign(body)}`;
  }

  verifyInputProof(
    token: string,
    ctx: RequestContext,
  ): { ok: true; satisfied: SatisfiedInput } | { ok: false; reason: string } {
    const [body, sig] = token.split('.');
    if (!body || !sig) return { ok: false, reason: 'malformed proof' };
    if (!safeEqual(sig, this.sign(body))) return { ok: false, reason: 'bad signature' };

    let payload: any;
    try {
      payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    } catch {
      return { ok: false, reason: 'unreadable proof' };
    }

    if (payload.v !== CRAP_VERSION) return { ok: false, reason: 'unsupported proof version' };
    if (payload.iss !== this.opts.issuer) return { ok: false, reason: 'proof issued by another origin' };
    if (typeof payload.exp !== 'number' || payload.exp * 1000 <= Date.now()) {
      return { ok: false, reason: 'proof expired' };
    }
    // The binding that stops a GET proof opening a DELETE.
    if (payload.method !== ctx.method.toUpperCase()) return { ok: false, reason: 'method mismatch' };
    if (payload.target !== normaliseTarget(ctx.target)) return { ok: false, reason: 'target mismatch' };
    if ((payload.sub ?? null) !== (ctx.principal ?? null)) return { ok: false, reason: 'principal mismatch' };
    if (payload.digest && ctx.body !== undefined && payload.digest !== digest(ctx.body)) {
      return { ok: false, reason: 'body digest mismatch' };
    }

    const answers: Record<string, GradedAnswer> = {};
    for (const [k, a] of Object.entries(payload.ans ?? {})) {
      const entry = a as { v: unknown; a: Assurance };
      if (!ASSURANCE_ORDER.includes(entry.a)) return { ok: false, reason: 'unknown assurance level' };
      answers[k] = { value: entry.v, assurance: entry.a };
    }

    return {
      ok: true,
      satisfied: {
        challengeId: payload.cid,
        answers,
        declined: payload.dec ?? [],
        principal: ctx.principal,
        round: payload.round ?? 1,
      },
    };
  }

  private sign(body: string): string {
    return createHmac('sha256', this.opts.secret).update(body).digest('base64url');
  }
}

/* ---------------------------- helpers ---------------------------- */

export function header(headers: RequestContext['headers'], name: string): string | undefined {
  const value = headers[name] ?? headers[name.toLowerCase()];
  return Array.isArray(value) ? value[0] : value;
}

function digest(body: Buffer | string): string {
  const hash = createHash('sha256').update(body).digest('base64');
  return `sha-256=:${hash}:`;
}

/** Compare origin + path, ignoring query order and default ports. */
function normaliseTarget(target: string): string {
  try {
    const url = new URL(target);
    url.searchParams.sort();
    url.hash = '';
    return url.toString();
  } catch {
    return target;
  }
}

function safeEqual(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

export function problemResponse(status: number, title: string, detail?: string): CrapResponse {
  return {
    status,
    headers: { 'content-type': PROBLEM_MEDIA_TYPE, 'cache-control': 'no-store' },
    body: JSON.stringify({ type: `${PROBLEM_TYPE}#error`, title, status, detail }, null, 2),
  };
}

/* ------------------------- node http adapter ------------------------- */

export interface NodeLikeRequest {
  method?: string;
  url?: string;
  headers: Record<string, string | string[] | undefined>;
  on(event: string, cb: (...args: any[]) => void): unknown;
}

export interface NodeLikeResponse {
  writeHead(status: number, headers: Record<string, string>): unknown;
  end(body?: string): unknown;
}

/**
 * Express/Node middleware. On allow it sets `req.crap` to the graded answers
 * and calls next(); otherwise it writes the protocol response itself.
 */
export function crapMiddleware(server: CrapServer, opts: { origin: string; principal?: (req: any) => string | undefined } = { origin: '' }) {
  return async (req: any, res: NodeLikeResponse, next: () => void) => {
    const body = await readBody(req);
    const ctx: RequestContext = {
      method: req.method ?? 'GET',
      target: new URL(req.url ?? '/', opts.origin || `http://${req.headers.host ?? 'localhost'}`).toString(),
      headers: req.headers,
      principal: opts.principal?.(req),
      body,
    };
    const result = await server.handle(ctx);
    if (result.kind === 'allow') {
      req.crap = result.satisfied;
      req.rawBody = body;
      return next();
    }
    res.writeHead(result.response.status, result.response.headers);
    res.end(result.response.body);
  };
}

async function readBody(req: NodeLikeRequest): Promise<Buffer> {
  if ((req as any).rawBody) return (req as any).rawBody;
  const chunks: Buffer[] = [];
  await new Promise<void>((resolve, reject) => {
    req.on('data', (c: Buffer) => chunks.push(Buffer.from(c)));
    req.on('end', () => resolve());
    req.on('error', reject);
  });
  return Buffer.concat(chunks);
}
