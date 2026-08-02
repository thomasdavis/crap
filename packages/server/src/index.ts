/**
 * @thomasdavis/crap-server — issue challenges, validate answers, mint scoped
 * continuation proofs.
 *
 * Transport-neutral core plus a thin Node `http` adapter. The core knows
 * nothing about frameworks: you hand it a description of the request and it
 * hands back a decision.
 */

import { createHmac, randomBytes, timingSafeEqual, createHash } from 'node:crypto';
import {
  CRAP_VERSION,
  EVIDENCE_CLASSES,
  HEADER_ACCEPT,
  HEADER_CHALLENGE_ID,
  HEADER_INPUT_PROOF,
  PROBLEM_MEDIA_TYPE,
  PROBLEM_TYPE,
  RESPONSE_MEDIA_TYPE,
  STATUS_COMPAT,
  STATUS_INPUT_REQUIRED,
  SUBMISSION_PATH_PREFIX,
  clientSupportsVersion,
  isExpired,
  submissionPath,
  validateValue,
  type Challenge,
  type ChallengeResponse,
  type EvidenceClass,
  type EvidenceDescriptor,
  type InputRequest,
  type ProblemDocument,
  type ValidationError,
} from '@thomasdavis/crap-schema';

export * from '@thomasdavis/crap-schema';

/** The request, reduced to what a policy decision actually needs. */
export interface RequestContext {
  method: string;
  /** Absolute effective request URI. */
  target: string;
  headers: Record<string, string | string[] | undefined>;
  /** Authenticated principal, if your auth layer resolved one. */
  principal?: string;
  /** Raw body. Absence and emptiness are distinguished — see hasContent(). */
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

/** An accepted answer, with a structured account of how it was established. */
export interface GradedAnswer {
  value: unknown;
  evidence: EvidenceDescriptor;
}

export interface SatisfiedInput {
  challengeId: string;
  answers: Record<string, GradedAnswer>;
  declined: string[];
  principal?: string;
  round: number;
}

export interface EvidenceVerifier {
  /**
   * Verify one `evidence` answer. Return a descriptor, a bare class, or null
   * to reject. Default policy: reject everything, because an unverified proof
   * is just a string that says "proof".
   */
  (input: {
    request: InputRequest;
    answer: unknown;
    context: RequestContext;
    challenge: Challenge;
  }): Promise<EvidenceDescriptor | EvidenceClass | null> | EvidenceDescriptor | EvidenceClass | null;
}

export interface ChallengeStore {
  put(challenge: Challenge): Promise<void>;
  get(id: string): Promise<Challenge | undefined>;
  /** Mark consumed. Must return false if already consumed (replay). */
  consume(id: string): Promise<boolean>;
}

/** A minted decision, referenced by an opaque handle. */
export interface DecisionRecord {
  id: string;
  challengeId: string;
  scopeHash: string;
  principal: string | null;
  round: number;
  answers: Record<string, GradedAnswer>;
  declined: string[];
  expiresAt: number;
}

export interface DecisionStore {
  put(record: DecisionRecord): Promise<void>;
  get(id: string): Promise<DecisionRecord | undefined>;
}

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

export class MemoryDecisionStore implements DecisionStore {
  private live = new Map<string, DecisionRecord>();

  async put(record: DecisionRecord): Promise<void> {
    this.live.set(record.id, record);
    const now = Date.now();
    for (const [id, r] of this.live) if (r.expiresAt <= now) this.live.delete(id);
  }

  async get(id: string): Promise<DecisionRecord | undefined> {
    const record = this.live.get(id);
    if (record && record.expiresAt <= Date.now()) {
      this.live.delete(id);
      return undefined;
    }
    return record;
  }
}

export interface CrapServerOptions {
  /** Absolute origin of this server, e.g. `https://data.example`. */
  issuer: string;
  /** Secret used to authenticate proof handles. Rotate like any other key. */
  secret: string | Buffer;
  /** Your policy. Return allow / deny / input_required. */
  evaluate(ctx: RequestContext, satisfied?: SatisfiedInput): Promise<Decision> | Decision;
  store?: ChallengeStore;
  decisions?: DecisionStore;
  verifyEvidence?: EvidenceVerifier;
  /**
   * `opaque` (default): the proof is a random handle; answers stay server-side.
   * `stateless`: the proof carries a digest of the answers, not the answers.
   * Neither puts answer values in a header.
   */
  proofMode?: 'opaque' | 'stateless';
  /** Seconds a challenge stays answerable. Default 900. */
  ttlSeconds?: number;
  /** Consecutive challenges for one operation before a hard 403. Default 3. */
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

export type HandleResult =
  | { kind: 'allow'; satisfied?: SatisfiedInput }
  | { kind: 'respond'; response: CrapResponse };

export class CrapServer {
  private readonly opts: Required<Omit<CrapServerOptions, 'policyVersion'>> & { policyVersion?: string };

  constructor(options: CrapServerOptions) {
    this.opts = {
      store: new MemoryChallengeStore(),
      decisions: new MemoryDecisionStore(),
      verifyEvidence: () => null,
      proofMode: 'opaque',
      ttlSeconds: 900,
      maxRounds: 3,
      proofTtlSeconds: 300,
      ...options,
    } as Required<Omit<CrapServerOptions, 'policyVersion'>> & { policyVersion?: string };
  }

  /**
   * The whole protocol, one call. Feed it every request to a protected
   * resource; it returns "allow, carry on" or a response to send.
   */
  async handle(ctx: RequestContext): Promise<HandleResult> {
    if (this.isSubmission(ctx)) {
      return { kind: 'respond', response: await this.submit(ctx) };
    }

    const proof = header(ctx.headers, HEADER_INPUT_PROOF);
    let satisfied: SatisfiedInput | undefined;
    if (proof) {
      const verified = await this.verifyInputProof(proof, ctx);
      if (!verified.ok) {
        return { kind: 'respond', response: this.problem(ctx, STATUS_COMPAT, 'Invalid Input Proof', verified.reason) };
      }
      satisfied = verified.satisfied;
    }

    const decision = await this.opts.evaluate(ctx, satisfied);
    if (decision.kind === 'allow') return { kind: 'allow', satisfied };
    if (decision.kind === 'deny') {
      return { kind: 'respond', response: this.problem(ctx, STATUS_COMPAT, 'Forbidden', decision.reason) };
    }

    const round = (satisfied?.round ?? 0) + 1;
    if (round > this.opts.maxRounds) {
      return {
        kind: 'respond',
        response: this.problem(ctx, STATUS_COMPAT, 'Forbidden', `challenge limit reached after ${this.opts.maxRounds} rounds`),
      };
    }

    const challenge = await this.issue(ctx, decision, round);
    return { kind: 'respond', response: this.challengeResponse(ctx, challenge, decision.detail) };
  }

  /** Is this a POST to a challenge transaction resource? */
  private isSubmission(ctx: RequestContext): boolean {
    if (ctx.method.toUpperCase() !== 'POST') return false;
    try {
      return new URL(ctx.target).pathname.startsWith(`${SUBMISSION_PATH_PREFIX}/`);
    } catch {
      return false;
    }
  }

  private challengeIdFromTarget(target: string): string | undefined {
    try {
      const { pathname } = new URL(target);
      const match = pathname.match(
        new RegExp(`^${SUBMISSION_PATH_PREFIX}/([^/]+)/responses/?$`),
      );
      return match ? decodeURIComponent(match[1]) : undefined;
    } catch {
      return undefined;
    }
  }

  /** Build and persist a challenge bound to this exact request. */
  async issue(
    ctx: RequestContext,
    decision: Extract<Decision, { kind: 'input_required' }>,
    round = 1,
  ): Promise<Challenge> {
    const ttl = decision.ttlSeconds ?? this.opts.ttlSeconds;
    const now = new Date();
    const id = `ch_${randomBytes(12).toString('base64url')}`;
    const withContent = hasContent(ctx);

    const challenge: Challenge = {
      id,
      version: CRAP_VERSION,
      issuer: this.opts.issuer,
      issued_at: now.toISOString(),
      expires_at: new Date(now.getTime() + ttl * 1000).toISOString(),
      request_state: randomBytes(24).toString('base64url'),
      scope: {
        method: ctx.method.toUpperCase(),
        target: ctx.target,
        has_content: withContent,
        ...(withContent ? { content_digest: contentDigest(ctx.body!) } : {}),
        ...(ctx.principal ? { principal: ctx.principal } : {}),
      },
      input_requests: decision.requests,
      submission: {
        method: 'POST',
        target: new URL(submissionPath(id), this.opts.issuer).toString(),
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
   * Render a challenge. The compatibility profile (`403`) is the baseline;
   * native `430` only for clients that advertised the exact version.
   */
  challengeResponse(ctx: RequestContext, challenge: Challenge, detail?: string): CrapResponse {
    const native = clientSupportsVersion(header(ctx.headers, HEADER_ACCEPT));
    const status = native ? STATUS_INPUT_REQUIRED : STATUS_COMPAT;
    const problem: ProblemDocument = {
      type: PROBLEM_TYPE,
      title: 'Input Required',
      // RFC 9457 §3.1: this MUST match the response status, so the two
      // profiles are semantically identical but not byte-identical.
      status,
      detail: detail ?? 'This resource requires additional input before it can be served.',
      instance: ctx.target,
      challenge,
    };
    return {
      status,
      headers: {
        'content-type': PROBLEM_MEDIA_TYPE,
        'cache-control': 'no-store',
        vary: HEADER_ACCEPT,
        [HEADER_CHALLENGE_ID]: challenge.id,
        link: `<${challenge.submission.target}>; rel="https://crap.blah.dev/rels/submit-input"`,
      },
      body: JSON.stringify(problem, null, 2),
    };
  }

  /** Handle a POST to a challenge transaction resource. */
  async submit(ctx: RequestContext): Promise<CrapResponse> {
    let parsed: ChallengeResponse;
    try {
      parsed = JSON.parse(typeof ctx.body === 'string' ? ctx.body : (ctx.body ?? Buffer.alloc(0)).toString('utf8'));
    } catch {
      return this.problem(ctx, 400, 'Bad Request', 'submission body is not valid JSON');
    }

    const pathId = this.challengeIdFromTarget(ctx.target);
    if (!pathId) return this.problem(ctx, 404, 'Not Found', 'not a challenge transaction resource');
    if (pathId !== parsed.challenge_id) {
      return this.problem(ctx, STATUS_COMPAT, 'Invalid Submission', 'challenge id does not match the transaction resource');
    }

    const challenge = await this.opts.store.get(parsed.challenge_id);
    if (!challenge) return this.problem(ctx, STATUS_COMPAT, 'Unknown Challenge', 'no such challenge');
    if (isExpired(challenge)) return this.problem(ctx, STATUS_COMPAT, 'Challenge Expired', 'challenge has expired');

    if (!safeEqual(parsed.request_state ?? '', challenge.request_state)) {
      return this.problem(ctx, STATUS_COMPAT, 'Invalid Submission', 'request_state mismatch');
    }
    if ((challenge.scope.principal ?? null) !== (ctx.principal ?? null)) {
      return this.problem(ctx, STATUS_COMPAT, 'Invalid Submission', 'principal mismatch');
    }

    const declined = parsed.declined ?? [];
    const answers: Record<string, GradedAnswer> = {};
    const errors: ValidationError[] = [];

    for (const request of challenge.input_requests) {
      if (declined.includes(request.id)) {
        if (request.required) errors.push({ path: `/${request.id}`, message: 'declined but required' });
        continue;
      }
      const raw = parsed.input_responses?.[request.id];
      if (raw === undefined) {
        if (request.required) errors.push({ path: `/${request.id}`, message: 'missing required answer' });
        continue;
      }

      if (request.kind === 'declaration' || request.kind === 'task') {
        const schema = request.kind === 'task' ? request.output_schema : request.schema;
        const schemaErrors = validateValue(raw, schema ?? {}, `/${request.id}`);
        if (schemaErrors.length) {
          errors.push(...schemaErrors);
          continue;
        }
        answers[request.id] = { value: raw, evidence: { class: 'self_asserted' } };
        continue;
      }

      // evidence / approval both require verification.
      const verified = await this.opts.verifyEvidence({ request, answer: raw, context: ctx, challenge });
      if (!verified) {
        errors.push({ path: `/${request.id}`, message: 'evidence rejected' });
        continue;
      }
      const evidence: EvidenceDescriptor = typeof verified === 'string' ? { class: verified } : verified;
      if (!EVIDENCE_CLASSES.includes(evidence.class)) {
        errors.push({ path: `/${request.id}`, message: `unknown evidence class "${evidence.class}"` });
        continue;
      }
      // Set membership, not rank: the issuer said which classes it accepts.
      const accepted = request.accepted_evidence;
      if (accepted && !accepted.includes(evidence.class)) {
        errors.push({
          path: `/${request.id}`,
          message: `evidence class ${evidence.class} is not in accepted_evidence [${accepted.join(', ')}]`,
        });
        continue;
      }
      answers[request.id] = { value: raw, evidence };
    }

    if (errors.length) {
      return {
        status: 422,
        headers: { 'content-type': PROBLEM_MEDIA_TYPE, 'cache-control': 'no-store' },
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

    if (!(await this.opts.store.consume(challenge.id))) {
      return this.problem(ctx, STATUS_COMPAT, 'Replay', 'challenge already answered');
    }

    const proof = await this.mintInputProof(challenge, {
      challengeId: challenge.id,
      answers,
      declined,
      principal: ctx.principal,
      round: challenge.round,
    });

    return {
      status: 204,
      headers: { [HEADER_INPUT_PROOF]: proof, 'cache-control': 'no-store' },
      body: '',
    };
  }

  /**
   * A continuation proof says "these requirements were satisfied for this
   * exact request". It is NOT a session token and carries no answer values —
   * headers end up in logs and intermediary telemetry.
   */
  async mintInputProof(challenge: Challenge, satisfied: SatisfiedInput): Promise<string> {
    const expiresAt = Date.now() + this.opts.proofTtlSeconds * 1000;
    const scopeHash = this.scopeHash(challenge.scope);
    const id = `dec_${randomBytes(18).toString('base64url')}`;

    await this.opts.decisions.put({
      id,
      challengeId: challenge.id,
      scopeHash,
      principal: satisfied.principal ?? null,
      round: satisfied.round,
      answers: satisfied.answers,
      declined: satisfied.declined,
      expiresAt,
    });

    if (this.opts.proofMode === 'opaque') {
      return `ip1.${id}.${this.sign(id)}`;
    }
    // Stateless: a decision id plus a digest of the answers. Still no values.
    const payload = Buffer.from(
      JSON.stringify({
        v: CRAP_VERSION,
        id,
        cid: challenge.id,
        scope: scopeHash,
        sub: satisfied.principal ?? null,
        round: satisfied.round,
        adigest: sha256(JSON.stringify(satisfied.answers)),
        exp: Math.floor(expiresAt / 1000),
      }),
    ).toString('base64url');
    return `ip2.${payload}.${this.sign(payload)}`;
  }

  async verifyInputProof(
    token: string,
    ctx: RequestContext,
  ): Promise<{ ok: true; satisfied: SatisfiedInput } | { ok: false; reason: string }> {
    const [profile, body, sig] = token.split('.');
    if (!profile || !body || !sig) return { ok: false, reason: 'malformed proof' };
    if (!safeEqual(sig, this.sign(body))) return { ok: false, reason: 'bad signature' };

    let decisionId: string;
    if (profile === 'ip1') {
      decisionId = body;
    } else if (profile === 'ip2') {
      try {
        const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
        if (payload.v !== CRAP_VERSION) return { ok: false, reason: 'unsupported proof version' };
        if (typeof payload.exp !== 'number' || payload.exp * 1000 <= Date.now()) {
          return { ok: false, reason: 'proof expired' };
        }
        decisionId = payload.id;
      } catch {
        return { ok: false, reason: 'unreadable proof' };
      }
    } else {
      return { ok: false, reason: 'unknown proof profile' };
    }

    const record = await this.opts.decisions.get(decisionId);
    if (!record) return { ok: false, reason: 'unknown or expired proof' };
    if (record.expiresAt <= Date.now()) return { ok: false, reason: 'proof expired' };
    if ((record.principal ?? null) !== (ctx.principal ?? null)) return { ok: false, reason: 'principal mismatch' };

    // Full scope binding: method, exact target, AND content presence/digest.
    const presented = this.scopeHash({
      method: ctx.method.toUpperCase(),
      target: ctx.target,
      has_content: hasContent(ctx),
      ...(hasContent(ctx) ? { content_digest: contentDigest(ctx.body!) } : {}),
      ...(ctx.principal ? { principal: ctx.principal } : {}),
    });
    if (presented !== record.scopeHash) {
      return { ok: false, reason: await this.scopeMismatchReason(record, ctx) };
    }

    return {
      ok: true,
      satisfied: {
        challengeId: record.challengeId,
        answers: record.answers,
        declined: record.declined,
        principal: ctx.principal,
        round: record.round,
      },
    };
  }

  /**
   * Which component differed. Recomputed against the stored challenge so the
   * error is useful; the check itself is the single hash comparison above.
   */
  private async scopeMismatchReason(record: DecisionRecord, ctx: RequestContext): Promise<string> {
    const challenge = await this.opts.store.get(record.challengeId);
    if (!challenge) return 'scope mismatch';
    const scope = challenge.scope;
    if (scope.method.toUpperCase() !== ctx.method.toUpperCase()) return 'method mismatch';
    if (scope.target !== ctx.target) return 'target mismatch';
    if (scope.has_content !== hasContent(ctx)) return 'request content presence mismatch';
    if (scope.content_digest && hasContent(ctx) && scope.content_digest !== contentDigest(ctx.body!)) {
      return 'content digest mismatch';
    }
    return 'scope mismatch';
  }

  private scopeHash(scope: Challenge['scope']): string {
    return sha256(
      JSON.stringify([
        this.opts.issuer,
        scope.method.toUpperCase(),
        scope.target,
        scope.has_content,
        scope.content_digest ?? null,
        scope.principal ?? null,
      ]),
    );
  }

  private problem(ctx: RequestContext, status: number, title: string, detail?: string): CrapResponse {
    void ctx;
    return {
      status,
      headers: {
        'content-type': PROBLEM_MEDIA_TYPE,
        'cache-control': 'no-store',
        vary: HEADER_ACCEPT,
      },
      body: JSON.stringify({ type: `${PROBLEM_TYPE}#error`, title, status, detail }, null, 2),
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

/**
 * Content presence, distinguished from absence. A proof minted for a request
 * with content must not be presentable on one without it, and vice versa.
 */
export function hasContent(ctx: Pick<RequestContext, 'body'>): boolean {
  if (ctx.body === undefined || ctx.body === null) return false;
  return ctx.body.length > 0;
}

/** RFC 9530 Content-Digest, sha-256. */
export function contentDigest(body: Buffer | string): string {
  return `sha-256=:${createHash('sha256').update(body).digest('base64')}:`;
}

function sha256(input: string): string {
  return createHash('sha256').update(input).digest('base64url');
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
    headers: { 'content-type': PROBLEM_MEDIA_TYPE, 'cache-control': 'no-store', vary: HEADER_ACCEPT },
    body: JSON.stringify({ type: `${PROBLEM_TYPE}#error`, title, status, detail }, null, 2),
  };
}

/* ------------------------- node http adapter ------------------------- */

export interface NodeLikeResponse {
  writeHead(status: number, headers: Record<string, string>): unknown;
  end(body?: string): unknown;
}

/**
 * Express/Node middleware. On allow it sets `req.crap` to the graded answers
 * and calls next(); otherwise it writes the protocol response itself.
 */
export function crapMiddleware(
  server: CrapServer,
  opts: { origin: string; principal?: (req: any) => string | undefined },
) {
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

async function readBody(req: any): Promise<Buffer> {
  if (req.rawBody) return req.rawBody;
  const chunks: Buffer[] = [];
  await new Promise<void>((resolve, reject) => {
    req.on('data', (c: Buffer) => chunks.push(Buffer.from(c)));
    req.on('end', () => resolve());
    req.on('error', reject);
  });
  return Buffer.concat(chunks);
}
