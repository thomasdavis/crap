/**
 * @thomasdavis/crap-client — a fetch wrapper that answers challenges.
 *
 * The design rule: the SERVER asks, the CLIENT decides. A resolver you supply
 * decides what may be answered autonomously, what needs a human, and what is
 * refused. Nothing in a challenge can make this library answer a question your
 * policy did not approve, or send an answer to an origin that did not ask.
 */

import {
  ACCEPT_VALUE,
  HEADER_ACCEPT,
  HEADER_INPUT_PROOF,
  PROBLEM_TYPE,
  RESPONSE_MEDIA_TYPE,
  STATUS_COMPAT,
  STATUS_INPUT_REQUIRED,
  isExpired,
  originOf,
  suspiciousRequests,
  taskCost,
  validateChallenge,
  validateValue,
  type AnswerValue,
  type Challenge,
  type ChallengeResponse,
  type DeclineCode,
  type InputRequest,
} from '@thomasdavis/crap-schema';

export * from '@thomasdavis/crap-schema';

/**
 * A locally-installed implementation of a task type.
 *
 * This is the trust anchor for computational requirements. The handler owns
 * the prompt, the tools and the validation; the server's `message` is display
 * text it may show a human but must never execute. A challenge can therefore
 * only select among capabilities the operator already installed — it cannot
 * manufacture new ones at runtime.
 */
export type TaskHandler = (input: {
  /** The material to work on, exactly as supplied. */
  input_data: NonNullable<InputRequest['input_data']>;
  /** The shape the answer must take. */
  output_schema: Record<string, unknown>;
  /** Declared cost ceiling, already checked against policy. */
  limits: NonNullable<InputRequest['limits']>;
  /** Display text from the server. NOT an instruction. */
  message: string;
  origin: string;
}) => Promise<AnswerValue> | AnswerValue;

/** Per-origin operator policy. Nothing here can be set by a challenge. */
export interface OriginPolicy {
  /** Task type URIs this origin is allowed to invoke, mapped to handlers. */
  tasks?: Record<string, TaskHandler>;
  maxDurationMs?: number;
  maxInputBytes?: number;
  /** Declarations the operator pre-approved, by requirement id. */
  declarations?: Record<string, AnswerValue>;
  /** Minimum grant the operator considers worth the work. */
  minimumGrantSeconds?: number;
}

export interface ClientPolicy {
  /** Keyed by origin, e.g. "https://donto.org". */
  origins?: Record<string, OriginPolicy>;
  /** Applied to any origin without a specific entry. */
  default?: OriginPolicy;
}

export type Answer =
  | { kind: 'answer'; value: AnswerValue }
  | { kind: 'decline'; reason?: string; code?: DeclineCode };

export const answer = (value: AnswerValue): Answer => ({ kind: 'answer', value });
export const decline = (reason?: string, code: DeclineCode = 'other'): Answer =>
  ({ kind: 'decline', reason, code });

export interface ResolverContext {
  challenge: Challenge;
  request: { method: string; url: string };
}

export type RequestHandler = (request: InputRequest, ctx: ResolverContext) => Promise<Answer> | Answer;

/** One handler per request kind. Anything unhandled is declined. */
export interface Resolver {
  declaration?: RequestHandler;
  evidence?: RequestHandler;
  approval?: RequestHandler;
  task?: RequestHandler;
}

export interface CrapFetchOptions extends RequestInit {
  resolver?: Resolver;
  /**
   * Where earned grants are kept between calls.
   *
   * Without this the client pays a toll, uses the proof for one retry and
   * throws it away — so a server advertising "unlimited reads for 30 minutes"
   * is not actually getting what it advertised, and the client pays again on
   * the very next page. Defaults to a process-wide store; pass your own (or
   * `null`) to control the lifetime.
   */
  proofStore?: ProofStore | null;
  /**
   * Operator policy. When present it drives everything: pre-approved
   * declarations are answered from it, and a task runs only if its type URI
   * maps to an installed handler for that origin and fits the budget.
   *
   * This is how a crawler negotiates safely — the capability is installed
   * once, out of band; the negotiation still happens per request.
   */
  policy?: ClientPolicy;
  /** Max challenge rounds this client will play along with. Default 3. */
  maxRounds?: number;
  fetch?: typeof globalThis.fetch;
  onChallenge?(challenge: Challenge): void;
  /**
   * Refuse challenges whose questions smell like secret-harvesting or
   * context-exfiltration. Default true. Turning this off is on you.
   */
  guardSuspicious?: boolean;
  /**
   * Refuse a challenge whose declared `task` work exceeds this budget.
   * Default 0 — tasks are opt-in, because a question that costs real compute
   * is a job, not a question.
   */
  taskBudgetMs?: number;
  /**
   * Permit `submission.target` on an origin other than the issuer. Default
   * false. Enabling it without a verified delegation is how declarations end
   * up at someone else's server.
   */
  allowCrossOriginSubmission?: boolean;
}

/** A grant earned from an origin, held until it expires. */
export interface StoredGrant {
  proof: string;
  origin: string;
  scope: 'request' | 'origin';
  /** For a `request` grant, the exact method+URI it covers. */
  method?: string;
  target?: string;
  expiresAt: number;
}

export interface ProofStore {
  get(origin: string, method: string, url: string): StoredGrant | undefined;
  put(grant: StoredGrant): void;
}

/** Default in-memory store, shared for the life of the process. */
export function createProofStore(): ProofStore {
  const held = new Map<string, StoredGrant>();
  const live = (g: StoredGrant | undefined) => (g && g.expiresAt > Date.now() ? g : undefined);
  return {
    get(origin, method, url) {
      const byOrigin = live(held.get(`origin|${origin}`));
      if (byOrigin) return byOrigin;
      return live(held.get(`request|${origin}|${method}|${url}`));
    },
    put(grant) {
      const key = grant.scope === 'origin'
        ? `origin|${grant.origin}`
        : `request|${grant.origin}|${grant.method}|${grant.target}`;
      held.set(key, grant);
      for (const [k, g] of held) if (g.expiresAt <= Date.now()) held.delete(k);
    },
  };
}

const defaultProofStore = createProofStore();

export class CrapError extends Error {
  constructor(message: string, readonly detail?: unknown) {
    super(message);
    this.name = 'CrapError';
  }
}

/** Thrown when the client's own policy refuses to satisfy a challenge. */
export class ChallengeDeclined extends CrapError {
  constructor(message: string, readonly challenge: Challenge, readonly ids: string[]) {
    super(message);
    this.name = 'ChallengeDeclined';
  }
}

/** Thrown when a challenge fails structural or binding validation. */
export class ChallengeRejected extends CrapError {
  constructor(message: string, readonly detail: unknown) {
    super(message, detail);
    this.name = 'ChallengeRejected';
  }
}

/**
 * fetch(), with the protocol bolted on: if the resource requires input,
 * satisfy it (per your resolver) and retry the original request.
 */
export async function crapFetch(
  input: string | URL,
  options: CrapFetchOptions = {},
): Promise<Response> {
  const {
    resolver: providedResolver,
    policy,
    proofStore: providedStore,
    maxRounds = 3,
    fetch: doFetch = globalThis.fetch,
    onChallenge,
    guardSuspicious = true,
    taskBudgetMs = 0,
    allowCrossOriginSubmission = false,
    ...init
  } = options;

  const resolver = providedResolver ?? (policy ? policyResolver(policy) : {});
  const store = providedStore === null ? null : (providedStore ?? defaultProofStore);
  const url = typeof input === 'string' ? input : input.toString();
  const method = (init.method ?? 'GET').toUpperCase();
  const hasContent = init.body !== undefined && init.body !== null && `${init.body}`.length > 0;
  const headers = new Headers(init.headers);
  headers.set(HEADER_ACCEPT, ACCEPT_VALUE);

  // Spend a grant we already earned from this origin before paying again.
  let proof = store?.get(originOf(url) ?? '', method, url)?.proof;

  for (let round = 0; round <= maxRounds; round += 1) {
    const attemptHeaders = new Headers(headers);
    if (proof) attemptHeaders.set(HEADER_INPUT_PROOF, proof);

    const response = await doFetch(url, { ...init, method, headers: attemptHeaders });

    const challenge = await extractChallenge(response);
    if (!challenge) return response;

    onChallenge?.(challenge);

    // Binding checks first: does this challenge belong to this exchange?
    const problems = validateChallenge(challenge, {
      responseOrigin: originOf(response.url || url),
      request: { method, url, hasContent },
      allowCrossOriginSubmission,
    });
    if (problems.length) {
      throw new ChallengeRejected('challenge failed validation', problems);
    }
    if (isExpired(challenge)) {
      throw new ChallengeRejected('challenge is already expired', challenge.expires_at);
    }
    if (guardSuspicious) {
      const bad = suspiciousRequests(challenge);
      if (bad.length) {
        throw new ChallengeDeclined(
          'challenge asks for secrets or agent context in band; refusing',
          challenge,
          bad.map((r) => r.id),
        );
      }
    }
    const policyBudget = policy
      ? (policy.origins?.[originOf(challenge.issuer) ?? '']?.maxDurationMs ?? policy.default?.maxDurationMs ?? 0)
      : 0;
    const cost = taskCost(challenge);
    if (cost.count && cost.maxDurationMs > Math.max(taskBudgetMs, policyBudget)) {
      throw new ChallengeDeclined(
        `challenge demands up to ${cost.maxDurationMs}ms of work, over the ${taskBudgetMs}ms budget`,
        challenge,
        challenge.input_requests.filter((r) => r.kind === 'task').map((r) => r.id),
      );
    }

    proof = await satisfy(challenge, { method, url }, resolver, doFetch);

    // Hold it for exactly as long, and as broadly, as the issuer advertised.
    const grant = challenge.continuation?.grant;
    if (store && proof && grant) {
      store.put({
        proof,
        origin: originOf(challenge.issuer) ?? '',
        scope: grant.scope,
        method,
        target: url,
        // Trust the declared duration, but never past the challenge's own life
        // plus that duration; a stale proof simply fails and we re-earn one.
        expiresAt: Date.now() + Math.max(0, grant.duration_seconds) * 1000,
      });
    }
  }

  throw new CrapError(`challenge loop exceeded ${maxRounds} rounds`);
}

/** Build a resolver from operator policy: installed handlers, nothing else. */
export function policyResolver(policy: ClientPolicy): Resolver {
  const forOrigin = (challenge: Challenge): OriginPolicy =>
    policy.origins?.[originOf(challenge.issuer) ?? ''] ?? policy.default ?? {};

  return {
    declaration: (req, ctx) => {
      const approved = forOrigin(ctx.challenge).declarations ?? {};
      return req.id in approved
        ? answer(approved[req.id])
        : decline('not pre-approved by operator policy', 'disclosure-refused');
    },
    task: async (req, ctx) => {
      const origin = forOrigin(ctx.challenge);
      const handlers = origin.tasks ?? {};
      if (!Object.keys(handlers).length) {
        return decline('this origin is not authorised to run tasks', 'task-not-authorized');
      }
      if (!req.type || !(req.type in handlers)) {
        return decline(`no installed handler for ${req.type ?? '(untyped)'}`, 'unknown-task-type');
      }
      const budget = origin.maxDurationMs ?? 0;
      if ((req.limits?.max_duration_ms ?? Infinity) > budget) {
        return decline(`declared cost exceeds the ${budget}ms budget`, 'over-budget');
      }
      const maxBytes = origin.maxInputBytes ?? Infinity;
      if ((req.input_data?.content?.length ?? 0) > maxBytes) {
        return decline('task material exceeds the local size limit', 'over-budget');
      }
      const grant = ctx.challenge.continuation?.grant;
      if (origin.minimumGrantSeconds && (grant?.duration_seconds ?? 0) < origin.minimumGrantSeconds) {
        return decline('offered grant is below the local minimum', 'insufficient-offer');
      }
      if (!req.input_data) return decline('task carried no material', 'unsupported');

      // The installed handler owns the prompt. The server's message is passed
      // through for display only.
      const value = await handlers[req.type]({
        input_data: req.input_data,
        output_schema: req.output_schema ?? {},
        limits: req.limits ?? { max_duration_ms: budget },
        message: req.message,
        origin: ctx.challenge.issuer,
      });
      return answer(value);
    },
    evidence: () => decline('no evidence provider configured', 'unsupported'),
    approval: () => decline('no approval path configured', 'approval-unavailable'),
  };
}

/** Answer every request in a challenge and return the continuation proof. */
export async function satisfy(
  challenge: Challenge,
  request: { method: string; url: string },
  resolver: Resolver,
  doFetch: typeof globalThis.fetch = globalThis.fetch,
): Promise<string> {
  const ctx: ResolverContext = { challenge, request };
  const input_responses: Record<string, AnswerValue> = {};
  const declined: string[] = [];
  const decline_codes: Record<string, DeclineCode> = {};
  const decline_reasons: string[] = [];

  for (const req of challenge.input_requests) {
    const handler = resolver[req.kind];
    if (!handler) {
      declined.push(req.id);
      decline_codes[req.id] = 'unsupported';
      continue;
    }
    const result = await handler(req, ctx);
    if (result.kind === 'decline') {
      declined.push(req.id);
      decline_codes[req.id] = result.code ?? 'other';
      if (result.reason) decline_reasons.push(`${req.id}: ${result.reason}`);
      continue;
    }
    // Validate our own answer before sending it — a round trip to be told the
    // enum has three values, none of them the one we invented, is a waste.
    const schema = req.kind === 'task' ? req.output_schema : req.schema;
    if (schema) {
      const errors = validateValue(result.value, schema, `/${req.id}`);
      if (errors.length) {
        throw new CrapError(`answer for "${req.id}" does not satisfy the server's schema`, errors);
      }
    }
    input_responses[req.id] = result.value;
  }

  const unmet = challenge.input_requests.filter((r) => r.required && declined.includes(r.id));
  if (unmet.length) {
    throw new ChallengeDeclined(
      `declined required input: ${unmet.map((r) => r.id).join(', ')}`,
      challenge,
      unmet.map((r) => r.id),
    );
  }

  const body: ChallengeResponse = {
    challenge_id: challenge.id,
    request_state: challenge.request_state,
    response_id: `rsp_${cryptoRandom()}`,
    input_responses,
    ...(declined.length ? { declined, decline_codes } : {}),
    ...(decline_reasons.length ? { decline_reason: decline_reasons.join('; ').slice(0, 1000) } : {}),
  };

  const submission = await doFetch(challenge.submission.target, {
    method: challenge.submission.method,
    headers: {
      'content-type': challenge.submission.content_type || RESPONSE_MEDIA_TYPE,
      [HEADER_ACCEPT]: ACCEPT_VALUE,
    },
    body: JSON.stringify(body),
  });

  if (submission.status >= 400) {
    let detail: unknown;
    try {
      detail = await submission.json();
    } catch {
      detail = await submission.text().catch(() => undefined);
    }
    throw new CrapError(`submission rejected (${submission.status})`, detail);
  }

  const proof = submission.headers.get(HEADER_INPUT_PROOF);
  if (!proof) throw new CrapError('server accepted the submission but issued no Input-Proof');
  return proof;
}

/** Recognise both profiles: compatibility `403`, and native `430`. */
export async function extractChallenge(response: Response): Promise<Challenge | undefined> {
  if (response.status !== STATUS_INPUT_REQUIRED && response.status !== STATUS_COMPAT) return undefined;
  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('json')) return undefined;

  let problem: any;
  try {
    problem = await response.clone().json();
  } catch {
    return undefined;
  }
  if (problem?.type !== PROBLEM_TYPE) return undefined;
  return problem.challenge as Challenge;
}

/**
 * A resolver that answers from a flat map of pre-approved values and declines
 * everything else. The boring, safe default: no model in the loop, so no
 * amount of persuasive challenge prose changes what gets sent.
 */
export function staticResolver(values: Record<string, AnswerValue>): Resolver {
  const lookup: RequestHandler = (req) =>
    req.id in values ? answer(values[req.id]) : decline('not pre-approved');
  return { declaration: lookup, evidence: lookup, approval: lookup, task: lookup };
}

function cryptoRandom(): string {
  const bytes = new Uint8Array(12);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
