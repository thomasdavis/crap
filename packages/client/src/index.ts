/**
 * @thomasdavis/crap-client — a fetch wrapper that answers challenges.
 *
 * The design rule: the SERVER asks, the CLIENT decides. A resolver you supply
 * decides what may be answered autonomously, what needs a human, and what is
 * refused outright. Nothing in a challenge can make this library answer a
 * question your policy did not approve.
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
  suspiciousRequests,
  validateChallenge,
  validateValue,
  type AnswerValue,
  type Challenge,
  type ChallengeResponse,
  type InputRequest,
} from '@thomasdavis/crap-schema';

export * from '@thomasdavis/crap-schema';

/** What a resolver may return for one question. */
export type Answer =
  | { kind: 'answer'; value: AnswerValue }
  | { kind: 'decline'; reason?: string };

export const answer = (value: AnswerValue): Answer => ({ kind: 'answer', value });
export const decline = (reason?: string): Answer => ({ kind: 'decline', reason });

export interface ResolverContext {
  challenge: Challenge;
  /** The request that triggered the challenge. */
  request: { method: string; url: string };
}

export interface Resolver {
  form?(request: InputRequest, ctx: ResolverContext): Promise<Answer> | Answer;
  proof?(request: InputRequest, ctx: ResolverContext): Promise<Answer> | Answer;
  approval?(request: InputRequest, ctx: ResolverContext): Promise<Answer> | Answer;
  url?(request: InputRequest, ctx: ResolverContext): Promise<Answer> | Answer;
}

export interface CrapFetchOptions extends RequestInit {
  resolver?: Resolver;
  /** Max challenge rounds this client will play along with. Default 3. */
  maxRounds?: number;
  fetch?: typeof globalThis.fetch;
  /** Called for every challenge received — logging, metrics, human display. */
  onChallenge?(challenge: Challenge): void;
  /**
   * Refuse challenges whose questions smell like secret-harvesting or
   * context-exfiltration. Default true. Turning this off is on you.
   */
  guardSuspicious?: boolean;
}

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

/**
 * fetch(), with the protocol bolted on: if the resource asks questions, answer
 * them (per your resolver) and retry the original request once per round.
 */
export async function crapFetch(
  input: string | URL,
  options: CrapFetchOptions = {},
): Promise<Response> {
  const {
    resolver = {},
    maxRounds = 3,
    fetch: doFetch = globalThis.fetch,
    onChallenge,
    guardSuspicious = true,
    ...init
  } = options;

  const url = typeof input === 'string' ? input : input.toString();
  const method = (init.method ?? 'GET').toUpperCase();
  const headers = new Headers(init.headers);
  headers.set(HEADER_ACCEPT, ACCEPT_VALUE);

  let proof: string | undefined;

  for (let round = 0; round <= maxRounds; round += 1) {
    const attemptHeaders = new Headers(headers);
    if (proof) attemptHeaders.set(HEADER_INPUT_PROOF, proof);

    const response = await doFetch(url, { ...init, method, headers: attemptHeaders });

    const challenge = await extractChallenge(response);
    if (!challenge) return response;

    onChallenge?.(challenge);

    const problems = validateChallenge(challenge);
    if (problems.length) {
      throw new CrapError('server sent a malformed challenge', problems);
    }
    if (isExpired(challenge)) {
      throw new CrapError('server sent an already-expired challenge');
    }
    if (guardSuspicious) {
      const bad = suspiciousRequests(challenge);
      if (bad.length) {
        throw new ChallengeDeclined(
          'challenge asks for secrets or agent context in form mode; refusing',
          challenge,
          bad.map((r) => r.id),
        );
      }
    }

    proof = await satisfy(challenge, { method, url }, resolver, doFetch);
  }

  throw new CrapError(`challenge loop exceeded ${maxRounds} rounds`);
}

/** Answer every question in a challenge and return the continuation proof. */
export async function satisfy(
  challenge: Challenge,
  request: { method: string; url: string },
  resolver: Resolver,
  doFetch: typeof globalThis.fetch = globalThis.fetch,
): Promise<string> {
  const ctx: ResolverContext = { challenge, request };
  const input_responses: Record<string, AnswerValue> = {};
  const declined: string[] = [];

  for (const req of challenge.input_requests) {
    const handler = resolver[req.mode];
    if (!handler) {
      declined.push(req.id);
      continue;
    }
    const result = await handler(req, ctx);
    if (result.kind === 'decline') {
      declined.push(req.id);
      continue;
    }
    // Validate our own answer before sending it — a round trip to be told the
    // enum has three values, none of them the one we invented, is a waste.
    if (req.mode === 'form' && req.schema) {
      const errors = validateValue(result.value, req.schema, `/${req.id}`);
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
    ...(declined.length ? { declined } : {}),
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
  if (!proof) throw new CrapError('server accepted answers but issued no Input-Proof');
  return proof;
}

/** Recognise both profiles: native 430, and 403 + the problem type. */
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
  const lookup = (req: InputRequest): Answer =>
    req.id in values ? answer(values[req.id]) : decline('not pre-approved');
  return { form: lookup, proof: lookup, approval: lookup, url: lookup };
}

function cryptoRandom(): string {
  const bytes = new Uint8Array(12);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
