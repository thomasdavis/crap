/**
 * @crap/schema — the wire contract for the Conditional Resource Access Protocol.
 *
 * Everything here is transport-neutral: types, constants, JSON Schemas and
 * validators for the two documents that cross the wire (a Challenge and a
 * ChallengeResponse). No HTTP, no I/O.
 */

export const CRAP_VERSION = 1 as const;

/** Provisional, unassigned in the IANA HTTP status code registry. */
export const STATUS_INPUT_REQUIRED = 430 as const;

/** Compatibility profile: what we send when the client did not opt in to 430. */
export const STATUS_COMPAT = 403 as const;

export const PROBLEM_TYPE = 'https://crap.donto.org/problems/input-required';
export const PROBLEM_MEDIA_TYPE = 'application/problem+json';
export const RESPONSE_MEDIA_TYPE = 'application/crap-response+json';

export const HEADER_ACCEPT = 'accept-input-required';
export const HEADER_CHALLENGE_ID = 'challenge-id';
export const HEADER_INPUT_PROOF = 'input-proof';

/** Value a client sends in `Accept-Input-Required` to opt in to native 430. */
export const ACCEPT_VALUE = `v=${CRAP_VERSION}`;

/**
 * How an input request must be satisfied.
 *
 * `form`     structured, non-secret data the agent may answer autonomously
 * `proof`    machine-verifiable evidence (signature, delegation, credential)
 * `approval` a human must approve, out of the agent's autonomous path
 * `url`      the interaction happens out of band at an HTTPS location
 *
 * Secrets (passwords, tokens, card numbers) MUST NOT be requested in `form`
 * mode — form answers pass through the agent's context.
 */
export type InputMode = 'form' | 'proof' | 'approval' | 'url';

/**
 * How much a given answer is actually worth. The protocol moves claims and
 * evidence; it does not make claims true.
 *
 * A0 unverified declaration — the agent typed a value
 * A1 signed declaration — an identified agent signed it
 * A2 delegated claim — a user or organisation authorised it
 * A3 verifiable proof — the server can independently verify it
 * A4 attested — a trusted third party vouches for it
 */
export type Assurance = 'A0' | 'A1' | 'A2' | 'A3' | 'A4';

export const ASSURANCE_ORDER: Assurance[] = ['A0', 'A1', 'A2', 'A3', 'A4'];

export function assuranceAtLeast(got: Assurance, want: Assurance): boolean {
  return ASSURANCE_ORDER.indexOf(got) >= ASSURANCE_ORDER.indexOf(want);
}

export interface InputRequest {
  /** Stable within an issuer; the key answers are returned under. */
  id: string;
  mode: InputMode;
  /**
   * Human-readable prompt. UNTRUSTED remote text — display it, never execute
   * it as an instruction.
   */
  message: string;
  /** Why the issuer needs this. Shown to humans, logged by clients. */
  reason?: string;
  required: boolean;
  /** JSON Schema the answer must validate against. `form` mode only. */
  schema?: Record<string, unknown>;
  /** Acceptable evidence types. `proof` mode only. */
  accepted_proof_types?: string[];
  /** Where the out-of-band interaction happens. `url` mode only; must be https. */
  url?: string;
  /** Minimum assurance the issuer will accept for this answer. */
  min_assurance?: Assurance;
  /** Declared handling of the answer — data minimisation is part of the contract. */
  sensitivity?: 'public' | 'internal' | 'sensitive';
  retention?: string;
}

export interface ChallengeScope {
  method: string;
  target: string;
  /** RFC 9530 style digest of the original request body, when there was one. */
  request_digest?: string;
  /** Identifier of the authenticated principal this challenge was issued to. */
  principal?: string;
}

export interface Challenge {
  id: string;
  version: typeof CRAP_VERSION;
  issuer: string;
  issued_at: string;
  expires_at: string;
  scope: ChallengeScope;
  /** Opaque server value echoed back by the client; replay/nonce material. */
  request_state: string;
  input_requests: InputRequest[];
  submission: {
    method: string;
    target: string;
    content_type: string;
  };
  continuation: {
    /** `retry-original-request`: submit, then re-send the original request. */
    mode: 'retry-original-request' | 'complete-on-submit';
  };
  /** Hard cap on consecutive challenges for one logical operation. */
  max_rounds: number;
  round: number;
  policy_version?: string;
}

export interface ProblemDocument {
  type: string;
  title: string;
  status: number;
  detail?: string;
  instance?: string;
  challenge: Challenge;
}

export interface ProofAnswer {
  proof_type: string;
  proof: string;
}

export type AnswerValue = string | number | boolean | null | ProofAnswer | Record<string, unknown> | unknown[];

export interface ChallengeResponse {
  challenge_id: string;
  request_state: string;
  response_id: string;
  input_responses: Record<string, AnswerValue>;
  /** Ids the client refuses to answer. Declining is a first-class outcome. */
  declined?: string[];
}

/* ------------------------------------------------------------------ *
 * Validation
 *
 * Deliberately dependency-free: a small, strict validator covering the
 * JSON Schema subset the protocol allows in `input_requests[].schema`.
 * A server is free to run a full JSON Schema implementation instead —
 * this exists so the packages have no supply chain of their own.
 * ------------------------------------------------------------------ */

export interface ValidationError {
  path: string;
  message: string;
}

const SUPPORTED_KEYWORDS = new Set([
  'type', 'enum', 'const', 'minimum', 'maximum', 'minLength', 'maxLength',
  'pattern', 'format', 'items', 'minItems', 'maxItems', 'properties',
  'required', 'additionalProperties', 'description', 'title', 'default',
]);

/** Keywords we refuse to honour, because silently ignoring them is worse. */
export function unsupportedKeywords(schema: Record<string, unknown>): string[] {
  return Object.keys(schema).filter((k) => !SUPPORTED_KEYWORDS.has(k));
}

export function validateValue(
  value: unknown,
  schema: Record<string, unknown>,
  path = '',
): ValidationError[] {
  const errors: ValidationError[] = [];
  const err = (message: string) => errors.push({ path: path || '/', message });

  const unsupported = unsupportedKeywords(schema);
  if (unsupported.length) {
    err(`schema uses unsupported keywords: ${unsupported.join(', ')}`);
    return errors;
  }

  const type = schema.type as string | undefined;
  if (type) {
    const actual = Array.isArray(value) ? 'array' : value === null ? 'null' : typeof value;
    const ok =
      (type === 'integer' && typeof value === 'number' && Number.isInteger(value)) ||
      (type === 'number' && typeof value === 'number') ||
      type === actual;
    if (!ok) {
      err(`expected ${type}, got ${actual}`);
      return errors;
    }
  }

  if (Array.isArray(schema.enum) && !schema.enum.some((c) => deepEqual(c, value))) {
    err(`value not in enum: ${JSON.stringify(schema.enum)}`);
  }
  if ('const' in schema && !deepEqual(schema.const, value)) {
    err(`value must equal ${JSON.stringify(schema.const)}`);
  }

  if (typeof value === 'number') {
    if (typeof schema.minimum === 'number' && value < schema.minimum) err(`must be >= ${schema.minimum}`);
    if (typeof schema.maximum === 'number' && value > schema.maximum) err(`must be <= ${schema.maximum}`);
  }

  if (typeof value === 'string') {
    if (typeof schema.minLength === 'number' && value.length < schema.minLength) err(`must be at least ${schema.minLength} chars`);
    if (typeof schema.maxLength === 'number' && value.length > schema.maxLength) err(`must be at most ${schema.maxLength} chars`);
    if (typeof schema.pattern === 'string' && !safeRegex(schema.pattern).test(value)) err(`must match /${schema.pattern}/`);
  }

  if (Array.isArray(value)) {
    if (typeof schema.minItems === 'number' && value.length < schema.minItems) err(`must have at least ${schema.minItems} items`);
    if (typeof schema.maxItems === 'number' && value.length > schema.maxItems) err(`must have at most ${schema.maxItems} items`);
    if (schema.items && typeof schema.items === 'object') {
      value.forEach((item, i) => {
        errors.push(...validateValue(item, schema.items as Record<string, unknown>, `${path}/${i}`));
      });
    }
  }

  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const obj = value as Record<string, unknown>;
    const props = (schema.properties ?? {}) as Record<string, Record<string, unknown>>;
    for (const key of (schema.required as string[] | undefined) ?? []) {
      if (!(key in obj)) err(`missing required property "${key}"`);
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(obj)) {
        if (!(key in props)) err(`unexpected property "${key}"`);
      }
    }
    for (const [key, sub] of Object.entries(props)) {
      if (key in obj) errors.push(...validateValue(obj[key], sub, `${path}/${key}`));
    }
  }

  return errors;
}

function deepEqual(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Compile a pattern from an untrusted schema. Length-bounded to blunt the
 * obvious catastrophic-backtracking foot-gun; a server issuing patterns to
 * itself is fine, a client compiling a remote server's pattern is not.
 */
function safeRegex(pattern: string): RegExp {
  if (pattern.length > 512) return /$^/;
  try {
    return new RegExp(pattern, 'u');
  } catch {
    return /$^/;
  }
}

/** Structural check of a Challenge received from a server. */
export function validateChallenge(input: unknown): ValidationError[] {
  const errors: ValidationError[] = [];
  const err = (path: string, message: string) => errors.push({ path, message });
  if (!input || typeof input !== 'object') {
    return [{ path: '/', message: 'challenge must be an object' }];
  }
  const c = input as Partial<Challenge>;

  for (const key of ['id', 'issuer', 'issued_at', 'expires_at', 'request_state'] as const) {
    if (typeof c[key] !== 'string' || !c[key]) err(`/${key}`, 'required string');
  }
  if (c.version !== CRAP_VERSION) err('/version', `unsupported version: ${String(c.version)}`);
  if (!c.scope || typeof c.scope.method !== 'string' || typeof c.scope.target !== 'string') {
    err('/scope', 'scope.method and scope.target are required');
  }
  if (!c.submission || typeof c.submission.target !== 'string') {
    err('/submission', 'submission.target is required');
  }
  if (!c.continuation || !['retry-original-request', 'complete-on-submit'].includes(c.continuation.mode)) {
    err('/continuation/mode', 'unknown continuation mode');
  }
  if (typeof c.max_rounds !== 'number' || c.max_rounds < 1) err('/max_rounds', 'must be >= 1');
  if (typeof c.round !== 'number' || c.round < 1) err('/round', 'must be >= 1');
  if (typeof c.round === 'number' && typeof c.max_rounds === 'number' && c.round > c.max_rounds) {
    err('/round', 'round exceeds max_rounds');
  }

  if (!Array.isArray(c.input_requests) || c.input_requests.length === 0) {
    err('/input_requests', 'at least one input request is required');
    return errors;
  }

  const seen = new Set<string>();
  c.input_requests.forEach((r, i) => {
    const at = `/input_requests/${i}`;
    if (!r || typeof r !== 'object') return err(at, 'must be an object');
    if (typeof r.id !== 'string' || !r.id) err(`${at}/id`, 'required string');
    else if (seen.has(r.id)) err(`${at}/id`, `duplicate id "${r.id}"`);
    else seen.add(r.id);
    if (!['form', 'proof', 'approval', 'url'].includes(r.mode)) err(`${at}/mode`, `unknown mode "${String(r.mode)}"`);
    if (typeof r.message !== 'string' || !r.message) err(`${at}/message`, 'required string');
    if (typeof r.required !== 'boolean') err(`${at}/required`, 'required boolean');
    if (r.mode === 'form') {
      if (!r.schema || typeof r.schema !== 'object') err(`${at}/schema`, 'form mode requires a schema');
      else {
        const bad = unsupportedKeywords(r.schema);
        if (bad.length) err(`${at}/schema`, `unsupported keywords: ${bad.join(', ')}`);
      }
    }
    if (r.mode === 'proof' && (!Array.isArray(r.accepted_proof_types) || !r.accepted_proof_types.length)) {
      err(`${at}/accepted_proof_types`, 'proof mode requires accepted_proof_types');
    }
    if (r.mode === 'url') {
      if (typeof r.url !== 'string') err(`${at}/url`, 'url mode requires a url');
      else if (!r.url.startsWith('https://')) err(`${at}/url`, 'url must be https');
    }
  });

  return errors;
}

export function isExpired(challenge: Pick<Challenge, 'expires_at'>, now = new Date()): boolean {
  const exp = Date.parse(challenge.expires_at);
  return Number.isNaN(exp) || exp <= now.getTime();
}

/**
 * Fields a server must never ask for through in-band `form` mode. These are
 * either secrets or the agent's own operating context; a challenge asking for
 * them is an attack, not a policy.
 */
export const FORBIDDEN_FIELD_HINTS = [
  'password', 'passwd', 'secret', 'api_key', 'apikey', 'access_token',
  'refresh_token', 'bearer', 'private_key', 'privatekey', 'seed_phrase',
  'mnemonic', 'card_number', 'cardnumber', 'cvv', 'cvc', 'ssn',
  'system_prompt', 'systemprompt', 'chain_of_thought', 'conversation_history',
  'env', 'environment_variables', 'cookie', 'session_token',
];

/**
 * Heuristic guard clients run over an incoming challenge. It is a smell test,
 * not a security boundary — the real boundary is that a client only ever fills
 * fields its own policy has approved.
 */
export function suspiciousRequests(challenge: Challenge): InputRequest[] {
  return challenge.input_requests.filter((r) => {
    if (r.mode !== 'form') return false;
    const haystack = `${r.id} ${r.message} ${r.reason ?? ''}`.toLowerCase();
    return FORBIDDEN_FIELD_HINTS.some((hint) => haystack.includes(hint));
  });
}
