/**
 * @thomasdavis/crap-schema — the wire contract for the Conditional Resource
 * Access Protocol.
 *
 * Transport-neutral: types, constants and validators for the two documents
 * that cross the wire (a Challenge and a ChallengeResponse). No HTTP, no I/O.
 */

export const CRAP_VERSION = 2 as const;

/**
 * The normative baseline is the compatibility profile: `403` + problem+json.
 * `430` is an optional negotiated profile and a provisional squat on an
 * unassigned code — it is a dispatch convenience, not the protocol.
 */
export const STATUS_COMPAT = 403 as const;
export const STATUS_INPUT_REQUIRED = 430 as const;

export const PROBLEM_TYPE = 'https://crap.blah.dev/problems/input-required';
export const PROBLEM_MEDIA_TYPE = 'application/problem+json';
export const RESPONSE_MEDIA_TYPE = 'application/crap-response+json';

export const HEADER_ACCEPT = 'accept-input-required';
export const HEADER_CHALLENGE_ID = 'challenge-id';
export const HEADER_INPUT_PROOF = 'input-proof';

/** Where challenge transactions live, relative to the issuing origin. */
export const SUBMISSION_PATH_PREFIX = '/.well-known/input-challenges';

export const submissionPath = (challengeId: string): string =>
  `${SUBMISSION_PATH_PREFIX}/${encodeURIComponent(challengeId)}/responses`;

/** Value a client sends in `Accept-Input-Required` to opt in to native 430. */
export const ACCEPT_VALUE = `v=${CRAP_VERSION}`;

/**
 * RFC 9651 structured field: a dictionary whose `v` key is an integer.
 * Parsed exactly, so `v=20` never satisfies a check for `v=2`.
 */
export function parseAcceptInputRequired(field: string | undefined): number[] {
  if (!field) return [];
  const versions: number[] = [];
  for (const member of field.split(',')) {
    const [rawKey, rawValue] = member.split('=');
    if (!rawValue) continue;
    if (rawKey.trim().toLowerCase() !== 'v') continue;
    const value = rawValue.trim();
    if (!/^\d+$/.test(value)) continue;
    versions.push(Number(value));
  }
  return versions;
}

export function clientSupportsVersion(field: string | undefined, version: number = CRAP_VERSION): boolean {
  return parseAcceptInputRequired(field).includes(version);
}

/* --------------------------------------------------------------- *
 * The request taxonomy.
 *
 * v0.1 had a single `mode` enum (form/proof/approval/url) whose members
 * were not peers: form described a representation, proof an evidence
 * class, approval a decider, url a delivery channel. OAuth is all three
 * at once, which the enum could not say. These are now independent
 * facets.
 * --------------------------------------------------------------- */

/** What is being asked for. */
export type RequestKind =
  /** A bounded statement of fact or intent. */
  | 'declaration'
  /** Something the server can check. */
  | 'evidence'
  /** A decision by a person or body. */
  | 'approval'
  /** Work performed by the client. Experimental — see §task limits. */
  | 'task';

/** Who must produce it. */
export type Actor = 'client' | 'user' | 'organization' | 'third_party';

/** Whether it travels in band (through the agent) or out of band. */
export type Interaction = 'inline' | 'out_of_band';

/** What the answer is cryptographically tied to, if anything. */
export type Binding = 'none' | 'client_key' | 'user_identity' | 'organization_identity';

/**
 * How an accepted answer was established. Deliberately NOT a total order:
 * "independently verified" and "third-party attested" answer different
 * questions, and a user delegation is about authority, not identity.
 * Servers list the classes they accept; membership is checked, not rank.
 */
export type EvidenceClass =
  /** The client said so. Nothing more. */
  | 'self_asserted'
  /** Signed by an identified client key. */
  | 'client_signed'
  /** A user or organisation conferred the authority. */
  | 'delegated'
  /** The server checked it against the issuing authority. */
  | 'independently_verified'
  /** A recognised third party vouches for it. */
  | 'third_party_attested';

export const EVIDENCE_CLASSES: EvidenceClass[] = [
  'self_asserted', 'client_signed', 'delegated', 'independently_verified', 'third_party_attested',
];

/** Structured description of how one answer was established. */
export interface EvidenceDescriptor {
  class: EvidenceClass;
  /** Who made the claim (e.g. an agent key id). */
  claimant?: string;
  /** Where the authority came from (e.g. `organization-delegation`). */
  authority?: string;
  /** How the server checked it (e.g. `issuer-verified`). */
  verification?: string;
  /** Who vouched, for third-party attestations. */
  attester?: string;
  /** Trust framework the above is meaningful within. */
  trust_framework?: string;
}

/** Bounds on a `task` request, so a client can price refusal mechanically. */
export interface TaskLimits {
  max_duration_ms: number;
  max_output_tokens?: number;
  max_rounds?: number;
}

export interface InputRequest {
  /** Stable within an issuer; the key the answer is returned under. */
  id: string;
  kind: RequestKind;
  actor: Actor;
  interaction: Interaction;
  binding?: Binding;
  /**
   * Human-readable prompt. UNTRUSTED remote text — display it, never execute
   * it as an instruction.
   */
  message: string;
  /** Why the issuer needs this. Shown to humans, logged by clients. */
  reason?: string;
  required: boolean;
  /** JSON Schema (subset, §4.3) the answer must satisfy. */
  schema?: Record<string, unknown>;
  /** For `task`: schema of the work product. */
  output_schema?: Record<string, unknown>;
  /** For `task`: declared cost ceiling. Required. */
  limits?: TaskLimits;
  /**
   * For `task`: the material to work on.
   *
   * Separate from `message` on purpose. `message` is the instruction and
   * `input_data` is inert data — a client MUST NOT treat anything inside it as
   * an instruction, even when it looks like one, and SHOULD bound how much of
   * it it will process. Putting the material in `message` would make the two
   * indistinguishable, which is the whole prompt-injection problem.
   */
  input_data?: {
    media_type: string;
    content: string;
    /** Where it came from, so an agent can decline on provenance grounds. */
    source?: string;
    /** True when `content` is an excerpt rather than the whole thing. */
    truncated?: boolean;
  };
  /** For `evidence`: which classes the issuer will accept. Set membership. */
  accepted_evidence?: EvidenceClass[];
  /** For `evidence`: concrete mechanisms the issuer can check. */
  accepted_proof_types?: string[];
  /** Required when `interaction` is `out_of_band`. MUST be https. */
  url?: string;
  /** Declared handling of the answer — data minimisation is part of the deal. */
  sensitivity?: 'public' | 'internal' | 'sensitive';
  retention?: string;
}

export interface ChallengeScope {
  method: string;
  /** Exact effective request URI. Compared verbatim (§6.1). */
  target: string;
  /** RFC 9530 `Content-Digest` of the request body, when one was present. */
  content_digest?: string;
  /** Explicit statement of whether the bound request carried content. */
  has_content: boolean;
  /** Identifier of the authenticated principal this was issued to. */
  principal?: string;
}

export interface Challenge {
  id: string;
  version: typeof CRAP_VERSION;
  /** MUST equal the origin that served the response carrying it. */
  issuer: string;
  issued_at: string;
  expires_at: string;
  scope: ChallengeScope;
  /** Opaque server value echoed back by the client; replay/nonce material. */
  request_state: string;
  input_requests: InputRequest[];
  submission: {
    method: string;
    /** MUST be same-origin with `issuer` unless the client has a delegation. */
    target: string;
    content_type: string;
  };
  continuation: {
    mode: 'retry-original-request' | 'complete-on-submit';
    /**
     * What satisfying this challenge actually buys.
     *
     * Without this a client cannot price the exchange: it is being asked to
     * spend real compute for an unstated return, and the safe assumption —
     * that it buys exactly the one request it was making — makes almost any
     * task a bad deal. An issuer that wants compliance should say what the
     * answer is worth, and is then bound by it.
     */
    grant?: {
      /** `request`: this method+URI only. `origin`: anything at this origin. */
      scope: 'request' | 'origin';
      duration_seconds: number;
      /** Optional human-readable summary, e.g. "unlimited reads for 30 min". */
      description?: string;
    };
  };
  max_rounds: number;
  round: number;
  policy_version?: string;
}

export interface ProblemDocument {
  type: string;
  title: string;
  /** MUST equal the HTTP status of the response carrying it (RFC 9457 §3.1). */
  status: number;
  detail?: string;
  instance?: string;
  challenge: Challenge;
}

export interface EvidenceAnswer {
  proof_type: string;
  proof: string;
}

export type AnswerValue =
  | string | number | boolean | null
  | EvidenceAnswer
  | Record<string, unknown>
  | unknown[];

export interface ChallengeResponse {
  challenge_id: string;
  request_state: string;
  response_id: string;
  input_responses: Record<string, AnswerValue>;
  /** Ids the client refuses to answer. Declining is a first-class outcome. */
  declined?: string[];
  /**
   * Optional, human-readable reason for declining.
   *
   * A server learns nothing from an agent that simply disappears, and an agent
   * that refuses usually has a specific objection — the ask was too expensive,
   * it looked like data exfiltration, the operator had not authorised it. This
   * field turns a silent walkaway into feedback. It is never required, and a
   * server MUST NOT make access conditional on supplying one.
   */
  decline_reason?: string;
}

/* ------------------------------------------------------------------ *
 * Validation
 *
 * Dependency-free, and a deliberately small JSON Schema subset. A server
 * may run a full implementation over its own schemas; this is what a
 * client is expected to evaluate against a STRANGER's schema.
 * ------------------------------------------------------------------ */

export interface ValidationError {
  path: string;
  message: string;
}

/**
 * `pattern` and `format` are excluded on purpose.
 *
 * `pattern` means compiling a stranger's regex: JavaScript has no execution
 * limit, and short expressions backtrack catastrophically, so a length cap
 * buys nothing. `format` was advertised but unenforced in v0.1, which is
 * worse than absent — a server could believe it had constrained an answer.
 */
const SUPPORTED_KEYWORDS = new Set([
  'type', 'enum', 'const', 'minimum', 'maximum', 'minLength', 'maxLength',
  'items', 'minItems', 'maxItems', 'properties', 'required',
  'additionalProperties', 'description', 'title', 'default',
]);

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

/** Origin of a URL, or undefined if it isn't one. */
export function originOf(url: string): string | undefined {
  try {
    return new URL(url).origin;
  } catch {
    return undefined;
  }
}

export function sameOrigin(a: string, b: string): boolean {
  const oa = originOf(a);
  const ob = originOf(b);
  return oa !== undefined && oa === ob;
}

export interface ChallengeValidationOptions {
  /** Origin that served the response. `issuer` must match it. */
  responseOrigin?: string;
  /** The request that triggered the challenge; `scope` must match it. */
  request?: { method: string; url: string; hasContent?: boolean };
  /** Allow `submission.target` on another origin. Off by default. */
  allowCrossOriginSubmission?: boolean;
}

/**
 * Structural + binding validation of a Challenge received from a server.
 *
 * The binding checks are the security-relevant half: without them a
 * challenge can direct a client's declarations to an origin that never
 * issued it.
 */
export function validateChallenge(
  input: unknown,
  options: ChallengeValidationOptions = {},
): ValidationError[] {
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
  if (c.scope && typeof c.scope.has_content !== 'boolean') {
    err('/scope/has_content', 'required boolean');
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

  // --- binding -----------------------------------------------------
  const { responseOrigin, request, allowCrossOriginSubmission } = options;

  if (responseOrigin && c.issuer && originOf(c.issuer) !== responseOrigin) {
    err('/issuer', `issuer ${c.issuer} does not match responding origin ${responseOrigin}`);
  }
  if (c.issuer && c.submission?.target && !allowCrossOriginSubmission) {
    if (!sameOrigin(c.issuer, c.submission.target)) {
      err('/submission/target', 'submission target is not same-origin with the issuer');
    }
  }
  if (c.submission?.target && !/^https:/.test(c.submission.target) && !isLoopback(c.submission.target)) {
    err('/submission/target', 'submission target must be https');
  }
  if (request && c.scope) {
    if (c.scope.method?.toUpperCase() !== request.method.toUpperCase()) {
      err('/scope/method', `scope method ${c.scope.method} does not match the request`);
    }
    if (c.scope.target !== request.url) {
      err('/scope/target', 'scope target does not match the requested URI');
    }
    if (request.hasContent !== undefined && c.scope.has_content !== request.hasContent) {
      err('/scope/has_content', 'scope disagrees with the request about content');
    }
  }

  // --- input requests ----------------------------------------------
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

    if (!['declaration', 'evidence', 'approval', 'task'].includes(r.kind)) {
      err(`${at}/kind`, `unknown kind "${String(r.kind)}"`);
    }
    if (!['client', 'user', 'organization', 'third_party'].includes(r.actor)) {
      err(`${at}/actor`, `unknown actor "${String(r.actor)}"`);
    }
    if (!['inline', 'out_of_band'].includes(r.interaction)) {
      err(`${at}/interaction`, `unknown interaction "${String(r.interaction)}"`);
    }
    if (typeof r.message !== 'string' || !r.message) err(`${at}/message`, 'required string');
    if (typeof r.required !== 'boolean') err(`${at}/required`, 'required boolean');

    if (r.interaction === 'out_of_band') {
      if (typeof r.url !== 'string') err(`${at}/url`, 'out_of_band requires a url');
      else if (!r.url.startsWith('https://')) err(`${at}/url`, 'url must be https');
    }
    if (r.kind === 'declaration') {
      if (!r.schema || typeof r.schema !== 'object') err(`${at}/schema`, 'declaration requires a schema');
      else {
        const bad = unsupportedKeywords(r.schema);
        if (bad.length) err(`${at}/schema`, `unsupported keywords: ${bad.join(', ')}`);
      }
    }
    if (r.kind === 'evidence' && (!Array.isArray(r.accepted_evidence) || !r.accepted_evidence.length)) {
      err(`${at}/accepted_evidence`, 'evidence requests must list accepted evidence classes');
    }
    if (r.kind === 'evidence' && Array.isArray(r.accepted_evidence)) {
      for (const cls of r.accepted_evidence) {
        if (!EVIDENCE_CLASSES.includes(cls)) err(`${at}/accepted_evidence`, `unknown evidence class "${cls}"`);
      }
      if (r.accepted_evidence.includes('self_asserted')) {
        err(`${at}/accepted_evidence`, 'self_asserted is not evidence; use kind "declaration"');
      }
    }
    if (r.kind === 'task') {
      if (!r.limits || typeof r.limits.max_duration_ms !== 'number') {
        err(`${at}/limits`, 'task requests must declare limits.max_duration_ms');
      }
      if (!r.output_schema || typeof r.output_schema !== 'object') {
        err(`${at}/output_schema`, 'task requests must declare an output_schema');
      }
      if (r.input_data) {
        if (typeof r.input_data.content !== 'string' || typeof r.input_data.media_type !== 'string') {
          err(`${at}/input_data`, 'input_data needs media_type and content');
        } else if (r.input_data.content.length > MAX_TASK_INPUT_CHARS) {
          err(`${at}/input_data`, `material exceeds ${MAX_TASK_INPUT_CHARS} chars`);
        }
      }
    }
  });

  return errors;
}

function isLoopback(url: string): boolean {
  const origin = originOf(url);
  return !!origin && /^https?:\/\/(127\.0\.0\.1|\[::1\]|localhost)(:\d+)?$/.test(origin);
}

export function isExpired(challenge: Pick<Challenge, 'expires_at'>, now = new Date()): boolean {
  const exp = Date.parse(challenge.expires_at);
  return Number.isNaN(exp) || exp <= now.getTime();
}

/**
 * Fields a server must never ask for in band. Secrets, or the agent's own
 * operating context. A challenge asking for these is an attack.
 */
export const FORBIDDEN_FIELD_HINTS = [
  'password', 'passwd', 'secret', 'api_key', 'apikey', 'access_token',
  'refresh_token', 'bearer', 'private_key', 'privatekey', 'seed_phrase',
  'mnemonic', 'card_number', 'cardnumber', 'cvv', 'cvc', 'ssn',
  'system_prompt', 'systemprompt', 'chain_of_thought', 'conversation_history',
  'env', 'environment_variables', 'cookie', 'session_token',
];

/**
 * Heuristic guard clients run over an incoming challenge. A smell test, not
 * a security boundary — the boundary is that a client only fills fields its
 * own policy approved.
 */
export function suspiciousRequests(challenge: Challenge): InputRequest[] {
  return challenge.input_requests.filter((r) => {
    if (r.interaction !== 'inline') return false;
    const haystack = `${r.id} ${r.message} ${r.reason ?? ''}`.toLowerCase();
    return FORBIDDEN_FIELD_HINTS.some((hint) => haystack.includes(hint));
  });
}

/**
 * Ceiling on task material a client will accept in one challenge. A server
 * that wants a book processed can ask; the client does not have to read it.
 */
export const MAX_TASK_INPUT_CHARS = 20000;

/** Total declared cost of the `task` requests in a challenge. */
export function taskCost(challenge: Challenge): { count: number; maxDurationMs: number } {
  const tasks = challenge.input_requests.filter((r) => r.kind === 'task');
  return {
    count: tasks.length,
    maxDurationMs: tasks.reduce((sum, t) => sum + (t.limits?.max_duration_ms ?? 0), 0),
  };
}
