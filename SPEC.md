# CRAP: Conditional Resource Access Protocol

**Version:** 0.2 (experimental)
**Status:** working draft, no IANA registrations, breaking changes expected
**Normative baseline:** `403` + `application/problem+json`
**Optional negotiated profile:** `430 Input Required` (provisional squat)
**Problem type:** `https://crap.blah.dev/problems/input-required`
**Response media type:** `application/crap-response+json`

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

> **Changes from 0.1.** The `mode` enum split into independent facets (`kind`,
> `actor`, `interaction`, `binding`), because form/proof/approval/url were not
> peers. The A0–A4 assurance ladder became unordered evidence classes, because
> it is not a total order. Answers submit to a dedicated transaction resource,
> not the protected resource. Continuation proofs are opaque and carry no
> answer values. Content presence is bound in both directions. Targets are
> compared verbatim. `pattern` and `format` left the schema subset.

---

## 1. Overview

An origin server MAY respond to an otherwise-valid request with a
**challenge**: a machine-readable set of **input requests** the client must
satisfy before the request can be processed. The client submits **answers** to
a challenge transaction resource, receives a scoped **continuation proof**, and
retries the original request.

The protocol is a carrier. It defines how requirements and answers travel, how
they bind to a request, and how an accepted answer's provenance is recorded. It
does not define what may be asked — that is the application's business.

```
  Client                                     Server
    │                                           │
    │ GET /records                              │
    │ Accept-Input-Required: v=2                │
    │──────────────────────────────────────────▶│  policy: input_required
    │ 430 Input Required  (or 403, §3)          │
    │ problem+json { challenge }                │
    │◀──────────────────────────────────────────│
    │                                           │
    │ POST /.well-known/input-challenges/{id}/responses
    │ Content-Type: application/crap-response+json
    │ { challenge_id, request_state, answers }   │
    │──────────────────────────────────────────▶│  validate, verify, consume
    │ 204 No Content                            │
    │ Input-Proof: ip1.<opaque handle>          │
    │◀──────────────────────────────────────────│
    │                                           │
    │ GET /records                              │
    │ Input-Proof: ip1.<opaque handle>          │
    │──────────────────────────────────────────▶│  verify binding
    │ 200 OK                                    │
    │◀──────────────────────────────────────────│
```

## 2. Status codes

### 2.1 The baseline is `403`

The normative v0.2 wire format is a `403 Forbidden` carrying
`application/problem+json` with the CRAP problem type. Clients MUST detect a
challenge by the problem `type`, never by the status code.

This is the durable part of the protocol: the problem type, the challenge
document, submission semantics, request binding, the continuation proof, and
the client's right to refuse. The status code is only a dispatch convenience.

### 2.2 `430 Input Required` (provisional, optional)

> The origin server understands the request and MAY be willing to process it,
> but requires the client to satisfy one or more application-level input
> requirements first. The response describes those requirements and how to
> fulfil them. After satisfying them, the client MAY retry the original
> request.

`430` is unassigned in the IANA HTTP Status Code Registry at the time of
writing; this document squats on it provisionally. A server MUST NOT return
`430` unless the client advertised support (§3.1). Nothing in this protocol
depends on `430` being registered.

Both profiles MUST be sent with `Cache-Control: no-store` and
`Vary: Accept-Input-Required`.

### 2.3 Choosing the right status

| Condition | Status |
|---|---|
| Credentials absent, invalid, or insufficient | `401` |
| Payment required (`402` is reserved; concrete schemes profile it) | `402` |
| Final policy decision; more input will not help | `403` |
| Request conflicts with resource state | `409` |
| The submitted representation is itself invalid | `422` |
| Client must slow down | `429` |
| Recoverable, application-defined input needed | `403` + problem type, or `430` |

A server MUST NOT issue a challenge when it has already decided to refuse. A
challenge is a promise that an answer exists which would change the outcome.

## 3. Capability negotiation

### 3.1 `Accept-Input-Required`

A client that understands this protocol SHOULD send an RFC 9651 structured
dictionary:

```
Accept-Input-Required: v=2
```

Servers MUST parse this as a structured field and compare the integer exactly.
A substring test is non-conforming: `v=20` does not indicate support for
version 2.

A server MUST NOT respond `430` to a request lacking a matching version.

### 3.2 Compatibility profile

When the client has not opted in, the server sends the same problem document
with status `403`. The two profiles are semantically identical but NOT
byte-identical: RFC 9457 §3.1 requires the `status` member to match the actual
HTTP status, so it is `403` in one and `430` in the other.

## 4. The challenge

Sent as `application/problem+json` (RFC 9457) with a `challenge` member.

```json
{
  "type": "https://crap.blah.dev/problems/input-required",
  "title": "Input Required",
  "status": 403,
  "detail": "This resource requires additional input before it can be served.",
  "instance": "https://data.example/v1/records",
  "challenge": {
    "id": "ch_zC4mV8xQ",
    "version": 2,
    "issuer": "https://data.example",
    "issued_at": "2026-08-02T00:00:00Z",
    "expires_at": "2026-08-02T00:15:00Z",
    "request_state": "6Rk9…opaque…",
    "scope": {
      "method": "GET",
      "target": "https://data.example/v1/records",
      "has_content": false,
      "principal": "acct:agent-7"
    },
    "input_requests": [ … ],
    "submission": {
      "method": "POST",
      "target": "https://data.example/.well-known/input-challenges/ch_zC4mV8xQ/responses",
      "content_type": "application/crap-response+json"
    },
    "continuation": { "mode": "retry-original-request" },
    "max_rounds": 3,
    "round": 1
  }
}
```

### 4.1 Challenge members

| Member | Req | Meaning |
|---|---|---|
| `id` | ✔ | Unique challenge identifier. |
| `version` | ✔ | Protocol version. `2`. |
| `issuer` | ✔ | Origin that issued it. MUST equal the responding origin (§7.2). |
| `issued_at` / `expires_at` | ✔ | RFC 3339 timestamps. |
| `request_state` | ✔ | Opaque server value; the client MUST echo it. Nonce material. |
| `scope` | ✔ | The request this challenge binds to (§6.1). |
| `input_requests` | ✔ | One or more requirements. |
| `submission` | ✔ | The transaction resource (§6.2). |
| `continuation` | ✔ | `retry-original-request` or `complete-on-submit`. |
| `max_rounds` / `round` | ✔ | Loop bound (§6.5). |
| `policy_version` | | Which version of the issuer's policy produced this. |

### 4.2 Input requests

A requirement is described by four independent facets. v0.1 used a single
`mode` enum whose members were not peers — `form` described a representation,
`proof` an evidence class, `approval` a decider, `url` a delivery channel — so
OAuth (out-of-band, user-mediated, evidence-producing) could not be expressed.

```json
{
  "id": "purpose",
  "kind": "declaration",
  "actor": "client",
  "interaction": "inline",
  "message": "What is this data for?",
  "reason": "The collection has purpose-specific access conditions.",
  "required": true,
  "sensitivity": "internal",
  "retention": "P1Y",
  "schema": {
    "type": "string",
    "enum": ["academic_research", "commercial_product", "model_training"]
  }
}
```

| Facet | Values | Question it answers |
|---|---|---|
| `kind` | `declaration` \| `evidence` \| `approval` \| `task` | What is being asked for? |
| `actor` | `client` \| `user` \| `organization` \| `third_party` | Who must produce it? |
| `interaction` | `inline` \| `out_of_band` | Does it pass through the agent? |
| `binding` | `none` \| `client_key` \| `user_identity` \| `organization_identity` | What is it tied to? |

Which composes the cases that mattered:

| Requirement | kind | actor | interaction | binding |
|---|---|---|---|---|
| Purpose of use | declaration | client | inline | none |
| Human confirmation | approval | user | out_of_band | user_identity |
| OAuth delegation | evidence | user | out_of_band | user_identity |
| Verifiable credential | evidence | third_party | inline | organization_identity |
| Work as toll (§5.4) | task | client | inline | none |

Other members:

| Member | Req | Meaning |
|---|---|---|
| `id` | ✔ | Key the answer returns under. Unique within a challenge. |
| `message` | ✔ | Human-readable prompt. **Untrusted text** (§7.1). |
| `required` | ✔ | Whether declining fails the challenge. |
| `reason` | | Why the issuer needs it. SHOULD be present. |
| `schema` | declaration | JSON Schema subset (§4.3). |
| `accepted_evidence` | evidence | Evidence classes accepted (§8). Set membership. |
| `accepted_proof_types` | | Concrete mechanisms the issuer can check. |
| `output_schema` / `limits` | task | Work product shape and cost ceiling (§5.4). |
| `url` | out_of_band | HTTPS location of the interaction. |
| `sensitivity` / `retention` | | Declared handling of the answer. |

### 4.3 Schema subset

Restricted to: `type`, `enum`, `const`, `minimum`, `maximum`, `minLength`,
`maxLength`, `items`, `minItems`, `maxItems`, `properties`, `required`,
`additionalProperties`, `description`, `title`, `default`.

A client encountering any other keyword MUST reject the challenge rather than
ignore it. `$ref`, `allOf`/`anyOf`/`oneOf` and remote schema loading are
excluded: a client MUST NOT fetch a schema over the network to understand a
requirement.

`pattern` and `format` were in the v0.1 subset and are now excluded.
`pattern` requires compiling a stranger's regular expression, and a length cap
does not prevent catastrophic backtracking — short expressions backtrack fine.
An implementation wanting `pattern` MUST use a linear-time engine (RE2 or
equivalent) and MUST declare that it does. `format` was advertised but
unenforced in v0.1, which is worse than absent: a server could believe it had
constrained an answer that nothing checked.

## 5. Kinds

### 5.1 `declaration`

A bounded statement of fact or intent, answerable by the client from its own
policy and context. Always `self_asserted` (§8) — a declaration is a claim, and
no amount of schema validation makes it true.

A server MUST NOT request, and a client MUST refuse, in-band declarations of:
passwords, API keys, access or refresh tokens, private keys, seed phrases,
payment card data, or the client's own operating context (system prompt,
reasoning trace, conversation history, environment variables, cookies).

### 5.2 `evidence`

Something the server can check: HTTP Message Signatures (RFC 9421), OAuth
delegation, verifiable credentials, key-possession proofs, attestations.

The answer is `{ "proof_type": "…", "proof": "…" }`. Servers MUST verify
evidence and MUST assign an evidence class from verification, never from what
the answer called itself. `accepted_evidence` MUST NOT include `self_asserted`;
an unverifiable requirement is a `declaration`.

### 5.3 `approval`

A decision by a person or body. Clients MUST surface these outside the agent's
autonomous path and MUST NOT allow a model to self-approve. The answer SHOULD
be a signed approval receipt.

### 5.4 `task` (experimental)

Work performed by the client as a condition of access — the "computational
toll" application. It is separated from `declaration` deliberately: it has a
different cost, abuse, fairness and denial-of-service profile, and a
conservative client may support declarations while refusing all tasks.

A `task` request MUST declare `output_schema` and `limits.max_duration_ms`. A
client MUST reject a task with no declared limits as unbounded, and SHOULD
refuse tasks exceeding a local budget. The reference client's default budget is
zero: tasks are opt-in.

```json
{
  "id": "classify",
  "kind": "task",
  "actor": "client",
  "interaction": "inline",
  "message": "Classify this document under the supplied taxonomy.",
  "required": true,
  "output_schema": { "type": "string", "enum": ["policy", "correspondence", "report"] },
  "limits": { "max_duration_ms": 5000, "max_output_tokens": 500, "max_rounds": 1 },
  "compensation": { "type": "conditional_access" }
}
```

Servers MUST NOT treat task output as verified information. It is
`self_asserted` output from a party with an incentive to answer quickly rather
than correctly, and SHOULD be sampled, cross-checked or corroborated before it
is relied upon.

### 5.5 Out-of-band interaction

When `interaction` is `out_of_band`, the exchange happens at `url`: OAuth
consent, identity verification, payment, legally significant acceptance. Values
entered there never enter the agent's context. This is the only correct place
for anything §5.1 forbids in band.

## 6. Binding

### 6.1 Scope

A challenge binds to: method, the **exact effective request URI**, content
presence, content digest when present, and principal.

Targets are compared **verbatim**. Implementations MUST NOT canonicalise the
query — sorting parameters changes application semantics for repeated
parameters and for APIs where order is meaningful. Where finer-grained
component coverage is wanted, use the derived components of RFC 9421 rather
than inventing a canonicalisation rule.

`scope.has_content` states whether the bound request carried content, and MUST
be bound in both directions:

```
proof has content  ⇔  retried request has content
```

A proof minted for a request with a body MUST NOT be presentable on one
without, and vice versa. When content is present, `scope.content_digest`
carries the RFC 9530 `Content-Digest` value and MUST match.

### 6.2 Submission

Answers are POSTed to a challenge transaction resource, NOT to the protected
resource — protocol answers otherwise collide with the resource's own `POST`
semantics and force middleware to discriminate by content type.

```
POST /.well-known/input-challenges/{challenge_id}/responses
Content-Type: application/crap-response+json
```

```json
{
  "challenge_id": "ch_zC4mV8xQ",
  "request_state": "6Rk9…opaque…",
  "response_id": "rsp_9f21…",
  "input_responses": { "purpose": "academic_research" },
  "declined": ["retention"]
}
```

`submission.target` MUST be same-origin with `issuer`. A client MUST reject a
cross-origin submission target unless it holds an explicit, separately
authenticated delegation permitting it; an `https` scheme is not sufficient.
Without this, a challenge can direct a client's declarations to an origin that
never asked for them.

The server MUST reject the submission if: the challenge is unknown, expired, or
already consumed; the id in the path differs from the body; `request_state`
does not match; the principal differs; a required input is missing or declined;
any answer fails its schema; or any evidence class is not in
`accepted_evidence`. Schema failures return `422` with a machine-readable
`errors` array; everything else returns `403`.

On success: `204 No Content` with an `Input-Proof` header.

### 6.3 Continuation proof

`Input-Proof` is opaque to the client. It MUST bind: issuing origin, method,
exact target, content presence and digest, principal, round, and an expiry. It
SHOULD be short-lived (minutes) and SHOULD be sender-constrained where the
client has a key.

A proof MUST NOT carry answer values. Headers are logged by servers, proxies
and telemetry pipelines; purpose, retention and delegation metadata do not
belong there, and large answers break header size limits. Two profiles:

- **`ip1` (opaque, default)** — a random handle; the decision, answers and
  scope hash live server-side.
- **`ip2` (stateless)** — a signed token carrying a decision id, scope hash and
  a **digest** of the answers. Still no values.

A proof MUST NOT be usable at another origin, for another method, target or
content, by another principal, or after expiry. A proof is not a session token
and MUST NOT be accepted in place of authentication.

### 6.4 Idempotency

Answering a challenge MUST be single-use. Retrying the original request with a
valid unexpired proof is not a replay and MAY be repeated until expiry.

### 6.5 Rounds

A server MAY issue a further challenge after a successful submission.
`round` increments; when it would exceed `max_rounds` the server MUST return a
final `403`. Default cap 3. Clients MUST independently cap rounds.

## 7. Security considerations

### 7.1 Challenges are attacker-controlled input

`message` and `reason` are remote text delivered into an agent's execution
context, and this protocol lets any server put arbitrary prose in front of any
agent. Clients MUST treat challenge text as data, MUST fill only declared
fields per their own policy, and MUST NOT act on instructions embedded in it.
Client policy MUST override server request in all cases.

Servers SHOULD assume the same in reverse: an answer is text an agent produced,
possibly under a third party's influence.

### 7.2 Challenge-to-exchange binding

Before answering, a client MUST verify that:

```
challenge.issuer origin  == responding origin
challenge.scope.method   == the method it sent
challenge.scope.target   == the URI it requested
challenge.scope.has_content == whether it sent content
submission.target origin == challenge.issuer origin
```

A challenge failing any of these MUST be rejected without answering.

### 7.3 Interrogation and surveillance

An open-ended requirement channel is an open-ended data-collection channel.
Requests SHOULD declare `reason`, `sensitivity` and `retention`. Clients MUST
be able to decline any individual requirement and refuse a challenge entirely.
Servers MUST NOT treat declining as grounds for anything beyond the `403` the
client already accepted.

### 7.4 Proof theft

A stolen proof is a stolen request, bounded by §6.3. Sender-constrain proofs
where agent keys exist (Web Bot Auth, RFC 9421).

### 7.5 Cache safety

Challenges, submissions and proof-bearing responses MUST be `Cache-Control:
no-store`, and challenge responses MUST send `Vary: Accept-Input-Required`
since status and representation depend on it. A challenge MUST NOT be shared
between principals through a shared cache.

### 7.6 Denial of service

Issuance is cheap, verification is not. Servers SHOULD rate-limit submissions
independently of requests, bound challenge storage, and expire aggressively.
Clients bound the reverse risk with round caps and task budgets.

### 7.7 What this protocol does not do

It does not verify that declarations are true. It does not identify agents
(Web Bot Auth does). It does not distinguish humans from machines and MUST NOT
be used to. It does not make an unenforceable promise enforceable.

## 8. Evidence classes

How an accepted answer was established. Deliberately **not** a total order:
independent verification and third-party attestation answer different
questions, and delegation is about authority rather than identity. Servers list
what they accept; membership is checked, never rank.

| Class | Meaning |
|---|---|
| `self_asserted` | The client said so. All declarations and task output. |
| `client_signed` | Signed by an identified client key. |
| `delegated` | A user or organisation conferred the authority. |
| `independently_verified` | The server checked it with the issuing authority. |
| `third_party_attested` | A recognised third party vouches. |

An accepted answer carries a descriptor, not just a label:

```json
{
  "class": "delegated",
  "claimant": "agent-key:abc123",
  "authority": "organization-delegation",
  "verification": "issuer-verified",
  "attester": null,
  "trust_framework": "https://example.org/trust/profiles/v1"
}
```

Servers SHOULD record the evidence descriptor alongside the decision it
produced, and SHOULD NOT make consequential decisions on `self_asserted` alone.

## 9. Relationship to existing work

| Mechanism | Requirement expressed |
|---|---|
| `401` / `WWW-Authenticate` | Authentication credentials |
| RFC 9470 | Stronger or more recent authentication — the same challenge/retry shape, scoped to auth |
| `402` + payment profiles | Payment |
| MCP elicitation | Additional input inside an MCP interaction |
| RFC 9457 | Machine-readable description of a problem |
| RFC 9421 / RFC 9530 | Signing and digesting HTTP messages |
| Web Bot Auth | Stable agent identity and operator metadata |
| **CRAP** | Application-defined, per-request requirements over HTTP |

## 10. IANA considerations

Nothing is registered. A future version would request:

1. **Problem type** `https://crap.blah.dev/problems/input-required` (Specification Required) — the achievable near-term step.
2. **Media type** `application/crap-response+json`.
3. **Well-known URI** `input-challenges`.
4. **Field names** `Accept-Input-Required`, `Input-Proof`, `Challenge-Id`.
5. **HTTP status code** `430 Input Required` (IETF Review) — explicitly not on the critical path.

## 11. Open questions

Genuinely open — input wanted.

1. **Cross-origin proofs.** Should an answer given to one origin be reusable at another that trusts it? Useful, and a tracking vector.
2. **Standing answers.** Pre-publishing stable answers in an agent card so common requirements never round-trip.
3. **Requirement vocabulary.** A small registry of well-known ids (`purpose`, `retention`, `human_in_loop`) so servers don't each invent their own, without a committee gating anything.
4. **Counter-offers.** A declining client should be able to propose a narrower scope instead of just failing.
5. **Receipts.** Should the client get a signed record of what it was asked and what it answered? Symmetry matters if this becomes common.
6. **Task economics.** `limits` makes cost visible, but not fair. Who decides that five seconds of inference is a reasonable price for a document, and what stops a server from asking a thousand agents the same question and calling the consensus a dataset?
