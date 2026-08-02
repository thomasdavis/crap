# CRAP: Conditional Resource Access Protocol

**Version:** 0.1 (experimental)
**Status:** working draft, no IANA registrations, breaking changes expected
**Provisional status code:** `430 Input Required`
**Problem type:** `https://crap.donto.org/problems/input-required`
**Response media type:** `application/crap-response+json`

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

---

## 1. Overview

An origin server MAY respond to an otherwise-valid request with a
**challenge**: a machine-readable set of **input requests** the client must
satisfy before the request can be processed. The client submits **answers**,
receives a scoped **continuation proof**, and retries the original request.

The protocol is a carrier. It defines how questions and answers travel, how
they are bound to a request, and how much an answer is worth. It does not
define what may be asked — that is the application's business.

```
  Client                                  Server
    │                                        │
    │ GET /resource                          │
    │ Accept-Input-Required: v=1             │
    │───────────────────────────────────────▶│
    │                                        │  policy: input_required
    │ 430 Input Required                     │
    │ problem+json { challenge }             │
    │◀───────────────────────────────────────│
    │                                        │
    │ POST /resource                         │
    │ Content-Type: application/crap-response+json
    │ { challenge_id, request_state, answers }│
    │───────────────────────────────────────▶│  validate + grade + consume
    │ 204 No Content                         │
    │ Input-Proof: <scoped proof>            │
    │◀───────────────────────────────────────│
    │                                        │
    │ GET /resource                          │
    │ Input-Proof: <scoped proof>            │
    │───────────────────────────────────────▶│  verify binding
    │ 200 OK                                 │
    │◀───────────────────────────────────────│
```

## 2. Status codes

### 2.1 `430 Input Required` (provisional)

> The origin server understands the request and MAY be willing to process it,
> but requires the client to satisfy one or more application-level input
> requirements first. The response describes those requirements and how to
> fulfil them. After satisfying them, the client MAY retry the original
> request.

`430` is unassigned in the IANA HTTP Status Code Registry at the time of
writing. This document squats on it provisionally. A server MUST NOT return
`430` unless the client advertised support (§3.1).

`430` is not cacheable by default and MUST be sent with `Cache-Control: no-store`.

### 2.2 Choosing the right status

| Condition | Status |
|---|---|
| Credentials absent, invalid, or insufficient | `401` |
| Payment required | `402` |
| Final policy decision; more input will not help | `403` |
| Request conflicts with resource state | `409` |
| The submitted representation is itself invalid | `422` |
| Client must slow down | `429` |
| Recoverable, application-defined input needed | `430` |

A server MUST NOT use `430` when it has already decided to refuse. `430` is a
promise that an answer exists which would change the outcome.

## 3. Capability negotiation

### 3.1 `Accept-Input-Required`

A client that understands this protocol SHOULD send:

```
Accept-Input-Required: v=1
```

A server MUST NOT respond `430` to a request lacking this field. Instead it
uses the compatibility profile.

### 3.2 Compatibility profile

When the client has not opted in, the server sends the identical problem
document with status `403`. Clients detect a challenge by the problem `type`,
not by the status code. Both profiles are otherwise byte-identical.

This exists because unknown 4xx codes are treated as `400` by RFC 9110 §15.5,
and because intermediaries, SDKs and API gateways in the wild do not all
tolerate unregistered codes.

## 4. The challenge

Sent as `application/problem+json` (RFC 9457) with a `challenge` member.

```json
{
  "type": "https://crap.donto.org/problems/input-required",
  "title": "Input Required",
  "status": 430,
  "detail": "This resource has questions that must be answered before it can be served.",
  "instance": "https://data.example/v1/records",
  "challenge": {
    "id": "ch_zC4mV8xQ",
    "version": 1,
    "issuer": "https://data.example",
    "issued_at": "2026-08-02T00:00:00Z",
    "expires_at": "2026-08-02T00:15:00Z",
    "request_state": "6Rk9…opaque…",
    "scope": {
      "method": "GET",
      "target": "https://data.example/v1/records",
      "request_digest": "sha-256=:n4bQgYhMfWWaLq…:",
      "principal": "acct:agent-7"
    },
    "input_requests": [ … ],
    "submission": {
      "method": "POST",
      "target": "https://data.example/v1/records",
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
| `version` | ✔ | Protocol version. `1`. |
| `issuer` | ✔ | Origin that issued it. Proofs are only valid at this origin. |
| `issued_at` / `expires_at` | ✔ | RFC 3339 timestamps. |
| `request_state` | ✔ | Opaque server value; the client MUST echo it. Nonce material. |
| `scope` | ✔ | The request this challenge is bound to (§6.1). |
| `input_requests` | ✔ | One or more questions. |
| `submission` | ✔ | Where and how to send answers. |
| `continuation` | ✔ | `retry-original-request` or `complete-on-submit`. |
| `max_rounds` / `round` | ✔ | Loop bound (§6.4). |
| `policy_version` | | Which version of the issuer's policy produced this. |

### 4.2 Input requests

```json
{
  "id": "purpose",
  "mode": "form",
  "message": "What is this data for?",
  "reason": "The collection has purpose-specific access conditions.",
  "required": true,
  "sensitivity": "internal",
  "retention": "P1Y",
  "min_assurance": "A0",
  "schema": {
    "type": "string",
    "enum": ["academic_research", "commercial_product", "model_training"]
  }
}
```

| Member | Req | Meaning |
|---|---|---|
| `id` | ✔ | Key the answer is returned under. Unique within a challenge. |
| `mode` | ✔ | `form` \| `proof` \| `approval` \| `url` (§5). |
| `message` | ✔ | Human-readable prompt. **Untrusted text** (§7.1). |
| `required` | ✔ | Whether declining fails the challenge. |
| `reason` | | Why the issuer needs it. SHOULD be present. |
| `schema` | form | JSON Schema subset (§4.3) the answer must satisfy. |
| `accepted_proof_types` | proof | Evidence types the issuer will consider. |
| `url` | url | HTTPS location of the out-of-band interaction. |
| `min_assurance` | | Lowest acceptable grade (§8). |
| `sensitivity` / `retention` | | Declared handling of the answer. |

### 4.3 Schema subset

`form` schemas are restricted to: `type`, `enum`, `const`, `minimum`,
`maximum`, `minLength`, `maxLength`, `pattern`, `format`, `items`, `minItems`,
`maxItems`, `properties`, `required`, `additionalProperties`, `description`,
`title`, `default`.

A client encountering any other keyword MUST reject the challenge rather than
ignore the keyword. `$ref`, `allOf`/`anyOf`/`oneOf`, and remote schema loading
are excluded deliberately: a client MUST NOT fetch a schema from the network to
understand a question.

Implementations SHOULD bound `pattern` compilation against catastrophic
backtracking.

## 5. Input modes

### 5.1 `form`

Structured, non-secret data, answerable autonomously.

A server MUST NOT request through `form` mode: passwords, API keys, access or
refresh tokens, private keys, seed phrases, payment card data, or the client's
own operating context (system prompt, reasoning trace, conversation history,
environment variables, cookies).

Clients SHOULD refuse challenges that appear to do so and MAY report them.

### 5.2 `proof`

Machine-verifiable evidence: HTTP Message Signatures (RFC 9421), OAuth
delegation, verifiable credentials, key-possession proofs, organisational
attestations.

The answer is `{ "proof_type": "…", "proof": "…" }`. Servers MUST verify
proofs. An unverified proof MUST be graded A0 or rejected — never treated as
evidence because it was labelled evidence.

### 5.3 `approval`

A human must approve. Clients MUST surface these outside the agent's autonomous
path and MUST NOT allow a model to self-approve. The answer SHOULD be a signed
approval receipt.

### 5.4 `url`

The interaction happens out of band at an HTTPS location: OAuth consent,
identity verification, payment, legally significant acceptance. Values entered
there never enter the agent's context.

## 6. Binding

### 6.1 Scope binding

A challenge is bound to `scope`: method, normalised target URI, principal, and
— when a body is present — a digest of it. A server MUST reject a submission
whose request context does not match the scope of the challenge being answered.

Targets are compared after normalisation: query parameters sorted, fragment
removed, default ports elided.

### 6.2 Submission

The client POSTs `application/crap-response+json` to `submission.target`:

```json
{
  "challenge_id": "ch_zC4mV8xQ",
  "request_state": "6Rk9…opaque…",
  "response_id": "rsp_9f21…",
  "input_responses": { "purpose": "academic_research" },
  "declined": ["retention"]
}
```

The server MUST reject the submission if: the challenge is unknown or expired;
`request_state` does not match; the principal differs; the target differs; a
required input is missing or declined; any answer fails its schema; any answer
falls below `min_assurance`; or the challenge has already been consumed.

Schema failures return `422` with a machine-readable `errors` array. Everything
else returns `403`.

On success: `204 No Content` with an `Input-Proof` header.

### 6.3 Continuation proof

The `Input-Proof` value is opaque to the client. It MUST be bound to at least:
issuing origin, method, normalised target, principal, body digest (when
applicable), round, and an expiry. It SHOULD be short-lived (minutes) and
SHOULD be sender-constrained where the client has a key.

A proof MUST NOT be usable:
- at another origin,
- for another method or target,
- by another principal,
- after expiry,
- more than the issuer permits.

A proof is not a session token and MUST NOT be accepted in place of
authentication.

### 6.4 Rounds

A server MAY issue a further challenge after a successful submission (e.g. the
answers revealed a new obligation). `round` increments; when it would exceed
`max_rounds` the server MUST return a final `403` instead. Default cap: 3.

Clients MUST independently cap the number of rounds they will play.

### 6.5 Idempotency

Answering a challenge MUST be single-use. A replayed submission MUST be
rejected. Retrying the original request with a valid, unexpired proof is not a
replay and MAY be repeated until the proof expires.

## 7. Security considerations

### 7.1 Challenges are attacker-controlled input

`message` and `reason` are remote text delivered into an agent's execution
context. This is a prompt-injection surface, and CRAP makes it a first-class
one: any server can now put arbitrary prose in front of any agent.

Clients MUST treat challenge text as data. An agent MUST fill only declared
fields, per its own policy, and MUST NOT act on instructions embedded in
challenge text. Client policy MUST override server request in all cases.

Servers SHOULD assume the same in reverse: an answer is text an agent produced,
possibly under the influence of a third party.

### 7.2 Interrogation and surveillance

An open-ended question channel is an open-ended data-collection channel. Every
input request SHOULD declare `reason`, `sensitivity` and `retention`. Clients
MUST be able to decline any individual input and MUST be able to refuse a
challenge entirely. Servers MUST NOT treat declining as grounds for anything
except the `403` the client already accepted.

### 7.3 Proof theft

Because proofs authorise a retry, a stolen proof is a stolen request — bounded
by §6.3's binding. Implementations SHOULD sender-constrain proofs when agent
keys are available (Web Bot Auth, RFC 9421).

### 7.4 Cache poisoning

Challenges, submissions and proof-bearing responses MUST be sent with
`Cache-Control: no-store`. A challenge MUST NOT be shared between principals
through a shared cache.

### 7.5 Denial of service

Challenge issuance is cheap; validation is not. Servers SHOULD rate-limit
submissions independently of requests, bound challenge storage, and expire
aggressively.

### 7.6 What this protocol does not do

It does not verify that declarations are true. It does not identify agents
(that's Web Bot Auth). It does not distinguish humans from machines and MUST
NOT be used to. It does not make an unenforceable promise enforceable.

## 8. Assurance levels

| Level | Meaning |
|---|---|
| A0 | Unverified declaration. The agent supplied a value. |
| A1 | Signed declaration. An identified agent signed the value. |
| A2 | Delegated claim. A user or organisation authorised it. |
| A3 | Verifiable proof. The server verified it independently. |
| A4 | Attestation. A recognised third party vouches for it. |

`form` answers are A0 by definition. Servers SHOULD record the assurance of
every answer alongside the decision it produced, and SHOULD NOT make
consequential decisions on A0 alone.

## 9. Relationship to existing work

| | |
|---|---|
| **MCP Elicitation** | The same interaction inside MCP: schema-driven requests, URL mode, secret-handling rules. CRAP generalises it to HTTP and adds request binding, proofs and assurance. Field naming deliberately echoes it. |
| **RFC 9457** | The challenge is a problem document. Compatibility profile depends on it. |
| **RFC 9421** | Message signatures are the expected `proof` mechanism. |
| **Web Bot Auth** | Stable agent identity and metadata. CRAP handles the per-request questions a static agent card can't answer. |
| **RFC 9470** | Step-up authentication — the auth-specific special case of this shape. |
| **x402 / `402`** | Payment — the money-specific special case. |
| **`401` / RFC 9110** | Authentication — the credential-specific special case. |

## 10. IANA considerations

Nothing is registered yet. A future version would request:

1. **HTTP status code** `430 Input Required` (IETF Review).
2. **Problem type** `https://crap.donto.org/problems/input-required` (Specification Required).
3. **Media type** `application/crap-response+json`.
4. **Field names** `Accept-Input-Required`, `Input-Proof`, `Challenge-Id`.

The problem-type registration is the achievable near-term step; the status code
is not on the critical path, which is why the compatibility profile exists.

## 11. Open questions

Genuinely open — input wanted:

1. **Cross-origin proofs.** Should an answer given to one origin be reusable at another that trusts it? Useful, and a tracking vector.
2. **Standing answers.** A way to pre-publish stable answers (in an agent card) so common questions never round-trip.
3. **Question vocabulary.** A small core registry of well-known ids (`purpose`, `retention`, `human_in_loop`) so servers don't each invent their own, without a committee gating anything.
4. **Negotiation.** A client that declines should be able to counter-offer: "not that, but I'll accept this narrower scope."
5. **Receipts.** Should the client get a signed record of what it was asked and what it answered? Symmetry matters if this becomes common.
6. **Compute-bearing answers.** If a question's answer requires real work by the agent, the server has effectively priced access in the client's compute. Where's the line between a fair question and a work requirement?
