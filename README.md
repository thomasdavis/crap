# CRAP — Conditional Resource Access Protocol

**HTTP can say yes. It can say no. It can't ask a question.**

CRAP adds the third answer: *hold on, I have some questions*. A server responds
to an otherwise-valid request with a machine-readable set of questions. The
client answers them. The original request is retried and succeeds.

```
GET /v1/records                    →  430 Input Required + questions
POST /v1/records (answers)         →  204 + Input-Proof
GET /v1/records (Input-Proof: …)   →  200 OK
```

The questions are whatever you want. Purpose of use. Retention period. Which
model is calling. Whether a human approved this. Which licence is being
accepted. Whether it's a dry run. The protocol carries JSON Schema; it doesn't
care what you ask.

Status: **experimental**, v0.2, nothing is registered with IANA yet. The
normative wire format is `403` + `application/problem+json`; `430` is an
optional negotiated profile and a provisional squat on an unassigned code.
See [SPEC.md](./SPEC.md).

## Install

```bash
npm install @thomasdavis/crap-server   # protecting a resource
npm install @thomasdavis/crap-client   # calling one
```

## Server

```js
import { CrapServer, allow, inputRequired } from '@thomasdavis/crap-server';

const crap = new CrapServer({
  issuer: 'https://data.example',
  secret: process.env.CRAP_SECRET,

  evaluate(ctx, satisfied) {
    if (satisfied?.answers.purpose?.value === 'model_training') {
      return deny('this collection is not licensed for training');
    }
    if (satisfied) return allow();

    return inputRequired([
      {
        id: 'purpose',
        kind: 'declaration',
        actor: 'client',
        interaction: 'inline',
        message: 'What is this data for?',
        reason: 'The collection has purpose-specific access conditions.',
        required: true,
        schema: {
          type: 'string',
          enum: ['academic_research', 'commercial_product', 'model_training'],
        },
      },
    ]);
  },
});

// Anywhere you have a request:
const result = await crap.handle(ctx);
if (result.kind === 'allow') { /* serve it; result.satisfied has the answers */ }
else { /* send result.response */ }
```

Or as Express/Node middleware:

```js
app.use('/v1/records', crapMiddleware(crap, { origin: 'https://data.example' }));
```

## Client

```js
import { crapFetch, answer, decline } from '@thomasdavis/crap-client';

const res = await crapFetch('https://data.example/v1/records', {
  resolver: {
    declaration: (req) => {
      if (req.id === 'purpose') return answer('academic_research');
      return decline('not something I disclose');
    },
    approval: (req) => askTheHuman(req.message),
  },
});
```

The client decides. Nothing in a challenge can make it answer a question your
policy didn't approve — and a challenge that fishes for system prompts, keys or
conversation history is refused outright before your resolver ever sees it.

## Four facets, not four modes

A requirement is described independently along four axes, because
form/proof/approval/url were never peers (OAuth is out-of-band, user-mediated
and evidence-producing all at once):

| Facet | Values |
|---|---|
| `kind` | `declaration` · `evidence` · `approval` · `task` |
| `actor` | `client` · `user` · `organization` · `third_party` |
| `interaction` | `inline` · `out_of_band` |
| `binding` | `none` · `client_key` · `user_identity` · `organization_identity` |

Secrets never travel inline — inline answers pass through the agent's context
window. That's what `out_of_band` is for.

`task` (work as a condition of access) is experimental and separated on
purpose: it has a different cost and abuse profile, must declare
`limits.max_duration_ms`, and the reference client refuses it by default.

## Evidence classes: what an answer is actually worth

An agent saying *"I promise not to train on this"* is not evidence. It's a
string. Every accepted answer carries a class describing how it was
established:

| Class | Meaning |
|---|---|
| `self_asserted` | the client said so — all declarations, all task output |
| `client_signed` | signed by an identified client key |
| `delegated` | a user or organisation conferred the authority |
| `independently_verified` | the server checked it with the issuing authority |
| `third_party_attested` | a recognised third party vouches |

These are **not** ranked. `independently_verified` is not "less than"
`third_party_attested`; delegation answers a question about authority, not
identity. A server lists what it accepts and membership is checked:

```js
accepted_evidence: ['delegated', 'independently_verified']
```

Your verifier assigns the class, and rejects everything by default, because an
unverified proof is just a string that says "proof":

```js
new CrapServer({
  verifyEvidence: async ({ request, answer }) => {
    if (request.id !== 'authority') return null;
    if (!(await checkDelegation(answer.proof))) return null;
    return { class: 'delegated', authority: 'organization-delegation',
             verification: 'issuer-verified' };
  },
});
```

## Two profiles, so you can ship today

Registering an HTTP status code takes years. So:

- **Compatibility (normative)** — `403` + `application/problem+json` ([RFC 9457](https://www.rfc-editor.org/info/rfc9457/)), problem type `https://crap.blah.dev/problems/input-required`. Works through every proxy and SDK that exists today.
- **Native (optional)** — client sends `Accept-Input-Required: v=2` as an RFC 9651 structured field, server may answer `430`.

The server picks automatically. Clients detect a challenge by the problem type,
never by the status code, so `430` staying unregistered forever costs nothing.

## Security properties (and the tests that hold them)

Every one of these is covered in `test/protocol.test.mjs`:

- A proof binds **method + exact target + content presence + content digest + principal + expiry**. A proof earned on `GET /records/1` does not open `DELETE /records/1`.
- Content presence binds **both ways**: you cannot drop the body from a proof earned with one, or add a body to a proof earned without one.
- Targets compare verbatim. Reordering query parameters is a different request, not a canonicalisation opportunity.
- Proofs carry **no answer values** — headers end up in logs. Opaque handle by default; the stateless profile carries a digest.
- Clients reject a challenge whose `issuer` isn't the responding origin, whose `scope` isn't the request they made, or whose `submission.target` is cross-origin.
- A challenge can be answered **once**, at its own transaction resource.
- Rounds are capped server-side (default 3), then it's a real `403`.
- Clients validate their own answers before sending, refuse challenges fishing for secrets or agent context, and refuse `task` work over budget.
- Declining is first-class. A client can always refuse and take the `403`.

```bash
npm test   # 28 tests, real HTTP, no mocks
npm run example
```

## What this is not

Not authentication (`401`). Not payment (`402`, x402). Not a CAPTCHA — it does
not try to tell humans from machines, and it never should. Not a truth oracle:
it moves claims and evidence, and grades them honestly.

## Contributing

This is a v0.1 protocol sketch with a working implementation, and the design
space is wide open. Ideas, objections, and "you've got this wrong because…" are
all welcome — open an issue.

Especially wanted: interesting requirements to put in front of an agent,
evidence-type integrations (Web Bot Auth, verifiable credentials, OAuth token
exchange), a Rust/Go/Python implementation, a gateway that speaks CRAP in front
of an API that doesn't, and arguments about the open questions at the end of
the spec.

MIT.
