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

Status: **experimental**, v0.1, nothing is registered with IANA yet, and `430`
is a provisional squat on an unassigned code. See [SPEC.md](./SPEC.md).

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
        mode: 'form',
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
    form: (req) => {
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

## The four modes

| Mode | For | Answered by |
|---|---|---|
| `form` | structured, non-secret answers | the agent, autonomously |
| `proof` | signatures, delegations, credentials | the agent's key material |
| `approval` | high-impact actions | a human, out of band |
| `url` | OAuth, KYC, payment, consent | the user, in a browser |

Secrets never travel in `form` mode — form answers pass through the agent's
context window. That's what `url` mode is for.

## Assurance: what an answer is actually worth

An agent saying *"I promise not to train on this"* is not evidence. It's a
string. Every accepted answer is graded:

| | |
|---|---|
| **A0** | unverified declaration — the agent typed a value |
| **A1** | signed declaration — an identified agent signed it |
| **A2** | delegated claim — a user or org authorised it |
| **A3** | verifiable proof — the server checked it independently |
| **A4** | attested — a trusted third party vouches |

`form` answers are always A0. `proof` answers are graded by *your* verifier,
which rejects everything by default, because an unverified proof is just a
string that says "proof".

```js
new CrapServer({
  verifyProof: async ({ request, answer }) => {
    if (request.id !== 'authority') return null;
    return (await checkDelegation(answer.proof)) ? 'A2' : null;
  },
});
```

## Two profiles, so you can ship today

Registering an HTTP status code takes years. So:

- **Compatibility** — `403` + `application/problem+json` ([RFC 9457](https://www.rfc-editor.org/info/rfc9457/)), problem type `https://crap.donto.org/problems/input-required`. Works through every proxy and SDK that exists today.
- **Native** — client sends `Accept-Input-Required: v=1`, server may answer `430`.

The server picks automatically based on what the client advertised. Nobody eats
a mystery status code they didn't ask for.

## Security properties (and the tests that hold them)

Every one of these is covered in `test/protocol.test.mjs`:

- A proof is bound to **method + target + principal + body digest + expiry**. A proof earned on `GET /records/1` does not open `DELETE /records/1`.
- Tampering with an answer inside a proof invalidates the signature.
- A challenge can be answered **once**. Replays are rejected.
- `request_state` must be echoed back — you can't answer a challenge you weren't given.
- Rounds are capped server-side (default 3), then it's a real `403`. No infinite question loops.
- Clients validate their own answers against the server's schema before sending.
- Clients refuse challenges fishing for secrets or agent context.
- Declining is first-class. A client can always refuse and take the `403`.

```bash
npm test   # 15 tests, real HTTP, no mocks
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

Especially wanted: interesting questions to ask an agent, other input modes,
proof-type integrations (Web Bot Auth, verifiable credentials, OAuth token
exchange), a Rust/Go/Python implementation, and a gateway that speaks CRAP in
front of an API that doesn't.

MIT.
