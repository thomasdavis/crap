# @thomasdavis/crap-gateway

A reverse proxy that speaks CRAP in front of an upstream API that does not. All
protocol mechanics — challenges, submissions, proofs, grants — are handled at the
gateway by `@thomasdavis/crap-server`; requests that satisfy the policy (or were never
protected) are forwarded upstream with hop-by-hop and CRAP headers stripped.

## Usage

```js
import { createServer } from 'node:http';
import { createGateway, allow, inputRequired } from '@thomasdavis/crap-gateway';

const purpose = {
  id: 'purpose',
  kind: 'declaration',
  actor: 'client',
  interaction: 'inline',
  message: 'What is this data for?',
  reason: 'The collection has purpose-specific access conditions.',
  required: true,
  schema: { type: 'string', enum: ['academic_research', 'commercial_product'] },
};

createServer(
  createGateway({
    upstream: 'http://127.0.0.1:4001',
    issuer: 'https://gateway.example',
    secret: process.env.CRAP_SECRET,
    evaluate: (ctx, satisfied) => (satisfied ? allow() : inputRequired([purpose])),
    protect: (ctx) => new URL(ctx.target).pathname.startsWith('/v1/'),
  }),
).listen(8080);
```

## Configuration

- `upstream` — origin of the API being fronted; the incoming request's path and query
  are appended verbatim.
- `protect(ctx)` — which requests must satisfy CRAP before they are forwarded.
  Everything else is proxied untouched. Submissions under
  `/.well-known/input-challenges` are always handled locally.
- `failOpen` — what to do when the challenge machinery itself fails; see below.
- `principal(req)` — resolve the authenticated principal, mirroring `crapMiddleware`.

Plus every `CrapServer` option (`evaluate`, `secret`, `store`, `decisions`,
`proofMode`, `grantScope`, and the rest), passed through. `issuer` is the gateway's own
public origin: challenges and transaction resources live at the gateway, never
upstream.

## Failure policy

Default is fail-closed: a request the gateway cannot police is refused with 502. The
reference deployment deliberately fails open ("Everything fails open: if the toll
service is slow, down, or confused, the page is served" — FINDINGS), which is a
defensible posture for a public website and the wrong default for a library, so
`failOpen: true` is an explicit opt-in that restores that behaviour — for
challenge-machinery failures only. An unreachable upstream is always 502 regardless,
and an upstream that dies part-way through a body it promised gets the connection
broken rather than left hanging.

Two limits worth knowing before you deploy it:

- Each request is buffered in memory before the decision, because the protocol binds
  proofs to a content digest of the exact bytes. There is no size cap here, so put a
  body limit in front of the gateway.
- Only origin-form request targets (`/path?query`) are accepted; anything carrying its
  own authority is a 400. A gateway is the origin server as far as the client is
  concerned — absolute-form is for forward proxies (RFC 9112 §3.2.2), and honouring it
  would let a caller choose which host the gateway connects to.
