/**
 * Gateway tests over real HTTP on the loopback interface. No mocks: a recording
 * upstream sits behind a real gateway, driven by the real client package.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, request } from 'node:http';
import { connect } from 'node:net';

import { createGateway, allow, inputRequired } from '@thomasdavis/crap-gateway';
import {
  crapFetch,
  staticResolver,
  HEADER_ACCEPT,
  ACCEPT_VALUE,
  PROBLEM_TYPE,
} from '@thomasdavis/crap-client';

const SECRET = 'test-secret-do-not-ship';

const PURPOSE = {
  id: 'purpose',
  kind: 'declaration',
  actor: 'client',
  interaction: 'inline',
  message: 'What is this data for?',
  reason: 'The collection has purpose-specific access conditions.',
  required: true,
  schema: { type: 'string', enum: ['academic_research', 'commercial_product', 'model_training'] },
};

/** An upstream that records every request it receives and answers 200. */
async function bootUpstream({ responseHeaders = {} } = {}) {
  const hits = [];
  const http = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    hits.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks) });
    res.writeHead(200, { 'content-type': 'application/json', ...responseHeaders });
    res.end(JSON.stringify({ ok: true, path: req.url }));
  });

  await new Promise((resolve) => http.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${http.address().port}`;
  return { origin, hits, close: () => new Promise((r) => http.close(r)) };
}

/** A gateway on its own port, protecting /v1/ in front of `upstream`. */
async function bootGateway(upstream, overrides = {}) {
  // The issuer needs the port, so the listener delegates to a late-assigned handler,
  // the same way protocol.test.mjs late-assigns its `server` variable.
  let handler;
  const http = createServer((req, res) => handler(req, res));
  await new Promise((resolve) => http.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${http.address().port}`;
  handler = createGateway({
    upstream,
    issuer: origin,
    secret: SECRET,
    evaluate: (ctx, satisfied) => (satisfied ? allow() : inputRequired([PURPOSE])),
    protect: (ctx) => new URL(ctx.target).pathname.startsWith('/v1/'),
    ...overrides,
  });
  return { origin, close: () => new Promise((r) => http.close(r)) };
}

/** Drive one challenge through the gateway manually; return { challenge, proof }. */
async function earnProof(origin, { path = '/v1/records', method = 'GET', body } = {}) {
  const res = await fetch(`${origin}${path}`, { method, headers: { [HEADER_ACCEPT]: ACCEPT_VALUE }, body });
  const { challenge } = await res.json();
  const submission = await fetch(challenge.submission.target, {
    method: 'POST',
    headers: { 'content-type': challenge.submission.content_type },
    body: JSON.stringify({
      challenge_id: challenge.id,
      request_state: challenge.request_state,
      response_id: 'rsp_test',
      input_responses: { purpose: 'academic_research' },
    }),
  });
  return { challenge, proof: submission.headers.get('input-proof'), submission };
}

/**
 * Raw node:http request — fetch forbids hop-by-hop header names, and will not send a
 * request target that carries an authority. `path` goes on the wire verbatim.
 */
function rawRequest(origin, { method = 'GET', path = '/', headers = {} } = {}) {
  const { hostname, port } = new URL(origin);
  return new Promise((resolve, reject) => {
    const req = request({ hostname, port, method, path, headers }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () =>
        resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }),
      );
    });
    req.on('error', reject);
    req.end();
  });
}

/**
 * Write a request line onto the socket byte-for-byte and read the status line back.
 * node:http (and fetch) normalise dot-segments out of the request target client-side,
 * which would hide the very bypass under test; a raw socket sends `target` verbatim,
 * so any refusal is provably the gateway's, not the client's.
 */
function rawSocketStatus(origin, target) {
  const { hostname, port } = new URL(origin);
  return new Promise((resolve, reject) => {
    const socket = connect(Number(port), hostname, () => {
      socket.write(`GET ${target} HTTP/1.1\r\nHost: ${hostname}:${port}\r\nConnection: close\r\n\r\n`);
    });
    const chunks = [];
    socket.on('data', (c) => chunks.push(c));
    socket.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8');
      const status = Number(text.split(' ')[1]);
      resolve({ status, text });
    });
    socket.on('error', reject);
  });
}

test('an unprotected path passes through untouched', async (t) => {
  const upstream = await bootUpstream();
  const gw = await bootGateway(upstream.origin);
  t.after(() => Promise.all([gw.close(), upstream.close()]));

  const res = await fetch(`${gw.origin}/public/thing?b=2&a=1`);
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true, path: '/public/thing?b=2&a=1' });
  assert.equal(upstream.hits.length, 1);
  assert.equal(upstream.hits[0].method, 'GET');
  assert.equal(upstream.hits[0].url, '/public/thing?b=2&a=1', 'query verbatim, order preserved');
});

test('a protected path is challenged without touching upstream', async (t) => {
  const upstream = await bootUpstream();
  const gw = await bootGateway(upstream.origin);
  t.after(() => Promise.all([gw.close(), upstream.close()]));

  const legacy = await fetch(`${gw.origin}/v1/records`);
  assert.equal(legacy.status, 403);
  const problem = await legacy.json();
  assert.equal(problem.type, PROBLEM_TYPE);
  assert.ok(problem.challenge, 'the compatibility profile still carries the challenge');

  const native = await fetch(`${gw.origin}/v1/records`, { headers: { [HEADER_ACCEPT]: ACCEPT_VALUE } });
  assert.equal(native.status, 430);
  assert.equal(upstream.hits.length, 0, 'upstream never saw either request');
});

test('a submission is handled at the gateway, never proxied', async (t) => {
  const upstream = await bootUpstream();
  const gw = await bootGateway(upstream.origin);
  t.after(() => Promise.all([gw.close(), upstream.close()]));

  const { proof, submission } = await earnProof(gw.origin);
  assert.equal(submission.status, 204);
  assert.ok(proof, 'the submission response carries an input-proof header');
  assert.equal(upstream.hits.length, 0);
});

test('answer, proof, retry reaches upstream exactly once', async (t) => {
  const upstream = await bootUpstream();
  const gw = await bootGateway(upstream.origin);
  t.after(() => Promise.all([gw.close(), upstream.close()]));

  const res = await crapFetch(`${gw.origin}/v1/records`, {
    resolver: staticResolver({ purpose: 'academic_research' }),
  });
  assert.equal(res.status, 200);
  assert.deepEqual(await res.json(), { ok: true, path: '/v1/records' });
  assert.equal(upstream.hits.length, 1);

  const hit = upstream.hits[0];
  assert.equal(hit.headers['input-proof'], undefined, 'the proof is the gateway\'s credential');
  assert.equal(hit.headers['accept-input-required'], undefined, 'negotiation was answered here');
  assert.doesNotMatch(JSON.stringify(hit.headers), /academic_research/, 'no answer values leak upstream');
});

test('proof binding is enforced through the gateway', async (t) => {
  const upstream = await bootUpstream();
  const gw = await bootGateway(upstream.origin);
  t.after(() => Promise.all([gw.close(), upstream.close()]));

  const { proof } = await earnProof(gw.origin, { path: '/v1/records', method: 'GET' });

  const wrongMethod = await fetch(`${gw.origin}/v1/records`, {
    method: 'DELETE',
    headers: { 'input-proof': proof },
  });
  assert.notEqual(wrongMethod.status, 200);
  assert.match((await wrongMethod.json()).detail, /method mismatch/);

  const wrongTarget = await fetch(`${gw.origin}/v1/other`, { headers: { 'input-proof': proof } });
  assert.notEqual(wrongTarget.status, 200);
  assert.match((await wrongTarget.json()).detail, /target mismatch/);

  assert.equal(upstream.hits.length, 0, 'a mis-scoped proof never reaches upstream');
});

test('hop-by-hop headers are stripped in both directions', async (t) => {
  const upstream = await bootUpstream({
    responseHeaders: { 'proxy-authenticate': 'Basic realm="up"', 'keep-alive': 'timeout=600' },
  });
  const gw = await bootGateway(upstream.origin);
  t.after(() => Promise.all([gw.close(), upstream.close()]));

  // connection: close keeps node's own keep-alive machinery from re-adding response
  // headers, so absence below is the gateway's stripping, not an accident of reuse.
  // transfer-encoding: chunked is required by node's client before it will send a
  // trailer header at all — and is itself hop-by-hop, so it must not reach upstream.
  const res = await rawRequest(gw.origin, {
    path: '/public/thing',
    headers: {
      'proxy-authorization': 'Basic secret',
      'keep-alive': 'timeout=5',
      te: 'trailers',
      trailer: 'expires',
      'transfer-encoding': 'chunked',
      'x-carried': 'yes',
      connection: 'close',
    },
  });
  assert.equal(res.status, 200);

  const hit = upstream.hits[0];
  for (const name of ['proxy-authorization', 'keep-alive', 'te', 'trailer', 'transfer-encoding']) {
    assert.equal(hit.headers[name], undefined, `${name} must not reach upstream`);
  }
  assert.equal(hit.headers['x-carried'], 'yes', 'ordinary headers still pass');

  assert.equal(res.headers['proxy-authenticate'], undefined, 'stripped from the response');
  assert.equal(res.headers['keep-alive'], undefined, 'stripped from the response');
});

test('a dead upstream is a 502, and challenges still issue locally', async (t) => {
  const upstream = await bootUpstream();
  const dead = upstream.origin;
  await upstream.close();
  const gw = await bootGateway(dead);
  t.after(() => gw.close());

  const proxied = await fetch(`${gw.origin}/public/thing`);
  assert.equal(proxied.status, 502);
  assert.match(proxied.headers.get('content-type'), /application\/problem\+json/);

  const challenged = await fetch(`${gw.origin}/v1/records`);
  assert.equal(challenged.status, 403);
  assert.ok((await challenged.json()).challenge, 'the machinery is local and does not need upstream');
});

test('failOpen bypasses a broken challenge store only when configured', async (t) => {
  const upstream = await bootUpstream();
  const brokenStore = () => ({
    put: async () => { throw new Error('store down'); },
    get: async () => { throw new Error('store down'); },
    consume: async () => { throw new Error('store down'); },
  });
  const closed = await bootGateway(upstream.origin, { store: brokenStore() });
  const open = await bootGateway(upstream.origin, { store: brokenStore(), failOpen: true });
  t.after(() => Promise.all([closed.close(), open.close(), upstream.close()]));

  const refused = await fetch(`${closed.origin}/v1/records`);
  assert.equal(refused.status, 502);
  assert.equal(upstream.hits.length, 0, 'fail closed touches nothing');

  const served = await fetch(`${open.origin}/v1/records`);
  assert.equal(served.status, 200);
  assert.equal(upstream.hits.length, 1, 'fail open serves unchallenged — the documented divergence');
});

test('a request target that names another host is refused', async (t) => {
  const upstream = await bootUpstream();
  const victim = await bootUpstream();
  const gw = await bootGateway(upstream.origin);
  t.after(() => Promise.all([gw.close(), upstream.close(), victim.close()]));

  const { hostname, port } = new URL(victim.origin);
  const authority = `${hostname}:${port}`;
  // Two families. The first is authority-bearing forms the raw-input prefix test catches.
  // The second is dot-segment targets that start with a single `/`, pass that test, and
  // normalise to a `//authority` pathname — the round-2 open-proxy bypass. Both must 400,
  // and the victim must never be contacted. Driven over a raw socket because node:http
  // and fetch both collapse the dot-segments client-side and would mask the bug.
  const targets = [
    `//${authority}/x`,
    `${victim.origin}/x`,
    `/\\${authority}/x`,
    `/..//${authority}/x`,
    `/././/${authority}/x`,
    `/a/../..//${authority}/x`,
  ];
  for (const target of targets) {
    const res = await rawSocketStatus(gw.origin, target);
    assert.equal(res.status, 400, `${target} must be refused by the gateway, got ${res.status}`);
    assert.match(res.text, /application\/problem\+json/);
  }

  assert.equal(victim.hits.length, 0, 'the gateway is not an open relay');
  assert.equal(upstream.hits.length, 0, 'and it did not quietly forward them either');
});

test('a truncated upstream response does not hang the client', async (t) => {
  // Promises more than it delivers, then closes cleanly mid-body: a FIN, not a reset,
  // so the upstream request never errors — only the response stream ends short.
  const liar = createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'text/plain', 'content-length': '100' });
    res.write('partial');
    res.socket.end();
  });
  await new Promise((resolve) => liar.listen(0, '127.0.0.1', resolve));
  const gw = await bootGateway(`http://127.0.0.1:${liar.address().port}`);
  t.after(() => Promise.all([gw.close(), new Promise((r) => liar.close(r))]));

  let settle;
  const outcome = await new Promise((resolve) => {
    // The timer only fires in the failure case; a working gateway settles long first.
    const timer = setTimeout(() => settle('hung'), 2000);
    const { hostname, port } = new URL(gw.origin);
    const req = request({ hostname, port, path: '/public/thing' }, (res) => {
      res.on('aborted', () => settle('aborted'));
      res.on('error', () => settle('errored'));
      res.on('end', () => settle('ended'));
      res.resume();
    });
    settle = (how) => {
      clearTimeout(timer);
      // Release the client socket whichever way this went, so the servers can close
      // and a hung gateway fails the assertion instead of wedging the test run.
      req.destroy();
      resolve(how);
    };
    req.on('error', () => settle('errored'));
    req.end();
  });

  assert.notEqual(outcome, 'hung', 'a half-delivered response must break the connection');
});

test('a post body and its digest binding survive the proxy', async (t) => {
  const upstream = await bootUpstream();
  const gw = await bootGateway(upstream.origin);
  t.after(() => Promise.all([gw.close(), upstream.close()]));

  const body = JSON.stringify({ q: 'everything' });
  const { proof } = await earnProof(gw.origin, { path: '/v1/search', method: 'POST', body });

  const retried = await fetch(`${gw.origin}/v1/search`, {
    method: 'POST',
    headers: { 'input-proof': proof },
    body,
  });
  assert.equal(retried.status, 200);
  assert.equal(upstream.hits.length, 1);
  assert.ok(upstream.hits[0].body.equals(Buffer.from(body)), 'the exact bytes reach upstream');

  const tampered = await fetch(`${gw.origin}/v1/search`, {
    method: 'POST',
    headers: { 'input-proof': proof },
    body: JSON.stringify({ q: 'something else' }),
  });
  assert.notEqual(tampered.status, 200);
  assert.equal(upstream.hits.length, 1, 'digest binding is enforced before forwarding');
});
