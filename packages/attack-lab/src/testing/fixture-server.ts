import { createServer } from 'node:http';

const port = Number(process.env['SECURITY_LAB_FIXTURE_PORT'] ?? 4317);

const server = createServer((req, res) => {
  if (!req.url) {
    res.writeHead(400, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'missing_url' }));
    return;
  }

  if (req.url === '/health') {
    res.writeHead(200, { 'content-type': 'application/json' });
    // The nonce lets a caller prove it is talking to the server it just
    // started rather than a stale process holding the same port.
    res.end(JSON.stringify({
      ok: true,
      service: 'security-lab-fixture',
      nonce: process.env['SECURITY_LAB_FIXTURE_NONCE'] ?? null,
    }));
    return;
  }

  if (req.url === '/private') {
    if (req.headers['x-test-token'] === 'allow') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, secret: 'super-secret' }));
      return;
    }

    res.writeHead(401, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'unauthorized' }));
    return;
  }

  if (req.url === '/public-proof') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ status: 'redacted', public: true }));
    return;
  }

  if (req.url === '/public/challenge') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ challenge: 'fixture-challenge-01', public: true }));
    return;
  }

  if (req.url.startsWith('/chain/private')) {
    const url = new URL(req.url, `http://127.0.0.1:${port}`);
    const challenge = url.searchParams.get('challenge');
    const token = req.headers['x-test-token'];

    if (challenge === 'fixture-challenge-01' && token === 'allow') {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, secret: 'super-secret' }));
      return;
    }

    res.writeHead(403, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'chain_blocked' }));
    return;
  }

  res.writeHead(404, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ error: 'not_found' }));
});

server.listen(port, '127.0.0.1', () => {
  console.log(`Security Lab fixture server listening on http://127.0.0.1:${port}`);
});

