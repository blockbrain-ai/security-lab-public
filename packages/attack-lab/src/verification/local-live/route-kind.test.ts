import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { detectRouteKind, isSpaShell } from './route-kind.js';

describe('route-kind detectRouteKind', () => {
  it('detects JSON API from content-type', () => {
    assert.equal(
      detectRouteKind({
        path: '/api/v1/users',
        status: 200,
        headers: { 'content-type': 'application/json; charset=utf-8' },
        body: '{"users":[]}',
      }),
      'json_api',
    );
  });

  it('detects vendor JSON content types', () => {
    assert.equal(
      detectRouteKind({
        path: '/api/records',
        status: 200,
        headers: { 'content-type': 'application/vnd.api+json' },
        body: '{"data":[]}',
      }),
      'json_api',
    );
  });

  it('detects SPA shell HTML', () => {
    const spaBody = `<!DOCTYPE html>
<html><head><title>App</title></head>
<body><div id="root"></div>
<script type="module" src="/assets/main.abc123.js"></script>
</body></html>`;
    assert.equal(
      detectRouteKind({
        path: '/dashboard/settings',
        status: 200,
        headers: { 'content-type': 'text/html' },
        body: spaBody,
      }),
      'spa_shell',
    );
  });

  it('detects regular HTML pages', () => {
    const htmlBody = `<!DOCTYPE html>
<html><head><title>Admin</title></head>
<body><h1>Administration Panel</h1>
<p>Welcome to the admin panel. Here you can manage users, roles, and permissions for your organization. Use the navigation menu on the left to get started with configuration.</p>
</body></html>`;
    assert.equal(
      detectRouteKind({
        path: '/admin',
        status: 200,
        headers: { 'content-type': 'text/html' },
        body: htmlBody,
      }),
      'html_page',
    );
  });

  it('detects static assets by path extension', () => {
    assert.equal(
      detectRouteKind({
        path: '/assets/main.abc123.js',
        status: 200,
        headers: { 'content-type': 'application/javascript' },
        body: 'var x = 1;',
      }),
      'asset_static',
    );
  });

  it('detects static assets by content type', () => {
    assert.equal(
      detectRouteKind({
        path: '/logo',
        status: 200,
        headers: { 'content-type': 'image/png' },
        body: '',
      }),
      'asset_static',
    );
  });

  it('detects CSS as static', () => {
    assert.equal(
      detectRouteKind({
        path: '/styles/main.css',
        status: 200,
        headers: { 'content-type': 'text/css' },
        body: 'body { color: red; }',
      }),
      'asset_static',
    );
  });

  it('detects redirects', () => {
    assert.equal(
      detectRouteKind({
        path: '/login',
        status: 302,
        headers: { location: '/auth/callback' },
        body: '',
      }),
      'redirect_bootstrap',
    );
  });

  it('detects 301 permanent redirects', () => {
    assert.equal(
      detectRouteKind({
        path: '/old-api',
        status: 301,
        headers: { location: '/api/v2' },
        body: '',
      }),
      'redirect_bootstrap',
    );
  });

  it('detects websocket upgrade', () => {
    assert.equal(
      detectRouteKind({
        path: '/ws',
        status: 101,
        headers: { upgrade: 'websocket' },
        body: '',
      }),
      'websocket_upgrade',
    );
  });

  it('infers json_api from API path when no content type', () => {
    assert.equal(
      detectRouteKind({
        path: '/api/v1/health',
        status: 200,
        headers: {},
        body: 'OK',
      }),
      'json_api',
    );
  });

  it('returns unknown for ambiguous responses', () => {
    assert.equal(
      detectRouteKind({
        path: '/something',
        status: 200,
        headers: { 'content-type': 'text/plain' },
        body: 'hello',
      }),
      'unknown',
    );
  });

  it('detects HTML without explicit content type by body sniffing', () => {
    assert.equal(
      detectRouteKind({
        path: '/page',
        status: 200,
        headers: {},
        body: '<!DOCTYPE html><html><body><p>A full page with real textual content describing the features of the application in detail.</p></body></html>',
      }),
      'html_page',
    );
  });
});

describe('route-kind isSpaShell', () => {
  it('detects React-style SPA shell', () => {
    const body = `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/><title>App</title></head>
<body><div id="root"></div>
<script type="module" src="/static/js/main.chunk.js"></script>
</body></html>`;
    assert.equal(isSpaShell(body), true);
  });

  it('detects Next.js-style SPA shell', () => {
    const body = `<!DOCTYPE html>
<html><head></head><body><div id="__next"></div>
<script src="/_next/static/chunks/main.js"></script>
</body></html>`;
    assert.equal(isSpaShell(body), true);
  });

  it('rejects content-rich HTML', () => {
    const body = `<!DOCTYPE html>
<html><head><title>Blog</title></head>
<body><h1>My Blog Post</h1>
<p>This is a long blog post with actual content that describes something meaningful about the topic at hand. It contains multiple paragraphs and real information that a user would read.</p>
<p>Second paragraph with even more detail about the subject.</p>
</body></html>`;
    assert.equal(isSpaShell(body), false);
  });

  it('rejects non-HTML content', () => {
    assert.equal(isSpaShell('{"users":[]}'), false);
  });

  it('detects minimal bundle-only HTML', () => {
    const body = `<!DOCTYPE html><html><head></head><body>
<script src="/bundle.js"></script></body></html>`;
    assert.equal(isSpaShell(body), true);
  });
});
