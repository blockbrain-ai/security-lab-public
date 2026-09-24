import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { classifyResponse, detectErrorLeakage } from './response-surprise.js';
import type { LiveExecutionResult, CanarySpec } from './contracts.js';

function buildResult(
  overrides: Partial<LiveExecutionResult['response']> & { canaryMatched?: LiveExecutionResult['canaryMatched'] } = {},
): Pick<LiveExecutionResult, 'canaryMatched' | 'response'> {
  const { canaryMatched, ...responseOverrides } = overrides;
  return {
    canaryMatched,
    response: {
      status: 200,
      headers: {},
      body: 'ok',
      durationMs: 50,
      ...responseOverrides,
    },
  };
}

describe('classifyResponse', () => {
  it('classifies stack-trace bodies as surprising', () => {
    const result = buildResult({
      body: 'Traceback (most recent call last):\n  File "/home/app/server.py", line 42, in handler',
    });
    const classification = classifyResponse(result);
    assert.equal(classification.verdict, 'surprising');
    assert.ok(classification.indicators.errorLeakage, 'errorLeakage indicator should be set');
  });

  it('classifies SQL syntax errors as surprising', () => {
    const result = buildResult({
      body: 'SQL syntax error near "SELECT name FROM users WHERE id"',
    });
    const classification = classifyResponse(result);
    assert.equal(classification.verdict, 'surprising');
    assert.ok(classification.indicators.errorLeakage);
  });

  it('classifies anomalous latency as surprising', () => {
    const result = buildResult({ durationMs: 8000 });
    const classification = classifyResponse(result);
    assert.equal(classification.verdict, 'surprising');
    assert.ok(classification.indicators.anomalousLatency);
  });

  it('classifies 5xx without canary as surprising', () => {
    const result = buildResult({ status: 503, body: '' });
    const classification = classifyResponse(result);
    assert.equal(classification.verdict, 'surprising');
    assert.ok(classification.indicators.statusMismatch);
  });

  it('classifies status that does not match canary as surprising', () => {
    const canary: Pick<CanarySpec, 'expectedWhenSafe' | 'expectedWhenExploitable'> = {
      expectedWhenSafe: { status: 403, bodyContains: ['forbidden'] },
      expectedWhenExploitable: { status: 200, bodyContains: ['secret'] },
    };
    const result = buildResult({ status: 500, body: '{"error":"boom"}' });
    const classification = classifyResponse(result, { canary });
    assert.equal(classification.verdict, 'surprising');
    assert.ok(classification.indicators.statusMismatch);
  });

  it('classifies a canary-safe match as expected', () => {
    const canary: Pick<CanarySpec, 'expectedWhenSafe' | 'expectedWhenExploitable'> = {
      expectedWhenSafe: { status: 403, bodyContains: ['forbidden'] },
      expectedWhenExploitable: { status: 200 },
    };
    const result = buildResult({ status: 403, body: '{"error":"forbidden"}', canaryMatched: 'safe' });
    const classification = classifyResponse(result, { canary });
    assert.equal(classification.verdict, 'expected');
  });

  it('classifies an ordinary 200 body as neither (no surprise and no canary)', () => {
    const result = buildResult({ status: 200, body: '{"ok":true}' });
    const classification = classifyResponse(result);
    assert.equal(classification.verdict, 'neither');
  });
});

describe('detectErrorLeakage', () => {
  it('detects internal paths', () => {
    const { leaked } = detectErrorLeakage('Error reading /Users/app/config.yaml');
    assert.ok(leaked);
  });

  it('detects node_modules stack frames', () => {
    const { leaked } = detectErrorLeakage('at handler (node_modules/express/lib/router.js:123)');
    assert.ok(leaked);
  });

  it('returns false for clean bodies', () => {
    const { leaked } = detectErrorLeakage('{"status":"ok"}');
    assert.equal(leaked, false);
  });
});
