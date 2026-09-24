import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { ClaudeCodeAdapter } from './claude-code-adapter.js';

test('ClaudeCodeAdapter parses stream-json output and falls back from invalid resume session', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'security-lab-claude-cli-'));
  const binaryPath = resolve(dir, 'claude');
  await writeFile(binaryPath, `#!/bin/sh
if [ "$1" = "-p" ]; then
  for arg in "$@"; do
    if [ "$arg" = "--resume" ]; then
      echo "resume failed" >&2
      exit 1
    fi
  done
fi
cat <<'EOF'
{"type":"assistant","session_id":"sess-123","message":{"content":[{"type":"text","text":"{\\"ok\\":true}"}]}}
{"type":"result","session_id":"sess-123","result":"{\\"ok\\":true}","total_cost_usd":0.25,"duration_ms":12,"usage":{"input_tokens":10,"output_tokens":5}}
EOF
`, 'utf8');
  await chmod(binaryPath, 0o755);

  const adapter = new ClaudeCodeAdapter({
    provider: 'claude_code',
    model: 'claude-opus-4-6',
    binaryPath,
  });

  const response = await adapter.invoke({
    sessionId: 'stale-session',
    prompt: 'Return JSON.',
  });

  assert.equal(response.provider, 'claude_code');
  assert.equal(response.model, 'claude-opus-4-6');
  assert.equal(response.sessionId, 'sess-123');
  assert.equal(response.usage.costUsd, 0.25);
  assert.equal(response.content, '{"ok":true}');
});

test('ClaudeCodeAdapter invokes Claude with stdin ignored so CLI workers do not wait on pipes', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'security-lab-claude-cli-stdin-'));
  const binaryPath = resolve(dir, 'claude');
  await writeFile(binaryPath, `#!/bin/sh
python3 - <<'PY'
import os, select, sys
ready, _, _ = select.select([0], [], [], 0.2)
if not ready:
    print('stdin did not reach EOF promptly', file=sys.stderr)
    sys.exit(1)
data = os.read(0, 1)
if data != b'':
    print(f'stdin unexpectedly contained data: {data!r}', file=sys.stderr)
    sys.exit(1)
PY
cat <<'EOF'
{"type":"assistant","session_id":"sess-stdin","message":{"content":[{"type":"text","text":"ok"}]}}
{"type":"result","session_id":"sess-stdin","result":"ok","total_cost_usd":0.01,"duration_ms":4,"usage":{"input_tokens":2,"output_tokens":1}}
EOF
`, 'utf8');
  await chmod(binaryPath, 0o755);

  const adapter = new ClaudeCodeAdapter({
    provider: 'claude_code',
    model: 'claude-opus-4-6',
    binaryPath,
  });

  const response = await adapter.invoke({
    prompt: 'Return ok.',
  });

  assert.equal(response.sessionId, 'sess-stdin');
  assert.equal(response.content, 'ok');
});

test('ClaudeCodeAdapter injects the minimal two-rule worker contract into the prompt', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'security-lab-claude-cli-guardrails-'));
  const binaryPath = resolve(dir, 'claude');
  const promptCapturePath = resolve(dir, 'prompt.txt');
  await writeFile(binaryPath, `#!/bin/sh
printf '%s' "$3" > ${JSON.stringify(promptCapturePath)}
cat <<'EOF'
{"type":"assistant","session_id":"sess-guardrails","message":{"content":[{"type":"text","text":"ok"}]}}
{"type":"result","session_id":"sess-guardrails","result":"ok","total_cost_usd":0.01,"duration_ms":4,"usage":{"input_tokens":2,"output_tokens":1}}
EOF
`, 'utf8');
  await chmod(binaryPath, 0o755);

  const adapter = new ClaudeCodeAdapter({
    provider: 'claude_code',
    model: 'claude-opus-4-6',
    binaryPath,
  });

  await adapter.invoke({
    systemPrompt: 'Return JSON.',
    prompt: 'Inspect the repo.',
  });

  const prompt = await readFile(promptCapturePath, 'utf8');
  assert.match(prompt, /must not invoke Security Lab recursively/i);
  assert.match(prompt, /must not send probes to authorized live or hosted targets/i);
  assert.match(prompt, /free to read any file/i);
  // The old restrictive language must be gone so workers actually get freedom.
  assert.ok(!/prefer bounded/i.test(prompt));
  assert.ok(!/do not start or stop long-running services/i.test(prompt));
});

test('ClaudeCodeAdapter resumes a persisted session across invocations', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'security-lab-claude-cli-resume-'));
  const binaryPath = resolve(dir, 'claude');
  const resumeLogPath = resolve(dir, 'resume.log');
  await writeFile(binaryPath, `#!/bin/sh
resume_id=""
next=0
for arg in "$@"; do
  if [ "$next" = "1" ]; then
    resume_id="$arg"
    next=0
  fi
  if [ "$arg" = "--resume" ]; then
    next=1
  fi
done
printf '%s' "$resume_id" >> ${JSON.stringify(resumeLogPath)}
cat <<EOF
{"type":"assistant","session_id":"sess-resume","message":{"content":[{"type":"text","text":"continued"}]}}
{"type":"result","session_id":"sess-resume","result":"continued","total_cost_usd":0.02,"duration_ms":5,"usage":{"input_tokens":3,"output_tokens":2}}
EOF
`, 'utf8');
  await chmod(binaryPath, 0o755);

  const adapter = new ClaudeCodeAdapter({
    provider: 'claude_code',
    model: 'claude-opus-4-6',
    binaryPath,
  });

  const first = await adapter.invoke({ prompt: 'initial' });
  assert.equal(first.sessionId, 'sess-resume');

  const second = await adapter.invoke({ sessionId: first.sessionId, prompt: 'continue' });
  assert.equal(second.sessionId, 'sess-resume');
  assert.equal(second.content, 'continued');

  const resumeLog = await readFile(resumeLogPath, 'utf8');
  // First call had no sessionId, second call should have sent sess-resume via --resume.
  assert.equal(resumeLog, 'sess-resume');
});
