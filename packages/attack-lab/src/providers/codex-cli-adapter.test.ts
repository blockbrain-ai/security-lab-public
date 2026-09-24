import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { CodexCliAdapter } from './codex-cli-adapter.js';

test('CodexCliAdapter parses JSON events and resumes by dropping an invalid thread id', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'security-lab-codex-cli-'));
  const binaryPath = resolve(dir, 'codex');
  await writeFile(
    binaryPath,
    `#!/bin/sh
if [ "$2" = "resume" ]; then
  echo "resume failed" >&2
  exit 1
fi
cat <<'EOF'
{"type":"thread.started","thread_id":"thread-789"}
{"type":"item.completed","item":{"type":"agent_message","text":"{\\"answer\\":\\"ok\\"}"}}
{"type":"turn.completed","usage":{"input_tokens":1000,"output_tokens":200}}
EOF
`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new CodexCliAdapter({
    provider: 'codex_cli',
    model: 'gpt-5.4',
    binaryPath,
  });

  const response = await adapter.invoke({
    sessionId: 'stale-thread',
    prompt: 'Return JSON.',
  });

  assert.equal(response.provider, 'codex_cli');
  assert.equal(response.sessionId, 'thread-789');
  assert.equal(response.content, '{"answer":"ok"}');
  assert.ok(response.usage.costUsd > 0);
});

test('CodexCliAdapter injects the minimal two-rule worker contract into the prompt', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'security-lab-codex-cli-guardrails-'));
  const binaryPath = resolve(dir, 'codex');
  const promptCapturePath = resolve(dir, 'prompt.txt');
  await writeFile(
    binaryPath,
    `#!/bin/sh
last=""
for arg in "$@"; do
  last="$arg"
done
printf '%s' "$last" > ${JSON.stringify(promptCapturePath)}
cat <<'EOF'
{"type":"thread.started","thread_id":"thread-guardrails"}
{"type":"item.completed","item":{"type":"agent_message","text":"ok"}}
{"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":2}}
EOF
`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new CodexCliAdapter({
    provider: 'codex_cli',
    model: 'gpt-5.4',
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
  assert.ok(!/prefer bounded/i.test(prompt));
  assert.ok(!/do not start or stop long-running services/i.test(prompt));
});

test('CodexCliAdapter resumes a persisted session across invocations', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'security-lab-codex-cli-resume-'));
  const binaryPath = resolve(dir, 'codex');
  const resumeLogPath = resolve(dir, 'resume.log');
  const freshArgsPath = resolve(dir, 'fresh-args.log');
  const resumeArgsPath = resolve(dir, 'resume-args.log');
  await writeFile(
    binaryPath,
    `#!/bin/sh
if [ "$2" = "resume" ]; then
  printf '%s' "$3" >> ${JSON.stringify(resumeLogPath)}
  printf '%s\\n' "$@" > ${JSON.stringify(resumeArgsPath)}
else
  printf '%s\\n' "$@" > ${JSON.stringify(freshArgsPath)}
fi
cat <<'EOF'
{"type":"thread.started","thread_id":"thread-resume"}
{"type":"item.completed","item":{"type":"agent_message","text":"continued"}}
{"type":"turn.completed","usage":{"input_tokens":5,"output_tokens":2}}
EOF
`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new CodexCliAdapter({
    provider: 'codex_cli',
    model: 'gpt-5.4',
    binaryPath,
    workingDirectory: dir,
    additionalDirectories: [resolve(dir, 'extra-a'), resolve(dir, 'extra-b')],
  });

  const first = await adapter.invoke({ prompt: 'initial' });
  assert.equal(first.sessionId, 'thread-resume');

  const second = await adapter.invoke({
    sessionId: first.sessionId,
    prompt: 'continue',
  });
  assert.equal(second.sessionId, 'thread-resume');
  assert.equal(second.content, 'continued');

  const resumeLog = await readFile(resumeLogPath, 'utf8');
  assert.equal(resumeLog, 'thread-resume');

  const freshArgs = await readFile(freshArgsPath, 'utf8');
  assert.match(freshArgs, /^exec$/m);
  assert.match(freshArgs, /^-C$/m);
  assert.match(freshArgs, /^--add-dir$/m);

  const resumeArgs = await readFile(resumeArgsPath, 'utf8');
  assert.match(resumeArgs, /^exec$/m);
  assert.match(resumeArgs, /^resume$/m);
  assert.match(resumeArgs, /^thread-resume$/m);
  assert.match(resumeArgs, /^--dangerously-bypass-approvals-and-sandbox$/m);
  assert.doesNotMatch(resumeArgs, /^-C$/m);
  assert.doesNotMatch(resumeArgs, /^--add-dir$/m);
});

test('CodexCliAdapter passes local Codex transport flags on fresh runs and zeroes local cost', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'security-lab-codex-cli-local-'));
  const binaryPath = resolve(dir, 'codex');
  const freshArgsPath = resolve(dir, 'fresh-args.log');
  await writeFile(
    binaryPath,
    `#!/bin/sh
printf '%s\\n' "$@" > ${JSON.stringify(freshArgsPath)}
cat <<'EOF'
{"type":"thread.started","thread_id":"thread-local"}
{"type":"item.completed","item":{"type":"agent_message","text":"local-ok"}}
{"type":"turn.completed","usage":{"input_tokens":1000,"output_tokens":200}}
EOF
`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new CodexCliAdapter({
    provider: 'codex_cli',
    model: 'qwen3.6:27b',
    binaryPath,
    localInference: true,
    cliLocalProvider: 'ollama',
    cliProfile: 'local-qwen',
  });

  const response = await adapter.invoke({ prompt: 'Inspect the repo.' });

  assert.equal(response.content, 'local-ok');
  assert.equal(response.usage.costUsd, 0);

  const freshArgs = await readFile(freshArgsPath, 'utf8');
  assert.match(freshArgs, /^-p$/m);
  assert.match(freshArgs, /^local-qwen$/m);
  assert.match(freshArgs, /^--oss$/m);
  assert.match(freshArgs, /^--local-provider$/m);
  assert.match(freshArgs, /^ollama$/m);
});

test('CodexCliAdapter resume sends --oss/--local-provider for local models but omits profile', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'security-lab-codex-cli-local-resume-'));
  const binaryPath = resolve(dir, 'codex');
  const freshArgsPath = resolve(dir, 'fresh-args.log');
  const resumeArgsPath = resolve(dir, 'resume-args.log');
  await writeFile(
    binaryPath,
    `#!/bin/sh
if [ "$2" = "resume" ]; then
  printf '%s\\n' "$@" > ${JSON.stringify(resumeArgsPath)}
else
  printf '%s\\n' "$@" > ${JSON.stringify(freshArgsPath)}
fi
cat <<'EOF'
{"type":"thread.started","thread_id":"thread-local-resume"}
{"type":"item.completed","item":{"type":"agent_message","text":"ok"}}
{"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":2}}
EOF
`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new CodexCliAdapter({
    provider: 'codex_cli',
    model: 'qwen3.6:27b',
    binaryPath,
    localInference: true,
    cliLocalProvider: 'ollama',
    cliProfile: 'local-qwen',
  });

  const first = await adapter.invoke({ prompt: 'initial' });
  const second = await adapter.invoke({
    sessionId: first.sessionId,
    prompt: 'continue',
  });

  assert.equal(second.sessionId, 'thread-local-resume');

  const freshArgs = await readFile(freshArgsPath, 'utf8');
  assert.match(freshArgs, /^--oss$/m);
  assert.match(freshArgs, /^--local-provider$/m);
  assert.match(freshArgs, /^-p$/m);

  const resumeArgs = await readFile(resumeArgsPath, 'utf8');
  assert.match(resumeArgs, /^--oss$/m);
  assert.match(resumeArgs, /^--local-provider$/m);
  assert.match(resumeArgs, /^ollama$/m);
  assert.doesNotMatch(resumeArgs, /^-p$/m);
});

test('CodexCliAdapter refuses an oversized prompt when brief mode is absent', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'security-lab-codex-cli-largeprompt-'));
  const binaryPath = resolve(dir, 'codex');
  // The binary should never be invoked — the adapter must throw before exec.
  await writeFile(
    binaryPath,
    `#!/bin/sh
echo "codex should not have been called" >&2
exit 99
`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new CodexCliAdapter({
    provider: 'codex_cli',
    model: 'gpt-5.4',
    binaryPath,
  });

  // ~500K chars ≈ 125K approx tokens — over the 100K guard threshold
  const hugePrompt = 'x'.repeat(500_000);

  await assert.rejects(adapter.invoke({ prompt: hugePrompt }), /refusing prompt of ~[\d,]+ tokens without brief mode/, 'large prompt without brief mode should be refused');
});

test('CodexCliAdapter accepts an oversized prompt when brief mode IS attached', async () => {
  const dir = await mkdtemp(resolve(tmpdir(), 'security-lab-codex-cli-brief-accept-'));
  const binaryPath = resolve(dir, 'codex');
  await writeFile(
    binaryPath,
    `#!/bin/sh
cat <<'EOF'
{"type":"thread.started","thread_id":"thread-brief"}
{"type":"item.completed","item":{"type":"agent_message","text":"ok"}}
{"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":2}}
EOF
`,
    'utf8',
  );
  await chmod(binaryPath, 0o755);

  const adapter = new CodexCliAdapter({
    provider: 'codex_cli',
    model: 'gpt-5.4',
    binaryPath,
  });

  const hugePrompt = 'x'.repeat(500_000);

  // With brief mode attached, the guard is bypassed because large context
  // is assumed to be on disk (the prompt itself may still be large in
  // pathological cases, but the caller is asserting it has taken steps).
  const response = await adapter.invoke({
    prompt: hugePrompt,
    briefMode: {
      briefPath: '/tmp/fake-brief.md',
      artifactsDir: '/tmp/fake-artifacts',
      scopeId: 'test',
      evidencePointers: [],
    },
  });

  assert.equal(response.sessionId, 'thread-brief');
});
