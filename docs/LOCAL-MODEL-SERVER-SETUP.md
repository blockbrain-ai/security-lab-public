# Local Model Server Setup

How to start the local inference servers needed for verification runs.

## Qwen 3.6-27B (default path)

All verification profiles use the Qwen llama-server on port 8080 as the primary or runtime model.

### Start

```bash
llama-server \
  -m /path/to/model.gguf \
  --port 8080 \
  -ngl 99 \
  --ctx-size 32768 \
  --reasoning-budget 4096 \
  --reasoning-format deepseek
```

### Verify

```bash
curl -s http://127.0.0.1:8080/v1/models
```

### Flags explained

| Flag | Purpose |
|------|---------|
| `-ngl 99` | Offload all layers to GPU (M4 Max 36GB fits the Q4_K_XL quantization) |
| `--ctx-size 32768` | 32K context window — matches bounded_local adapter's max |
| `--reasoning-budget 4096` | Cap thinking tokens so they don't consume the entire response budget |
| `--reasoning-format deepseek` | Separate thinking tokens into `reasoning_content` field (required for Qwen 3.6 thinking mode) |

## Ollama (comparator profiles)

Only needed for profiles that use DeepSeek-R1, Qwen 14B, Gemma 3, or Gemma 4 as comparators. The default `qwen_default` profile does not need Ollama.

### Start

```bash
ollama serve
```

### Verify

```bash
curl -s http://127.0.0.1:11434/v1/models
ollama list
```

### Required models

Pull the models needed by the comparator profiles:

```bash
ollama pull deepseek-r1:14b    # for qwen_source_r1_critic, r1_source_qwen_runtime
ollama pull qwen3:14b           # for qwen14_source_qwen27_runtime
ollama pull gemma3:12b          # for gemma_source_qwen_runtime
ollama pull gemma4:26b          # for gemma4_source_qwen_runtime, qwen_source_gemma4_critic
```

## Preflight check

After starting servers, verify everything works before running long benchmarks:

```bash
cd packages/attack-lab

# Default profile (Qwen only)
npx tsx src/autonomous/verify-cli.ts --verification-profile qwen_default --preflight-only

# Comparator profile (needs both llama-server + Ollama)
npx tsx src/autonomous/verify-cli.ts --verification-profile qwen_source_r1_critic --preflight-only
```

## Profile → server mapping

| Profile | llama-server (8080) | Ollama (11434) |
|---------|-------------------|----------------|
| `qwen_default` | required | not needed |
| `qwen_source_r1_critic` | required (source + runtime) | required (critic: deepseek-r1:14b) |
| `r1_source_qwen_runtime` | required (runtime) | required (source: deepseek-r1:14b) |
| `qwen14_source_qwen27_runtime` | required (runtime) | required (source: qwen3:14b) |
| `gemma_source_qwen_runtime` | required (runtime) | required (source: gemma3:12b) |
| `gemma4_source_qwen_runtime` | required (runtime) | required (source: gemma4:26b) |
| `qwen_source_gemma4_critic` | required (source + runtime) | required (critic: gemma4:26b) |

## Benchmark run sequence

After preflight passes:

```bash
cd packages/attack-lab

# 1. Qwen baseline
npx tsx src/autonomous/verify-cli.ts \
  --campaign <id> --target targets/<target>.yaml \
  --verification-mode source \
  --verification-profile qwen_default \
  --candidate-limit 5 --skip-audit \
  --benchmark-label qwen-<target>-source-baseline \
  --promote-benchmark-baseline

# 2. Comparator run
npx tsx src/autonomous/verify-cli.ts \
  --campaign <id> --target targets/<target>.yaml \
  --verification-mode source \
  --verification-profile qwen_source_r1_critic \
  --candidate-limit 5 --skip-audit \
  --benchmark-label qwen-r1critic-<target>-source
```

Results go to `data/benchmarks/<targetId>/` with scorecards, registry, and matrix summary.
