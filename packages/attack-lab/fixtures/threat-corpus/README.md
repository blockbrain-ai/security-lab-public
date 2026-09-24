# Threat Corpus

Fixed adversarial fixture set with known ground-truth signals.
Used to measure whether the autonomous investigator is improving.

## Fixtures

| Directory | What It Tests | Chain? | Dormant Reactivation? |
|-----------|--------------|--------|----------------------|
| `authz-drift/` | Inconsistent auth across public/private surfaces | Yes | Yes |
| `prompt-smuggle/` | Business-data and tool-output instruction smuggling | Yes | Yes |
| `state-tamper/` | State/config mutation to bypass governance | Yes | No |
| `process-decoy/` | Decoy secrets and process-surface visibility | Yes | Yes |
| `evidence-poison/` | Evaluation label and baseline distortion | Yes | No |
| `persistence-decoy/` | Scheduled task / background process footholds | No | No |
| `dependency-trap/` | Lockfile drift, install-script behavior, provenance | Yes | No |
| `composition-chain/` | Multi-surface chain (file editor → shell input → code exec) | Yes | Yes |
| `thread-pull/` | Signals that correlate only after deeper investigation | Yes | Yes |

## Ground Truth

Each fixture's ground truth is defined in `packages/attack-lab/src/evaluation/corpus.ts`.
The scorer at `packages/attack-lab/src/evaluation/scorer.ts` compares investigator
outputs against this truth to compute recall, precision, chain confirmation,
dormant reactivation, and cost efficiency.

## Verification Criteria

The investigator is not considered functional until it can:

1. Find at least one multi-step chain in the corpus
2. Solve at least one fixture by reopening earlier low-confidence signals
3. Show measurable improvement between two runs via the scorer
