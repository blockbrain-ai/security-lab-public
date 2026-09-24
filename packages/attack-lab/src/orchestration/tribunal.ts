/**
 * Tribunal — second-pass or tie-break verdicts for critical/ambiguous findings.
 *
 * When the planner and judge disagree, or when severity is critical,
 * the tribunal uses a third model (or the same model with a different
 * prompt) to reach a final verdict.
 */

import type { ModelAdapter, ModelResponse } from '../providers/contracts.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TribunalInput {
  /** The finding or hypothesis in question. */
  hypothesis: string;
  /** What the planner concluded. */
  plannerVerdict: string;
  plannerReasoning: string;
  /** What the judge concluded. */
  judgeVerdict: string;
  judgeReasoning: string;
  /** Raw evidence (probe observations). */
  evidence: string;
  /** Severity of the hypothesis. */
  severity: string;
}

export interface TribunalVerdict {
  /** The tribunal's final verdict. */
  verdict: 'confirmed' | 'refuted' | 'insufficient_evidence' | 'needs_more_probes';
  /** Reasoning for the verdict. */
  reasoning: string;
  /** Confidence level 0-1. */
  confidence: number;
  /** Whether the tribunal agrees with planner, judge, or neither. */
  agreesWithPlanner: boolean;
  agreesWithJudge: boolean;
}

// ---------------------------------------------------------------------------
// Tribunal execution
// ---------------------------------------------------------------------------

const TRIBUNAL_SYSTEM_PROMPT = `You are a security tribunal arbiter. You receive a hypothesis about a potential vulnerability, along with the planner's verdict and reasoning, the judge's verdict and reasoning, and the raw evidence from probe observations.

Your job is to reach an independent final verdict. You must:
1. Consider both the planner's and judge's reasoning
2. Evaluate the raw evidence independently
3. Look for confirmation bias in either party's reasoning
4. Determine whether the evidence actually supports the hypothesis

Respond with a JSON object:
{
  "verdict": "confirmed" | "refuted" | "insufficient_evidence" | "needs_more_probes",
  "reasoning": "your detailed reasoning",
  "confidence": 0.0 to 1.0,
  "agreesWithPlanner": true/false,
  "agreesWithJudge": true/false
}`;

export async function runTribunal(
  adapter: ModelAdapter,
  input: TribunalInput,
): Promise<TribunalInvocation> {
  const prompt = `## Hypothesis
${input.hypothesis}

## Severity
${input.severity}

## Planner Verdict: ${input.plannerVerdict}
${input.plannerReasoning}

## Judge Verdict: ${input.judgeVerdict}
${input.judgeReasoning}

## Raw Evidence
${input.evidence}

Provide your independent verdict as JSON.`;

  const response = await adapter.invoke({
    systemPrompt: TRIBUNAL_SYSTEM_PROMPT,
    prompt,
    maxTokens: 8192,
    temperature: 0,
  });

  // Try to parse structured verdict from response
  const jsonMatch =
    response.content.match(/```(?:json)?\s*\n?([\s\S]*?)\n?```/) ??
    response.content.match(/(\{[\s\S]*\})/);

  if (jsonMatch) {
    try {
      const parsed = JSON.parse(jsonMatch[1]!);
      return {
        output: {
          verdict: parsed.verdict ?? 'insufficient_evidence',
          reasoning: parsed.reasoning ?? response.content,
          confidence: typeof parsed.confidence === 'number' ? parsed.confidence : 0.5,
          agreesWithPlanner: parsed.agreesWithPlanner ?? false,
          agreesWithJudge: parsed.agreesWithJudge ?? false,
        },
        prompt,
        systemPrompt: TRIBUNAL_SYSTEM_PROMPT,
        response,
        parseSuccess: true,
      };
    } catch {
      // Fall through to default
    }
  }

  return {
    output: {
      verdict: 'insufficient_evidence',
      reasoning: response.content,
      confidence: 0.3,
      agreesWithPlanner: false,
      agreesWithJudge: false,
    },
    prompt,
    systemPrompt: TRIBUNAL_SYSTEM_PROMPT,
    response,
    parseSuccess: false,
  };
}

export interface TribunalInvocation {
  output: TribunalVerdict;
  prompt: string;
  systemPrompt: string;
  response: ModelResponse;
  parseSuccess: boolean;
}
