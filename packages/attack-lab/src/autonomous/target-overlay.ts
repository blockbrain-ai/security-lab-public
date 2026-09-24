/**
 * Target overlay loader — reads an overlay from a target profile (either
 * inline or from a file path), validates it, and renders it into a prompt
 * fragment. Replaces the old hardcoded per-target overlay approach.
 */

import { readFile } from 'node:fs/promises';
import { dirname, isAbsolute, resolve } from 'node:path';
import YAML from 'yaml';
import { z } from 'zod';
import type { InvestigationTarget, OverlayInline } from './target-profile.js';

// ---------------------------------------------------------------------------
// Validation schema
// ---------------------------------------------------------------------------

export const OverlayInlineSchema = z.object({
  stackHints: z.record(z.string()).optional(),
  highValuePatterns: z.array(z.string()).optional(),
  trustBoundaries: z.array(z.object({
    from: z.string(),
    to: z.string(),
    mechanism: z.string(),
    notes: z.string().optional(),
  })).optional(),
  vulnerabilityFamilies: z.array(z.object({
    family: z.string(),
    description: z.string(),
    priority: z.enum(['critical', 'high', 'medium', 'low']).optional(),
    checkLocations: z.array(z.string()).optional(),
  })).optional(),
  engineeringStandards: z.array(z.string()).optional(),
});

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

/**
 * Load and render the target overlay as a markdown prompt fragment.
 * Returns an empty string if the target has no overlay declared.
 */
export async function loadTargetOverlay(target: InvestigationTarget): Promise<string> {
  if (!target.overlay) {
    return '';
  }

  let overlay: OverlayInline;

  if (typeof target.overlay === 'string') {
    overlay = await loadOverlayFile(target.overlay, target.profilePath);
  } else {
    overlay = OverlayInlineSchema.parse(target.overlay);
  }

  return renderOverlay(overlay, target.name);
}

async function loadOverlayFile(overlayPath: string, profilePath?: string): Promise<OverlayInline> {
  const resolvedPath = resolveOverlayPath(overlayPath, profilePath);
  const raw = await readFile(resolvedPath, 'utf8');
  const parsed = YAML.parse(raw);
  return OverlayInlineSchema.parse(parsed);
}

function resolveOverlayPath(overlayPath: string, profilePath?: string): string {
  if (isAbsolute(overlayPath)) {
    return overlayPath;
  }
  if (profilePath) {
    return resolve(dirname(profilePath), overlayPath);
  }
  return resolve(overlayPath);
}

// ---------------------------------------------------------------------------
// Renderer
// ---------------------------------------------------------------------------

function renderOverlay(overlay: OverlayInline, targetName: string): string {
  const sections: string[] = [];

  sections.push(`## Target-Specific Investigation Hints: ${targetName}`);
  sections.push('');

  if (overlay.stackHints && Object.keys(overlay.stackHints).length > 0) {
    const stackLine = Object.entries(overlay.stackHints)
      .map(([key, value]) => `${key}: ${value}`)
      .join(', ');
    sections.push(`Stack: ${stackLine}`);
    sections.push('');
  }

  if (overlay.vulnerabilityFamilies && overlay.vulnerabilityFamilies.length > 0) {
    sections.push('### Priority Vulnerability Families');
    sections.push('');
    for (const f of overlay.vulnerabilityFamilies) {
      sections.push(`- **${f.family}** (${f.priority ?? 'medium'}): ${f.description}`);
    }
    sections.push('');
  }

  if (overlay.trustBoundaries && overlay.trustBoundaries.length > 0) {
    sections.push('### Trust Boundaries to Probe');
    sections.push('');
    for (const b of overlay.trustBoundaries) {
      const notes = b.notes ? ` (${b.notes})` : '';
      sections.push(`- ${b.from} → ${b.to}: ${b.mechanism}${notes}`);
    }
    sections.push('');
  }

  if (overlay.highValuePatterns && overlay.highValuePatterns.length > 0) {
    sections.push('### High-Value Code Patterns');
    sections.push('');
    sections.push(`Search for: ${overlay.highValuePatterns.join(', ')}`);
    sections.push('');
  }

  if (overlay.engineeringStandards && overlay.engineeringStandards.length > 0) {
    sections.push('### Engineering Standards (may be violated)');
    sections.push('');
    for (const standard of overlay.engineeringStandards) {
      sections.push(`- ${standard}`);
    }
    sections.push('');
  }

  return sections.join('\n');
}
