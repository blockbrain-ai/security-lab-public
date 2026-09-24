/**
 * Target scanner — reads a target codebase and builds a TargetSurfaceMap
 * that fits in a model context window for planner consumption.
 */

import { readFile, readdir, stat } from 'node:fs/promises';
import { resolve, join, relative, extname } from 'node:path';
import { collectIndicatorsFromLockfile, detectLockfile, readSelectedLockfile } from '../dependencies/lockfile.js';
import type {
  TargetSurfaceMap,
  StackInfo,
  RouteSurface,
  RouteAuthObservation,
  AuthSurface,
  ConfigSurface,
  PersistenceSurface,
  PublicSurface,
  StructureSummary,
  DependencySurface,
  SurfaceProvenance,
  CoverageClassification,
  DetectedStack,
} from './contracts.js';
import { detectPythonManifests, parsePythonDependencies } from './manifest-parsers/python.js';
import { detectGoManifests, parseGoDependencies } from './manifest-parsers/go.js';
import { detectRustManifests, parseRustDependencies } from './manifest-parsers/rust.js';
import { detectJavaManifests, parseJavaDependencies } from './manifest-parsers/java.js';

// ---------------------------------------------------------------------------
// Generated / build artifact directories to exclude from scanning
// ---------------------------------------------------------------------------

export const EXCLUDED_DIRS = new Set([
  'node_modules', '.git', 'dist', '.next', 'out', 'build',
  'coverage', '.nyc_output', 'playwright-report', '.playwright',
  '.turbo', '.cache', '.parcel-cache', '__pycache__',
  '.pytest_cache', '.tsbuildinfo', 'storybook-static',
  '.docusaurus', '.vercel', '.output',
]);

export interface ScanOptions {
  includePaths?: string[];
  excludePaths?: string[];
  routeRoots?: string[];
  searchRoots?: string[];
  maxFiles?: number;
}

interface FileAuthMarker {
  routerVar: string;
  line: number;
  pathPrefix?: string;
  evidence: string[];
}

// Source-file extensions. Node (ts/tsx/js/jsx), Python (py/pyi), and Go
// (go) all supported. Config extensions (.json/.yaml/.toml/.env) are
// classified separately in scanStructure.
const NODE_SOURCE_EXTS = new Set(['.ts', '.tsx', '.js', '.jsx']);
const PYTHON_SOURCE_EXTS = new Set(['.py', '.pyi']);
const GO_SOURCE_EXTS = new Set(['.go']);
const SOURCE_FILE_REGEX = /\.(ts|tsx|js|jsx|py|pyi|go)$/;

// Route-call pattern for Node frameworks (Express/Hono/Fastify):
//   app.get('/path'), router.post("...")
const ROUTE_PATTERN = /(\w+)\.(get|post|put|patch|delete|head|options|all)\s*\(\s*['"`]([^'"`]+)['"`]/gi;

// FastAPI / Starlette / Flask decorator pattern:
//   @app.get("/path")              → method GET, path /path
//   @router.post("/items")         → method POST, path /items
//   @app.api_route("/x", methods=) → method ROUTE (unknown until kwarg parse)
//   @app.route("/y")               → method ROUTE (Flask; default GET)
// The `@` decorator prefix is what distinguishes a route decorator from a
// method call on a dict/response/etc., so it's required to avoid false
// positives. Path is in the first positional arg, single or double quotes.
const FASTAPI_ROUTE_PATTERN = /@\s*(\w+)\.(get|post|put|patch|delete|head|options|api_route|route)\s*\(\s*['"]([^'"]+)['"]/g;

// Go HTTP framework route patterns. Go's ecosystem is fragmented enough
// that we need two complementary patterns:
//
// Pattern A — per-method decorators on gin/echo/chi/fiber style:
//   r.GET("/users", handler)        → gin, chi (via Get), echo (via GET)
//   e.Post("/api", handler)         → echo lowercase alias
//   app.Delete(...)                 → fiber
//   router.PATCH(...)                → gin
// Capitalized method names are the Go convention; fiber and chi also
// expose mixed-case forms. We accept both.
const GO_ROUTE_PATTERN = /(\w+)\.(Get|Post|Put|Patch|Delete|Head|Options|GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*\(\s*"([^"]+)"/g;
//
// Pattern B — HandleFunc / Handle (net/http stdlib, gorilla/mux, chi
// fallback). These have no HTTP method in the call signature — the
// method is either unrestricted or specified via a chained .Methods()
// call that we do not attempt to track. Routes matched here are
// classified as method 'ANY'.
//   http.HandleFunc("/api", handler)
//   router.Handle("/path", handler)
//   mux.HandleFunc("/users", userHandler)
const GO_HANDLEFUNC_PATTERN = /(\w+)\.(HandleFunc|Handle)\s*\(\s*"([^"]+)"/g;

const AUTH_HINT_PATTERN = /\b(requireAuth|isAuthenticated|authGuard|requireScope|requireAdmin|authorize|verifyToken|authMiddleware|jwt|bearer|session)\b/gi;
// Python/FastAPI-specific auth hints. Matched against route snippets and
// file-level patterns alongside the Node AUTH_HINT_PATTERN.
const PYTHON_AUTH_HINT_PATTERN = /\b(Depends|Security|OAuth2PasswordBearer|HTTPBearer|current_user|get_current_user|verify_token|verify_password|require_auth|require_admin)\b/g;
// Go-specific auth hints. Matched against route snippets and file-level
// patterns alongside the Node AUTH_HINT_PATTERN.
const GO_AUTH_HINT_PATTERN = /\b(RequireAuth|AuthMiddleware|JWTMiddleware|BearerAuth|BasicAuth|SessionMiddleware|CheckAuth|Authorize|jwt\.Parse|jwt\.Verify|bcrypt\.Compare|sessions\.Get|middleware\.Auth|r\.Use|app\.Use|e\.Use)\b/g;
const VALIDATION_HINT_PATTERN = /\b(zod|validate|schema|parse|safeParse|validator|pydantic|BaseModel)\b/gi;

// ---------------------------------------------------------------------------
// Main scanner
// ---------------------------------------------------------------------------

export async function scanTarget(
  repoRoot: string,
  targetId: string,
  options: ScanOptions = {},
): Promise<TargetSurfaceMap> {
  const structure = await scanStructure(repoRoot, options);
  const stack = await detectStack(repoRoot);
  const routes = await extractRoutes(repoRoot, options);
  const auth = await extractAuth(repoRoot, options);
  const config = await extractConfig(repoRoot, options);
  const persistence = await extractPersistence(repoRoot, options);
  const publicSurfaces = await extractPublicSurfaces(repoRoot, options);
  const dependencies = await extractDependencies(repoRoot);

  // Determine coverage classification. A "Node stack with deps" is one
  // where `detectStack` resolved a Node framework AND `extractDependencies`
  // found a package.json with entries. `detectStack` may also return
  // `runtime: 'python'` when a Python framework is detected; in that case
  // the Python branch of `classifyCoverage` takes over.
  const isNodeStack = stack.runtime === 'node' && stack.framework !== 'unknown';
  const hasNodePackageJson = dependencies.length > 0;

  const { coverage, supportedProbeKinds, detectedStack, extraDependencies } =
    await classifyCoverage(repoRoot, isNodeStack && hasNodePackageJson, routes, dependencies);

  return {
    targetId,
    scannedAt: new Date().toISOString(),
    repoRoot,
    stack,
    routes,
    auth,
    config,
    persistence,
    publicSurfaces,
    dependencies: [...dependencies, ...extraDependencies],
    structure,
    coverage,
    supportedProbeKinds,
    detectedStack,
  };
}

// ---------------------------------------------------------------------------
// Coverage classification
// ---------------------------------------------------------------------------

interface CoverageResult {
  coverage: CoverageClassification;
  supportedProbeKinds: string[];
  detectedStack?: DetectedStack;
  extraDependencies: DependencySurface[];
}

async function classifyCoverage(
  repoRoot: string,
  isNodeWithDeps: boolean,
  routes: RouteSurface[],
  nodeDependencies: DependencySurface[],
): Promise<CoverageResult> {
  // Node stack with recognized framework + routes = full coverage
  if (isNodeWithDeps && routes.length > 0) {
    return {
      coverage: 'full',
      supportedProbeKinds: ['http_request', 'code_read', 'dependency_read', 'dependency_scan', 'state_check', 'evidence_check'],
      extraDependencies: [],
    };
  }

  // Node stack with package.json but no routes — still full (code-only Node is well-supported)
  if (isNodeWithDeps && nodeDependencies.length > 0) {
    return {
      coverage: 'full',
      supportedProbeKinds: ['code_read', 'dependency_read', 'dependency_scan', 'state_check', 'evidence_check'],
      extraDependencies: [],
    };
  }

  // Non-Node: check for other language manifests
  const [pythonManifests, goManifests, rustManifests, javaManifests] = await Promise.all([
    detectPythonManifests(repoRoot),
    detectGoManifests(repoRoot),
    detectRustManifests(repoRoot),
    detectJavaManifests(repoRoot),
  ]);

  const allManifests = [...pythonManifests, ...goManifests, ...rustManifests, ...javaManifests];

  if (allManifests.length === 0) {
    return {
      coverage: 'none',
      supportedProbeKinds: [],
      extraDependencies: [],
    };
  }

  // Determine language from detected manifests
  const language = pythonManifests.length > 0
    ? 'python'
    : goManifests.length > 0
      ? 'go'
      : rustManifests.length > 0
        ? 'rust'
        : 'java';

  const detectedStack: DetectedStack = {
    language,
    framework: 'unknown',
    manifestFiles: allManifests,
  };

  // Try to parse dependencies from the manifests
  const parsedDeps: DependencySurface[] = [];
  const disabledParsers = new Set(
    (process.env['DISABLED_MANIFEST_PARSERS'] ?? '').split(',').map((s) => s.trim().toLowerCase()).filter(Boolean),
  );

  if (pythonManifests.length > 0 && !disabledParsers.has('python')) {
    parsedDeps.push(...await parsePythonDependencies(repoRoot));
  }
  if (goManifests.length > 0 && !disabledParsers.has('go')) {
    parsedDeps.push(...await parseGoDependencies(repoRoot));
  }
  if (rustManifests.length > 0 && !disabledParsers.has('rust')) {
    parsedDeps.push(...await parseRustDependencies(repoRoot));
  }
  if (javaManifests.length > 0 && !disabledParsers.has('java')) {
    parsedDeps.push(...await parseJavaDependencies(repoRoot));
  }

  // Python-specific: if we extracted FastAPI/Flask/Starlette routes, we have
  // route + auth data and can support http_request probes too. This mirrors
  // the Node "full coverage" path.
  if (language === 'python' && routes.length > 0) {
    return {
      coverage: 'full',
      supportedProbeKinds: [
        'http_request',
        'code_read',
        'dependency_read',
        'dependency_scan',
        'state_check',
        'evidence_check',
      ],
      detectedStack,
      extraDependencies: parsedDeps,
    };
  }

  // Python-specific: manifests + parsed deps but no routes (e.g. a pure
  // library). Still elevate to 'full' code-only coverage so the planner
  // knows Python source is scannable — this is equivalent to the Node
  // "code-only Node is well-supported" branch above.
  if (language === 'python' && parsedDeps.length > 0) {
    return {
      coverage: 'full',
      supportedProbeKinds: ['code_read', 'dependency_read', 'dependency_scan', 'state_check', 'evidence_check'],
      detectedStack,
      extraDependencies: parsedDeps,
    };
  }

  // Go-specific: same shape as Python. If FastAPI-like route extraction
  // produced hits on Go source (via GO_ROUTE_PATTERN / GO_HANDLEFUNC_PATTERN),
  // elevate to full with http_request probes. Otherwise if go.mod deps
  // parsed, elevate to full code-only coverage.
  if (language === 'go' && routes.length > 0) {
    return {
      coverage: 'full',
      supportedProbeKinds: [
        'http_request',
        'code_read',
        'dependency_read',
        'dependency_scan',
        'state_check',
        'evidence_check',
      ],
      detectedStack,
      extraDependencies: parsedDeps,
    };
  }
  if (language === 'go' && parsedDeps.length > 0) {
    return {
      coverage: 'full',
      supportedProbeKinds: ['code_read', 'dependency_read', 'dependency_scan', 'state_check', 'evidence_check'],
      detectedStack,
      extraDependencies: parsedDeps,
    };
  }

  if (parsedDeps.length > 0) {
    return {
      coverage: 'partial',
      supportedProbeKinds: ['code_read', 'dependency_read', 'dependency_scan'],
      detectedStack,
      extraDependencies: parsedDeps,
    };
  }

  // Manifests detected but no deps parsed (empty files, etc.)
  return {
    coverage: 'manifest-only',
    supportedProbeKinds: ['dependency_read'],
    detectedStack,
    extraDependencies: [],
  };
}

// ---------------------------------------------------------------------------
// Structure scanning
// ---------------------------------------------------------------------------

async function scanStructure(root: string, options: ScanOptions): Promise<StructureSummary> {
  const dirs: string[] = [];
  let totalFiles = 0;
  let sourceFiles = 0;
  let testFiles = 0;
  let configFiles = 0;
  let scannedFiles = 0;
  const roots = resolveScanRoots(root, options.includePaths);
  const maxFiles = options.maxFiles ?? Number.POSITIVE_INFINITY;

  async function walk(dir: string, depth: number): Promise<void> {
    if (depth > 4 || scannedFiles >= maxFiles) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch { return; }

    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (shouldSkipEntry(entry.name, full, root, options)) continue;
      if (entry.isDirectory()) {
        if (depth < 3) dirs.push(relative(root, full));
        await walk(full, depth + 1);
      } else {
        scannedFiles++;
        totalFiles++;
        const ext = extname(entry.name);
        if (NODE_SOURCE_EXTS.has(ext)) {
          if (entry.name.includes('.test.') || entry.name.includes('.spec.')) {
            testFiles++;
          } else {
            sourceFiles++;
          }
        } else if (PYTHON_SOURCE_EXTS.has(ext)) {
          // Python test naming conventions: test_foo.py, foo_test.py, or
          // inside a tests/ directory. The directory check is handled by
          // classifyProvenance when routes/auth are extracted; here we
          // only classify per-filename.
          if (entry.name.startsWith('test_') || entry.name.endsWith('_test.py')) {
            testFiles++;
          } else {
            sourceFiles++;
          }
        } else if (GO_SOURCE_EXTS.has(ext)) {
          // Go test convention is *_test.go (mandatory for the go test
          // toolchain). No other suffix is recognised as a test file.
          if (entry.name.endsWith('_test.go')) {
            testFiles++;
          } else {
            sourceFiles++;
          }
        } else if (['.json', '.yaml', '.yml', '.toml', '.env'].includes(ext) || entry.name === '.env') {
          configFiles++;
        }
      }
    }
  }

  for (const scanRoot of roots) {
    await walk(scanRoot, 0);
  }
  return { totalFiles, sourceFiles, testFiles, configFiles, directories: dirs };
}

// ---------------------------------------------------------------------------
// Stack detection
// ---------------------------------------------------------------------------

async function detectStack(root: string): Promise<StackInfo> {
  const info: StackInfo = { runtime: 'node', framework: 'unknown' };

  let sawNodeFramework = false;
  try {
    const pkg = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8'));
    const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };

    if (allDeps['express']) { info.framework = 'express'; sawNodeFramework = true; }
    else if (allDeps['fastify']) { info.framework = 'fastify'; sawNodeFramework = true; }
    else if (allDeps['next']) { info.framework = 'next'; sawNodeFramework = true; }
    else if (allDeps['hono']) { info.framework = 'hono'; sawNodeFramework = true; }

    if (allDeps['@prisma/client'] || allDeps['prisma']) info.orm = 'prisma';
    else if (allDeps['typeorm']) info.orm = 'typeorm';
    else if (allDeps['drizzle-orm']) info.orm = 'drizzle';

    if (allDeps['next']) info.frontend = 'next';
    else if (allDeps['react']) info.frontend = 'react';
    else if (allDeps['vue']) info.frontend = 'vue';

    if (allDeps['vitest']) info.testFramework = 'vitest';
    else if (allDeps['jest']) info.testFramework = 'jest';
    else if (allDeps['mocha']) info.testFramework = 'mocha';
  } catch {
    // No package.json
  }

  // Python framework detection via pyproject.toml / requirements.txt.
  // If a Python web framework is detected AND no Node web framework was
  // seen (some projects like fixture-target ship both a Node UI piece and a Python
  // proxy binary — the Python framework should win if there's no Node
  // framework in the root package.json), override the runtime.
  let sawPythonFramework = false;
  if (!sawNodeFramework) {
    const pythonFramework = await detectPythonFramework(root);
    if (pythonFramework) {
      info.runtime = 'python';
      info.framework = pythonFramework;
      sawPythonFramework = true;
    }
  }

  // Go framework detection via go.mod. Runs last — Node and Python both
  // win if present, because a repo that ships both a Python binary AND a
  // vendored Go utility (e.g. llama.cpp helper) should still be classified
  // as Python. Go wins only when nothing else is detected.
  if (!sawNodeFramework && !sawPythonFramework) {
    const goFramework = await detectGoFramework(root);
    if (goFramework) {
      info.runtime = 'go';
      info.framework = goFramework;
    }
  }

  return info;
}

async function detectPythonFramework(root: string): Promise<string | undefined> {
  const frameworkMap: Array<{ pkg: string; name: string }> = [
    { pkg: 'fastapi', name: 'fastapi' },
    { pkg: 'starlette', name: 'starlette' },
    { pkg: 'flask', name: 'flask' },
    { pkg: 'django', name: 'django' },
    { pkg: 'tornado', name: 'tornado' },
    { pkg: 'sanic', name: 'sanic' },
    { pkg: 'aiohttp', name: 'aiohttp' },
  ];

  const candidates = ['pyproject.toml', 'requirements.txt', 'setup.py', 'Pipfile'];
  for (const candidate of candidates) {
    try {
      const content = await readFile(resolve(root, candidate), 'utf8');
      const lower = content.toLowerCase();
      for (const { pkg, name } of frameworkMap) {
        // Match the package as a token boundary: `"fastapi"`, `fastapi==`,
        // `fastapi>=`, or bare `fastapi` on its own line.
        const pattern = new RegExp(
          `(?:^|[\\s'"\\[,])${pkg}(?:==|>=|<=|~=|!=|<|>|\\s|'|"|$)`,
          'm',
        );
        if (pattern.test(lower)) {
          return name;
        }
      }
    } catch {
      // file absent; continue
    }
  }
  return undefined;
}

async function detectGoFramework(root: string): Promise<string | undefined> {
  // Framework precedence order. Most specific match wins.
  // "net-http" is the stdlib fallback — if any other framework is
  // present as a go.mod require, it wins; otherwise we assume stdlib.
  const frameworkMap: Array<{ module: string; name: string }> = [
    { module: 'github.com/gin-gonic/gin', name: 'gin' },
    { module: 'github.com/labstack/echo', name: 'echo' },
    { module: 'github.com/go-chi/chi', name: 'chi' },
    { module: 'github.com/gofiber/fiber', name: 'fiber' },
    { module: 'github.com/gorilla/mux', name: 'gorilla' },
    { module: 'github.com/julienschmidt/httprouter', name: 'httprouter' },
  ];

  try {
    const content = await readFile(resolve(root, 'go.mod'), 'utf8');
    // Module lines look like: `    github.com/gin-gonic/gin v1.9.1`
    // or `    github.com/gin-gonic/gin/v2 v2.0.0`
    for (const { module, name } of frameworkMap) {
      // Match start-of-line whitespace then module path. Allow /v2, /v3, etc.
      const pattern = new RegExp(`^\\s*${module.replace(/\\./g, '\\.').replace(/\//g, '\\/')}(?:/v\\d+)?\\s+v`, 'm');
      if (pattern.test(content)) {
        return name;
      }
    }

    // No framework matched but go.mod exists. Treat as stdlib net/http —
    // many large Go projects (Kubernetes, Docker, ollama) use stdlib
    // directly with custom routers rather than one of the popular
    // frameworks above.
    return 'net-http';
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------
// Route extraction (pattern-based, not AST)
// ---------------------------------------------------------------------------

async function extractRoutes(root: string, options: ScanOptions): Promise<RouteSurface[]> {
  const routes: RouteSurface[] = [];

  await searchFiles(root, SOURCE_FILE_REGEX, async (file, content) => {
    const rel = relative(root, file);
    if (rel.includes('.test.') || rel.includes('.spec.') || rel.includes('node_modules')) return;
    if (rel.includes('/tests/') || rel.startsWith('tests/')) return;

    const isPython = rel.endsWith('.py') || rel.endsWith('.pyi');
    const isGo = rel.endsWith('.go');
    // Go test files end with _test.go; we already skip /tests/ above but
    // the per-file test suffix needs a separate check.
    if (isGo && rel.endsWith('_test.go')) return;

    // Collect (pattern, kind) tuples to sweep. Node and Python use one
    // pattern each; Go uses two complementary patterns (per-method
    // decorators + HandleFunc/Handle fallback).
    const sweeps: Array<{ regex: RegExp; kind: 'node' | 'python' | 'go-method' | 'go-handle' }> = [];
    if (isPython) {
      sweeps.push({ regex: FASTAPI_ROUTE_PATTERN, kind: 'python' });
    } else if (isGo) {
      sweeps.push({ regex: GO_ROUTE_PATTERN, kind: 'go-method' });
      sweeps.push({ regex: GO_HANDLEFUNC_PATTERN, kind: 'go-handle' });
    } else {
      sweeps.push({ regex: ROUTE_PATTERN, kind: 'node' });
    }

    // Node code has Express-style router-level middleware (`router.use(...)`);
    // FastAPI auth markers are inline dependencies (`Depends()`), not
    // registered on the router object; Go middleware is chained via
    // `router.Use(middleware)` but tracking middleware scoping across Go
    // compositional styles is beyond the scope of pattern matching. So we
    // only run the Express-style marker extractor for Node files.
    const authMarkers = isPython || isGo ? [] : extractFileAuthMarkers(content);
    const lines = content.split('\n');
    const seen = new Set<string>();  // dedupe (method, path, file, line)

    for (const sweep of sweeps) {
      let match;
      while ((match = sweep.regex.exec(content)) !== null) {
        const routerVar = match[1]!;
        const rawMethod = match[2]!.toUpperCase();

        // Method normalization per-sweep:
        //  - FastAPI's api_route / Flask's route → ANY (method list in kwargs
        //    we don't parse)
        //  - Go HandleFunc / Handle → ANY (no method in call signature; may
        //    be constrained by chained .Methods() we don't track)
        let method: string;
        if (sweep.kind === 'python') {
          method = rawMethod === 'API_ROUTE' || rawMethod === 'ROUTE' ? 'ANY' : rawMethod;
        } else if (sweep.kind === 'go-handle') {
          method = 'ANY';
        } else {
          method = rawMethod;
        }

        const path = match[3]!;
        const lineNum = content.substring(0, match.index).split('\n').length;

        // Dedupe — Go's two patterns can't overlap (HandleFunc vs Get/Post
        // are different tokens) but this is defensive in case we ever add
        // a third sweep that could double-match.
        const key = `${method}|${path}|${lineNum}`;
        if (seen.has(key)) continue;
        seen.add(key);

        const callSnippet = extractRouteSnippet(content, match.index);
        const surroundingLines = lines.slice(Math.max(0, lineNum - 3), lineNum + 3).join(' ');

        // FastAPI dependencies live in the handler signature below the
        // decorator, so we widen the inspection window to include ~15 lines
        // after the decorator for Python routes. Go handlers are usually
        // anonymous function literals passed as the second argument to the
        // route call, so the call snippet itself is usually sufficient.
        const handlerWindow = sweep.kind === 'python'
          ? lines.slice(Math.max(0, lineNum - 1), lineNum + 15).join(' ')
          : callSnippet;

        let localAuthEvidence: string[];
        if (sweep.kind === 'python') {
          localAuthEvidence = collectHintMatches(handlerWindow, PYTHON_AUTH_HINT_PATTERN);
        } else if (sweep.kind === 'go-method' || sweep.kind === 'go-handle') {
          // Go: combine the generic auth hint (bearer, session, etc.) with
          // the Go-specific auth hints (RequireAuth, middleware.Auth,
          // jwt.Parse, etc.).
          localAuthEvidence = [
            ...collectHintMatches(callSnippet, AUTH_HINT_PATTERN),
            ...collectHintMatches(callSnippet, GO_AUTH_HINT_PATTERN),
          ];
        } else {
          localAuthEvidence = collectHintMatches(callSnippet, AUTH_HINT_PATTERN);
        }

        const fileMiddleware = authMarkers.filter(
          (marker) =>
            marker.routerVar === routerVar
            && marker.line <= lineNum
            && routeMatchesPrefix(path, marker.pathPrefix),
        );
        const authEvidence = localAuthEvidence.length > 0
          ? localAuthEvidence
          : [...new Set(fileMiddleware.flatMap((marker) => marker.evidence))].slice(0, 5);
        const authObservation: RouteAuthObservation = localAuthEvidence.length > 0
          ? 'handler_local'
          : fileMiddleware.length > 0
            ? 'file_middleware'
            : 'not_observed';
        const validationEvidence = collectHintMatches(callSnippet, VALIDATION_HINT_PATTERN);
        const notes = authObservation === 'not_observed'
          ? 'No local auth markers observed in the route definition. Mount-level auth may still exist elsewhere.'
          : undefined;

        routes.push({
          method,
          path,
          file: rel,
          line: lineNum,
          hasAuth: authObservation !== 'not_observed',
          authObservation,
          authEvidence,
          hasValidation:
            validationEvidence.length > 0
            || /\bzod\b|\bvalidate\b|\bschema\b|\bparse\b|\bpydantic\b|\bBaseModel\b/i.test(surroundingLines),
          provenance: classifyProvenance(rel),
          notes,
        });
      }
      sweep.regex.lastIndex = 0;
    }
  }, {
    ...options,
    searchRoots: options.routeRoots ?? options.searchRoots ?? options.includePaths,
  });

  return routes;
}

// ---------------------------------------------------------------------------
// Auth extraction
// ---------------------------------------------------------------------------

async function extractAuth(root: string, options: ScanOptions): Promise<AuthSurface[]> {
  const surfaces: AuthSurface[] = [];
  const authPatterns = [
    { pattern: /middleware.*auth/i, mechanism: 'auth middleware' },
    { pattern: /requireAuth|isAuthenticated|authGuard|requireScope|requireAdmin|authorize/i, mechanism: 'auth guard' },
    { pattern: /jwt\.verify|verifyToken/i, mechanism: 'JWT verification' },
    { pattern: /bcrypt|argon2|scrypt/i, mechanism: 'password hashing' },
    { pattern: /session\.(get|set|destroy)/i, mechanism: 'session management' },
    // Python / FastAPI equivalents
    { pattern: /Depends\s*\(|Security\s*\(/, mechanism: 'FastAPI dependency injection' },
    { pattern: /OAuth2PasswordBearer|HTTPBearer|OAuth2AuthorizationCodeBearer/, mechanism: 'FastAPI bearer auth scheme' },
    { pattern: /get_current_user|current_user/, mechanism: 'current-user resolver' },
    { pattern: /jwt\.decode|PyJWT|pyjwt/, mechanism: 'PyJWT verification' },
    { pattern: /passlib|bcrypt\.hashpw|argon2\.PasswordHasher/, mechanism: 'password hashing (python)' },
    { pattern: /verify_password|verify_token/, mechanism: 'token/password verification' },
    // Go equivalents
    { pattern: /RequireAuth|AuthMiddleware|JWTMiddleware|BearerAuth|BasicAuth|SessionMiddleware|CheckAuth|Authorize/, mechanism: 'Go auth middleware' },
    { pattern: /jwt\.Parse|jwt\.Verify|jwt\.ParseWithClaims/, mechanism: 'Go JWT verification' },
    { pattern: /bcrypt\.Compare|bcrypt\.GenerateFromPassword/, mechanism: 'Go bcrypt password hashing' },
    { pattern: /sessions\.Get|sessions\.Store|sessions\.Save/, mechanism: 'Go session management' },
    { pattern: /gin\.BasicAuth|echo\.BasicAuth|chi\.BasicAuth/, mechanism: 'Go framework basic auth' },
    { pattern: /r\.Use\s*\(|app\.Use\s*\(|e\.Use\s*\(/, mechanism: 'Go router-level middleware' },
  ];

  await searchFiles(root, SOURCE_FILE_REGEX, async (file, content) => {
    const rel = relative(root, file);
    if (rel.includes('.test.') || rel.includes('node_modules')) return;
    if (rel.includes('/tests/') || rel.startsWith('tests/')) return;

    for (const { pattern, mechanism } of authPatterns) {
      const match = pattern.exec(content);
      if (match) {
        const line = content.substring(0, match.index).split('\n').length;
        surfaces.push({ type: 'middleware', file: rel, line, mechanism, provenance: classifyProvenance(rel) });
      }
      pattern.lastIndex = 0;
    }
  }, options);

  return surfaces;
}

// ---------------------------------------------------------------------------
// Config extraction
// ---------------------------------------------------------------------------

async function extractConfig(root: string, options: ScanOptions): Promise<ConfigSurface[]> {
  const surfaces: ConfigSurface[] = [];
  const sensitivePatterns = /api.?key|secret|password|token|credential|private.?key/gi;

  const configFiles = ['.env', '.env.example', '.env.local', 'config.json', 'config.yaml'];
  for (const cf of configFiles) {
    try {
      const content = await readFile(resolve(root, cf), 'utf8');
      const keys: string[] = [];
      let match;
      while ((match = sensitivePatterns.exec(content)) !== null) {
        keys.push(match[0]);
      }
      sensitivePatterns.lastIndex = 0;

      const rel = relative(root, resolve(root, cf));
      if (shouldExcludePath(rel, options)) {
        continue;
      }
      if (keys.length > 0) {
        surfaces.push({
          file: cf,
          kind: cf.endsWith('.json') ? 'json' : cf.endsWith('.yaml') || cf.endsWith('.yml') ? 'yaml' : 'env',
          sensitiveKeys: [...new Set(keys)],
          provenance: classifyProvenance(cf),
        });
      }
    } catch {
      // File doesn't exist
    }
  }

  return surfaces;
}

// ---------------------------------------------------------------------------
// Persistence extraction
// ---------------------------------------------------------------------------

async function extractPersistence(root: string, options: ScanOptions): Promise<PersistenceSurface[]> {
  const surfaces: PersistenceSurface[] = [];

  // Check for Prisma schema
  await searchFiles(root, /schema\.prisma$/, async (file, content) => {
    const models = (content.match(/model\s+(\w+)/g) ?? []).map((m) => m.replace('model ', ''));
    const rel = relative(root, file);
    surfaces.push({
      type: 'prisma',
      file: rel,
      models,
      hasRawQueries: false,
      provenance: classifyProvenance(rel),
    });
  }, options);

  // Check for raw SQL queries. Node patterns (Prisma / generic query APIs),
  // Python patterns (SQLAlchemy `text(...)`, DB-API `cursor.execute`,
  // raw `%s`-interpolated SQL), and Go patterns (database/sql, sqlx, gorm).
  await searchFiles(root, SOURCE_FILE_REGEX, async (file, content) => {
    const rel = relative(root, file);
    if (rel.includes('.test.') || rel.includes('node_modules')) return;
    if (rel.includes('/tests/') || rel.startsWith('tests/')) return;
    if (rel.endsWith('_test.go')) return;

    const isPython = rel.endsWith('.py') || rel.endsWith('.pyi');
    const isGo = rel.endsWith('.go');
    const nodeHit = /\$queryRaw|\$executeRaw|\.query\s*\(|\.raw\s*\(/i.test(content);
    const pythonHit =
      isPython
      && (/\bcursor\.execute\s*\(/i.test(content)
        || /\bsession\.execute\s*\(/i.test(content)
        || /\bsqlalchemy\.text\s*\(|\s+text\s*\(\s*f?['"]/i.test(content)
        || /\braw_sql\b/i.test(content));
    // Go raw SQL: database/sql `db.Query(...)` / `db.Exec(...)`, sqlx's
    // `db.Queryx(...)` / `db.Select(...)`, gorm's `db.Raw(...)`. Backtick
    // strings are the Go convention for multi-line SQL literals.
    const goHit =
      isGo
      && (/\bdb\.Query(?:Context|Row|Rowx|x)?\s*\(/.test(content)
        || /\bdb\.Exec(?:Context)?\s*\(/.test(content)
        || /\bdb\.Raw\s*\(/.test(content)
        || /\bdb\.Select\s*\(/.test(content)
        || /\bdb\.Get\s*\(/.test(content)
        || /`\s*(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\s/i.test(content));

    if (nodeHit || pythonHit || goHit) {
      surfaces.push({
        type: 'sql',
        file: rel,
        hasRawQueries: true,
        provenance: classifyProvenance(rel),
        notes: 'raw query detected',
      });
    }
  }, options);

  return surfaces;
}

// ---------------------------------------------------------------------------
// Public surface extraction
// ---------------------------------------------------------------------------

async function extractPublicSurfaces(root: string, options: ScanOptions): Promise<PublicSurface[]> {
  const surfaces: PublicSurface[] = [];

  // Check for public/static directories
  for (const dir of ['public', 'static', 'assets']) {
    try {
      await stat(resolve(root, dir));
      if (shouldExcludePath(dir, options)) {
        continue;
      }
      surfaces.push({ type: 'static', path: `/${dir}`, file: dir, tier: 'public', provenance: classifyProvenance(dir) });
    } catch {
      // Doesn't exist
    }
  }

  // Check for export/proof endpoints
  await searchFiles(root, SOURCE_FILE_REGEX, async (file, content) => {
    const rel = relative(root, file);
    if (rel.includes('.test.') || rel.includes('node_modules')) return;
    if (rel.includes('/tests/') || rel.startsWith('tests/')) return;

    if (/export|proof|public.*api|webhook/i.test(rel) || /\/public\//i.test(content)) {
      surfaces.push({ type: 'api', path: rel, file: rel, tier: 'public', provenance: classifyProvenance(rel) });
    }
  }, options);

  return surfaces;
}

// ---------------------------------------------------------------------------
// Dependency extraction
// ---------------------------------------------------------------------------

async function extractDependencies(root: string): Promise<DependencySurface[]> {
  const surfaces: DependencySurface[] = [];

  let pkg: Record<string, unknown> | null = null;
  try {
    pkg = JSON.parse(await readFile(resolve(root, 'package.json'), 'utf8')) as Record<string, unknown>;
  } catch {
    return surfaces;
  }

  const directDeps = {
    ...readDependencyMap(pkg['dependencies']),
    ...readDependencyMap(pkg['devDependencies']),
  };

  for (const [name, version] of Object.entries(directDeps)) {
    const riskIndicators = collectVersionIndicators(version);
    let hasInstallScript = false;

    try {
      const depPkgPath = resolve(root, 'node_modules', name, 'package.json');
      const depPkg = JSON.parse(await readFile(depPkgPath, 'utf8')) as { scripts?: Record<string, string> };
      const scriptIndicators = collectInstallScriptIndicators(depPkg.scripts ?? {});
      hasInstallScript = scriptIndicators.length > 0;
      riskIndicators.push(...scriptIndicators);
    } catch {
      // Dependency may not be installed locally. Keep the direct-dependency record anyway.
    }

    surfaces.push({
      name,
      version,
      hasInstallScript,
      isDirectDependency: true,
      riskIndicators: [...new Set(riskIndicators)],
    });
  }

  const rootScriptIndicators = collectInstallScriptIndicators(
    typeof pkg['scripts'] === 'object' && pkg['scripts'] !== null
      ? (pkg['scripts'] as Record<string, string>)
      : {},
  );
  if (rootScriptIndicators.length > 0) {
    surfaces.push({
      name: '(root package)',
      version: String(pkg['version'] ?? 'workspace'),
      hasInstallScript: true,
      isDirectDependency: true,
      riskIndicators: [...new Set(rootScriptIndicators)],
    });
  }

  const lockfileSelection = await detectLockfile(root);
  const lockfileIndicators = await collectLockfileIndicators(root);
  if (lockfileIndicators.length > 0) {
    surfaces.push({
      name: `(lockfile${lockfileSelection.lockfileName ? `:${lockfileSelection.lockfileName}` : ''})`,
      version: lockfileSelection.packageManager,
      hasInstallScript: false,
      isDirectDependency: false,
      riskIndicators: [...new Set(lockfileIndicators)],
    });
  }

  return surfaces;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function searchFiles(
  root: string,
  filePattern: RegExp,
  callback: (file: string, content: string) => Promise<void>,
  options: ScanOptions = {},
  maxDepth: number = 5,
): Promise<void> {
  const roots = resolveScanRoots(root, options.searchRoots ?? options.includePaths);
  const maxFiles = options.maxFiles ?? Number.POSITIVE_INFINITY;
  let visitedFiles = 0;

  async function walk(dir: string, depth: number): Promise<void> {
    if (depth > maxDepth || visitedFiles >= maxFiles) return;
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch { return; }

    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (shouldSkipEntry(entry.name, full, root, options)) continue;
      if (entry.name.endsWith('.d.ts') || entry.name.endsWith('.map')) continue;

      if (entry.isDirectory()) {
        await walk(full, depth + 1);
      } else if (filePattern.test(entry.name)) {
        visitedFiles++;
        try {
          const content = await readFile(full, 'utf8');
          await callback(full, content);
        } catch {
          // Skip unreadable files
        }
      }
    }
  }

  for (const scanRoot of roots) {
    await walk(scanRoot, 0);
  }
}

// ---------------------------------------------------------------------------
// Compact summary for model context
// ---------------------------------------------------------------------------

export function summarizeForModel(map: TargetSurfaceMap, maxRoutes: number = 100): string {
  // Prioritise routes without local auth markers (highest security interest)
  const unauthRoutes = map.routes
    .filter((r) => r.authObservation === 'not_observed')
    .sort((left, right) => provenanceWeight(right.provenance) - provenanceWeight(left.provenance));
  const authRoutes = map.routes
    .filter((r) => r.authObservation !== 'not_observed')
    .sort((left, right) => provenanceWeight(right.provenance) - provenanceWeight(left.provenance));
  const prioritised = [...unauthRoutes, ...authRoutes].slice(0, maxRoutes);
  const handlerLocalRoutes = map.routes.filter((route) => route.authObservation === 'handler_local').length;
  const fileMiddlewareRoutes = map.routes.filter((route) => route.authObservation === 'file_middleware').length;
  const noLocalAuthRoutes = map.routes.filter((route) => route.authObservation === 'not_observed').length;

  const lines: string[] = [
    `# Target Surface Map: ${map.targetId}`,
    `Scanned: ${map.scannedAt}`,
    `Stack: ${map.stack.runtime}/${map.stack.framework} ORM=${map.stack.orm ?? 'none'} Frontend=${map.stack.frontend ?? 'none'}`,
    `Coverage: ${map.coverage}`,
    `Files: ${map.structure.sourceFiles} source, ${map.structure.testFiles} test, ${map.structure.configFiles} config`,
  ];

  if (map.coverage !== 'full') {
    if (map.detectedStack) {
      lines.push(`Detected stack: ${map.detectedStack.language}/${map.detectedStack.framework} (manifests: ${map.detectedStack.manifestFiles.join(', ')})`);
    }
    lines.push(`Supported probe kinds: ${map.supportedProbeKinds.length > 0 ? map.supportedProbeKinds.join(', ') : 'none'}`);
    if (map.coverage === 'partial') {
      lines.push('Note: this is a non-Node target with no framework-level surface extraction. Dependency scanning and code reading are supported; route extraction is not available for this stack.');
    } else if (map.coverage === 'manifest-only') {
      lines.push('Note: manifest files were detected but no dependencies could be parsed. Only manifest presence is known.');
    } else if (map.coverage === 'none') {
      lines.push('Note: no recognizable stack or manifest files were found. The scanner cannot extract meaningful surface data from this target.');
    }
  }

  if (map.stack.framework === 'fastify') {
    lines.push(
      'Framework note: Fastify parent hooks usually apply to routes registered via app.register(...). Treat plugin-based auth bypass as unconfirmed unless the code shows a separate Fastify instance or disabled/inconsistent hook mounting.',
    );
  }

  lines.push(
    '',
    `## Routes (${map.routes.length} total, ${noLocalAuthRoutes} without local auth markers, ${fileMiddlewareRoutes} with file-level middleware, ${handlerLocalRoutes} with handler-local auth, showing top ${prioritised.length})`,
    'Auth observation is static and local-only: not_observed is a lead, not proof of public exposure.',
    ...prioritised.map((r) => {
      const authDetail = r.authEvidence.length > 0 ? ` authEvidence=${r.authEvidence.join('|')}` : '';
      return `${r.method} ${r.path} [${r.file}:${r.line ?? '?'}] auth=${r.authObservation} validation=${r.hasValidation} provenance=${r.provenance}${authDetail}`;
    }),
  );

  if (map.routes.length > maxRoutes) {
    lines.push(`... and ${map.routes.length - maxRoutes} more routes`);
  }

  lines.push(
    '',
    '## Auth Surfaces',
    ...map.auth.slice(0, 30).map((a) => `${a.mechanism} [${a.file}:${a.line ?? '?'}] provenance=${a.provenance}`),
    '',
    '## Config (Sensitive Keys)',
    ...map.config.slice(0, 20).map((c) => `${c.file}: ${c.sensitiveKeys.join(', ')} provenance=${c.provenance}`),
    '',
    `## Persistence (${map.persistence.length} total)`,
    ...map.persistence.filter((p) => p.hasRawQueries).map((p) => `[RAW QUERY] ${p.type} [${p.file}] provenance=${p.provenance} ${p.notes ?? ''}`),
    ...map.persistence.filter((p) => !p.hasRawQueries).slice(0, 20).map((p) => `${p.type} [${p.file}] provenance=${p.provenance} ${p.notes ?? ''}`),
    '',
    '## Public Surfaces',
    ...map.publicSurfaces.slice(0, 20).map((p) => `${p.type} ${p.path} tier=${p.tier ?? 'unknown'} provenance=${p.provenance}`),
    '',
    '## Dependency Risks',
    ...(map.dependencies.filter((d) => d.riskIndicators.length > 0).length > 0
      ? map.dependencies.filter((d) => d.riskIndicators.length > 0).slice(0, 20).map((d) =>
          `${d.name}@${d.version} direct=${d.isDirectDependency} installScript=${d.hasInstallScript} indicators=${d.riskIndicators.join(', ')}`,
        )
      : ['No dependency risks detected.']),
    '',
    '## Directory Structure',
    ...map.structure.directories.slice(0, 30).map((d) => `  ${d}/`),
  );

  return lines.join('\n');
}

function resolveScanRoots(root: string, roots?: string[]): string[] {
  if (!roots || roots.length === 0) {
    return [root];
  }

  return roots.map((entry) => resolve(root, entry));
}

function extractRouteSnippet(content: string, startIndex: number): string {
  const slice = content.slice(startIndex, Math.min(content.length, startIndex + 500));
  const closing = slice.indexOf(');');
  return closing >= 0 ? slice.slice(0, closing + 2) : slice;
}

function extractFileAuthMarkers(content: string): FileAuthMarker[] {
  const markers: FileAuthMarker[] = [];
  const usePattern = /(\w+)\.use\s*\(([\s\S]{0,320}?)\)\s*;?/g;

  let match;
  while ((match = usePattern.exec(content)) !== null) {
    const routerVar = match[1]!;
    const args = match[2]!;
    const evidence = collectHintMatches(args, AUTH_HINT_PATTERN);
    if (evidence.length === 0) {
      continue;
    }

    const line = content.substring(0, match.index).split('\n').length;
    const pathMatch = args.match(/^\s*['"`]([^'"`]+)['"`]\s*,/);
    markers.push({
      routerVar,
      line,
      pathPrefix: pathMatch?.[1],
      evidence,
    });
  }
  usePattern.lastIndex = 0;

  return markers;
}

function routeMatchesPrefix(routePath: string, prefix?: string): boolean {
  if (!prefix || prefix === '/') {
    return true;
  }

  const normalizedRoute = normalizePathSegment(routePath);
  const normalizedPrefix = normalizePathSegment(prefix);
  return normalizedRoute === normalizedPrefix || normalizedRoute.startsWith(`${normalizedPrefix}/`);
}

function normalizePathSegment(value: string): string {
  const normalized = value.trim().replace(/\/+/g, '/');
  if (!normalized.startsWith('/')) {
    return `/${normalized}`;
  }
  return normalized.endsWith('/') && normalized !== '/' ? normalized.slice(0, -1) : normalized;
}

function collectHintMatches(text: string, pattern: RegExp): string[] {
  const matches = new Set<string>();
  let match;
  while ((match = pattern.exec(text)) !== null) {
    matches.add(match[1]?.toString() ?? match[0]!.toString());
  }
  pattern.lastIndex = 0;
  return [...matches];
}

function shouldSkipEntry(entryName: string, fullPath: string, root: string, options: ScanOptions): boolean {
  if (EXCLUDED_DIRS.has(entryName)) {
    return true;
  }
  const rel = relative(root, fullPath).replace(/\\/g, '/');
  return shouldExcludePath(rel, options);
}

function shouldExcludePath(relativePath: string, options: ScanOptions): boolean {
  const normalized = relativePath.replace(/\\/g, '/').replace(/^\.?\//, '');
  if (!normalized) {
    return false;
  }

  return (options.excludePaths ?? []).some((excluded) => {
    const candidate = excluded.replace(/\\/g, '/').replace(/^\.?\//, '').replace(/\/+$/, '');
    return normalized === candidate || normalized.startsWith(`${candidate}/`);
  });
}

function classifyProvenance(relativePath: string): SurfaceProvenance {
  const normalized = relativePath.replace(/\\/g, '/').toLowerCase();

  if (
    normalized.includes('/.next/')
    || normalized.includes('/coverage/')
    || normalized.includes('/playwright-report/')
    || normalized.includes('/storybook-static/')
    || normalized.includes('/dist/')
    || normalized.includes('/build/')
    || normalized.endsWith('.d.ts')
    || normalized.endsWith('.map')
  ) {
    return 'generated';
  }
  if (normalized.includes('/docs/') || normalized.includes('/plans/') || normalized.endsWith('.md')) {
    return 'docs';
  }
  if (
    normalized.includes('__tests__/')
    || normalized.includes('/fixtures/')
    || normalized.includes('.test.')
    || normalized.includes('.spec.')
  ) {
    return 'test';
  }
  if (normalized.includes('node_modules/')) {
    return 'third_party';
  }
  return 'first_party';
}

function provenanceWeight(provenance: SurfaceProvenance): number {
  switch (provenance) {
    case 'first_party': return 5;
    case 'third_party': return 3;
    case 'test': return 2;
    case 'docs': return 1;
    case 'generated': return 0;
    default: return 0;
  }
}

function readDependencyMap(value: unknown): Record<string, string> {
  if (!value || typeof value !== 'object') {
    return {};
  }

  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([name, version]) => [name, String(version)]),
  );
}

function collectVersionIndicators(version: string): string[] {
  const indicators: string[] = [];

  if (/^(file:|link:|workspace:)/.test(version)) indicators.push('non-registry-source');
  if (/^(git\+|github:|https?:\/\/)/.test(version)) indicators.push('remote-source');
  if (version === 'latest' || version === '*') indicators.push('floating-version');
  if (/^[~^]/.test(version)) indicators.push('semver-range');

  return indicators;
}

function collectInstallScriptIndicators(scripts: Record<string, string>): string[] {
  const indicators: string[] = [];
  const riskyScriptNames = ['preinstall', 'install', 'postinstall', 'prepare'];
  const riskyPatterns = [/curl\s+/i, /wget\s+/i, /child_process/i, /eval\(/i, /\$\(/, /`[^`]*`/];

  for (const name of riskyScriptNames) {
    const script = scripts[name];
    if (!script) continue;
    indicators.push(`install-script:${name}`);
    for (const pattern of riskyPatterns) {
      if (pattern.test(script)) {
        indicators.push(`install-script-pattern:${pattern.source}`);
      }
    }
  }

  return indicators;
}

async function collectLockfileIndicators(root: string): Promise<string[]> {
  const { selection, content } = await readSelectedLockfile(root);
  if (!content) {
    return [];
  }
  return collectIndicatorsFromLockfile(content, selection);
}
