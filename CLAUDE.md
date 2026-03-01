# CLAUDE.md — Shadow AI Sentinel

## Project Overview

**Shadow AI Sentinel** is an enterprise Data Loss Prevention (DLP) solution for AI tools. It detects and blocks sensitive data (PII, API keys, source code, medical records) before it reaches AI services like ChatGPT, Claude, Gemini, etc. It also monitors "shadow AI" usage across organizations to identify unauthorized or risky AI tool access.

**Current Phase:** Phase 1 — Browser extension + regex-based scanning + local proxy service.

---

## Monorepo Structure

```
shadow-ai-sentinel/
├── apps/
│   ├── browser-extension/     # Chrome extension (TypeScript + Webpack)
│   ├── proxy-service/         # Go HTTP proxy (content scanning & LLM routing)
│   └── ml-service/            # Python ML classifier (PII via Presidio + spaCy)
├── packages/
│   ├── shared-types/          # Shared TypeScript interfaces and enums
│   ├── regex-patterns/        # PII/secret detection regex patterns + validators
│   └── ai-domain-registry/    # Database of 70+ AI services with risk metadata
├── infra/
│   ├── docker-compose.yml         # Local dev stack (Postgres + Redis)
│   ├── docker-compose.onprem.yml  # On-premise full stack
│   ├── .env.example               # Required environment variables
│   └── terraform/gcp/             # GCP infrastructure (Phase 2)
├── package.json       # Root npm workspace + Turbo scripts
├── turbo.json         # Turborepo pipeline configuration
└── tsconfig.json      # Root TypeScript config (ES2022, strict)
```

**Build orchestrator:** [Turborepo](https://turbo.build/). All packages and apps are managed as npm workspaces.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Browser Extension | TypeScript 5.5, Webpack 5, Chrome Manifest V3 |
| Proxy Service | Go 1.22, chi v5 router, pgx v5, go-redis v9, zap logging, JWT auth |
| ML Service | Python 3.11, FastAPI 0.115, Presidio 2.2, spaCy, ONNX Runtime, PyTorch 2.5 |
| Database | PostgreSQL 16 |
| Cache | Redis 7 |
| Testing | Vitest 2.1 (TypeScript), Go built-in testing |
| Infrastructure | Docker, docker-compose, Terraform (GCP) |

---

## Development Workflows

### Prerequisites

- Node.js 20+, npm
- Go 1.22+
- Python 3.11+
- Docker & docker-compose

### Initial Setup

```bash
npm install                       # Install all workspace dependencies
npm run docker:up                 # Start Postgres + Redis via docker-compose
cp infra/.env.example infra/.env  # Create local env file and fill in secrets
```

### Common Commands

```bash
npm run build        # Build all packages and apps (via Turbo)
npm run dev          # Start all services in watch/dev mode
npm run test         # Run all tests across workspaces
npm run lint         # TypeScript type-check all packages
npm run clean        # Remove all dist/ directories

npm run docker:up        # Start local Postgres + Redis
npm run docker:down      # Stop local services
npm run docker:onprem    # Start full on-premise stack (includes proxy + ML)
```

### Per-Service Development

**Browser Extension:**
```bash
cd apps/browser-extension
npm run build   # Webpack production build → dist/
npm run dev     # Webpack watch mode
```
Load the `dist/` folder as an unpacked extension in Chrome (`chrome://extensions`).

**Proxy Service:**
```bash
cd apps/proxy-service
go run ./src/main.go             # Development server
go build -o bin/proxy ./src/...  # Production binary
go test ./...                    # Run Go tests
```

**ML Service:**
```bash
cd apps/ml-service
pip install -r requirements.txt
python -m spacy download en_core_web_lg
uvicorn api.main:app --reload    # Development server on :8000
```

**Shared Packages:**
```bash
cd packages/shared-types    # or regex-patterns / ai-domain-registry
npm run build               # Compile TypeScript → dist/
npm run test                # Run Vitest tests (regex-patterns only)
```

---

## Architecture & Data Flow

### Phase 1 Flow (Current)

```
User types in ChatGPT/etc.
        ↓
Chrome Content Script (apps/browser-extension/src/content/index.ts)
        ↓ detects paste/input/upload events
regex-patterns package (packages/regex-patterns/src/index.ts)
        ↓ fast local scan (<5ms)
Background Service Worker (apps/browser-extension/src/background/index.ts)
        ↓ batches events, polls config
Local Proxy Service (apps/proxy-service/src/)
        ↓ policy engine → block / redact / warn / log
External LLM API (or on-prem Ollama)
```

### Detection Pipeline (Proxy Service)

1. **scanner/scanner.go** — orchestrates regex + (Phase 2) ML scanning
2. **policy/engine.go** — evaluates org policies against detections
3. **redactor/redactor.go** — redacts PII if action is `REDACT`
4. **router/llm_router.go** — routes to external LLMs or on-prem Ollama

---

## Package Details

### `packages/shared-types`

Central TypeScript type definitions used across all apps and packages. Key types:

- `Detection`, `ScanResult`, `SensitivityLevel` — scanning output contracts
- `PolicyRule`, `PolicyCondition` — policy configuration
- `AiToolEntry`, `AiToolRiskLevel` — AI service registry types
- `AuditEvent`, `ShadowAiEvent` — audit logging shapes
- `Organization`, `User`, `OrgSettings` — auth/org management
- `ProxyRequest`, `ProxyResponse`, `ExtensionConfig` — API contracts

> Always import shared types from this package. Do not redefine types locally.

### `packages/regex-patterns`

40+ regex patterns for PII and secret detection. Key exports:

- `PII_PATTERNS` — map of entity type → regex pattern
- `scanText(text: string): Detection[]` — runs all patterns, returns detections
- `redactText(text: string): string` — replaces detections with `[REDACTED_TYPE]` placeholders
- `luhnCheck(num: string): boolean` — validates credit card numbers (Luhn algorithm)
- `validateSSN(ssn: string): boolean` — validates SSN format
- `shannonEntropy(str: string): number` — used for API key/secret detection

Tests live in `packages/regex-patterns/src/index.test.ts` (Vitest).

### `packages/ai-domain-registry`

Database of 70+ AI services. Key exports:

- `AI_TOOL_REGISTRY: AiToolEntry[]` — full registry array
- `matchDomain(hostname: string): AiToolEntry | null` — looks up a domain
- `isAiApiEndpoint(url: string): boolean` — checks if URL is a known AI API
- `getDomainsByRisk(level: AiToolRiskLevel): AiToolEntry[]` — filter by risk

Risk levels: `SAFE` → `CAUTION` → `RISKY` → `BLOCKED`

---

## Key Conventions

### Naming Conventions

- **Service names:** `sentinel-{name}` (e.g., `sentinel-postgres`, `sentinel-redis`, `sentinel-proxy`)
- **Entity types / risk levels / policy actions:** `SCREAMING_SNAKE_CASE` (e.g., `CREDIT_CARD`, `HIGH`, `BLOCK`)
- **TypeScript files:** `camelCase.ts` in `src/`, compiled to `dist/`
- **Go files:** `snake_case.go` organized by feature directory under `src/`
- **Python files:** `snake_case.py` under `api/`

### Code Style

- **TypeScript:** Strict mode enabled (`"strict": true` in tsconfig). Use enums (not string unions) for constants defined in shared-types.
- **Go:** Follow standard Go formatting (`gofmt`). Use `zap` for structured logging—no `fmt.Println`.
- **Python:** Use type hints throughout. `dataclass` + `Enum` for data models. FastAPI dependency injection.
- **Comments:** Major sections use `// ====================` ASCII dividers. Each file has a header comment explaining its role.

### Environment & Secrets

- Never commit `.env` files—use `infra/.env.example` as the template.
- Never commit `*.pem`, `*.key`, or `service-account.json` files (all in `.gitignore`).
- Required secrets for local dev: `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `JWT_SECRET`.
- Optional API keys: `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GOOGLE_AI_KEY` (only needed for cloud proxy mode).

### Adding New AI Domains

Edit `packages/ai-domain-registry/src/index.ts`. Add an `AiToolEntry` object to the registry array with:
- `domain`, `name`, `category`
- `riskLevel`: one of `SAFE | CAUTION | RISKY | BLOCKED`
- `dataResidency`, `trainsOnUserData`, `soc2`, `hipaa`

### Adding New Detection Patterns

Edit `packages/regex-patterns/src/index.ts`. Add a new entry to `PII_PATTERNS` with:
- A key matching a `EntityType` from `shared-types`
- A compiled `RegExp` with the `gi` flags (case-insensitive, global)

Add corresponding tests in `packages/regex-patterns/src/index.test.ts`.

---

## Testing

### Running Tests

```bash
npm run test                         # All tests (Turbo)
cd packages/regex-patterns && npm test  # Unit tests for regex patterns
cd apps/proxy-service && go test ./...  # Go service tests
```

### Test Conventions

- TypeScript tests use **Vitest**. Test files are named `*.test.ts` co-located with source.
- Tests must cover both **true positives** (real PII detected) and **false positives** (dates not flagged as SSNs, etc.).
- Go tests use the standard `testing` package with table-driven tests.

---

## Infrastructure

### Local Development

`infra/docker-compose.yml` spins up:
- `sentinel-postgres` (PostgreSQL 16, port 5432)
- `sentinel-redis` (Redis 7, port 6379)

Phase 2 services (ml-service, proxy-service) and Phase 3 (dashboard) are commented out in docker-compose until ready.

### On-Premise Deployment

```bash
npm run docker:onprem
# Uses infra/docker-compose.onprem.yml
# Includes Ollama for local LLM inference (llama3.1:8b by default)
```

### Cloud Deployment (Phase 2)

Terraform configs in `infra/terraform/gcp/` provision GCP resources. Requires:
- `GCP_PROJECT_ID`, `GCP_REGION`, `GCP_SERVICE_ACCOUNT_KEY` in environment

---

## Development Phases Roadmap

| Phase | Status | Description |
|---|---|---|
| Phase 1 | **Current** | Browser extension + regex scanning + local proxy |
| Phase 2 | Planned | ML classifier service + cloud proxy + GCP infra |
| Phase 3 | Planned | Admin dashboard + webhook alerts (Slack/Teams) + SIEM integration |

Phase boundaries are marked in source code comments. Do not implement Phase 2+ features unless explicitly requested.

---

## Important Files Reference

| File | Purpose |
|---|---|
| `apps/browser-extension/src/content/index.ts` | Intercepts paste/input/upload on AI tool pages |
| `apps/browser-extension/src/background/index.ts` | Service worker: config polling, event batching |
| `apps/browser-extension/src/popup/index.ts` | Extension popup UI |
| `apps/browser-extension/manifest.json` | Chrome extension manifest (MV3) |
| `apps/proxy-service/src/main.go` | Proxy HTTP server entry point |
| `apps/proxy-service/src/scanner/scanner.go` | Orchestrates content scanning |
| `apps/proxy-service/src/policy/engine.go` | Policy evaluation (block/redact/warn/log) |
| `apps/proxy-service/src/redactor/redactor.go` | PII redaction logic |
| `apps/proxy-service/src/router/llm_router.go` | Routes requests to LLM backends |
| `apps/ml-service/api/main.py` | FastAPI app with `/api/v1/classify` endpoint |
| `apps/ml-service/api/classifier.py` | Presidio + spaCy NER integration |
| `packages/shared-types/src/index.ts` | All shared TypeScript types |
| `packages/regex-patterns/src/index.ts` | All PII/secret regex patterns |
| `packages/ai-domain-registry/src/index.ts` | AI service registry |
| `infra/docker-compose.yml` | Local dev infrastructure |
| `infra/.env.example` | Environment variable template |
