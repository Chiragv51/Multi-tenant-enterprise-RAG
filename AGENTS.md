# AGENTS.md — Engineering Guidelines for AI Agents & Developers

This document serves as the single source of truth for AI agents (Claude Code, Cursor, Antigravity, etc.) and human developers working on the **Multi-Tenant Enterprise Knowledge Search (RAG) Platform** for **MedInsure Labs**.

Every instruction here is binding. Any PR or code change violating these principles will be rejected.

---

## 1. Project Overview & Architecture Stack

We are building a production-grade B2B SaaS Multi-Tenant RAG platform where enterprise clients (hospitals, insurance providers) query sensitive SOPs, policies, and claim guidelines.

### Tech Stack
- **Language & Runtime:** Python 3.11+
- **API Framework:** FastAPI (async endpoints, Pydantic v2 validation, SSE streaming)
- **Vector Database & Primary DB:** PostgreSQL 16 + `pgvector` (Row-Level Security, relational metadata, BM25 full-text search)
- **Cache & Rate Limiting:** Redis 7+ (per-tenant caching, token bucket rate limiter)
- **Object Storage:** MinIO (S3-compatible storage for raw documents)
- **Job Queue / Worker:** Celery / RQ (asynchronous background ingestion)
- **Database Migrations:** Alembic
- **Testing:** pytest, pytest-asyncio, testcontainers (or isolated Docker DB)
- **Observability:** OpenTelemetry, Langfuse (LLM traces), Prometheus, Grafana
- **Formatting & Linting:** `ruff`, `black`

---

## 2. Directory Structure & Responsibilities

```
rag-platform/
├── AGENTS.md                 # This file: engineering principles & standards
├── README.md                 # Project description & progress status
├── docker-compose.yml        # Orchestration (api, postgres, redis, minio)
├── pyproject.toml            # Dependencies and tool configurations
├── .env.example              # Template for environment variables
├── app/
│   ├── __init__.py
│   ├── api/                  # Routes & controllers (/v1/auth, /v1/documents, /v1/ask, etc.)
│   ├── core/                 # Config (pydantic-settings), security (JWT), tenant context middleware, errors
│   ├── db/                   # SQLAlchemy/SQLModel models, session factory, Alembic migrations, RLS scripts
│   ├── ingestion/            # File parsers (PDF/DOCX/MD), chunking, embedding generation, background worker
│   ├── retrieval/            # Hybrid search (vector + BM25), RRF fusion, cross-encoder reranker, prompt builder
│   └── observability/        # Structured logging, OpenTelemetry / Langfuse instrumentation, metrics
├── tests/
│   ├── security/             # Strict tenant isolation tests, ACL verification, cache leak tests
│   └── integration/          # E2E API flows, ingestion pipeline verification
├── data/                     # Local test datasets & synthetic tenant documents (gitignored)
├── eval/                     # Golden evaluation dataset (golden_set.jsonl), ablation scripts
├── docs/                     # Architectural decision records (ADRs), API specs, diagrams
└── infra/
    └── postgres/             # Database initialization scripts (pgvector extension, RLS helper functions)
```

---

## 3. Non-Negotiable Core Rules (નિયમો)

1. **Zero Cross-Tenant Leakage (100% Tenant Isolation):**
   - **No query may run without a `tenant_id` filter.**
   - Both application-level filtering and database Row-Level Security (RLS) must be used (Defense in Depth).
   - If a tenant context is missing from an authenticated request, immediately abort with HTTP 403/401.

2. **Security & Secret Management:**
   - Secrets (passwords, JWT secrets, LLM API keys) must **only** reside in `.env`.
   - Never commit `.env` or credential files to Git. Check `git status` before committing.
   - API keys stored in the database must be cryptographically hashed (e.g., SHA-256 / bcrypt), never stored in plaintext.

3. **Log Sanitization & PII Protection:**
   - **Never log raw document text, employee questions, or Personal Identifiable Information (PII).**
   - Logs must be structured JSON containing only metadata: `request_id`, `tenant_id`, `user_id`, endpoint, status code, latency (ms), token count.

4. **Strict Ticket Boundaries (No Scope Creep):**
   - Only execute work explicitly requested in the assigned ticket (T1 to T21).
   - Do not refactor unrelated modules or add unrequested "bonus" features.

5. **Dependency Discipline:**
   - Before adding any new dependency to `pyproject.toml` or `requirements.txt`, document the rationale, trade-offs, and why existing libraries cannot accomplish the task.

6. **Prompt Injection Hardening:**
   - Treat all retrieved document chunks as **untrusted data**, never as system instructions.
   - System prompts must explicitly instruct the LLM to ignore instructions embedded inside document context.

7. **ACL Query-Time Filtering:**
   - Access Control Lists (ACLs) must be evaluated **inside the database query itself** (`WHERE ... AND (acl_user = user_id OR acl_group IN (groups))`).
   - Never retrieve chunks into memory and then filter them in Python.

---

## 4. API & Coding Standards

### Standard Error Response Format
All API error responses must adhere strictly to this schema:
```json
{
  "error": {
    "code": "TENANT_NOT_FOUND",
    "message": "Tenant with ID 'tenant-123' does not exist.",
    "request_id": "c56a4180-65aa-42ec-a945-5fd21dec0538"
  }
}
```

### Request Context & Tracing
- Every HTTP request must be tagged with a unique `request_id` (via middleware).
- The `request_id` must be propagated across logs, downstream client responses, and OpenTelemetry spans.

### Code Style
- **Python Version:** 3.11+
- **Type Annotations:** 100% type hints on all function arguments and return values.
- **Data Validation:** Pydantic v2 schemas for all inputs and outputs.
- **Asynchronous Execution:** Async I/O for database queries, external API calls, and streaming responses.
- **Tooling:** Enforce `ruff check .` and `black --check .` before committing.

---

## 5. Git & PR Workflow

- **Main Branch Protection:** Direct commits to `main` are prohibited. All code merges via Pull Requests.
- **Branch Naming:** `feature/<ticket-id>-<short-description>` (e.g., `feature/T1-foundation`).
- **Commit Messages:** Conventional Commits (`feat: ...`, `fix: ...`, `test: ...`, `chore: ...`).
- **PR Review Checklist:**
  - [ ] Does every database query have a `tenant_id` filter?
  - [ ] Are isolation tests included and passing?
  - [ ] Are all secrets isolated in `.env`?
  - [ ] Are logs free of raw text/PII?
  - [ ] Is error handling conforming to `{"error": {"code", "message", "request_id"}}`?

