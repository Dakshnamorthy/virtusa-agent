# CIDAN — Regulatory Circular to Live Rule Engine

CIDAN is a locally run, backend-only regulatory document analysis prototype. It reads
source PDFs, indexes text in local ChromaDB, uses five LangChain structured-output
agents coordinated by LangGraph, and executes only validated declarative rules in a
restricted local sandbox.

**The loan approval circular in this project is synthetic demo material. Its ₹80,000
threshold and illustrative effective date are fictional, not official RBI
requirements.** The application does not establish legal compliance, provide legal
advice, access banking systems, or deploy rules. A rule remains a draft until it has
passing tests and a human records local approval.

## Source PDFs

The workspace already includes the two demonstration PDFs in `cidan/data/`. The
ingestion discovery also checks `data/source_pdfs/`, `data/`, and the project root.
For a clean new checkout, put exactly these two supplied demo PDFs in
`data/source_pdfs/`:

- Synthetic bank rules and policies handbook
- Synthetic RBI-style loan approval circular

Do not use a real regulatory document as a substitute for the synthetic circular.
PDFs must be text-readable (not image-only scans), and each file must be at most 25 MB.
If discovery does not find exactly one handbook and one circular, `/documents` and the
CLI report where to place or rename them. The existing file names are recognized.

## Requirements and setup (Windows PowerShell)

Use Python 3.11 or 3.12. From the project root:

```powershell
# Use py -3.11 instead if Python 3.12 is not installed.
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python --version
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if (!(Test-Path .env)) { Copy-Item .env.example .env }
```

If PowerShell prevents virtual-environment activation, enable it only for the current
terminal:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Set your Groq API key without putting it in source code or printing it. This updates
the existing `.env`, removes obsolete OpenAI settings, and selects Groq/local-embedding
defaults:

```powershell
$secret = Read-Host "Groq API key" -AsSecureString
$groqKey = [System.Net.NetworkCredential]::new("", $secret).Password
$lines = @(Get-Content .env | Where-Object {
    $_ -notmatch '^(OPENAI_API_KEY|GROQ_API_KEY|LLM_MODEL|EMBEDDING_MODEL)='
})
$lines += "GROQ_API_KEY=$groqKey"
$lines += "LLM_MODEL=qwen/qwen3.8-27b"
$lines += "EMBEDDING_MODEL=BAAI/bge-small-en-v1.5"
$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllLines((Join-Path (Get-Location) ".env"), $lines, $utf8NoBom)
Remove-Variable groqKey, secret
```

`.env` is git-ignored. The reasoning agents use Groq through `langchain-groq`; the
default chat model is `qwen/qwen3.8-27b`. Chroma embeddings are generated locally
with FastEmbed (`BAAI/bge-small-en-v1.5`), so no OpenAI key or embedding service is
used. FastEmbed downloads its model the first time it runs, so initial ingestion needs
internet access; later runs use its local cache. `/health` confirms whether a Groq key
is configured, but a real request is needed to verify that the key is valid.

## Ingest, run, and inspect

```powershell
# Inspect the locally discovered source file names and page counts.
python -c "from cidan.ingestion.pdf_loader import find_pdfs, load_pdf; print([(p.name, len(load_pdf(p))) for p in find_pdfs()])"

# Build/update the local persistent Chroma index (the initial run downloads the
# FastEmbed model locally).
python -c "from cidan.ingestion.vector_store import ingest; print(ingest())"

# Run all agents and save workflow state plus JSON/Markdown reports.
python run_workflow.py
```

Re-running ingestion replaces prior chunks for each source filename, and stable chunk
IDs prevent duplicates. The persistent vector index is under `storage/chroma/`.
Workflow state and local audit events are saved under `outputs/`; reports are under
`outputs/reports/<workflow-id>/`.

To start the API:

```powershell
uvicorn cidan.api:app --host 127.0.0.1 --port 8000 --reload
```

Open Swagger at <http://127.0.0.1:8000/docs>. Main endpoints:

- `GET /health` — Groq configuration and local embedding-provider status; never the key.
- `GET /documents` — detected source PDFs and metadata.
- `POST /ingest` — parse, chunk, embed, and index the PDFs.
- `POST /workflows/analyze` — run all five agents and persist the results.
- `GET /workflows`, `GET /workflows/{workflow_id}` — prior workflow state.
- `GET /workflows/{workflow_id}/report` and `/report/markdown` — saved report.
- `GET /rules` and `GET /rules/{rule_id}` — proposal status and evidence.
- `POST /rules/{rule_id}/approve` — requires a reviewer identifier and successful tests.
- `POST /rules/{rule_id}/export-preview` — requires explicit local approval.

When the server is running, `Invoke-RestMethod http://127.0.0.1:8000/health` reports
configuration state without returning the key. `Invoke-RestMethod
http://127.0.0.1:8000/documents` reports source discovery and index freshness.

Approval is only a local prototype record. Export is a preview package and never
connects to a production rule engine or any banking service. Approval and export
preview events are appended to `outputs/audit.jsonl`.

## Tests

Unit tests use the real PDFs where helpful but do not call paid LLM or embedding APIs.
LLM responses are replaced by local test doubles only when a test specifically checks
agent behavior. The optional real-service test is skipped unless explicitly enabled.

```powershell
python -m pytest -q
```

Run the optional integration test after configuring `.env` and indexing the PDFs:

```powershell
$env:CIDAN_RUN_LLM_INTEGRATION = "1"
python -m pytest -q tests\test_llm_integration.py
Remove-Item Env:CIDAN_RUN_LLM_INTEGRATION
```

## Troubleshooting

- **No PDFs / wrong count:** place the two synthetic PDFs in `data/source_pdfs/`, or
  retain the supplied copies in `cidan/data/`. Filenames should identify a handbook
  (`policy`, `handbook`, or `rules`) and circular (`circular`, `regulatory`, or `rbi`).
- **Missing Groq API key:** check `GROQ_API_KEY` in `.env` locally; `/health` explains
  configuration state. CIDAN does not use OpenAI; never paste a key into source code
  or an issue tracker.
- **Package conflicts:** use a fresh Python 3.11/3.12 virtual environment and install
  the pinned-compatible ranges from `requirements.txt`.
- **PDF extraction yields no text:** use a text-readable PDF; image-only scans need
  OCR, which is intentionally not enabled because OCR could introduce unsupported
  source text. The parser logs the affected filename and page.
- **Embedding failure:** verify first-run network access and that the configured
  FastEmbed model can be downloaded. Embeddings are local and use no paid embedding
  API. Re-run `POST /ingest` after fixing it.
- **LLM timeout or response validation error:** check the model name, account access,
  network, and timeout; see local logs for stage-level diagnostics. A failed agent
  blocks downstream stages; CIDAN will not create a successful-looking report.

## Project layout

- `cidan/ingestion/` — safe PDF discovery, page extraction, chunking, Chroma storage,
  and cited retrieval.
- `cidan/agents/` — obligation extraction, semantic mapping, rule proposals, synthetic
  tests, and impact reporting.
- `cidan/workflow/` — typed LangGraph state, execution, and local persistence.
- `cidan/rule_engine.py` — allowlisted schema validation and deterministic interpreter.
- `cidan/services/` — workflow execution, approval and export preview controls.
- `cidan/api.py` — FastAPI service; no frontend.
- `tests/` — offline unit tests and opt-in LLM integration test.
