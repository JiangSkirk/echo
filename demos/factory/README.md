# Factory Documentation Demo

A complete, self-contained demonstration of how JS Agent manages real factory documentation — product specs, production workflows, and quality checklists — using its semantic memory and auto-fetch pipeline.

## What This Demo Shows

1. **Structured Document Ingestion** — Factory docs are chunked, embedded, and stored in the agent's semantic memory with source citations.
2. **Transparent Memory Retrieval** — When you ask about a product, the agent shows which document and section it retrieved the answer from.
3. **Editable Memory** — Users can view, edit, or delete stored facts in the desktop app, with full audit trails.
4. **Resilience** — Documents survive Host restarts, model disconnects, and task interruptions via checkpoint/resume.

## Files

| File | Description |
|------|-------------|
| `products/HL-2026-TShirt.md` | Product spec: fabric, sizes, colors, MOQ |
| `products/HL-2026-Hoodie.md` | Product spec: heavyweight hoodie line |
| `workflows/Cutting-SOP-v3.md` | Standard operating procedure for fabric cutting |
| `workflows/Sewing-Assembly-v2.md` | Sewing and assembly workflow |
| `quality/QC-Checklist-AQL-2.5.md` | Quality control checklist (AQL 2.5) |
| `ingest.py` | Script to load all docs into the agent's memory |

## Quick Start

```bash
# 1. Start the local Host (does not open a browser)
js appshell --no-browser

# 2. In another terminal, ingest the demo documents
cd demos/factory
python ingest.py

# 3. Open the JS Agent desktop app
# 4. Ask questions like:
#    "What is the fabric composition of HL-2026-TShirt?"
#    "What are the sewing tolerances?"
#    "Show me the QC checklist for AQL 2.5"
```

## How It Works

### 1. Chunking
Documents are split into ≤3000-token chunks with YAML frontmatter preserved:
```yaml
---
source: products/HL-2026-TShirt.md
section: Fabric Composition
category: product_spec
---
```

### 2. Embedding + Storage
Each chunk is embedded and stored in `semantic_memories` with:
- `key`: Document path + section title
- `value`: Chunk content
- `category`: `product_spec`, `workflow`, `quality_checklist`
- `source`: Full file path (shown in UI)
- `confidence`: 0.95 (high confidence for authoritative docs)

### 3. Retrieval
When you ask a question, the agent:
1. Embeds your query
2. Searches semantic memory for nearest neighbors
3. Injects top-5 relevant chunks into the prompt with `[source: ...]` citations
4. Shows the sources it used in the response

### 4. Transparency
In the desktop app **Memory** panel:
- Each memory shows its `source` file
- Click **Edit** to update a fact (e.g., new fabric blend)
- Click **Delete** to remove outdated specs
- All changes are logged in the **Audit** tab

## Extending the Demo

Add your own documents:
```bash
# Drop new .md files into products/, workflows/, or quality/
# Re-run ingest.py
python ingest.py
```

Or enable the **Auto-Fetch Pipeline** to watch a directory and auto-ingest:
```yaml
# ~/.config/js/config.yaml
pipeline:
  enabled: true
  poll_interval_minutes: 60
  token_limit: 3000
  vault_dir: ~/FactoryDocs
  sources:
    file:
      path: ./demos/factory
      patterns: ["**/*.md"]
```

## Production Readiness Checklist

This demo validates the following 9/10 product features:

- [x] **One-click install** — `python ingest.py` loads everything
- [x] **First-start wizard** — desktop app guides model setup on first visit
- [x] **Model switching** — Switch between local LM Studio models without restart
- [x] **Transparent memory** — Sources visible, editable, deletable
- [x] **Real documentation** — Actual factory SOPs, not toy examples
- [x] **Stability recovery** — WAL-mode SQLite, checkpoint resume, degraded mode
