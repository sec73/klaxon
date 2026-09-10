# System Architecture: Local Klaxon & Ollama Security Assistant

This document outlines the infrastructure, compliance structure, and data flow for a fully local, GDPR-compliant AI security assistant using Klaxon and Ollama.

---

## 1. Architectural Overview

The system is split into three decoupled, secure layers to ensure that Personally Identifiable Information (PII) never interacts with the Large Language Model (LLM) or the vector generation ecosystem.

```text
==========================================================================================
1. INGESTION AND COMPLIANCE LAYER (Real-time & Ingest-side)
==========================================================================================

 [ Unmasked Raw Data ] ──► (e.g., Wazuh / Syslogs containing real names, IPs, emails)
           │
           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────────┐
 │ OPENSEARCH CLUSTER (Local or Serverless Deployment)                                   │
 │                                                                                       │
 │  ┌─────────────────────────────────────────────────────────────────────────────────┐  │
 │  │ Klaxon Ingest Pipeline (`klaxon-mask-<tenant>`)                                 │  │
 │  │  - Deterministic HMAC-SHA256 filter (e.g., admin -> [USER_8f3a9b])              │  │
 │  │  - Automatically detects emails, IPs & free-text patterns                       │  │
 │  └───────────────────────────────┬─────────────────────────────────────────────────┘  │
 │                                  │                                                    │
 │                 ┌────────────────┴────────────────┐                                   │
 │                 ▼ (Successfully Masked)           ▼ (Masking Error / Fail-Closed)     │
 │   ┌───────────────────────────────┐     ┌──────────────────────────────────────────┐  │
 │   │ Masked Stream                 │     │ Quarantine Stream                        │  │
 │   │ `klaxon-masked-<tenant>-v5*`  │     │ `klaxon-quarantine-<tenant>-v5-raw`      │  │
 │   │                               │     │                                          │  │
 │   │  [Text Logs]                  │     │  [Raw Logs + Error Metadata]             │  │
 │   │  (Anonymous tokens only)      │     │  (Strictly blocked from LLM/RAG access!) │  │
 │   └─────────────┬─────────────────┘     └──────────────────────────────────────────┘  │
 └─────────────────┼─────────────────────────────────────────────────────────────────────┘
                   │
                   ▼ (Triggered via regular background cron job)
 ┌───────────────────────────────────────────────────────────────────────────────────────┐
 │ Python Vector Sync Script                                                             │
 │  1. Fetches un-vectorized text strings from the 'Masked Stream'                       │
 │  2. Sends text to the local Ollama API (`/api/embed` -> nomic-embed-text)             │
 │  3. Writes the 768-dim vector back into the OpenSearch field `klaxon_vector`          │
 └─────────────────┬─────────────────────────────────────────────────────────────────────┘
                   │
                   ▼
 ┌───────────────────────────────────────────────────────────────────────────────────────┐
 │ `klaxon_vector` (Integrated k-NN Index inside the OpenSearch Masked Stream)           │
 └───────────────────────────────────────────────────────────────────────────────────────┐

==========================================================================================
2. ORCHESTRATION AND TOOL LAYER (Query-time execution)
==========================================================================================

                             User asks a question in the Chat UI
                       (e.g., "Show me anomalies regarding [USER_8f3a9b]")
                                           │
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────────┐
 │ USER INTERFACE (e.g., Open WebUI or Custom Python App)                                │
 └─────────────────┬───────────────────────────────────────────────────▲─────────────────┘
                   │                                                   │
                   │ (Communicates via MCP Protocol)                   │ (Returns natural response)
                   ▼                                                   │
 ┌─────────────────────────────────────────────────────────────────────┴─────────────────┐
 │ KLAXON-MCP GATEWAY (Model Context Protocol Server)                                    │
 │  - Exposes tools for both Semantic Vector Search & BM25 Full-Text Search              │
 │  - Enforces RBAC (Only possesses read permissions for `klaxon-masked-*`)              │
 └─────────────────┬───────────────────────────────────────────────────▲─────────────────┘
                   │                                                   │
                   │ (Executes k-NN Vector Search query)               │ (Returns masked context
                   ▼                                                   │  data / relevant log hits)
 ┌─────────────────────────────────────────────────────────────────────┴─────────────────┐
 │ OPENSEARCH k-NN INDEX (Queries the 768-dimensional stored vectors)                    │
 └─────────────────────────────────────────────────────────────────────┴─────────────────┐

==========================================================================================
3. INFERENCE LAYER (Local Hardware Execution)
==========================================================================================

                  Local application sends query + masked context payload
                                           │
                                           ▼
 ┌───────────────────────────────────────────────────────────────────────────────────────┐
 │ OLLAMA KI-ENGINE (Self-Hosted odr running fully offline on your workstation)          │
 │                                                                                       │
 │  Hardware Allocation:                                                                 │
 │  ┌─────────────────────────────────────────────────────────────────────────────────┐  │
 │  │ NVIDIA RTX 4080 (16 GB VRAM)                                                    │  │
 │  │  ├── Vector Embeddings: `nomic-embed-text` (768 Dimensions)                     │  │
 │  │  └── Security LLM:       `qwen2.5:14b` or `deepseek-r1:14b` (Fully in VRAM)     │  │
 │  └─────────────────────────────────────────────────────────────────────────────────┘  │
 │  ┌─────────────────────────────────────────────────────────────────────────────────┐  │
 │  │ AMD RYZEN 7 9800X3D & 64 GB SYSTEM RAM                                          │  │
 │  │  └── System headroom for OpenSearch nodes, OS processes & Klaxon Sync engine    │  │
 │  └─────────────────────────────────────────────────────────────────────────────────┘  │
 └───────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Layer Deep-Dive

### Ingestion & Compliance Layer
* **Klaxon Ingest Pipeline:** Leverages high-performance Painless scripts within OpenSearch to mask structured fields and free-text strings on the fly using a secure, static HMAC-SHA256 salt.
* **Deterministic Pseudonyms:** Translates standard identifiers into immutable, context-preserving hashes (e.g., `[USER_8f3a9b]`). This keeps network graphs and sequential access analysis functional for the LLM without leaking identities.
* **Fail-Closed Isolation:** If the regex mapping or tokenization engine runs into processing boundaries, the `on_failure` block instantly intercepts the document, labels it with metadata, and isolates it inside a dedicated quarantine data stream. It never bypasses security filters or visual feeds designated for the LLM.

### Orchestration & Tool Layer
* **Model Context Protocol (MCP):** Klaxon acts as a specialized backend gateway. By wrapping vector and structural index lookups into atomic MCP tools, the frontend client can run complex hybrid queries safely.
* **Granular RBAC:** Access rights are handled natively inside the OpenSearch security framework. The system operator assigns exclusive write-access to the index synchronizer, whereas the AI client only carries isolated read-access to the pre-masked indices.

### Inference Layer
* **Ollama Ecosystem:** Operates 100% offline via local REST endpoints. Standard operations allocate vector mapping workloads to `nomic-embed-text` and structural analytics to deep-reasoning parameters such as `qwen2.5:14b` or `deepseek-r1:14b`.
* **Hardware Optimizations:** Fully utilizes the 16 GB VRAM of the workstation's RTX 4080 GPU to host full 14B parameter context windows locally. Memory and computational headroom are actively cushioned by the high L3 cache of the AMD Ryzen 7 9800X3D and 64 GB of desktop RAM.

---

## 3. Data Integrity & GDPR Advantages
1. **Zero Data Leakage:** Because data manipulation occurs during cluster-level record entry, indexing endpoints and vector components never interface with unmasked source formats.
2. **Reverse Encryption Defenses:** Standard text embeddings are prone to reconstruction vectors (Vector Inversion Attacks). Masking raw inputs *prior* to token processing strips out identity signatures, rendering mathematical inversion exploits harmless.
3. **Automated Cleanups (Art. 17 GDPR Compliance):** Automated retention rules (ISM Policies) phase out older masked indexes within predefined intervals (e.g., 30 days) while preserving structural forensic backups under quarantined vaults for an expanded timeframe.
