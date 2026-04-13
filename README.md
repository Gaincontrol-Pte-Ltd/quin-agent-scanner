# Quin Agent Scanner

> Nothing in your codebase is hidden from Quin.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

Named after [Bao Qingtian](https://gaincontrol.ai/about) -- the incorruptible judge of the Song Dynasty who saw through every deception -- **Quin** is an open-source CLI tool by [Gaincontrol](https://gaincontrol.ai/) that scans any codebase to detect AI agents, extract system prompts, classify risk, and produce compliance-ready reports.

Point Quin at a repo and get back: every AI agent, what it does, what tools it has, and what risks it carries -- in a single HTML report.

Learn more at [gaincontrol.ai/quin](https://gaincontrol.ai/quin).

---

## About Gaincontrol

Quin is built by [Gaincontrol](https://gaincontrol.ai/), headquartered in Singapore. We build the infrastructure enterprises need to run AI agents safely.

| Product | What it does |
|---|---|
| **[Quin](https://gaincontrol.ai/quin)** | AI Agent Scanner -- see every agent, trust nothing blindly |
| **[Aegis](https://gaincontrol.ai/)** | AI Identity Governance -- every agent operates only within its granted authority |
| **[Drona](https://gaincontrol.ai/)** | Safe Execution Fabric -- deterministic execution for probabilistic AI |

- **Website:** [gaincontrol.ai](https://gaincontrol.ai/)
- **Contact:** [pixiedust@gaincontrol.ai](mailto:pixiedust@gaincontrol.ai)

---

## Quick Start

### 1. Install

```bash
pip install quin-scanner
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv tool install quin-scanner
```

### 2. Set up your `.env`

Create a `.env` file in your working directory:

```bash
# Pick one LLM provider:
ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...
# GOOGLE_API_KEY=...

# For scanning GitHub repos or orgs:
GITHUB_TOKEN=ghp_...
```

### 3. Set up `scanner-config.yaml`

```bash
curl -O https://raw.githubusercontent.com/Gaincontrol-Pte-Ltd/quin-agent-scanner/main/scanner-config.yaml
```

The default config uses Anthropic and outputs HTML:

```yaml
llm:
  provider: anthropic                  # openai | anthropic | google | ollama | openai-compatible
  model: claude-haiku-4-5-20251001
  # api_key_env: ANTHROPIC_API_KEY     # reads from your .env

output:
  format: html                         # html | json | yaml

scanners:
  enabled:
    - dependency
    - config
    - code_pattern
    - file_structure
    - framework
    - prompt_discovery
    - dockerfile
    - jupyter
    - iac
    - ci
    - mcp
    - agent_instance
    - tool_definition
```

### 4. Run your first scan

```bash
# Scan a local repo -- generates an HTML report in ./report/
quin-scanner scan ./path/to/repo --config scanner-config.yaml

# Scan a GitHub repo
quin-scanner scan https://github.com/org/repo --config scanner-config.yaml

# Static-only scan (no LLM, no API key needed)
quin-scanner scan ./path/to/repo --config scanner-config.yaml --no-llm
```

---

## Scan an Entire GitHub Org

```bash
quin-scanner scan-org my-github-org \
  --config scanner-config.yaml \
  --skip-archived \
  --skip-forks
```

This discovers all repos in the org via the GitHub API, scans each one, and writes per-repo HTML reports to `./report/`.

```
Options:
  -o, --output [json|yaml|html]   Output format (default: html)
  --output-dir PATH               Directory for reports (default: ./report/)
  --skip-archived                 Skip archived repositories
  --skip-forks                    Skip forked repositories
  --no-llm                        Skip LLM analysis
  --config PATH                   Path to scanner-config.yaml
```

Requires `GITHUB_TOKEN` with `repo` + `read:org` scopes. Create one at [github.com/settings/tokens](https://github.com/settings/tokens).

---

## Supported Frameworks

Quin detects AI usage across these frameworks and SDKs:

| Framework | Language |
|---|---|
| LangChain / LangGraph | Python, Node.js |
| CrewAI | Python |
| AutoGen | Python |
| MetaGPT | Python |
| OpenAI Agents SDK | Python |
| Anthropic Agent SDK | Python |
| Google ADK | Python |
| Databricks Agent Framework | Python |
| LlamaIndex | Python, Node.js |
| Haystack | Python |
| Semantic Kernel | Python, Node.js |
| Dify | Python |
| Flowise | Node.js |
| PromptFlow | Python |
| Vercel AI SDK | TypeScript |
| MCP (Model Context Protocol) | Any |
| OpenClaw | Node.js |
| PydanticAI | Python |
| DSPy / Guidance / Outlines | Python |
| OpenAI SDK | Python, Node.js, Go, Rust, Java |
| Anthropic SDK | Python, Node.js |
| Google Generative AI | Python, Node.js |
| Transformers / Diffusers | Python |
| LiteLLM | Python |

Also detects vector databases (ChromaDB, Pinecone, Qdrant, Weaviate, FAISS, pgvector, Milvus), embedding providers (Cohere, Sentence Transformers, Hugging Face), and voice/image AI packages (ElevenLabs, Whisper, Stable Diffusion).

---

## Installation

### Prerequisites

- **Python 3.11+** -- [download](https://www.python.org/downloads/)
- **An LLM API key** -- OpenAI, Anthropic, Google, or a local Ollama model
- **git** -- for scanning GitHub repos
- **GitHub token** _(optional)_ -- for private repos or org scanning

### From PyPI

```bash
pip install quin-scanner
```

### From source

```bash
git clone https://github.com/Gaincontrol-Pte-Ltd/quin-agent-scanner
cd quin-agent-scanner
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync --all-extras
cp .env.example .env   # edit with your API keys

uv run quin-scanner scan ./path/to/repo --config scanner-config.yaml
```

### LLM Providers

| Provider | Config value | Default Model | API Key Env Var |
|---|---|---|---|
| Anthropic | `anthropic` | `claude-haiku-4-5-20251001` | `ANTHROPIC_API_KEY` |
| OpenAI | `openai` | `gpt-4o-mini` | `OPENAI_API_KEY` |
| Google | `google` | `gemini-2.0-flash` | `GOOGLE_API_KEY` |
| Ollama (local) | `ollama` | `llama3.2` | -- |
| OpenAI-compatible | `openai-compatible` | _(set with `--llm-model`)_ | `OPENAI_API_KEY` |

---

## How It Works

Quin runs 13 scanner plugins in parallel, then uses a two-pass LLM pipeline:

```
Repo  -->  13 Scanners (parallel)  -->  Pass 1: Classification  -->  Pass 2: Synthesis  -->  Report
```

1. **13 scanners** detect dependencies, code patterns, configs, prompts, frameworks, tools, agents, MCP servers, Dockerfiles, notebooks, CI pipelines, and infrastructure-as-code
2. **Pass 1 (Classification)** -- an LLM classifies the system type (`standard_ai`, `agentic_ai`, `mcp_enabled`, `multi_agent`) and identifies relevant threats from a taxonomy sourced from OWASP LLM Top 10, OWASP Agentic Top 10, OWASP MCP Top 10, MAESTRO, and Databricks DASF
3. **Pass 2 (Synthesis)** -- a second LLM call profiles each agent with taxonomy-grounded risk indicators, maps tool usages to service categories, and generates a narrative summary

Use `--no-llm` to skip both LLM passes and run scanners only.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

Apache-2.0 -- see [LICENSE](LICENSE).
