# Quin Agent Scanner

> Nothing in your codebase is hidden from Quin.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

Named after [Bao Qingtian](https://gaincontrol.ai/about) -- the incorruptible judge of the Song Dynasty who saw through every deception -- **Quin** is an open-source CLI tool by [Gaincontrol](https://gaincontrol.ai/) that scans any codebase to detect AI agents, extract system prompts, analyze intent, and produce compliance-ready reports.

Point Quin at any repository, local or remote, and get a structured map of every AI agent, what it's instructed to do, and what risks it carries. No other open-source tool combines AI dependency detection, system prompt discovery, LLM-powered agent intent analysis, and model usage identification in a single scan.

Learn more at [gaincontrol.ai/quin](https://gaincontrol.ai/quin).

---

## Quick Start

Get scanning in under 2 minutes.

### 1. Install

```bash
pip install quin-scanner
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv tool install quin-scanner
```

### 2. Configure your environment

Create a `.env` file in your working directory with your LLM API key and (optionally) a GitHub token:

```bash
# Pick one LLM provider:
ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...
# GOOGLE_API_KEY=...

# For scanning GitHub repos or orgs:
GITHUB_TOKEN=ghp_...
```

### 3. Configure the scanner

Copy and edit the config file to set your preferred LLM provider and model:

```bash
# Download the example config
curl -O https://raw.githubusercontent.com/Gaincontrol-Pte-Ltd/quin-agent-scanner/main/scanner-config.yaml
```

Edit `scanner-config.yaml` to match your provider:

```yaml
llm:
  provider: anthropic                  # openai | anthropic | google | ollama
  model: claude-haiku-4-5-20251001     # see LLM Providers for options
  api_key_env: ANTHROPIC_API_KEY       # reads from your .env file
```

### 4. Run your first scan

```bash
# Scan a local repository
quin-scanner scan ./path/to/repo --config scanner-config.yaml --output json

# Scan a GitHub repository
quin-scanner scan https://github.com/org/repo --config scanner-config.yaml --output json

# Scan all repos in a GitHub organization
quin-scanner scan-org my-github-org --config scanner-config.yaml --output-dir ./reports/
```

### Alternative: Run from source

If you prefer not to install via pip, you can clone the repo and run directly:

```bash
git clone https://github.com/Gaincontrol-Pte-Ltd/quin-agent-scanner
cd quin-agent-scanner

# Install uv if you don't have it
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install dependencies
uv sync --all-extras

# Set up your .env file
cp .env.example .env
# Edit .env with your API keys

# Run scans with uv run
uv run quin-scanner scan ./path/to/repo --config scanner-config.yaml --output json
```

> When running from source, prefix all commands with `uv run` (e.g. `uv run quin-scanner scan ...`).

---

## Table of Contents

- [Quick Start](#quick-start)
- [What It Does](#what-it-does)
- [Supported Frameworks](#supported-frameworks)
- [Installation](#installation)
- [Configuration](#configuration)
- [Commands Reference](#commands-reference)
- [LLM Providers](#llm-providers)
- [Output Format](#output-format)
- [Scanners & Capability Tags](#scanners)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [Development Setup](#development-setup)
- [Contributing](#contributing)
- [Roadmap & Comparison](#roadmap)
- [License](#license)
- [About Gaincontrol](#about-gaincontrol)

---

## What It Does

- **Detects AI applications** across 23+ frameworks in Python, JavaScript/TypeScript, Go, Rust, and Java
- **Identifies the AI framework** — LangChain, CrewAI, Anthropic Agent SDK, AutoGen, LlamaIndex, and more
- **Identifies LLM models** in use — including provider, model name, and primary/fallback routing patterns
- **Discovers system prompts** from source code, YAML configs, Markdown, and template files (Jinja2, Mustache)
- **Profiles each agent** using a single LLM synthesis call — name, type (supervisor/utility/worker), goal, capabilities, tools, skills, and risk signals
- **Detects MCP servers** — name, transport (stdio/http/sse), and source file
- **Detects tool usage** — repo-wide tool and function references
- **Detects deployment infrastructure** — Terraform, Kubernetes, and Docker Compose configurations
- **Scans everywhere** — local folders, GitHub repo URLs, or an entire GitHub org

---

## Supported Frameworks

| Framework | Language | Capability Tags |
|---|---|---|
| LangChain / LangGraph | Python | orchestration, rag, tool-use |
| CrewAI | Python | multi-agent, orchestration |
| AutoGen | Python | multi-agent, orchestration |
| OpenAI Agents SDK | Python | llm-api, tool-use |
| Anthropic Agent SDK | Python | llm-api, orchestration, tool-use |
| Google ADK | Python | llm-api, orchestration, tool-use |
| Databricks Agent Framework | Python | llm-api, orchestration |
| LlamaIndex | Python | rag, embeddings |
| Haystack | Python | rag, orchestration |
| Semantic Kernel | Python / C# | orchestration, tool-use |
| Dify | Python | orchestration, prompt-templates |
| Flowise | Node.js | orchestration |
| PromptFlow | Python | orchestration, prompt-templates |
| Vercel AI SDK | TypeScript | llm-api, orchestration |
| MCP (Model Context Protocol) | Any | tool-use |
| OpenAI SDK | Python / JS / Go / Rust / Java | llm-api |
| Anthropic SDK | Python / JS | llm-api |
| Google Generative AI | Python / JS | llm-api |
| Transformers / Diffusers | Python | fine-tuning, image-gen |
| LiteLLM | Python | llm-api, orchestration |

---

## Installation

### From PyPI (recommended)

```bash
pip install quin-scanner
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv tool install quin-scanner
```

### Prerequisites

- **Python 3.11 or higher** — [download here](https://www.python.org/downloads/)
- **An LLM API key** — for agent intent analysis (OpenAI, Anthropic, Google, or a local Ollama model)
- **git** — for cloning and scanning GitHub repositories
- **A GitHub token** _(optional)_ — for scanning private repos or GitHub orgs

---

## Configuration

Quin requires two configuration files to run at full capability: a **`.env` file** for API keys and a **`scanner-config.yaml`** for scanner settings.

### Step 1: Set up your `.env` file

Create a `.env` file in the directory where you run `quin-scanner`:

```bash
# Pick one LLM provider and set its API key:
ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...
# GOOGLE_API_KEY=...

# For scanning GitHub repos or orgs:
GITHUB_TOKEN=ghp_...
```

API keys can also be passed as CLI flags (`--llm-api-key`, `--github-token`), but a `.env` file is recommended for repeated use.

### Step 2: Set up your `scanner-config.yaml`

Download or create a config file:

```bash
curl -O https://raw.githubusercontent.com/Gaincontrol-Pte-Ltd/quin-agent-scanner/main/scanner-config.yaml
```

Edit it to match your LLM provider:

```yaml
llm:
  provider: anthropic                  # openai | anthropic | google | ollama | openai-compatible
  model: claude-haiku-4-5-20251001     # see LLM Providers section for options
  api_key_env: ANTHROPIC_API_KEY       # reads the key from your .env file

output:
  format: json                         # json | yaml

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
```

Pass it to any command with `--config scanner-config.yaml`.

**Config priority** (highest to lowest): CLI flags -> config file -> environment variables -> defaults.

### Step 3: Run a scan

```bash
# Scan a local repository
quin-scanner scan ./my-repo --config scanner-config.yaml

# Scan a GitHub repository
quin-scanner scan https://github.com/org/repo --config scanner-config.yaml

# Scan with YAML output to a file
quin-scanner scan ./my-repo --config scanner-config.yaml --output yaml --output-file report.yaml
```

### GitHub Token Scopes

For scanning public repos: `public_repo` scope is sufficient.
For scanning private repos or org membership: `repo` + `read:org` scopes are required.

Create a token at [github.com/settings/tokens](https://github.com/settings/tokens).

### Environment Variables Reference

| Variable | Description | Required For |
|---|---|---|
| `ANTHROPIC_API_KEY` | Anthropic API key (`sk-ant-...`) | `provider: anthropic` |
| `OPENAI_API_KEY` | OpenAI API key (`sk-...`) | `provider: openai` |
| `GOOGLE_API_KEY` | Google AI API key | `provider: google` |
| `GITHUB_TOKEN` | GitHub Personal Access Token | Scanning GitHub repos or orgs |
| `OPENAI_COMPATIBLE_URL` | Base URL for OpenAI-compatible endpoints | `provider: openai-compatible` |

---

## Architecture

### How It Works

The scan pipeline flows linearly through these stages:

```
CLI → RepoAccessorFactory → FileIndex → ScanOrchestrator
         ↓                                      ↓
  LocalRepoAccessor               ┌─────────────────────────┐
  GitHubAPIAccessor               │  11 Scanner Plugins      │
                                  │  + ModelIdentifier        │
                                  │  + SynthesisAgent (LLM)  │
                                  └─────────────────────────┘
                                              ↓
                                       ReportGenerator
                                              ↓
                                      JSON / YAML output
```

1. The CLI parses arguments and resolves configuration (flags → config file → env vars)
2. `RepoAccessorFactory` creates the right accessor for the target (local path or GitHub URL)
3. `FileIndex` enumerates all files and builds a lookup structure (extension → paths, dir → paths)
4. `ScanOrchestrator` runs all enabled scanner plugins in parallel, collects `ScanFinding` objects
5. `ModelIdentifier` scans code and config files for LLM model name references
6. `SynthesisAgent` sends a summary of all findings to an LLM for agent profiling (skipped if `--no-llm`)
7. `ReportGenerator` serializes the final `ScanReport` to JSON or YAML

### Directory Structure

```
quin-agent-scanner/
├── src/
│   └── quin_scanner/
│       ├── cli.py                    # click entry point — all commands defined here
│       ├── config.py                 # ScannerConfig dataclass + loader
│       ├── models.py                 # All data models (ScanFinding, ScanReport, ModelUsage, ...)
│       ├── orchestrator.py           # ScanOrchestrator — wires everything together
│       ├── repo_accessor.py          # RepoAccessor ABC + LocalRepoAccessor + GitHubAPIAccessor
│       ├── file_index.py             # FileIndex — fast glob matching over repo file tree
│       ├── model_identifier.py       # ModelIdentifier — LLM model name detection
│       ├── github_client.py          # GitHubClient — minimal REST API v3 (org/user repo listing, auto-detected)
│       ├── report.py                 # ReportGenerator — JSON/YAML serialization
│       ├── scanners/
│       │   ├── base.py               # BaseScanner ABC
│       │   ├── dependency.py         # DependencyScanner
│       │   ├── config_scanner.py     # ConfigScanner
│       │   ├── code_pattern.py       # CodePatternScanner
│       │   ├── file_structure.py     # FileStructureScanner
│       │   ├── framework.py          # FrameworkMarkerScanner
│       │   ├── prompt_discovery.py   # PromptDiscoveryScanner
│       │   ├── dockerfile.py         # DockerfileScanner
│       │   ├── jupyter.py            # JupyterScanner
│       │   ├── ci_scanner.py         # CIScanner
│       │   ├── iac.py                # IaCScanner
│       │   ├── mcp_scanner.py        # MCPScanner
│       │   ├── agent_instance_scanner.py  # AgentInstanceScanner
│       │   └── tool_definition_scanner.py # ToolDefinitionScanner
│       ├── llm/
│       │   ├── base.py               # BaseLLMProvider ABC
│       │   ├── synthesis_agent.py    # SynthesisAgent — orchestrates the LLM call
│       │   ├── analyzer.py           # LLMAnalyzer — prompt construction
│       │   ├── openai_provider.py    # OpenAIProvider
│       │   ├── anthropic_provider.py # AnthropicProvider
│       │   ├── google_provider.py    # GoogleProvider
│       │   ├── ollama_provider.py    # OllamaProvider
│       │   └── openai_compatible.py  # OpenAICompatibleProvider
│       └── rules/
│           ├── dependencies.yaml     # AI package names per ecosystem
│           ├── code_patterns.yaml    # Import/usage regex patterns per language
│           ├── frameworks.yaml       # Framework config file names + confidence
│           ├── file_markers.yaml     # AI-related directory names
│           ├── models.yaml           # LLM model registry for provider classification
│           ├── prompt_signals.yaml   # Patterns for system prompt detection
│           └── exclusions.yaml       # Paths/patterns to skip during scanning
├── scanner-config.yaml               # Default config (copy of scanner-config.example.yaml)
├── pyproject.toml                    # Project metadata + dependencies
├── uv.lock                           # Locked dependency versions
├── .env.example                      # Environment variable template
├── .python-version                   # Pinned Python version for uv
└── CONTRIBUTING.md                   # Contribution guidelines
```

### Key Abstractions

**`RepoAccessor` (ABC)**

Uniform file access interface for local and remote repositories:

```python
class RepoAccessor(ABC):
    def read_file(self, path: str) -> str: ...
    def list_files(self) -> list[str]: ...
```

- `LocalRepoAccessor` — reads from the local filesystem using `pathlib.Path`
- `GitHubAPIAccessor` — clones the repo via `git clone --depth 1` then reads locally
- `RepoAccessorFactory` — creates the right accessor from a target string (path, `https://github.com/...`, `org/repo#branch`)

**`BaseScanner` (ABC)**

All scanner plugins implement two methods:

```python
class BaseScanner(ABC):
    def name(self) -> str: ...
    def scan(self, accessor: RepoAccessor, file_index: FileIndex) -> list[ScanFinding]: ...
```

Scanners are stateless. They receive a `RepoAccessor` (file I/O) and a `FileIndex` (fast path lookups) and return a flat list of `ScanFinding` objects.

**`BaseLLMProvider` (ABC)**

All LLM adapters implement a single method:

```python
class BaseLLMProvider(ABC):
    def analyze_prompt(self, system_prompt: str) -> AgentIntentSummary: ...
```

**`FileIndex`**

Builds a fast lookup structure over the repo's file tree:

```python
index.all_files()                    # all paths
index.glob("**/*.py")               # glob matching
index.files_by_extension(".py")     # files with a given extension
index.files_in_dir("src/agents")    # files under a directory
```

### Data Models

All models are plain Python dataclasses with a `.to_dict()` method for serialization:

| Model | Purpose |
|---|---|
| `ScanFinding` | A single detected signal from a scanner plugin |
| `ModelUsage` | An identified LLM model reference (provider, model_name, source, file, line, role) |
| `AgentIntentSummary` | LLM analysis result (framework, summary, agents, tool_usages) |
| `AgentProfile` | Individual agent profile (name, type, goal, capabilities, tools, risk_signals) |
| `ToolUsage` | Tool/function reference (tool_name, source_file, line_number) |
| `MCPServer` | MCP server config (name, transport, source_file) |
| `InfraProfile` | Infrastructure profile (platform, details, source_files) |
| `ScanReport` | Final output — aggregates all of the above |
| `ScannerConfig` | Runtime configuration parsed from CLI flags + config file + env vars |

### Detection Pipeline Detail

```
ScanFinding  ←─── DependencyScanner      (requirements.txt, package.json, go.mod, ...)
ScanFinding  ←─── CodePatternScanner     (import langchain, from anthropic import, ...)
ScanFinding  ←─── ConfigScanner          (OPENAI_API_KEY=, ANTHROPIC_API_KEY=, ...)
ScanFinding  ←─── FileStructureScanner   (agents/, prompts/, vector_store/, ...)
ScanFinding  ←─── FrameworkMarkerScanner (langgraph.json, crew.yaml, .mcp.json, ...)
ScanFinding  ←─── PromptDiscoveryScanner (system_prompt = "...", SYSTEM: ..., ...)
ScanFinding  ←─── DockerfileScanner      (FROM langchain/..., pip install openai, ...)
ScanFinding  ←─── JupyterScanner         (.ipynb cells with AI imports/prompts)
ScanFinding  ←─── CIScanner             (GitHub Actions with OPENAI_API_KEY, ...)
ScanFinding  ←─── IaCScanner            (Terraform aws_bedrock_*, k8s model-service, ...)
ScanFinding  ←─── MCPScanner            (.mcp.json, claude_desktop_config.json, ...)
ModelUsage   ←─── ModelIdentifier        (model="gpt-4o", model: claude-sonnet-4-6, ...)
                              │
                              ▼
                    SynthesisAgent (single LLM call)
                              │
                              ▼
              AgentIntentSummary (framework, agents[], summary)
```

All scanner output is merged into a `ScanReport` by `ScanOrchestrator`:
- `is_ai_application` is `True` if total confidence-weighted signals exceed threshold
- `confidence` is the highest single-finding confidence, capped at 0.99
- `capability_tags` is the union of all finding tags

---

## Commands Reference

### `scan` — Scan a Single Repository

```
quin-scanner scan TARGET [OPTIONS]

Arguments:
  TARGET  Local path or GitHub URL (https://github.com/org/repo)

Options:
  -o, --output [json|yaml]             Output format (default: json)
  -f, --output-file PATH               Write output to a specific file
  -d, --output-dir PATH                Write output to this directory (auto-names file)
  --llm-provider [openai|anthropic|google|ollama|openai-compatible]
                                       LLM provider for agent intent analysis
  --llm-model TEXT                     Override the default model for the provider
  --llm-api-key TEXT                   API key (overrides env var)
  --openai-compatible-url TEXT         Base URL for OpenAI-compatible endpoints
  --github-token TEXT                  GitHub PAT (overrides GITHUB_TOKEN env var)
  --branch TEXT                        Branch to scan (default: main)
  --no-llm                             Skip LLM analysis entirely (faster, no key needed)
  --config PATH                        Path to a scanner-config.yaml file
  -h, --help                           Show this message and exit
```

**Examples:**

```bash
# Scan a local repo using your config file
quin-scanner scan ./my-repo --config scanner-config.yaml

# Scan with YAML output to a file
quin-scanner scan ./my-repo \
  --config scanner-config.yaml \
  --output yaml \
  --output-file report.yaml

# Scan a GitHub repo on a specific branch
quin-scanner scan https://github.com/org/repo \
  --config scanner-config.yaml \
  --branch develop

# Override LLM provider via CLI flags
quin-scanner scan ./my-repo \
  --llm-provider openai \
  --llm-model gpt-4o

# Use a local Ollama model (no API key needed)
quin-scanner scan ./my-repo \
  --llm-provider ollama \
  --llm-model llama3.2

# Use any OpenAI-compatible endpoint (vLLM, LiteLLM, Azure, etc.)
quin-scanner scan ./my-repo \
  --llm-provider openai-compatible \
  --openai-compatible-url http://localhost:8000/v1 \
  --llm-model my-fine-tuned-model \
  --llm-api-key dummy

# Static-only scan (skips LLM agent intent analysis)
quin-scanner scan ./my-repo --no-llm
```

### `scan-org` — Scan All Repos in a GitHub Organization or User Account

```
quin-scanner scan-org ORG_NAME [OPTIONS]

Arguments:
  ORG_NAME  GitHub organization or user account name (auto-detected)

Options:
  -o, --output [json|yaml]             Output format (default: json)
  --output-dir PATH                    Directory for per-repo reports (default: current dir)
  --github-token TEXT                  GitHub PAT (or set GITHUB_TOKEN env var)
  --skip-archived                      Skip archived repositories
  --skip-forks                         Skip forked repositories
  --no-llm                             Skip LLM analysis
  --config PATH                        Path to scanner-config.yaml
```

**Example:**

```bash
# Scan all non-archived, non-forked repos in an org, save JSON reports to ./reports/
quin-scanner scan-org my-github-org \
  --config scanner-config.yaml \
  --skip-archived \
  --skip-forks \
  --output-dir ./reports/
```

### `scan-batch` — Scan Multiple Repos from a File

```
quin-scanner scan-batch TARGETS_FILE [OPTIONS]

Arguments:
  TARGETS_FILE  File with one target per line (local path or GitHub URL)

Options:
  -o, --output [json|yaml]             Output format (default: json)
  --output-dir PATH                    Directory for per-repo reports
  --no-llm                             Skip LLM analysis
```

**Example:**

`targets.txt`:
```
./local-repo-1
https://github.com/org/repo-a
https://github.com/org/repo-b
```

```bash
quin-scanner scan-batch targets.txt --config scanner-config.yaml --output-dir ./reports/
```

### Commands Summary

| Command | Description |
|---|---|
| `quin-scanner scan TARGET --config scanner-config.yaml` | Scan a repo with LLM analysis |
| `quin-scanner scan-org ORG --config scanner-config.yaml` | Scan entire GitHub org or user account |
| `quin-scanner scan-batch targets.txt --config scanner-config.yaml` | Batch scan from a file |
| `quin-scanner --help` | Show all commands and options |

---

## LLM Providers

Quin Scanner uses a **single LLM synthesis call** after all 11 scanners complete. The prompt includes pre-summarised evidence from every scanner and asks the LLM to return: the detected framework, per-agent profiles (name, type, goal, capabilities, tools, risk signals), and a plain-English narrative summary.

Configure the LLM provider in your `scanner-config.yaml` or with `--llm-provider`:

| Provider | Config value | Default Model | API Key Env Var | Notes |
|---|---|---|---|---|
| Anthropic | `anthropic` | `claude-haiku-4-5-20251001` | `ANTHROPIC_API_KEY` | Recommended for most teams |
| OpenAI | `openai` | `gpt-4o-mini` | `OPENAI_API_KEY` | Fast and cost-effective |
| Google | `google` | `gemini-2.0-flash` | `GOOGLE_API_KEY` | Good for high-volume scans |
| Ollama (local) | `ollama` | `llama3.2` | — | No API key, runs locally |
| OpenAI-compatible | `openai-compatible` | _(specify with `--llm-model`)_ | `OPENAI_API_KEY` or `--llm-api-key` | vLLM, LiteLLM, Azure, Bedrock |

**Ollama setup** (local inference, no API key needed):

```bash
# Install Ollama: https://ollama.ai
ollama pull llama3.2

quin-scanner scan ./my-repo --llm-provider ollama --llm-model llama3.2
```

> **Static-only mode:** You can pass `--no-llm` to skip LLM analysis entirely. All 13 scanners still run and detect dependencies, prompts, MCP servers, infrastructure, and model usage. Only the synthesis step (agent profiles, framework detection, narrative summary) is skipped.

---

## Output Format

The scan result is a single JSON (or YAML) document:

```json
{
  "repo_path": "./my-repo",
  "scan_timestamp": "2026-03-31T10:00:00+00:00",
  "is_ai_application": true,
  "confidence": 0.97,
  "capability_tags": ["llm-api", "rag", "tool-use", "orchestration"],
  "framework": "LangChain",
  "summary": "This repository implements a multi-agent research system using LangChain. A supervisor agent orchestrates two utility agents — one for web search and one for summarisation — with results stored in a ChromaDB vector store.",
  "agents": [
    {
      "name": "ResearchAgent",
      "agent_type": "utility",
      "goal": "Search the web and summarise research findings",
      "capabilities": ["web-search", "summarisation"],
      "risk_signals": ["makes outbound HTTP requests", "returns user-facing content"],
      "skills": [],
      "tools": ["web_search", "summarise"],
      "source_file": "src/agents/researcher.py"
    },
    {
      "name": "OrchestratorAgent",
      "agent_type": "supervisor",
      "goal": "Route tasks to specialist agents and compile the final answer",
      "capabilities": ["orchestration", "multi-agent"],
      "risk_signals": [],
      "skills": [],
      "tools": [],
      "source_file": "src/agents/orchestrator.py"
    }
  ],
  "tool_usages": [
    { "tool_name": "web_search", "source_file": "src/tools.py", "line_number": 12 },
    { "tool_name": "summarise",  "source_file": "src/tools.py", "line_number": 28 }
  ],
  "mcp_servers": [
    { "name": "filesystem", "transport": "stdio", "source_file": ".mcp.json" }
  ],
  "infra": {
    "platform": "kubernetes",
    "details": ["Deployment: agent-service", "ConfigMap: model-config"],
    "source_files": ["k8s/deployment.yaml", "k8s/configmap.yaml"]
  },
  "model_usages": [
    {
      "provider": "openai",
      "model_name": "gpt-4o",
      "source": "code",
      "file_path": "src/agent.py",
      "line_number": 14,
      "role": "primary"
    }
  ],
  "findings": [
    {
      "scanner_name": "DependencyScanner",
      "category": "dependency",
      "file_path": "requirements.txt",
      "line_number": 1,
      "match_text": "langchain==0.2.0",
      "capability_tag": "orchestration",
      "confidence": 0.95
    }
  ],
  "metadata": {
    "scan_duration_seconds": 2.4,
    "file_count": 312,
    "finding_count": 11,
    "findings_by_scanner": {
      "DependencyScanner": 3,
      "CodePatternScanner": 7,
      "PromptDiscoveryScanner": 1
    }
  }
}
```

**Top-level fields:**

| Field | Type | Description |
|---|---|---|
| `repo_path` | string | The scan target (path or URL) |
| `scan_timestamp` | ISO 8601 string | When the scan was performed |
| `is_ai_application` | bool | Whether this repo is an AI application |
| `confidence` | float 0–1 | Detection confidence |
| `capability_tags` | string[] | Union of all finding capability tags |
| `framework` | string | Detected framework name (`"unknown"` if `--no-llm`) |
| `summary` | string | LLM-generated narrative (`""` if `--no-llm`) |
| `agents` | AgentProfile[] | Per-agent profiles (`[]` if `--no-llm`) |
| `tool_usages` | ToolUsage[] | Repo-wide tool references (`[]` if `--no-llm`) |
| `mcp_servers` | MCPServer[] | Detected MCP server configs |
| `infra` | InfraProfile \| null | Infrastructure profile (Terraform, k8s, Docker) |
| `model_usages` | ModelUsage[] | Identified LLM model references |
| `findings` | ScanFinding[] | Raw scanner output |
| `metadata` | object | Scan stats (duration, file count, finding counts) |

---

## Scanners

Quin Scanner runs up to 13 plugins. Each plugin is independent, stateless, and receives the same `RepoAccessor` and `FileIndex`:

| Scanner | Files Examined | What It Detects |
|---|---|---|
| **DependencyScanner** | requirements.txt, pyproject.toml, package.json, go.mod, Cargo.toml, pom.xml, build.gradle | AI packages by ecosystem |
| **ConfigScanner** | `.env`, `.env.*` files | AI API keys (OpenAI, Anthropic, Hugging Face, Pinecone, Cohere, etc.) |
| **CodePatternScanner** | .py, .js, .ts, .go, .rs, .java | AI library imports and API call patterns |
| **FileStructureScanner** | Directory names | AI-related directory names (`agents/`, `prompts/`, `chains/`, `vector_store/`, ...) |
| **FrameworkMarkerScanner** | Config file names | Framework config files (`langgraph.json`, `crew.yaml`, `adk_config.yaml`, `.mcp.json`, `dify.yaml`, ...) |
| **PromptDiscoveryScanner** | .py, .yaml, .yml, .md, .prompt, .jinja2, .mustache | System prompts in string literals, YAML keys, and template files |
| **DockerfileScanner** | `Dockerfile`, `docker-compose.yml`, `docker-compose.yaml` | AI base images (`FROM langchain/...`) and AI pip installs |
| **JupyterScanner** | .ipynb | AI imports, API calls, and system prompts in notebook cells |
| **CIScanner** | `.github/workflows/*.yml`, `.gitlab-ci.yml`, `azure-pipelines.yml`, `.circleci/config.yml` | AI API key references and `pip install` of AI packages in CI pipelines |
| **IaCScanner** | `*.tf`, `*.yaml` (k8s/Helm) | AI-related Terraform resources and Kubernetes workloads |
| **MCPScanner** | `.mcp.json`, `claude_desktop_config.json`, `mcp.json`, and other MCP config files | MCP server name, transport type, and config path |
| **AgentInstanceScanner** | .py, .ts, .js, `agents.yaml`, `crew.yaml`, `flow.dag.yaml` | Named agent instantiations (`Agent(name="...")`, `AssistantAgent(...)`, etc.) |
| **ToolDefinitionScanner** | .py, .ts, .js | Tool/function definitions decorated with `@tool`, `@function_tool`, etc. |

---

## Capability Tags

Every `ScanFinding` carries a `capability_tag` that describes what type of AI capability it represents:

| Tag | Meaning |
|---|---|
| `llm-api` | Direct LLM API calls (OpenAI, Anthropic, Google, etc.) |
| `embeddings` | Vector embedding generation |
| `rag` | Retrieval-Augmented Generation (vector stores, similarity search) |
| `tool-use` | Function calling / tool use with LLMs |
| `multi-agent` | Multi-agent orchestration patterns |
| `memory` | Agent memory (short-term session or long-term persistent) |
| `prompt-templates` | System prompt templates (Jinja2, Mustache, YAML-defined) |
| `fine-tuning` | Model fine-tuning or training pipelines |
| `image-gen` | Image generation (DALL-E, Stable Diffusion, etc.) |
| `voice-ai` | Speech-to-text, text-to-speech, or voice agent capabilities |
| `code-gen` | Code generation, code review, or execution |
| `orchestration` | Agent orchestration frameworks (LangGraph, CrewAI, AutoGen, etc.) |

---

## Troubleshooting

### `uv: command not found`

uv is not installed or not on your `PATH`. Install it:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
# Then reload your shell or run:
source $HOME/.cargo/env    # or wherever uv was installed
```

### `ModuleNotFoundError: No module named 'quin_scanner'`

The virtual environment is not activated and you're not using `uv run`. Either:

```bash
# Option A: Use uv run (no activation needed)
uv run quin-scanner scan ./repo --config scanner-config.yaml

# Option B: Activate the venv first
source .venv/bin/activate
quin-scanner scan ./repo --config scanner-config.yaml
```

### `uv sync` fails with Python version error

Pin the correct Python version:

```bash
uv python pin 3.11
uv sync --all-extras
```

Or install Python 3.11+ and re-run `uv sync --all-extras`.

### GitHub API rate limiting

```
ERROR: GitHub API rate limit exceeded
```

Set a GitHub token to get 5,000 requests/hour (vs 60 unauthenticated):

```bash
export GITHUB_TOKEN=ghp_...
uv run quin-scanner scan https://github.com/org/repo --github-token $GITHUB_TOKEN
```

### LLM API errors

**`AuthenticationError`** — your API key is missing or invalid. Verify:

```bash
# Check it's set:
echo $OPENAI_API_KEY

# Or pass it directly:
uv run quin-scanner scan ./repo --llm-provider openai --llm-api-key sk-...
```

**`RateLimitError`** — you've exceeded your LLM provider's rate limit. Switch to a smaller or less-loaded model:

```bash
# Switch to a smaller model
quin-scanner scan ./repo --llm-provider openai --llm-model gpt-4o-mini

# Or switch provider
quin-scanner scan ./repo --llm-provider google --llm-model gemini-2.0-flash
```

### Ollama connection refused

```
ERROR: Connection refused — is Ollama running?
```

Start Ollama and pull your model:

```bash
ollama serve &         # start the Ollama server
ollama pull llama3.2   # download the model (first time only)
uv run quin-scanner scan ./repo --llm-provider ollama --llm-model llama3.2
```

### Empty or unexpected scan results

1. **Check the target path**: Ensure the local path exists and is a directory.
2. **Check exclusions**: `src/quin_scanner/rules/exclusions.yaml` lists paths that are skipped. A very deep or unusual directory structure might be matched.
3. **Check the file count**: The `metadata.file_count` in the output tells you how many files were indexed. A count of 0 suggests the accessor failed to enumerate files.
4. **Isolate the issue**: Run with `--no-llm` to check if the issue is in static scanning or LLM analysis.

### Scan is slow on large repos

Static scanning is fast (typically under 5 seconds for repos up to 10,000 files). The LLM synthesis call is the bottleneck — use a fast/cheap model:

```bash
quin-scanner scan ./repo --llm-provider openai --llm-model gpt-4o-mini
quin-scanner scan ./repo --llm-provider anthropic --llm-model claude-haiku-4-5-20251001
quin-scanner scan ./repo --llm-provider google --llm-model gemini-2.0-flash
```

---

## Development Setup

For contributing to Quin or running from source:

```bash
# 1. Clone the repository
git clone https://github.com/Gaincontrol-Pte-Ltd/quin-agent-scanner
cd quin-agent-scanner

# 2. Install uv (if not installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# 3. Install all dependencies
uv sync --all-extras

# 4. Set up your environment
cp .env.example .env
# Edit .env with your API keys

# 5. Run a scan (via uv run)
uv run quin-scanner scan ./path/to/repo --config scanner-config.yaml

# 6. Run tests
uv run pytest tests/ -v
```

### Tech Stack

- **Language**: Python 3.11+
- **CLI framework**: [click](https://click.palletsprojects.com/) 8.1+
- **Package manager**: [uv](https://docs.astral.sh/uv/) (fast, PEP 517 compliant)
- **Build backend**: [hatchling](https://hatch.pypa.io/)
- **Configuration parsing**: PyYAML 6.0+
- **Environment variables**: python-dotenv 1.2.2+
- **HTTP client**: httpx 0.27+
- **LLM SDKs**: openai 1.0+, anthropic 0.20+, google-genai 1.0+
- **Testing**: pytest 8.0+, pytest-cov 5.0+, pytest-asyncio 0.23+, respx 0.21+
- **Detection rules**: YAML data files in `src/quin_scanner/rules/`

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

```bash
# Create a branch
git checkout -b feat/my-new-scanner

# Make changes, write tests, verify
uv run pytest tests/ -v

# Open a PR against main
```

**Adding a new scanner plugin:**

1. Create `src/quin_scanner/scanners/my_scanner.py` extending `BaseScanner`
2. Implement `name() -> str` and `scan(accessor, file_index) -> list[ScanFinding]`
3. Register it in `orchestrator.py` → `_SCANNER_REGISTRY`
4. Add detection rules to `rules/*.yaml` if needed
5. Write tests in `tests/test_scanners/test_my_scanner.py`

**Adding framework detection rules:**

Most new frameworks can be supported with YAML-only changes — no code required:

```yaml
# rules/frameworks.yaml — add an entry:
- name: MyFramework
  file_markers:
    - myframework.yaml
    - .myframework.json
  confidence: 0.85
  capability_tags:
    - orchestration
    - tool-use
```

---

## Roadmap

Features are released in numbered drops:

| Drop | Theme | Status |
|---|---|---|
| **v0.1.0** | Scan Any Repo for AI | ✅ Released |
| **v0.2.0** | Understand the Risk | Planned |
| **v0.3.0** | Prove Compliance | Planned |
| **v0.4.0** | Automate in CI | Planned |
| **v0.5.0** | Scale to the Org | Planned |
| **v0.6.0** | Generate the Guardrails | Planned |
| **v0.7.0** | Make It Yours | Planned |

See [`docs/plans/2026-03-31-quin-agent-scanner-drop-plan.md`](docs/plans/2026-03-31-quin-agent-scanner-drop-plan.md) for the full drop plan.

---

## Comparison

|  | Quin Scanner | Semgrep | Trivy | Syft + Grype | Garak |
|---|---|---|---|---|---|
| AI dependency detection | ✅ 5 ecosystems | ⚠️ Community rules | ✅ General only | ✅ General only | ❌ |
| AI capability taxonomy | ✅ 12 tags | ❌ | ❌ | ❌ | ❌ |
| System prompt discovery | ✅ | ❌ | ❌ | ❌ | ❌ |
| LLM model identification | ✅ + routing | ❌ | ❌ | ❌ | ❌ |
| Agent intent analysis (LLM) | ✅ | ❌ | ❌ | ❌ | ❌ |
| MCP server detection | ✅ | ❌ | ❌ | ❌ | ❌ |
| Org-level scanning | ✅ | ⚠️ Enterprise | ✅ | ✅ | ❌ |
| No-config local run | ✅ | ⚠️ | ✅ | ✅ | ⚠️ |
| Open source | ✅ Apache-2.0 | ✅ / ⚠️ | ✅ | ✅ | ✅ |

---

## License

Apache-2.0 — see [LICENSE](LICENSE).

---

## About Gaincontrol

Quin is built by [Gaincontrol](https://gaincontrol.ai/), headquartered in Singapore. We build the infrastructure enterprises need to run AI agents safely.

Quin is one of three products in the Gaincontrol platform:

| Product | What it does |
|---|---|
| **[Quin](https://gaincontrol.ai/quin)** | AI Agent Scanner -- see every agent, trust nothing blindly |
| **[Aegis](https://gaincontrol.ai/)** | AI Identity Governance -- every agent operates only within its granted authority |
| **[Drona](https://gaincontrol.ai/)** | Safe Execution Fabric -- deterministic execution for probabilistic AI |

- **Website:** [gaincontrol.ai](https://gaincontrol.ai/)
- **About:** [gaincontrol.ai/about](https://gaincontrol.ai/about)
- **Contact:** [pixiedust@gaincontrol.ai](mailto:pixiedust@gaincontrol.ai)
