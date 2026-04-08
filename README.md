# Quin Agent Scanner

> Scan repositories to detect GenAI and Agentic AI applications, identify which LLMs they use, and analyze agent intent from system prompts.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

Quin Agent Scanner is an open-source CLI tool that occupies a unique position in the security and governance tooling landscape: **AI-specific static analysis**. No other open-source tool combines AI dependency detection, system prompt discovery, LLM-powered agent intent analysis, and model usage identification in a single scan.

---

## Table of Contents

- [Installation](#installation)
- [What It Does](#what-it-does)
- [Supported Frameworks](#supported-frameworks)
- [Tech Stack](#tech-stack)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
- [Architecture](#architecture)
- [Environment Variables](#environment-variables)
- [Commands Reference](#commands-reference)
- [Configuration File](#configuration-file)
- [LLM Providers](#llm-providers)
- [Output Format](#output-format)
- [Scanners](#scanners)
- [Capability Tags](#capability-tags)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [Comparison](#comparison)
- [License](#license)

---

## Installation

### From PyPI (recommended)

```bash
pip install quin-scanner
```

Or with uv:

```bash
uv tool install quin-scanner
```

Then run:

```bash
quin-scanner --help
```

> For development setup (contributing to the project), see [Getting Started](#getting-started) below.

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

## Tech Stack

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

## Prerequisites

Before you begin, ensure you have the following installed on your machine:

- **Python 3.11 or higher** — [download here](https://www.python.org/downloads/)
- **uv** — the package manager used for this project:

```bash
# macOS / Linux
curl -LsSf https://astral.sh/uv/install.sh | sh

# Or via pipx
pipx install uv

# Or via Homebrew (macOS)
brew install uv

# Windows (PowerShell)
powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 | iex"
```

- **git** — for cloning and scanning GitHub repositories
- **An LLM API key** _(optional)_ — for agent intent analysis (`--no-llm` works without any key)

---

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/quin-scanner/quin-agent-scanner
cd quin-agent-scanner
```

### 2. Initialize the Environment

Install all dependencies:

```bash
uv sync --all-extras
```

### 3. Configure Environment Variables

Copy the example env file and fill in the values you need:

```bash
cp .env.example .env
```

At minimum, you only need to set variables for the services you intend to use. Open `.env` in your editor:

```bash
# For LLM-powered agent intent analysis (pick one):
OPENAI_API_KEY=sk-...
# ANTHROPIC_API_KEY=sk-ant-...
# GOOGLE_API_KEY=...

# For scanning GitHub repos or orgs:
GITHUB_TOKEN=ghp_...
```

> **Tip:** You can skip this step entirely and pass API keys as CLI flags (`--llm-api-key`, `--github-token`), or use `--no-llm` to skip LLM analysis completely.

### 4. Run Your First Scan

Scan a local repository without LLM analysis (no API key needed):

```bash
uv run quin-scanner scan ./path/to/my-repo --no-llm --output json
```

Scan a public GitHub repo:

```bash
uv run quin-scanner scan https://github.com/anthropics/anthropic-sdk-python --no-llm
```

Scan with LLM-powered agent intent analysis:

```bash
uv run quin-scanner scan ./my-repo --llm-provider openai --llm-model gpt-4o-mini
```

### 5. Choose Your Run Method

You have four options for invoking the `quin-scanner` command:

**Option A — `uv run` (no activation needed, recommended for development):**
```bash
uv run quin-scanner scan ./my-repo --no-llm
```

**Option B — activate the virtual environment:**
```bash
source .venv/bin/activate
quin-scanner scan ./my-repo --no-llm
```

**Option C — install as a global tool:**
```bash
uv tool install .
quin-scanner scan ./my-repo --no-llm
```

**Option D — editable install into an existing venv:**
```bash
pip install -e .
quin-scanner scan ./my-repo --no-llm
```

> All examples in this README use `uv run quin-scanner`. Drop the `uv run` prefix if you used Option B, C, or D.

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

## Environment Variables

### API Keys

| Variable | Description | Required For |
|---|---|---|
| `OPENAI_API_KEY` | OpenAI API key (`sk-...`) | `--llm-provider openai` |
| `ANTHROPIC_API_KEY` | Anthropic API key (`sk-ant-...`) | `--llm-provider anthropic` |
| `GOOGLE_API_KEY` | Google AI API key | `--llm-provider google` |
| `GITHUB_TOKEN` | GitHub Personal Access Token | Scanning GitHub repos or orgs |

### Optional Configuration

| Variable | Description | Default |
|---|---|---|
| `OPENAI_COMPATIBLE_URL` | Base URL for OpenAI-compatible endpoints | `http://localhost:11434/v1` |

### Setting Variables

**Via `.env` file (recommended):**

```bash
cp .env.example .env
# Edit .env with your values — it is gitignored
```

**Via shell export:**

```bash
export OPENAI_API_KEY=sk-...
export GITHUB_TOKEN=ghp_...
```

**Via CLI flags (override env vars):**

```bash
uv run quin-scanner scan ./repo --llm-api-key sk-... --github-token ghp_...
```

### GitHub Token Scopes

For scanning public repos: `public_repo` scope is sufficient.
For scanning private repos or org membership: `repo` + `read:org` scopes are required.

Create a token at [github.com/settings/tokens](https://github.com/settings/tokens).

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
# Fast scan, no LLM, JSON output to stdout
uv run quin-scanner scan ./my-repo --no-llm

# Full scan with OpenAI analysis, YAML output to file
uv run quin-scanner scan ./my-repo \
  --llm-provider openai \
  --llm-model gpt-4o \
  --output yaml \
  --output-file report.yaml

# Scan a GitHub repo on a specific branch
uv run quin-scanner scan https://github.com/org/repo \
  --branch develop \
  --no-llm \
  --output json

# Use a local Ollama model
uv run quin-scanner scan ./my-repo \
  --llm-provider ollama \
  --llm-model llama3.2

# Use any OpenAI-compatible endpoint (vLLM, LiteLLM, Azure, etc.)
uv run quin-scanner scan ./my-repo \
  --llm-provider openai-compatible \
  --openai-compatible-url http://localhost:8000/v1 \
  --llm-model my-fine-tuned-model \
  --llm-api-key dummy
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
# Scan all non-archived, non-forked repos in an org or user account, save JSON reports to ./reports/
uv run quin-scanner scan-org my-github-org \
  --github-token $GITHUB_TOKEN \
  --skip-archived \
  --skip-forks \
  --no-llm \
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
uv run quin-scanner scan-batch targets.txt --no-llm --output-dir ./reports/
```

### Available Scripts Summary

| Command | Description |
|---|---|
| `uv sync --all-extras` | Install all runtime + dev dependencies |
| `uv run quin-scanner scan TARGET --no-llm` | Scan a repo (no LLM) |
| `uv run quin-scanner scan TARGET --llm-provider openai` | Scan with OpenAI analysis |
| `uv run quin-scanner scan-org ORG_OR_USER --github-token TOKEN` | Scan entire GitHub org or user account |
| `uv run quin-scanner scan-batch targets.txt` | Batch scan from a file |
| `uv run quin-scanner --help` | Show all commands and options |
| `uv run pytest tests/ -v` | Run full test suite |
| `uv run pytest tests/ -v --cov=quin_scanner` | Run tests with coverage report |
| `uv add <package>` | Add a runtime dependency |
| `uv add --dev <package>` | Add a dev dependency |

---

## Configuration File

For repeated use or team workflows, use a configuration file instead of CLI flags on every invocation.

Copy and customize the bundled example:

```bash
cp scanner-config.yaml my-scanner-config.yaml
```

Pass it to any command:

```bash
uv run quin-scanner scan <target> --config my-scanner-config.yaml
uv run quin-scanner scan-org <org> --config my-scanner-config.yaml
```

**Full config reference (`scanner-config.yaml`):**

```yaml
# ── LLM provider ─────────────────────────────────────────────────────────────
llm:
  # Provider: openai | anthropic | google | ollama | openai-compatible
  provider: anthropic

  # Model name for the chosen provider:
  #   openai:             gpt-4o-mini, gpt-4o, o3-mini, o4-mini, ...
  #   anthropic:          claude-haiku-4-5-20251001, claude-sonnet-4-6, claude-opus-4-6
  #   google:             gemini-2.0-flash, gemini-1.5-pro, gemini-1.5-flash, ...
  #   ollama:             llama3.2, mistral, phi3, codellama, ...
  #   openai-compatible:  depends on your endpoint
  model: claude-haiku-4-5-20251001

  # API key — prefer setting via environment variable.
  api_key_env: ANTHROPIC_API_KEY    # read key from this env var (recommended)
  # api_key: sk-ant-...             # or inline (not recommended for shared configs)

  # Base URL for OpenAI-compatible endpoints (vLLM, LiteLLM, Azure, Ollama, etc.)
  # openai_compatible_url: http://localhost:11434/v1

# ── Output ───────────────────────────────────────────────────────────────────
output:
  format: json                      # json | yaml

# ── Scanners ─────────────────────────────────────────────────────────────────
scanners:
  enabled:
    - dependency       # AI packages in requirements.txt, pyproject.toml, go.mod, etc.
    - config           # AI API keys in .env files
    - code_pattern     # AI import statements in source code
    - file_structure   # AI-related directory names (agents/, prompts/, ...)
    - framework        # Framework config files (crew.yaml, langgraph.json, ...)
    - prompt_discovery # System prompts in Python, YAML, Jinja2, Mustache
    - dockerfile       # AI base images / pip installs in Dockerfile
    - jupyter          # AI usage in Jupyter notebooks (.ipynb)
    - iac              # AI services in Terraform and Kubernetes YAML
    - ci               # AI keys / installs in GitHub Actions, GitLab CI, etc.
    - mcp              # MCP server configurations
```

**Config priority** (highest to lowest): CLI flags → config file → environment variables → defaults.

---

## LLM Providers

Quin Scanner uses a **single LLM synthesis call** after all 11 scanners complete. The prompt includes pre-summarised evidence from every scanner and asks the LLM to return: the detected framework, per-agent profiles (name, type, goal, capabilities, tools, risk signals), and a plain-English narrative summary.

Configure the LLM provider with `--llm-provider`:

| Provider | Flag | Default Model | API Key Env Var | Notes |
|---|---|---|---|---|
| OpenAI | `openai` | `gpt-4o-mini` | `OPENAI_API_KEY` | Fast and cost-effective |
| Anthropic | `anthropic` | `claude-haiku-4-5-20251001` | `ANTHROPIC_API_KEY` | Recommended for most teams |
| Google | `google` | `gemini-2.0-flash` | `GOOGLE_API_KEY` | Good for high-volume scans |
| Ollama (local) | `ollama` | `llama3.2` | — | No API key, runs locally |
| OpenAI-compatible | `openai-compatible` | _(specify with `--llm-model`)_ | `OPENAI_API_KEY` or `--llm-api-key` | vLLM, LiteLLM, Azure, Bedrock |

**Run without any LLM** using `--no-llm`:

All 11 scanners still run. MCP servers, infrastructure, and model usage are still detected. Only the synthesis step (agent profiles, framework detection, narrative summary) is skipped — `framework` will be `"unknown"`, `summary` will be `""`, and `agents` / `tool_usages` will be empty lists.

**Ollama setup** (local inference, no API key needed):

```bash
# Install Ollama: https://ollama.ai
ollama pull llama3.2

uv run quin-scanner scan ./my-repo \
  --llm-provider ollama \
  --llm-model llama3.2
```

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
uv run quin-scanner scan ./repo --no-llm

# Option B: Activate the venv first
source .venv/bin/activate
quin-scanner scan ./repo --no-llm
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

**`RateLimitError`** — you've exceeded your LLM provider's rate limit. Use `--no-llm` or switch to a less-loaded model:

```bash
# Switch to a smaller model
uv run quin-scanner scan ./repo --llm-provider openai --llm-model gpt-4o-mini

# Or skip LLM entirely
uv run quin-scanner scan ./repo --no-llm
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
2. **Try `--no-llm`**: Isolate whether the issue is in static scanning or LLM analysis.
3. **Check exclusions**: `src/quin_scanner/rules/exclusions.yaml` lists paths that are skipped. A very deep or unusual directory structure might be matched.
4. **Check the file count**: The `metadata.file_count` in the output tells you how many files were indexed. A count of 0 suggests the accessor failed to enumerate files.

### Scan is slow on large repos

Static scanning is fast (typically under 5 seconds for repos up to 10,000 files). The LLM synthesis call is the bottleneck — use a fast/cheap model:

```bash
uv run quin-scanner scan ./repo --llm-provider openai --llm-model gpt-4o-mini
uv run quin-scanner scan ./repo --llm-provider anthropic --llm-model claude-haiku-4-5-20251001
uv run quin-scanner scan ./repo --llm-provider google --llm-model gemini-2.0-flash
```

Or skip LLM analysis:

```bash
uv run quin-scanner scan ./repo --no-llm
```

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full guide.

**Quick contributor workflow:**

```bash
# 1. Fork and clone
git clone https://github.com/YOUR_USERNAME/quin-agent-scanner
cd quin-agent-scanner

# 2. Set up environment
uv sync --all-extras

# 3. Create a branch
git checkout -b feat/my-new-scanner

# 4. Make changes and write tests
# ...

# 5. Verify all tests pass
uv run pytest tests/ -v

# 6. Open a PR against main
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
