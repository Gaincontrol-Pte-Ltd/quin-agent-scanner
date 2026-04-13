# Changelog

All notable changes to Quin Agent Scanner are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Added

#### Scanner Plugins (+2, now 13 total)
- `tool_definition` — extracts named tool definitions from code via `@tool`, `@function_tool`, `@register_tool`, `@kernel_function`, `@register_function` decorators, `BaseTool` / `StructuredTool` class inheritance, tool registration calls (`register_tool()`, `server.tool()`), and Markdown tool-definition tables
- `agent_instance` — extracts named agent instantiations from code (`Agent(name=...)`, `AssistantAgent`, `UserProxyAgent`, `ConversableAgent`, etc.) and YAML/JSON agent config files

#### Risk Taxonomy & Classification
- `risk_taxonomy.yaml` — structured threat catalog sourced from OWASP LLM Top 10, OWASP Agentic Top 10, OWASP MCP Top 10, MAESTRO, and Databricks DASF
- `risk_taxonomy.py` — loader and query interface for the threat taxonomy
- `classification_agent.py` — LLM Pass 1 that classifies system type (`standard_ai`, `agentic_ai`, `mcp_enabled`, `multi_agent`) and identifies relevant threats from the taxonomy
- `RiskIndicator` dataclass — pairs a key risk indicator signal with its recommended controls
- `ClassificationResult` dataclass — captures system types and relevant threat IDs
- Repo-level `risk_signals` field on `SynthesisResult` and `ScanReport`

#### External Service Detection
- `tool_services.yaml` — maps high-signal packages to service categories: web search, web browsing, code execution, database access, file system, email, and more
- `ToolUsage` now includes `tool_type` (tool_definition / external_service / skill / mcp_tool) and `service_category`

#### Signal Groups
- `signal_groups.yaml` — cross-scanner framework corroboration rules that boost confidence when multiple co-occurring signals appear (e.g. OpenClaw: `SOUL.md` + `AGENTS.md` + `openclaw.json`)

#### HTML Report Output
- `html_template.py` — self-contained HTML report template with embedded JS dashboard
- `--format html` output option via `ReportGenerator.to_html()`

#### Detection Rules (expanded)
- New entries in `code_patterns.yaml`, `dependencies.yaml`, `file_markers.yaml`, `frameworks.yaml`, and `frameworks_lookup.yaml`

### Changed
- `findings` field renamed to `artifacts` in `ScanReport` output
- `risk_signals` on `AgentProfile` changed from `list[str]` to `list[RiskIndicator]` (now includes recommended controls)
- CLI help text and option descriptions overhauled for all scan commands
- Orchestrator expanded with two-pass LLM pipeline (classification → synthesis)

### Fixed
- Removed compiled Python bytecache files (`.pyc`) from repository

### Maintenance
- Updated dependency versions in `pyproject.toml`
- Updated scanner configuration defaults in `scanner-config.yaml`
- PyPI publish workflow switched to OIDC authentication with `contents: read` permission
- Updated project branding, repository URL, and company information in README
- Removed testing documentation and references from project files

---

## [0.1.0] — 2026-03-31

**Drop 1 — Scan Any Repo for AI**

### Added

#### Scan Modes
- `scan` command — scan a local folder or GitHub repo URL
- `scan-org` command — scan all repos in a GitHub org sequentially
- `scan-batch` command — scan multiple targets from a file
- `GitHubAPIAccessor` — shallow-clone any GitHub repo URL via REST API
- `GitHubMCPAccessor` — MCP-based accessor for interactive use
- `RepoAccessorFactory` — auto-selects accessor from target string (local path vs GitHub URL)
- `--github-token` flag and `GITHUB_TOKEN` env var for GitHub PAT authentication
- `--skip-archived` and `--skip-forks` flags on `scan-org`

#### Scanner Plugins (11 total)
- `dependency` — AI packages in requirements.txt, pyproject.toml, package.json, go.mod, Cargo.toml, pom.xml, build.gradle
- `code_pattern` — AI imports and API calls in .py, .js, .ts, .go, .rs, .java
- `config` — AI API keys in .env and config files
- `file_structure` — AI-related directories (prompts/, agents/, chains/, vector_store/)
- `framework` — framework config files (langgraph.json, crew.yaml, .mcp.json, dify.yaml, and 10+ more)
- `prompt_discovery` — system prompts from Python strings, YAML, .prompt, .jinja2, .mustache
- `dockerfile` — AI base images and pip installs in Dockerfile and docker-compose
- `jupyter` — AI imports and prompts in Jupyter notebooks (.ipynb)
- `ci` — AI API keys and installs in GitHub Actions, GitLab CI, Azure Pipelines, CircleCI, Jenkins
- `iac` — AI services in Terraform (.tf) and Kubernetes/Helm YAML
- `mcp` — MCP server configs (.mcp.json, claude_desktop_config.json, cline settings, etc.)

#### Framework Detection (23+ frameworks)
- LangChain, LangGraph, CrewAI, AutoGen, OpenAI Agents SDK
- **New**: Anthropic Agent SDK (`claude-agent-sdk`)
- **New**: Google ADK (`google-adk`)
- **New**: Databricks Agent Framework (`databricks-agents`)
- LlamaIndex, Haystack, Semantic Kernel, Dify, Flowise, PromptFlow, Vercel AI SDK, MCP

#### LLM Model Identification
- `model_identifier.py` — detects LLM model names from code, config files, and env vars
- Identifies provider (openai, anthropic, google, meta, mistral, cohere, aws, databricks)
- Detects primary/fallback routing patterns from YAML config and code structures
- `rules/models.yaml` — known model name registry across all major providers
- `ModelUsage` dataclass with provider, model_name, source, file_path, line_number, role
- `model_usages` section added to `ScanReport` output

#### LLM Providers (5 total)
- OpenAI (`openai`) — default model: `gpt-4o-mini`
- Anthropic (`anthropic`) — default model: `claude-haiku-4-5-20251001`
- Google (`google`) — default model: `gemini-2.0-flash`
- Ollama (`ollama`) — default model: `llama3.2`
- **New**: OpenAI-compatible (`openai-compatible`) — any endpoint implementing the OpenAI chat API (vLLM, LiteLLM, Azure OpenAI, AWS Bedrock via gateway, LocalAI)
- `--openai-compatible-url` flag for base URL configuration

#### Output & Configuration
- JSON and YAML output formats
- `--no-llm` flag — run all 11 scanners without LLM calls
- `--output-file` flag — write report to file instead of stdout
- `--config` flag — load settings from `scanner-config.yaml`
- `--branch` flag — specify git branch for GitHub URL scans

#### Detection Rules
- `dependencies.yaml` — 100+ AI packages across PyPI, npm, Go, crates.io, Maven
- `code_patterns.yaml` — 60+ regex patterns across Python, JS, TS, Go, Rust, Java
- `file_markers.yaml` — AI-related directory and file extension markers
- `frameworks.yaml` — 23+ framework config file signatures
- `models.yaml` — known LLM model names by provider

#### 12 Capability Tags
`llm-api` · `embeddings` · `rag` · `tool-use` · `multi-agent` · `memory` · `prompt-templates` · `fine-tuning` · `image-gen` · `voice-ai` · `code-gen` · `orchestration`

---

[Unreleased]: https://github.com/quin-scanner/quin-agent-scanner/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/quin-scanner/quin-agent-scanner/releases/tag/v0.1.0
