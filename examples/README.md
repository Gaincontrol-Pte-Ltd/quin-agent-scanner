# Example Reports

Sample HTML reports produced by Quin Scanner against public example repositories for each
supported agent framework. Two variants are provided per framework:

- **`report-no-llm.html`** -- static analysis only (`--no-llm`): rule-based detection, no
  LLM-written summary, agent goals, or risk narratives.
- **`report-llm.html`** -- same scan with LLM-assisted synthesis enabled, adding a narrative
  summary, per-agent goals/classification, and risk signals on top of the static findings.

> **Disclaimer:** These reports were generated as-is, by scanning the public repositories
> listed below at a single point in time, solely to demonstrate Quin's detection
> capabilities. They are not security audits, are not endorsed by the scanned projects or
> their maintainers, and may not reflect those repositories' current state (the source repos
> continue to change after the scan date). Static-analysis findings can also contain false
> positives/negatives, and LLM-synthesized narrative content can be inaccurate --
> see the note in the [main README](../README.md#quin-agent-scanner) for the general
> as-is disclaimer that applies to every Quin scan.
>
> **If you maintain one of the scanned repositories, or otherwise believe any finding in
> one of these reports is inaccurate, please [open an issue](https://github.com/Gaincontrol-Pte-Ltd/quin-agent-scanner/issues)
> or email [pixiedust@gaincontrol.ai](mailto:pixiedust@gaincontrol.ai) -- we want to know.**

## Reports

| Framework | Source repository | Path scanned |
|---|---|---|
| [Google ADK](google-adk/) | [google/adk-samples](https://github.com/google/adk-samples) | `python/agents/llm-auditor` |
| [Strands Agents (AWS)](strands-agents/) | [strands-agents/samples](https://github.com/strands-agents/samples) | `python/01-learn` |
| [Microsoft Agent Framework](microsoft-agent-framework/) | [microsoft/agent-framework](https://github.com/microsoft/agent-framework) | `python/samples` (excluding the `autogen-migration` / `semantic-kernel-migration` comparison folders) |
| [LangChain](langchain/) | [langchain-ai/rag-from-scratch](https://github.com/langchain-ai/rag-from-scratch) | repo root |
| [LangGraph](langgraph/) | [langchain-ai/langgraph-101](https://github.com/langchain-ai/langgraph-101) | repo root |
| [CrewAI](crewai/) | [crewAIInc/crewAI-examples](https://github.com/crewAIInc/crewAI-examples) | `crews/` |
| [AutoGen](autogen/) | [microsoft/autogen](https://github.com/microsoft/autogen) | `python/samples` |
| [OpenAI Agents SDK](openai-agents-sdk/) | [openai/openai-agents-python](https://github.com/openai/openai-agents-python) | `examples/` |
| [LangChain Deep Agents](langchain-deep-agents/) | [langchain-ai/deepagents](https://github.com/langchain-ai/deepagents) | `examples/` |
| [Agno](agno/) | [agno-agi/agno](https://github.com/agno-agi/agno) | `cookbook/00_quickstart`, `cookbook/02_agents`, `cookbook/03_teams` |
| [Mastra](mastra/) | [mastra-ai/weather-agent](https://github.com/mastra-ai/weather-agent) | repo root |

All scans were run on 2026-08-29. The LLM-enabled variants used a self-hosted
OpenAI-compatible (llama.cpp) endpoint; vulnerability lookups used OSV.dev only (no web-search
provider configured).
