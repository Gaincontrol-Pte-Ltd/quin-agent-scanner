# AI-BOM (CycloneDX)

`-o cyclonedx` writes the AI parts of a repository as a [CycloneDX 1.6](https://cyclonedx.org/docs/1.6/json/) JSON BOM:

    quin-scanner scan ./my-agent-app -o cyclonedx -f ai-bom.cdx.json

It works on `scan`, `scan-batch` and `scan-org` (one BOM per repository, named `<repo>_<timestamp>.cdx.json`).

The BOM holds AI components only. For packages, generate an SBOM with [syft](https://github.com/anchore/syft) or
[cdxgen](https://github.com/CycloneDX/cdxgen) and combine the two with the
[CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli):

    syft dir:./my-agent-app -o cyclonedx-json=sbom.cdx.json
    cyclonedx merge --input-files sbom.cdx.json ai-bom.cdx.json --output-file full.cdx.json

For Dependency-Track, upload the merged `full.cdx.json`: uploading a BOM replaces the project's inventory, so uploading
the SBOM and the AI-BOM one after the other to the same project keeps only the second. Alternatively, upload each file to
a project of its own.

## What is in it

| Quin item | CycloneDX | `bom-ref` |
|---|---|---|
| Repository | `metadata.component` (`application`) | `repo` |
| Framework and version found by static detection | component, `type: framework`, with `purl` | the purl, e.g. `pkg:pypi/crewai@0.80.0` |
| Model with a literal name | component, `type: machine-learning-model`, `publisher` = provider (omitted when the provider is unknown); each use is an occurrence | `model:<provider>/<name>`, `model:unknown/<name>` without a provider |
| Agent | component, `type: application`, property `quin:kind=agent`; each instance is an occurrence. An agent without a literal name (`quin:identity=weak`) has its ID as `name` | the agent ID, e.g. `agent:researcher` |
| Tool | component, `type: application`, property `quin:kind=tool`; its definition is an occurrence | the tool ID, e.g. `tool:search` |
| MCP server | service | `service:mcp:<name>` |
| LLM endpoint (resolved address) | service, `endpoints` = redacted URLs, one per host | `service:endpoint:<host>` |
| OSV vulnerability in the framework | vulnerability, `affects` = the framework | `vuln:<id>` |

The framework is included only when static detection found it (`metadata.framework_source` is `static` in the JSON
report). When only the LLM named the framework, the BOM has no framework component and so no vulnerabilities, because
the LLM's answer can differ between runs.

Agents whose instances are all in test or example code have `scope: excluded`; production agents have `scope: required`.

Each agent instance is an `evidence.occurrences` entry with the file, the line, the instance ID as `bom-ref`, and an
`additionalContext` string such as `scope=test; model=gpt-4o; tools=search,scrape`. `tools=unknown` means the tools
could not be read from the code (e.g. `tools=get_tools()`); `multiplicity=many` means the agent is created in a loop.

The `dependencies` graph links the repository to the framework, every agent and every service, and each agent to the
tools and models it is given.

### `quin:` properties

| Property | On | Values |
|---|---|---|
| `quin:kind` | agents, tools | `agent`, `tool` |
| `quin:identity` | agents | `strong` (literal name in code), `weak` (no literal name) |
| `quin:tool-type` | tools | `tool_definition`, `external_service`, `skill`, `mcp_tool` |
| `quin:transport` | MCP servers | `stdio`, `http`, `sse`, `unknown` |
| `quin:source-file` | MCP servers | file the server is configured in |
| `quin:endpoint-kind` | endpoints | `hosted_provider`, `local`, `private`, `remote`, `unknown`; a comma-separated list (sorted) when one host has endpoints of several kinds, e.g. `hosted_provider,remote` |

## What is left out, and why

- **Anything the LLM writes**: agent goals, types and capabilities, tool service categories, and the unverified
  `llm_inferred_agents` / `llm_inferred_tools`, and a framework that only the LLM named. The BOM is built from static
  evidence only, so it is the same with or without an LLM key: the same commit, the same Quin version and the same OSV
  data give the same BOM apart from `serialNumber` (new for every BOM, as the CycloneDX spec requires) and
  `metadata.timestamp`.
- **Web-search vulnerabilities**: results from `--vuln-search-provider` can differ between runs and sometimes have no
  advisory ID. The BOM carries OSV results only; Quin prints how many web-search results it left out. They remain in
  the JSON and HTML reports.
- **Risk signals and inventory flags** such as tool divergence: the BOM is an inventory. Use the JSON report or SARIF
  for risks.
- **Unresolved and templated endpoints**: an LLM endpoint with no address is left out, and so is one whose host
  contains `$`, or whose host or URL contains any of `{ } < > " | \ ^` `` ` `` or whitespace. These are template
  placeholders such as `${HOST}` or `$HOST`, not real addresses.
- **Package dependencies**: use syft or cdxgen (above).
