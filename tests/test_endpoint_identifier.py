"""Tests for LLM inference endpoint detection and credential redaction."""
from __future__ import annotations

import json

import pytest

from quin_scanner.endpoint_identifier import EndpointIdentifier, classify_host, redact
from quin_scanner.file_index import FileIndex
from quin_scanner.repo_accessor import LocalRepoAccessor


def _find(tmp_path, files: dict[str, str]):
    for rel, body in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    acc = LocalRepoAccessor(tmp_path)
    idx = FileIndex(acc)
    idx.build()
    return EndpointIdentifier().identify(acc, idx)


class TestRedact:
    def test_userinfo(self):
        assert redact("https://admin:s3cret@llm.corp:8000/v1") == "https://REDACTED@llm.corp:8000/v1"

    def test_query_secrets(self):
        out = redact("https://x.openai.azure.com/openai?api-version=1&api-key=abc123&key=zzz")
        assert "abc123" not in out and "zzz" not in out and "api-version=1" in out

    def test_expression(self):
        assert "hunter2" not in redact('f"http://bob:hunter2@{host}/v1"')


class TestClassify:
    def test_kinds(self):
        assert classify_host("api.openai.com") == "hosted_provider"
        assert classify_host("acme.openai.azure.com") == "hosted_provider"
        assert classify_host("localhost") == "local"
        assert classify_host("127.0.0.1") == "local"
        assert classify_host("192.168.20.5") == "private"
        assert classify_host("llm.internal") == "private"
        assert classify_host("vllm") == "private"
        assert classify_host("inference.example.com") == "remote"
        assert classify_host("{host}") == "unknown"


class TestIdentify:
    def test_code_literal_base_url(self, tmp_path):
        r = _find(tmp_path, {"a.py": 'llm = ChatOpenAI(base_url="http://10.0.0.5:8000/v1", api_key="sk-secret")\n'})
        assert [(e.url, e.kind) for e in r] == [("http://10.0.0.5:8000/v1", "private")]
        assert "sk-secret" not in json.dumps([e.to_dict() for e in r])

    def test_credentials_in_url_never_stored(self, tmp_path):
        r = _find(tmp_path, {"a.py": 'c = OpenAI(base_url="https://user:pw123@llm.example.com/v1?api_key=tok999")\n'})
        blob = json.dumps([e.to_dict() for e in r])
        assert r and "pw123" not in blob and "tok999" not in blob and "user:" not in blob

    def test_hosted_url_literal(self, tmp_path):
        r = _find(tmp_path, {"a.py": 'requests.post("https://api.anthropic.com/v1/messages")\n'})
        assert r[0].kind == "hosted_provider"

    def test_ollama_style_path(self, tmp_path):
        r = _find(tmp_path, {"a.py": 'requests.post("http://localhost:11434/api/generate", json=x)\n'})
        assert r[0].kind == "local"

    def test_yaml_llm_block_only(self, tmp_path):
        cfg = "api:\n  base_url: http://192.168.20.3:3030\nhttp_llm:\n  url: \"http://192.168.20.5:8081\"\n"
        r = _find(tmp_path, {"config.yaml": cfg})
        assert [(e.url, e.key, e.line_number) for e in r] == [("http://192.168.20.5:8081", "http_llm.url", 4)]

    def test_env_file(self, tmp_path):
        r = _find(tmp_path, {".env": "OPENAI_BASE_URL=http://vllm:8000/v1\nDATABASE_URL=postgres://u:p@db/x\n"})
        assert [(e.url, e.source) for e in r] == [("http://vllm:8000/v1", "env_var")]

    def test_fstring_resolved_from_config(self, tmp_path):
        r = _find(tmp_path, {
            "config.yaml": "http_llm:\n  url: http://192.168.20.5:8081\n",
            "cli.py": "llm = ChatOpenAI(base_url=f\"{cfg['url']}/v1\")\n",
        })
        code = [e for e in r if e.source == "code"][0]
        assert code.url == "http://192.168.20.5:8081/v1" and code.resolved_from == "config.yaml:2"

    def test_unresolved_expression(self, tmp_path):
        r = _find(tmp_path, {"a.py": "c = OpenAI(base_url=os.environ['LLM_URL'])\n"})
        assert r[0].kind == "unresolved" and "LLM_URL" in r[0].url

    def test_comments_ignored(self, tmp_path):
        assert _find(tmp_path, {"a.py": '# base_url="http://x.example.com/v1"\n'}) == []


class TestFalsePositives:
    def test_build_output_and_docs_urls_ignored(self, tmp_path):
        r = _find(tmp_path, {
            "web/.next/server/m.js": 'throw new Error("see https://nextjs.org/docs/messages/foo")\n',
            "web/app.js": 'log("https://nextjs.org/docs/messages/foo")\n',
        })
        assert r == []

    def test_minified_and_long_lines_ignored(self, tmp_path):
        long = 'x=1;' * 500 + 'fetch("https://api.openai.com/v1/chat/completions")\n'
        assert _find(tmp_path, {"a.js": long, "b.min.js": 'fetch("https://api.openai.com/v1/chat/completions")\n'}) == []

    def test_generic_base_url_without_llm_context_ignored(self, tmp_path):
        r = _find(tmp_path, {"c.py": 'client = RestClient(base_url="https://api.example.com/v2")\n'})
        assert r == []

    def test_generic_base_url_with_llm_context_kept(self, tmp_path):
        r = _find(tmp_path, {"c.py": 'client = OpenAI(\n    base_url="https://api.example.com/v2",\n)\n'})
        assert [e.url for e in r] == ["https://api.example.com/v2"]

    def test_function_signature_and_passthrough_ignored(self, tmp_path):
        src = ("def make(base_url: str = API_BASE_URL, api_key: str = KEY):\n    pass\n"
               "c = ChatOpenAI(base_url=base_url)\n")
        assert _find(tmp_path, {"c.py": src}) == []

    def test_ollama_path_only_for_local_or_private(self, tmp_path):
        r = _find(tmp_path, {"a.py": 'a("https://shop.example.com/api/chat")\nb("http://10.0.0.2:11434/api/chat")\n'})
        assert [e.url for e in r] == ["http://10.0.0.2:11434/api/chat"]


class TestKnownProviders:
    """Hosts that a check of ten public AI-agent repositories found tagged `remote` although they are genuine inference providers
    (gap 18.4/18.16); `remote` is for addresses the scanner does not recognise, which the overview asks a person to approve."""

    @pytest.mark.parametrize("host", [
        "api.moonshot.ai", "api.novita.ai", "api-inference.modelscope.cn", "dashscope.aliyuncs.com", "api.tokenfactory.nebius.com",
        "api.minimax.io", "api.z.ai", "api.githubcopilot.com", "api.aimlapi.com", "api.atlascloud.ai", "api.avian.io", "api.forge.tensorblock.co",
        "api.cerebras.ai", "api.sambanova.ai", "api.deepinfra.com", "integrate.api.nvidia.com", "open.bigmodel.cn", "models.github.ai",
    ])
    def test_real_providers_are_recognised(self, host):
        assert classify_host(host) == "hosted_provider"

    @pytest.mark.parametrize("host", ["API.MOONSHOT.AI", "eu.api.moonshot.ai", "acme.cognitiveservices.azure.com", "us-central1-aiplatform.googleapis.com",
                                       "europe-west4-aiplatform.googleapis.com", "[api.z.ai]"])
    def test_case_subdomains_regional_and_bracketed_forms(self, host):
        assert classify_host(host) == "hosted_provider"

    @pytest.mark.parametrize("host", [
        "google.serper.dev", "my-provider.com", "llm.api.browser-use.com", "inference.example.com",    # not on the list: still `remote`
        "api.moonshot.ai.evil.com", "fake-api.moonshot.ai", "notapi.z.ai", "api.z.ai.attacker.net", "moonshot.ai",   # look-alikes never match
        "evil-aiplatform.googleapis.com.example.org", "aiplatform.googleapis.com.evil.io",
    ])
    def test_unlisted_and_lookalike_hosts_stay_remote(self, host):
        assert classify_host(host) == "remote"

    def test_the_original_kinds_are_unchanged(self):
        assert [classify_host(h) for h in ("api.openai.com", "localhost", "192.168.1.5", "vllm", "{host}", None)] == [
            "hosted_provider", "local", "private", "private", "unknown", "unknown"]
