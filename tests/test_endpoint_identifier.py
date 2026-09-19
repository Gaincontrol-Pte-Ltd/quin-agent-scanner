"""Tests for LLM inference endpoint detection and credential redaction."""
from __future__ import annotations

import json

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
