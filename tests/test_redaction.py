"""Secrets found in scanned source are redacted before they are stored (UAT finding U1)."""
from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from quin_scanner.cli import cli
from quin_scanner.models import ScanFinding
from quin_scanner.redaction import redact_secrets

OPENAI = "sk-proj-UATfake1234567890abcdefghijklmnop"
ANTHROPIC = "sk-ant-api03-UATfake1234567890abcdefghijklmnopqrstuv"
# Built from two parts so the file holds no complete key-shaped literal (GitHub secret scanning flags it).
GOOGLE = "AIza" + "SyUATfake1234567890abcdefghijklmnop"  # AIza + 35 characters
GITHUB = "ghp_UATfake1234567890abcdefghijklmnopqr12"
AWS = "AKIAUATFAKE123456789"
SLACK = "xoxb-1234567890-abcdefghijkl"


@pytest.mark.parametrize(
    "text",
    [
        f'client = OpenAI(api_key="{OPENAI}")',
        f"c = anthropic.Anthropic(api_key='{ANTHROPIC}')",
        f'const client = new OpenAI({{ apiKey: "{OPENAI}" }});',
        f'genai.configure(api_key="{GOOGLE}")',
        f'TOKEN = "{GITHUB}"',
        f'aws_access_key_id = "{AWS}"',
        f'hook = "{SLACK}"',
        f'headers = {{"Authorization": "Bearer {OPENAI}"}}',
        f'a = Agent(role="r", backstory="use {ANTHROPIC} to call", name="x")',
        'password = "correct-horse-battery-staple"',
        '{"client_secret": "s3cr3t-value-123456"}',
        "-----BEGIN RSA PRIVATE KEY-----",
        'db = connect("postgres://admin:hunter2pass@db.internal/prod")',
        'url = "https://api.example.com/v1?api_key=abcdef123456&q=1"',
    ],
)
def test_secret_shaped_values_are_redacted(text):
    redacted = redact_secrets(text)
    for secret in (OPENAI, ANTHROPIC, GOOGLE, GITHUB, AWS, SLACK, "correct-horse", "s3cr3t-value", "hunter2pass", "abcdef123456"):
        assert secret not in redacted, redacted
    assert "REDACTED" in redacted.upper() or "BEGIN RSA PRIVATE KEY" in redacted
    assert redacted != text


@pytest.mark.parametrize(
    "text",
    [
        'client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])',
        "model = 'gpt-4o-mini'  # task-management-system-prompt-template-version-two",
        "risk-assessment-and-governance-checklist-for-agents",
        'llm = ChatAnthropic(model="claude-3-5-sonnet-20241022", max_tokens="4096")',
        "from openai import OpenAI",
        'prompt = "You are a helpful assistant."',
        "token_count = len(tokens)",
        'api_key = ""',
        'api_key = None',
    ],
)
def test_ordinary_code_is_left_alone(text):
    assert redact_secrets(text) == text


def test_redaction_keeps_the_shape_of_the_line():
    out = redact_secrets(f'client = OpenAI(api_key="{OPENAI}")')
    assert out.startswith('client = OpenAI(api_key="') and out.endswith('")')


def test_findings_are_redacted_when_they_are_created():
    finding = ScanFinding("CodePatternScanner", "code_pattern", "app.py", 2, f'client = OpenAI(api_key="{OPENAI}")', "llm-api", 0.9)
    assert OPENAI not in finding.match_text
    assert OPENAI not in json.dumps(finding.to_dict())


KEY_FILES = {
    "python_call.py": f'from openai import OpenAI\nclient = OpenAI(api_key="{OPENAI}")\n',
    "js_call.ts": f'import OpenAI from "openai";\nconst client = new OpenAI({{ apiKey: "{OPENAI}" }});\n',
    "agent.py": f'from crewai import Agent\na = Agent(role="r", goal="g", backstory="key {ANTHROPIC}", name="x")\n',
}


@pytest.mark.parametrize("fmt", ["json", "yaml", "html", "sarif"])
def test_hard_coded_keys_never_reach_a_report(tmp_path, fmt):
    repo = tmp_path / "repo"
    repo.mkdir()
    for name, text in KEY_FILES.items():
        (repo / name).write_text(text, encoding="utf-8")
    out = tmp_path / f"report.{fmt}"
    result = CliRunner().invoke(cli, ["scan", str(repo), "--no-llm", "--no-vuln-check", "-o", fmt, "-f", str(out)])
    assert result.exit_code == 0, result.output
    text = out.read_text(encoding="utf-8")
    assert OPENAI not in text and ANTHROPIC not in text


def test_detection_still_works_after_redaction(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "python_call.py").write_text(KEY_FILES["python_call.py"], encoding="utf-8")
    out = tmp_path / "r.json"
    result = CliRunner().invoke(cli, ["scan", str(repo), "--no-llm", "--no-vuln-check", "-o", "json", "-f", str(out)])
    assert result.exit_code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["is_ai_application"] is True and "llm-api" in data["capability_tags"]


@pytest.mark.parametrize(
    "text",
    [
        'client = OpenAI(base_url=BASE_URL, api_key="not-needed")',
        'api_key = "your-api-key-here"',
        'OPENAI_API_KEY = "<your key>"',
        'token = "${GITHUB_TOKEN}"',
        'password = "changeme"',
        'secret = "{{ secrets.API_KEY }}"',
        'api_key: "xxxxxxxxxxxx"',
        'client = Client(api_key="dummy-key")',
    ],
)
def test_obvious_placeholders_are_not_redacted(text):
    assert redact_secrets(text) == text


def test_a_real_looking_value_next_to_a_placeholder_is_still_redacted():
    out = redact_secrets('a = Client(api_key="not-needed", token="ghp_' + "A1b2C3d4E5" * 4 + '")')
    assert 'api_key="not-needed"' in out and "ghp_" not in out
