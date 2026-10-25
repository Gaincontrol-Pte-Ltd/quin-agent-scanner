from quin_scanner.models import SkillRecord
from quin_scanner.repo_accessor import LocalRepoAccessor
from quin_scanner.scanners.skills.bundle import (
    MAX_EVIDENCE_CHARS,
    SkillBundle,
    evidence,
    file_kind,
    load_bundle,
)


def test_file_kind():
    assert file_kind("a/SKILL.md") == "markdown"
    assert file_kind("a/run.py") == "code"
    assert file_kind("a/run.sh") == "shell"
    assert file_kind("a/package.json") == "config"
    assert file_kind("a/requirements.txt") == "text"
    assert file_kind("a/Makefile") == "shell"
    assert file_kind("a/logo.png") is None


def test_evidence_collapses_whitespace_and_caps():
    text = "a\n\n   b\t" + "x" * 1000
    out = evidence(text)
    assert out.startswith("a b ")
    assert len(out) <= MAX_EVIDENCE_CHARS + 1  # trailing ellipsis


def test_evidence_redacts_secrets():
    out = evidence("export API_KEY=abcd1234efgh5678ijkl and sk-abcdefghijklmnopqrstuvwxyz123456")
    assert "abcd1234efgh5678ijkl" not in out
    assert "sk-abcdefghijklmnopqrstuvwxyz123456" not in out
    assert "REDACTED" in out


def test_evidence_redacts_url_credentials():
    assert "hunter2" not in evidence("curl https://user:hunter2@example.com/x")


def test_from_texts_builds_record_and_files():
    b = SkillBundle.from_texts({"SKILL.md": "hi", "run.py": "print(1)"}, name="demo")
    assert b.record.name == "demo"
    assert b.record.skill_md_path == "SKILL.md"
    assert [f.path for f in b.of_kind("code")] == ["run.py"]


def test_load_bundle_skips_binary_oversize_and_unreadable(tmp_path):
    d = tmp_path / "skills" / "demo"
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text("# demo")
    (d / "run.py").write_text("print(1)")
    (d / "blob.py").write_text("a\x00b")
    (d / "big.py").write_text("x" * 1_000_001)
    (d / "logo.png").write_bytes(b"\x89PNG")
    record = SkillRecord(
        id="1",
        name="demo",
        description="",
        root_path="skills/demo",
        skill_md_path="skills/demo/SKILL.md",
        files=[
            "skills/demo/SKILL.md",
            "skills/demo/run.py",
            "skills/demo/blob.py",
            "skills/demo/big.py",
            "skills/demo/logo.png",
            "skills/demo/missing.py",
        ],
    )
    bundle = load_bundle(record, LocalRepoAccessor(tmp_path))
    assert sorted(f.path for f in bundle.files) == ["skills/demo/SKILL.md", "skills/demo/run.py"]
    reasons = " ".join(bundle.skipped)
    assert "blob.py: binary" in reasons
    assert "big.py: too large" in reasons
    assert "missing.py: unreadable" in reasons
    assert "logo.png" not in reasons  # non-text files are ignored silently


def test_load_bundle_caps_file_count(tmp_path):
    d = tmp_path / "s"
    d.mkdir()
    paths = []
    for i in range(510):
        (d / f"f{i}.py").write_text("x = 1")
        paths.append(f"s/f{i}.py")
    record = SkillRecord(id="1", name="s", description="", root_path="s", skill_md_path="", files=paths)
    bundle = load_bundle(record, LocalRepoAccessor(tmp_path))
    assert len(bundle.files) == 500
    assert any("10 files beyond cap" in s for s in bundle.skipped)
    assert bundle.capped is True


def test_evidence_redacts_more_secret_shapes():
    from quin_scanner.scanners.skills.bundle import evidence

    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcDEF123_-xyz"
    secrets = {
        "Authorization: Bearer abc123tokenvalue": "abc123tokenvalue",
        "Authorization: Basic dXNlcjpwYXNzd29yZA==": "dXNlcjpwYXNzd29yZA",
        "Authorization: token ghs_zzzzzzzzzz": "ghs_zzzzzzzzzz",
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG": "wJalrXUtnFEMI",
        "export MY_DB_PASSWD=hunter22xyz": "hunter22xyz",
        "GITHUB_TOKEN=abcd1234": "abcd1234",
        f"x = {jwt}": jwt,
        "password=abc123": "abc123",
        "api_key: s3cr3t": "s3cr3t",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxyz\n-----END RSA PRIVATE KEY-----": "MIIEowIBAAKCAQEAxyz",
        "-----BEGIN PRIVATE KEY-----": "BEGIN PRIVATE KEY",
    }
    for text, secret in secrets.items():
        out = evidence(text)
        assert secret not in out, (text, out)
