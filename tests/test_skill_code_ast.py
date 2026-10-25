# tests/test_skill_code_ast.py
from quin_scanner.scanners.skills.analyzers.code_ast import analyze_python
from quin_scanner.scanners.skills.bundle import SkillBundle


def _scan(code):
    return analyze_python(SkillBundle.from_texts({"run.py": code}))


def _by_rule(findings):
    return {f.rule_id: f for f in findings}


def test_eval_of_dynamic_input_is_high():
    [f] = _scan("def f(x):\n    return eval(x)\n")
    assert f.rule_id == "SK-CODE-001" and f.severity == "high" and f.line_number == 2


def test_eval_of_constant_is_medium():
    [f] = _scan("eval('1+1')\n")
    assert f.rule_id == "SK-CODE-001" and f.severity == "medium"


def test_decoded_payload_exec_is_critical_obfuscation():
    [f] = _scan("exec(__import__('base64').b64decode('cHJpbnQoMSk='))\n")
    assert f.rule_id == "SK-CODE-005" and f.severity == "critical"


def test_shell_true_with_dynamic_command():
    f = _by_rule(_scan("import subprocess\nsubprocess.run(cmd, shell=True)\n"))["SK-CODE-002"]
    assert f.severity == "high"


def test_shell_true_with_constant_command_is_medium():
    f = _by_rule(_scan("import subprocess\nsubprocess.run('ls', shell=True)\n"))["SK-CODE-002"]
    assert f.severity == "medium"


def test_subprocess_without_shell_is_not_flagged():
    assert _scan("import subprocess\nsubprocess.run(['ls', '-la'])\n") == []


def test_os_system_dynamic_is_high():
    f = _by_rule(_scan("import os\nos.system(f'rm {path}')\n"))["SK-CODE-002"]
    assert f.severity == "high"


def test_unsafe_deserialization():
    assert "SK-CODE-003" in _by_rule(_scan("import pickle\npickle.loads(data)\n"))
    assert "SK-CODE-003" in _by_rule(_scan("import yaml\nyaml.load(text)\n"))
    assert _scan("import yaml\nyaml.load(text, Loader=yaml.SafeLoader)\n") == []


def test_dynamic_import_flagged_constant_not():
    assert "SK-CODE-004" in _by_rule(_scan("import importlib\nimportlib.import_module(name)\n"))
    assert _scan("import importlib\nimportlib.import_module('json')\n") == []


def test_syntax_error_and_non_python_are_ignored():
    assert _scan("def broken(:\n") == []
    assert analyze_python(SkillBundle.from_texts({"run.sh": "eval $X"})) == []


def test_clean_code_has_no_findings():
    assert _scan("import json\n\ndef load(p):\n    return json.loads(open(p).read())\n") == []
