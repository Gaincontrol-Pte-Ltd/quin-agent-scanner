"""HTTPS calls made with urllib must verify certificates on Pythons that ship no CA bundle (UAT finding U3)."""
from __future__ import annotations

import ssl
import subprocess
import sys
import urllib.error
import urllib.request

import pytest

NO_SYSTEM_CAS = {"SSL_CERT_FILE": "/nonexistent/cert.pem", "SSL_CERT_DIR": "/nonexistent/certs"}


def _ca_count(expr: str) -> int:
    import os

    env = {**os.environ, **NO_SYSTEM_CAS}
    out = subprocess.run([sys.executable, "-c", expr], capture_output=True, text=True, env=env, check=True)
    return int(out.stdout.strip())


@pytest.mark.skipif(sys.platform == "win32", reason="Windows always loads the system certificate store, whatever SSL_CERT_FILE says")
def test_a_python_without_a_ca_bundle_would_have_no_trusted_certificates():
    # This is the python.org-on-macOS situation: the default context trusts nothing.
    assert _ca_count("import ssl; print(ssl.create_default_context().cert_store_stats()['x509_ca'])") == 0


def test_the_context_still_trusts_the_certifi_bundle_when_the_system_has_none():
    assert _ca_count("from quin_scanner._http import ssl_context; print(ssl_context().cert_store_stats()['x509_ca'])") > 100


def test_the_context_verifies_certificates_and_hostnames():
    from quin_scanner._http import ssl_context

    ctx = ssl_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True


def test_a_certificate_failure_becomes_a_one_line_actionable_error(monkeypatch):
    from quin_scanner import _http

    def boom(*args, **kwargs):
        raise urllib.error.URLError(ssl.SSLCertVerificationError(1, "certificate verify failed: unable to get local issuer certificate"))

    monkeypatch.setattr(urllib.request, "urlopen", boom)
    with pytest.raises(_http.TLSVerificationError) as info:
        _http.urlopen(urllib.request.Request("https://api.github.com/x"), timeout=5)
    message = str(info.value)
    assert "api.github.com" in message and "SSL_CERT_FILE" in message and "\n" not in message


def test_other_network_errors_pass_through_unchanged(monkeypatch):
    from quin_scanner import _http

    def refused(*args, **kwargs):
        raise urllib.error.URLError(ConnectionRefusedError(61, "refused"))

    monkeypatch.setattr(urllib.request, "urlopen", refused)
    with pytest.raises(urllib.error.URLError):
        _http.urlopen(urllib.request.Request("https://api.github.com/x"), timeout=5)


def test_the_github_clients_use_the_shared_helper():
    import inspect

    from quin_scanner import github_client, repo_accessor

    for module in (github_client, repo_accessor):
        source = inspect.getsource(module)
        assert "urllib.request.urlopen" not in source, f"{module.__name__} must go through quin_scanner._http.urlopen"


def test_a_certificate_problem_is_not_retried():
    from quin_scanner._http import TLSVerificationError
    from quin_scanner.repo_accessor import _is_permanent_error

    assert _is_permanent_error(TLSVerificationError("x")) is True
