"""HTTPS for the few calls made with urllib (the GitHub API).

Some Pythons ship no CA bundle (python.org builds for macOS until "Install Certificates.command" is run), and every
verified HTTPS request then fails. The context used here trusts the system store *and* the ``certifi`` bundle, so it
works there and still honours a corporate CA configured through the system or ``SSL_CERT_FILE``.
"""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from urllib.parse import urlsplit


class TLSVerificationError(RuntimeError):
    """The server's certificate could not be verified."""


def ssl_context() -> ssl.SSLContext:
    context = ssl.create_default_context()  # system store, SSL_CERT_FILE / SSL_CERT_DIR
    try:
        import certifi

        context.load_verify_locations(cafile=certifi.where())
    except (ImportError, OSError):  # certifi missing or unreadable: keep whatever the system trusts
        pass
    return context


def urlopen(request: urllib.request.Request | str, timeout: float = 30):
    """``urllib.request.urlopen`` with the context above and a readable error when verification fails."""
    try:
        return urllib.request.urlopen(request, timeout=timeout, context=ssl_context())
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, ssl.SSLCertVerificationError):
            url = request if isinstance(request, str) else request.full_url
            raise TLSVerificationError(
                f"Could not verify the TLS certificate of {urlsplit(url).hostname}. Install your system's root certificates "
                "(on macOS with python.org Python, run 'Install Certificates.command'), or set SSL_CERT_FILE to a CA bundle."
            ) from exc
        raise
