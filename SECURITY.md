# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x (beta) | ✅ Yes    |

## Reporting a Vulnerability

If you discover a security vulnerability in Quin Agent Scanner, please **do not** open a public GitHub Issue.

Instead, report it via **GitHub Private Security Advisories**:

1. Go to the repository on GitHub
2. Click **Security** → **Advisories** → **Report a vulnerability**
3. Provide a description of the issue, steps to reproduce, and potential impact

We aim to acknowledge reports within **5 business days** and resolve confirmed vulnerabilities within **90 days** of disclosure.

## Scope

This policy covers the `quin-scanner` Python package and its source code. It does not cover:
- Third-party dependencies (report those to the respective upstream projects)
- Issues in repositories that `quin-scanner` scans (those are the user's responsibility)

## Verifying releases

Releases are published to PyPI from this repository's GitHub Actions workflow using PyPI trusted publishing, and each file carries a PEP 740 attestation that names the repository and workflow that built it. Check a file with PyPI's integrity API, for example `https://pypi.org/integrity/quin-scanner/<version>/<filename>/provenance` (use the `Accept: application/vnd.pypi.integrity.v1+json` header), or with a tool that verifies PEP 740 attestations.

## Handling of untrusted input

Quin reads repositories, skills and archives that you do not control, so the following are in scope for a report:

- Anything that makes Quin execute code from a scanned repository, skill, archive or LLM response.
- Writing outside the temporary directory when extracting a `.zip` for `quin-scanner skills scan`, or exceeding its limits (5000 members, 200 MB uncompressed) without an error. Archives with absolute paths, `..` components, symlinks or special files are rejected.
- Credentials from a scanned repository leaking into reports or into text sent to an LLM. Evidence snippets are redacted before they are stored, and with LLM review enabled only flagged, redacted snippets are sent, never whole files.

## Disclosure Policy

Once a fix is available, we will publish a GitHub Security Advisory with full details. We follow coordinated disclosure — we ask that reporters keep details private until a fix is released.
