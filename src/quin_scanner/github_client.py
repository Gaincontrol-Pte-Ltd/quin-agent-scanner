"""GitHub REST API client for listing org repos and repo metadata."""
from __future__ import annotations
import json
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class RepoInfo:
    owner: str
    name: str
    full_name: str
    clone_url: str
    default_branch: str
    archived: bool = False
    fork: bool = False
    description: str = ""
    topics: list[str] = field(default_factory=list)


class GitHubClient:
    """Minimal GitHub REST API v3 client."""

    BASE_URL = "https://api.github.com"

    def __init__(self, token: str | None = None):
        self.token = token

    def _request(self, path: str) -> dict | list:
        url = f"{self.BASE_URL}{path}"
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())

    def _paginate(self, path: str) -> Iterator[dict]:
        page = 1
        while True:
            sep = "&" if "?" in path else "?"
            data = self._request(f"{path}{sep}per_page=100&page={page}")
            if not data:
                break
            for item in data:
                yield item
            if len(data) < 100:
                break
            page += 1

    def list_org_repos(
        self,
        org: str,
        skip_archived: bool = False,
        skip_forks: bool = False,
    ) -> list[RepoInfo]:
        repos = []
        for item in self._paginate(f"/orgs/{org}/repos?type=all"):
            if skip_archived and item.get("archived"):
                continue
            if skip_forks and item.get("fork"):
                continue
            repos.append(RepoInfo(
                owner=item["owner"]["login"],
                name=item["name"],
                full_name=item["full_name"],
                clone_url=item["clone_url"],
                default_branch=item.get("default_branch", "main"),
                archived=item.get("archived", False),
                fork=item.get("fork", False),
                description=item.get("description") or "",
                topics=item.get("topics", []),
            ))
        return repos

    def list_user_repos(
        self,
        username: str,
        skip_archived: bool = False,
        skip_forks: bool = False,
    ) -> list[RepoInfo]:
        repos = []
        for item in self._paginate(f"/users/{username}/repos?type=owner"):
            if skip_archived and item.get("archived"):
                continue
            if skip_forks and item.get("fork"):
                continue
            repos.append(RepoInfo(
                owner=item["owner"]["login"],
                name=item["name"],
                full_name=item["full_name"],
                clone_url=item["clone_url"],
                default_branch=item.get("default_branch", "main"),
                archived=item.get("archived", False),
                fork=item.get("fork", False),
                description=item.get("description") or "",
                topics=item.get("topics", []),
            ))
        return repos

    def list_repos_for(
        self,
        name: str,
        skip_archived: bool = False,
        skip_forks: bool = False,
    ) -> list[RepoInfo]:
        """List repos for an org or user account, auto-detecting the type."""
        try:
            return self.list_org_repos(name, skip_archived=skip_archived, skip_forks=skip_forks)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return self.list_user_repos(name, skip_archived=skip_archived, skip_forks=skip_forks)
            raise

    def get_repo(self, owner: str, repo: str) -> RepoInfo:
        item = self._request(f"/repos/{owner}/{repo}")
        return RepoInfo(
            owner=item["owner"]["login"],
            name=item["name"],
            full_name=item["full_name"],
            clone_url=item["clone_url"],
            default_branch=item.get("default_branch", "main"),
            archived=item.get("archived", False),
            fork=item.get("fork", False),
            description=item.get("description") or "",
            topics=item.get("topics", []),
        )
