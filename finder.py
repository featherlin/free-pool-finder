#!/usr/bin/env python3
from __future__ import annotations

import base64
import binascii
import json
import os
import random
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import quote
from zoneinfo import ZoneInfo

import requests
import yaml


ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.yaml"
KNOWN_PATH = ROOT / "known_sources.json"
REPORTS_DIR = ROOT / "reports"

GITHUB_API = "https://api.github.com"
RAW_HOST = "https://raw.githubusercontent.com"
RAW_READ_LIMIT = 3 * 1024 * 1024
REPORT_TZ = ZoneInfo("Asia/Shanghai")

UA = "free-pool-finder/1.0"
FORMAT_PRIORITY = {"base64": 3, "plain": 3, "clash": 1}
DISCARDED_FORMATS = {"singbox(弃)", "http-socks(弃)", "unknown"}

PROTOCOL_RE = re.compile(
    r"\b(?:vless|vmess|trojan|ssr?|hysteria2?|hy2|tuic)://[^\s'\"<>]+",
    re.IGNORECASE,
)
TOP_LEVEL_PROXIES_RE = re.compile(r"(?m)^proxies\s*:")
CLASH_NODE_RE = re.compile(r"(?m)^\s*-\s*name\s*:")
OUTBOUNDS_RE = re.compile(r"\boutbounds\b", re.IGNORECASE)
HTTP_SOCKS_RE = re.compile(r"(?m)^(?:https?|socks5?)://\d", re.IGNORECASE)
BASE64_CHARS_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")

SUB_FILE_RE = re.compile(
    r"""
    (?ix)
    (^|/)
    (?:
        (?:all[_-]?)?subs?(?:cription)?s?
      | base64
      | v2ray(?:[_-]?(?:base64|nodes?|subs?|configs?))?
      | vless(?:[_-]?(?:base64|nodes?|subs?|configs?))?
      | vmess(?:[_-]?(?:base64|nodes?|subs?|configs?))?
      | trojan(?:[_-]?(?:base64|nodes?|subs?|configs?))?
      | hysteria2?(?:[_-]?(?:nodes?|subs?|configs?))?
      | hy2(?:[_-]?(?:nodes?|subs?|configs?))?
      | tuic(?:[_-]?(?:nodes?|subs?|configs?))?
      | nodes?
      | nodefree
      | clash
      | mihomo
      | configs?(?:[_-]?base64)?
      | black[_-]?vless
      | proxies?
    )
    [^/]*
    \.(?:txt|yaml|yml)$
    """
)


@dataclass(frozen=True)
class Detection:
    format: str
    nodes: int


class GitHubNotFound(Exception):
    pass


class GitHubRequestError(Exception):
    pass


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_github_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def iso_date(value: datetime | None) -> str:
    if value is None:
        return ""
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d")


def md_escape(value: Any, max_len: int | None = None) -> str:
    if value is None:
        text = ""
    else:
        text = str(value)
    text = " ".join(text.replace("|", r"\|").split())
    if max_len is not None and len(text) > max_len:
        text = text[: max_len - 1].rstrip() + "…"
    return text


def repo_api_path(full_name: str) -> str:
    owner, repo = full_name.split("/", 1)
    return f"/repos/{quote(owner, safe='')}/{quote(repo, safe='')}"


def raw_url(owner: str, repo: str, branch: str, path: str) -> str:
    branch_q = quote(branch, safe="")
    path_q = quote(path, safe="/")
    return f"{RAW_HOST}/{owner}/{repo}/{branch_q}/{path_q}"


def mirror_url(mirror_template: str, owner: str, repo: str, branch: str, path: str) -> str:
    path_q = quote(path, safe="/")
    return mirror_template.format(owner=owner, repo=repo, branch=branch, path=path_q)


class GitHubClient:
    def __init__(self, token: str | None) -> None:
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": UA,
            }
        )
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        url = path if path.startswith("http") else f"{GITHUB_API}{path}"
        last_error: str | None = None

        for attempt in range(6):
            try:
                resp = self.session.get(url, params=params, timeout=30)
            except requests.RequestException as exc:
                last_error = str(exc)
                self._sleep_before_retry(attempt, f"network error: {exc}")
                continue

            if resp.status_code == 404:
                raise GitHubNotFound(url)

            if self._is_primary_rate_limited(resp):
                reset_at = self._rate_limit_reset(resp)
                wait = max(1, int(reset_at - time.time()) + 5)
                print(f"[rate-limit] GitHub primary limit hit; sleeping {wait}s", file=sys.stderr)
                time.sleep(wait)
                continue

            if resp.status_code in {403, 429}:
                body = resp.text.lower()
                if "secondary rate limit" in body or "abuse detection" in body:
                    self._sleep_before_retry(attempt, "secondary rate limit")
                    continue

            if resp.status_code >= 500 or resp.status_code == 429:
                self._sleep_before_retry(attempt, f"HTTP {resp.status_code}")
                continue

            if resp.status_code >= 400:
                raise GitHubRequestError(f"{url} returned HTTP {resp.status_code}: {resp.text[:300]}")

            try:
                return resp.json()
            except ValueError as exc:
                raise GitHubRequestError(f"{url} returned invalid JSON: {exc}") from exc

        raise GitHubRequestError(last_error or f"{url} failed after retries")

    @staticmethod
    def _is_primary_rate_limited(resp: requests.Response) -> bool:
        return resp.status_code == 403 and resp.headers.get("X-RateLimit-Remaining") == "0"

    @staticmethod
    def _rate_limit_reset(resp: requests.Response) -> int:
        raw = resp.headers.get("X-RateLimit-Reset") or "0"
        try:
            return int(raw)
        except ValueError:
            return int(time.time()) + 60

    @staticmethod
    def _sleep_before_retry(attempt: int, reason: str) -> None:
        wait = min(120, (2**attempt) + random.uniform(0.25, 1.25))
        print(f"[retry] {reason}; sleeping {wait:.1f}s", file=sys.stderr)
        time.sleep(wait)


def load_config() -> dict[str, Any]:
    with CONFIG_PATH.open("r", encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}
    if not isinstance(config.get("keywords"), list) or not config["keywords"]:
        raise ValueError("config.yaml must define a non-empty keywords list")
    return config


def load_known_sources() -> dict[str, dict[str, Any]]:
    if not KNOWN_PATH.exists():
        return {}
    with KNOWN_PATH.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("known_sources.json must be a JSON object keyed by owner/repo")
    return data


def save_known_sources(known: dict[str, dict[str, Any]]) -> None:
    with KNOWN_PATH.open("w", encoding="utf-8") as f:
        json.dump(known, f, ensure_ascii=False, indent=2, sort_keys=True)
        f.write("\n")


def discover_repositories(client: GitHubClient, config: dict[str, Any], now: datetime) -> list[dict[str, Any]]:
    days_active = int(config.get("days_active", 14))
    per_page = max(1, min(100, int(config.get("per_page", 20))))
    max_repos = max(1, int(config.get("max_repos", 80)))
    search_sleep = float(config.get("search_sleep_seconds", 2.6))
    cutoff = now - timedelta(days=days_active)
    repos: dict[str, dict[str, Any]] = {}

    for keyword in config["keywords"]:
        query = f"{keyword} pushed:>={cutoff.date().isoformat()}"
        params = {"q": query, "sort": "updated", "order": "desc", "per_page": per_page}
        print(f"[search] {query}", file=sys.stderr)
        try:
            data = client.get("/search/repositories", params=params)
        except (GitHubNotFound, GitHubRequestError) as exc:
            print(f"[warn] search failed for {keyword!r}: {exc}", file=sys.stderr)
            time.sleep(search_sleep)
            continue

        for repo in data.get("items", []):
            pushed_at = parse_github_dt(repo.get("pushed_at"))
            if pushed_at is None or pushed_at < cutoff:
                continue
            full_name = repo.get("full_name")
            if not full_name:
                continue
            current = repos.get(full_name)
            if current is None:
                repos[full_name] = repo
                continue
            current_pushed = parse_github_dt(current.get("pushed_at")) or datetime.min.replace(tzinfo=timezone.utc)
            if pushed_at > current_pushed:
                repos[full_name] = repo

        time.sleep(search_sleep)

    ordered = sorted(
        repos.values(),
        key=lambda item: (
            parse_github_dt(item.get("pushed_at")) or datetime.min.replace(tzinfo=timezone.utc),
            int(item.get("stargazers_count") or 0),
        ),
        reverse=True,
    )
    return ordered[:max_repos]


def path_score(path: str) -> tuple[int, int, str]:
    name = Path(path).name.lower()
    exact = {
        "sub.txt",
        "all_sub.txt",
        "base64.txt",
        "v2ray.txt",
        "vless.txt",
        "vmess.txt",
        "nodes.txt",
        "nodefree.txt",
        "clash.yaml",
        "clash.yml",
        "mihomo.yaml",
        "mihomo.yml",
        "configs_base64.txt",
        "v2ray_base64.txt",
        "v2ray-base64.txt",
    }
    score = 0
    if name in exact:
        score += 100
    if "base64" in name:
        score += 30
    if any(token in name for token in ("v2ray", "vless", "vmess", "trojan", "node", "sub")):
        score += 20
    if name.startswith(("clash", "mihomo")):
        score += 15
    score -= path.count("/") * 3
    return (-score, len(path), path.lower())


def find_candidate_paths(client: GitHubClient, repo: dict[str, Any]) -> list[str]:
    full_name = repo["full_name"]
    branch = repo.get("default_branch") or "main"
    tree_path = f"{repo_api_path(full_name)}/git/trees/{quote(branch, safe='')}"
    data = client.get(tree_path, params={"recursive": "1"})
    if data.get("truncated"):
        print(f"[warn] tree truncated for {full_name}; using returned subset", file=sys.stderr)

    paths: list[str] = []
    seen: set[str] = set()
    for item in data.get("tree", []):
        if item.get("type") != "blob":
            continue
        path = item.get("path")
        if not path or path in seen:
            continue
        if SUB_FILE_RE.search(path):
            seen.add(path)
            paths.append(path)

    return sorted(paths, key=path_score)[:8]


def fetch_raw(owner: str, repo: str, branch: str, path: str, limit: int = RAW_READ_LIMIT) -> bytes | None:
    url = raw_url(owner, repo, branch, path)
    headers = {"User-Agent": UA}
    last_error: str | None = None

    for attempt in range(4):
        try:
            with requests.get(url, headers=headers, stream=True, timeout=(10, 30)) as resp:
                if resp.status_code == 404:
                    return None
                if resp.status_code >= 500 or resp.status_code == 429:
                    GitHubClient._sleep_before_retry(attempt, f"raw HTTP {resp.status_code}")
                    continue
                if resp.status_code >= 400:
                    print(f"[warn] raw fetch skipped {url}: HTTP {resp.status_code}", file=sys.stderr)
                    return None

                chunks: list[bytes] = []
                total = 0
                for chunk in resp.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    remaining = limit - total
                    if remaining <= 0:
                        break
                    chunks.append(chunk[:remaining])
                    total += len(chunk[:remaining])
                    if total >= limit:
                        break
                return b"".join(chunks)
        except requests.RequestException as exc:
            last_error = str(exc)
            GitHubClient._sleep_before_retry(attempt, f"raw network error: {exc}")

    print(f"[warn] raw fetch failed {url}: {last_error or 'retries exhausted'}", file=sys.stderr)
    return None


def try_decode_base64(text: str) -> str | None:
    cleaned = "".join(text.strip().split())
    if len(cleaned) < 16:
        return None
    if not BASE64_CHARS_RE.fullmatch(cleaned):
        return None
    if len(cleaned) % 4 == 1:
        return None

    normalized = cleaned.replace("-", "+").replace("_", "/")
    normalized += "=" * ((4 - len(normalized) % 4) % 4)
    try:
        decoded = base64.b64decode(normalized, validate=False)
    except (binascii.Error, ValueError):
        return None
    return decoded.decode("utf-8", errors="replace")


def count_protocol_links(text: str) -> int:
    return len(PROTOCOL_RE.findall(text))


def detect(content: bytes) -> Detection:
    text = content.decode("utf-8", errors="replace").lstrip("\ufeff")

    decoded = try_decode_base64(text)
    if decoded is not None:
        nodes = count_protocol_links(decoded)
        if nodes > 0:
            return Detection("base64", nodes)

    nodes = count_protocol_links(text)
    if nodes > 0:
        return Detection("plain", nodes)

    if TOP_LEVEL_PROXIES_RE.search(text):
        return Detection("clash", len(CLASH_NODE_RE.findall(text)))

    if OUTBOUNDS_RE.search(text):
        return Detection("singbox(弃)", 0)

    if HTTP_SOCKS_RE.search(text):
        return Detection("http-socks(弃)", 0)

    return Detection("unknown", 0)


def better_candidate(left: dict[str, Any] | None, right: dict[str, Any]) -> dict[str, Any]:
    if left is None:
        return right
    left_score = (FORMAT_PRIORITY.get(left["format"], 0), int(left["nodes"]))
    right_score = (FORMAT_PRIORITY.get(right["format"], 0), int(right["nodes"]))
    return right if right_score > left_score else left


def evaluate_repo(repo: dict[str, Any], config: dict[str, Any], client: GitHubClient) -> dict[str, Any] | None:
    full_name = repo["full_name"]
    owner, repo_name = full_name.split("/", 1)
    branch = repo.get("default_branch") or "main"
    min_nodes = int(config.get("min_nodes", 10))
    mirror_template = str(config.get("mirror"))

    try:
        paths = find_candidate_paths(client, repo)
    except GitHubNotFound:
        print(f"[skip] repository tree not found: {full_name}", file=sys.stderr)
        return None
    except GitHubRequestError as exc:
        print(f"[warn] tree fetch failed for {full_name}: {exc}", file=sys.stderr)
        return None

    best: dict[str, Any] | None = None
    for path in paths:
        content = fetch_raw(owner, repo_name, branch, path)
        if content is None:
            continue
        detection = detect(content)
        if detection.format in DISCARDED_FORMATS or detection.nodes < min_nodes:
            continue

        candidate = {
            "full_name": full_name,
            "owner": owner,
            "repo": repo_name,
            "branch": branch,
            "path": path,
            "url": mirror_url(mirror_template, owner, repo_name, branch, path),
            "format": detection.format,
            "nodes": detection.nodes,
            "stars": int(repo.get("stargazers_count") or 0),
            "pushed_at": repo.get("pushed_at") or "",
            "updated_at": repo.get("updated_at") or "",
            "description": repo.get("description") or "",
            "html_url": repo.get("html_url") or f"https://github.com/{full_name}",
        }
        best = better_candidate(best, candidate)

    return best


def update_known_sources(
    known: dict[str, dict[str, Any]],
    candidates: list[dict[str, Any]],
    today: str,
) -> list[dict[str, Any]]:
    new_candidates: list[dict[str, Any]] = []
    for candidate in candidates:
        full_name = candidate["full_name"]
        entry = known.get(full_name)
        if entry is None:
            entry = {
                "status": "candidate",
                "first_seen": today,
            }
            known[full_name] = entry
            new_candidates.append(candidate)

        entry.update(
            {
                "last_seen": today,
                "url": candidate["url"],
                "format": candidate["format"],
                "nodes": candidate["nodes"],
                "branch": candidate["branch"],
                "path": candidate["path"],
                "stars": candidate["stars"],
                "repo_pushed_at": candidate["pushed_at"],
                "repo_updated_at": candidate["updated_at"],
                "description": candidate["description"],
            }
        )

    return new_candidates


def refresh_in_use_sources(
    client: GitHubClient,
    known: dict[str, dict[str, Any]],
    today: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for full_name, entry in sorted(known.items()):
        if entry.get("status") != "in-use":
            continue
        row = {"full_name": full_name, **entry}
        try:
            repo = client.get(repo_api_path(full_name))
            entry.update(
                {
                    "last_repo_check": today,
                    "stars": int(repo.get("stargazers_count") or 0),
                    "repo_pushed_at": repo.get("pushed_at") or entry.get("repo_pushed_at", ""),
                    "repo_updated_at": repo.get("updated_at") or entry.get("repo_updated_at", ""),
                    "description": repo.get("description") or entry.get("description", ""),
                }
            )
            row.update(entry)
            row["html_url"] = repo.get("html_url") or f"https://github.com/{full_name}"
        except (GitHubNotFound, GitHubRequestError) as exc:
            row["check_error"] = str(exc)
            row["html_url"] = f"https://github.com/{full_name}"
            print(f"[warn] in-use refresh failed for {full_name}: {exc}", file=sys.stderr)
        rows.append(row)
    return rows


def candidate_sort_key(candidate: dict[str, Any]) -> tuple[int, int]:
    return (FORMAT_PRIORITY.get(candidate.get("format"), 0), int(candidate.get("nodes") or 0))


def render_new_candidates_table(candidates: list[dict[str, Any]]) -> str:
    if not candidates:
        return "_本周没有发现超过预筛门槛的新仓库。_"

    lines = [
        "| 仓库链接 | 订阅URL(jsdelivr) | 格式 | 节点数 | stars | 仓库最近更新 | 简介 |",
        "| --- | --- | --- | ---: | ---: | --- | --- |",
    ]
    for item in sorted(candidates, key=candidate_sort_key, reverse=True):
        repo_link = f"[{md_escape(item['full_name'])}]({item['html_url']})"
        sub_url = md_escape(item["url"])
        fmt = md_escape(item["format"])
        nodes = int(item.get("nodes") or 0)
        stars = int(item.get("stars") or 0)
        pushed = md_escape(iso_date(parse_github_dt(item.get("pushed_at"))))
        desc = md_escape(item.get("description"), max_len=90)
        lines.append(f"| {repo_link} | {sub_url} | {fmt} | {nodes} | {stars} | {pushed} | {desc} |")
    return "\n".join(lines)


def render_in_use_table(rows: list[dict[str, Any]], now: datetime) -> str:
    if not rows:
        return "_known_sources.json 里没有 status=in-use 的源。_"

    lines = [
        "| 在用源 | 订阅URL | 格式 | stars | 仓库最近更新 | 距今 | 结论 |",
        "| --- | --- | --- | ---: | --- | ---: | --- |",
    ]
    for row in rows:
        full_name = row["full_name"]
        repo_link = f"[{md_escape(full_name)}]({row.get('html_url') or f'https://github.com/{full_name}'})"
        sub_url = md_escape(row.get("url", ""))
        fmt = md_escape(row.get("format", ""))
        stars = int(row.get("stars") or 0)
        pushed_dt = parse_github_dt(row.get("repo_pushed_at"))
        if pushed_dt is None:
            pushed = ""
            days = ""
            verdict = "未知，需手动查看仓库"
        else:
            pushed = iso_date(pushed_dt)
            age_days = max(0, (now - pushed_dt).days)
            days = str(age_days)
            verdict = "⚠️ >10天没更新，留意替补" if age_days > 10 else "近期有更新"
        if row.get("check_error"):
            verdict = "刷新失败，需手动查看仓库"
        lines.append(f"| {repo_link} | {sub_url} | {fmt} | {stars} | {pushed} | {days} | {verdict} |")
    return "\n".join(lines)


def build_report_payload(
    report_date: str,
    now: datetime,
    new_candidates: list[dict[str, Any]],
    in_use_rows: list[dict[str, Any]],
    total_repos: int,
    total_passed: int,
) -> dict[str, Any]:
    def candidate_payload(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "full_name": item.get("full_name", ""),
            "html_url": item.get("html_url", ""),
            "url": item.get("url", ""),
            "format": item.get("format", ""),
            "nodes": int(item.get("nodes") or 0),
            "stars": int(item.get("stars") or 0),
            "repo_pushed_at": iso_date(parse_github_dt(item.get("pushed_at"))),
            "description": item.get("description", ""),
        }

    def in_use_payload(row: dict[str, Any]) -> dict[str, Any]:
        pushed_dt = parse_github_dt(row.get("repo_pushed_at"))
        if pushed_dt is None:
            age_days: int | None = None
            verdict = "未知，需手动查看仓库"
            pushed = ""
        else:
            age_days = max(0, (now - pushed_dt).days)
            verdict = "超过10天没更新，留意替补" if age_days > 10 else "近期有更新"
            pushed = iso_date(pushed_dt)
        if row.get("check_error"):
            verdict = "刷新失败，需手动查看仓库"

        return {
            "full_name": row.get("full_name", ""),
            "html_url": row.get("html_url") or f"https://github.com/{row.get('full_name', '')}",
            "url": row.get("url", ""),
            "format": row.get("format", ""),
            "stars": int(row.get("stars") or 0),
            "repo_pushed_at": pushed,
            "age_days": age_days,
            "verdict": verdict,
        }

    return {
        "date": report_date,
        "generated_at": now.isoformat(),
        "notice": "存活需在路由器面板用中国出口手动验证。本工具只做 GitHub 发现和格式预筛，不做云端 alive/health-check。",
        "summary": {
            "scanned_repos": total_repos,
            "passed_repos": total_passed,
            "new_candidates": len(new_candidates),
            "in_use_sources": len(in_use_rows),
        },
        "new_candidates": [
            candidate_payload(item)
            for item in sorted(new_candidates, key=candidate_sort_key, reverse=True)
        ],
        "in_use": [in_use_payload(row) for row in in_use_rows],
    }


def update_report_archive(report_date: str, generated_at: str) -> None:
    archive_path = REPORTS_DIR / "index.json"
    if archive_path.exists():
        try:
            archive = json.loads(archive_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            archive = []
    else:
        archive = []
    if not isinstance(archive, list):
        archive = []

    archive = [item for item in archive if item.get("date") != report_date]
    archive.append(
        {
            "date": report_date,
            "generated_at": generated_at,
            "markdown": f"reports/{report_date}.md",
            "json": f"reports/{report_date}.json",
        }
    )
    archive.sort(key=lambda item: item.get("date", ""), reverse=True)
    archive_path.write_text(json.dumps(archive, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def write_reports(
    report_date: str,
    now: datetime,
    new_candidates: list[dict[str, Any]],
    in_use_rows: list[dict[str, Any]],
    total_repos: int,
    total_passed: int,
) -> None:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    payload = build_report_payload(report_date, now, new_candidates, in_use_rows, total_repos, total_passed)
    body = f"""# 免费节点池候选发现周报 - {report_date}

> 存活需在路由器面板用中国出口手动验证。本工具只做 GitHub 发现和格式预筛，不做云端 alive/health-check。

- 生成时间：{now.strftime("%Y-%m-%d %H:%M:%S %Z")}
- 搜索后进入仓库扫描：{total_repos}
- 通过格式与节点数预筛：{total_passed}
- 新增候选仓库：{len(new_candidates)}

## 🆕 本周新候选

{render_new_candidates_table(new_candidates)}

## 📉 在用源体检

{render_in_use_table(in_use_rows, now)}

## 使用说明

1. 先把「本周新候选」里的 jsdelivr URL 加到 OpenClash/mihomo 的多源订阅里。
2. 只在路由器面板或中国大陆出口环境验证实际可用性。
3. 可用则把 `known_sources.json` 中该仓库的 `status` 改为 `in-use`；不可用则改为 `rejected` 并补充 `note`。
"""
    (REPORTS_DIR / f"{report_date}.md").write_text(body, encoding="utf-8")
    (REPORTS_DIR / "latest.md").write_text(body, encoding="utf-8")
    (REPORTS_DIR / f"{report_date}.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (REPORTS_DIR / "latest.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    update_report_archive(report_date, payload["generated_at"])


def main() -> int:
    now = utc_now()
    report_now = now.astimezone(REPORT_TZ)
    today = report_now.date().isoformat()
    token = os.environ.get("GITHUB_TOKEN")
    config = load_config()
    known = load_known_sources()
    client = GitHubClient(token)

    repos = discover_repositories(client, config, now)
    passed: list[dict[str, Any]] = []
    for index, repo in enumerate(repos, start=1):
        full_name = repo.get("full_name", "<unknown>")
        print(f"[scan] {index}/{len(repos)} {full_name}", file=sys.stderr)
        try:
            candidate = evaluate_repo(repo, config, client)
        except Exception as exc:
            print(f"[warn] repository skipped {full_name}: {exc}", file=sys.stderr)
            continue
        if candidate is not None:
            passed.append(candidate)

    new_candidates = update_known_sources(known, passed, today)
    in_use_rows = refresh_in_use_sources(client, known, today)
    save_known_sources(known)
    write_reports(today, report_now, new_candidates, in_use_rows, len(repos), len(passed))

    print(
        f"[done] scanned={len(repos)} passed={len(passed)} new={len(new_candidates)} report=reports/{today}.md",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
