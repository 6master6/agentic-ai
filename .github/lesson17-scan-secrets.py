#!/usr/bin/env python3
"""Lesson17 CI 密钥扫描器。

配合课程第 17 节实验手册 §4 ② GitHub CI：用 GitHub Actions 在 push 时
扫描 ``claude-code/multi-file-refactor/`` 子树下 git tracked 文件，找
出硬编码密钥。仅 Python 标准库，可本地复用。

扫描范围
--------
- 仅 ``git ls-files claude-code/multi-file-refactor`` 列出的 tracked 文件
  （仓库外 / 未 tracked 的散落文件不在 CI 范围内）
- 跳过白名单路径（见 ``WHITELIST_GLOBS``）

检测模式（按命中度从高到低）
----------------------------
- AWS Access Key ID      ``AKIA[0-9A-Z]{16}``
- GitHub PAT             ``(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}``
- OpenAI API key         ``sk-[A-Za-z0-9]{20,}``
- Feishu app_secret      ``(?i)(feishu_)?app_secret\\s*[:=]\\s*['"][A-Za-z0-9]{16,}['"]``
- 通用 secret 赋值       ``(?i)(password|secret|api[_-]?key|token|access[_-]?key|
                            auth[_-]?token|app[_-]?secret|private[_-]?key)\\s*
                            [:=]\\s*['"][^'\"\\s]{8,}['"]``
- PEM private key 块     ``-----BEGIN (RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----``

白名单
------
- ``*.md``：文档 / lab 手册里常贴示例密钥
- ``**/tests/**``：测试 fixture / dummy 值
- ``**/.env.example``：示例环境变量
- ``**/common/git-hooks/**``：pre-commit hook 自身含示例 regex
- 本脚本自身（``lesson17-scan-secrets.py``）

用法
----
本地::

    python .github/lesson17-scan-secrets.py

CI（GitHub Actions）::

    python .github/lesson17-scan-secrets.py

退出码
------
- ``0``：未发现硬编码密钥
- ``1``：发现命中，CI step 失败
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# 路径与配置
# ---------------------------------------------------------------------------

# 仓库根（脚本被 GitHub Actions 在仓库根调用，也可在本地仓库根手动跑）。
REPO_ROOT = Path(
    subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
)

# 限制扫描的子树前缀（相对仓库根）。
SCAN_PREFIX = "claude-code/multi-file-refactor"

# ---------------------------------------------------------------------------
# 模式定义
# ---------------------------------------------------------------------------

# (pattern_id, compiled regex, 描述)
PATTERNS: list[tuple[str, "re.Pattern[str]", str]] = [
    (
        "aws-access-key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "AWS Access Key ID",
    ),
    (
        "github-pat",
        re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"),
        "GitHub personal/access token",
    ),
    (
        "openai-key",
        re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
        "OpenAI API key",
    ),
    (
        "feishu-secret",
        re.compile(
            r"""(?i)(feishu_)?app_secret\s*[:=]\s*['"][A-Za-z0-9]{16,}['"]"""
        ),
        "Feishu app_secret 字面量赋值",
    ),
    (
        "generic-secret",
        re.compile(
            r"""(?ix)
            (
                password | passwd | pwd
              | secret
              | api[_-]? key
              | access[_-]? key
              | auth[_-]? token
              | app[_-]? secret
              | private[_-]? key
            )
            \s*[:=]\s*
            ['"][^'"\s]{8,}['"]
            """
        ),
        "通用 password / secret / token / key 字面量赋值",
    ),
    (
        "private-key-block",
        re.compile(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"
        ),
        "PEM private key 块",
    ),
]

# 白名单 glob（相对仓库根的路径），命中则跳过扫描。
# 用 ``Path.match`` 而非 ``fnmatch``，因为前者按段处理 ``**/`` 更可靠。
WHITELIST_GLOBS: list[str] = [
    "*.md",
    "**/tests/**",
    "**/.env.example",
    "**/common/git-hooks/**",
    "**/lesson17-scan-secrets.py",
]


def _is_whitelisted(rel_path: str) -> bool:
    """``rel_path`` 是否命中任一白名单 glob。"""
    p = Path(rel_path)
    for pattern in WHITELIST_GLOBS:
        if p.match(pattern):
            return True
    return False


# ---------------------------------------------------------------------------
# 扫描逻辑
# ---------------------------------------------------------------------------


def _tracked_files() -> list[str]:
    """返回 ``SCAN_PREFIX`` 下所有 git tracked 文件相对仓库根的路径。"""
    result = subprocess.run(
        ["git", "ls-files", "--", SCAN_PREFIX],
        capture_output=True,
        text=True,
        check=True,
        cwd=REPO_ROOT,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _read_blob(rel_path: str) -> str | None:
    """读 git index 里的 blob 内容（不是工作区当前版本）。

    用 ``git show :<path>`` 而非读磁盘文件，确保：
    - CI 跑的是 push 时仓库里的版本（不被工作区未提交改动影响）
    - 跳过未 tracked 文件（与 ``git ls-files`` 配套）

    二进制内容（图片 / 字体 / 编译产物等）用 ``errors="replace"`` 容错：
    替换字符不是 ASCII，不会匹配 secret 正则 → 二进制文件安全跳过。
    """
    result = subprocess.run(
        ["git", "show", f":{rel_path}"],
        capture_output=True,
        cwd=REPO_ROOT,
    )
    if result.returncode != 0:
        return None
    return result.stdout.decode("utf-8", errors="replace")


def _scan_file(rel_path: str) -> list[dict[str, object]]:
    """扫一个文件，返回命中列表。"""
    content = _read_blob(rel_path)
    if content is None:
        return []

    hits: list[dict[str, object]] = []
    for pid, regex, desc in PATTERNS:
        for m in regex.finditer(content):
            line_no = content.count("\n", 0, m.start()) + 1
            snippet = m.group(0)
            # 截断显示，避免把整个长 token 打日志。
            display = snippet if len(snippet) <= 60 else snippet[:57] + "…"
            hits.append(
                {
                    "file": rel_path,
                    "line": line_no,
                    "pattern_id": pid,
                    "desc": desc,
                    "match": display,
                }
            )
    return hits


def _print_report(
    hits: list[dict[str, object]], scanned: int, skipped: int
) -> None:
    bar = "=" * 72
    print(bar, file=sys.stderr)
    print("❌  Secret scan 发现硬编码密钥", file=sys.stderr)
    print(bar, file=sys.stderr)
    for h in hits:
        print(
            f"\n  {h['file']}:{h['line']}  [{h['pattern_id']}]  {h['desc']}",
            file=sys.stderr,
        )
        print(f"    匹配: {h['match']!r}", file=sys.stderr)
    print(
        f"\n建议：把密钥移到 GitHub Actions Secrets 或本地 .env（且 .env 已 gitignore），"
        f"\n       然后从 git 历史里彻底清除（参见 git-filter-repo / BFG）。",
        file=sys.stderr,
    )
    print(bar, file=sys.stderr)
    print(
        f"\n扫描汇总：scanned={scanned}, skipped={skipped}, hits={len(hits)}",
        file=sys.stderr,
    )


def main() -> int:
    files = _tracked_files()
    all_hits: list[dict[str, object]] = []
    scanned = 0
    skipped = 0
    for rel in files:
        if _is_whitelisted(rel):
            skipped += 1
            continue
        scanned += 1
        all_hits.extend(_scan_file(rel))

    print(
        f"[scan-secrets] prefix={SCAN_PREFIX}/ "
        f"scanned={scanned} skipped={skipped} hits={len(all_hits)}"
    )

    if not all_hits:
        print("✅ No hardcoded secrets detected.")
        return 0

    _print_report(all_hits, scanned, skipped)
    return 1


if __name__ == "__main__":
    sys.exit(main())