"""
vulnops/verifier.py — Modular vulnerability verification layer.

Each verifier connects to the target system (via SSH or Git) and confirms
whether the vulnerability described by a Finding actually exists.

Class hierarchy:
    BaseVerifier (ABC)
    ├── SSHVerifier          — asyncssh: runs dpkg/rpm/config checks
    │   └── QualysVerifier   — scanner_type == "qualys"
    └── GitVerifier          — gitpython: checks repository for vulnerable patterns
        └── PrismaVerifier   — scanner_type == "prisma"

Use verifier_factory(scanner_type) to get the right verifier for a finding.
"""

from __future__ import annotations

import os
import re
import tempfile
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

from common.logger import get_logger
from vulnops.models import Finding, VerificationResult

load_dotenv()

logger = get_logger("aegis.vulnops.verifier")

_SSH_KEY_PATH: str = os.environ.get("SSH_KEY_PATH", "~/.ssh/id_rsa")
_SSH_USERNAME: str = os.environ.get("SSH_USERNAME", "ubuntu")


# ── Base ──────────────────────────────────────────────────────────────────────

class BaseVerifier(ABC):
    """Abstract verifier. Every concrete verifier implements verify()."""

    @abstractmethod
    async def verify(self, finding: Finding) -> VerificationResult:
        """Check whether the finding exists on the target. Never raises."""


def _now() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


# ── SSH Verifier ──────────────────────────────────────────────────────────────

class SSHVerifier(BaseVerifier):
    """
    Verifies a vulnerability by connecting to the target host via SSH and
    running package-manager or configuration queries.

    Requires:
      - SSH_KEY_PATH  (env, default: ~/.ssh/id_rsa)
      - SSH_USERNAME  (env, default: ubuntu)
      - finding.target_host must be non-empty
    """

    def __init__(
        self,
        username: str = _SSH_USERNAME,
        key_path: str = _SSH_KEY_PATH,
    ) -> None:
        self._username = username
        self._key_path = str(Path(key_path).expanduser())

    async def verify(self, finding: Finding) -> VerificationResult:
        host = finding.target_host
        if not host:
            logger.warning(
                "SSH verification skipped — no target_host",
                extra={"action": "verify_skip", "finding_id": finding.finding_id, "reason": "no_host"},
            )
            return VerificationResult(
                confirmed=False,
                evidence="No target host configured for this finding.",
                method="skipped",
                host="",
                timestamp=_now(),
            )

        logger.info(
            "Starting SSH verification",
            extra={"action": "verify_start", "method": "ssh", "host": host, "finding_id": finding.finding_id},
        )

        try:
            evidence = await self._run_checks(host, finding)
            confirmed = self._assess_evidence(finding, evidence)

            logger.info(
                "SSH verification complete",
                extra={"action": "verify_complete", "method": "ssh", "host": host,
                       "confirmed": confirmed, "finding_id": finding.finding_id},
            )
            return VerificationResult(
                confirmed=confirmed,
                evidence=evidence,
                method="ssh",
                host=host,
                timestamp=_now(),
            )

        except Exception as exc:
            logger.error(
                "SSH verification failed",
                exc_info=True,
                extra={"action": "verify_error", "method": "ssh", "host": host,
                       "finding_id": finding.finding_id, "error": str(exc)},
            )
            return VerificationResult(
                confirmed=False,
                evidence=f"SSH error: {exc}",
                method="ssh",
                host=host,
                timestamp=_now(),
            )

    async def _run_checks(self, host: str, finding: Finding) -> str:
        """Connect via asyncssh and run package-manager queries."""
        try:
            import asyncssh
        except BaseException as e:
            raise RuntimeError(
                f"asyncssh could not be loaded ({type(e).__name__}: {e}). "
                "Ensure the 'cryptography' native extensions are installed."
            ) from e

        connect_kwargs: dict = {
            "username": self._username,
            "known_hosts": None,          # disable host key checking (trust-on-first-use)
        }
        if os.path.exists(self._key_path):
            connect_kwargs["client_keys"] = [self._key_path]

        async with asyncssh.connect(host, **connect_kwargs) as conn:
            evidence_parts: list[str] = []

            if finding.component_name:
                pkg = finding.component_name

                # Try dpkg (Debian/Ubuntu)
                result = await conn.run(f"dpkg -l {pkg} 2>/dev/null | grep -i {pkg}", check=False)
                if result.stdout.strip():
                    evidence_parts.append(f"[dpkg]\n{result.stdout.strip()}")

                # Try rpm (RHEL/CentOS/Amazon Linux)
                result = await conn.run(f"rpm -qa | grep -i {pkg} 2>/dev/null", check=False)
                if result.stdout.strip():
                    evidence_parts.append(f"[rpm]\n{result.stdout.strip()}")

                # Try pip
                result = await conn.run(f"pip3 show {pkg} 2>/dev/null || pip show {pkg} 2>/dev/null", check=False)
                if result.stdout.strip():
                    evidence_parts.append(f"[pip]\n{result.stdout.strip()}")

                # Try npm
                result = await conn.run(f"npm list -g {pkg} 2>/dev/null", check=False)
                if result.stdout.strip() and "empty" not in result.stdout.lower():
                    evidence_parts.append(f"[npm]\n{result.stdout.strip()}")

            # Kernel version (useful for OS-level CVEs)
            result = await conn.run("uname -r", check=False)
            if result.stdout.strip():
                evidence_parts.append(f"[kernel]\n{result.stdout.strip()}")

        return "\n\n".join(evidence_parts) if evidence_parts else "No package evidence found."

    def _assess_evidence(self, finding: Finding, evidence: str) -> bool:
        """Return True if evidence suggests the vulnerable package is installed."""
        if "No package evidence found" in evidence:
            return False

        pkg = finding.component_name.lower()
        ver = finding.component_version.lower()
        evidence_lower = evidence.lower()

        if pkg and pkg not in evidence_lower:
            return False

        if ver and ver in evidence_lower:
            return True

        # If we found the package but have no version to compare, treat as confirmed
        return bool(pkg and pkg in evidence_lower)


# ── Git Verifier ──────────────────────────────────────────────────────────────

class GitVerifier(BaseVerifier):
    """
    Verifies a vulnerability by cloning (or updating) the target repository
    and searching for vulnerable code patterns.

    Requires:
      - finding.repo_url must be non-empty
    """

    # Patterns of vulnerable constructs by scanner hint
    _VULN_PATTERNS: dict[str, list[str]] = {
        "default": [
            r"import\s+{component_name}",
            r"require\(['\"]?{component_name}['\"]?\)",
            r"from\s+{component_name}",
        ],
    }

    def __init__(self, clone_base: Optional[str] = None) -> None:
        self._clone_base = Path(clone_base or tempfile.gettempdir()) / "aegis-vulnops-repos"
        self._clone_base.mkdir(parents=True, exist_ok=True)

    async def verify(self, finding: Finding) -> VerificationResult:
        repo_url = finding.repo_url
        if not repo_url:
            logger.warning(
                "Git verification skipped — no repo_url",
                extra={"action": "verify_skip", "finding_id": finding.finding_id, "reason": "no_repo_url"},
            )
            return VerificationResult(
                confirmed=False,
                evidence="No repository URL configured for this finding.",
                method="skipped",
                host="",
                timestamp=_now(),
            )

        logger.info(
            "Starting Git verification",
            extra={"action": "verify_start", "method": "git", "repo": repo_url, "finding_id": finding.finding_id},
        )

        try:
            repo_dir = await self._ensure_repo(repo_url)
            matches = self._search_repo(repo_dir, finding)
            confirmed = bool(matches)

            evidence = (
                "Vulnerable patterns found:\n" + "\n".join(matches[:20])
                if matches
                else "No vulnerable patterns found in repository."
            )

            logger.info(
                "Git verification complete",
                extra={"action": "verify_complete", "method": "git", "confirmed": confirmed,
                       "matches": len(matches), "finding_id": finding.finding_id},
            )
            return VerificationResult(
                confirmed=confirmed,
                evidence=evidence,
                method="git",
                host=repo_url,
                timestamp=_now(),
            )

        except Exception as exc:
            logger.error(
                "Git verification failed",
                exc_info=True,
                extra={"action": "verify_error", "method": "git", "repo": repo_url,
                       "finding_id": finding.finding_id, "error": str(exc)},
            )
            return VerificationResult(
                confirmed=False,
                evidence=f"Git error: {exc}",
                method="git",
                host=repo_url,
                timestamp=_now(),
            )

    async def _ensure_repo(self, repo_url: str) -> Path:
        """Clone the repo if not present; pull latest if it is."""
        import asyncio

        from git import InvalidGitRepositoryError, Repo

        # Derive a safe directory name from the URL
        safe_name = re.sub(r"[^\w.-]", "_", repo_url.split("/")[-1].replace(".git", ""))
        repo_dir = self._clone_base / safe_name

        if repo_dir.exists():
            try:
                repo = Repo(str(repo_dir))
                # Pull in a thread to avoid blocking the event loop
                await asyncio.get_event_loop().run_in_executor(
                    None, lambda: repo.remotes.origin.pull()
                )
                return repo_dir
            except InvalidGitRepositoryError:
                import shutil
                shutil.rmtree(str(repo_dir), ignore_errors=True)

        # Clone in a thread
        from git import Repo as _Repo
        await asyncio.get_event_loop().run_in_executor(
            None, lambda: _Repo.clone_from(repo_url, str(repo_dir))
        )
        return repo_dir

    def _search_repo(self, repo_dir: Path, finding: Finding) -> list[str]:
        """Return a list of 'file:line: matched_text' strings."""
        matches: list[str] = []
        pkg = finding.component_name

        if not pkg:
            return matches

        # Build search patterns
        patterns = [
            re.compile(p.format(component_name=re.escape(pkg)), re.IGNORECASE)
            for p in self._VULN_PATTERNS.get("default", [])
        ]

        # Also search for the package name + version string directly
        if finding.component_version:
            patterns.append(
                re.compile(
                    re.escape(f"{pkg}@{finding.component_version}"), re.IGNORECASE
                )
            )
            patterns.append(
                re.compile(
                    re.escape(f'"{pkg}": "{finding.component_version}"'), re.IGNORECASE
                )
            )

        text_extensions = {".py", ".js", ".ts", ".java", ".go", ".rb", ".php",
                           ".json", ".toml", ".txt", ".yaml", ".yml", ".xml"}

        for path in repo_dir.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in text_extensions:
                continue
            # Skip hidden dirs and common non-source paths
            if any(p.startswith(".") for p in path.parts):
                continue
            if "node_modules" in path.parts or "__pycache__" in path.parts:
                continue

            try:
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            for lineno, line in enumerate(content.splitlines(), start=1):
                for pattern in patterns:
                    if pattern.search(line):
                        rel = path.relative_to(repo_dir)
                        matches.append(f"{rel}:{lineno}: {line.strip()[:120]}")
                        break  # one match per line is enough

            if len(matches) >= 50:
                break  # cap to avoid huge evidence strings

        return matches


# ── Scanner-specific subclasses ───────────────────────────────────────────────

class QualysVerifier(SSHVerifier):
    """SSH verifier tailored for Qualys findings (OS-level CVEs)."""

    async def _run_checks(self, host: str, finding: Finding) -> str:
        base_evidence = await super()._run_checks(host, finding)

        # Qualys reports often include CVE IDs — check if the system has applied
        # the relevant patch via the changelog or apt/yum history.
        try:
            import asyncssh
        except BaseException:
            return base_evidence  # base checks already ran; extras skipped

        extra_parts: list[str] = [base_evidence]

        connect_kwargs: dict = {
            "username": self._username,
            "known_hosts": None,
        }
        if os.path.exists(self._key_path):
            connect_kwargs["client_keys"] = [self._key_path]

        try:
            async with asyncssh.connect(host, **connect_kwargs) as conn:
                # Check apt history for recent upgrades of the package
                if finding.component_name:
                    result = await conn.run(
                        f"grep -i '{finding.component_name}' /var/log/apt/history.log 2>/dev/null | tail -20",
                        check=False,
                    )
                    if result.stdout.strip():
                        extra_parts.append(f"[apt history]\n{result.stdout.strip()}")

                # Check OS release for patch-level context
                result = await conn.run("cat /etc/os-release 2>/dev/null | head -5", check=False)
                if result.stdout.strip():
                    extra_parts.append(f"[os-release]\n{result.stdout.strip()}")
        except Exception:
            pass  # best-effort extras

        return "\n\n".join(p for p in extra_parts if p)


class PrismaVerifier(GitVerifier):
    """Git verifier tailored for Prisma Cloud (container/IaC) findings."""

    _VULN_PATTERNS = {
        "default": [
            r"FROM\s+.*{component_name}",          # Dockerfile base image
            r"image:\s+.*{component_name}",         # docker-compose / k8s manifest
            r"\"?{component_name}\"?\s*[:=]",       # package.json / requirements.txt
            r"^{component_name}[=><]",              # pip requirements style
        ],
    }


# ── Factory ───────────────────────────────────────────────────────────────────

class _FallbackVerifier(BaseVerifier):
    """Used when no verifier is available for the scanner type."""

    async def verify(self, finding: Finding) -> VerificationResult:
        logger.warning(
            "No verifier available for scanner type — marking as unverified",
            extra={"action": "verify_fallback", "scanner_type": finding.scanner_type,
                   "finding_id": finding.finding_id},
        )
        return VerificationResult(
            confirmed=False,
            evidence=f"No verifier implemented for scanner_type={finding.scanner_type!r}. Manual review required.",
            method="skipped",
            host="",
            timestamp=_now(),
        )


def verifier_factory(scanner_type: str) -> BaseVerifier:
    """Return the appropriate verifier for the given scanner type."""
    st = scanner_type.lower().strip()
    if "qualys" in st:
        return QualysVerifier()
    if "prisma" in st or "twistlock" in st:
        return PrismaVerifier()
    if st in ("ssh", "os", "network"):
        return SSHVerifier()
    if st in ("git", "sast", "code"):
        return GitVerifier()
    return _FallbackVerifier()
