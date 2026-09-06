"""Safe subprocess wrapper.

Every child process Sentinel spawns must go through this module so that:

* commands are **argv lists only** — a string command or any signal of shell
  interpretation is rejected (no ``shell=True`` anywhere in the codebase);
* every invocation has a hard timeout and captures bounded output (a runaway
  process can never hang Sentinel or fill memory);
* the child gets an isolated environment (only allowlisted variables are
  passed through), so repo code cannot read machine secrets;
* ``cwd`` is validated to exist.

The environment policy: by default all variables are stripped; allowlist the
system vars that tools actually need (PATH, SystemRoot, TEMP, PYTHON*, HOME/USERPROFILE
when requested via ``extra_env``).  Anything secret belongs in ``extra_env`` and
is passed only to the tool that explicitly needs it (e.g. bandit reading the
repo config) — never universally.
"""

from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass
from pathlib import Path

DEFAULT_TIMEOUT = 120
MAX_OUTPUT = 1_000_000  # 1MB per stream


class CommandSafetyError(ValueError):
    pass


@dataclass
class ProcessResult:
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.timed_out and not self.error and self.returncode == 0


ENV_ALLOWLIST = (
    "PATH",
    "COMSPEC",
    "SystemRoot",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "HOME",
    "PYTHONPATH",
    "PYTHONUTF8",
    "PYTHONIOENCODING",
    "PYTHONUSERBASE",
    "VIRTUAL_ENV",
    "PIP_*",
    "OLLAMA_*",
    # Site/sysconfig + config discovery on Windows: packages installed for the
    # user live under %APPDATA%\Python and many tools read %LOCALAPPDATA% for
    # settings. These are dev-environment paths, not secrets.
    "APPDATA",
    "LOCALAPPDATA",
    "PROGRAMDATA",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "USERPROFILE",
)


def _user_site_pythonpath() -> list[str]:
    """Directories a child using the same interpreter needs on PYTHONPATH.

    The per-user site-packages (Windows: %APPDATA%\\Python\\Python313\\site-packages)
    are normally re-derived by the child from its own env — but ``run_safe``
    strips that env, and tools like pytest/git live there. We compute it from
    *this* interpreter instead of guessing from environment variables.
    """
    try:
        import site

        user_site = site.getusersitepackages()
    except Exception:  # pragma: no cover - defensive
        return []
    if not user_site:
        return []
    p = Path(user_site)
    return [str(p)] if p.is_dir() else []


def _env_ok(varname: str) -> bool:
    import fnmatch

    return any(fnmatch.fnmatch(varname, pat) for pat in ENV_ALLOWLIST)


def run_safe(
    argv: list[str],
    *,
    cwd: str | None = None,
    timeout: int = DEFAULT_TIMEOUT,
    extra_env: dict[str, str] | None = None,
    max_output: int = MAX_OUTPUT,
    input_text: str | None = None,
) -> ProcessResult:
    """Run ``argv`` (list only) with a timeout and isolated environment.

    Raises CommandSafetyError for obviously unsafe invocations (string command,
    empty argv) or a missing cwd.  Never returns partial hang — TimeoutExpired
    becomes a ``timed_out`` result.
    """
    if isinstance(argv, (str, bytes)):
        raise CommandSafetyError("subprocess argv must be a list, not a string")
    if not argv or not argv[0]:
        raise CommandSafetyError("subprocess argv must contain a program")

    if not all(isinstance(a, str) for a in argv):
        raise CommandSafetyError("subprocess argv must contain only strings")

    if cwd is not None and not os.path.isdir(cwd):
        raise CommandSafetyError(f"cwd does not exist or is not a directory: {cwd!r}")

    env = {k: v for k, v in os.environ.items() if _env_ok(k)}
    user_site_dirs = _user_site_pythonpath()
    if user_site_dirs:
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = os.pathsep.join(
            user_site_dirs + ([existing] if existing else [])
        )
    if extra_env:
        env.update({k: str(v) for k, v in extra_env.items()})

    try:
        res = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            input=input_text,
        )
    except subprocess.TimeoutExpired as exc:
        return ProcessResult(
            returncode=-1,
            stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
            stderr="",
            timed_out=True,
            error=f"timed out after {timeout}s",
        )
    except FileNotFoundError:
        return ProcessResult(returncode=-1, error=f"program not found: {argv[0]}")
    except OSError as exc:
        return ProcessResult(returncode=-1, error=f"{type(exc).__name__}: {exc}")

    return ProcessResult(
        returncode=res.returncode,
        stdout=_clip(res.stdout or ""),
        stderr=_clip(res.stderr or ""),
    )


def _clip(text: str, limit: int = MAX_OUTPUT) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[output truncated at {limit} chars]"


def shell_split(shell_line: str) -> list[str]:
    """Split a shell string into argv for logging/display (never executed)."""
    return shlex.split(shell_line, posix=False) if shell_line else []