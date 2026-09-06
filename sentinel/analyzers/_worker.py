"""Subprocess worker for bounded content analysis (batch mode).

``analyzers.base`` invokes this module with a batch request: several changesets
plus several content analyzers. The worker runs each analyzer over each
changeset, writes a per-analyzer progress file before starting each analyzer,
and finally writes the results JSON. If the parent's wall-clock budget expires,
the parent kills us mid-flight and uses the progress file to attribute the
timeout to whichever analyzer was running at that moment — so no analyzer can
ever be seen as "clean PASS" when the batch died.

Why a subprocess at all: Python's ``re`` C engine does not release the GIL, so
a pathological (catastrophic-backtracking) rule cannot be preempted by a thread.
A disposable OS process can be killed by its parent.

Protocol (all files, never stdout):
  ``--in``    changesets JSON  {"file": {"file": str, "additions": [{kind,text,...}]}}
  ``--out``   results JSON     {"results": {name: {"findings": [...] | "error": str}}}
  ``--phase`` progress JSON    written before each analyzer:
                               {"done": {name: {"findings": [...]}}, "current": name}
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from sentinel.analyzers.base import CONTENT_ANALYZERS
from sentinel.diffparse import Changeset, DiffLine

# Importing the analyzers package runs the ``@register_content`` decorators —
# without it CONTENT_ANALYZERS would be empty in this process.
import sentinel.analyzers  # noqa: F401  isort: skip


def _cs_to_json(cs: Changeset) -> dict:
    return {
        "file": cs.file,
        "additions": [
            {"kind": d.kind, "text": d.text, "new_line": d.new_line, "old_line": d.old_line}
            for d in cs.additions
        ],
    }


def _cs_from_json(data: dict) -> Changeset:
    return Changeset(
        file=data.get("file", ""),
        additions=[DiffLine(**a) for a in data.get("additions", [])],
    )


def _finding_to_dict(f) -> dict:
    sev = getattr(f, "severity", "")
    sev_name = getattr(sev, "name", None) or str(sev)
    return {
        "rule_id": getattr(f, "rule_id", ""),
        "severity": sev_name,
        "file": getattr(f, "file", ""),
        "line": getattr(f, "line", 0),
        "code_snippet": getattr(f, "code_snippet", ""),
        "description": getattr(f, "description", ""),
        "evidence": getattr(f, "evidence", ""),
        "suggested_fix": getattr(f, "suggested_fix", ""),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--in", dest="in_path", required=True)
    parser.add_argument("--out", dest="out_path", required=True)
    parser.add_argument("--phase", dest="progress_path", required=True)
    args = parser.parse_args()

    results: dict[str, dict] = {}
    done: dict[str, dict] = {}
    try:
        data = json.loads(Path(args.in_path).read_text(encoding="utf-8"))
        changesets = {name: _cs_from_json(b) for name, b in data.get("changesets", {}).items()}
        analyzers = data.get("analyzers", [])

        for name in analyzers:
            # this file is what the parent reads if it kills us mid-flight
            Path(args.progress_path).write_text(
                json.dumps({"done": done, "current": name}), encoding="utf-8"
            )
            cls = CONTENT_ANALYZERS.get(name)
            if cls is None:
                results[name] = {"error": f"analyzer not registered: {name}"}
                continue
            try:
                collected = []
                for cs in changesets.values():
                    collected.extend(cls().analyze(cs))
                out = {"findings": [_finding_to_dict(f) for f in collected]}
            except Exception as exc:
                out = {"error": f"{type(exc).__name__}: {exc}"}
            results[name] = out
            done[name] = out
    except Exception as exc:
        raise SystemExit(f"worker fatal error: {type(exc).__name__}: {exc}")

    Path(args.out_path).write_text(json.dumps({"results": results}), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())