"""Parsing of unified git diffs into structured, line-aware hunks."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class DiffLine:
    """A single line inside a hunk.

    ``new_line`` is the line number in the *new* file for added lines; for context lines
    both old and new share the number; ``None`` for removed lines.
    """

    kind: str  # 'context' | 'add' | 'del'
    text: str
    new_line: int | None = None
    old_line: int | None = None


@dataclass
class Changeset:
    """Per-file changes from a unified diff."""

    file: str
    additions: list[DiffLine] = field(default_factory=list)

    def lines_added(self) -> int:
        return len(self.additions)

    def get_line(self, line_number: int) -> DiffLine | None:
        for ln in self.additions:
            if ln.new_line == line_number:
                return ln
        return None

    def snippet_around(self, line_number: int, radius: int = 3) -> str:
        idx = {ln.new_line: i for i, ln in enumerate(self.additions)}
        if line_number not in idx:
            return self.get_line(line_number).text if self.get_line(line_number) else ""
        i = idx[line_number]
        out = []
        for j in range(max(0, i - radius), min(len(self.additions), i + radius + 1)):
            ln = self.additions[j]
            out.append(f"L{ln.new_line} | {ln.text}")
        return "\n".join(out)


_HUNK_HEADER = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")
_FILE_HEADER = re.compile(
    r'^diff --git "?a/(.+?)"?\s+"?b/(.+?)"?\s*$'
)


def parse_diff(raw: str) -> dict[str, Changeset]:
    """Parse a unified diff string into {file: Changeset}."""
    changesets: dict[str, Changeset] = {}
    current_file: str | None = None
    cur_new: int | None = None
    cur_old: int | None = None
    expect_pair = False

    for raw_line in raw.splitlines():
        if raw_line.startswith("diff --git "):
            m = _FILE_HEADER.match(raw_line)
            if m:
                current_file = re.sub(r"/+", "/", m.group(2).replace("\\", "/"))
                changesets[current_file] = Changeset(file=current_file)
            else:
                current_file = None
            continue

        if current_file is None:
            continue

        if raw_line.startswith(("--- ", "+++ ", "index ", "new file mode", "deleted file mode")):
            continue
        if raw_line == r"\ No newline at end of file":
            continue

        m = _HUNK_HEADER.match(raw_line)
        if m:
            cur_old = int(m.group(1))
            cur_new = int(m.group(2))
            expect_pair = True
            continue

        # Detect binary files
        if raw_line.startswith("Binary files "):
            continue

        kind = "context"
        text = raw_line
        if raw_line.startswith("+"):
            kind = "add"
            text = raw_line[1:]
        elif raw_line.startswith("-"):
            kind = "del"
            text = raw_line[1:]

        if kind == "add" and cur_new is not None:
            changesets[current_file].additions.append(DiffLine(kind=kind, text=text, new_line=cur_new, old_line=None))
        elif kind == "del" and cur_old is not None:
            changesets[current_file].additions.append(DiffLine(kind=kind, text=text, new_line=None, old_line=cur_old))
        elif kind == "context" and cur_new is not None:
            changesets[current_file].additions.append(DiffLine(kind=kind, text=text, new_line=cur_new, old_line=cur_old))

        # advance line counters (handles /dev/null hunks where we only track + side)
        if expect_pair:
            if kind != "context":
                if kind == "add" and cur_new is not None:
                    cur_new += 1
            else:
                if cur_new is not None:
                    cur_new += 1
                if cur_old is not None:
                    cur_old += 1
            # Counter nuance: for del+add pairs they move apart; we only really
            # need `new_line` for findings, which advances on add/context entries.

    return changesets


def line_of_text(changeset: Changeset, text: str) -> int | None:
    """Find the new-file line number where an added line equals ``text`` exactly."""
    for ln in changeset.additions:
        if ln.kind == "add" and ln.text == text:
            return ln.new_line
    return None


def contains_line(changeset: Changeset, text: str) -> bool:
    return line_of_text(changeset, text) is not None