from sentinel.memory import MemoryStore, fingerprint
from sentinel.models import Finding, Severity


def test_fingerprint_normalizes_whitespace():
    a = fingerprint('os.system("x")')
    b = fingerprint('  os.system("x")  ')
    assert a == b
    assert fingerprint('os.system("y")') != a


def test_remember_and_recall(tmp_path):
    store = MemoryStore(str(tmp_path / "mem"))
    f = Finding(rule_id="S001", severity=Severity.HIGH, file="a.py", line=1,
                code_snippet='password = "abc"')
    store.remember(f, "moved secret to env var")
    hit = store.recall(f)
    assert hit is not None
    assert hit.fix_summary == "moved secret to env var"


def test_recall_missing(tmp_path):
    store = MemoryStore(str(tmp_path / "mem"))
    f = Finding(rule_id="S001", severity=Severity.HIGH, file="a.py", line=1,
                code_snippet='password = "abc"')
    assert store.recall(f) is None


def test_match_count(tmp_path):
    store = MemoryStore(str(tmp_path / "mem"))
    for i in range(3):
        store.remember(
            Finding(rule_id="S005", severity=Severity.CRITICAL, file=f"{i}.py", line=1,
                    code_snippet=f"eval({i})"), "removed eval"
        )
    assert store.match_count("S005") == 3

def test_store_does_not_dedupe_new_snippets(tmp_path):
    """identical snippet + rule is deduped; distinct shapes counted."""
    store = MemoryStore(str(tmp_path / "mem"))
    snippet = "eval(x)"
    for _ in range(3):
        store.remember(
            Finding(rule_id="S005", severity=Severity.CRITICAL, file="a.py", line=1,
                    code_snippet=snippet), "removed eval"
        )
    assert store.match_count("S005") == 1


def test_store_persists(tmp_path):
    d = tmp_path / "mem"
    store = MemoryStore(str(d))
    f = Finding(rule_id="S002", severity=Severity.HIGH, file="a.py", line=1,
                code_snippet="AKIAIOSFODNN7EXAMPLE")
    store.remember(f, "revoked + rotated key")
    store2 = MemoryStore(str(d))  # reload from disk
    assert store2.match_count("S002") == 1