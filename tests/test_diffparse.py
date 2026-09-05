from sentinel.diffparse import parse_diff

DIFF = """diff --git a/src/app.py b/src/app.py
index 1111111..2222222 100644
--- a/src/app.py
+++ b/src/app.py
@@ -10,2 +10,5 @@ def foo():
     existing = True
+
+    os.system("ls")       # line 13 new
+    print("hello")        # line 14 new
+    return None
diff --git a/src/lib.py b/src/lib.py
index 3333333..4444444 100644
--- a/src/lib.py
+++ b/src/lib.py
@@ -1,1 +1,1 @@
-    return old
+    return new
"""


def test_parse_diff_files():
    changesets = parse_diff(DIFF)
    assert set(changesets) == {"src/app.py", "src/lib.py"}


def test_parse_diff_line_numbers():
    changesets = parse_diff(DIFF)
    app = changesets["src/app.py"]
    adds = [ln for ln in app.additions if ln.kind == "add"]
    assert adds[0].new_line == 11  # empty line
    assert adds[1].new_line == 12
    assert adds[2].new_line == 13
    assert adds[1].text.strip().startswith('os.system("ls")')


def test_snippet_around():
    changesets = parse_diff(DIFF)
    app = changesets["src/app.py"]
    snip = app.snippet_around(12)
    assert "os.system" in snip
    assert "L12" in snip


def test_replacement_line_works():
    changesets = parse_diff(DIFF)
    lib = changesets["src/lib.py"]
    adds = [ln for ln in lib.additions if ln.kind == "add"]
    assert adds[0].new_line == 1
    assert adds[0].text == "    return new"


def test_empty_diff():
    assert parse_diff("") == {}