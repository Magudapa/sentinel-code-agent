from sentinel.mcp_server import list_rules, review_diff_tool


def test_review_diff_tool_detects_issues():
    diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,1 +1,2 @@
 import os
+os.system("ls")
"""
    import json

    out = json.loads(review_diff_tool(diff))
    assert out["finding_count"] >= 1
    assert any(f["rule_id"] == "S007" for f in out["findings"])


def test_list_rules_nonempty():
    import json

    rules = json.loads(list_rules())
    assert len(rules) >= 10


def test_clean_diff_no_findings():
    diff = """diff --git a/x.py b/x.py
--- a/x.py
+++ b/x.py
@@ -1,1 +1,2 @@
-def f():
+def f():
+    return 42
"""
    import json

    out = json.loads(review_diff_tool(diff))
    assert out["finding_count"] == 0