import unittest
from risk_analyzer.analyzer import analyze_diff, render
class RiskTests(unittest.TestCase):
 def test_small_change_is_low(self): self.assertEqual(analyze_diff('diff --git a/a.py b/a.py\n+++ b/a.py\n+print(1)\n')['risk_level'],'LOW')
 def test_destructive_sql_is_high(self):
  r=analyze_diff('diff --git a/db.sql b/db.sql\n+++ b/db.sql\n+DROP TABLE customers;\n'); self.assertEqual(r['risk_level'],'HIGH'); self.assertTrue(r['findings'])
 def test_world_writable_permissions_flagged(self): self.assertEqual(analyze_diff('diff --git a/x.sh b/x.sh\n+++ b/x.sh\n+chmod 777 /opt/app\n')['risk_level'],'HIGH')
 def test_report_contains_recommendations(self): self.assertIn('Recommendations',render(analyze_diff('')))
 def test_change_counts(self):
  r=analyze_diff('diff --git a/a.py b/a.py\n+++ b/a.py\n+added\n-removed\n'); self.assertEqual(r['files_changed_count'],1); self.assertEqual(r['additions'],1); self.assertEqual(r['deletions'],1)
if __name__=='__main__': unittest.main()
