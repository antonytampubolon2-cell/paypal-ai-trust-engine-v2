"""Checks for generated synthetic demo files in the exact Pages artifact."""
import json, os, re, unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parent/"_site"
class DemoArtifactTests(unittest.TestCase):
 def test_demo_artifacts_exist_and_share_build_identity(self):
  expected=os.environ.get("GITHUB_SHA","").strip();self.assertRegex(expected,r"^[0-9a-f]{40}$")
  html=(ROOT/"dashboard_demo.html").read_text(encoding="utf-8");manifest=json.loads((ROOT/"build-info.json").read_text(encoding="utf-8"));data=json.loads((ROOT/"hasil_demo.json").read_text(encoding="utf-8"))
  self.assertIn(f'<meta name="trustguard-build-commit" content="{expected}">',html);self.assertIn(f'<code id="build-commit">{expected}</code>',html);self.assertEqual(manifest["frontend_commit"],expected)
  self.assertEqual(data["demo_mode"],"SIMULATED");self.assertFalse(data["external_provider_calls"]);self.assertFalse(data["real_payment_executed"]);self.assertEqual(data["statistics"]["real_payments"],0);self.assertEqual(data["verification_capabilities"]["paypal_authorization"],"NOT_ATTEMPTED");self.assertEqual(data["latest_scenario"]["status"],"NOT_EXECUTED");self.assertNotIn("__TRUSTGUARD_BUILD_COMMIT__",html)
if __name__=="__main__":unittest.main()
