"""Dependency-free safety checks for the hackathon demo."""
import json, unittest
from pathlib import Path
import main_public
ROOT=Path(__file__).resolve().parent
class DemoSafetyTests(unittest.TestCase):
 def test_explicit_simulation_and_no_real_payment(self):
  d=main_public.build_demo_snapshot(); self.assertEqual(d["demo_mode"],"SIMULATED"); self.assertFalse(d["external_provider_calls"]); self.assertFalse(d["real_payment_executed"]); self.assertEqual(d["statistics"]["real_payments"],0); self.assertEqual(d["latest_scenario"]["status"],"NOT_EXECUTED")
 def test_unknown_fails_closed(self):
  x=[e for e in main_public.build_demo_snapshot()["audit_trail"] if e["classification"]=="UNKNOWN_BLOCKED"]; self.assertEqual(len(x),1); self.assertIn("FAIL_CLOSED",x[0]["result"]); self.assertIn("not attempted",x[0]["result"].lower())
 def test_external_verification_not_claimed(self):
  v=main_public.build_demo_snapshot()["verification_capabilities"]; self.assertEqual(v["kyapay_issuer"],"UNVERIFIED"); self.assertEqual(v["merchant_identity"],"UNVERIFIED"); self.assertEqual(v["dpop_signature"],"UNVERIFIED"); self.assertEqual(v["paypal_authorization"],"NOT_ATTEMPTED")
 def test_checked_in_fixture_contract(self):
  d=json.loads((ROOT/"hasil.json").read_text(encoding="utf-8")); self.assertEqual(d["demo_mode"],"SIMULATED"); self.assertFalse(d["external_provider_calls"]); self.assertFalse(d["real_payment_executed"]); self.assertEqual(d["statistics"]["real_payments"],0); self.assertTrue(all("classification" in e for e in d["audit_trail"]))
 def test_dashboard_text_rendering_and_disclosure(self):
  h=(ROOT/"dashboard_v2.html").read_text(encoding="utf-8"); self.assertIn("textContent",h); self.assertIn("SIMULATED",h); self.assertNotIn(".innerHTML",h); self.assertNotIn("Live Data",h); self.assertNotIn("100%",h)
 def test_demo_entrypoint_has_no_provider_calls(self):
  s=(ROOT/"main_public.py").read_text(encoding="utf-8").lower(); self.assertNotIn("paypal_agent_toolkit",s); self.assertNotIn("paypal_client_secret",s); self.assertNotIn("requests.",s); self.assertNotIn("httpx.",s)
if __name__=="__main__": unittest.main()
