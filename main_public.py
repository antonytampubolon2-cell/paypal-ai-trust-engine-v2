"""Offline synthetic TrustGuard demo; no provider calls or payment actions."""
import argparse, json
from datetime import datetime, timezone
from pathlib import Path

def build_demo_snapshot():
    return {
      "schema_version": 1, "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
      "demo_mode": "SIMULATED", "data_source": "synthetic_local_fixture",
      "external_provider_calls": False, "real_payment_executed": False,
      "notice": "Synthetic only: no PayPal/OpenAI request, KYAPay issuer, merchant identity, or DPoP signature was verified.",
      "verification_capabilities": {"kyapay_issuer":"UNVERIFIED","merchant_identity":"UNVERIFIED","dpop_signature":"UNVERIFIED","paypal_authorization":"NOT_ATTEMPTED"},
      "statistics": {"simulated_scenarios":4,"simulated_allow":1,"simulated_block":2,"fail_closed_unknown":1,"real_payments":0},
      "latest_scenario": {"id":"SYNTHETIC-ONLY","status":"NOT_EXECUTED","merchant":"UNVERIFIED — synthetic placeholder","amount":None,"currency":None},
      "audit_trail": [
        {"time":"scenario-01","event":"Structurally complete synthetic grant","result":"SIMULATED_ALLOW — not issuer verified","classification":"SIMULATED"},
        {"time":"scenario-02","event":"Repeated synthetic token identifier","result":"SIMULATED_BLOCK","classification":"SIMULATED"},
        {"time":"scenario-03","event":"Expired synthetic grant","result":"SIMULATED_BLOCK","classification":"SIMULATED"},
        {"time":"scenario-04","event":"DPoP signature verification unavailable","result":"FAIL_CLOSED — external authorization not attempted","classification":"UNKNOWN_BLOCKED"}
      ]
    }

def main():
    parser=argparse.ArgumentParser(description="Generate offline synthetic TrustGuard demo data.")
    parser.add_argument("--output",default="hasil.json"); args=parser.parse_args()
    Path(args.output).write_text(json.dumps(build_demo_snapshot(),indent=2,ensure_ascii=False)+"\n",encoding="utf-8")
    print("TrustGuard demo generated. Mode=SIMULATED; provider calls=0; real payments=0.")
    return 0
if __name__=="__main__": raise SystemExit(main())
