"""Release workflow structure checks. These tests never dispatch a deployment."""
import ast
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent
WORKFLOW = ROOT / ".github/workflows/deploy-pages.yml"


def load_workflow():
    with WORKFLOW.open(encoding="utf-8") as stream:
        return yaml.load(stream, Loader=yaml.BaseLoader)


class ReleasePipelineTests(unittest.TestCase):
    def test_deployment_is_manual_and_requires_explicit_confirmation(self):
        workflow = load_workflow()
        self.assertIn("workflow_dispatch", workflow["on"])
        inputs = workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(inputs["confirm_production_deploy"]["required"], "true")
        self.assertIn("DEPLOY_TO_PRODUCTION", inputs["confirm_production_deploy"]["description"])
        self.assertIn("refs/heads/main", workflow["jobs"]["build"]["if"])
        self.assertIn("DEPLOY_TO_PRODUCTION", workflow["jobs"]["build"]["if"])
        self.assertNotIn("push", workflow["on"])
        self.assertNotIn("pull_request", workflow["on"])

    def test_least_privilege_and_artifact_gate_order(self):
        workflow = load_workflow()
        self.assertEqual(workflow["permissions"]["contents"], "read")
        self.assertEqual(workflow["jobs"]["deploy"]["permissions"]["actions"], "read")
        self.assertEqual(workflow["jobs"]["deploy"]["permissions"]["pages"], "write")
        self.assertEqual(workflow["jobs"]["deploy"]["permissions"]["id-token"], "write")
        self.assertNotIn("pages", workflow["jobs"]["build"].get("permissions", {}))
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertLess(text.index("pages_artifact_tests"), text.index("upload-pages-artifact"))
        self.assertLess(text.index("upload-pages-artifact"), text.index("actions/deploy-pages"))

    def test_public_verification_checks_manifest_index_dashboards_and_data(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        for marker in ("dashboard.html", "dashboard_v2.html", "index.html", "build-info.json",
                       "hasil.json", "DEPLOYMENT_NOT_VERIFIED", "UNVERIFIED_STATIC_FRONTEND", "data_error",
                       "visible.group(1) == expected", "manifest_error", "index_error"):
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_embedded_python_blocks_are_syntactically_valid(self):
        workflow = load_workflow()
        scripts = []
        for job in workflow["jobs"].values():
            for step in job.get("steps", []):
                run = step.get("run", "")
                scripts.extend(re.findall(r"python - <<'PY'\n(.*?)\nPY", run, re.S))
        self.assertGreaterEqual(len(scripts), 2)
        for script in scripts:
            ast.parse(script)

    def test_probe_never_claims_deployment_from_http_200_alone(self):
        probe = (ROOT / "deployment_probe.py").read_text(encoding="utf-8")
        self.assertIn("MANIFEST_NOT_VERIFIED", probe)
        self.assertIn("DASHBOARD_VERSION_MISMATCH", probe)
        self.assertIn("manifest_sha == dashboard_sha", probe)
        self.assertIn("TRUSTGUARD_PROBE_STRICT", probe)

    def test_workflows_use_supported_runner_and_node24_compatible_actions(self):
        for relative in (".github/workflows/deploy-pages.yml",
                         ".github/workflows/release-pipeline-tests.yml",
                         ".github/workflows/dashboard-tests.yml"):
            text = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(workflow=relative):
                self.assertIn("runs-on: ubuntu-24.04", text)
                # Pin third-party workflow code to immutable, reviewed commit SHAs.
                self.assertRegex(text, r"actions/checkout@[0-9a-f]{40}")
                self.assertRegex(text, r"actions/setup-python@[0-9a-f]{40}")
                self.assertNotRegex(text, r"actions/(?:checkout|setup-python)@v[0-9]+(?:\\b|$)")

    def test_dashboard_fetches_are_timeout_bounded_in_release_candidate(self):
        for relative in ("dashboard.html", "dashboard_v2.html"):
            text = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(dashboard=relative):
                self.assertIn("AbortController", text)
                self.assertIn("FETCH_TIMEOUT_MS", text)
                self.assertIn('fetchWithTimeout("build-info.json"', text)
                self.assertIn('fetchWithTimeout("hasil.json"', text)


    def test_all_workflow_actions_are_immutable_and_known_pins_match_upstream_tags(self):
        workflow_dir = ROOT / ".github" / "workflows"
        workflows = sorted(workflow_dir.glob("*.yml"))
        self.assertEqual(len(workflows), 6, "The six reviewed workflows must remain present")
        expected_pins = {
            "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/setup-python": "6d4fd22b20465ccc0f7354476588e8df7c9ca0e0",
            "actions/upload-pages-artifact": "56afc609e74202658d3ffba0e8f6dda462b719fa",
            "actions/deploy-pages": "d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e",
        }
        seen = set()
        for workflow in workflows:
            for line in workflow.read_text(encoding="utf-8").splitlines():
                if re.match(r"^\s*uses\s*:", line):
                    match = re.match(r"^\s*uses\s*:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})\s*$", line)
                    self.assertIsNotNone(match, f"{workflow.name}: action must use an immutable 40-character SHA: {line.strip()}")
                    action, sha = match.groups()
                    seen.add(action)
                    if action in expected_pins:
                        self.assertEqual(sha, expected_pins[action], f"{workflow.name}: unexpected reviewed SHA for {action}")
        self.assertTrue(set(expected_pins).issubset(seen))

    def test_integrated_workflow_runs_spend_reservation_regressions(self):
        workflow = ROOT / ".github" / "workflows" / "system-integration-tests.yml"
        self.assertIn("spend_reservations_tests", workflow.read_text(encoding="utf-8"))

if __name__ == "__main__":
    unittest.main(verbosity=2)
