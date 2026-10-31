"""Structural validation for GitHub Actions workflow YAML and release gates."""
import ast
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent


def load_workflow(path):
    # BaseLoader avoids YAML 1.1 treating the GitHub Actions key "on" as boolean True.
    with (ROOT / path).open(encoding="utf-8") as stream:
        return yaml.load(stream, Loader=yaml.BaseLoader)


class WorkflowValidationTests(unittest.TestCase):
    def test_deployment_workflow_is_manual_and_confirmed(self):
        workflow = load_workflow(".github/workflows/deploy-pages.yml")
        self.assertIn("workflow_dispatch", workflow["on"])
        inputs = workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertTrue(inputs["confirm_production_deploy"]["required"] == "true")
        self.assertIn("DEPLOY_TO_PRODUCTION", inputs["confirm_production_deploy"]["description"])
        build_if = workflow["jobs"]["build"]["if"]
        self.assertIn("refs/heads/main", build_if)
        self.assertIn("DEPLOY_TO_PRODUCTION", build_if)
        self.assertIn("actions/upload-pages-artifact@", str(workflow))
        self.assertIn("actions/deploy-pages@", str(workflow))
        self.assertNotIn("push", workflow["on"], "production Pages publish must not run automatically")
        self.assertNotIn("pull_request", workflow["on"], "PR checks must not publish publicly")

    def test_deployment_workflow_has_post_deploy_identity_probe(self):
        workflow_text = (ROOT / ".github/workflows/deploy-pages.yml").read_text(encoding="utf-8")
        self.assertIn("build-info.json", workflow_text)
        self.assertIn("trustguard-build-commit", workflow_text)
        self.assertIn("DEPLOYMENT_NOT_VERIFIED", workflow_text)
        self.assertIn("path: _site", workflow_text)
        self.assertIn("manifest[\"frontend_commit\"] == expected", workflow_text)

    def test_deployment_permissions_and_predeploy_gates_are_least_privilege(self):
        workflow = load_workflow(".github/workflows/deploy-pages.yml")
        self.assertEqual(workflow["permissions"]["contents"], "read")
        self.assertEqual(workflow["jobs"]["deploy"]["permissions"]["pages"], "write")
        self.assertEqual(workflow["jobs"]["deploy"]["permissions"]["id-token"], "write")
        self.assertNotIn("pages", workflow["jobs"]["build"].get("permissions", {}))
        workflow_text = (ROOT / ".github/workflows/deploy-pages.yml").read_text(encoding="utf-8")
        self.assertIn("Run full Pages artifact contract tests before upload", workflow_text)
        self.assertIn("upload-pages-artifact", workflow_text)
        self.assertLess(workflow_text.index("pages_artifact_tests"), workflow_text.index("upload-pages-artifact"))
        for marker in ("__TRUSTGUARD_BUILD_COMMIT__", "7R3064957MB0759941", "3HD92730V0626752B", "1U9063377E719994A"):
            with self.subTest(marker=marker):
                self.assertIn(marker, workflow_text)

    def test_postdeploy_checks_both_dashboards_and_manifest_contract(self):
        workflow_text = (ROOT / ".github/workflows/deploy-pages.yml").read_text(encoding="utf-8")
        for marker in ("dashboard.html", "dashboard_v2.html", "build-info.json", "hasil.json",
                       "DEPLOYMENT_NOT_VERIFIED", "UNVERIFIED_STATIC_FRONTEND",
                       "visible.group(1) == expected", "bad_content", "bad_status",
                       "transaction data is not fail-closed", "forbidden legacy transaction content"):
            with self.subTest(marker=marker):
                self.assertIn(marker, workflow_text)

    def test_security_workflow_runs_all_required_test_groups(self):
        workflow = load_workflow(".github/workflows/security-tests.yml")
        commands = "\n".join(step.get("run", "") for step in workflow["jobs"]["test"]["steps"])
        for suite in ("security_tests", "frontend_tests", "frontend_browser_tests", "pages_artifact_tests", "workflow_validation_tests"):
            with self.subTest(suite=suite):
                self.assertIn(suite, commands)

    def test_release_repair_branch_is_in_ci_push_matrix(self):
        workflow_text = (ROOT / ".github/workflows/security-tests.yml").read_text(encoding="utf-8")
        self.assertIn("codex/pages-release-repair", workflow_text)
        self.assertIn("codex/pages-release-audit-stage-5-2", workflow_text)

    def test_build_refuses_environment_sha_that_differs_from_checkout(self):
        build_text = (ROOT / "build_pages.py").read_text(encoding="utf-8")
        self.assertIn('git", "rev-parse", "HEAD"', build_text)
        self.assertIn("GITHUB_SHA does not match the checked-out commit", build_text)

    def test_embedded_deployment_python_scripts_are_syntactically_valid(self):
        workflow = load_workflow(".github/workflows/deploy-pages.yml")
        scripts = []
        for step in workflow["jobs"]["build"]["steps"] + workflow["jobs"]["deploy"]["steps"]:
            run = step.get("run", "")
            scripts.extend(re.findall(r"python - <<'PY'\n(.*?)\nPY", run, re.S))
        self.assertGreaterEqual(len(scripts), 2, "expected pre-deploy and post-deploy Python checks")
        for index, script in enumerate(scripts, start=1):
            with self.subTest(script=index):
                ast.parse(script)


if __name__ == "__main__":
    unittest.main(verbosity=2)
