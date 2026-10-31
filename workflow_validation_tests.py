"""Structural validation for GitHub Actions workflow YAML and release gates."""
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

    def test_deployment_workflow_has_post_deploy_identity_probe(self):
        workflow_text = (ROOT / ".github/workflows/deploy-pages.yml").read_text(encoding="utf-8")
        self.assertIn("build-info.json", workflow_text)
        self.assertIn("trustguard-build-commit", workflow_text)
        self.assertIn("DEPLOYMENT_NOT_VERIFIED", workflow_text)

    def test_security_workflow_runs_all_required_test_groups(self):
        workflow = load_workflow(".github/workflows/security-tests.yml")
        commands = "\n".join(step.get("run", "") for step in workflow["jobs"]["test"]["steps"])
        for suite in ("security_tests", "frontend_tests", "frontend_browser_tests", "pages_artifact_tests", "workflow_validation_tests"):
            with self.subTest(suite=suite):
                self.assertIn(suite, commands)

    def test_release_repair_branch_is_in_ci_push_matrix(self):
        workflow_text = (ROOT / ".github/workflows/security-tests.yml").read_text(encoding="utf-8")
        self.assertIn("codex/pages-release-repair", workflow_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
