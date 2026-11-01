"""Build a minimal, auditable GitHub Pages artifact from this exact checkout."""
import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "_site"
SHA = os.environ.get("GITHUB_SHA", "").strip() or subprocess.check_output(
    ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
).strip()
if len(SHA) != 40 or any(ch not in "0123456789abcdef" for ch in SHA.lower()):
    raise SystemExit(f"Refusing build: invalid commit SHA {SHA!r}")

if OUT.exists():
    shutil.rmtree(OUT)
OUT.mkdir(parents=True)
for name in ("dashboard.html", "dashboard_v2.html", "hasil.json"):
    source = ROOT / name
    if not source.is_file():
        raise SystemExit(f"Refusing build: required file missing: {name}")
    content = source.read_text(encoding="utf-8")
    if name.endswith(".html"):
        if "__TRUSTGUARD_BUILD_COMMIT__" not in content:
            raise SystemExit(f"Refusing build: commit marker missing in {name}")
        content = content.replace("__TRUSTGUARD_BUILD_COMMIT__", SHA)
    (OUT / name).write_text(content, encoding="utf-8")

manifest = {
    "application": "PayPal AI Trust Engine",
    "frontend_commit": SHA,
    "build_source": "GitHub Actions checkout",
    "status": "UNVERIFIED_STATIC_FRONTEND",
}
(OUT / "build-info.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
(OUT / "index.html").write_text(
    """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="trustguard-build-commit" content="{sha}">
<title>PayPal AI Trust Engine — Dashboard</title>
</head>
<body>
<main>
<h1>PayPal AI Trust Engine</h1>
<p>Security prototype dashboard. Static status is unverified and is not proof of a live transaction or production security.</p>
<ul>
<li><a href="dashboard.html">Dashboard</a></li>
<li><a href="dashboard_v2.html">Dashboard v2</a></li>
</ul>
<p>Frontend build commit: <code id="build-commit">{sha}</code></p>
<p>Authentication, policy, and delivery status: UNKNOWN until verified backend telemetry is connected.</p>
</main>
</body>
</html>
""".format(sha=SHA),
    encoding="utf-8",
)
print(f"Built _site from commit {SHA}")
