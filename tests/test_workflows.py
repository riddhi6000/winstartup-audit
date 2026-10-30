from pathlib import Path

import pytest
import yaml

WORKFLOW_FOLDER = Path(__file__).resolve().parents[1] / ".github" / "workflows"
WORKFLOWS = sorted(WORKFLOW_FOLDER.glob("*.yml"))


def test_the_workflows_are_found():
    assert {path.name for path in WORKFLOWS} >= {"tests.yml", "windows-scan.yml"}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_workflow_is_valid_yaml_with_runnable_jobs(path):
    # GitHub rejects an invalid workflow file before running anything, and the
    # only symptom is a red mark with no log. A stray ": " inside a command
    # is enough to cause it, so every file is parsed here first.
    data = yaml.safe_load(path.read_text(encoding="utf-8"))

    assert isinstance(data, dict)
    assert data["jobs"], "a workflow needs at least one job"
    assert True in data or "on" in data, "a workflow needs a trigger"  # YAML reads `on` as true

    for name, job in data["jobs"].items():
        assert "runs-on" in job, f"job {name} has no runner"
        assert job["steps"], f"job {name} has no steps"
        for step in job["steps"]:
            assert "uses" in step or "run" in step, f"a step in {name} does nothing"
            if "run" in step:
                assert isinstance(step["run"], str) and step["run"].strip()


def test_the_tests_workflow_runs_on_windows_and_on_two_pythons():
    data = yaml.safe_load((WORKFLOW_FOLDER / "tests.yml").read_text(encoding="utf-8"))
    job = data["jobs"]["test"]

    assert job["runs-on"] == "windows-latest"
    assert job["strategy"]["matrix"]["python-version"] == ["3.12", "3.13"]


def test_the_scan_workflow_uses_the_check_command_instead_of_inline_code():
    data = yaml.safe_load((WORKFLOW_FOLDER / "windows-scan.yml").read_text(encoding="utf-8"))
    commands = [step["run"] for step in data["jobs"]["scan"]["steps"] if "run" in step]

    assert any("winaudit check" in command for command in commands)
    assert not any("python -c" in command for command in commands)
