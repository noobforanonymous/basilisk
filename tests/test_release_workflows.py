from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_manual_pypi_publication_is_validated_and_enabled() -> None:
    workflow = (ROOT / ".github/workflows/python-publish.yml").read_text(encoding="utf-8")

    assert "release_tag:" in workflow
    assert "signing_ref:" in workflow
    assert "github.event_name == 'workflow_dispatch'" in workflow
    assert "github.ref == 'refs/heads/main'" in workflow
    assert "Release $RELEASE_TAG does not match pyproject.toml version" in workflow
    assert "build.yml@${SIGNING_REF}" in workflow
    assert (
        "pypa/gh-action-pypi-publish@dc37677b2e1c63e2034f94d8a5b11f265b73ba33"
        in workflow
    )


def test_release_workflow_dispatches_pypi_publication() -> None:
    workflow = (ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")

    assert "actions: write" in workflow
    assert "gh workflow run python-publish.yml" in workflow
    assert '--field release_tag="$RELEASE_TAG"' in workflow
    assert '--field signing_ref="$SIGNING_REF"' in workflow
