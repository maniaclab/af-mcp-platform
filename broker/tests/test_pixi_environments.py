"""The container image's pixi environment must not configure the broker.

Containerfile.broker bakes ``pixi shell-hook --environment broker`` into the
image entrypoint, and that script exports every activation variable *after*
Kubernetes sets the container's env. Any broker setting placed in an
activation env of a feature the ``broker`` environment includes therefore
silently overrides the deployment's own configuration in production.
"""

import tomllib
from pathlib import Path

import pytest

_PIXI_TOML = Path(__file__).resolve().parents[2] / "pixi.toml"
_IMAGE_ENVIRONMENT = "broker"


def _environment_features(manifest: dict, environment: str) -> list[str]:
    spec = manifest["environments"][environment]
    features = spec["features"] if isinstance(spec, dict) else spec
    return ["default", *features]


def _activation_env(manifest: dict, feature: str) -> dict[str, str]:
    if feature == "default":
        return manifest.get("activation", {}).get("env", {})
    return (
        manifest.get("feature", {})
        .get(feature, {})
        .get("activation", {})
        .get("env", {})
    )


@pytest.fixture(scope="module")
def manifest() -> dict:
    with _PIXI_TOML.open("rb") as fh:
        return tomllib.load(fh)


def test_image_environment_sets_no_activation_env(manifest: dict) -> None:
    leaked = {
        feature: sorted(_activation_env(manifest, feature))
        for feature in _environment_features(manifest, _IMAGE_ENVIRONMENT)
        if _activation_env(manifest, feature)
    }
    assert leaked == {}, (
        f"features of the {_IMAGE_ENVIRONMENT!r} pixi environment set activation env "
        f"vars that the image entrypoint would export over the deployment's config: {leaked}"
    )


@pytest.mark.parametrize("environment", ["dev", "bypass"])
def test_local_environments_point_at_the_dev_policy_and_services(
    manifest: dict, environment: str
) -> None:
    env: dict[str, str] = {}
    for feature in _environment_features(manifest, environment):
        env.update(_activation_env(manifest, feature))
    # Both are `${VAR:-<default>}`: the default is the dev file, and a
    # caller's own export wins.
    assert "broker/src/af_mcp_broker/authorization/policy.yaml" in env["POLICY_FILE"]
    assert "broker/src/af_mcp_broker/mcp/services.yaml" in env["SERVICES_FILE"]


def test_image_puts_the_broker_environment_on_path() -> None:
    """``kubectl exec`` bypasses the entrypoint, so PATH must come from the image's own ENV."""
    containerfile = _PIXI_TOML.with_name("Containerfile.broker").read_text()

    assert 'ENV PATH="/app/.pixi/envs/broker/bin:$PATH"' in containerfile
