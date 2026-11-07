#!/usr/bin/env python3
"""Verify the custom models, server OIDC provider, and packaged frontend."""

from __future__ import annotations

import argparse
import hashlib
import importlib
import importlib.metadata
import json
import re
import sys
import tempfile
from pathlib import Path
from typing import Any


def normalized_name(name: str) -> str:
    """Normalize a Python distribution name for identity comparisons."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _report(message: str) -> None:
    sys.stdout.write(f"{message}\n")


def verify_frontend_notices(manifest: dict[str, Any]) -> None:
    """Verify that packaged frontend license notices match the build manifest."""
    record = manifest.get("license_notices", {}).get("frontend_dependency_notices", {})
    expected_hash = record.get("sha256")
    if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        fail("frontend dependency notice hash is missing or invalid")
    notice_paths = (
        Path(str(record.get("path", ""))),
        Path(tempfile.gettempdir()) / "oidc-licenses" / "frontend-THIRD_PARTY_NOTICES.txt",
    )
    for notice_path in notice_paths:
        try:
            actual_hash = hashlib.sha256(notice_path.read_bytes()).hexdigest()
        except OSError:
            continue
        if actual_hash != expected_hash:
            fail(f"frontend dependency notices do not match the build manifest: {notice_path}")
        return
    fail("frontend dependency license notices are missing from the image")


def fail(message: str) -> None:
    """Stop image verification with a specific failure reason."""
    raise SystemExit(f"OIDC image verification failed: {message}")


def verify_distribution(name: str, expected: dict[str, Any]) -> importlib.metadata.Distribution:
    """Check that exactly one installed distribution has the expected version."""
    matches = [
        distribution
        for distribution in importlib.metadata.distributions()
        if normalized_name(distribution.metadata.get("Name", "")) == normalized_name(name)
    ]
    if len(matches) != 1:
        fail(f"expected one installed {name} distribution, found {len(matches)}")
    distribution = matches[0]
    version = distribution.version
    if version != expected["version"]:
        fail(f"{name} is {version}; expected {expected['version']}")
    return distribution


def frontend_asset_hash(package_dir: Path) -> str:
    """Hash packaged frontend assets while excluding generated marker files."""
    excluded = {"oidc_build_info.json", "THIRD_PARTY_NOTICES.txt"}
    digest = hashlib.sha256()
    for path in sorted(item for item in package_dir.rglob("*") if item.is_file()):
        if path.name in excluded or path.suffix == ".pyc" or "__pycache__" in path.parts:
            continue
        relative = path.relative_to(package_dir).as_posix().encode()
        digest.update(relative + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def verify_frontend_package(manifest: dict[str, Any]) -> tuple[str, str]:
    """Verify the installed frontend source, version, assets, and OIDC markers."""
    distributions = manifest["distributions"]
    frontend = importlib.import_module("music_assistant_frontend")
    frontend_dir = Path(frontend.where()).resolve()
    if not frontend_dir.is_dir() or not (frontend_dir / "index.html").is_file():
        fail(f"music_assistant_frontend.where() has no packaged index.html: {frontend_dir}")
    if "site-packages" not in frontend_dir.parts:
        fail(f"frontend did not resolve from the installed Python environment: {frontend_dir}")

    frontend_build_info_path = frontend_dir / "oidc_build_info.json"
    try:
        frontend_info = json.loads(frontend_build_info_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        fail(f"frontend build marker is missing or invalid: {err}")
    expected_frontend = manifest["sources"]["frontend"]["revision"]
    if frontend_info.get("revision") != expected_frontend:
        fail("installed frontend build marker does not match the pinned frontend commit")
    if frontend_info.get("version") != distributions["frontend"]["version"]:
        fail("installed frontend marker does not match its distribution version")
    actual_assets_hash = frontend_asset_hash(frontend_dir)
    if actual_assets_hash != frontend_info.get("assets_sha256"):
        fail("installed frontend assets differ from the recorded production build")
    if actual_assets_hash != distributions["frontend"].get("assets_sha256"):
        fail("installed frontend assets do not match the image build manifest")

    index_html = (frontend_dir / "index.html").read_text(encoding="utf-8")
    expected_meta = f'name="ma-frontend-commit" content="{expected_frontend}"'
    if expected_meta not in index_html:
        fail("frontend index.html does not identify the pinned frontend source commit")
    assets_dir = frontend_dir / "assets"
    javascript_files = list(assets_dir.glob("*.js"))
    if not javascript_files:
        fail("frontend package has no production JavaScript assets")
    javascript = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore") for path in javascript_files
    )
    for marker in manifest.get("frontend_features", []):
        if marker not in javascript:
            fail(f"frontend production bundle is missing expected functionality: {marker}")
    return expected_frontend, actual_assets_hash


def verify_server_build_info(manifest: dict[str, Any]) -> None:
    """Check server source metadata and confirm no private Widevine files shipped."""
    build_info_path = Path("/app/build_info.json")
    try:
        server_build_info = json.loads(build_info_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        fail(f"server build information is missing or invalid: {err}")
    if server_build_info.get("revision") != manifest["sources"]["server"]["revision"]:
        fail("server wheel build information does not match the pinned server revision")

    if manifest.get("base", {}).get("widevine_files_included") is not False:
        fail("build manifest unexpectedly says private Widevine files are included")
    for relative in (
        "/usr/local/bin/widevine_cdm/client_id.bin",
        "/usr/local/bin/widevine_cdm/private_key.pem",
    ):
        if Path(relative).exists():
            fail(f"private Widevine client file was copied into the image: {relative}")


def verify(manifest_path: Path) -> None:
    """Verify installed packages and build markers against the image manifest."""
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        fail(f"cannot read image build manifest {manifest_path}: {err}")

    distributions = manifest["distributions"]
    server_distribution = verify_distribution("music-assistant", distributions["server"])
    verify_distribution("music-assistant-frontend", distributions["frontend"])
    verify_distribution("music-assistant-models", distributions["models"])
    model_auth = importlib.import_module("music_assistant_models.auth")
    if model_auth.AuthProviderType.OIDC.value != "oidc":
        fail("AuthProviderType.OIDC is missing or has the wrong value")
    oidc_provider = importlib.import_module(
        "music_assistant.controllers.webserver.helpers.oidc_provider"
    )
    if not hasattr(oidc_provider, "OIDCLoginProvider"):
        fail("OIDCLoginProvider could not be imported")
    expected_frontend, actual_assets_hash = verify_frontend_package(manifest)
    verify_server_build_info(manifest)
    verify_frontend_notices(manifest)

    _report(f"Server distribution: {server_distribution.version}")
    _report(f"Models distribution: {distributions['models']['version']}")
    _report(f"Frontend distribution: {distributions['frontend']['version']}")
    _report(f"Frontend source: {expected_frontend}")
    _report(f"Frontend assets SHA-256: {actual_assets_hash}")
    _report("Frontend dependency license notices: verified")
    _report("AuthProviderType.OIDC and OIDCLoginProvider: verified")
    _report("No upstream frontend/model replacement or Widevine client files: verified")


def main() -> int:
    """Run image verification for the selected build manifest."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("/app/oidc-build-info.json"))
    parser.add_argument(
        "--package-only",
        action="store_true",
        help="verify installed distributions without starting the Music Assistant server",
    )
    args = parser.parse_args()
    verify(args.manifest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
