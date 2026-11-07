#!/usr/bin/env python3
"""Prepare and validate the pinned OIDC image build inputs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import urllib.error
import urllib.request
import zipfile
from email.parser import BytesParser
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_COMPONENTS = ("server", "frontend", "models")
BUILD_TOOL_FILES = (
    "oidc-build.lock.json",
    ".github/workflows/oidc-image.yml",
    "Dockerfile.oidc",
    "scripts/oidc_image.py",
    "scripts/verify_oidc_image.py",
    "scripts/smoke_test_oidc_image.py",
)
OIDC_FEATURE_MARKERS = (
    "/auth/oidc/link/start",
    "oidc_registration_policy",
    "Sign in with OpenID Connect",
)


class BuildError(Exception):
    """A user-actionable source or build-input error."""


def _report(message: str) -> None:
    sys.stdout.write(f"{message}\n")


def read_json(path: Path) -> dict[str, Any]:
    """Read a JSON object from a UTF-8 encoded file."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as err:
        raise BuildError(f"Could not read JSON file {path}: {err}") from err


def write_json(path: Path, value: dict[str, Any]) -> None:
    """Write stable, human-readable JSON to a file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def build_tooling_hashes() -> dict[str, str]:
    """Hash the build scripts and configuration that affect the image."""
    hashes: dict[str, str] = {}
    for relative in BUILD_TOOL_FILES:
        path = ROOT / relative
        try:
            hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError as err:
            raise BuildError(f"Could not read build tooling file {path}: {err}") from err
    return hashes


def run(command: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    """Run a fixed-argument command and return its standard output."""
    try:
        completed = subprocess.run(  # noqa: S603 - argv is assembled here; shell execution is disabled.
            command,
            cwd=cwd,
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as err:
        raise BuildError(f"Required command is unavailable: {command[0]}") from err
    except subprocess.CalledProcessError as err:
        detail = (err.stderr or err.stdout or "").strip()
        raise BuildError(f"Command failed ({' '.join(command)}): {detail}") from err
    return completed.stdout.strip()


def validate_repository(repository: str) -> None:
    """Require a GitHub repository in owner/name form."""
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise BuildError(f"Repository must be an owner/name pair, got {repository!r}")


def validate_revision(revision: str, component: str) -> None:
    """Require a full lower-case Git commit SHA."""
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise BuildError(f"{component} revision must be a full lower-case 40-character commit SHA")


def source_values(lock: dict[str, Any], args: argparse.Namespace) -> dict[str, Any]:
    """Resolve and validate component source pins from the lock and CLI."""
    sources: dict[str, Any] = {}
    for component in EXPECTED_COMPONENTS:
        locked = lock["repositories"][component]
        repository = getattr(args, f"{component}_repository") or locked["repository"]
        revision = getattr(args, f"{component}_revision") or locked["revision"]
        validate_repository(repository)
        validate_revision(revision, component)
        sources[component] = {"repository": repository, "revision": revision}
    return sources


def resolve(args: argparse.Namespace) -> None:
    """Write the resolved, hashed inputs for a container build."""
    lock = read_json(args.lock)
    sources = source_values(lock, args)
    frontend_assets_sha256 = (
        args.frontend_assets_sha256 or lock.get("frontend_build", {}).get("assets_sha256", "")
    ).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", frontend_assets_sha256):
        raise BuildError(
            "A reviewed frontend_assets_sha256 is required in the lock file or dispatch input"
        )
    publish = args.publish
    if publish and not args.redistribution_reviewed:
        raise BuildError(
            "Publishing is disabled until redistribution rights have been reviewed. "
            "The base build uses FFmpeg --enable-nonfree; see the OIDC Docker build guide."
        )
    tooling_hashes = build_tooling_hashes()
    build_inputs = {
        "sources": sources,
        "frontend_assets_sha256": frontend_assets_sha256,
        "build_tooling_sha256": tooling_hashes,
        "vcs_dependencies": lock["vcs_dependencies"],
        "toolchain": lock["toolchain"],
        "base": lock["base"],
        "image": lock["image"],
    }
    input_manifest_sha256 = hashlib.sha256(
        json.dumps(build_inputs, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    build_tag = "oidc-" + "-".join(
        [*(sources[name]["revision"][:12] for name in EXPECTED_COMPONENTS), input_manifest_sha256]
    )
    if len(build_tag) > 128:
        raise BuildError("Commit-derived image tag exceeds the OCI 128-character limit")
    resolved = {
        "schema_version": 1,
        "sources": sources,
        "frontend_assets_sha256": frontend_assets_sha256,
        "build_tooling_sha256": tooling_hashes,
        "vcs_dependencies": lock["vcs_dependencies"],
        "toolchain": lock["toolchain"],
        "base": lock["base"],
        "image": lock["image"],
        "build_tag": build_tag,
        "input_manifest_sha256": input_manifest_sha256,
        "publish": publish,
        "redistribution_reviewed": args.redistribution_reviewed,
    }
    write_json(args.output, resolved)
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as output:
            for component in EXPECTED_COMPONENTS:
                output.write(f"{component}_repository={sources[component]['repository']}\n")
                output.write(f"{component}_revision={sources[component]['revision']}\n")
            output.write(f"image={resolved['image']}\n")
            output.write(f"build_tag={build_tag}\n")
            output.write(f"input_manifest_sha256={input_manifest_sha256}\n")
            output.write(f"publish={'true' if publish else 'false'}\n")
            output.write(f"frontend_assets_sha256={frontend_assets_sha256}\n")
            for name, value in lock["toolchain"].items():
                output.write(f"{name}={value}\n")
    _report(f"Resolved source tag: {build_tag}")


def verify_remote_commit(repository: str, revision: str) -> None:
    """Confirm GitHub serves the requested commit for a pinned repository."""
    validate_repository(repository)
    validate_revision(revision, repository)
    url = f"https://api.github.com/repos/{repository}/commits/{revision}"
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "music-assistant-oidc-image-build",
    }
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 - URL uses fixed HTTPS host and validated path components.
            payload = json.loads(response.read())
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError,
    ) as err:
        raise BuildError(
            f"Pinned commit {repository}@{revision} is unavailable from GitHub: {err}"
        ) from err
    if payload.get("sha", "").lower() != revision:
        raise BuildError(
            f"GitHub returned {payload.get('sha')!r} for {repository}@{revision}; refusing build"
        )
    _report(f"Verified GitHub source {repository}@{revision}")


def verify_checkout(directory: Path, repository: str, revision: str) -> None:
    """Check a local checkout and its remote GitHub commit against the pin."""
    if not directory.is_dir():
        raise BuildError(f"Checkout directory does not exist: {directory}")
    actual = run(["git", "rev-parse", "HEAD"], cwd=directory).lower()
    if actual != revision:
        raise BuildError(f"{repository} checkout is at {actual}, expected pinned commit {revision}")
    verify_remote_commit(repository, revision)


def verify_sources(args: argparse.Namespace) -> None:
    """Verify all component and VCS dependency source revisions."""
    resolved = read_json(args.resolved)
    for component in EXPECTED_COMPONENTS:
        source = resolved["sources"][component]
        verify_checkout(
            Path(getattr(args, f"{component}_dir")),
            source["repository"],
            source["revision"],
        )
    for dependency in resolved["vcs_dependencies"].values():
        verify_remote_commit(dependency["repository"], dependency["revision"])


def commit_epoch(directory: Path, revision: str) -> str:
    """Return the commit timestamp used for reproducible build metadata."""
    return run(["git", "show", "-s", "--format=%ct", revision], cwd=directory)


def package_metadata(wheel: Path) -> tuple[dict[str, str], bytes]:
    """Read normalized project metadata and raw METADATA bytes from a wheel."""
    try:
        with zipfile.ZipFile(wheel) as archive:
            metadata_path = next(
                name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
            )
            raw = archive.read(metadata_path)
    except (OSError, zipfile.BadZipFile, StopIteration) as err:
        raise BuildError(f"Wheel metadata missing or corrupt: {wheel}") from err
    message = BytesParser().parsebytes(raw)
    metadata = {
        "name": str(message.get("Name", "")),
        "version": str(message.get("Version", "")),
        "requires_python": str(message.get("Requires-Python", "")),
    }
    return metadata, raw


def normalized_name(name: str) -> str:
    """Normalize a distribution name according to Python package rules."""
    return re.sub(r"[-_.]+", "-", name).lower()


def one_wheel(directory: Path, label: str) -> Path:
    """Return the sole wheel in a build directory or fail clearly."""
    wheels = sorted(directory.glob("*.whl"))
    if len(wheels) != 1:
        raise BuildError(f"Expected exactly one {label} wheel in {directory}; found {len(wheels)}")
    return wheels[0]


def inspect_frontend_wheel(wheel: Path, expected_revision: str) -> dict[str, str]:
    """Validate the frontend wheel's source marker and OIDC production assets."""
    metadata, _ = package_metadata(wheel)
    if normalized_name(metadata["name"]) != "music-assistant-frontend":
        raise BuildError(f"Unexpected frontend wheel name: {metadata['name']}")
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
        marker_path = "music_assistant_frontend/oidc_build_info.json"
        if "music_assistant_frontend/index.html" not in names or marker_path not in names:
            raise BuildError("Frontend wheel is missing built assets or its source marker")
        marker = json.loads(archive.read(marker_path))
        if marker.get("revision") != expected_revision:
            raise BuildError("Frontend wheel marker does not match the pinned frontend commit")
        if marker.get("version") != metadata["version"]:
            raise BuildError("Frontend wheel metadata version does not match its build marker")
        javascript = b"\n".join(
            archive.read(name)
            for name in names
            if name.startswith("music_assistant_frontend/assets/") and name.endswith(".js")
        ).decode("utf-8", errors="ignore")
        missing = [token for token in OIDC_FEATURE_MARKERS if token not in javascript]
        if missing:
            raise BuildError(
                "Built frontend is missing expected OIDC functionality markers: "
                + ", ".join(missing)
            )
        index_html = archive.read("music_assistant_frontend/index.html").decode("utf-8")
        if f'name="ma-frontend-commit" content="{expected_revision}"' not in index_html:
            raise BuildError("Built frontend index does not identify the pinned source commit")
    return {**metadata, "assets_sha256": marker["assets_sha256"]}


def _stage_frontend_package(
    frontend_dir: Path, package_dir: Path, output_dir: Path, patched_pyproject: str
) -> None:
    """Copy the stamped package and build metadata into an isolated source tree."""
    if output_dir.exists():
        raise BuildError(f"Frontend package staging directory already exists: {output_dir}")
    output_dir.mkdir(parents=True)
    for filename in ("README.md", "LICENSE", "MANIFEST.in"):
        source = frontend_dir / filename
        if source.is_file():
            shutil.copy2(source, output_dir / filename)
    (output_dir / "pyproject.toml").write_text(patched_pyproject, encoding="utf-8")
    shutil.copytree(package_dir, output_dir / "music_assistant_frontend")


def stamp_frontend(args: argparse.Namespace) -> None:
    """Add reviewed source metadata and notices to the built frontend package."""
    frontend_dir = Path(args.frontend_dir)
    server_dir = Path(args.server_dir)
    revision = args.revision.lower()
    validate_revision(revision, "frontend")
    frontend_source = run(["git", "rev-parse", "HEAD"], cwd=frontend_dir).lower()
    if frontend_source != revision:
        raise BuildError(f"Frontend checkout is at {frontend_source}, expected {revision}")

    server_project = tomllib.loads((server_dir / "pyproject.toml").read_text(encoding="utf-8"))
    expected_public_version: str | None = None
    for dependency in server_project["project"]["dependencies"]:
        match = re.fullmatch(r"music-assistant-frontend==([^;\s]+)", dependency)
        if match:
            expected_public_version = match.group(1)
            break
    if not expected_public_version:
        raise BuildError("Server pyproject does not pin music-assistant-frontend with ==VERSION")
    version = f"{expected_public_version}+woobble.oidc.g{revision[:12]}"

    pyproject = frontend_dir / "pyproject.toml"
    source_text = pyproject.read_text(encoding="utf-8")
    project = tomllib.loads(source_text)["project"]
    existing_version = project["version"]
    patched, count = re.subn(
        r'(?m)^version\s*=\s*"[^"]+"\s*$',
        f'version = "{version}"',
        source_text,
        count=1,
    )
    if count != 1:
        raise BuildError("Could not set the frontend distribution version in pyproject.toml")

    package_dir = frontend_dir / "music_assistant_frontend"
    index_path = package_dir / "index.html"
    if not index_path.is_file():
        raise BuildError("Frontend production build is missing music_assistant_frontend/index.html")
    index_html = index_path.read_text(encoding="utf-8")
    if "ma-frontend-commit" in index_html:
        raise BuildError("Frontend index already has an OIDC build marker; clean and rebuild it")
    marker = f'<meta name="ma-frontend-commit" content="{revision}">'
    if not re.search(r"<head(?:\s[^>]*)?>", index_html, flags=re.IGNORECASE):
        raise BuildError("Frontend build index has no <head> element")
    index_html = re.sub(
        r"(<head(?:\s[^>]*)?>)",
        lambda match: match.group(1) + marker,
        index_html,
        count=1,
        flags=re.IGNORECASE,
    )
    index_path.write_text(index_html, encoding="utf-8")

    notice_text = collect_frontend_notices(frontend_dir)
    (package_dir / "THIRD_PARTY_NOTICES.txt").write_text(notice_text, encoding="utf-8")
    assets_sha256 = hash_frontend_assets(package_dir)
    expected_assets_sha256 = args.expected_assets_sha256.lower()
    if assets_sha256 != expected_assets_sha256:
        raise BuildError(
            "Built frontend assets do not match the reviewed hash: "
            f"expected {expected_assets_sha256}, got {assets_sha256}. "
            "Review the new output and update the lock file before building an image."
        )
    write_json(
        package_dir / "oidc_build_info.json",
        {
            "repository": args.repository,
            "revision": revision,
            "version": version,
            "assets_sha256": assets_sha256,
            "previous_project_version": existing_version,
            "features": list(OIDC_FEATURE_MARKERS),
        },
    )
    output_dir = Path(args.output)
    _stage_frontend_package(frontend_dir, package_dir, output_dir, patched)
    _report(f"Stamped built frontend from {revision} as {version}")
    _report(f"Frontend assets SHA-256: {assets_sha256}")
    _report(f"Prepared isolated Python package source at {output_dir}")


def hash_frontend_assets(package_dir: Path) -> str:
    """Hash all packaged frontend files except generated build metadata."""
    excluded = {"oidc_build_info.json", "THIRD_PARTY_NOTICES.txt"}
    digest = hashlib.sha256()
    for path in sorted(item for item in package_dir.rglob("*") if item.is_file()):
        if path.name in excluded:
            continue
        relative = path.relative_to(package_dir).as_posix().encode()
        digest.update(relative + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def collect_frontend_notices(frontend_dir: Path) -> str:
    """Collect declared licenses and available notices from pnpm packages."""
    package_store = frontend_dir / "node_modules" / ".pnpm"
    if not package_store.is_dir():
        raise BuildError("pnpm node_modules is missing; install with --frozen-lockfile first")
    records: list[tuple[str, str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for package_json in sorted(package_store.glob("*/node_modules/**/package.json")):
        try:
            package = json.loads(package_json.read_text(encoding="utf-8"))
        except OSError, json.JSONDecodeError:
            continue
        name = package.get("name")
        version = package.get("version")
        if not name or not version or name == "frontend":
            continue
        package_root = package_json.parent
        license_value = package.get("license", "UNSPECIFIED")
        if isinstance(license_value, (dict, list)):
            license_value = json.dumps(license_value, sort_keys=True)
        license_files = sorted(
            path
            for path in package_root.iterdir()
            if path.is_file()
            and re.match(r"^(license|licence|copying|notice)(\.|$|[-_])", path.name, re.IGNORECASE)
        )
        text = "\n\n".join(
            f"--- {path.name} ---\n{path.read_text(encoding='utf-8', errors='replace')}"
            for path in license_files
            if path.stat().st_size <= 1_000_000
        )
        key = (f"{name}@{version}", text)
        if key in seen:
            continue
        seen.add(key)
        records.append((str(name), str(version), str(license_value), text))
    if not records:
        raise BuildError("Could not collect any frontend dependency license metadata")
    lines = [
        "Music Assistant frontend dependency notices",
        "Collected from pnpm's installed package store for the locked frontend build.",
        "The package's declared license is shown for every dependency; available license",
        "and notice files are included below. This list includes development dependencies too.",
        "",
    ]
    for name, version, license_value, text in records:
        lines.extend([f"{name} {version}", f"Declared license: {license_value}"])
        if text:
            lines.extend([text])
        else:
            lines.append("No standalone license or notice file was present in the package.")
        lines.append("")
    return "\n".join(lines)


def wheel_info(wheel: Path, expected_name: str) -> dict[str, str]:
    """Return verified wheel metadata with its SHA-256 digest."""
    metadata, raw = package_metadata(wheel)
    if normalized_name(metadata["name"]) != normalized_name(expected_name):
        raise BuildError(
            f"Expected {expected_name} wheel; got {metadata['name']} from {wheel.name}"
        )
    return {
        **metadata,
        "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "metadata": raw.decode("utf-8", errors="replace"),
    }


def verify_wheel_set(
    server_wheel: Path,
    frontend_wheel: Path,
    models_wheel: Path,
    resolved: dict[str, Any],
) -> dict[str, Any]:
    """Check wheel identities, source pins, frontend assets, and OIDC models."""
    server = wheel_info(server_wheel, "music-assistant")
    frontend = wheel_info(frontend_wheel, "music-assistant-frontend")
    models = wheel_info(models_wheel, "music-assistant-models")
    requirements = server["metadata"].splitlines()
    for component, package, expected in (
        ("models", "music-assistant-models", "1.1.236"),
        ("frontend", "music-assistant-frontend", None),
    ):
        lines = [
            line for line in requirements if line.lower().startswith(f"requires-dist: {package}")
        ]
        if len(lines) != 1:
            raise BuildError(f"Server wheel must declare exactly one {package} dependency")
        match = re.search(r"==([^;\s]+)", lines[0])
        if not match:
            raise BuildError(f"Server wheel {package} requirement is not an exact pin")
        public_version = match.group(1)
        wheel_version = models["version"] if component == "models" else frontend["version"]
        if expected and public_version != expected:
            raise BuildError(
                f"Server wheel expects {package} {public_version}; expected {expected}"
            )
        if wheel_version.split("+", 1)[0] != public_version or "+" not in wheel_version:
            raise BuildError(
                f"Custom {package} version {wheel_version} does not satisfy server pin {public_version}"
            )

    aiolib_pins = resolved["vcs_dependencies"]["aiolibdatachannel"]["revision"]
    if not any(
        line.startswith("Requires-Dist: aiolibdatachannel @") and aiolib_pins in line
        for line in requirements
    ):
        raise BuildError("Server wheel does not contain the pinned aiolibdatachannel commit")
    frontend_info = inspect_frontend_wheel(
        frontend_wheel, resolved["sources"]["frontend"]["revision"]
    )
    if frontend_info["assets_sha256"] != resolved["frontend_assets_sha256"]:
        raise BuildError("Frontend wheel assets do not match the reviewed build hash")
    frontend["assets_sha256"] = frontend_info["assets_sha256"]

    with zipfile.ZipFile(models_wheel) as archive:
        auth_model = next(
            (
                name
                for name in archive.namelist()
                if name.endswith("music_assistant_models/auth.py")
            ),
            None,
        )
        if not auth_model or not re.search(
            rb"\bOIDC\s*=\s*['\"]oidc['\"]", archive.read(auth_model)
        ):
            raise BuildError("Models wheel does not define AuthProviderType.OIDC = 'oidc'")

    return {
        "server": {key: value for key, value in server.items() if key != "metadata"},
        "frontend": {key: value for key, value in frontend.items() if key != "metadata"},
        "models": {key: value for key, value in models.items() if key != "metadata"},
    }


def build_server_wheel(args: argparse.Namespace) -> None:
    """Build a reproducible server wheel from the pinned source commit."""
    server_dir = Path(args.server_dir)
    resolved = read_json(args.resolved)
    revision = resolved["sources"]["server"]["revision"]
    actual = run(["git", "rev-parse", "HEAD"], cwd=server_dir).lower()
    if actual != revision:
        raise BuildError(f"Server checkout is at {actual}, expected {revision}")
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix="music-assistant-server-wheel-"))
    try:
        archive_path = work_dir / "source.tar"
        run(
            ["git", "archive", "--format=tar", "--output", str(archive_path), revision],
            cwd=server_dir,
        )
        source_dir = work_dir / "source"
        source_dir.mkdir()
        with tarfile.open(archive_path) as archive:
            archive.extractall(source_dir, filter="data")
        pyproject = source_dir / "pyproject.toml"
        contents = pyproject.read_text(encoding="utf-8")
        dep = resolved["vcs_dependencies"]["aiolibdatachannel"]
        old = f"git+https://github.com/{dep['repository']}@{dep['replaces']}"
        new = f"git+https://github.com/{dep['repository']}@{dep['revision']}"
        contents, count = contents.replace(old, new), contents.count(old)
        if count != 1:
            raise BuildError(
                "Could not apply the pinned aiolibdatachannel package metadata override"
            )
        pyproject.write_text(contents, encoding="utf-8")
        env = os.environ.copy()
        env["SOURCE_DATE_EPOCH"] = commit_epoch(server_dir, revision)
        env["TZ"] = "UTC"
        run(
            ["uv", "build", "--wheel", "--out-dir", str(output), str(source_dir)],
            cwd=server_dir,
            env=env,
        )
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
    wheel = one_wheel(output, "server")
    _report(f"Built server wheel: {wheel.name} ({hashlib.sha256(wheel.read_bytes()).hexdigest()})")


def replace_requirement(contents: str, package: str, new_line: str) -> str:
    """Replace exactly one package requirement in a requirements file."""
    lines = contents.splitlines()
    matches = [
        index for index, line in enumerate(lines) if line.lower().startswith(f"{package.lower()} @")
    ]
    if len(matches) != 1:
        raise BuildError(f"Expected one {package} VCS requirement, found {len(matches)}")
    lines[matches[0]] = new_line
    return "\n".join(lines) + "\n"


def assert_vcs_requirements_are_pinned(contents: str) -> None:
    """Reject VCS dependency lines that do not use a full commit SHA."""
    for line in contents.splitlines():
        if " @ git+" not in line:
            continue
        match = re.search(r"@([0-9a-f]{40})(?:\s|$)", line)
        if not match:
            raise BuildError(f"Unpinned VCS dependency in container requirements: {line}")


def prepare_base_context(
    server_dir: Path,
    output: Path,
    python_version: str,
    python_image: str,
    debian_snapshot: str,
    dockerfile_frontend: str,
) -> None:
    """Create a locked Docker base context without private Widevine files."""
    dockerfile = (server_dir / "Dockerfile.base").read_text(encoding="utf-8")
    if not re.fullmatch(r"docker/dockerfile:[^@\s]+@sha256:[0-9a-f]{64}", dockerfile_frontend):
        raise BuildError("Dockerfile frontend must be pinned by digest")
    dockerfile, syntax_count = re.subn(
        r"(?m)^# syntax=[^\s]+$",
        f"# syntax={dockerfile_frontend}",
        dockerfile,
        count=1,
    )
    if syntax_count != 1:
        raise BuildError("Dockerfile.base no longer has its expected syntax directive")
    dockerfile, py_count = re.subn(
        r"(?m)^ARG PYTHON_VERSION=3\.14\s*$",
        f"ARG PYTHON_IMAGE={python_image}\nARG PYTHON_VERSION={python_version}",
        dockerfile,
        count=1,
    )
    if py_count != 1:
        raise BuildError("Dockerfile.base no longer has its expected Python version default")
    dockerfile, from_count = re.subn(
        r"(?m)^FROM python:\$\{PYTHON_VERSION\}-slim-trixie(\s+AS\s+[^\s]+)?$",
        lambda match: "FROM ${PYTHON_IMAGE}" + (match.group(1) or ""),
        dockerfile,
    )
    if from_count != 4:
        raise BuildError(f"Expected four pinned Python base stages, found {from_count}")

    apt_sources_replacement = (
        "sed -i -e 's|^URIs: http://deb.debian.org/debian$|"
        f"URIs: http://snapshot.debian.org/archive/debian/{debian_snapshot}|"
        "' -e 's|^URIs: http://deb.debian.org/debian-security$|"
        f"URIs: http://snapshot.debian.org/archive/debian-security/{debian_snapshot}|"
        "' /etc/apt/sources.list.d/debian.sources && "
        "apt-get -o Acquire::Check-Valid-Until=false update"
    )
    apt_update_count = dockerfile.count("apt-get update")
    if apt_update_count < 3:
        raise BuildError("Dockerfile.base no longer has the expected apt update commands")
    dockerfile = dockerfile.replace("apt-get update", apt_sources_replacement)

    widevine_block = (
        "# Copy widevine client files to container\n"
        "RUN mkdir -p /usr/local/bin/widevine_cdm\n"
        "COPY widevine_cdm/* /usr/local/bin/widevine_cdm/\n"
    )
    if dockerfile.count(widevine_block) != 1:
        raise BuildError(
            "Could not safely remove the private Widevine file injection from Dockerfile.base"
        )
    dockerfile = dockerfile.replace(widevine_block, "")

    ffmpeg_cleanup = (
        "    && strip /usr/local/bin/ffmpeg /usr/local/bin/ffprobe \\\n    && rm -rf /tmp/ffmpeg*"
    )
    ffmpeg_cleanup_replacement = (
        "    && strip /usr/local/bin/ffmpeg /usr/local/bin/ffprobe \\\n"
        "    && mkdir -p /usr/local/share/licenses/FFmpeg \\\n"
        "    && cp COPYING.GPLv3 /usr/local/share/licenses/FFmpeg/COPYING.GPLv3 \\\n"
        "    && rm -rf /tmp/ffmpeg*"
    )
    if dockerfile.count(ffmpeg_cleanup) != 1:
        raise BuildError("Could not add the FFmpeg GPL license notice to the custom base")
    dockerfile = dockerfile.replace(ffmpeg_cleanup, ffmpeg_cleanup_replacement)

    ffmpeg_copy_anchor = "COPY --from=ffmpeg-builder /usr/local/lib/libsw*.so* /usr/local/lib/\n"
    ffmpeg_copy_position = dockerfile.rfind(ffmpeg_copy_anchor)
    if ffmpeg_copy_position < 0:
        raise BuildError("Could not preserve the FFmpeg license notice in the custom base")
    insertion = ffmpeg_copy_position + len(ffmpeg_copy_anchor)
    dockerfile = (
        dockerfile[:insertion]
        + "COPY --from=ffmpeg-builder /usr/local/share/licenses/FFmpeg/ /usr/local/share/licenses/FFmpeg/\n"
        + dockerfile[insertion:]
    )

    output.mkdir(parents=True)
    manifest = server_dir / "music_assistant/providers/sendspin/manifest.json"
    if not manifest.is_file():
        raise BuildError(f"Missing PyAV version manifest required by Dockerfile.base: {manifest}")
    (output / "Dockerfile.base").write_text(dockerfile, encoding="utf-8")
    manifest_dest = output / "music_assistant/providers/sendspin/manifest.json"
    manifest_dest.parent.mkdir(parents=True)
    shutil.copy2(manifest, manifest_dest)
    write_json(
        output / "base-build-info.json",
        {
            "dockerfile_frontend": dockerfile_frontend,
            "python_image": python_image,
            "debian_snapshot": debian_snapshot,
            "widevine_files_included": False,
            "ffmpeg_license_notice": "/usr/local/share/licenses/FFmpeg/COPYING.GPLv3",
        },
    )


def _write_context_requirements(
    server_dir: Path, output: Path, resolved: dict[str, Any], wheel_paths: dict[str, Path]
) -> str:
    """Pin VCS dependencies and replace frontend/model pins with local wheels."""
    requirements = (server_dir / "requirements_all.txt").read_text(encoding="utf-8")
    aiolib = resolved["vcs_dependencies"]["aiolibdatachannel"]
    lc3 = resolved["vcs_dependencies"]["lc3py"]
    requirements = replace_requirement(
        requirements,
        "aiolibdatachannel",
        f"aiolibdatachannel @ git+https://github.com/{aiolib['repository']}@{aiolib['revision']}",
    )
    requirements = replace_requirement(
        requirements,
        "lc3py",
        f"lc3py @ git+https://github.com/{lc3['repository']}.git@{lc3['revision']}",
    )
    assert_vcs_requirements_are_pinned(requirements)
    for package, component in (
        ("music-assistant-models", "models"),
        ("music-assistant-frontend", "frontend"),
    ):
        lines = requirements.splitlines()
        matches = [
            index for index, line in enumerate(lines) if line.lower().startswith(f"{package}==")
        ]
        if len(matches) != 1:
            raise BuildError(f"Expected one pinned {package} requirement, found {len(matches)}")
        lines[matches[0]] = f"./dist/{wheel_paths[component].name}"
        requirements = "\n".join(lines) + "\n"
    assert_vcs_requirements_are_pinned(requirements)
    (output / "requirements_all.txt").write_text(requirements, encoding="utf-8")
    return requirements


def prepare_context(args: argparse.Namespace) -> None:
    """Assemble verified wheels, licenses, and Docker files into a build context."""
    resolved = read_json(args.resolved)
    server_dir = Path(args.server_dir)
    frontend_dir = Path(args.frontend_dir)
    models_dir = Path(args.models_dir)
    tools_dir = Path(args.tools_dir)
    output = Path(args.output)
    if output.exists():
        raise BuildError(
            f"Build context already exists; remove it explicitly before rebuilding: {output}"
        )
    output.mkdir(parents=True)

    server_wheel = one_wheel(Path(args.server_dist), "server")
    frontend_wheel = one_wheel(Path(args.frontend_dist), "frontend")
    models_wheel = one_wheel(Path(args.models_dist), "models")
    package_versions = verify_wheel_set(server_wheel, frontend_wheel, models_wheel, resolved)

    dist_dir = output / "dist"
    dist_dir.mkdir()
    wheel_paths = {}
    for component, wheel in (
        ("server", server_wheel),
        ("frontend", frontend_wheel),
        ("models", models_wheel),
    ):
        destination = dist_dir / wheel.name
        shutil.copy2(wheel, destination)
        wheel_paths[component] = destination

    requirements = _write_context_requirements(server_dir, output, resolved, wheel_paths)

    source_metadata = resolved["sources"]
    frontend_notices = frontend_dir / "music_assistant_frontend" / "THIRD_PARTY_NOTICES.txt"
    if not frontend_notices.is_file() or frontend_notices.stat().st_size == 0:
        raise BuildError("Frontend dependency license notices are missing or empty")
    frontend_notices_sha256 = hashlib.sha256(frontend_notices.read_bytes()).hexdigest()
    build_info = {
        "schema_version": 1,
        "image": resolved["image"],
        "tag": resolved["build_tag"],
        "input_manifest_sha256": resolved["input_manifest_sha256"],
        "build_tooling_sha256": resolved["build_tooling_sha256"],
        "sources": source_metadata,
        "frontend_features": list(OIDC_FEATURE_MARKERS),
        "vcs_dependencies": resolved["vcs_dependencies"],
        "distributions": package_versions,
        "requirements_all_sha256": hashlib.sha256(requirements.encode()).hexdigest(),
        "license_notices": {
            "frontend_dependency_notices": {
                "path": "/usr/share/licenses/music-assistant-oidc/frontend-THIRD_PARTY_NOTICES.txt",
                "sha256": frontend_notices_sha256,
            }
        },
        "base": {
            **resolved["base"],
            "widevine_files_included": False,
            "apple_music_widevine_supported": False,
            "ffmpeg_nonfree_enabled": True,
        },
    }
    write_json(output / "oidc-build-info.json", build_info)

    for filename in ("Dockerfile.oidc", "scripts/verify_oidc_image.py"):
        source = tools_dir / filename
        if not source.is_file():
            raise BuildError(f"Missing OIDC build input: {source}")
        if filename == "Dockerfile.oidc":
            expected_syntax = f"# syntax={resolved['base']['dockerfile_frontend']}"
            if source.read_text(encoding="utf-8").splitlines()[0] != expected_syntax:
                raise BuildError("Dockerfile.oidc syntax directive does not match the lock file")
        destination = output / Path(filename).name
        shutil.copy2(source, destination)

    license_dir = output / "licenses"
    license_dir.mkdir()
    shutil.copy2(frontend_notices, license_dir / "frontend-THIRD_PARTY_NOTICES.txt")
    for component, directory in (
        ("server", server_dir),
        ("frontend", frontend_dir),
        ("models", models_dir),
    ):
        for filename in ("LICENSE", "NOTICE"):
            source = directory / filename
            if source.is_file():
                shutil.copy2(source, license_dir / f"{component}-{filename}")
    limitations = (
        "This image omits the private Widevine client files copied by the upstream base image.\n"
        "Apple Music playback requiring those files is unavailable unless the operator supplies\n"
        "their own authorized CDM files outside this image. The inherited FFmpeg build enables\n"
        "GPL and nonfree components; review redistribution rights before publishing this image.\n"
    )
    (license_dir / "BUILD-LIMITATIONS.txt").write_text(limitations, encoding="utf-8")

    prepare_base_context(
        server_dir,
        output / "base-context",
        resolved["toolchain"]["python"],
        resolved["base"]["python_image"],
        resolved["base"]["debian_snapshot"],
        resolved["base"]["dockerfile_frontend"],
    )
    _report(f"Prepared OIDC Docker context at {output}")
    _report(json.dumps(build_info, indent=2, sort_keys=True))


def write_test_requirements(args: argparse.Namespace) -> None:
    """Write runtime and test requirements with VCS pins checked."""
    server_project = tomllib.loads(
        (Path(args.server_dir) / "pyproject.toml").read_text(encoding="utf-8")
    )["project"]
    requirements = Path(args.requirements).read_text(encoding="utf-8").rstrip()
    test_dependencies = server_project.get("optional-dependencies", {}).get("test", [])
    if not test_dependencies:
        raise BuildError("Server pyproject has no test extra")
    requirements += "\n\n# Pinned development dependencies used by the focused auth tests.\n"
    requirements += "\n".join(test_dependencies) + "\n"
    assert_vcs_requirements_are_pinned(requirements)
    Path(args.output).write_text(requirements, encoding="utf-8")
    _report(f"Wrote pinned test requirements to {args.output}")


def build_parser() -> argparse.ArgumentParser:
    """Create the command-line parser for OIDC image build operations."""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    resolve_parser = subparsers.add_parser(
        "resolve", help="resolve lock-file pins and workflow inputs"
    )
    resolve_parser.add_argument("--lock", type=Path, default=ROOT / "oidc-build.lock.json")
    resolve_parser.add_argument("--output", type=Path, required=True)
    resolve_parser.add_argument("--github-output", type=Path)
    for component in EXPECTED_COMPONENTS:
        resolve_parser.add_argument(f"--{component}-repository", default="")
        resolve_parser.add_argument(f"--{component}-revision", default="")
    resolve_parser.add_argument("--publish", action="store_true")
    resolve_parser.add_argument("--redistribution-reviewed", action="store_true")
    resolve_parser.add_argument("--frontend-assets-sha256", default="")
    resolve_parser.set_defaults(func=resolve)

    verify_parser = subparsers.add_parser(
        "verify-sources", help="verify exact local and GitHub commits"
    )
    verify_parser.add_argument("--resolved", type=Path, required=True)
    for component in EXPECTED_COMPONENTS:
        verify_parser.add_argument(f"--{component}-dir", type=Path, required=True)
    verify_parser.set_defaults(func=verify_sources)

    server_parser = subparsers.add_parser(
        "build-server-wheel", help="build server wheel from pinned source"
    )
    server_parser.add_argument("--server-dir", type=Path, required=True)
    server_parser.add_argument("--resolved", type=Path, required=True)
    server_parser.add_argument("--output", type=Path, required=True)
    server_parser.set_defaults(func=build_server_wheel)

    frontend_parser = subparsers.add_parser(
        "stamp-frontend", help="stamp built frontend and package version"
    )
    frontend_parser.add_argument("--frontend-dir", type=Path, required=True)
    frontend_parser.add_argument("--server-dir", type=Path, required=True)
    frontend_parser.add_argument("--repository", required=True)
    frontend_parser.add_argument("--revision", required=True)
    frontend_parser.add_argument("--expected-assets-sha256", required=True)
    frontend_parser.add_argument("--output", type=Path, required=True)
    frontend_parser.set_defaults(func=stamp_frontend)

    context_parser = subparsers.add_parser(
        "prepare-context", help="assemble verified wheel and Docker inputs"
    )
    for name in (
        "resolved",
        "server-dir",
        "frontend-dir",
        "models-dir",
        "server-dist",
        "frontend-dist",
        "models-dist",
        "tools-dir",
        "output",
    ):
        context_parser.add_argument(f"--{name}", type=Path, required=True)
    context_parser.set_defaults(func=prepare_context)

    tests_parser = subparsers.add_parser(
        "write-test-requirements",
        help="add pinned server test dependencies to runtime requirements",
    )
    tests_parser.add_argument("--server-dir", type=Path, required=True)
    tests_parser.add_argument("--requirements", type=Path, required=True)
    tests_parser.add_argument("--output", type=Path, required=True)
    tests_parser.set_defaults(func=write_test_requirements)
    return parser


def main() -> int:
    """Run the selected build command and report expected input errors."""
    args = build_parser().parse_args()
    try:
        args.func(args)
    except BuildError as err:
        sys.stderr.write(f"OIDC image build error: {err}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
