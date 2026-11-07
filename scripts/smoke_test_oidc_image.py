#!/usr/bin/env python3
"""Start an isolated container and check its startup, auth API, and frontend."""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import urllib.parse
import uuid
from pathlib import Path


def docker(command: list[str], *, check: bool = True) -> str:
    """Run a Docker CLI argument vector and return its standard output."""
    try:
        result = subprocess.run(  # noqa: S603 - argv is passed directly without a shell.
            command, check=check, capture_output=True, text=True
        )
    except FileNotFoundError as err:
        raise RuntimeError("Docker is required for the container smoke test") from err
    if check and result.returncode:
        raise RuntimeError(f"Docker command failed: {' '.join(command)}\n{result.stderr.strip()}")
    return result.stdout.strip()


def http_request(
    url: str, *, method: str = "GET", timeout: int = 5
) -> tuple[int, bytes, dict[str, str]]:
    """Request a local smoke-test endpoint and return its status, body, and headers."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}:
        raise RuntimeError(f"Smoke-test requests must target the local container: {url}")
    connection = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=timeout)
    try:
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        connection.request(method, path)
        response = connection.getresponse()
        return response.status, response.read(), dict(response.getheaders())
    finally:
        connection.close()


def check_package_image(image: str) -> None:
    """Run the image's package integrity verifier without starting the server."""
    sys.stdout.write("Checking installed image packages and pinned frontend marker\n")
    docker(
        [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "/app/venv/bin/python",
            image,
            "/app/verify_oidc_image.py",
            "--manifest",
            "/app/oidc-build-info.json",
            "--package-only",
        ]
    )


def _container_base_url(name: str) -> str:
    """Return the local URL for a container's dynamically published port."""
    port_text = docker(["docker", "port", name, "8095/tcp"])
    match = re.search(r":(\d+)$", port_text)
    if not match:
        raise RuntimeError(f"Could not determine the mapped server port: {port_text}")
    return f"http://127.0.0.1:{match.group(1)}"


def _wait_for_frontend(name: str, base_url: str, timeout: int) -> bytes:
    """Wait for the container to serve its HTML frontend or report its logs."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, body, _headers = http_request(base_url + "/", timeout=3)
            if status == 200 and b"<html" in body.lower():
                return body
        except OSError, TimeoutError:
            pass
        state = docker(["docker", "inspect", "--format", "{{.State.Status}}", name])
        if state not in ("created", "running", "restarting"):
            break
        time.sleep(2)
    logs = docker(["docker", "logs", "--tail", "80", name], check=False)
    raise RuntimeError(f"Music Assistant did not serve its frontend within {timeout}s.\n{logs}")


def _container_build_info(name: str) -> dict[str, object]:
    """Read the image build manifest from a running smoke-test container."""
    output = docker(
        [
            "docker",
            "exec",
            name,
            "/app/venv/bin/python",
            "-c",
            "from pathlib import Path; print(Path('/app/oidc-build-info.json').read_text())",
        ]
    )
    return json.loads(output)


def _check_frontend(base_url: str, index_body: bytes, revision: str) -> int:
    """Check the served frontend source marker and load every production asset."""
    marker = f'name="ma-frontend-commit" content="{revision}"'.encode()
    if marker not in index_body:
        raise RuntimeError("HTTP frontend response is not the pinned custom frontend package")
    asset_paths = re.findall(rb"(?:src|href)=['\"]([^'\"]+\.(?:js|css))['\"]", index_body)
    if not asset_paths:
        raise RuntimeError("Served frontend index does not reference production JS/CSS assets")
    loaded_assets = 0
    for asset_path in asset_paths:
        asset_url = urllib.parse.urljoin(base_url + "/", asset_path.decode("utf-8"))
        status, body, _headers = http_request(asset_url)
        if status != 200 or not body:
            raise RuntimeError(f"Production frontend asset did not load: {asset_url} ({status})")
        loaded_assets += 1
    return loaded_assets


def _check_auth_routes(base_url: str) -> set[str]:
    """Check provider discovery and the expected unauthenticated OIDC responses."""
    status, body, _headers = http_request(base_url + "/auth/providers")
    if status != 200:
        raise RuntimeError(f"Auth provider discovery returned HTTP {status}: {body[:200]!r}")
    providers = json.loads(body)
    provider_ids = {provider.get("provider_id") for provider in providers}
    if "builtin" not in provider_ids:
        raise RuntimeError(f"Built-in login provider is missing: {providers!r}")
    status, _body, _headers = http_request(base_url + "/auth/authorize?provider_id=oidc")
    if status != 400:
        raise RuntimeError(
            f"Unconfigured OIDC authorization should fail closed with HTTP 400; got {status}"
        )
    status, _body, _headers = http_request(base_url + "/auth/oidc/link/start", method="POST")
    if status != 401:
        raise RuntimeError(f"Unauthenticated OIDC linking should return HTTP 401; got {status}")
    status, _body, _headers = http_request(
        base_url + "/auth/callback?provider_id=oidc&state=invalid-smoke-state&code=unused"
    )
    if status >= 500:
        raise RuntimeError(f"Invalid OIDC callback caused an HTTP {status} server error")
    return provider_ids


def _cleanup_container(name: str, image: str, data_path: Path) -> None:
    """Stop and remove the test container, then restore temporary mount ownership."""
    docker(["docker", "stop", "--time", "10", name], check=False)
    docker(["docker", "rm", "--force", name], check=False)
    docker(
        [
            "docker",
            "run",
            "--rm",
            "--volume",
            f"{data_path}:/data",
            "--entrypoint",
            "chown",
            image,
            "-R",
            f"{os.getuid()}:{os.getgid()}",
            "/data",
        ],
        check=False,
    )


def smoke(image: str, startup_timeout: int) -> None:
    """Start an isolated image and check startup, auth routes, and production assets."""
    name = f"music-assistant-oidc-smoke-{uuid.uuid4().hex[:10]}"
    with tempfile.TemporaryDirectory(prefix="music-assistant-oidc-data-") as data_dir:
        data_path = Path(data_dir)
        docker(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                name,
                "--publish",
                "127.0.0.1::8095",
                "--volume",
                f"{data_path}:/data",
                image,
            ]
        )
        try:
            base_url = _container_base_url(name)
            index_body = _wait_for_frontend(name, base_url, startup_timeout)
            build_info = _container_build_info(name)
            frontend_revision = build_info["sources"]["frontend"]["revision"]
            asset_count = _check_frontend(base_url, index_body, frontend_revision)
            provider_ids = _check_auth_routes(base_url)
            if not any(data_path.iterdir()):
                raise RuntimeError("Fresh /data directory remained empty after application startup")
            sys.stdout.write(f"HTTP frontend served from pinned commit {frontend_revision}\n")
            sys.stdout.write(f"Production frontend assets loaded: {asset_count}\n")
            sys.stdout.write(f"Auth provider discovery: {sorted(provider_ids)}\n")
            sys.stdout.write(
                "Built-in setup/login, unauthenticated link guard, and callback route: verified\n"
            )
            sys.stdout.write("Fresh isolated /data startup: verified\n")
        finally:
            _cleanup_container(name, image, data_path)


def main() -> int:
    """Run the package and server smoke checks for an image."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--startup-timeout", type=int, default=180)
    args = parser.parse_args()
    try:
        check_package_image(args.image)
        smoke(args.image, args.startup_timeout)
    except (RuntimeError, OSError, http.client.HTTPException, json.JSONDecodeError) as err:
        sys.stderr.write(f"OIDC container smoke test failed: {err}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
