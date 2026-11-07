# OIDC-enabled Docker image

This build combines the OIDC server implementation with the pinned models and frontend forks. It
builds production wheels from source and installs those wheels into the official Music Assistant
runtime layout. It does not use a developer virtual environment, a Vite dev server, or frontend
asset mounts.

## Pinned sources and build tools

[`oidc-build.lock.json`](../../oidc-build.lock.json) is the reviewed source and toolchain manifest.
It pins the three fork repositories and commit SHAs, the VCS dependencies used by the server,
Python, Node, pnpm, uv, Buildx, BuildKit, the Python frontend build tools, the Dockerfile frontend
digest, the Python base image digest, the Debian snapshot, FFmpeg and its checksum, and the uv
builder image digest. The CI workflow uses the pinned BuildKit image and Ubuntu 24.04 runner. The
initial source pins are:

| Component | Repository | Commit |
| --- | --- | --- |
| Server | `woobble/music-assistant-server` | `87db99cc5db430b5adff419cbd6a9cfb5a39c3ce` |
| Frontend | `woobble/music-assistant-frontend` | `ee04752885ecffee0719c93829c37c5f6e755008` |
| Models | `woobble/music-assistant-models` | `c2884424c419d8ae0279455aa7d2755de0ea2c3a` |

The build checks out exact SHAs and asks GitHub for each commit before building. A missing commit,
wrong checkout, non-SHA revision, or unpinned VCS dependency fails the build. The container
requirements replace the server's exact frontend and models pins with the freshly built local
wheels. The custom versions retain the upstream public version and use a PEP 440 local version
suffix, so the server's `==` dependency constraints remain satisfied. The server wheel is built
from a clean Git archive; its temporary packaging metadata pins the test-drive aiolibdatachannel
branch to the commit recorded in the lock file.

The workflow is manually dispatched from the server fork. Blank source inputs use the lock file;
repository and revision inputs can override it. Revisions must be full commit SHAs. The resulting
OCI tag includes the first 12 characters of each source SHA and the full build-input manifest SHA;
the manifest covers source, toolchain, base image, frontend asset, and build tooling hashes. The
image manifest records all full revisions and tooling hashes. There is no `latest` alias.

## Build locally

Use clean checkouts at the three locked commits. The following assumes the repositories are
siblings and the current directory is the server repository root:

```sh
SERVER_DIR="$PWD"
FRONTEND_DIR="../music-assistant-frontend"
MODELS_DIR="../music-assistant-models"
BUILD_DIR="$(mktemp -d)"
CONTEXT="$BUILD_DIR/context"

python3 scripts/oidc_image.py resolve --output "$BUILD_DIR/resolved.json"
python3 scripts/oidc_image.py verify-sources \
  --resolved "$BUILD_DIR/resolved.json" \
  --server-dir "$SERVER_DIR" \
  --frontend-dir "$FRONTEND_DIR" \
  --models-dir "$MODELS_DIR"
```

Use the pinned tool versions in the lock file: Python 3.14.9, Node 22.16.0, pnpm 11.8.0, uv
0.13.7, Buildx v0.38.2, `build` 1.3.0, and setuptools 80.9.0. Run the models tests and make the
models wheel:

```sh
uv run --project "$MODELS_DIR" --extra test pytest "$MODELS_DIR/tests/test_auth.py"
mkdir -p "$BUILD_DIR/models-dist" "$BUILD_DIR/server-dist"
SOURCE_DATE_EPOCH="$(git -C "$MODELS_DIR" show -s --format=%ct HEAD)" \
  uv build --wheel --out-dir "$BUILD_DIR/models-dist" "$MODELS_DIR"
```

Build and check the production frontend. The stamping command stages a separate Python package
source tree, leaving the frontend checkout's tracked files alone:

```sh
cd "$FRONTEND_DIR"
pnpm install --frozen-lockfile
pnpm lint:check
pnpm test:run
pnpm build
cd "$SERVER_DIR"

FRONTEND_ASSETS_SHA256="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["frontend_assets_sha256"])' "$BUILD_DIR/resolved.json")"
python3 scripts/oidc_image.py stamp-frontend \
  --frontend-dir "$FRONTEND_DIR" \
  --server-dir "$SERVER_DIR" \
  --repository woobble/music-assistant-frontend \
  --revision ee04752885ecffee0719c93829c37c5f6e755008 \
  --expected-assets-sha256 "$FRONTEND_ASSETS_SHA256" \
  --output "$BUILD_DIR/frontend-package"
python3 -m pip install build==1.3.0 setuptools==80.9.0
mkdir -p "$BUILD_DIR/frontend-package/dist"
cd "$BUILD_DIR/frontend-package"
SOURCE_DATE_EPOCH="$(git -C "$FRONTEND_DIR" show -s --format=%ct HEAD)" \
  TZ=UTC python3 -m build --no-isolation --wheel --sdist --outdir dist
bash "$FRONTEND_DIR/.github/scripts/verify-python-package.sh"
cd "$SERVER_DIR"
```

Build the server wheel from the pinned commit, assemble the minimal Docker context, and run the
focused server auth tests against the built models/frontend wheels:

```sh
python3 scripts/oidc_image.py build-server-wheel \
  --server-dir "$SERVER_DIR" \
  --resolved "$BUILD_DIR/resolved.json" \
  --output "$BUILD_DIR/server-dist"

python3 scripts/oidc_image.py prepare-context \
  --resolved "$BUILD_DIR/resolved.json" \
  --server-dir "$SERVER_DIR" \
  --frontend-dir "$FRONTEND_DIR" \
  --models-dir "$MODELS_DIR" \
  --server-dist "$BUILD_DIR/server-dist" \
  --frontend-dist "$BUILD_DIR/frontend-package/dist" \
  --models-dist "$BUILD_DIR/models-dist" \
  --tools-dir "$SERVER_DIR" \
  --output "$CONTEXT"

python3 scripts/oidc_image.py write-test-requirements \
  --server-dir "$SERVER_DIR" \
  --requirements "$CONTEXT/requirements_all.txt" \
  --output "$BUILD_DIR/test-requirements.txt"
cd "$CONTEXT"
uv venv "$BUILD_DIR/test-venv" --python 3.14.9
uv pip install --python "$BUILD_DIR/test-venv/bin/python" \
  --index-strategy unsafe-best-match --no-binary urllib3-future \
  -r "$BUILD_DIR/test-requirements.txt"
uv pip check --python "$BUILD_DIR/test-venv/bin/python"
cd "$SERVER_DIR"
"$BUILD_DIR/test-venv/bin/python" -m pytest \
  tests/controllers/webserver/test_oidc_auth.py \
  tests/controllers/webserver/test_oidc_issuer.py \
  tests/controllers/webserver/test_login_flow.py \
  tests/controllers/webserver/test_auth_callback.py \
  tests/controllers/webserver/test_auth_logout.py \
  tests/controllers/webserver/test_command_impersonation.py \
  tests/controllers/webserver/test_roles.py \
  tests/controllers/webserver/test_ingress_auth.py \
  tests/test_webserver_auth.py
```

Build the compatibility base from the pinned upstream `Dockerfile.base`, then build and smoke test
the final image. The generated base context only contains the Dockerfile and the Sendspin manifest
it needs; it never contains `widevine_cdm` files.

```sh
SERVER_REVISION=87db99cc5db430b5adff419cbd6a9cfb5a39c3ce
FRONTEND_REVISION=ee04752885ecffee0719c93829c37c5f6e755008
MODELS_REVISION=c2884424c419d8ae0279455aa7d2755de0ea2c3a
IMAGE=ghcr.io/woobble/music-assistant-oidc
TAG="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["build_tag"])' "$BUILD_DIR/resolved.json")"
BASE_IMAGE="music-assistant-oidc-base:$SERVER_REVISION"
MASS_VERSION="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["distributions"]["server"]["version"])' "$CONTEXT/oidc-build-info.json")"
MASS_WHEEL_SHA256="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["distributions"]["server"]["sha256"])' "$CONTEXT/oidc-build-info.json")"

docker buildx build --platform linux/amd64 --load --tag "$BASE_IMAGE" \
  --file "$CONTEXT/base-context/Dockerfile.base" "$CONTEXT/base-context"
docker buildx build --platform linux/amd64 --load --tag "$IMAGE:$TAG" \
  --file "$CONTEXT/Dockerfile.oidc" \
  --build-arg "BASE_IMAGE=$BASE_IMAGE" \
  --build-arg "MASS_VERSION=$MASS_VERSION" \
  --build-arg "MASS_REVISION=$SERVER_REVISION" \
  --build-arg "FRONTEND_REVISION=$FRONTEND_REVISION" \
  --build-arg "MODELS_REVISION=$MODELS_REVISION" \
  --build-arg "MASS_WHEEL_SHA256=$MASS_WHEEL_SHA256" \
  "$CONTEXT"
python3 scripts/smoke_test_oidc_image.py --image "$IMAGE:$TAG"
```

The build installs the local component wheels, runs `uv pip check`, and verifies installed
distribution versions after installing the server wheel. The image verifier also imports
`AuthProviderType.OIDC` and `OIDCLoginProvider`, checks the frontend package's `where()` path,
validates the recorded frontend asset hash and source marker, and fails if upstream models or
frontend versions replaced the custom wheels.

## CI build and optional GHCR publishing

Run **Actions → OIDC Docker image → Run workflow** in the server fork. The workflow runs model
tests, frontend lint/type checks/tests/build, the focused server OIDC/auth tests, a linux/amd64
Docker build, and an isolated container smoke test. Python/uv, pnpm, and Docker layers use caches.
The source check, image build, and smoke-test jobs have read-only repository permissions. The
separate publishing job receives `packages: write` only when `publish_image` is enabled, and it
pushes the exact image archive that passed smoke testing. The workflow rejects a public existing
GHCR package and refuses to overwrite a previously used commit-derived tag.

Publishing is disabled by default. The base recipe enables FFmpeg's `--enable-nonfree` and
`--enable-gpl` options and includes Fraunhofer FDK AAC. FFmpeg's own [licensing guidance](https://ffmpeg.org/legal.html)
states that a build using `--enable-nonfree` is not redistributable. The workflow therefore also
requires the operator to affirm that redistribution rights have been reviewed. Keep the package
private unless that review authorizes a broader scope. A private GHCR package is created by
default; the publish job fails if an existing package is public. The build does not publish or
deploy automatically.

For a successful publish, the workflow summary records the full component revisions and registry
digest. Pull by the commit-derived tag or digest, never by `latest`:

```sh
docker pull ghcr.io/woobble/music-assistant-oidc:oidc-<server-12>-<frontend-12>-<models-12>-<input-manifest-sha256>
docker pull ghcr.io/woobble/music-assistant-oidc@sha256:<recorded-digest>
```

## Image verification and isolated staging

Inside the image, inspect the exact package versions and source pins:

```sh
docker run --rm --entrypoint /app/venv/bin/python ghcr.io/woobble/music-assistant-oidc:<tag> \
  /app/verify_oidc_image.py --manifest /app/oidc-build-info.json
```

The smoke test starts the application with a new temporary `/data` directory, confirms the root
page serves the pinned built frontend and its production assets, checks `/auth/providers` for the
built-in login provider, verifies the unauthenticated OIDC-link guard, and confirms an invalid OIDC
callback fails without a server error. The issuer is intentionally not configured in this smoke
run. OIDC discovery, callback exchange, and account linking are covered by the server tests with
the local mock issuer; CI does not need Pocket ID credentials.

For a manual staging run on Rocky Linux, use a separate Compose project name and a new host data
directory. Do not point staging at production `/data`:

```yaml
services:
  music-assistant-oidc-stage:
    image: ghcr.io/woobble/music-assistant-oidc:<commit-derived-tag>
    container_name: music-assistant-oidc-stage
    restart: unless-stopped
    network_mode: host
    volumes:
      - /srv/music-assistant-oidc-stage:/data
```

Keep the normal Music Assistant persistence path, host networking, audio devices, and any provider
mounts from the existing deployment as appropriate. Confirm the server is reachable at port 8095
before configuring OIDC. In Pocket ID, create an OIDC client with the exact callback URI
`https://<your-public-host>/auth/callback?provider_id=oidc` (or the exact configured external URL),
scopes `openid profile email`, and a client secret. Configure the issuer, client ID, and secret in
Music Assistant's webserver auth settings. Enable OIDC registration only if the identity provider's
membership policy is intentionally open to new regular Music Assistant users.

Before any production change, make a consistent backup of the current Compose file and the entire
existing `/data` directory, including its database and configuration. Keep the current image tag
and backup together. This work does not modify the production installation or Compose deployment.

Rollback requires restoring a pre-OIDC `/data` backup as well as the previous image. Older models
versions do not know `AuthProviderType.OIDC`; their unknown-value fallback interprets an OIDC link
as `builtin` when it is deserialized and can write that value back. Do not roll back an installation
that contains OIDC links to an older models/server image unless restoring a compatible backup or a
separately validated migration plan.

## Packaging and provider limitations

The standard base build copies Apple Music Widevine client files from a private `appvars` checkout.
This build removes that copy instruction and never fetches those files. Apple Music playback that
requires Widevine is unavailable unless the operator supplies their own authorized CDM files
outside the image. The standard server code's `apple_music/bin/README.md` describes the expected
files. The OIDC image also retains the server branch's existing limitation that OIDC is not
advertised for Music Assistant Remote Access app sign-in.

The image includes the server, frontend, and models license files, the server NOTICE, collected
frontend dependency notices, and the FFmpeg GPL notice. The image still contains the upstream
nonfree FFmpeg configuration described above, so inclusion of notices alone does not authorize
redistribution. Review local codec patent and service terms before publishing or distributing the
image.

## Current build report

The workflow writes the wheel versions and SHA-256 values, frontend asset SHA-256, source commits,
local image configuration digest, and (when publishing is enabled) GHCR manifest digest into its
run summary. Record the workflow run with the staging image. The pinned models wheel is expected to
be `1.1.236+woobble.oidc.1`; compare its rebuilt hash with the run manifest rather than assuming a
prior local wheel is being used.
