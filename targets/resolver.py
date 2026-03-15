"""
TargetResolver — normalises any target input into a local path or pass-through
ref that each scanner already understands.

Supported target_type values:
  auto         — sniff from string pattern
  file_upload  — UUID in data/uploads/{id}/
  public_url   — HTTP/HTTPS URL (downloaded for artifact scanners; passed-through for url/dast)
  private_url  — HTTP/HTTPS URL with auth credentials
  s3           — s3://bucket/key (requires boto3)
  git          — git clone --depth=1 (supports private repos via token in URL)
  container    — pass-through ref (docker image:tag)
  local_path   — must exist on server filesystem
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from fastapi import HTTPException

# Base directory for uploaded artifacts
_UPLOADS_DIR = Path(__file__).resolve().parent.parent / "data" / "uploads"

# URL/DAST scan types where URLs should be passed through, not downloaded
_URL_PASSTHROUGH_TYPES = {"url", "dast", "zap"}


class LocalTarget:
    """Holds the resolved path/ref and owns cleanup of any temp directories."""

    def __init__(self, path: str, is_temp: bool = False, tmp_dir: Path | None = None):
        self.path = path
        self.is_temp = is_temp
        self._tmp_dir = tmp_dir

    def cleanup(self) -> None:
        if self.is_temp and self._tmp_dir and self._tmp_dir.exists():
            shutil.rmtree(self._tmp_dir, ignore_errors=True)


class TargetResolver:
    """Resolves target + target_type + credentials into a LocalTarget."""

    async def resolve(
        self,
        target: str,
        target_type: str,
        credentials: dict[str, Any] | None,
        scan_type: str,
    ) -> LocalTarget:
        effective_type = target_type if target_type != "auto" else self._detect(target)

        if effective_type == "file_upload":
            return self._from_upload(target)

        if effective_type == "local_path":
            return self._validate_local(target)

        if effective_type == "container":
            # Pass-through — scanner handles pull
            return LocalTarget(path=target)

        if effective_type in ("public_url", "private_url"):
            # For URL/DAST scanners the URL itself is the target
            if scan_type in _URL_PASSTHROUGH_TYPES:
                return LocalTarget(path=target)
            headers = self._build_headers(credentials)
            return await self._download_url(target, headers, scan_type)

        if effective_type == "s3":
            return await self._download_s3(target, credentials)

        if effective_type == "git":
            return await self._clone_git(target, credentials)

        # Fallback: treat as container ref or plain string
        return LocalTarget(path=target)

    # ── Detection ─────────────────────────────────────────────────

    @staticmethod
    def _detect(target: str) -> str:
        if target.startswith(("http://", "https://")):
            return "public_url"
        if target.startswith("s3://"):
            return "s3"
        if target.startswith(("git@", "git://")) or (
            target.endswith(".git") and "://" in target
        ):
            return "git"
        if target.startswith(("/", "./", "../")):
            return "local_path"
        return "container"

    # ── Resolvers ─────────────────────────────────────────────────

    def _from_upload(self, upload_id: str) -> LocalTarget:
        """Resolve a file_upload by looking up data/uploads/{id}/."""
        upload_dir = _UPLOADS_DIR / upload_id
        if not upload_dir.exists():
            raise HTTPException(status_code=404, detail=f"Upload not found: {upload_id}")
        files = list(upload_dir.iterdir())
        if not files:
            raise HTTPException(status_code=404, detail=f"Upload directory empty: {upload_id}")
        # Return path to the file (first/only file in the directory)
        return LocalTarget(path=str(files[0]))

    def _validate_local(self, path: str) -> LocalTarget:
        p = Path(path)
        if not p.exists():
            raise HTTPException(status_code=400, detail=f"Local path does not exist: {path}")
        return LocalTarget(path=str(p.resolve()))

    async def _download_url(
        self, url: str, headers: dict[str, str], scan_type: str
    ) -> LocalTarget:
        """Download URL to a temp directory. Extract archives for IaC scans."""
        tmp_dir = Path(tempfile.mkdtemp(prefix="shieldkit_dl_"))
        filename = url.split("?")[0].rstrip("/").split("/")[-1] or "artifact"
        dest = tmp_dir / filename

        try:
            await self._fetch_url(url, headers, dest)
        except Exception as exc:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise HTTPException(status_code=400, detail=f"Failed to download {url}: {exc}")

        # Extract archives (IaC scanners need a directory)
        resolved_path = str(dest)
        if scan_type == "iac" and (
            filename.endswith(".zip") or filename.endswith(".tar.gz")
        ):
            extract_dir = tmp_dir / "extracted"
            extract_dir.mkdir()
            try:
                if filename.endswith(".zip"):
                    import zipfile
                    with zipfile.ZipFile(dest, "r") as zf:
                        zf.extractall(extract_dir)
                else:
                    import tarfile
                    with tarfile.open(dest, "r:gz") as tf:
                        tf.extractall(extract_dir)
                resolved_path = str(extract_dir)
            except Exception:
                pass  # Fall back to raw file path

        return LocalTarget(path=resolved_path, is_temp=True, tmp_dir=tmp_dir)

    async def _fetch_url(
        self, url: str, headers: dict[str, str], dest: Path
    ) -> None:
        """Download URL content to dest. Tries httpx first, falls back to urllib."""
        try:
            import httpx
            async with httpx.AsyncClient(follow_redirects=True, timeout=60.0) as client:
                async with client.stream("GET", url, headers=headers) as response:
                    response.raise_for_status()
                    with open(dest, "wb") as f:
                        async for chunk in response.aiter_bytes():
                            f.write(chunk)
        except ImportError:
            import urllib.request
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as resp:
                dest.write_bytes(resp.read())

    async def _download_s3(
        self, s3_uri: str, credentials: dict[str, Any] | None
    ) -> LocalTarget:
        """Download from s3://bucket/key using boto3."""
        try:
            import boto3  # type: ignore
        except ImportError:
            raise HTTPException(
                status_code=400,
                detail="boto3 is required for s3:// targets. Install: pip install boto3",
            )

        # Parse s3://bucket/key
        match = re.match(r"s3://([^/]+)/(.+)", s3_uri)
        if not match:
            raise HTTPException(status_code=400, detail=f"Invalid S3 URI: {s3_uri}")
        bucket, key = match.group(1), match.group(2)

        tmp_dir = Path(tempfile.mkdtemp(prefix="shieldkit_s3_"))
        filename = key.split("/")[-1] or "artifact"
        dest = tmp_dir / filename

        try:
            boto_kwargs: dict[str, Any] = {}
            if credentials:
                if credentials.get("access_key"):
                    boto_kwargs["aws_access_key_id"] = credentials["access_key"]
                if credentials.get("secret_key"):
                    boto_kwargs["aws_secret_access_key"] = credentials["secret_key"]
                if credentials.get("region"):
                    boto_kwargs["region_name"] = credentials["region"]

            s3 = boto3.client("s3", **boto_kwargs)
            s3.download_file(bucket, key, str(dest))
        except Exception as exc:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise HTTPException(
                status_code=400, detail=f"S3 download failed for {s3_uri}: {exc}"
            )

        return LocalTarget(path=str(dest), is_temp=True, tmp_dir=tmp_dir)

    async def _clone_git(
        self, repo_url: str, credentials: dict[str, Any] | None
    ) -> LocalTarget:
        """Clone a git repo (shallow) to a temp directory. Injects token for private repos."""
        tmp_dir = Path(tempfile.mkdtemp(prefix="shieldkit_git_"))
        clone_url = repo_url
        log_url = repo_url  # safe URL for logging (no credentials)

        if credentials:
            cred_type = credentials.get("type", "bearer")
            if cred_type == "bearer" and credentials.get("token"):
                token = credentials["token"]
                # Inject token: https://TOKEN@github.com/...
                clone_url = re.sub(r"https?://", f"https://{token}@", repo_url, count=1)
                log_url = re.sub(r"https?://", "https://***@", repo_url, count=1)
            elif cred_type == "basic":
                user = credentials.get("username", "")
                passwd = credentials.get("password", "")
                if user or passwd:
                    clone_url = re.sub(
                        r"https?://", f"https://{user}:{passwd}@", repo_url, count=1
                    )
                    log_url = re.sub(r"https?://", f"https://{user}:***@", repo_url, count=1)

        print(f"[TargetResolver] git clone {log_url}")
        try:
            proc = await asyncio.create_subprocess_exec(
                "git", "clone", "--depth=1", clone_url, str(tmp_dir / "repo"),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
            if proc.returncode != 0:
                err = stderr.decode()[:500].replace(clone_url, log_url)
                shutil.rmtree(tmp_dir, ignore_errors=True)
                raise HTTPException(
                    status_code=400, detail=f"git clone failed: {err}"
                )
        except asyncio.TimeoutError:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise HTTPException(status_code=408, detail="git clone timed out (>120s)")

        return LocalTarget(
            path=str(tmp_dir / "repo"), is_temp=True, tmp_dir=tmp_dir
        )

    # ── Credential Helpers ────────────────────────────────────────

    @staticmethod
    def _build_headers(credentials: dict[str, Any] | None) -> dict[str, str]:
        if not credentials:
            return {}
        cred_type = credentials.get("type", "bearer")
        if cred_type == "bearer" and credentials.get("token"):
            return {"Authorization": f"Bearer {credentials['token']}"}
        if cred_type == "basic":
            import base64
            user = credentials.get("username", "")
            passwd = credentials.get("password", "")
            encoded = base64.b64encode(f"{user}:{passwd}".encode()).decode()
            return {"Authorization": f"Basic {encoded}"}
        if cred_type == "header":
            extra = credentials.get("headers", {})
            if isinstance(extra, str):
                try:
                    extra = json.loads(extra)
                except Exception:
                    extra = {}
            return {str(k): str(v) for k, v in extra.items()}
        return {}
