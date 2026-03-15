"""
ShieldKit Secrets Manager
--------------------------
Abstracts secrets storage behind a common interface.

Providers:
  local_encrypted  — AES-256 (Fernet) stored in data/secrets.enc
                     Key from SHIELDKIT_MASTER_KEY env var; auto-generated if absent.
  hashicorp_vault  — HashiCorp Vault KV v2 via REST (no SDK required)
  aws_secrets      — AWS Secrets Manager via boto3
  azure_keyvault   — Azure Key Vault via azure-keyvault-secrets
  gcp_secret       — GCP Secret Manager via google-cloud-secret-manager

Secret references in tool configs:
  sk://my-api-key          → resolved via active provider
  sk://grype/db-token      → supports / in key names (stored as-is per provider)
"""

from __future__ import annotations

import base64
import json
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Optional

_BASE = Path(__file__).resolve().parent
_PROVIDER: "SecretsProvider | None" = None


# ── Abstract Base ─────────────────────────────────────────────────────────────

class SecretsProvider(ABC):
    @abstractmethod
    async def get(self, key: str) -> Optional[str]: ...

    @abstractmethod
    async def set(self, key: str, value: str) -> None: ...

    @abstractmethod
    async def delete(self, key: str) -> None: ...

    @abstractmethod
    async def list_keys(self) -> list[str]: ...

    @abstractmethod
    async def test(self) -> dict[str, Any]: ...


# ── Local Encrypted Provider (Fernet / AES-128-CBC + HMAC-SHA256) ────────────

class LocalEncryptedProvider(SecretsProvider):
    """
    Stores secrets in data/secrets.enc as Fernet-encrypted JSON.
    Master key order of precedence:
      1. SHIELDKIT_MASTER_KEY env var (base64url-encoded 32 bytes)
      2. data/.master.key file (auto-generated on first use)
    """

    def __init__(self, master_key: str = "", secrets_path: Optional[str] = None):
        self._secrets_path = Path(secrets_path or _BASE / "data" / "secrets.enc")
        self._key_path = _BASE / "data" / ".master.key"
        self._master_key = master_key or os.environ.get("SHIELDKIT_MASTER_KEY", "")
        self._fernet = None

    def _get_fernet(self):
        if self._fernet:
            return self._fernet
        try:
            from cryptography.fernet import Fernet
        except ImportError:
            raise RuntimeError(
                "cryptography package required: pip install cryptography"
            )

        if self._master_key:
            # Accept raw base64 key or generate proper Fernet key from it
            key_bytes = self._master_key.encode()
            # Fernet keys must be 32 url-safe base64-encoded bytes
            if len(key_bytes) < 32:
                key_bytes = key_bytes.ljust(32, b"=")
            fernet_key = base64.urlsafe_b64encode(key_bytes[:32])
        elif self._key_path.exists():
            fernet_key = self._key_path.read_bytes().strip()
        else:
            # Auto-generate and persist
            fernet_key = Fernet.generate_key()
            self._key_path.parent.mkdir(parents=True, exist_ok=True)
            self._key_path.write_bytes(fernet_key)
            self._key_path.chmod(0o600)

        self._fernet = Fernet(fernet_key)
        return self._fernet

    def _load(self) -> dict[str, str]:
        if not self._secrets_path.exists():
            return {}
        try:
            encrypted = self._secrets_path.read_bytes()
            plaintext = self._get_fernet().decrypt(encrypted)
            return json.loads(plaintext)
        except Exception:
            return {}

    def _save(self, data: dict[str, str]) -> None:
        self._secrets_path.parent.mkdir(parents=True, exist_ok=True)
        plaintext = json.dumps(data).encode()
        encrypted = self._get_fernet().encrypt(plaintext)
        self._secrets_path.write_bytes(encrypted)
        self._secrets_path.chmod(0o600)

    async def get(self, key: str) -> Optional[str]:
        return self._load().get(key)

    async def set(self, key: str, value: str) -> None:
        data = self._load()
        data[key] = value
        self._save(data)

    async def delete(self, key: str) -> None:
        data = self._load()
        data.pop(key, None)
        self._save(data)

    async def list_keys(self) -> list[str]:
        return list(self._load().keys())

    async def test(self) -> dict[str, Any]:
        try:
            self._get_fernet()
            count = len(self._load())
            return {
                "ok": True,
                "provider": "local_encrypted",
                "secrets_file": str(self._secrets_path),
                "key_source": "env" if self._master_key else str(self._key_path),
                "secret_count": count,
            }
        except Exception as e:
            return {"ok": False, "provider": "local_encrypted", "error": str(e)}


# ── HashiCorp Vault Provider (KV v2 — pure REST) ─────────────────────────────

class HashiCorpVaultProvider(SecretsProvider):
    """
    Uses Vault KV v2 via REST API. No SDK required — only httpx/requests.
    Stores each ShieldKit secret at: {mount}/data/{path_prefix}/{key}
    """

    def __init__(self, addr: str, token: str, mount: str = "secret", path_prefix: str = "shieldkit"):
        self.addr = addr.rstrip("/")
        self.token = token
        self.mount = mount
        self.path_prefix = path_prefix.strip("/")

    def _headers(self) -> dict:
        return {"X-Vault-Token": self.token, "Content-Type": "application/json"}

    def _url(self, key: str, data: bool = True) -> str:
        segment = "data" if data else "metadata"
        return f"{self.addr}/v1/{self.mount}/{segment}/{self.path_prefix}/{key}"

    async def get(self, key: str) -> Optional[str]:
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                r = await client.get(self._url(key), headers=self._headers())
                if r.status_code == 404:
                    return None
                r.raise_for_status()
                return r.json()["data"]["data"].get("value")
        except ImportError:
            import urllib.request
            req = urllib.request.Request(self._url(key), headers=self._headers())
            try:
                with urllib.request.urlopen(req) as resp:
                    body = json.loads(resp.read())
                    return body["data"]["data"].get("value")
            except Exception:
                return None
        except Exception:
            return None

    async def set(self, key: str, value: str) -> None:
        payload = json.dumps({"data": {"value": value}}).encode()
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                r = await client.post(self._url(key), headers=self._headers(), content=payload)
                r.raise_for_status()
        except ImportError:
            import urllib.request
            req = urllib.request.Request(
                self._url(key), data=payload, headers=self._headers(), method="POST"
            )
            with urllib.request.urlopen(req):
                pass

    async def delete(self, key: str) -> None:
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                await client.delete(self._url(key, data=False), headers=self._headers())
        except ImportError:
            import urllib.request
            req = urllib.request.Request(
                self._url(key, data=False), headers=self._headers(), method="DELETE"
            )
            try:
                with urllib.request.urlopen(req):
                    pass
            except Exception:
                pass

    async def list_keys(self) -> list[str]:
        list_url = f"{self.addr}/v1/{self.mount}/metadata/{self.path_prefix}?list=true"
        try:
            import httpx
            async with httpx.AsyncClient() as client:
                r = await client.get(list_url, headers=self._headers())
                if r.status_code == 404:
                    return []
                r.raise_for_status()
                return r.json().get("data", {}).get("keys", [])
        except Exception:
            return []

    async def test(self) -> dict[str, Any]:
        try:
            import urllib.request
            req = urllib.request.Request(
                f"{self.addr}/v1/sys/health", headers=self._headers()
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                health = json.loads(resp.read())
            return {
                "ok": True,
                "provider": "hashicorp_vault",
                "addr": self.addr,
                "initialized": health.get("initialized"),
                "sealed": health.get("sealed"),
                "version": health.get("version"),
            }
        except Exception as e:
            return {"ok": False, "provider": "hashicorp_vault", "error": str(e)}


# ── AWS Secrets Manager Provider ──────────────────────────────────────────────

class AWSSecretsManagerProvider(SecretsProvider):
    """
    Uses boto3 to read/write AWS Secrets Manager.
    Each ShieldKit secret maps to one SM secret named {prefix}{key}.
    """

    def __init__(self, region: str, prefix: str = "shieldkit/", profile: str = ""):
        self.region = region
        self.prefix = prefix
        self.profile = profile

    def _client(self):
        try:
            import boto3
            kwargs: dict = {"region_name": self.region}
            if self.profile:
                session = boto3.Session(profile_name=self.profile)
                return session.client("secretsmanager", **kwargs)
            return boto3.client("secretsmanager", **kwargs)
        except ImportError:
            raise RuntimeError("boto3 required: pip install boto3")

    def _name(self, key: str) -> str:
        return f"{self.prefix}{key}"

    async def get(self, key: str) -> Optional[str]:
        try:
            r = self._client().get_secret_value(SecretId=self._name(key))
            return r.get("SecretString")
        except Exception:
            return None

    async def set(self, key: str, value: str) -> None:
        client = self._client()
        name = self._name(key)
        try:
            client.put_secret_value(SecretId=name, SecretString=value)
        except client.exceptions.ResourceNotFoundException:
            client.create_secret(Name=name, SecretString=value)

    async def delete(self, key: str) -> None:
        try:
            self._client().delete_secret(
                SecretId=self._name(key), ForceDeleteWithoutRecovery=True
            )
        except Exception:
            pass

    async def list_keys(self) -> list[str]:
        try:
            paginator = self._client().get_paginator("list_secrets")
            keys = []
            for page in paginator.paginate(
                Filters=[{"Key": "name", "Values": [self.prefix]}]
            ):
                for s in page.get("SecretList", []):
                    name = s["Name"]
                    if name.startswith(self.prefix):
                        keys.append(name[len(self.prefix):])
            return keys
        except Exception:
            return []

    async def test(self) -> dict[str, Any]:
        try:
            self._client().list_secrets(MaxResults=1)
            return {
                "ok": True,
                "provider": "aws_secrets",
                "region": self.region,
                "prefix": self.prefix,
            }
        except Exception as e:
            return {"ok": False, "provider": "aws_secrets", "error": str(e)}


# ── Azure Key Vault Provider ──────────────────────────────────────────────────

class AzureKeyVaultProvider(SecretsProvider):
    """
    Uses azure-keyvault-secrets + azure-identity.
    Key names: hyphens replace / (Azure KV restriction).
    """

    def __init__(self, vault_url: str):
        self.vault_url = vault_url.rstrip("/")

    def _client(self):
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
            return SecretClient(vault_url=self.vault_url, credential=DefaultAzureCredential())
        except ImportError:
            raise RuntimeError(
                "azure-keyvault-secrets and azure-identity required: "
                "pip install azure-keyvault-secrets azure-identity"
            )

    @staticmethod
    def _sanitize(key: str) -> str:
        # Azure KV names: alphanumeric + hyphens only
        return key.replace("/", "--").replace("_", "-").replace(".", "-")

    async def get(self, key: str) -> Optional[str]:
        try:
            s = self._client().get_secret(self._sanitize(key))
            return s.value
        except Exception:
            return None

    async def set(self, key: str, value: str) -> None:
        self._client().set_secret(self._sanitize(key), value)

    async def delete(self, key: str) -> None:
        try:
            poller = self._client().begin_delete_secret(self._sanitize(key))
            poller.wait()
        except Exception:
            pass

    async def list_keys(self) -> list[str]:
        try:
            return [p.name for p in self._client().list_properties_of_secrets()]
        except Exception:
            return []

    async def test(self) -> dict[str, Any]:
        try:
            list(self._client().list_properties_of_secrets())
            return {"ok": True, "provider": "azure_keyvault", "vault_url": self.vault_url}
        except Exception as e:
            return {"ok": False, "provider": "azure_keyvault", "error": str(e)}


# ── GCP Secret Manager Provider ───────────────────────────────────────────────

class GCPSecretManagerProvider(SecretsProvider):
    """
    Uses google-cloud-secret-manager.
    Secrets are named: projects/{project}/secrets/{prefix}-{key}
    """

    def __init__(self, project_id: str, prefix: str = "shieldkit"):
        self.project_id = project_id
        self.prefix = prefix

    def _client(self):
        try:
            from google.cloud import secretmanager
            return secretmanager.SecretManagerServiceClient()
        except ImportError:
            raise RuntimeError(
                "google-cloud-secret-manager required: "
                "pip install google-cloud-secret-manager"
            )

    def _secret_id(self, key: str) -> str:
        return f"{self.prefix}-{key.replace('/', '-').replace('_', '-')}"

    def _parent(self) -> str:
        return f"projects/{self.project_id}"

    def _name(self, key: str) -> str:
        return f"{self._parent()}/secrets/{self._secret_id(key)}"

    async def get(self, key: str) -> Optional[str]:
        try:
            client = self._client()
            version = client.access_secret_version(
                name=f"{self._name(key)}/versions/latest"
            )
            return version.payload.data.decode()
        except Exception:
            return None

    async def set(self, key: str, value: str) -> None:
        client = self._client()
        name = self._name(key)
        payload_bytes = value.encode()
        try:
            client.add_secret_version(
                parent=name,
                payload={"data": payload_bytes}
            )
        except Exception:
            # Create the secret first
            client.create_secret(
                parent=self._parent(),
                secret_id=self._secret_id(key),
                secret={"replication": {"automatic": {}}},
            )
            client.add_secret_version(
                parent=name,
                payload={"data": payload_bytes}
            )

    async def delete(self, key: str) -> None:
        try:
            self._client().delete_secret(name=self._name(key))
        except Exception:
            pass

    async def list_keys(self) -> list[str]:
        try:
            client = self._client()
            prefix_dash = f"{self.prefix}-"
            return [
                s.name.split("/")[-1].replace(prefix_dash, "", 1)
                for s in client.list_secrets(parent=self._parent())
                if s.name.split("/")[-1].startswith(prefix_dash)
            ]
        except Exception:
            return []

    async def test(self) -> dict[str, Any]:
        try:
            list(self._client().list_secrets(parent=self._parent()))
            return {
                "ok": True,
                "provider": "gcp_secret",
                "project_id": self.project_id,
                "prefix": self.prefix,
            }
        except Exception as e:
            return {"ok": False, "provider": "gcp_secret", "error": str(e)}


# ── Factory & Singleton ───────────────────────────────────────────────────────

def _build_provider(config: dict) -> SecretsProvider:
    kind = config.get("provider", "local_encrypted")

    if kind == "local_encrypted":
        return LocalEncryptedProvider(
            master_key=config.get("master_key", ""),
            secrets_path=config.get("secrets_path"),
        )
    if kind == "hashicorp_vault":
        return HashiCorpVaultProvider(
            addr=config.get("vault_addr", ""),
            token=config.get("vault_token", ""),
            mount=config.get("vault_mount", "secret"),
            path_prefix=config.get("vault_path_prefix", "shieldkit"),
        )
    if kind == "aws_secrets":
        return AWSSecretsManagerProvider(
            region=config.get("aws_sm_region", "us-east-1"),
            prefix=config.get("aws_sm_prefix", "shieldkit/"),
            profile=config.get("aws_sm_profile", ""),
        )
    if kind == "azure_keyvault":
        return AzureKeyVaultProvider(vault_url=config.get("azure_vault_url", ""))
    if kind == "gcp_secret":
        return GCPSecretManagerProvider(
            project_id=config.get("gcp_sm_project", ""),
            prefix=config.get("gcp_sm_prefix", "shieldkit"),
        )

    raise ValueError(f"Unknown secrets provider: {kind}")


_PROVIDER_CACHE: SecretsProvider | None = None
_PROVIDER_CONFIG: dict = {}

_SECRETS_CONFIG_PATH = _BASE / "data" / "secrets_config.json"


def load_secrets_config() -> dict:
    if _SECRETS_CONFIG_PATH.exists():
        try:
            return json.loads(_SECRETS_CONFIG_PATH.read_text())
        except Exception:
            pass
    return {"provider": "local_encrypted"}


def save_secrets_config(config: dict) -> None:
    _SECRETS_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Never persist actual secrets in the config — only provider settings
    safe = {k: v for k, v in config.items() if "token" not in k.lower() and "key" not in k.lower()}
    safe["provider"] = config.get("provider", "local_encrypted")
    _SECRETS_CONFIG_PATH.write_text(json.dumps(safe, indent=2))


def get_provider(config: dict | None = None) -> SecretsProvider:
    global _PROVIDER_CACHE, _PROVIDER_CONFIG
    cfg = config or load_secrets_config()
    if _PROVIDER_CACHE is None or cfg != _PROVIDER_CONFIG:
        _PROVIDER_CACHE = _build_provider(cfg)
        _PROVIDER_CONFIG = cfg
    return _PROVIDER_CACHE


def invalidate_provider_cache() -> None:
    global _PROVIDER_CACHE
    _PROVIDER_CACHE = None


# ── Reference Resolution ──────────────────────────────────────────────────────

SK_REF_PREFIX = "sk://"


def is_secret_ref(value: str) -> bool:
    return isinstance(value, str) and value.startswith(SK_REF_PREFIX)


async def resolve_ref(value: str, provider: SecretsProvider | None = None) -> str:
    """Resolve a sk://key-name reference. Returns the original value if not a ref."""
    if not is_secret_ref(value):
        return value
    key = value[len(SK_REF_PREFIX):]
    p = provider or get_provider()
    resolved = await p.get(key)
    if resolved is None:
        raise ValueError(f"Secret '{key}' not found in provider")
    return resolved


async def resolve_config_dict(config: dict, provider: SecretsProvider | None = None) -> dict:
    """Resolve all sk:// references in a config dict. Returns a new dict."""
    p = provider or get_provider()
    result = {}
    for k, v in config.items():
        if is_secret_ref(v):
            result[k] = await resolve_ref(v, p)
        else:
            result[k] = v
    return result


PROVIDER_METADATA = {
    "local_encrypted": {
        "label": "Local Encrypted",
        "icon": "🔐",
        "description": "AES-256 encrypted file stored on this server. Zero external dependencies.",
        "fields": [
            {"key": "master_key", "label": "Master Key (optional)", "type": "password",
             "help": "Base64 key. Leave empty to auto-generate and store in data/.master.key"},
        ],
    },
    "hashicorp_vault": {
        "label": "HashiCorp Vault",
        "icon": "🏛️",
        "description": "HashiCorp Vault KV v2. Token auth. No SDK required.",
        "fields": [
            {"key": "vault_addr", "label": "Vault Address", "type": "text",
             "placeholder": "https://vault.example.com:8200", "required": True},
            {"key": "vault_token", "label": "Vault Token", "type": "password", "required": True},
            {"key": "vault_mount", "label": "KV Mount", "type": "text",
             "placeholder": "secret", "default": "secret"},
            {"key": "vault_path_prefix", "label": "Path Prefix", "type": "text",
             "placeholder": "shieldkit", "default": "shieldkit"},
        ],
    },
    "aws_secrets": {
        "label": "AWS Secrets Manager",
        "icon": "🟠",
        "description": "AWS Secrets Manager. Uses boto3 with your configured AWS credentials.",
        "fields": [
            {"key": "aws_sm_region", "label": "Region", "type": "text",
             "placeholder": "us-east-1", "required": True},
            {"key": "aws_sm_prefix", "label": "Secret Name Prefix", "type": "text",
             "placeholder": "shieldkit/", "default": "shieldkit/"},
            {"key": "aws_sm_profile", "label": "AWS Profile (optional)", "type": "text",
             "placeholder": "default"},
        ],
    },
    "azure_keyvault": {
        "label": "Azure Key Vault",
        "icon": "🔷",
        "description": "Azure Key Vault. Uses DefaultAzureCredential (env vars or managed identity).",
        "fields": [
            {"key": "azure_vault_url", "label": "Vault URL", "type": "text",
             "placeholder": "https://my-vault.vault.azure.net", "required": True},
        ],
    },
    "gcp_secret": {
        "label": "GCP Secret Manager",
        "icon": "🔵",
        "description": "Google Cloud Secret Manager. Uses Application Default Credentials.",
        "fields": [
            {"key": "gcp_sm_project", "label": "GCP Project ID", "type": "text",
             "required": True},
            {"key": "gcp_sm_prefix", "label": "Secret Name Prefix", "type": "text",
             "placeholder": "shieldkit", "default": "shieldkit"},
        ],
    },
}
