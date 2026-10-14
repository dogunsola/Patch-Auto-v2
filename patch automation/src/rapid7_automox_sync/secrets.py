import os
from typing import Protocol
from urllib.parse import urlparse


class SecretProvider(Protocol):
    def get_required(self, name: str) -> str:
        ...


class EnvSecretProvider:
    def get_required(self, name: str) -> str:
        value = os.environ.get(name, "").strip()
        if not value:
            raise SystemExit(f"Missing required environment variable: {name}")
        return value


class AzureKeyVaultSecretProvider:
    def __init__(self, vault_url: str) -> None:
        vault_url = validate_key_vault_url(vault_url)
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.secrets import SecretClient
        except ImportError as exc:
            raise SystemExit(
                "Azure Key Vault support is not installed. "
                "Install with: python -m pip install 'rapid7-automox-sync[azure]'"
            ) from exc

        self.client = SecretClient(
            vault_url=vault_url,
            credential=DefaultAzureCredential(exclude_interactive_browser_credential=True),
        )

    def get_required(self, name: str) -> str:
        name = name.strip()
        if not name:
            raise SystemExit("Azure Key Vault secret name must not be empty")
        try:
            value = self.client.get_secret(name).value
        except Exception as exc:
            raise SystemExit(f"Unable to read Azure Key Vault secret: {name}") from exc
        if not value or not value.strip():
            raise SystemExit(f"Azure Key Vault secret is empty: {name}")
        return value.strip()


def validate_key_vault_url(vault_url: str) -> str:
    vault_url = vault_url.strip().rstrip("/")
    parsed = urlparse(vault_url)
    hostname = parsed.hostname or ""
    if (
        parsed.scheme != "https"
        or not hostname.endswith(".vault.azure.net")
        or hostname == ".vault.azure.net"
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise SystemExit("Azure Key Vault URL must be an HTTPS vault.azure.net URL")
    return vault_url


def default_secret_name(secret_source: str, env_name: str, azure_name: str) -> str:
    configured = os.environ.get(f"{env_name}_SECRET", "").strip()
    if configured:
        return configured
    if secret_source == "azure-keyvault":
        return azure_name
    return env_name
