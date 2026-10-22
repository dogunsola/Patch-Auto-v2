import argparse
import logging
import os
import stat
from pathlib import Path

from .automox import AutomoxClient
from .rapid7 import Rapid7Client
from .secrets import AzureKeyVaultSecretProvider, EnvSecretProvider, default_secret_name
from .transform import build_catalog, transform_assets, write_automox_csv

LOG = logging.getLogger(__name__)


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def required_positive_int(value: str, label: str) -> int:
    try:
        return positive_int(value)
    except argparse.ArgumentTypeError as exc:
        raise SystemExit(f"{label} must be a positive integer") from exc


def safe_output_path(path: Path) -> Path:
    if path.exists() and path.is_symlink():
        raise SystemExit("Refusing to write output through a symbolic link")
    return path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export critical and severe InsightVM findings to Automox."
    )
    parser.add_argument("--asset-group", default="workstations/laptops",
                        help="Exact Security Console asset group name")
    parser.add_argument("--page-size", type=positive_int, default=500)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("rapid7-findings.csv"),
        help="CSV output path",
    )
    parser.add_argument(
        "--hostname-fallback",
        choices=("skip", "ip"),
        default="skip",
        help="Behavior when an InsightVM asset has no hostname",
    )
    parser.add_argument(
        "--upload",
        action="store_true",
        help="Upload the generated CSV to Automox Vulnerability Sync",
    )
    parser.add_argument(
        "--secret-source",
        choices=("env", "azure-keyvault"),
        default=os.environ.get("SECRET_SOURCE", "env"),
        help="Secret source for credentials (default: SECRET_SOURCE or env)",
    )
    parser.add_argument(
        "--azure-key-vault-url",
        default=os.environ.get("AZURE_KEY_VAULT_URL", ""),
        help="Azure Key Vault URL when --secret-source azure-keyvault is used",
    )
    parser.add_argument(
        "--automox-api-key-secret",
        default=None,
        help="Secret name for the Automox API key",
    )
    parser.add_argument(
        "--automox-org-id-secret",
        default=None,
        help="Secret name for the Automox organization ID",
    )
    parser.add_argument("--console-url", default=os.environ.get("RAPID7_CONSOLE_URL", ""),
                        help="Security Console HTTPS origin, e.g. https://console:3780")
    parser.add_argument("--rapid7-console-username-secret", default=None)
    parser.add_argument("--rapid7-console-password-secret", default=None)
    parser.add_argument("--verbose", action="store_true")
    return parser.parse_args()


def build_secret_provider(args: argparse.Namespace) -> EnvSecretProvider | AzureKeyVaultSecretProvider:
    if args.secret_source == "env":
        return EnvSecretProvider()
    if not args.azure_key_vault_url:
        raise SystemExit(
            "--azure-key-vault-url or AZURE_KEY_VAULT_URL is required for Azure Key Vault"
        )
    return AzureKeyVaultSecretProvider(args.azure_key_vault_url)


def main() -> None:
    args = parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    secrets = build_secret_provider(args)
    automox_api_key_secret = args.automox_api_key_secret or default_secret_name(
        args.secret_source, "AUTOMOX_API_KEY", "automox-api-key"
    )
    automox_org_id_secret = args.automox_org_id_secret or default_secret_name(
        args.secret_source, "AUTOMOX_ORG_ID", "automox-org-id"
    )

    if not args.console_url:
        raise SystemExit("--console-url or RAPID7_CONSOLE_URL is required for Rapid7 API access")
    rapid7 = Rapid7Client(
        args.console_url,
        secrets.get_required(args.rapid7_console_username_secret or default_secret_name(
            args.secret_source, "RAPID7_CONSOLE_USERNAME", "rapid7-console-username")),
        secrets.get_required(args.rapid7_console_password_secret or default_secret_name(
            args.secret_source, "RAPID7_CONSOLE_PASSWORD", "rapid7-console-password")),
        page_size=args.page_size,
        asset_group=args.asset_group,
    )
    LOG.info("Downloading Rapid7 Critical and Severe vulnerability catalog")
    catalog = build_catalog(rapid7.iter_vulnerability_catalog())
    LOG.info("Catalog contains %s Critical/Severe vulnerability IDs", len(catalog))

    LOG.info("Downloading affected Rapid7 assets and active findings")
    findings, stats = transform_assets(
        rapid7.iter_affected_assets(),
        catalog,
        hostname_fallback=args.hostname_fallback,
        solution_lookup=rapid7.get_vulnerability_solutions,
    )
    args.output = safe_output_path(args.output)
    write_automox_csv(args.output, findings)
    LOG.info("Wrote %s unique findings to %s", len(findings), args.output)
    LOG.info(
        "Summary: assets=%s, no-host=%s, unknown-vulnerability-id=%s",
        stats.assets_seen,
        stats.assets_without_host,
        stats.vulnerability_ids_not_in_catalog,
    )

    if args.upload:
        if not findings:
            raise SystemExit("CSV has no findings; refusing to upload an empty report")
        automox = AutomoxClient(
            api_key=secrets.get_required(automox_api_key_secret),
            organization_id=required_positive_int(
                secrets.get_required(automox_org_id_secret), "Automox organization ID"
            ),
        )
        result = automox.upload_rapid7_csv(args.output)
        LOG.info(
            "Automox accepted action set id=%s status=%s",
            result.get("id", "unknown"),
            result.get("status", "unknown"),
        )
    else:
        LOG.info("Dry run complete; use --upload to send this CSV to Automox")

    try:
        mode = stat.S_IMODE(args.output.stat().st_mode)
        if mode & 0o077:
            LOG.warning("%s is readable by group/other; consider chmod 600", args.output)
    except OSError:
        pass


if __name__ == "__main__":
    main()
