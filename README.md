# Rapid7 InsightVM to Automox Sync

This tool exports active Critical and Severe InsightVM findings, joins Rapid7
vulnerability IDs to remediation details, writes an Automox-compatible Rapid7
CSV, and can upload it to Automox Vulnerability Sync.

It uses the InsightVM Cloud Integrations API v4. The CSV always remains on disk
for auditability. Uploading to Automox is opt-in.

## Requirements

- Python 3.10+
- Rapid7 InsightVM API key
- Automox API key and numeric organization ID when using `--upload`
- Automox Vulnerability Sync enabled

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
cd "patch automation"
python -m pip install -e ".[dev]"
```

Export the values from `.env` into your shell or secret-management system.
The application intentionally does not parse `.env` files itself.

```bash
set -a
source .env
set +a
```

## CI Setup

For automated runs, this project uses Azure Key Vault for secret retrieval.
Install the Azure SDK extras so the Key Vault integration is available:

```bash
cd "patch automation"
python -m pip install -e ".[dev,azure]"
```

Authenticate with Azure before running locally or in a pipeline:

```bash
az login
```

For Azure DevOps, configure a service connection and provide the required pipeline variables for the Key Vault URL and secret names.

## Run

Create the CSV without sending anything to Automox:

```bash
rapid7-automox-sync --output rapid7-findings.csv
```

Create and upload the CSV:

```bash
rapid7-automox-sync --output rapid7-findings.csv --upload
```

## Secrets

By default, secrets are read from environment variables:

```bash
export RAPID7_API_KEY="..."
export AUTOMOX_API_KEY="..."
export AUTOMOX_ORG_ID="123456"
```

You can also read them from Azure Key Vault. Install the optional Azure support:

```bash
python -m pip install -e ".[azure]"
```

Create Key Vault secrets, for example:

```text
rapid7-api-key
automox-api-key
automox-org-id
```

Then run with Azure Key Vault:

```bash
rapid7-automox-sync \
  --secret-source azure-keyvault \
  --azure-key-vault-url https://your-vault-name.vault.azure.net/ \
  --output rapid7-findings.csv
```

For upload:

```bash
rapid7-automox-sync \
  --secret-source azure-keyvault \
  --azure-key-vault-url https://your-vault-name.vault.azure.net/ \
  --output rapid7-findings.csv \
  --upload
```

Authentication uses Azure `DefaultAzureCredential`, so it works with managed
identity in Azure, workload identity, service principal environment variables,
or local Azure CLI login. Grant the identity only `get` access to the required
Key Vault secrets.

If your secret names differ, pass explicit names:

```bash
rapid7-automox-sync \
  --secret-source azure-keyvault \
  --azure-key-vault-url https://your-vault-name.vault.azure.net/ \
  --rapid7-api-key-secret prod-rapid7-api-key \
  --automox-api-key-secret prod-automox-api-key \
  --automox-org-id-secret prod-automox-org-id \
  --upload
```

Useful options:

```text
--region ca            Rapid7 region: us, us2, us3, eu, ca, au, ap, aps2, me1
--page-size 500        Rapid7 API page size
--hostname-fallback ip Use an asset IP when Rapid7 has no hostname
--verbose              Enable debug logging
```

The output format is:

```csv
Hosts,Solution,Fix details
server01.example.com;server02.example.com,Upgrade Apache Tomcat,Install the vendor update
```

Findings are grouped by Rapid7 solution and fix details, with the associated
hosts listed together in each row. Rapid7 `Severe` is mapped to Automox `high`.
Findings without a usable hostname are skipped and reported in the run summary.
Microsoft-related patches are excluded from the generated CSV.

## Scheduling

Run after InsightVM scans using a scheduler such as cron, a Kubernetes CronJob,
or a CI system. Store API keys in the scheduler's secret store. Start without
`--upload`, inspect the CSV and skipped counts, then enable upload.

## Security Notes

This is a CLI integration rather than a web application, so some OWASP Top 10
classes such as browser XSS, CSRF, and session management do not directly apply.
The implementation still includes controls for the applicable risks:

- API traffic is restricted to HTTPS and expected Rapid7/Automox hostnames.
- TLS certificate validation is performed by Python's default trust store with
  TLS 1.2 or newer.
- API keys are read from environment variables and are not logged.
- API keys can also be retrieved from Azure Key Vault at runtime and are not
  written to disk by the application.
- Generated CSV files are written with `0600` permissions.
- CSV cells are escaped to reduce spreadsheet formula-injection risk.
- Multipart upload filenames are sanitized.
- Uploading to Automox is opt-in with `--upload`.
- The default environment-variable mode has no third-party runtime dependencies;
  Azure Key Vault mode uses the official Azure SDK packages listed in
  `patch automation/pyproject.toml`.

Treat the generated CSV as sensitive because it contains vulnerability and asset
data. Store it only in protected locations and remove old exports according to
your retention policy.

## Test

```bash
cd "patch automation"
python -m pytest
```
