# Rapid7 InsightVM to Automox Sync

This tool exports active Critical and Severe InsightVM findings, joins Rapid7
vulnerability IDs to remediation details, writes an Automox-compatible Rapid7
CSV, and can upload it to Automox Vulnerability Sync.

All Rapid7 requests use Security Console API v3 at
`https://<host>:<port>/api/3` with HTTP Basic authentication. The CSV always remains on disk
for auditability. Uploading to Automox is opt-in.

## Requirements

- Python 3.10+
- Rapid7 Security Console HTTPS URL, username and password
- Network access from the runner to the Security Console
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
export RAPID7_CONSOLE_URL="https://your-console:3780"
export RAPID7_CONSOLE_USERNAME="your-api-user"
export RAPID7_CONSOLE_PASSWORD="..."
export AUTOMOX_API_KEY="..."
export AUTOMOX_ORG_ID="123456"
```

You can also read them from Azure Key Vault. Install the optional Azure support:

```bash
python -m pip install -e ".[azure]"
```

Create Key Vault secrets, for example:

```text
rapid7-console-username
rapid7-console-password
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
  --rapid7-console-username-secret prod-console-username \
  --rapid7-console-password-secret prod-console-password \
  --automox-api-key-secret prod-automox-api-key \
  --automox-org-id-secret prod-automox-org-id \
  --upload
```

Useful options:

```text
--asset-group workstations/laptops  Exact console asset group name
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
or a CI system. Store credentials in the scheduler's secret store. Start without
`--upload`, inspect the CSV and skipped counts, then enable upload.

## Security Notes

This is a CLI integration rather than a web application, so some OWASP Top 10
classes such as browser XSS, CSRF, and session management do not directly apply.
The implementation still includes controls for the applicable risks:

- API traffic is restricted to HTTPS and expected Rapid7/Automox hostnames.
- TLS certificate validation is performed by Python's default trust store with
  TLS 1.2 or newer.
- Credentials are read from environment variables and are not logged.
- Credentials can also be retrieved from Azure Key Vault at runtime and are not
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

## Security Console solutions

Solution lookup requires network access to your Security Console and these settings:

```bash
export RAPID7_CONSOLE_URL="https://your-console:3780"
export RAPID7_CONSOLE_USERNAME="your-api-user"
export RAPID7_CONSOLE_PASSWORD="..."
```

For Azure Key Vault, use `rapid7-console-username` and `rapid7-console-password`,
or override with `--rapid7-console-username-secret` and
`--rapid7-console-password-secret`. Set the URL with `--console-url` or the
environment variable above. No Rapid7 cloud API key or region is used.

The exporter resolves `GET /api/3/vulnerabilities/{id}/solutions`, then fetches
`GET /api/3/solutions/{id}` and maps `summary.text` to Solution and `steps.text`
to Fix details. Lookups are cached for each run. Multiple solutions produce
separate CSV groups; no solutions produce no row. API failures abort the export.
These are all candidate solutions across platforms, not asset-specific best fixes.
See the [Rapid7 API documentation](https://help.rapid7.com/insightvm/en-us/api/index.html).

In Azure Pipelines, configure the corresponding console URL, username and password
variables/secrets. The build agent must be able to reach the console.

### Console v3 finding selection

The exporter uses `GET /api/3/vulnerabilities` for Critical/Severe metadata,
excluding the Microsoft Patch category. It resolves the exact asset group name
through `GET /api/3/asset_groups` and its `/assets` membership endpoint, then
intersects those IDs with `POST /api/3/assets/search` using `last-scan-date`
`is-within-the-last: 7`. A missing or ambiguous group fails the run.
`GET /api/3/assets/{id}/vulnerabilities` supplies current findings; only
`status: vulnerable` is exported. Exceptions (`invulnerable`) and `no-results`
are excluded. Paged endpoints read `resources` and `page.totalPages`.

Migration: remove `--region`, `--rapid7-api-key-secret`, and `RAPID7_API_KEY`.
Configure the console URL and credentials above. Azure pipeline variable names
are `Rapid7-Console-URL`, `Rapid7-Console-Username`, and `Rapid7-Console-Password`.
The runner must have console network access and trust its TLS certificate.
