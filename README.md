# Falcon sensor coverage for cloud VMs

Read-only report of how many running cloud VMs have the CrowdStrike Falcon sensor, split into Kubernetes nodes and standalone VMs. It covers AWS EC2, Azure VMs and VM Scale Set instances, and GCP instances.

Outputs: an HTML report, a plain-text report, and CSV files. All of them are generated from the same data.

## Requirements

- Python 3.9 or newer. The script uses only the standard library, so there is nothing to install with `pip`.
- A CrowdStrike Falcon API client with the scope described below.

## Create the API client

1. In the Falcon console, go to **Support and resources > API clients and keys** and select **Create API client**. The menu path may differ slightly between console versions; search for "API clients" if needed.
2. Give it a name, for example `coverage-report-readonly`.
3. Grant only this scope:
   - **Cloud Security Assets: Read**

   Confirm the exact label in your console. The script does not need any other scope.
4. Save. Falcon shows the **Client ID** and **Client secret** only once. Copy both before closing the page.
5. Note the base URL for your cloud. Use the one that matches the console you log in to:

   | Cloud | Base URL |
   |-------|----------|
   | US-1 | `https://api.crowdstrike.com` |
   | US-2 | `https://api.us-2.crowdstrike.com` |
   | EU-1 | `https://api.eu-1.crowdstrike.com` |

## Configure credentials

The script reads three environment variables:

- `FALCON_CLIENT_ID`
- `FALCON_CLIENT_SECRET`
- `FALCON_BASE_URL` (optional; defaults to `https://api.crowdstrike.com`)

Credentials are never written in the code. Choose one of the options below.

### Option A: `.env` file (recommended)

Create a file named `.env` in the project folder:

```
FALCON_CLIENT_ID=your-client-id
FALCON_CLIENT_SECRET=your-client-secret
FALCON_BASE_URL=https://api.crowdstrike.com
```

Restrict it to your user, then load it into the shell before each run:

```
chmod 600 .env
set -a; source .env; set +a
```

`.env` is listed in `.gitignore`. Never commit it.

### Option B: export in the shell

```
export FALCON_CLIENT_ID=your-client-id
export FALCON_BASE_URL=https://api.crowdstrike.com
printf 'Client secret: '; read -rs FALCON_CLIENT_SECRET; echo
export FALCON_CLIENT_SECRET
```

The `read -rs` line prompts for the secret without displaying it or saving it in shell history. Exports last only for the current terminal session. Do not add them to a shell startup file such as `~/.bashrc` or `~/.zshrc`, because that stores the secret in plain text.

## Run the script

With either option set, run:

```
python3 sensor_coverage.py
```

Common examples:

```
python3 sensor_coverage.py                                  # VM report, HTML, running VMs
python3 sensor_coverage.py --format html,txt,csv            # several outputs from one fetch
python3 sensor_coverage.py --report summary --format txt    # KPIs and coverage tables only
python3 sensor_coverage.py --cloud aws --scope all --cache  # reuse fetched assets for 15 min
```

Options:

| Option | Default | Meaning |
|--------|---------|---------|
| `--report summary\|vm` | `vm` | `summary`: KPIs and coverage tables. `vm`: summary plus capped asset detail. |
| `--scope running\|all` | `running` | Only running VMs, or every VM record. |
| `--cloud all\|aws\|azure\|gcp` | `all` | Clouds to include. |
| `--format` | `html` | `html`, `txt`, `csv`, `all`, or a comma-separated list. |
| `--detail-limit N` | `100` | Asset rows shown in HTML and TXT. The CSV always contains every asset. |
| `--cache` | off | Reuse fetched assets for 15 minutes. |
| `--refresh` | off | Ignore the cache and query the API again. |

Outputs are written to `reports/`. For the default run:

- `reports/coverage-running.html`
- `reports/coverage-running-assets.csv`, the full asset list

Progress and timing are printed to the terminal.

## What the numbers mean

- **With sensor**: the asset's `managed_by` value is `Sensor`.
- **Agentless snapshot only**: visible through a snapshot scan, with no sensor installed.
- **Unmanaged**: neither a sensor nor a snapshot scan.
- **Without sensor**: agentless snapshot only, plus unmanaged.
- **Kubernetes node**: a VM whose tag keys identify it as an EKS, AKS, or GKE/K8s node.

Records with no sensor status are excluded from the counts, and the report states how many were excluded.

## Security notes

- The script only calls read endpoints. It has no write or delete calls.
- The `reports/` folder contains VM names, account IDs, and resource IDs. It is gitignored. Treat it as internal data.
- `reports/.cache/` holds the same data as JSON. Delete it when you finish, or run without `--cache`.
- If a client secret is exposed, delete that API client in the Falcon console and create a new one.
