# Falcon sensor coverage for cloud VMs

Read-only report of how many running cloud VMs have the CrowdStrike Falcon sensor, split into Kubernetes nodes and standalone VMs. It covers AWS EC2, Azure VMs and VM Scale Set instances, and GCP instances.

Outputs: HTML report, plain-text report, and CSV files. All three come from the same data.

## Requirements

- Python 3.9 or newer. The script uses only the standard library, so there is nothing to `pip install`.
- A Falcon API client (see below).

## Create the API client in the Falcon console

1. Go to **Support and resources > API clients and keys** and select **Create API client**.
2. Name it, for example `sensor-coverage-readonly`.
3. Grant only this scope:
   - **Cloud Security Assets: Read**

   Confirm the exact label in your console. The script needs no other scope.
4. Save. Falcon shows the **Client ID** and **Client secret** once. Copy both now.
5. Note the base URL for your cloud. Use the one that matches the console you log in to:

   | Cloud | Base URL |
   |-------|----------|
   | US-1 | `https://api.crowdstrike.com` |
   | US-2 | `https://api.us-2.crowdstrike.com` |
   | EU-1 | `https://api.eu-1.crowdstrike.com` |

## Configure credentials

Credentials are read from environment variables. Nothing is written in the code.

Create a `.env` file in the project folder. Replace the placeholders with your values:

```
FALCON_CLIENT_ID=your-client-id
FALCON_CLIENT_SECRET=your-client-secret
FALCON_BASE_URL=https://api.crowdstrike.com
```

Restrict the file so only your user can read it:

```
chmod 600 .env
```

`.env` is listed in `.gitignore`. Do not remove that entry, and never commit `.env`.

## Run the script

Load the variables into your shell for the current session, then run the script:

```
set -a; source .env; set +a
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
| `--detail-limit N` | `100` | Asset rows shown in HTML and TXT. The CSV always has every asset. |
| `--cache` | off | Reuse fetched assets for 15 minutes. |
| `--refresh` | off | Ignore the cache and query the API again. |

Outputs are written to `reports/`. For the default run:

- `reports/coverage-running.html`
- `reports/coverage-running-assets.csv`, the full asset list

The script prints progress and timing to the terminal.

## What the numbers mean

- **With sensor**: `managed_by` is `Sensor`.
- **Agentless snapshot only**: visible through a snapshot scan, no sensor installed.
- **Unmanaged**: neither a sensor nor a snapshot scan.
- **Without sensor**: agentless snapshot only plus unmanaged.
- **Kubernetes node**: a VM whose tag keys identify it as an EKS, AKS, or GKE/K8s node.

Records with no sensor status are excluded from the counts, and the report says how many.

## Security notes

- The script only calls read endpoints. It has no write or delete calls.
- The `reports/` folder contains VM names, account IDs and resource IDs. It is gitignored. Treat it as internal.
- `reports/.cache/` holds the same data as JSON. Delete it when you finish, or run without `--cache`.
- If a client secret is exposed, delete that API client in the console and create a new one.
