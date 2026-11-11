#!/usr/bin/env python3
"""Falcon sensor coverage for cloud VMs, split by Kubernetes membership. Read-only.

Requires FALCON_CLIENT_ID and FALCON_CLIENT_SECRET (optional FALCON_BASE_URL).
Load them from .env without writing them into code:  set -a; source .env; set +a

  python3 sensor_coverage.py                                  # VM report, HTML, running VMs
  python3 sensor_coverage.py --format html,txt,csv            # several outputs from one fetch
  python3 sensor_coverage.py --report summary --format txt    # KPIs and coverage tables only
  python3 sensor_coverage.py --cloud aws --scope all --cache  # reuse fetched assets for 15 min
"""
import argparse
import collections
import csv
import html
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPORTS = HERE / "reports"
CACHE_DIR = REPORTS / ".cache"
CACHE_TTL_SECONDS = 15 * 60
QUERY_PATH = "/cloud-security-assets/queries/resources/v1"
ENTITY_PATH = "/cloud-security-assets/entities/resources/v1"
BATCH_SIZE = 100
WORKERS = 6
RETRIES = 5
RETRY_STATUS = {429, 500, 502, 503, 504}

RESOURCE_TYPES = {
    "AWS": ["AWS::EC2::Instance"],
    "Azure": ["Microsoft.Compute/virtualMachines", "Microsoft.Compute/virtualMachineScaleSets/virtualMachines"],
    "GCP": ["compute.googleapis.com/Instance"],
}
CLOUD_STATE = {"AWS": "running", "Azure": "running", "GCP": "RUNNING"}
CLOUD_CHOICES = {"aws": "AWS", "azure": "Azure", "gcp": "GCP"}
K8S_TAG_KEY = {"AWS": r"eks", "Azure": r"aks", "GCP": r"goog-(gke|k8s)"}
K8S_LABEL = "Kubernetes nodes (EKS / AKS / GKE)"
STANDALONE_LABEL = "Standalone VMs (not Kubernetes)"
SENSOR_STATES = {"Sensor", "Snapshot", "Unmanaged"}
FIELDS = ["total", "with_sensor", "without_sensor", "snapshot", "unmanaged"]
VMSS_NAME = re.compile(r"virtualMachineScaleSets/([^/]+)/virtualMachines/([^/]+)$", re.I)
CONTAINER_DEFINITION = (
    "a VM counts as a container host only if its tags show it is a Kubernetes node "
    "(EKS: tag key containing 'eks'; AKS: 'aks'; GKE/K8s: 'goog-gke' or 'goog-k8s'). "
    "Docker-only VMs are counted as without containers, so the sizing split can over- or under-count."
)
CONTAINER_DISCLAIMER = "Container host definition: " + CONTAINER_DEFINITION
REPORT_TYPES = ["summary", "vm"]
FORMATS = ["html", "txt", "csv"]
SENSOR_PRIORITY = {"Unmanaged": 0, "Snapshot": 1, "Unknown": 2, "Sensor": 3}
CSV_COLUMNS = ["cloud", "segment", "total", "with_sensor", "without_sensor", "agentless_snapshot_only",
               "unmanaged", "coverage_pct"]
ASSET_COLUMNS = ["cloud", "resource_type", "name", "account", "resource_id", "state", "k8s", "sensor"]
ASSET_HEADERS = ["Cloud", "Resource type", "Name", "Account", "State", "K8s node", "Sensor status"]
HEADERS = [
    ("Cloud / segment", False, "Cloud, or a segment within it"),
    ("Total", True, "All VMs in scope"),
    ("With sensor", True, "With sensor = managed_by Sensor"),
    ("Without sensor", True, "Without sensor = Agentless snapshot only + Unmanaged"),
    ("of which: Agentless snapshot only", True, "Agentless snapshot only = visible via snapshot scan, no sensor installed"),
    ("of which: Unmanaged", True, "Unmanaged = neither sensor nor snapshot scan"),
    ("Coverage", True, "With sensor / Total"),
    ("Split bar", True, "Red = with sensor, blue = agentless snapshot only, dark grey = unmanaged"),
]


class Falcon:
    def __init__(self):
        cid = os.environ.get("FALCON_CLIENT_ID", "")
        secret = os.environ.get("FALCON_CLIENT_SECRET", "")
        if not cid or not secret:
            sys.exit("Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET first: set -a; source .env; set +a")
        self.base = os.environ.get("FALCON_BASE_URL", "https://api.crowdstrike.com").rstrip("/")
        self.token = self._call("POST", "/oauth2/token", form={"client_id": cid, "client_secret": secret})["access_token"]

    def _call(self, method, path, query=None, form=None, token=None):
        url = self.base + path
        if query:
            url += "?" + urllib.parse.urlencode(query, doseq=True)
        headers, data = {}, None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        if token:
            headers["Authorization"] = f"Bearer {token}"
        for attempt in range(RETRIES):
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as e:
                if e.code not in RETRY_STATUS or attempt == RETRIES - 1:
                    sys.exit(f"{method} {path} failed: HTTP {e.code}")
                retry_after = e.headers.get("Retry-After", "")
                time.sleep(int(retry_after) if retry_after.isdigit() else 2 ** attempt)
            except (urllib.error.URLError, TimeoutError):
                if attempt == RETRIES - 1:
                    sys.exit(f"{method} {path} failed: network timeout or connection error")
                time.sleep(2 ** attempt)

    def get(self, path, query):
        return self._call("GET", path, query=query, token=self.token)


TIMINGS = collections.OrderedDict()


@contextmanager
def phase(name):
    start = time.perf_counter()
    try:
        yield
    finally:
        TIMINGS[name] = TIMINGS.get(name, 0.0) + time.perf_counter() - start


def query_ids(api, cloud, rtype, scope):
    fql = f"resource_type:'{rtype}'"
    if scope == "running":
        fql += f"+instance_state:'{CLOUD_STATE[cloud]}'"
    ids, after = [], None
    while True:
        query = {"filter": fql, "limit": 1000}
        if after:
            query["after"] = after
        page = api.get(QUERY_PATH, query)
        ids += page["resources"]
        after = page.get("meta", {}).get("pagination", {}).get("after")
        if not after or not page["resources"]:
            break
    return ids


def slim(asset, cloud, rtype):
    ctx = asset.get("cloud_context") or {}
    tags = asset.get("tags") or {}
    return {
        "cloud": cloud,
        "resource_type": rtype,
        "name": vm_name(asset),
        "account": asset.get("account_name") or asset.get("account_id") or "",
        "resource_id": asset.get("resource_id") or "",
        "state": ctx.get("instance_state") or "",
        "k8s": any(re.search(K8S_TAG_KEY[cloud], k, re.I) for k in tags),
        "sensor": ctx.get("managed_by") or "Unknown",
    }


def fetch_entities(api, cloud, rtype, ids, scope):
    batches = [ids[i:i + BATCH_SIZE] for i in range(0, len(ids), BATCH_SIZE)]
    rows, done = [], 0

    def get_batch(batch):
        return api.get(ENTITY_PATH, {"ids": batch})["resources"]

    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for batch, resources in zip(batches, pool.map(get_batch, batches)):
            done += len(batch)
            for asset in resources:
                row = slim(asset, cloud, rtype)
                if scope == "all" or row["state"].lower() == "running":
                    rows.append(row)
            print(f"\r  entities {done}/{len(ids)}", end="", file=sys.stderr, flush=True)
    if ids:
        print(file=sys.stderr)
    return rows


def load_cache(path):
    if not path.exists():
        return None
    data = json.loads(path.read_text())
    if time.time() - data["created"] > CACHE_TTL_SECONDS:
        return None
    return data["rows"]


def save_cache(path, rows):
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"created": time.time(), "rows": rows}))


def collect_rows(api, clouds, scope, use_cache, refresh):
    rows = []
    for cloud in clouds:
        path = CACHE_DIR / f"assets-{scope}-{cloud}.json"
        cached = load_cache(path) if use_cache and not refresh else None
        if cached is not None:
            print(f"{cloud}: {len(cached)} rows from cache ({path.name})", file=sys.stderr)
            rows += cached
            continue
        cloud_rows = []
        for rtype in RESOURCE_TYPES[cloud]:
            with phase("query_ids"):
                ids = query_ids(api, cloud, rtype, scope)
            print(f"{rtype}: {len(ids)} ids", file=sys.stderr)
            with phase("get_entities"):
                cloud_rows += fetch_entities(api, cloud, rtype, ids, scope)
        if use_cache:
            save_cache(path, cloud_rows)
        rows += cloud_rows
    return rows



def vm_name(asset):
    m = VMSS_NAME.search(asset.get("resource_id") or "")
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    return asset.get("resource_name") or asset.get("resource_id")


def tally(label, cloud, level, rs):
    c = collections.Counter(r["sensor"] for r in rs)
    total = len(rs)
    with_sensor = c.get("Sensor", 0)
    snapshot = c.get("Snapshot", 0)
    unmanaged = c.get("Unmanaged", 0)
    return {
        "label": label,
        "cloud": cloud,
        "level": level,
        "total": total,
        "with_sensor": with_sensor,
        "without_sensor": snapshot + unmanaged,
        "snapshot": snapshot,
        "unmanaged": unmanaged,
        "coverage_pct": round(100 * with_sensor / total, 1) if total else 0.0,
    }


def summarize(rows, clouds, top_label):
    table = [tally(top_label, "All", 0, rows)]
    for cloud in clouds:
        cr = [r for r in rows if r["cloud"] == cloud]
        table.append(tally(cloud, cloud, 0, cr))
        table.append(tally(K8S_LABEL, cloud, 1, [r for r in cr if r["k8s"]]))
        table.append(tally(STANDALONE_LABEL, cloud, 1, [r for r in cr if not r["k8s"]]))
    split = [
        tally(STANDALONE_LABEL, "All", 1, [r for r in rows if not r["k8s"]]),
        tally(K8S_LABEL, "All", 1, [r for r in rows if r["k8s"]]),
        tally("All VMs", "All", 0, rows),
    ]
    return table, split


def expect(ok, msg):
    if not ok:
        sys.exit(f"Check failed: {msg}")


def verify(table, split, rows, clouds):
    expect(all(r["sensor"] in SENSOR_STATES for r in rows), "unexpected sensor status values")
    for s in table + split:
        expect(s["with_sensor"] + s["without_sensor"] == s["total"], f"with + without != total in {s['label']}")
        expect(s["without_sensor"] == s["snapshot"] + s["unmanaged"], f"without != snapshot + unmanaged in {s['label']}")
    grand = table[0]
    cloud_rows = [s for s in table if s["level"] == 0 and s["label"] in clouds]
    for field in FIELDS:
        expect(sum(c[field] for c in cloud_rows) == grand[field], f"selected clouds != All clouds on {field}")
    for c in cloud_rows:
        kids = [s for s in table if s["level"] == 1 and s["cloud"] == c["label"]]
        for field in FIELDS:
            expect(sum(k[field] for k in kids) == c[field], f"children != {c['label']} on {field}")
    all_vms = split[2]
    for field in FIELDS:
        expect(split[0][field] + split[1][field] == all_vms[field], f"standalone + K8s != All VMs on {field}")
        expect(all_vms[field] == grand[field], f"All VMs != All clouds on {field}")
    print("checks passed: with + without = total, clouds sum to All clouds, standalone + K8s = All VMs",
          file=sys.stderr)



def format_table(head, body, align):
    widths = [max(len(str(x)) for x in col) for col in zip(head, *body)]

    def line(cells):
        out = [str(c).ljust(w) if al == "l" else str(c).rjust(w) for c, w, al in zip(cells, widths, align)]
        return "  ".join(out).rstrip()

    return [line(head), "-" * (sum(widths) + 2 * (len(widths) - 1))] + [line(b) for b in body]


def text_cells(s):
    return [("  " if s["level"] else "") + s["label"], s["total"], s["with_sensor"], s["without_sensor"],
            s["snapshot"], s["unmanaged"], f"{s['coverage_pct']}%"]


def asset_cells(r):
    return [r["cloud"], r["resource_type"], str(r["name"]), r["account"], r["state"],
            "Yes" if r["k8s"] else "No", r["sensor"]]



METHOD_NOTES = [
    "Running means cloud_context.instance_state is running (GCP reports RUNNING).",
    "Sensor = managed_by Sensor. Agentless snapshot only = visible via snapshot scan, no sensor installed. Unmanaged = neither.",
    "Without sensor = Agentless snapshot only + Unmanaged.",
    'Kubernetes membership comes from tag keys: EC2 keys containing "eks", Azure keys containing "aks", GCP keys containing goog-gke or goog-k8s.',
    "Container proxy: a VM counts as running containers only when it is a Kubernetes node. Docker-only VMs are not detected.",
]
COVERAGE_HEAD = [h[0] for h in HEADERS[:7]]
SPLIT_HEAD = ["Segment"] + COVERAGE_HEAD[1:]
COVERAGE_ALIGN = ["l", "r", "r", "r", "r", "r", "r"]
ASSET_ALIGN = ["l"] * 7


def pct(n, d):
    return round(100 * n / d, 1) if d else 0.0


def showing_line(assets):
    if assets["shown"] < assets["total"]:
        return f"Showing {assets['shown']} of {assets['total']} assets. Full list in {assets['csv']}"
    return f"Showing all {assets['total']} assets. Full list in {assets['csv']}"


def build_model(a, stamp, clouds, table, split, rows, stem, excluded):
    overall, k8s = table[0], split[1]
    kpis = [
        ("VMs in scope", str(overall["total"])),
        ("With sensor", f"{overall['with_sensor']} ({overall['coverage_pct']}%)"),
        ("VMs without sensor", f"{overall['without_sensor']} ({pct(overall['without_sensor'], overall['total'])}%)"),
        ("Kubernetes nodes without sensor", f"{k8s['without_sensor']} of {k8s['total']}"),
    ]
    method = list(METHOD_NOTES)
    if excluded:
        method.append(f"{excluded} records with no sensor status (managed_by missing) are excluded from the counts.")
    assets = None
    if a.report == "vm":
        ordered = sorted(rows, key=lambda r: (SENSOR_PRIORITY.get(r["sensor"], 2), r["cloud"], str(r["name"])))
        assets = {
            "total": len(ordered),
            "shown": min(len(ordered), a.detail_limit),
            "csv": f"{stem}-assets.csv",
            "rows": ordered[:a.detail_limit],
            "all_rows": ordered,
        }
        method.append(f"Asset detail is capped at {a.detail_limit} rows: unmanaged first, then agentless snapshot only, "
                      "then with sensor. The full list is in the assets CSV.")
    return {
        "title": "Falcon sensor coverage",
        "report": a.report,
        "scope": a.scope,
        "clouds": ", ".join(clouds),
        "stamp": stamp,
        "kpis": kpis,
        "coverage": table,
        "split": split,
        "method": method,
        "assets": assets,
    }


def render_txt(m):
    out = [f"{m['title']} | report={m['report']} | scope={m['scope']} | clouds={m['clouds']} | {m['stamp']}", "",
           "KPIs"]
    out += [f"  {label}: {value}" for label, value in m["kpis"]]
    out += ["", "Coverage by cloud and Kubernetes membership"]
    out += format_table(COVERAGE_HEAD, [text_cells(s) for s in m["coverage"]], COVERAGE_ALIGN)
    out += ["", "Global split: standalone VMs vs Kubernetes nodes"]
    out += format_table(SPLIT_HEAD, [text_cells(s) for s in m["split"]], COVERAGE_ALIGN)
    out += ["", "Method"] + [f"  - {note}" for note in m["method"]]
    out += ["", CONTAINER_DISCLAIMER]
    if m["assets"]:
        out += ["", "Asset detail", showing_line(m["assets"])]
        out += format_table(ASSET_HEADERS, [asset_cells(r) for r in m["assets"]["rows"]], ASSET_ALIGN)
    return "\n".join(out) + "\n"


def coverage_csv(s):
    return {"cloud": s["cloud"], "segment": s["label"], "total": s["total"], "with_sensor": s["with_sensor"],
            "without_sensor": s["without_sensor"], "agentless_snapshot_only": s["snapshot"],
            "unmanaged": s["unmanaged"], "coverage_pct": s["coverage_pct"]}


def write_csv_file(path, columns, rows):
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=columns)
        w.writeheader()
        w.writerows(rows)
    return path


def write_outputs(model, formats, stem):
    REPORTS.mkdir(exist_ok=True)
    written = []
    if "html" in formats:
        path = REPORTS / f"{stem}.html"
        path.write_text(render_html(model), encoding="utf-8")
        written.append(path)
    if "txt" in formats:
        path = REPORTS / f"{stem}.txt"
        path.write_text(render_txt(model), encoding="utf-8")
        written.append(path)
    if "csv" in formats:
        written.append(write_csv_file(REPORTS / f"{stem}.csv", CSV_COLUMNS,
                                      [coverage_csv(s) for s in model["coverage"]]))
        written.append(write_csv_file(REPORTS / f"{stem}-global.csv", CSV_COLUMNS,
                                      [coverage_csv(s) for s in model["split"]]))
        if model["assets"]:
            written.append(write_csv_file(REPORTS / model["assets"]["csv"], ASSET_COLUMNS,
                                          model["assets"]["all_rows"]))
    for path in written:
        print(f"wrote {path}", file=sys.stderr)



CSS = """
body{font-family:"CrowdStrike Sharp Sans",Arial,Helvetica,sans-serif;background:#F8F8F8;color:#000;margin:0}
header{background:#000;color:#fff;padding:24px 32px;border-bottom:6px solid #EC0000}
header h1{margin:0;font-size:24px} header p{margin:6px 0 0;color:#ccc;font-size:13px}
main{padding:24px 32px}
.kpis{display:flex;gap:16px;flex-wrap:wrap;margin-bottom:24px}
.kpi{background:#fff;border-top:4px solid #EC0000;padding:16px 20px;min-width:180px}
.kpi b{display:block;font-size:28px} .kpi span{font-size:13px;color:#555}
table{border-collapse:collapse;width:100%;background:#fff}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid #e5e5e5;font-size:14px}
th{background:#000;color:#fff;font-weight:600}
th.n,td.n{text-align:right;font-variant-numeric:tabular-nums}
tr.total td{font-weight:700;background:#f0f0f0}
tr.child td:first-child{padding-left:30px;font-weight:400}
.bar{display:flex;height:14px;width:220px;background:#e5e5e5} .bar span{display:block;height:100%}
.legend span{display:inline-block;width:12px;height:12px;margin:0 4px 0 16px;vertical-align:middle}
.disclaimer{font-size:13px;color:#333;background:#fff;border-left:4px solid #61C4C9;padding:10px 14px;margin-top:16px}
h2{font-size:18px;margin:28px 0 8px}
.note{font-size:13px;color:#333}
ul.notes{font-size:13px;color:#333;line-height:1.6}
"""


def th(name, numeric, tip):
    cls = ' class="n"' if numeric else ""
    return f'<th{cls} title="{html.escape(tip)}">{html.escape(name)}</th>'


def bar(s):
    total = s["total"] or 1
    parts = [(s["with_sensor"], "Sensor", "#EC0000"),
             (s["snapshot"], "Agentless snapshot only", "#61C4C9"),
             (s["unmanaged"], "Unmanaged", "#3A3A3A")]
    return "".join(f'<span style="width:{100 * n / total:.1f}%;background:{color}" title="{label}: {n}"></span>'
                   for n, label, color in parts if n)


def html_table(data, first_label):
    heads = [(first_label, False, HEADERS[0][2])] + HEADERS[1:]
    head = "".join(th(name, numeric, tip) for name, numeric, tip in heads)
    body = "".join(html_row(s) for s in data)
    return f"<table><tr>{head}</tr>{body}</table>"


def html_row(s):
    cls = "total" if s["level"] == 0 else "child"
    cells = [
        f'<td>{html.escape(s["label"])}</td>',
        f'<td class="n">{s["total"]}</td>',
        f'<td class="n">{s["with_sensor"]}</td>',
        f'<td class="n">{s["without_sensor"]}</td>',
        f'<td class="n">{s["snapshot"]}</td>',
        f'<td class="n">{s["unmanaged"]}</td>',
        f'<td class="n">{s["coverage_pct"]}%</td>',
        f'<td><div class="bar">{bar(s)}</div></td>',
    ]
    return f'<tr class="{cls}">' + "".join(cells) + "</tr>"


def asset_row_html(r):
    return "<tr>" + "".join(f"<td>{html.escape(c)}</td>" for c in asset_cells(r)) + "</tr>"


def render_html(m):
    kpis = "".join(f'<div class="kpi"><b>{html.escape(v)}</b><span>{html.escape(k)}</span></div>'
                   for k, v in m["kpis"])
    method = "".join(f"<li>{html.escape(n)}</li>" for n in m["method"])
    assets = ""
    if m["assets"]:
        a = m["assets"]
        head = "".join(f"<th>{html.escape(h)}</th>" for h in ASSET_HEADERS)
        body = "".join(asset_row_html(r) for r in a["rows"])
        assets = (f'<h2>Asset detail</h2><p class="note">{html.escape(showing_line(a))}</p>'
                  f"<table><tr>{head}</tr>{body}</table>")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>Falcon sensor coverage</title>
<style>{CSS}</style></head><body>
<header><h1>Falcon sensor coverage</h1>
<p>Report: {html.escape(m['report'])} | Scope: {html.escape(m['scope'])} | Clouds: {html.escape(m['clouds'])} | Generated {html.escape(m['stamp'])} | Read-only</p></header>
<main>
<div class="kpis">{kpis}</div>
<h2>Coverage by cloud and Kubernetes membership</h2>
{html_table(m['coverage'], 'Cloud / segment')}
<p class="legend">
<span style="background:#EC0000"></span>Sensor
<span style="background:#61C4C9"></span>Agentless snapshot only
<span style="background:#3A3A3A"></span>Unmanaged
</p>
<h2>Global split: standalone VMs vs Kubernetes nodes</h2>
{html_table(m['split'], 'Segment')}
<p class="disclaimer"><b>Container host definition:</b> {html.escape(CONTAINER_DEFINITION)}</p>
<h2>Method</h2>
<ul class="notes">{method}</ul>
{assets}
</main></body></html>
"""


def parse_formats(ap, value):
    items = [v.strip().lower() for v in value.split(",") if v.strip()]
    if "all" in items:
        return FORMATS
    if not items or any(v not in FORMATS for v in items):
        ap.error("--format takes html, txt, csv, all, or a comma-separated list of them")
    return items


def output_stem(a):
    stem = f"coverage-{a.scope}"
    if a.cloud != "all":
        stem += f"-{a.cloud}"
    if a.report == "summary":
        stem += "-summary"
    return stem


def main():
    ap = argparse.ArgumentParser(description="Falcon sensor coverage for cloud VMs, split by Kubernetes membership. Read-only.")
    ap.add_argument("--report", choices=REPORT_TYPES, default="vm",
                    help="summary: KPIs and coverage tables; vm: summary plus capped asset detail")
    ap.add_argument("--scope", choices=["running", "all"], default="running")
    ap.add_argument("--cloud", choices=["all", *CLOUD_CHOICES], default="all")
    ap.add_argument("--format", default="html", help="html, txt, csv, all, or comma-separated (default: html)")
    ap.add_argument("--detail-limit", type=int, default=100, help="asset rows shown in HTML and TXT (default: 100)")
    ap.add_argument("--cache", action="store_true", help="reuse fetched assets for 15 minutes")
    ap.add_argument("--refresh", action="store_true", help="ignore cached assets and query the API again")
    a = ap.parse_args()
    if a.detail_limit < 0:
        ap.error("--detail-limit must be 0 or more")
    formats = parse_formats(ap, a.format)
    clouds = list(RESOURCE_TYPES) if a.cloud == "all" else [CLOUD_CHOICES[a.cloud]]
    top_label = "All clouds" if a.cloud == "all" else f"All clouds ({clouds[0]} only)"

    rows = collect_rows(Falcon(), clouds, a.scope, a.cache, a.refresh)
    excluded = sum(1 for r in rows if r["sensor"] not in SENSOR_STATES)
    rows = [r for r in rows if r["sensor"] in SENSOR_STATES]
    with phase("summarize_verify"):
        table, split = summarize(rows, clouds, top_label)
        verify(table, split, rows, clouds)
    stem = output_stem(a)
    with phase("render_write"):
        model = build_model(a, datetime.now().strftime("%Y-%m-%d %H:%M"), clouds, table, split, rows, stem, excluded)
        write_outputs(model, formats, stem)
    for name, secs in TIMINGS.items():
        print(f"[timing] {name}: {secs:.2f}s", file=sys.stderr)


if __name__ == "__main__":
    main()
