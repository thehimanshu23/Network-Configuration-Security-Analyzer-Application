import os
import re
import json
import uuid
import pandas as pd
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, send_file, flash

# ==============================
# ✅ CONFIG
# ==============================
UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "output"

ROUTER_JSON = "Cisco_router_benchmark.json"
SWITCH_L2_JSON = "switch_benchmark.json"
SWITCH_L3_JSON = "l3_switch.json"

ALLOWED_EXTENSIONS = {"txt", "cfg", "conf"}

app = Flask(__name__)
app.secret_key = "supersecretkey"  # ✅ change later
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["OUTPUT_FOLDER"] = OUTPUT_FOLDER

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["OUTPUT_FOLDER"], exist_ok=True)


# ==============================
# ✅ HELPERS
# ==============================
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def read_config(filepath):
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def normalize_cfg(cfg: str) -> str:
    return cfg.replace("\r\n", "\n").replace("\r", "\n")


def extract_ios_version(cfg: str):
    m = re.search(r"(?im)^\s*version\s+([0-9A-Za-z().]+)\s*$", cfg)
    if m:
        return m.group(1).strip()

    m = re.search(r"(?i)\bversion\s+([0-9A-Za-z().]+)", cfg)
    if m:
        return m.group(1).strip()

    return "Not Found"


def extract_device_software_line(cfg: str):
    m = re.search(r"(?im)^\s*(Cisco IOS Software.*)$", cfg)
    if m:
        return m.group(1).strip()
    return "Not Found"


# ==============================
# ✅ CIS URL AUTO BASED ON DEVICE
# ==============================
def get_cis_benchmark_url(device_type: str, device_software_info: str):
    dt = (device_type or "").lower().strip()
    info = (device_software_info or "").lower()

    fallback = "https://www.cisecurity.org/cis-benchmarks"

    if dt == "router":
        return "https://www.cisecurity.org/benchmark/cisco_ios"

    if dt in ["switch_l2", "switch_l3"]:
        if "ios-xe" in info or "ios xe" in info:
            return "https://www.cisecurity.org/benchmark/cisco"
        return "https://www.cisecurity.org/benchmark/cisco"

    return fallback


# ==============================
# ✅ DEVICE TYPE DETECTION
# ==============================
def detect_device_type(cfg: str):
    cfg_lower = cfg.lower()
    indicators = []

    router_score = 0
    switch_score = 0
    l3_score = 0

    router_models = [
        r"\bisr\b", r"\basr\b",
        r"\bcisco\s*29\d{2}\b",
        r"\bcisco\s*19\d{2}\b",
        r"\bcisco\s*39\d{2}\b",
    ]

    switch_models = [
        r"\bws-c\d{4}\b",
        r"\bcatalyst\b",
        r"\bc\d{4}\b",
        r"\bnexus\b",
    ]

    for pat in router_models:
        if re.search(pat, cfg_lower):
            router_score += 8
            indicators.append("Router hardware model signature found")
            break

    for pat in switch_models:
        if re.search(pat, cfg_lower):
            switch_score += 8
            indicators.append("Switch hardware model signature found")
            break

    switch_patterns = [
        (r"^\s*switchport\b", 6, "Switchport found"),
        (r"^\s*spanning-tree\b", 6, "Spanning-tree found"),
        (r"^\s*vlan\s+\d+\b", 4, "VLAN config found"),
        (r"^\s*channel-group\b", 3, "Port-channel config found"),
        (r"^\s*ip dhcp snooping\b", 5, "DHCP snooping found"),
    ]

    for pat, score, reason in switch_patterns:
        if re.search(pat, cfg, re.M | re.I):
            switch_score += score
            indicators.append(reason)

    router_patterns = [
        (r"^\s*ip nat\b", 6, "NAT found"),
        (r"^\s*crypto (isakmp|ikev2|ipsec)\b", 6, "VPN/Crypto found"),
        (r"^\s*interface\s+(Serial|Tunnel|Dialer|Cellular)\d+", 6, "WAN interface found"),
        (r"^\s*router\s+(bgp|eigrp|rip|isis)\b", 5, "Routing protocol found"),
    ]

    for pat, score, reason in router_patterns:
        if re.search(pat, cfg, re.M | re.I):
            router_score += score
            indicators.append(reason)

    if re.search(r"^\s*interface\s+Vlan\d+\b", cfg, re.M | re.I):
        switch_score += 5
        l3_score += 8
        indicators.append("SVI found (interface VlanX)")

    if re.search(r"^\s*ip routing\b", cfg, re.M | re.I):
        switch_score += 4
        l3_score += 8
        indicators.append("ip routing enabled")

    if re.search(r"^\s*ip route\b", cfg, re.M | re.I):
        switch_score += 3
        l3_score += 6
        indicators.append("Static route found (ip route)")

    if re.search(r"^\s*no switchport\b", cfg, re.M | re.I):
        switch_score += 3
        l3_score += 6
        indicators.append("Routed port found (no switchport)")

    if l3_score >= 12 and switch_score >= 10:
        device_type = "switch_l3"
    elif router_score >= switch_score + 4 and router_score >= 10:
        device_type = "router"
    elif switch_score >= router_score + 4 and switch_score >= 10:
        device_type = "switch_l2"
    else:
        device_type = "unknown"

    if device_type == "unknown":
        confidence = "Low"
    else:
        top = max(router_score, switch_score, l3_score)
        confidence = "High" if top >= 22 else "Medium" if top >= 14 else "Low"

    scores = {
        "router_score": router_score,
        "switch_score": switch_score,
        "l3_score": l3_score,
    }

    return device_type, confidence, indicators[:15], scores


# ==============================
# ✅ RULE HELPERS
# ==============================
def extract_blocks(cfg: str, header_regex: str):
    lines = cfg.splitlines()
    blocks = []
    i = 0

    while i < len(lines):
        if re.search(header_regex, lines[i], re.I):
            block = [lines[i]]
            i += 1

            while i < len(lines):
                line = lines[i]
                if line.strip() == "!":
                    break
                if re.match(r"^[A-Za-z]", line):
                    break
                block.append(line)
                i += 1

            blocks.append("\n".join(block))
        i += 1

    return blocks


def evidence_regex(text, pattern, max_lines=8):
    ev = []
    for line in text.splitlines():
        if re.search(pattern, line, re.I):
            ev.append(line.rstrip())
        if len(ev) >= max_lines:
            break
    return "\n".join(ev) if ev else "-"


def evidence_all_lines(text, pattern, max_lines=200):
    ev = []
    for line in text.splitlines():
        if re.search(pattern, line, re.I):
            ev.append(line.rstrip())
    if not ev:
        return "-"
    return "\n".join(ev[:max_lines])


def extract_banner(cfg_text: str, banner_type: str = "login"):
    start = re.search(rf"(?im)^\s*banner\s+{banner_type}\s+(\S+)\s*$", cfg_text)
    if not start:
        return None

    start_delim = start.group(1).strip()
    after = cfg_text[start.end():]

    possible_end_delims = [start_delim]

    if start_delim.startswith("^") and len(start_delim) > 2:
        possible_end_delims.append("^C")

    possible_end_delims.append("^C")

    seen = set()
    possible_end_delims = [d for d in possible_end_delims if not (d in seen or seen.add(d))]

    for d in possible_end_delims:
        m_end = re.search(rf"(?im)^\s*{re.escape(d)}\s*$", after)
        if m_end:
            content = after[:m_end.start()].strip("\n")
            return f"banner {banner_type} {start_delim}\n{content}\n{d}"

    return None


# ==============================
# ✅ RULE RUNNER
# ==============================
def run_rule(cfg: str, rule: dict):
    rule_type = rule.get("type", "").lower().strip()
    title = rule.get("title", "Unknown Rule")

    if rule_type == "manual":
        return "MANUAL", "Manual verification required", "-"

    if rule_type == "regex":
        pattern = rule.get("pattern", "")
        expect = rule.get("expect", "present").lower()

        if not pattern:
            return "MANUAL", f"{title} (pattern missing)", "-"

        found = bool(re.search(pattern, cfg, re.M | re.I))
        ev = evidence_regex(cfg, pattern)

        if expect == "present":
            return ("PASS", "Matched", ev) if found else ("FAIL", "Not found", "-")
        if expect == "absent":
            return ("FAIL", "Insecure config found", ev) if found else ("PASS", "Not present (good)", "-")
        if expect == "manual":
            return "MANUAL", "Manual verification required", ev if found else "-"

        return "MANUAL", "Invalid expect value", "-"

    if rule_type == "regex_capture":
        pattern = rule.get("pattern", "")
        expect = rule.get("expect", "present").lower()

        if not pattern:
            return "MANUAL", f"{title} (pattern missing)", "-"

        m = re.search(pattern, cfg, re.M | re.I)
        found = bool(m)
        ev = m.group(0).strip() if found else "-"

        if expect == "present":
            return ("PASS", "Matched", ev) if found else ("FAIL", "Not found", "-")
        if expect == "absent":
            return ("FAIL", "Insecure config found", ev) if found else ("PASS", "Not present (good)", "-")

        return "MANUAL", "Invalid expect value", "-"

    if rule_type == "regex_capture_all":
        pattern = rule.get("pattern", "")
        expect = rule.get("expect", "present").lower()

        if not pattern:
            return "MANUAL", f"{title} (pattern missing)", "-"

        matches = list(re.finditer(pattern, cfg, re.M | re.I))

        if not matches:
            if expect == "present":
                return "FAIL", "Not found", "-"
            if expect == "absent":
                return "PASS", "Not present (good)", "-"
            return "MANUAL", "Invalid expect value", "-"

        output_lines = [m.group(0).strip() for m in matches if m.group(0).strip()]
        evidence = "\n".join(output_lines[:200])

        if expect == "present":
            return "PASS", f"Matched {len(output_lines)} entries", evidence

        if expect == "absent":
            return "FAIL", f"Insecure config found ({len(output_lines)} entries)", evidence

        return "MANUAL", "Invalid expect value", evidence

    if rule_type == "banner":
        banner_type = rule.get("banner_type", "login").strip().lower()
        expect = rule.get("expect", "present").lower()

        banner_text = extract_banner(cfg, banner_type)
        found = banner_text is not None

        if expect == "present":
            return ("PASS", "Matched", banner_text) if found else ("FAIL", "Not found", "-")
        if expect == "absent":
            return ("FAIL", "Banner present (should be removed)", banner_text) if found else (
                "PASS", "Not present (good)", "-")

        return "MANUAL", "Invalid expect value", "-"

    if rule_type == "block_present":
        block_header = rule.get("block", "")
        pattern = rule.get("pattern", "")
        expect = rule.get("expect", "present").lower()
        evidence_pattern = rule.get("evidence_pattern")

        if not block_header or not pattern:
            return "MANUAL", f"{title} (block/pattern missing)", "-"

        header_regex = r"^" + re.escape(block_header)
        blocks = extract_blocks(cfg, header_regex)

        if not blocks:
            return "FAIL", f"{block_header} block not found", "-"

        found_any = False
        all_evidence = []

        for blk in blocks:
            if re.search(pattern, blk, re.M | re.I):
                found_any = True
                if evidence_pattern:
                    ev = evidence_all_lines(blk, evidence_pattern)
                else:
                    ev = evidence_all_lines(blk, pattern)

                all_evidence.append(blk.splitlines()[0])
                all_evidence.append(ev)

        evidence = "\n".join(all_evidence).strip() or "-"

        if expect == "present":
            return ("PASS", f"Matched in {len(all_evidence)//2} block(s)", evidence) if found_any else (
                "FAIL", "Not found", "-")

        if expect == "manual":
            return ("MANUAL", f"Matched in {len(all_evidence)//2} block(s)", evidence) if found_any else (
                "MANUAL", "Manual verification required", "-")

        return "MANUAL", "Invalid expect value", evidence

    if rule_type == "block_absent":
        block_header = rule.get("block", "")
        pattern = rule.get("pattern", "")
        expect = rule.get("expect", "absent").lower()
        evidence_pattern = rule.get("evidence_pattern")

        if not block_header or not pattern:
            return "MANUAL", f"{title} (block/pattern missing)", "-"

        header_regex = r"^" + re.escape(block_header)
        blocks = extract_blocks(cfg, header_regex)

        if not blocks:
            return "FAIL", f"{block_header} block not found", "-"

        found_any = False
        evidence_lines = []

        for blk in blocks:
            if re.search(pattern, blk, re.M | re.I):
                found_any = True
                if evidence_pattern:
                    evidence_lines.append(evidence_all_lines(blk, evidence_pattern))
                else:
                    evidence_lines.append(evidence_regex(blk, pattern))

        evidence = "\n\n".join([x for x in evidence_lines if x and x != "-"]).strip() or "-"

        if expect == "absent":
            return ("FAIL", "Insecure config found in block", evidence) if found_any else (
                "PASS", "Not present (good)", "-")

        return "MANUAL", "Invalid expect value", "-"

    return "MANUAL", "Rule type not supported", "-"


# ==============================
# ✅ GENERATED REPORT (report.html)
# ==============================
def generate_report_html(df, filepath, device_type, confidence, indicators,
                         benchmark_used, scores, ios_version, device_software_info, cis_benchmark_url):
    summary = df["Status"].value_counts().to_dict()
    pass_count = summary.get("PASS", 0)
    fail_count = summary.get("FAIL", 0)
    manual_count = summary.get("MANUAL", 0)
    total_count = len(df)

    # Confidence Badge
    if confidence == "High":
        confidence_badge = '<span class="pill pill-green">High</span>'
    elif confidence == "Medium":
        confidence_badge = '<span class="pill pill-yellow">Medium</span>'
    else:
        confidence_badge = '<span class="pill pill-red">Low</span>'

    # Indicators list
    indicator_html = ""
    if indicators:
        for x in indicators:
            indicator_html += f'<span class="chip">{x}</span>'
    else:
        indicator_html = '<span class="chip chip-muted">No indicators found</span>'

    # Table Rows
    rows = ""
    for _, r in df.iterrows():
        status = str(r["Status"]).strip().upper()
        risk = str(r["Risk"]).strip().lower()

        # Status badge
        if status == "PASS":
            status_badge = '<span class="pill pill-green">PASS</span>'
        elif status == "FAIL":
            status_badge = '<span class="pill pill-red">FAIL</span>'
        else:
            status_badge = '<span class="pill pill-yellow">MANUAL</span>'

        # Risk badge
        if risk == "high":
            risk_badge = '<span class="pill pill-red">High</span>'
        elif risk == "medium":
            risk_badge = '<span class="pill pill-yellow">Medium</span>'
        else:
            risk_badge = '<span class="pill pill-blue">Low</span>'

        evidence = str(r.get("Evidence", "")).strip()
        if evidence == "" or evidence.lower() in ["nan", "none"]:
            evidence = "—"

        remark = str(r.get("Remark", "")).strip()
        if remark == "" or remark.lower() in ["nan", "none"]:
            remark = "—"

        recommendation = str(r.get("Recommendation", "")).strip()
        if recommendation == "" or recommendation.lower() in ["nan", "none"]:
            recommendation = "—"

        rows += f"""
        <tr data-status="{status}">
            <td class="mono">{r['ID']}</td>
            <td class="muted">{r['Section']}</td>
            <td class="title">{r['Title']}</td>
            <td>{status_badge}</td>
            <td>{risk_badge}</td>
            <td class="muted">{remark}</td>
            <td class="evidence"><pre>{evidence}</pre></td>
            <td class="muted">{recommendation}</td>
        </tr>
        """

    html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>CIS Audit Report</title>

    <style>
        :root {{
            --bg1: #0b1020;
            --bg2: #070a14;
            --card: rgba(255,255,255,0.06);
            --cardBorder: rgba(255,255,255,0.10);
            --text: #e5e7eb;
            --muted: rgba(229,231,235,0.72);
            --shadow: 0 18px 50px rgba(0,0,0,0.45);

            --green: #22c55e;
            --red: #ef4444;
            --yellow: #f59e0b;
            --blue: #3b82f6;
        }}

        * {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
            background:
                radial-gradient(900px circle at 15% 10%, rgba(79,70,229,0.35), transparent 60%),
                radial-gradient(900px circle at 90% 25%, rgba(6,182,212,0.22), transparent 60%),
                radial-gradient(900px circle at 40% 95%, rgba(34,197,94,0.15), transparent 55%),
                linear-gradient(180deg, var(--bg1), var(--bg2));
            color: var(--text);
        }}

        .wrap {{
            max-width: 1300px;
            margin: auto;
            padding: 22px 16px 40px;
        }}

        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            margin-bottom: 14px;
        }}

        .title-area h1 {{
            margin: 0;
            font-size: 24px;
            letter-spacing: 0.2px;
        }}

        .title-area .sub {{
            margin-top: 6px;
            font-size: 13px;
            color: var(--muted);
        }}

        .actions {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }}

        .btn {{
            cursor: pointer;
            padding: 10px 12px;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.14);
            background: rgba(255,255,255,0.06);
            color: var(--text);
            font-weight: 600;
            font-size: 13px;
            transition: 0.2s ease;
        }}

        .btn:hover {{
            transform: translateY(-1px);
            background: rgba(255,255,255,0.10);
        }}

        .grid {{
            display: grid;
            grid-template-columns: repeat(12, 1fr);
            gap: 14px;
        }}

        .card {{
            background: var(--card);
            border: 1px solid var(--cardBorder);
            border-radius: 18px;
            padding: 16px;
            box-shadow: var(--shadow);
        }}

        .span-4 {{ grid-column: span 4; }}
        .span-6 {{ grid-column: span 6; }}
        .span-12 {{ grid-column: span 12; }}

        @media(max-width: 950px) {{
            .span-4, .span-6 {{ grid-column: span 12; }}
            .header {{
                flex-direction: column;
                align-items: flex-start;
            }}
        }}

        .label {{
            font-size: 12px;
            color: var(--muted);
            margin-bottom: 6px;
        }}

        .value {{
            font-size: 18px;
            font-weight: 800;
        }}

        .mono {{
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 12px;
        }}

        .pill {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 10px;
            border-radius: 999px;
            font-weight: 800;
            font-size: 12px;
            border: 1px solid rgba(255,255,255,0.14);
            background: rgba(255,255,255,0.06);
        }}

        .pill-green {{ color: #86efac; background: rgba(34,197,94,0.18); }}
        .pill-red {{ color: #fca5a5; background: rgba(239,68,68,0.18); }}
        .pill-yellow {{ color: #fde68a; background: rgba(245,158,11,0.18); }}
        .pill-blue {{ color: #93c5fd; background: rgba(59,130,246,0.18); }}

        .summaryRow {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 10px;
            margin-top: 10px;
        }}

        @media(max-width: 950px) {{
            .summaryRow {{
                grid-template-columns: repeat(2, 1fr);
            }}
        }}

        .kpi {{
            padding: 12px;
            border-radius: 16px;
            background: rgba(255,255,255,0.05);
            border: 1px solid rgba(255,255,255,0.10);
        }}

        .kpi .big {{
            font-size: 18px;
            font-weight: 900;
            margin-top: 6px;
        }}

        .chips {{
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 10px;
        }}

        .chip {{
            padding: 8px 10px;
            border-radius: 999px;
            background: rgba(255,255,255,0.06);
            border: 1px solid rgba(255,255,255,0.12);
            font-size: 12px;
            color: rgba(229,231,235,0.88);
        }}

        .toolbar {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 10px;
        }}

        .search {{
            flex: 1;
            min-width: 260px;
            padding: 12px 14px;
            border-radius: 14px;
            outline: none;
            border: 1px solid rgba(255,255,255,0.16);
            background: rgba(255,255,255,0.06);
            color: #fff;
            font-size: 14px;
        }}

        .filters {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
        }}

        .filterBtn {{
            cursor: pointer;
            padding: 10px 12px;
            border-radius: 12px;
            border: 1px solid rgba(255,255,255,0.14);
            background: rgba(255,255,255,0.06);
            color: var(--text);
            font-weight: 700;
            font-size: 12px;
            transition: 0.2s ease;
        }}

        .filterBtn.active {{
            background: rgba(255,255,255,0.14);
            border: 1px solid rgba(255,255,255,0.22);
        }}

        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 14px;
            border-radius: 18px;
            overflow: hidden;
            border: 1px solid rgba(255,255,255,0.14);
            background: rgba(255,255,255,0.04);
        }}

        thead th {{
            position: sticky;
            top: 0;
            z-index: 2;
            background: rgba(15, 23, 42, 0.92);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(255,255,255,0.12);
            padding: 12px 10px;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.55px;
            color: rgba(229,231,235,0.90);
        }}

        td {{
            padding: 12px 10px;
            border-bottom: 1px solid rgba(255,255,255,0.08);
            vertical-align: top;
            font-size: 13px;
        }}

        tr:hover {{
            background: rgba(255,255,255,0.06);
        }}

        .muted {{
            color: rgba(229,231,235,0.74);
        }}

        .title {{
            font-weight: 800;
            color: #ffffff;
        }}

        .evidence pre {{
            white-space: pre-wrap;
            margin: 0;
            padding: 10px;
            border-radius: 12px;
            background: rgba(0,0,0,0.35);
            border: 1px solid rgba(255,255,255,0.10);
            font-size: 12px;
            line-height: 1.45;
        }}

        tr[data-status="PASS"] td {{
            border-left: 4px solid rgba(34,197,94,0.75);
        }}
        tr[data-status="FAIL"] td {{
            border-left: 4px solid rgba(239,68,68,0.75);
        }}
        tr[data-status="MANUAL"] td {{
            border-left: 4px solid rgba(245,158,11,0.75);
        }}

        /* ✅ NEW CLICKABLE IOS VERSION */
        .ios-click {{
            cursor: pointer;
            text-decoration: underline;
            color: #93c5fd;
            font-weight: 900;
        }}
    </style>
</head>

<body>
    <div class="wrap">

        <div class="header">
            <div class="title-area">
                <h1>✅ CIS Audit Report</h1>
                <div class="sub"><b>Generated:</b> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</div>
            </div>

            <div class="actions">
                <button class="btn" onclick="window.print()">🖨 Print</button>
            </div>
        </div>

        <div class="grid">

            <div class="card span-4">
                <div class="label">Detected Device Type</div>
                <div class="value">{device_type}</div>
                <div class="sub" style="margin-top:8px;color:var(--muted);">Confidence: {confidence_badge}</div>
            </div>

            <div class="card span-4">
                <div class="label">IOS Version (Click to check CIS)</div>
                <div class="value ios-click" onclick="openCIS()">{ios_version}</div>
                <div class="sub" style="margin-top:8px;color:var(--muted); word-break:break-word;">
                    <b>Software:</b> {device_software_info}
                </div>
                <div style="margin-top:12px;">
                    <button class="btn" onclick="openCIS()">🔗 Check Latest CIS Benchmark</button>
                </div>
            </div>

            <div class="card span-4">
                <div class="label">Benchmark Used</div>
                <div class="value mono">{benchmark_used}</div>
            </div>

            <div class="card span-6">
                <div class="label">Summary</div>
                <div class="summaryRow">
                    <div class="kpi">
                        <div class="label">Total Checks</div>
                        <div class="big">{total_count}</div>
                    </div>
                    <div class="kpi">
                        <div class="label">PASS</div>
                        <div class="big" style="color:#86efac;">{pass_count}</div>
                    </div>
                    <div class="kpi">
                        <div class="label">FAIL</div>
                        <div class="big" style="color:#fca5a5;">{fail_count}</div>
                    </div>
                    <div class="kpi">
                        <div class="label">MANUAL</div>
                        <div class="big" style="color:#fde68a;">{manual_count}</div>
                    </div>
                </div>

                <div class="chips">
                    {indicator_html}
                </div>
            </div>

            <div class="card span-6">
                <div class="label">Detection Scores</div>

                <div class="summaryRow">
                    <div class="kpi">
                        <div class="label">Router Score</div>
                        <div class="big">{scores.get("router_score", 0)}</div>
                    </div>
                    <div class="kpi">
                        <div class="label">Switch Score</div>
                        <div class="big">{scores.get("switch_score", 0)}</div>
                    </div>
                    <div class="kpi">
                        <div class="label">L3 Score</div>
                        <div class="big">{scores.get("l3_score", 0)}</div>
                    </div>
                </div>
            </div>

            <div class="card span-12">
                <div class="label">Search & Filter Findings</div>

                <div class="toolbar">
                    <input id="searchBox" class="search" type="text"
                        placeholder="Search by ID / Section / Title / Evidence..."
                        onkeyup="applyFilters()" />

                    <div class="filters">
                        <button class="filterBtn active" id="btnAll" onclick="setStatusFilter('ALL')">ALL</button>
                        <button class="filterBtn" id="btnPASS" onclick="setStatusFilter('PASS')">PASS</button>
                        <button class="filterBtn" id="btnFAIL" onclick="setStatusFilter('FAIL')">FAIL</button>
                        <button class="filterBtn" id="btnMANUAL" onclick="setStatusFilter('MANUAL')">MANUAL</button>
                    </div>
                </div>

                <div style="margin-top:14px; overflow:auto; border-radius:18px;">
                    <table id="auditTable">
                        <thead>
                            <tr>
                                <th style="min-width:90px;">ID</th>
                                <th style="min-width:160px;">Section</th>
                                <th style="min-width:220px;">Title</th>
                                <th style="min-width:120px;">Status</th>
                                <th style="min-width:110px;">Risk</th>
                                <th style="min-width:160px;">Remark</th>
                                <th style="min-width:350px;">Evidence</th>
                                <th style="min-width:250px;">Recommendation</th>
                            </tr>
                        </thead>
                        <tbody>
                            {rows}
                        </tbody>
                    </table>
                </div>
            </div>

        </div>

    </div>

    <script>
        const CIS_URL = "{cis_benchmark_url}";
        let statusFilter = "ALL";

        function openCIS() {{
            window.open(CIS_URL, "_blank");
        }}

        function setStatusFilter(status) {{
            statusFilter = status;

            document.getElementById("btnAll").classList.remove("active");
            document.getElementById("btnPASS").classList.remove("active");
            document.getElementById("btnFAIL").classList.remove("active");
            document.getElementById("btnMANUAL").classList.remove("active");

            document.getElementById("btn" + status).classList.add("active");
            applyFilters();
        }}

        function applyFilters() {{
            const input = document.getElementById("searchBox").value.toLowerCase();
            const table = document.getElementById("auditTable");
            const trs = table.getElementsByTagName("tr");

            for (let i = 1; i < trs.length; i++) {{
                const row = trs[i];
                const rowText = row.innerText.toLowerCase();
                const rowStatus = row.getAttribute("data-status");

                const matchText = rowText.includes(input);
                const matchStatus = (statusFilter === "ALL") || (rowStatus === statusFilter);

                row.style.display = (matchText && matchStatus) ? "" : "none";
            }}
        }}

        applyFilters();
    </script>

</body>
</html>
"""

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)


# ==============================
# ✅ ROUTES
# ==============================
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        if "configfile" not in request.files:
            flash("No file selected")
            return redirect(request.url)

        file = request.files["configfile"]

        if file.filename == "":
            flash("No file selected")
            return redirect(request.url)

        if not allowed_file(file.filename):
            flash("Only .txt / .cfg / .conf files allowed")
            return redirect(request.url)

        unique_name = str(uuid.uuid4()) + "_" + file.filename
        upload_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_name)
        file.save(upload_path)

        return redirect(url_for("audit", filename=unique_name))

    return render_template("index.html")


@app.route("/audit/<filename>")
def audit(filename):
    upload_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)

    if not os.path.exists(upload_path):
        return "File not found", 404

    cfg = normalize_cfg(read_config(upload_path))

    ios_version = extract_ios_version(cfg)
    device_software_info = extract_device_software_line(cfg)

    device_type, confidence, indicators, scores = detect_device_type(cfg)

    if device_type == "router":
        benchmark_file = ROUTER_JSON
    elif device_type == "switch_l3":
        benchmark_file = SWITCH_L3_JSON
    elif device_type == "switch_l2":
        benchmark_file = SWITCH_L2_JSON
    else:
        benchmark_file = SWITCH_L2_JSON

    cis_benchmark_url = get_cis_benchmark_url(device_type, device_software_info)

    with open(benchmark_file, "r", encoding="utf-8") as f:
        rules = json.load(f)

    results = []
    for rule in rules:
        rid = rule.get("id", "N/A")
        section = rule.get("section", "-")
        title = rule.get("title", "-")
        risk = rule.get("risk", "Medium")
        recommendation = rule.get("recommendation", "-")

        status, remark, evidence = run_rule(cfg, rule)

        results.append({
            "ID": rid,
            "Section": section,
            "Title": title,
            "Status": status,
            "Risk": risk,
            "Remark": remark,
            "Evidence": evidence,
            "Recommendation": recommendation
        })

    df = pd.DataFrame(results)

    base_name = os.path.splitext(filename)[0]
    csv_name = f"{base_name}_{device_type}_Audit_Report.csv"
    html_name = f"{base_name}_{device_type}_Audit_Report.html"

    csv_path = os.path.join(app.config["OUTPUT_FOLDER"], csv_name)
    html_path = os.path.join(app.config["OUTPUT_FOLDER"], html_name)

    df.to_csv(csv_path, index=False)

    generate_report_html(
        df=df,
        filepath=html_path,
        device_type=device_type,
        confidence=confidence,
        indicators=indicators,
        benchmark_used=benchmark_file,
        scores=scores,
        ios_version=ios_version,
        device_software_info=device_software_info,
        cis_benchmark_url=cis_benchmark_url
    )

    summary = df["Status"].value_counts().to_dict()

    return render_template(
        "result.html",
        device_type=device_type,
        confidence=confidence,
        benchmark=benchmark_file,
        indicators=indicators,
        scores=scores,
        ios_version=ios_version,
        device_software_info=device_software_info,
        summary=summary,
        csv_file=csv_name,
        html_file=html_name,
        cis_benchmark_url=cis_benchmark_url
    )


@app.route("/download/<path:filename>")
def download(filename):
    file_path = os.path.join(app.config["OUTPUT_FOLDER"], filename)
    if not os.path.exists(file_path):
        return "Report not found", 404
    return send_file(file_path, as_attachment=True)


@app.route("/view/<path:filename>")
def view(filename):
    file_path = os.path.join(app.config["OUTPUT_FOLDER"], filename)
    if not os.path.exists(file_path):
        return "Report not found", 404

    with open(file_path, "r", encoding="utf-8") as f:
        data = f.read()
    return data


if __name__ == "__main__":
    app.run(debug=True)
