import re
import csv
import base64
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

# --- CONFIG ---
CSV_FILENAME = "IP_score.csv"
LOG_FILENAME = "logs.txt"
OUTPUT_FILENAME = "enriched_ips_extended.csv"

# --- REGEX PATTERNS ---
IP_REGEX = re.compile(r"\('([\d\.]+)',\s*\d+\)")
TIMESTAMP_REGEX = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)")
PAYLOAD_REGEX = re.compile(rb">> b'(.*)'")
MAIL_FROM_REGEX = re.compile(rb"MAIL FROM:<([^>]+)>", re.IGNORECASE)
RCPT_TO_REGEX = re.compile(rb"RCPT TO:<([^>]+)>", re.IGNORECASE)
EHLO_HELO_REGEX = re.compile(rb'\b(EHLO|HELO)\s+([^\s\r\n]+)', re.IGNORECASE)
HTTP_VERB_REGEX = re.compile(rb'\b(GET|POST|HEAD|OPTIONS|PUT|DELETE)\b')
HOST_HEADER_REGEX = re.compile(rb'Host:\s*(\S+)', re.IGNORECASE)
UA_HEADER_REGEX = re.compile(rb'User-Agent:\s*(.+)', re.IGNORECASE)
MGLNDD_REGEX = re.compile(rb'MGLNDD_[\d\.]+_\d+')
BYTECODE_REGEX = re.compile(rb'\\x[0-9A-Fa-f]{2}')
JSON_REGEX = re.compile(rb'^\{.*\}$')
STARTTLS_REGEX = re.compile(rb'STARTTLS', re.IGNORECASE)
AUTH_LOGIN_REGEX = re.compile(rb'AUTH LOGIN', re.IGNORECASE)
AUTH_NTLM_REGEX = re.compile(rb'AUTH NTLM', re.IGNORECASE)

# --- HELPERS ---


def extract_domain(addr: str) -> str:
    match = re.search(r'@([A-Za-z0-9.-]+\.[A-Za-z]{2,})', addr)
    return match.group(1) if match else ""


def safe_b64decode(s: str) -> str:
    try:
        decoded = base64.b64decode(s).decode("utf-8", errors="ignore")
        if decoded and all(32 <= ord(c) <= 126 for c in decoded):
            return decoded
    except Exception:
        pass
    return None


# --- LOAD CSV ---
base = Path(__file__).resolve().parent
csv_path = base / CSV_FILENAME
log_path = base / LOG_FILENAME
if not csv_path.exists() or not log_path.exists():
    raise SystemExit("CSV or log file not found.")

with open(csv_path, newline="", encoding="utf-8") as f:
    reader = csv.DictReader(f)
    ip_rows = list(reader)
    original_headers = reader.fieldnames

# --- INIT DATA STRUCTURE ---
data_map = defaultdict(lambda: defaultdict(set))
timestamps = defaultdict(list)
auth_login_pending = {}

# --- PROCESS LOGS ---
with open(log_path, "rb") as f:
    for line in f:
        try:
            line_str = line.decode(errors="ignore").strip()
        except:
            continue

        # Timestamp
        ts_match = re.match(
            r"\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)", line_str)
        ts = None
        if ts_match:
            ts = ts_match.group(1)
            try:
                ts_dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S,%f")
            except ValueError:
                ts_dt = None
        else:
            ts_dt = None

        # IP
        ip_match = IP_REGEX.search(line_str)
        if not ip_match:
            continue
        ip = ip_match.group(1)
        if ts_dt:
            timestamps[ip].append(ts_dt)

        # Payload
        payload_match = PAYLOAD_REGEX.search(line)
        if not payload_match:
            continue
        payload_bytes = payload_match.group(1)
        payload_str = payload_bytes.decode(errors="ignore")

        # --- MAIL FROM ---
        for m in MAIL_FROM_REGEX.findall(payload_bytes):
            raw = m.decode(errors="ignore").strip()
            data_map[ip]["MailFromRaw"].add(raw)
            dom = extract_domain(raw)
            if dom:
                data_map[ip]["MailFromDomain"].add(dom)

        # --- RCPT TO ---
        for r in RCPT_TO_REGEX.findall(payload_bytes):
            raw = r.decode(errors="ignore").strip()
            data_map[ip]["RCPT_Raw"].add(raw)
            dom = extract_domain(raw)
            if dom:
                data_map[ip]["RCPT_Domain"].add(dom)

        # --- EHLO/HELO ---
        for e in EHLO_HELO_REGEX.findall(payload_bytes):
            data_map[ip]["EHLO_HELO"].add(e[0].decode())
            data_map[ip]["EHLO_HELO_Value"].add(e[1].decode())

        # --- HTTP ---
        if HTTP_VERB_REGEX.search(payload_bytes):
            data_map[ip]["HTTP_Used"].add("1")
            h = HOST_HEADER_REGEX.search(payload_bytes)
            ua = UA_HEADER_REGEX.search(payload_bytes)
            if h:
                data_map[ip]["HTTP_Host"].add(h.group(1).decode().strip())
            if ua:
                data_map[ip]["UserAgent"].add(ua.group(1).decode().strip())

        # --- MGLNDD ---
        if MGLNDD_REGEX.search(payload_bytes):
            data_map[ip]["MGLNDD_Used"].add("1")
            data_map[ip]["MGLNDD_Raw"].add(payload_str)

        # --- BYTECODE ---
        if BYTECODE_REGEX.search(payload_bytes):
            data_map[ip]["ByteCode_Used"].add("1")
            data_map[ip]["ByteCode_Raw"].add(payload_str)

        # --- JSON ---
        if JSON_REGEX.match(payload_bytes.strip()):
            try:
                parsed = json.loads(payload_bytes.decode(errors="ignore"))
                data_map[ip]["JSON_Used"].add("1")
                data_map[ip]["JSON_Raw"].add(json.dumps(parsed))
            except:
                pass

        # --- STARTTLS ---
        if STARTTLS_REGEX.search(payload_bytes):
            data_map[ip]["STARTTLS_Used"].add("1")

        # --- AUTH NTLM ---
        if AUTH_NTLM_REGEX.search(payload_bytes):
            data_map[ip]["AUTH_NTLM_Used"].add("1")

        # --- AUTH LOGIN ---
        if AUTH_LOGIN_REGEX.search(payload_bytes):
            data_map[ip]["AUTH_LOGIN_Used"].add("1")
            auth_login_pending[ip] = 2
        elif auth_login_pending.get(ip, 0) > 0:
            decoded = safe_b64decode(payload_str)
            if decoded:
                data_map[ip]["AUTH_LOGIN_Decoded"].add(decoded)
                auth_login_pending[ip] -= 1
                if auth_login_pending[ip] <= 0:
                    del auth_login_pending[ip]

# --- WRITE ENRICHED CSV ---
extra_fields = [
    "MailFromRaw", "MailFromDomain",
    "RCPT_Raw", "RCPT_Domain",
    "EHLO_HELO", "EHLO_HELO_Value",
    "HTTP_Used", "HTTP_Host", "UserAgent",
    "MGLNDD_Used", "MGLNDD_Raw",
    "ByteCode_Used", "ByteCode_Raw",
    "JSON_Used", "JSON_Raw",
    "STARTTLS_Used",
    "AUTH_LOGIN_Used", "AUTH_LOGIN_Decoded",
    "AUTH_NTLM_Used",
    "Earliest_Timestamp", "Latest_Timestamp"
]

with open(base / OUTPUT_FILENAME, "w", newline="", encoding="utf-8") as f:
    writer = csv.DictWriter(f, fieldnames=original_headers + extra_fields)
    writer.writeheader()
    for row in ip_rows:
        ip = row.get("IP Address", "").strip()
        d = data_map.get(ip, {})
        # row["Earliest_Timestamp"] = min(timestamps[ip]).strftime(
        #     "%Y-%m-%d %H:%M:%S") if timestamps.get(ip) else ""
        # row["Latest_Timestamp"] = max(timestamps[ip]).strftime(
        #     "%Y-%m-%d %H:%M:%S") if timestamps.get(ip) else ""

for field in extra_fields:
    row[field] = ", ".join(
        sorted(d.get(field, []))) if d.get(field) else ""
row["Earliest_Timestamp"] = min(timestamps[ip]).strftime(
    "%Y-%m-%d %H:%M:%S") if timestamps.get(ip) else ""
row["Latest_Timestamp"] = max(timestamps[ip]).strftime(
    "%Y-%m-%d %H:%M:%S") if timestamps.get(ip) else ""
writer.writerow(row)
print(f"[+] Enriched CSV written to {OUTPUT_FILENAME}")
