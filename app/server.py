#!/usr/bin/env python3
"""Sitrep reads a checklist tree and serves it.

The process does not score hosts. It counts statuses already stored in
CKLB files and compares a quarter with the previous one.
"""

import getpass
import json
import os
import re
import socket
import struct
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(os.environ.get("CHECKLIST_ROOT", "/data")).resolve()
STATIC = Path(__file__).resolve().parent / "static"
PORT = int(os.environ.get("PORT", "8780"))
QUARTER_DIRS = (
    re.compile(r"(?P<year>\d{4})-q(?P<part>\d+)\Z", re.IGNORECASE),
    re.compile(r"Q(?P<part>\d+)_(?P<year>\d{4})\Z", re.IGNORECASE),
    re.compile(r"(?P<year>\d{4})Q(?P<part>\d+)\Z", re.IGNORECASE),
)
VERSION_RELEASE = re.compile(r"V\s*(\d+)\s*R\s*(\d+)", re.IGNORECASE)
RELEASE_NUMBER = re.compile(r"Release:\s*(\d+)", re.IGNORECASE)
VERSION_NUMBER = re.compile(r"V?\s*(\d+)\Z", re.IGNORECASE)
DBUS_SOCKETS = ("/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket")
NOT_A_DOMAIN = {"", ".", "local", "localdomain", "localhost"}

BENCHMARK_NAMES = {
    "RHEL_10_STIG": "RHEL 10",
    "RHEL_9_STIG": "RHEL 9",
    "RHEL_8_STIG": "RHEL 8",
    "RHEL_7_STIG": "RHEL 7",
    "Cisco_IOS_XE_Switch_L2S_STIG": "IOS-XE L2S",
    "Cisco_IOS_XE_Switch_NDM_STIG": "IOS-XE NDM",
    "Cisco_IOS_Switch_L2S_STIG": "IOS L2S",
    "Cisco_NX-OS_Switch_L2S_STIG": "NX-OS L2S",
}

SITE_FACT = ("banner", "organization-defined", "site fact", "approved")


def one_line(value, limit):
    text = " ".join((value or "").split())
    if not text or any(ord(ch) < 32 for ch in text):
        return ""
    return text[:limit]


def one_user(value):
    text = (value or "").strip()
    if not text or any(ch.isspace() or ord(ch) < 32 or ch in "/\\" for ch in text):
        return ""
    return text[:64]


def view_date():
    now = datetime.now().astimezone()
    return f"{now.strftime('%b')} {now.day}, {now.year}"


def seat_user():
    seat = Path("/run/systemd/seats/seat0")
    if not seat.is_file():
        return ""
    uid = ""
    for line in seat.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("ACTIVE_UID="):
            uid = line.split("=", 1)[1].strip()
    if not uid.isdigit():
        return ""
    record = Path("/run/systemd/users") / uid
    if not record.is_file():
        return ""
    for line in record.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("NAME="):
            return one_user(line.split("=", 1)[1])
    return ""


def viewer_name(headers):
    for key in ("Remote-User", "X-Forwarded-User"):
        found = one_user(headers.get(key))
        if found:
            return found
    found = seat_user()
    if found:
        return found
    for key in ("CHECKLIST_USER", "SUDO_USER", "USER", "LOGNAME"):
        found = one_user(os.environ.get(key, ""))
        if found and found != "root":
            return found
    try:
        found = one_user(getpass.getuser())
    except OSError:
        found = ""
    if found and found != "root":
        return found
    return ""


def resolv_domain():
    names = []
    for candidate in (Path("/etc/resolv.conf"), Path("/run/NetworkManager/resolv.conf")):
        if not candidate.is_file():
            continue
        for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] in ("domain", "search"):
                names.extend(parts[1:])
    for name in names:
        domain = name.strip().rstrip(".")
        if "." in domain and domain.lower() not in NOT_A_DOMAIN:
            return domain
    fqdn = socket.getfqdn()
    if "." in fqdn:
        suffix = fqdn.split(".", 1)[1].rstrip(".")
        if "." in suffix and suffix.lower() not in NOT_A_DOMAIN:
            return suffix
    return ""


def _dbus_pad(buf, alignment):
    extra = (-len(buf)) % alignment
    if extra:
        buf.extend(b"\0" * extra)


def _dbus_string(buf, text):
    _dbus_pad(buf, 4)
    raw = text.encode("utf-8")
    buf.extend(struct.pack("<I", len(raw)))
    buf.extend(raw)
    buf.append(0)


def _dbus_signature(buf, signature):
    raw = signature.encode("ascii")
    buf.append(len(raw))
    buf.extend(raw)
    buf.append(0)


def _dbus_message(serial, destination, path, interface, member, signature, args):
    fields = bytearray()
    parts = (
        (1, "o", path),
        (6, "s", destination),
        (2, "s", interface),
        (3, "s", member),
    )
    if signature:
        parts = parts + ((8, "g", signature),)
    for code, kind, value in parts:
        _dbus_pad(fields, 8)
        fields.append(code)
        _dbus_signature(fields, kind)
        if kind == "g":
            _dbus_signature(fields, value)
        else:
            _dbus_string(fields, value)
    body = bytearray()
    for arg in args:
        _dbus_string(body, arg)
    message = bytearray(b"l")
    message.extend((1, 0, 1))
    message.extend(struct.pack("<III", len(body), serial, len(fields)))
    message.extend(fields)
    _dbus_pad(message, 8)
    message.extend(body)
    return bytes(message)


def _recv_exact(sock, size, pending):
    buf = bytearray(pending)
    while len(buf) < size:
        chunk = sock.recv(size - len(buf))
        if not chunk:
            raise OSError("system bus closed")
        buf.extend(chunk)
    return bytes(buf[:size]), bytes(buf[size:])


def _dbus_read(sock, pending):
    head, pending = _recv_exact(sock, 16, pending)
    body_len, _serial, fields_len = struct.unpack_from("<III", head, 4)
    _fields, pending = _recv_exact(sock, fields_len, pending)
    pad = (-(16 + fields_len)) % 8
    if pad:
        _padding, pending = _recv_exact(sock, pad, pending)
    body, pending = _recv_exact(sock, body_len, pending)
    return head[1], body, 16 + fields_len + pad, pending


def _at(offset, alignment):
    return (offset + alignment - 1) & ~(alignment - 1)


def _read_signature(blob, offset):
    length = blob[offset]
    offset += 1
    signature = blob[offset:offset + length].decode("ascii")
    return signature, offset + length + 1


def _read_string(blob, offset):
    offset = _at(offset, 4)
    length = struct.unpack_from("<I", blob, offset)[0]
    offset += 4
    text = blob[offset:offset + length].decode("utf-8")
    return text, offset + length + 1


def _read_string_dict(blob, offset):
    offset = _at(offset, 4)
    nbytes = struct.unpack_from("<I", blob, offset)[0]
    offset += 4
    offset = _at(offset, 8)
    end = offset + nbytes
    found = {}
    while offset + 8 <= end:
        offset = _at(offset, 8)
        key, offset = _read_string(blob, offset)
        signature, offset = _read_signature(blob, offset)
        if signature != "s":
            break
        value, offset = _read_string(blob, offset)
        found[key] = value
    return found


def _variant_value(body, body_offset):
    blob = b"\0" * body_offset + body
    signature, offset = _read_signature(blob, body_offset)
    if signature in ("s", "o"):
        text, _offset = _read_string(blob, offset)
        return text
    if signature == "a{sv}":
        return _read_string_dict(blob, offset)
    return ""


class SystemBus:
    def __init__(self):
        self.sock = None
        self.pending = b""
        self.serial = 0
        last = None
        for path in DBUS_SOCKETS:
            if not os.path.exists(path):
                continue
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(1)
            try:
                sock.connect(path)
                token = str(os.getuid()).encode("ascii").hex().encode("ascii")
                sock.sendall(b"\0AUTH EXTERNAL " + token + b"\r\n")
                data = b""
                while b"\r\n" not in data:
                    data += sock.recv(256)
                line, _, rest = data.partition(b"\r\n")
                if not line.startswith(b"OK"):
                    sock.close()
                    last = OSError(line.decode("ascii", "replace"))
                    continue
                sock.sendall(b"BEGIN\r\n")
                self.sock = sock
                self.pending = rest
                self.call(
                    "org.freedesktop.DBus",
                    "/org/freedesktop/DBus",
                    "org.freedesktop.DBus",
                    "Hello",
                    "",
                    [],
                )
                return
            except OSError as exc:
                last = exc
                sock.close()
        raise OSError(last or "system bus is not available")

    def call(self, destination, path, interface, member, signature, args):
        self.serial += 1
        self.sock.sendall(_dbus_message(
            self.serial, destination, path, interface, member, signature, args,
        ))
        while True:
            kind, body, body_offset, self.pending = _dbus_read(self.sock, self.pending)
            if kind == 3:
                raise OSError("system bus call failed")
            if kind == 2:
                return body, body_offset

    def get(self, path, interface, name):
        body, body_offset = self.call(
            "org.freedesktop.NetworkManager",
            path,
            "org.freedesktop.DBus.Properties",
            "Get",
            "ss",
            [interface, name],
        )
        return _variant_value(body, body_offset)

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None


def connection_facts():
    bus = SystemBus()
    try:
        path = bus.get(
            "/org/freedesktop/NetworkManager",
            "org.freedesktop.NetworkManager",
            "PrimaryConnection",
        )
        if not isinstance(path, str) or path in ("", "/"):
            return "", ""
        name = bus.get(path, "org.freedesktop.NetworkManager.Connection.Active", "Id")
        if not isinstance(name, str):
            name = ""
        dhcp = bus.get(path, "org.freedesktop.NetworkManager.Connection.Active", "Dhcp4Config")
        domain = ""
        if isinstance(dhcp, str) and dhcp not in ("", "/"):
            options = bus.get(dhcp, "org.freedesktop.NetworkManager.DHCP4Config", "Options")
            if isinstance(options, dict):
                domain = options.get("domain_name") or options.get("domain_search") or ""
        return one_line(domain, 80), one_line(name, 80)
    finally:
        bus.close()


def network_name():
    chosen = one_line(os.environ.get("CHECKLIST_DOMAIN", ""), 80)
    if chosen:
        return chosen
    try:
        domain, name = connection_facts()
    except OSError:
        domain, name = "", ""
    if domain:
        first = domain.split()[0].rstrip(".")
        if "." in first and first.lower() not in NOT_A_DOMAIN:
            return first
    found = ""
    try:
        found = one_line(resolv_domain(), 80)
    except OSError:
        found = ""
    if found:
        return found
    if name:
        return name
    host = socket.gethostname().split(".", 1)[0]
    if host and host.lower() not in NOT_A_DOMAIN:
        return host
    return "This network"


def session_for(headers):
    return {
        "domain": network_name(),
        "date": view_date(),
        "user": viewer_name(headers),
    }


def quarter_label(quarter):
    if not quarter:
        return "Undated"
    year, part = quarter.split("-q", 1)
    return f"{year} Q{part}"


def quarter_key(quarter):
    if not quarter or "-q" not in quarter:
        return 0, 0
    year, part = quarter.split("-q", 1)
    return int(year), int(part)


def quarter_from_path(path):
    found = ""
    for part in path.relative_to(ROOT).parts[:-1]:
        for pattern in QUARTER_DIRS:
            match = pattern.fullmatch(part)
            if match:
                found = f"{int(match.group('year'))}-q{int(match.group('part'))}"
    return found


def host_from_path(path, target_host):
    host = (target_host or "").strip()
    if host:
        return host
    parent = path.parent.name
    if parent and parent != ROOT.name and not parent.endswith("_STIG") and not any(pattern.fullmatch(parent) for pattern in QUARTER_DIRS):
        return parent
    return path.stem


def os_for(benchmark_id, fallback):
    match = re.fullmatch(r"RHEL_(\d+)_STIG", benchmark_id or "")
    if match:
        return f"RHEL {match.group(1)}"
    ident = benchmark_id or ""
    if "IOS-XE" in ident or "IOS_XE" in ident:
        return "IOS-XE"
    if "IOS-XR" in ident or "IOS_XR" in ident:
        return "IOS-XR"
    if "NX-OS" in ident or "NX_OS" in ident:
        return "NX-OS"
    if ident.startswith("Cisco_IOS"):
        return "IOS"
    if ident.startswith("Cisco_ASA"):
        return "ASA"
    return fallback


def iter_cklb(root):
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [name for name in dirnames if not name.startswith(".")]
        for name in sorted(filenames):
            if name.startswith(".") or not name.endswith(".cklb"):
                continue
            yield Path(dirpath) / name


def version_release(text):
    match = VERSION_RELEASE.search(text or "")
    if not match:
        return ""
    return f"V{int(match.group(1))}R{int(match.group(2))}"


def release_from_stig(stig):
    info = stig.get("release_info") or ""
    explicit = version_release(info)
    if explicit:
        return explicit
    version = VERSION_NUMBER.fullmatch(str(stig.get("version") or stig.get("stig_version") or "").strip())
    release = RELEASE_NUMBER.search(info)
    if version and release:
        return f"V{int(version.group(1))}R{int(release.group(1))}"
    return ""


def release_from_sidecar(path):
    sidecar = Path(str(path) + ".provenance.json")
    if not sidecar.is_file():
        return ""
    try:
        document = json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ""
    benchmark = document.get("benchmark") or {}
    return version_release(str(benchmark.get("path") or ""))


def labeled_benchmark(name, release):
    if release:
        return f"{name} {release}"
    return name


def load_cklb(path):
    document = json.loads(path.read_text(encoding="utf-8"))
    stig = document["stigs"][0]
    target = document.get("target_data") or {}
    release = release_from_stig(stig) or release_from_sidecar(path)
    rules = []
    for rule in stig.get("rules") or []:
        rules.append({
            "group": rule.get("group_id") or "",
            "severity": (rule.get("severity") or "").lower(),
            "status": rule.get("status") or "",
            "comment": (rule.get("comments") or "").strip(),
            "check": (rule.get("check_content") or "").strip(),
            "title": rule.get("rule_title") or "",
        })
    return {
        "benchmark_id": stig.get("stig_id") or "",
        "benchmark": BENCHMARK_NAMES.get(stig.get("stig_id"), stig.get("stig_name") or stig.get("stig_id") or ""),
        "release": release,
        "size": stig.get("size"),
        "host": host_from_path(path, target.get("host_name")),
        "fqdn": target.get("fqdn") or "",
        "ip": target.get("ip_address") or "",
        "role": target.get("role") or "",
        "note": (target.get("comments") or "").strip(),
        "rules": rules,
        "path": str(path.relative_to(ROOT)),
    }


def discover():
    found = {}
    if not ROOT.is_dir():
        return found
    for path in iter_cklb(ROOT):
        try:
            loaded = load_cklb(path)
        except (OSError, json.JSONDecodeError, KeyError, IndexError, TypeError, ValueError):
            print(f"sitrep: skipped {path}", flush=True)
            continue
        quarter = quarter_from_path(path)
        key = (quarter, loaded["host"], loaded["benchmark_id"])
        modified = path.stat().st_mtime
        current = found.get(key)
        if current is None or modified >= current[0]:
            found[key] = (modified, loaded)
    return {key: item[1] for key, item in found.items()}


def expected_rows():
    path = ROOT / "expected.json"
    if not path.is_file():
        return []
    document = json.loads(path.read_text(encoding="utf-8"))
    rows = []
    for quarter, items in document.items():
        for item in items:
            rows.append({
                "quarter": quarter,
                "host": item["host"],
                "benchmark_id": item["benchmark_id"],
                "os": item.get("os") or "",
                "release": version_release(item.get("release") or ""),
            })
    return rows


def counts(rules):
    tally = {"open": 0, "not_reviewed": 0, "not_applicable": 0, "not_a_finding": 0}
    cat1 = 0
    for rule in rules:
        status = rule["status"]
        if status in tally:
            tally[status] += 1
        if status == "open" and rule["severity"] == "high":
            cat1 += 1
    return tally, cat1


def blocked_reason(loaded):
    if loaded["size"] not in (None, len(loaded["rules"])):
        return "Rule count does not match the checklist size."
    if any(not rule["check"] for rule in loaded["rules"]):
        return "Check text is empty on at least one rule."
    note = loaded["note"].lower()
    if "no closing end" in note or "incomplete" in note:
        return loaded["note"]
    if not loaded["ip"]:
        return "Target page has no IP."
    return ""


def highlights(current, previous):
    lines = []
    if current is None:
        if previous is None:
            lines.append("No checklist in this tree.")
        else:
            lines.append(f"Checklist was present in {quarter_label(previous['quarter'])} and is absent from this quarter.")
        return lines
    reason = blocked_reason(current)
    if reason:
        lines.append(f"Blocked: {reason}")
    if previous is not None:
        prior = {rule["group"]: rule for rule in previous["rules"]}
        changes = []
        for rule in current["rules"]:
            old = prior.get(rule["group"])
            if old and old["status"] != rule["status"]:
                changes.append(rule | {"old": old["status"]})
        for rule in changes[:6]:
            lines.append(
                f"Changed: {rule['group']} moved from {words(rule['old'])} to {words(rule['status'])}. {rule['comment']}"
            )
    cat1 = [rule for rule in current["rules"] if rule["status"] == "open" and rule["severity"] == "high"]
    for rule in cat1[:4]:
        lines.append(f"CAT I open: {rule['group']}. {rule['comment']}")
    facts = [
        rule for rule in current["rules"]
        if rule["status"] == "not_reviewed" and any(word in rule["comment"].lower() for word in SITE_FACT)
    ]
    for rule in facts[:3]:
        lines.append(f"Needs a site fact: {rule['group']}. {rule['comment']}")
    if not lines:
        lines.append("No status changes, CAT I opens, or site facts on this checklist.")
    return lines


def words(status):
    return {
        "open": "Open",
        "not_a_finding": "Not a finding",
        "not_reviewed": "Not reviewed",
        "not_applicable": "Not applicable",
    }.get(status, status)


def changed_count(current, previous):
    if current is None or previous is None:
        return None
    prior = {rule["group"]: rule["status"] for rule in previous["rules"]}
    return sum(1 for rule in current["rules"] if prior.get(rule["group"], rule["status"]) != rule["status"])


def posture():
    found = discover()
    watched = expected_rows()
    quarters = sorted({key[0] for key in found} | {row["quarter"] for row in watched}, key=quarter_key)
    dated = [quarter for quarter in quarters if quarter]
    previous_of = {quarter: dated[index - 1] if index else None for index, quarter in enumerate(dated)}
    slots = {}
    for row in watched:
        slots[(row["quarter"], row["host"], row["benchmark_id"])] = row
    for key, loaded in found.items():
        slots.setdefault(key, {
            "quarter": key[0],
            "host": loaded["host"],
            "benchmark_id": loaded["benchmark_id"],
            "os": "",
            "release": loaded["release"],
        })
    records = []
    def listing_order(item):
        year, part = quarter_key(item[0][0])
        return (-year, -part, item[0][1], item[0][2])

    for key, slot in sorted(slots.items(), key=listing_order):
        quarter, host, benchmark_id = key
        loaded = found.get(key)
        previous = None
        prior_quarter = previous_of.get(quarter)
        if prior_quarter:
            previous_loaded = found.get((prior_quarter, host, benchmark_id))
            if previous_loaded:
                previous = previous_loaded | {"quarter": prior_quarter}
        benchmark = BENCHMARK_NAMES.get(benchmark_id, loaded["benchmark"] if loaded else benchmark_id)
        os_name = slot.get("os") or os_for(benchmark_id, benchmark)
        release = (loaded["release"] if loaded else "") or slot.get("release") or ""
        benchmark_label = labeled_benchmark(benchmark, release)
        if loaded is None:
            records.append({
                "id": "|".join(key),
                "host": host,
                "quarter": quarter_label(quarter),
                "quarter_id": quarter,
                "benchmark": benchmark,
                "benchmark_label": benchmark_label,
                "benchmark_id": benchmark_id,
                "release": release,
                "os": os_name,
                "handoff": "Missing",
                "open": None,
                "cat1": None,
                "not_reviewed": None,
                "not_applicable": None,
                "not_a_finding": None,
                "changed": None,
                "path": "",
                "identity": "",
                "lines": highlights(None, previous),
            })
            continue
        tally, cat1 = counts(loaded["rules"])
        reason = blocked_reason(loaded)
        identity = " · ".join(part for part in (loaded["fqdn"], loaded["ip"], loaded["role"]) if part)
        records.append({
            "id": "|".join(key),
            "host": host,
            "quarter": quarter_label(quarter),
            "quarter_id": quarter,
            "benchmark": benchmark,
            "benchmark_label": benchmark_label,
            "benchmark_id": benchmark_id,
            "release": release,
            "os": os_name,
            "handoff": "Blocked" if reason else "Ready",
            "open": tally["open"],
            "cat1": cat1,
            "not_reviewed": tally["not_reviewed"],
            "not_applicable": tally["not_applicable"],
            "not_a_finding": tally["not_a_finding"],
            "changed": changed_count(loaded, previous),
            "path": loaded["path"],
            "identity": identity,
            "lines": highlights(loaded, previous),
        })
    return {"root": str(ROOT), "rows": records}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/posture":
            body = json.dumps(posture()).encode("utf-8")
            self.respond(200, "application/json; charset=utf-8", body)
            return
        if path == "/api/health":
            self.respond(200, "application/json", b'{"ok":true}')
            return
        if path == "/api/session":
            body = json.dumps(session_for(self.headers)).encode("utf-8")
            self.respond(200, "application/json; charset=utf-8", body)
            return
        if path in ("/", "/index.html"):
            self.respond(200, "text/html; charset=utf-8", (STATIC / "index.html").read_bytes())
            return
        self.respond(404, "text/plain; charset=utf-8", b"Not found\n")

    def respond(self, status, content_type, body):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.address_string(), fmt % args), flush=True)


def main():
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print(f"sitrep reading {ROOT} on {PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
