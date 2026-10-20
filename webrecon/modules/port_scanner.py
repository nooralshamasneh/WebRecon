"""Port and service detection: nmap (XML) with a TCP-connect fallback. Always scans the pinned IP."""
import concurrent.futures
import os
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 3306, 3389, 5432,
                6379, 8080, 8443, 9200, 11211, 27017]


def get_nmap_path():
    found = shutil.which("nmap")
    if found:
        return found
    for path in (r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"):
        if os.path.exists(path):
            return path
    return None


def _connect(ip, port):
    try:
        with socket.create_connection((ip, port), timeout=1):
            return port
    except OSError:
        return None


def socket_scan(ip, ports=COMMON_PORTS):
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
        return sorted(p for p in pool.map(lambda p: _connect(ip, p), ports) if p)


def parse_nmap_xml(xml_text):
    root = ET.fromstring(xml_text)
    services = []
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        attrs = svc.attrib if svc is not None else {}
        cpes = [c.text for c in svc.findall("cpe") if c.text] if svc is not None else []
        services.append({"port": int(port.get("portid")), "protocol": port.get("protocol", "tcp"),
                         "service": attrs.get("name", ""), "product": attrs.get("product", ""),
                         "version": attrs.get("version", ""), "extrainfo": attrs.get("extrainfo", ""),
                         "cpe": cpes})
    services.sort(key=lambda s: s["port"])
    return services


def format_services(services):
    lines = ["PORT      SERVICE        VERSION"]
    for s in services:
        ver = " ".join(x for x in (s["product"], s["version"], s["extrainfo"]) if x)
        lines.append(f"{s['port']}/{s['protocol']:<4}  {s['service']:<13}  {ver}".rstrip())
    return "\n".join(lines)


def scan(ip, timeout=240):
    """Scan a pre-validated, pinned IP address (never a hostname: nmap must not re-resolve)."""
    nmap = get_nmap_path()
    if not nmap:
        ports = socket_scan(ip)
        return {"tool": "socket", "open_ports": ports, "services": [{"port": p, "protocol": "tcp", "service": "",
                "product": "", "version": "", "extrainfo": "", "cpe": []} for p in ports],
                "text": "nmap not installed: TCP connect scan of common ports only (no version detection)."}
    cmd = [nmap, "-sV", "-T4", "--max-retries", "1", "--host-timeout", "180s", "-oX", "-"]
    if ":" in ip:
        cmd.append("-6")
    cmd += ["--", ip]  # list form, no shell; "--" ends option parsing
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        services = parse_nmap_xml(proc.stdout)
        return {"tool": "nmap", "open_ports": [s["port"] for s in services], "services": services,
                "text": format_services(services) if services else "No open ports found by nmap."}
    except (subprocess.TimeoutExpired, ET.ParseError, OSError) as exc:
        ports = socket_scan(ip)
        return {"tool": "socket", "open_ports": ports, "services": [{"port": p, "protocol": "tcp", "service": "",
                "product": "", "version": "", "extrainfo": "", "cpe": []} for p in ports],
                "text": f"nmap failed ({type(exc).__name__}); fell back to a TCP connect scan."}


PORT_FINDINGS = {23: "WR-PORT-001", 21: "WR-PORT-002", 445: "WR-PORT-003", 139: "WR-PORT-003", 3389: "WR-PORT-003",
                 1433: "WR-PORT-004", 3306: "WR-PORT-004", 5432: "WR-PORT-004", 6379: "WR-PORT-004",
                 9200: "WR-PORT-004", 11211: "WR-PORT-004", 27017: "WR-PORT-004", 110: "WR-PORT-005",
                 143: "WR-PORT-005"}


def port_findings(open_ports):
    from ..findings import make
    grouped = {}
    for port in open_ports:
        if port in PORT_FINDINGS:
            grouped.setdefault(PORT_FINDINGS[port], []).append(port)
    return [make(fid, evidence=[f"Port {p} open" for p in sorted(ports)]) for fid, ports in grouped.items()]
