# modules/port_scanner.py
import concurrent.futures
import os
import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 27017]


def get_nmap_path():
    found = shutil.which("nmap")
    if found:
        return found
    for path in (r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"):
        if os.path.exists(path):
            return path
    return None


def _connect(host, port):
    try:
        with socket.create_connection((host, port), timeout=1):
            return port
    except OSError:
        return None


def _socket_scan(host, ports=COMMON_PORTS):
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as pool:
        return sorted(p for p in pool.map(lambda p: _connect(host, p), ports) if p)


def _parse_nmap_xml(xml_text):
    root = ET.fromstring(xml_text)
    open_ports, services, lines = [], [], []
    for port in root.iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        portid = int(port.get("portid"))
        proto = port.get("protocol", "tcp")
        svc = port.find("service")
        name = svc.get("name", "") if svc is not None else ""
        product = svc.get("product", "") if svc is not None else ""
        version = svc.get("version", "") if svc is not None else ""
        open_ports.append(portid)
        services.append({"port": portid, "protocol": proto, "service": name,
                         "product": product, "version": version})
        lines.append(f"{portid}/{proto:<4} open  {name:<12} {product} {version}".rstrip())
    header = "PORT      STATE SERVICE      VERSION"
    return sorted(open_ports), services, "\n".join([header] + lines) if lines else ""


def scan(target, timeout=240):
    """Scan a (pre-validated) host. Returns open_ports, services and printable service_info."""
    nmap = get_nmap_path()
    if not nmap:
        return {"open_ports": _socket_scan(target), "services": [],
                "service_info": "nmap not installed: basic TCP connect scan only (no version detection)."}

    cmd = [nmap, "-sV", "-T4", "--max-retries", "1", "--host-timeout", "180s", "-oX", "-"]
    if ":" in target:
        cmd.append("-6")
    cmd += ["--", target]  # "--" stops nmap from treating the target as an option

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        ports, services, text = _parse_nmap_xml(proc.stdout)
        return {"open_ports": ports, "services": services,
                "service_info": text or "No open ports found by nmap."}
    except (subprocess.TimeoutExpired, ET.ParseError, OSError) as exc:
        return {"open_ports": _socket_scan(target), "services": [],
                "service_info": f"nmap failed ({type(exc).__name__}); fell back to basic TCP connect scan."}