import asyncio
import socket
import struct
import subprocess
import sys
import time
import json
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
from typing import List, Dict, Tuple, Optional, Set
import re
import argparse
import csv
import struct as _struct

def run_cmd(cmd: List[str], timeout: int = 10) -> Optional[str]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False)
        if p.returncode == 0:
            return p.stdout.decode(errors="ignore")
        return None
    except Exception:
        return None

def get_termux_wifi_info() -> Dict:
    out = run_cmd(["termux-wifi-connectioninfo"])
    if not out:
        return {}
    try:
        return json.loads(out)
    except Exception:
        return {}

def get_termux_location() -> Dict:
    out = run_cmd(["termux-location", "--provider", "gps", "--request", "once"])
    if not out:
        out = run_cmd(["termux-location", "--provider", "network", "--request", "once"])
    if not out:
        return {}
    try:
        return json.loads(out)
    except Exception:
        return {}

def get_default_interface() -> Optional[str]:
    out = run_cmd(["ip", "route"])
    if not out:
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0] == "default":
            for i, v in enumerate(parts):
                if v == "dev" and i + 1 < len(parts):
                    return parts[i + 1]
    return None

async def ping_ip(ip: str, timeout_ms: int = 800) -> bool:
    try:
        if sys.platform.startswith("win"):
            proc = await asyncio.create_subprocess_exec(
                "ping", "-n", "1", "-w", str(timeout_ms), ip,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", str(max(1, int(timeout_ms/1000))), ip,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
        try:
            outs, errs = await asyncio.wait_for(proc.communicate(), timeout=timeout_ms/1000 + 0.5)
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except Exception:
                pass
            return False
        out = (outs or b"").decode(errors="ignore").lower()
        if "ttl=" in out or "bytes=" in out or "1 received" in out:
            return True
        return proc.returncode == 0
    except Exception:
        return False

def dms_to_decimal(d: int, m: int, s: float, hemi: str) -> float:
    val = d + m / 60.0 + s / 3600.0
    if hemi.upper() in ("S", "W"):
        val = -val
    return val

def parse_dms_string(s: str) -> Optional[Tuple[float, float]]:
    s = s.strip()
    pat = re.compile(r'^\s*(\d{1,3})°(\d{1,2})\'(\d{1,2}(?:\.\d+)?)"([NnSs])\s+(\d{1,3})°(\d{1,2})\'(\d{1,2}(?:\.\d+)?)"([EeWw])\s*$')
    m = pat.match(s)
    if m:
        lat = dms_to_decimal(int(m.group(1)), int(m.group(2)), float(m.group(3)), m.group(4))
        lon = dms_to_decimal(int(m.group(5)), int(m.group(6)), float(m.group(7)), m.group(8))
        return lat, lon
    parts = s.replace(",", " ").split()
    if len(parts) >= 2:
        try:
            lat = float(parts[0])
            lon = float(parts[1])
            return lat, lon
        except Exception:
            return None
    return None

def get_interface_cidr(dev: Optional[str]) -> Optional[str]:
    if sys.platform.startswith("win"):
        out = run_cmd(["ipconfig"])
        if not out:
            return None
        lines = out.splitlines()
        ip = None
        mask = None
        for i, line in enumerate(lines):
            m_ip = re.search(r"IPv4[^:]*:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", line)
            if m_ip:
                cand_ip = m_ip.group(1)
                if cand_ip.startswith("127.") or cand_ip.startswith("0."):
                    continue
                ip = cand_ip
                for j in range(i + 1, min(i + 8, len(lines))):
                    m_mask = re.search(r"Subnet Mask[^:]*:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", lines[j])
                    if m_mask:
                        mask = m_mask.group(1)
                        break
                if ip and mask:
                    break
        if ip and mask:
            parts = [int(x) for x in mask.split(".")]
            bits = sum(bin(x).count("1") for x in parts)
            return f"{ip}/{bits}"
        return None
    else:
        if dev:
            out = run_cmd(["ip", "-o", "-4", "addr", "show", "dev", dev])
            if out:
                for line in out.splitlines():
                    parts = line.split()
                    for i, v in enumerate(parts):
                        if v == "inet" and i + 1 < len(parts):
                            return parts[i + 1]
        out = run_cmd(["ip", "-o", "-4", "addr", "show"])
        if not out:
            return None
        for line in out.splitlines():
            parts = line.split()
            for i, v in enumerate(parts):
                if v == "inet" and i + 1 < len(parts):
                    return parts[i + 1]
        return None

def cidr_to_network(cidr: str) -> Tuple[str, int]:
    ip, prefix = cidr.split("/")
    prefix = int(prefix)
    packed_ip = struct.unpack("!I", socket.inet_aton(ip))[0]
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
    network = packed_ip & mask
    return socket.inet_ntoa(struct.pack("!I", network)), prefix

def subnet_hosts(cidr: str, limit: int = 1024) -> List[str]:
    net_ip, prefix = cidr_to_network(cidr)
    base = struct.unpack("!I", socket.inet_aton(net_ip))[0]
    size = 1 << (32 - prefix)
    hosts = []
    end = min(size - 2, limit)
    for i in range(1, end + 1):
        hosts.append(socket.inet_ntoa(struct.pack("!I", base + i)))
    return hosts

def neighbors() -> List[str]:
    if sys.platform.startswith("win"):
        out = run_cmd(["arp", "-a"])
        if not out:
            return []
        ips = []
        for line in out.splitlines():
            if "dynamic" in line.lower() or "static" in line.lower():
                m = re.search(r"([0-9]{1,3}(?:\.[0-9]{1,3}){3})", line)
                if m:
                    ip = m.group(1)
                    try:
                        socket.inet_aton(ip)
                        ips.append(ip)
                    except Exception:
                        pass
        return ips
    else:
        out = run_cmd(["ip", "neigh"])
        if not out:
            return []
        ips = []
        for line in out.splitlines():
            parts = line.split()
            if parts:
                try:
                    socket.inet_aton(parts[0])
                    ips.append(parts[0])
                except Exception:
                    pass
        return ips

async def tcp_check(ip: str, port: int, timeout: float = 1.0) -> Tuple[bool, Optional[bytes]]:
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        try:
            writer.write(b"\r\n")
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            data = await asyncio.wait_for(reader.read(256), timeout=timeout)
        except Exception:
            data = None
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, data
    except Exception:
        return False, None

async def http_banner(ip: str, port: int, timeout: float = 1.0) -> Optional[str]:
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        req = f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: termux-scan\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        writer.write(req.encode())
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        if not data:
            return None
        d = data.decode(errors="ignore")
        return d[:512]
    except Exception:
        return None

async def rtsp_options(ip: str, port: int = 554, timeout: float = 1.0) -> Optional[str]:
    try:
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=timeout)
        req = "OPTIONS rtsp://{ip}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: termux-scan\r\n\r\n".format(ip=ip)
        writer.write(req.encode())
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        if not data:
            return None
        return data.decode(errors="ignore")[:512]
    except Exception:
        return None

def ssdp_search(st: str, mx: int = 2, timeout: float = 3.0) -> List[Dict[str, str]]:
    addr = ("239.255.255.250", 1900)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(timeout)
    req = "\r\n".join([
        "M-SEARCH * HTTP/1.1",
        "HOST: 239.255.255.250:1900",
        f"MAN: \"ssdp:discover\"",
        f"MX: {mx}",
        f"ST: {st}",
        "",
        ""
    ]).encode()
    try:
        s.sendto(req, addr)
    except Exception:
        return []
    results = []
    start = time.time()
    while time.time() - start < timeout:
        try:
            data, src = s.recvfrom(2048)
        except Exception:
            break
        text = data.decode(errors="ignore")
        headers = {}
        for line in text.split("\r\n"):
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        headers["__src_ip"] = src[0]
        results.append(headers)
    s.close()
    return results

def ssdp_all_ips(timeout: float = 3.0) -> Set[str]:
    addr = ("239.255.255.250", 1900)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(timeout)
    req = "\r\n".join([
        "M-SEARCH * HTTP/1.1",
        "HOST: 239.255.255.250:1900",
        "MAN: \"ssdp:discover\"",
        "MX: 2",
        "ST: ssdp:all",
        "",
        ""
    ]).encode()
    ips: Set[str] = set()
    try:
        s.sendto(req, addr)
    except Exception:
        return ips
    start = time.time()
    while time.time() - start < timeout:
        try:
            data, src = s.recvfrom(2048)
        except Exception:
            break
        try:
            socket.inet_aton(src[0])
            ips.add(src[0])
        except Exception:
            pass
    s.close()
    return ips

def fetch_url(url: str, timeout: int = 5) -> Optional[bytes]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "termux-scan"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except Exception:
        return None

def parse_igd_control_url(xml_bytes: bytes) -> Optional[Tuple[str, str]]:
    try:
        root = ET.fromstring(xml_bytes)
    except Exception:
        return None
    ns = {"s": "urn:schemas-upnp-org:device-1-0"}
    services = root.findall(".//{*}service")
    ctrl = None
    stype = None
    for svc in services:
        t = svc.find("{*}serviceType")
        c = svc.find("{*}controlURL")
        if t is None or c is None:
            continue
        tv = t.text or ""
        if "WANIPConnection" in tv or "WANPPPConnection" in tv:
            ctrl = c.text or ""
            stype = tv
            break
    if not ctrl or not stype:
        return None
    return ctrl, stype

def join_url(base: str, path: str) -> str:
    parsed = urllib.parse.urlparse(base)
    if path.startswith("http://") or path.startswith("https://"):
        return path
    if not path.startswith("/"):
        path = "/" + path
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))

def igd_port_mappings(igd_location: str) -> List[Dict[str, str]]:
    xml = fetch_url(igd_location)
    if not xml:
        return []
    ctrl = parse_igd_control_url(xml)
    if not ctrl:
        return []
    control_url, service_type = ctrl
    ctrl_abs = join_url(igd_location, control_url)
    mappings = []
    i = 0
    while True:
        soap_body = f"""<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetGenericPortMappingEntry xmlns:u="{service_type}">
      <NewPortMappingIndex>{i}</NewPortMappingIndex>
    </u:GetGenericPortMappingEntry>
  </s:Body>
</s:Envelope>"""
        try:
            req = urllib.request.Request(ctrl_abs, data=soap_body.encode(), headers={
                "Content-Type": "text/xml; charset=\"utf-8\"",
                "SOAPACTION": f"\"{service_type}#GetGenericPortMappingEntry\"",
                "User-Agent": "termux-scan"
            })
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = resp.read()
        except Exception:
            break
        try:
            root = ET.fromstring(data)
            fields = {}
            for tag in ["NewRemoteHost","NewExternalPort","NewProtocol","NewInternalPort","NewInternalClient","NewEnabled","NewPortMappingDescription","NewLeaseDuration"]:
                el = root.find(".//{*}"+tag)
                if el is not None and el.text is not None:
                    fields[tag] = el.text
            if fields:
                mappings.append(fields)
        except Exception:
            break
        i += 1
    return mappings

def ws_discovery_onvif(timeout: float = 3.0) -> Set[str]:
    addr = ("239.255.255.250", 3702)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    s.settimeout(timeout)
    msg = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
  <e:Header>
    <w:MessageID>uuid:{}</w:MessageID>
    <w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
    <w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
  </e:Header>
  <e:Body>
    <d:Probe>
      <d:Types>dn:NetworkVideoTransmitter tds:Device</d:Types>
    </d:Probe>
  </e:Body>
</e:Envelope>""".format(str(time.time()).replace(".", ""))
    try:
        s.sendto(msg.encode(), addr)
    except Exception:
        return set()
    ips = set()
    start = time.time()
    while time.time() - start < timeout:
        try:
            data, src = s.recvfrom(4096)
        except Exception:
            break
        ips.add(src[0])
    s.close()
    return ips

def classify_device(ip: str, open_ports: Set[int], banners: Dict[int, str], onvif: bool) -> Dict[str, bool]:
    is_camera = False
    is_dvr = False
    if onvif:
        is_camera = True
    if 554 in open_ports:
        is_camera = True
    if 37777 in open_ports:
        is_dvr = True
    if 8000 in open_ports or 8899 in open_ports or 5000 in open_ports:
        is_dvr = is_dvr or True
    b80 = banners.get(80, "") + banners.get(8080, "")
    if "DVR" in b80 or "Camera" in b80 or "Hikvision" in b80 or "Dahua" in b80 or "ONVIF" in b80:
        is_camera = True
        is_dvr = is_dvr or ("DVR" in b80)
    return {"is_camera": is_camera, "is_dvr": is_dvr}

async def scan_ips(ips: List[str], ports: List[int], concurrency: int = 200) -> Dict[str, Dict]:
    sem = asyncio.Semaphore(concurrency)
    results: Dict[str, Dict] = {}
    async def scan_ip(ip: str):
        banners: Dict[int, str] = {}
        open_set: Set[int] = set()
        onvif = False
        async with sem:
            for port in ports:
                ok, data = await tcp_check(ip, port, timeout=0.8)
                if ok:
                    open_set.add(port)
                    if port in (80, 8080):
                        b = await http_banner(ip, port, timeout=0.8)
                        if b:
                            banners[port] = b
                    if port == 554:
                        rb = await rtsp_options(ip, port, timeout=0.8)
                        if rb:
                            banners[port] = rb
        results[ip] = {"open_ports": sorted(list(open_set)), "banners": banners, "onvif": onvif}
    tasks = [asyncio.create_task(scan_ip(ip)) for ip in ips]
    await asyncio.gather(*tasks, return_exceptions=True)
    return results

def mark_onvif(results: Dict[str, Dict], discovered_onvif: Set[str]) -> None:
    for ip in discovered_onvif:
        if ip in results:
            results[ip]["onvif"] = True
        else:
            results[ip] = {"open_ports": [], "banners": {}, "onvif": True}

def detect_exposure(results: Dict[str, Dict]) -> Dict[str, Optional[bool]]:
    exposures: Dict[str, Optional[bool]] = {}
    igds = ssdp_search("urn:schemas-upnp-org:device:InternetGatewayDevice:1", timeout=3.0)
    if not igds:
        for ip in results.keys():
            exposures[ip] = None
        return exposures
    locs = []
    for r in igds:
        if "location" in r:
            locs.append(r["location"])
    mappings: List[Dict[str, str]] = []
    for loc in locs:
        for m in igd_port_mappings(loc):
            mappings.append(m)
    map_ips: Set[str] = set()
    for m in mappings:
        ic = m.get("NewInternalClient")
        if ic:
            map_ips.add(ic)
    for ip in results.keys():
        exposures[ip] = ip in map_ips
    return exposures

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--gps", type=str, default=None)
    parser.add_argument("--lat", type=float, default=None)
    parser.add_argument("--lon", type=float, default=None)
    parser.add_argument("--radius", type=float, default=None)
    parser.add_argument("--cidr", type=str, default=None)
    parser.add_argument("--max-hosts", type=int, default=1024)
    parser.add_argument("--ports", type=str, default=None)
    args = parser.parse_args()
    wifi = get_termux_wifi_info()
    loc = {}
    if args.gps:
        p = parse_dms_string(args.gps)
        if p:
            loc = {"latitude": p[0], "longitude": p[1], "provider": "manual", "radius": args.radius}
    elif args.lat is not None and args.lon is not None:
        loc = {"latitude": args.lat, "longitude": args.lon, "provider": "manual", "radius": args.radius}
    else:
        loc = get_termux_location()
    dev = None if sys.platform.startswith("win") else get_default_interface()
    cidr = args.cidr or get_interface_cidr(dev)
    neigh = []
    hosts = []
    filtered_neigh = []
    target_ips = []
    if cidr:
        neigh = neighbors()
        hosts = subnet_hosts(cidr, limit=max(1, args.max_hosts))
        net_ip, prefix = cidr_to_network(cidr)
        base = struct.unpack("!I", socket.inet_aton(net_ip))[0]
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        for ip in neigh:
            try:
                n = struct.unpack("!I", socket.inet_aton(ip))[0]
                if (n & mask) == base and not ip.startswith("224.") and not ip.endswith(".255"):
                    filtered_neigh.append(ip)
            except Exception:
                pass
        target_ips = list(dict.fromkeys(filtered_neigh + hosts))
    common_ports = [80, 8080, 554, 8000, 37777, 5000, 8899]
    common_ports += [81, 88, 443, 8081, 8001, 8554, 37778, 34567, 23, 22]
    if args.ports:
        try:
            user_ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
            common_ports = list(dict.fromkeys(common_ports + user_ports))
        except Exception:
            pass
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    async def ping_sweep(ips: List[str]) -> Dict[str, bool]:
        sem = asyncio.Semaphore(300)
        alive: Dict[str, bool] = {}
        async def one(ip: str):
            async with sem:
                ok = await ping_ip(ip, timeout_ms=800)
                alive[ip] = ok
        await asyncio.gather(*[asyncio.create_task(one(ip)) for ip in ips], return_exceptions=True)
        return alive
    alive_map: Dict[str, bool] = {}
    results: Dict[str, Dict] = {}
    ssdp_ips: Set[str] = set()
    if target_ips:
        alive_map = loop.run_until_complete(ping_sweep(target_ips))
        scan_candidates = [ip for ip in target_ips if alive_map.get(ip, False)] + filtered_neigh
        scan_candidates = list(dict.fromkeys(scan_candidates))
        results = loop.run_until_complete(scan_ips(scan_candidates, common_ports))
        onvif_ips = ws_discovery_onvif(timeout=3.0)
        mark_onvif(results, onvif_ips)
        ssdp_ips = ssdp_all_ips(timeout=2.5)
    exposures = detect_exposure(results)
    devices = []
    seen_ips = set(target_ips)
    for ip in seen_ips:
        info = results.get(ip, {"open_ports": [], "banners": {}, "onvif": False})
        cls = classify_device(ip, set(info["open_ports"]), {k: v for k, v in info["banners"].items()}, info["onvif"])
        devices.append({
            "ip": ip,
            "open_ports": info["open_ports"],
            "onvif": info["onvif"],
            "http_banner": info["banners"].get(80) or info["banners"].get(8080),
            "rtsp_banner": info["banners"].get(554),
            "is_camera": cls["is_camera"],
            "is_dvr": cls["is_dvr"],
            "exposed_via_upnp": exposures.get(ip),
            "alive": bool(alive_map.get(ip, False) or info["open_ports"] or info["onvif"] or (ip in ssdp_ips))
        })
    cams = [d for d in devices if d["is_camera"] or d["is_dvr"]]
    active = [d for d in devices if d["open_ports"]]
    exposed = [d for d in cams if d["exposed_via_upnp"]]
    discovered = [d for d in devices if d.get("alive")]
    report = {
        "summary": {
            "total_devices_scanned": len(target_ips),
            "total_discovered": len(discovered),
            "cameras_or_dvrs": len(cams),
            "active_devices": len(active),
            "internet_exposed_cameras_or_dvrs": len(exposed)
        },
        "wifi": wifi,
        "location": loc,
        "devices": devices
    }
    def write_ips_bin(ips: List[str], path: str) -> None:
        try:
            with open(path, "wb") as f:
                f.write(_struct.pack(">I", len(ips)))
                for ip in ips:
                    try:
                        f.write(socket.inet_aton(ip))
                    except Exception:
                        f.write(b"\x00\x00\x00\x00")
        except Exception:
            pass
    def write_devices_bin(devs: List[Dict], summary: Dict, locd: Dict, path: str) -> None:
        try:
            with open(path, "wb") as f:
                f.write(b"CAMR")
                f.write(_struct.pack(">H", 1))
                f.write(_struct.pack(">IIIII",
                                     summary.get("total_devices_scanned", 0),
                                     summary.get("total_discovered", 0),
                                     summary.get("cameras_or_dvrs", 0),
                                     summary.get("active_devices", 0),
                                     summary.get("internet_exposed_cameras_or_dvrs", 0)))
                la = None
                lo = None
                ra = None
                if isinstance(locd, dict):
                    la = locd.get("latitude")
                    lo = locd.get("longitude")
                    ra = locd.get("radius")
                present = 1 if (la is not None and lo is not None) else 0
                f.write(_struct.pack(">B", present))
                f.write(_struct.pack(">ddf",
                                     float(la if la is not None else 0.0),
                                     float(lo if lo is not None else 0.0),
                                     float(ra if ra is not None else 0.0)))
                f.write(_struct.pack(">I", len(devs)))
                for d in devs:
                    ipb = b"\x00\x00\x00\x00"
                    try:
                        ipb = socket.inet_aton(d.get("ip", "0.0.0.0"))
                    except Exception:
                        pass
                    f.write(ipb)
                    f.write(_struct.pack(">BBBB",
                                         1 if d.get("alive") else 0,
                                         1 if d.get("is_camera") else 0,
                                         1 if d.get("is_dvr") else 0,
                                         1 if d.get("onvif") else 0))
                    exp = d.get("exposed_via_upnp")
                    expv = 255 if exp is None else (1 if exp else 0)
                    f.write(_struct.pack(">B", expv))
                    ports = d.get("open_ports") or []
                    f.write(_struct.pack(">H", len(ports)))
                    for p in ports:
                        f.write(_struct.pack(">H", int(p)))
        except Exception:
            pass
    out_path = "devices_report.json"
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"Scanned {len(target_ips)} IPs")
        print(f"Responsive devices: {len(discovered)}")
        print(f"Cameras/DVRs: {len(cams)}")
        print(f"Active devices (open ports): {len(active)}")
        print(f"Internet-exposed cameras/DVRs: {len(exposed)}")
        if loc:
            la = loc.get("latitude")
            lo = loc.get("longitude")
            ra = loc.get("radius")
            if la is not None and lo is not None:
                print(f"GPS: {la},{lo}" + (f" radius {ra}m" if ra else ""))
        print(out_path)
        csv_path = "devices_report.csv"
        with open(csv_path, "w", newline="", encoding="utf-8") as cf:
            w = csv.writer(cf)
            w.writerow(["ip","alive","is_camera","is_dvr","onvif","open_ports","exposed_via_upnp","latitude","longitude"])
            la = loc.get("latitude") if isinstance(loc, dict) else None
            lo = loc.get("longitude") if isinstance(loc, dict) else None
            for d in devices:
                w.writerow([
                    d["ip"],
                    d.get("alive", False),
                    d["is_camera"],
                    d["is_dvr"],
                    d["onvif"],
                    ",".join(str(p) for p in d["open_ports"]),
                    d["exposed_via_upnp"],
                    la,
                    lo
                ])
        print(csv_path)
        resp_ips = [d["ip"] for d in devices if d.get("alive")]
        if resp_ips:
            print("Responsive IPs:")
            for ip in resp_ips[:50]:
                print(ip)
        write_ips_bin(target_ips, "ips.bin")
        write_devices_bin(devices, report["summary"], loc, "devices_report.bin")
        print("ips.bin")
        print("devices_report.bin")
    except Exception as e:
        print("Failed to write report:", e)
        try:
            write_ips_bin([], "ips.bin")
            write_devices_bin([], {"total_devices_scanned": 0, "total_discovered": 0, "cameras_or_dvrs": 0, "active_devices": 0, "internet_exposed_cameras_or_dvrs": 0}, {}, "devices_report.bin")
        except Exception:
            pass

if __name__ == "__main__":
    main()
