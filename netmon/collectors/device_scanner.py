import ipaddress
import psutil
import socket
import time
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from statistics import mean
from scapy.all import ARP, Ether, srp, conf

conf.verb = 0 # Tắt log Scapy
_dns_pool = ThreadPoolExecutor(max_workers=8)

def get_local_subnet() -> list[dict] :
    """Find active IPv4 interfaces and calculate their CIDR subnets using psutil."""
    subnets = []
    stats = psutil.net_if_stats()
    addrs = psutil.net_if_addrs()

    for iface, addr_list in addrs.items():
        # Skip interfaces that are down or loopback or link-local
        if iface in stats and not stats[iface].isup:
            continue

        for addr in addr_list:
            if addr.family == socket.AF_INET and not addr.address.startswith("127.") and not addr.address.startswith("169.254"):
                # Calculate CIDR (e.g., 192.168.1.0/24) from IP and Netmask
                network = ipaddress.IPv4Network(f"{addr.address}/{addr.netmask}", strict=False)
                subnets.append({
                    "iface": iface,
                    "ip": addr.address,
                    "cidr": str(network)
                })
    return subnets    
    
def arp_scan(cidr, iface):
    """Send ARP requests across the subnet using Scapy."""
    # Create Ethernet broadcast + ARP request packet
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
    
    # Send and receive at Layer 2
    answered, _ = srp(packet, iface=iface, timeout=2, verbose=False)
    
    devices = []
    for _, received in answered:
        devices.append({
            "ip": received.psrc,
            "mac": received.hwsrc
        })
    return devices
    
def measure_latency(
    host:str,
    port:int = 443,
    runs:int = 5,
    timeout:float = 3.0,
    delay:float = 0.5
    ):
    """Đo độ trễ TCP connect tới host:port.

    Trả về dict: avg_ms, min_ms, max_ms, loss_pct, samples.
    ConnectionRefusedError vẫn tính là phản hồi hợp lệ (host sống, cổng đóng).
    """
    samples: list[float|None] = []    
    for i in range(runs):
        start = time.perf_counter()
        try:
            with socket.create_connection((host,port), timeout=timeout):
                pass
            samples.append((time.perf_counter() - start) * 1000)
        except ConnectionRefusedError:
            # RST trả về => host sống, RTT vẫn hợp lệ
            samples.append((time.perf_counter() - start) * 1000)
        except OSError:
            # timeout, no route to host, network unreachable...
            samples.append(None)
            
        if i < runs - 1:
            time.sleep(delay)
    
    ok = [s for s in samples if s is not None]
    return {
        "avg_ms": round(mean(ok), 2) if ok else None,
        "min_ms": round(min(ok), 2) if ok else None,
        "max_ms": round(max(ok), 2) if ok else None,
        "loss_pct": round((runs - len(ok)) / runs * 100, 1),
        "samples": samples,
    }
        
def resolve_hostname(ip:str, timeout: float=1.0) -> str | None:
    """Reverse DNS: IP -> hostname. Trả None nếu không có PTR hoặc quá thời gian."""
    future = _dns_pool.submit(socket.gethostbyaddr, ip)
    try:
        return future.result(timeout=timeout)[0]
    except (OSError, FutureTimeout):
        # herror/gaierror (không có PTR) đều là lớp con của OSError
        return None

def _probe(dev: dict) -> dict:
    """Làm giàu thông tin cho MỘT thiết bị (chạy trong thread)."""
    lat = measure_latency(dev["ip"], port=80, runs=3, timeout=1.0)
    return {
        **dev,
        "hostname": resolve_hostname(dev["ip"]),
        "latency_ms": lat["avg_ms"],
        "loss_pct": lat["loss_pct"],
    }

    
def scan_devices() -> list[dict]:
    # Quét ARP trên từng subnet
    found: dict[str, dict] = {} #Key = MAC => tự loại trừ
    for subnet in get_local_subnet():
        for dev in arp_scan(subnet["cidr"], subnet["iface"]):
            found.setdefault(dev["mac"], {**dev, "iface": subnet["iface"]})
    if not found:
        return []
    # Đo latency + resolve hostname 
    with ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(_probe, found.values()))
    # Thêm trạng thái và thời điểm thấy
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for r in results:
        r["status"] = "online"  # trả lời ARP => đang sống
        r["last_seen"] = now

    return results
            
            
if __name__ == "__main__":
    for d in scan_devices():
        print(d)