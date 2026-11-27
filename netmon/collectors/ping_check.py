# ping_check.py
# Nhiệm vụ: kiểm tra 1 host Online/Offline + đo độ trễ (RTT).
# Đầu ra: dict để monitor.py ghi vào DB (bảng devices / events).

import platform
import re
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

SYSTEM = platform.system().lower() # "windows/linux/darwin"
RTT_RE = re.compile(r"time\s*[=<]\s*([\d.]+)\s*ms", re.IGNORECASE)
TTL_RE = re.compile(r"ttl\s*=", re.IGNORECASE)

def _build_cmd(ip: str, timeout_ms: int) -> list[str]:
    if SYSTEM == "windows":
        return ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    if SYSTEM == "darwin": #MacOS uses ms
        return ["ping", "-n", "1", "-W", str(timeout_ms), ip]
    return ["ping", "-c", "1", "-W", str(max(1, round(timeout_ms / 1000))), ip] #Linux use seconds


def ping_once(ip: str, timeout_ms: int = 1000) -> float | None:
    """
    Ping 1 gói tới `ip`.
    Trả về RTT (ms) nếu có phản hồi, None nếu timeout/lỗi.

    Gợi ý:
    - Windows: ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    - Linux/mac: ["ping", "-c", "1", "-W", <giây hoặc ms tuỳ OS>, ip]
      (platform.system() để phân biệt)
    - subprocess.run(..., capture_output=True, text=True, timeout=...)
    - Parse RTT bằng regex từ stdout: "time=12.3 ms" / "time<1ms"
    - Nhớ bắt subprocess.TimeoutExpired
    """
    cmd = _build_cmd(ip, timeout_ms)
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout = timeout_ms / 1000 + 2
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return None
    elapsed_ms = (time.perf_counter()-start) * 1000
    out = proc.stdout or ""
    # Windows trả returncode 0 cả khi "Destination host unreachable",
    # nên phải kiểm tra thêm có TTL= (chỉ xuất hiện khi host thật sự trả lời).
    if proc.returncode != 0 or not TTL_RE.search(out):
        return None

    m = RTT_RE.search(out)
    if m:
        return float(m.group(1))
    # "time<1ms" hoặc hệ điều hành đổi ngôn ngữ output -> dùng thời gian đo ngoài
    return round(elapsed_ms, 2)
        

def ping_host(ip: str, count: int = 3, timeout_ms: int = 1000) -> dict:
    """Ping `count` lần và tổng hợp: online, avg/min/max, % mất gói."""
    rtts = []
    for _ in range(count):
        rtt = ping_once(ip, timeout_ms)
        if rtt is not None:
            rtts.append(rtt)

    received = len(rtts)
    return {
        "ip": ip,
        "online": received > 0,
        "avg_ms": round(sum(rtts) / received, 2) if rtts else None,
        "min_ms": min(rtts) if rtts else None,
        "max_ms": max(rtts) if rtts else None,
        "loss_pct": round((count - received) / count * 100, 1),
        "checked_at": time.time(),
    }


def check_many(ips: list[str], count: int = 3,
               timeout_ms: int = 1000, workers: int = 50) -> list[dict]:
    """Ping song song nhiều thiết bị (quét /24 chỉ mất vài giây)."""
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda ip: ping_host(ip, count, timeout_ms), ips))


if __name__ == "__main__":
    for ip in ("127.0.0.1", "8.8.8.8", "10.255.255.1"):
        print(ping_host(ip))