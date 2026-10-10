"""
ThreatVector - Veri Toplama Modulu
----------------------------------
Calisan sureclerden iki tur ozellik cikarir:
  1) SAYISAL ozellikler  -> cpu, ram, thread, disk/ag hizi ...
  2) "KELIME" ozellikleri -> dosya konumu, imza durumu, DLL adlari, port,
                             komut satiri parcalari (Bag-of-Words icin)

Bu modul SADECE OKUR. Hicbir sureci degistirmez veya sonlandirmaz.

Kurulum:  pip install psutil
Calistir: python collector.py            (ilk 15 surec, ekrana yazar)
          python collector.py --json out.json   (hepsini dosyaya yazar)
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

import psutil

IS_WINDOWS = sys.platform.startswith("win")
NUM_CPUS = psutil.cpu_count() or 1   # psutil CPU yuzdesi tum cekirdekler toplami olabilir
MY_PID = os.getpid()                 # kendi kendimizi listeden cikaririz

# --------------------------------------------------------------------------
# 1) DIJITAL IMZA KONTROLU (Windows)
# --------------------------------------------------------------------------
_sig_cache = {}


def check_signatures(paths):
    """Verilen exe yollari icin imza durumunu toplu sorgular.
    Donus: {yol: 'signed' | 'unsigned' | 'invalid' | 'unknown'}
    Toplu sorgu, her surec icin ayri PowerShell acmaktan cok daha hizlidir."""
    todo = [p for p in set(paths) if p and p not in _sig_cache]
    if not todo:
        return {p: _sig_cache.get(p, "unknown") for p in paths}

    if not IS_WINDOWS:
        for p in todo:
            _sig_cache[p] = "unknown"  # Windows disinda imza kontrolu yok
        return {p: _sig_cache.get(p, "unknown") for p in paths}

    # Yollari tek bir PowerShell komutuna veriyoruz (JSON olarak, guvenli)
    ps_script = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$paths = ConvertFrom-Json $env:TV_PATHS;"
        "$paths | ForEach-Object {"
        "  $s = Get-AuthenticodeSignature -LiteralPath $_;"
        "  [PSCustomObject]@{p=$_; s=[string]$s.Status}"
        "} | ConvertTo-Json -Compress"
    )
    try:
        env = dict(os.environ, TV_PATHS=json.dumps(todo))
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True, text=True, timeout=60, env=env,
        ).stdout.strip()
        data = json.loads(out) if out else []
        if isinstance(data, dict):  # tek sonuc donerse
            data = [data]
        for item in data:
            status = item.get("s", "")
            if status == "Valid":
                _sig_cache[item["p"]] = "signed"
            elif status == "NotSigned":
                _sig_cache[item["p"]] = "unsigned"
            elif status in ("HashMismatch", "NotTrusted"):
                _sig_cache[item["p"]] = "invalid"   # bozulmus / guvenilmeyen imza
            else:
                # UnknownError, NotSupportedFileFormat, Incompatible ...
                # imza hakkinda bilgi yok -> risk sayilmasin
                _sig_cache[item["p"]] = "unknown"
    except Exception:
        pass

    for p in todo:
        _sig_cache.setdefault(p, "unknown")
    return {p: _sig_cache.get(p, "unknown") for p in paths}


# --------------------------------------------------------------------------
# 2) YARDIMCI FONKSIYONLAR
# --------------------------------------------------------------------------
def location_category(exe_path):
    """Dosya konumunu kategoriye cevirir (risk icin onemli ipucu)."""
    if not exe_path:
        return "loc_unknown"
    p = exe_path.lower().replace("/", "\\")
    if "\\windowsapps\\" in p:          # Program Files icinde, o yuzden once kontrol
        return "loc_windowsapps"
    if ("\\windows\\system32" in p or "\\windows\\syswow64" in p
            or "\\windows\\systemapps" in p):
        return "loc_system"
    if "\\program files" in p:
        return "loc_programfiles"
    if "\\appdata\\local\\temp" in p or "\\windows\\temp" in p or "\\tmp" in p:
        return "loc_temp"
    if "\\appdata\\" in p:
        return "loc_appdata"
    if "\\downloads" in p:
        return "loc_downloads"
    if "\\users\\public" in p or "\\programdata" in p:
        return "loc_public"
    return "loc_other"


def tokenize(text):
    """Metni kucuk harfli kelimelere boler (Bag-of-Words icin)."""
    return [t for t in re.split(r"[^a-z0-9]+", text.lower()) if len(t) > 1]


def safe(fn, default=None):
    """psutil bazen AccessDenied/NoSuchProcess firlatir; sessizce gec."""
    try:
        return fn()
    except (psutil.AccessDenied, psutil.NoSuchProcess,
            psutil.ZombieProcess, OSError):
        return default


# --------------------------------------------------------------------------
# 3) ANA TOPLAMA
# --------------------------------------------------------------------------
def collect(interval=1.0):
    """Tum sureclerden iki olcum arasinda (interval sn) veri toplar.
    Hiz (cpu, disk, ag) iki olcumun farkindan hesaplanir."""
    # PID 0 = System Idle Process (gercek bir program degil), MY_PID = bu script
    procs = [p for p in psutil.process_iter() if p.pid not in (0, MY_PID)]

    # 1. olcum: cpu sayaclarini hazirla, disk/ag baslangic degerlerini al
    start = {}
    for p in procs:
        safe(lambda: p.cpu_percent(None))
        io = safe(p.io_counters)
        start[p.pid] = (io.read_bytes + io.write_bytes) if io else 0
    time.sleep(interval)

    rows = []
    total_ram = psutil.virtual_memory().total

    for p in procs:
        info = safe(lambda: p.as_dict(attrs=[
            "pid", "name", "exe", "cmdline", "num_threads", "username",
            "create_time",
        ]))
        if not info:
            continue

        exe = info.get("exe") or ""
        # cpu_percent cok cekirdekte %100'u asabilir -> cekirdek sayisina bol
        cpu = min(safe(lambda: p.cpu_percent(None), 0.0) / NUM_CPUS, 100.0)
        mem = safe(p.memory_info)
        ram_pct = (mem.rss / total_ram * 100) if mem else 0.0

        io = safe(p.io_counters)
        io_now = (io.read_bytes + io.write_bytes) if io else 0
        disk_bps = max(0, io_now - start.get(p.pid, 0)) / interval

        conns = safe(lambda: p.net_connections(kind="inet"), []) or []
        remote = [c for c in conns if c.raddr]
        ports = sorted({c.raddr.port for c in remote})
        listening = [c for c in conns if c.status == "LISTEN"]

        # DLL / yuklu modul adlari
        maps = safe(p.memory_maps, []) or []
        modules = sorted({os.path.basename(m.path).lower() for m in maps
                          if m.path.lower().endswith((".dll", ".so"))})
        if not modules:  # bazi sistemlerde memory_maps bos gelir
            ol = safe(p.open_files, []) or []
            modules = sorted({os.path.basename(f.path).lower() for f in ol
                              if f.path.lower().endswith((".dll", ".so"))})

        cmdline = " ".join(info.get("cmdline") or [])
        age = time.time() - (info.get("create_time") or time.time())

        rows.append({
            "pid": info["pid"],
            "name": info.get("name") or "",
            "exe": exe,
            "user": info.get("username") or "",
            "numeric": {
                "cpu_percent": round(cpu, 2),
                "ram_percent": round(ram_pct, 3),
                "threads": info.get("num_threads") or 0,
                "disk_bytes_per_sec": round(disk_bps, 1),
                "remote_conn_count": len(remote),
                "listen_port_count": len(listening),
                "age_seconds": round(age),
            },
            "words": {
                "location": location_category(exe),
                "ports": [f"port_{x}" for x in ports],
                "modules": modules,
                "cmd_tokens": tokenize(cmdline),
            },
            "_exe_for_sig": exe,
        })

    # Imzalari toplu sorgula
    sigs = check_signatures([r["_exe_for_sig"] for r in rows])
    for r in rows:
        exe_path = r.pop("_exe_for_sig")
        sig = sigs.get(exe_path, "unknown")
        # Store (MSIX) uygulamalari paket imzali olur; Authenticode sorgusu
        # bunlari yanlislikla 'unsigned' gosterebilir (ornek: WhatsApp).
        if r["words"]["location"] == "loc_windowsapps" and sig in ("unsigned", "invalid"):
            sig = "packaged"
        elif not os.path.isfile(exe_path):
            # Registry, MemCompression gibi diskte dosyasi olmayan sistem
            # surecleri: imza sorgulanamaz -> invalid degil unknown
            sig = "unknown"
        r["words"]["signature"] = "sig_" + sig
    return rows


def to_word_list(row):
    """Bir surecin 'kelime' ozelliklerini tek bir kelime listesine cevirir.
    Bag-of-Words vektorlestirmeye bu liste girer."""
    w = row["words"]
    return ([w["location"], w["signature"]] + w["ports"]
            + [f"dll_{m}" for m in w["modules"]]
            + [f"cmd_{t}" for t in w["cmd_tokens"]])


# --------------------------------------------------------------------------
# 4) KOMUT SATIRI
# --------------------------------------------------------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", help="tum sonuclari bu dosyaya yaz")
    ap.add_argument("--top", type=int, default=15,
                    help="ekrana yazilacak surec sayisi (CPU'ya gore)")
    args = ap.parse_args()

    data = collect()

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"{len(data)} surec {args.json} dosyasina yazildi.")
    else:
        data.sort(key=lambda r: r["numeric"]["cpu_percent"], reverse=True)
        for r in data[:args.top]:
            n = r["numeric"]
            print(f"[{r['pid']:>6}] {r['name'][:22]:<22} "
                  f"cpu={n['cpu_percent']:>5}% ram={n['ram_percent']:>5}% "
                  f"conn={n['remote_conn_count']:<3} "
                  f"{r['words']['location']} {r['words']['signature']}")
