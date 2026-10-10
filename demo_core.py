"""Kullanım:
  python demo_core.py                 -> sahte süreçlerle dene
  python demo_core.py --json out.json -> collector'ın JSON çıktısını analiz et
  python demo_core.py --canli         -> bilgisayardaki gerçek süreçleri tara (psutil gerekir)
"""
import argparse
import json

from core.analyzer import analyze


def satir(ad, cpu=0, ram=0.5, thr=10, disk=0, uzak=0, dinle=0, yas=3600,
          konum="loc_programfiles", imza="sig_signed", ports=(), cmd=()):
    return {"pid": 0, "name": ad,
            "numeric": {"cpu_percent": cpu, "ram_percent": ram, "threads": thr,
                        "disk_bytes_per_sec": disk, "remote_conn_count": uzak,
                        "listen_port_count": dinle, "age_seconds": yas},
            "words": {"location": konum, "signature": imza, "ports": list(ports),
                      "modules": [], "cmd_tokens": list(cmd)}}


SAHTE = [
    satir("chrome.exe", cpu=25, ram=6, thr=60, disk=2e6, uzak=15, yas=20000, ports=["port_443"]),
    satir("Code.exe", cpu=3, ram=3, thr=35, disk=1e4, uzak=4, yas=5400,
          konum="loc_appdata", ports=["port_443"]),
    satir("WhatsApp.exe", cpu=1, thr=30, uzak=3, konum="loc_windowsapps",
          imza="sig_packaged", ports=["port_443"]),
    satir("System", konum="loc_unknown", imza="sig_unknown", thr=150, yas=500000),
    satir("sahte_miner.exe", cpu=90, ram=1, thr=8, uzak=1, yas=60, konum="loc_temp",
          imza="sig_unsigned", ports=["port_3333"], cmd=["stratum", "tcp", "pool"]),
    satir("sahte_spyware.exe", cpu=1, ram=0.3, thr=5, disk=3e5, uzak=2, yas=60,
          konum="loc_appdata", imza="sig_unsigned", ports=["port_443"], cmd=["hidden"]),
    satir("bilinmeyen.exe", cpu=40, ram=1, thr=10, konum="loc_temp", imza="sig_unsigned"),
    satir("video_kodlayici.exe", cpu=85, ram=5, thr=40, disk=2e7, yas=900,
          ports=["port_443"]),
]


def yazdir(sonuclar, ust=15):
    sonuclar = sorted(sonuclar, key=lambda s: s["risk"], reverse=True)[:ust]
    for s in sonuclar:
        print(f'{s["name"][:22]:22} -> {s["closest"]:12} risk={s["risk"]:3} ({s["level"]})')


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--json")
    ap.add_argument("--canli", action="store_true")
    a = ap.parse_args()
    if a.json:
        with open(a.json, encoding="utf-8") as f:
            satirlar = json.load(f)
    elif a.canli:
        from collector import collect
        print("Ölçüm yapılıyor, birkaç saniye sürebilir...")
        satirlar = collect()
    else:
        satirlar = SAHTE
    yazdir([analyze(r) for r in satirlar])
