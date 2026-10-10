"""Hangi DLL kaç süreçte var? Kullanım: python dll_say.py out.json"""
import json
import sys
from collections import Counter

with open(sys.argv[1], encoding="utf-8") as f:
    satirlar = json.load(f)

okunan = [r for r in satirlar if r["words"]["modules"]]
toplam = len(okunan)
sayac = Counter(m for r in okunan for m in set(r["words"]["modules"]))
print(f"Toplam {len(satirlar)} süreç, DLL bilgisi okunabilen: {toplam}\n")

ADAYLAR = ["ws2_32.dll", "wininet.dll", "winhttp.dll", "mswsock.dll", "dnsapi.dll",
           "iphlpapi.dll", "crypt32.dll", "bcrypt.dll", "ncrypt.dll", "rsaenh.dll",
           "schannel.dll", "fwpuclnt.dll"]
print("Ağ ve şifreleme DLL'leri (kaç süreçte var):")
for d in ADAYLAR:
    n = sayac.get(d, 0)
    yuzde = 100 * n / toplam if toplam else 0
    print(f"  {d:16} {n:4} süreç  (%{yuzde:4.0f})")

print("\nHer süreçte olan DLL'ler (ayırt edici DEĞİL, seçme): ",
      sum(1 for d, n in sayac.items() if n >= 0.9 * toplam), "adet")