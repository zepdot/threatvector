"""Gerçek süreçlerin skor dağılımını özetler.
Kullanım:  python ozet.py            (canlı tarama)
           python ozet.py out.json   (kayıtlı veri)"""
import json
import sys
from collections import Counter

from core.analyzer import analyze

if len(sys.argv) > 1:
    with open(sys.argv[1], encoding="utf-8") as f:
        satirlar = json.load(f)
else:
    from collector import collect
    print("Ölçüm yapılıyor, bekle...")
    satirlar = collect()

sonuc = [(r, analyze(r)) for r in satirlar]
print(f"\nToplam süreç: {len(sonuc)}")
print("Seviye   :", dict(Counter(a["level"] for _, a in sonuc)))
print("En yakın :", dict(Counter(a["closest"] for _, a in sonuc)))
print("İmza     :", dict(Counter(r["words"]["signature"] for r, _ in sonuc)))
print("Konum    :", dict(Counter(r["words"]["location"] for r, _ in sonuc)))

print("\nEn yüksek 10 risk:")
for r, a in sorted(sonuc, key=lambda x: x[1]["risk"], reverse=True)[:10]:
    print(f'  {a["name"][:24]:24} risk={a["risk"]:3} {r["words"]["signature"]:13} '
          f'{r["words"]["location"]:17} {a["similarities"]}')

print("\nİmzasız / geçersiz süreçler (asıl bakılacak liste):")
sus = [(r, a) for r, a in sonuc if r["words"]["signature"] in ("sig_unsigned", "sig_invalid")]
for r, a in sus[:20]:
    print(f'  {a["name"][:24]:24} risk={a["risk"]:3} {r["words"]["location"]:17} {r.get("exe", "")[-45:]}')
if not sus:
    print("  (yok)")

print("\nCPU'su en yüksek 5 süreç (yanlış alarm testi):")
for r, a in sorted(sonuc, key=lambda x: x[0]["numeric"]["cpu_percent"], reverse=True)[:5]:
    print(f'  {a["name"][:24]:24} cpu={r["numeric"]["cpu_percent"]:5}% '
          f'risk={a["risk"]:3} ({a["level"]}) {r["words"]["signature"]}')