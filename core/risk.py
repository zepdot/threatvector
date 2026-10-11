from core.vocabulary import RISKLI_KONUMLAR


def risk_hesapla(row, benzerlikler):
    """0-100 arası risk ve hesabın adımlarını döndürür (arayüzde 'neden bu skor?' için).
    Cosine tek başına risk değildir, imza ve konum kuralları eklenir."""
    en_kotu = max(("spyware", "cryptominer"), key=lambda k: benzerlikler[k])
    kotu = benzerlikler[en_kotu]
    skor = kotu * 100
    adimlar = [f"Temel skor: en yüksek zararlı cosine ({en_kotu}) {kotu:.3f} × 100 = {skor:.0f}"]

    w = row.get("words", {})
    imza = w.get("signature", "sig_unknown")
    konum = w.get("location", "loc_unknown")

    if imza in ("sig_signed", "sig_packaged"):
        skor *= 0.4                      # imzalı / Store uygulaması: belirgin indirim
        adimlar.append(f"İmzalı ({imza}): × 0.4 → {skor:.0f}")
    elif imza in ("sig_unsigned", "sig_invalid"):
        skor += 10                       # imzasız: artır
        adimlar.append(f"İmzasız ({imza}): +10 → {skor:.0f}")
        if konum in RISKLI_KONUMLAR:
            skor += 20                   # imzasız + riskli konum: daha çok artır
            adimlar.append(f"Riskli konum ({konum}): +20 → {skor:.0f}")
    else:
        adimlar.append("İmza bilinmiyor: ne artış ne indirim")
    # Konum tek başına risk sayılmaz (VS Code AppData'da çalışır).

    son = max(0, min(100, round(skor)))
    adimlar.append(f"Sonuç: {son} / 100")
    return son, adimlar


def risk_skoru(row, benzerlikler):
    return risk_hesapla(row, benzerlikler)[0]


def seviye(skor):
    return "düşük" if skor <= 30 else "orta" if skor <= 60 else "yüksek"
