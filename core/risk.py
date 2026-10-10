from core.vocabulary import RISKLI_KONUMLAR


def risk_skoru(row, benzerlikler):
    """0-100 arası risk. Cosine tek başına risk değildir, imza ve konum kuralları eklenir."""
    skor = max(benzerlikler["spyware"], benzerlikler["cryptominer"]) * 100
    w = row.get("words", {})
    imza = w.get("signature", "sig_unknown")
    konum = w.get("location", "loc_unknown")

    if imza in ("sig_signed", "sig_packaged"):
        skor *= 0.4                      # imzalı / Store uygulaması: belirgin indirim
    elif imza in ("sig_unsigned", "sig_invalid"):
        skor += 10                       # imzasız: artır
        if konum in RISKLI_KONUMLAR:
            skor += 20                   # imzasız + riskli konum: daha çok artır
    # sig_unknown: ne artır ne azalt. Konum tek başına risk sayılmaz.

    return max(0, min(100, round(skor)))


def seviye(skor):
    return "düşük" if skor <= 30 else "orta" if skor <= 60 else "yüksek"
