from core.vectorizer import surec_to_vektor
from core.cosine import cosine
from core.profiles import PROFILLER

def siniflandir(surec):
    v = surec_to_vektor(surec)
    skorlar = {isim: cosine(v, p) for isim, p in PROFILLER.items()}
    en_iyi = max(skorlar, key=skorlar.get)
    return en_iyi, skorlar

def risk_skoru(surec, skorlar):
    kelimeler = surec.get("kelimeler", [])
    kotu = max(skorlar["cryptominer"], skorlar["spyware"])
    imza = 1.0 if ("sig_none" in kelimeler or "sig_invalid" in kelimeler) else 0.0
    konum = 1.0 if ("loc_temp" in kelimeler or "loc_appdata" in kelimeler) else 0.0
    return round(100 * (0.6 * kotu + 0.25 * imza + 0.15 * konum))

def seviye(skor):
    return "düşük" if skor <= 30 else "orta" if skor <= 60 else "yüksek"