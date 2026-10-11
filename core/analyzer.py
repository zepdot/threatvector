from core.vectorizer import vektorlestir
from core.cosine import cosine
from core.profiles import PROFILLER
from core.risk import risk_hesapla, seviye

ESIK_BELIRSIZ = 0.30


def analyze(row):
    """Arayüzün çağıracağı tek fonksiyon: süreç + en yakın profil + cosine değerleri + risk skoru."""
    v = vektorlestir(row)
    benzerlikler = {ad: cosine(v, p) for ad, p in PROFILLER.items()}
    en_yakin = max(benzerlikler, key=benzerlikler.get)
    if benzerlikler[en_yakin] < ESIK_BELIRSIZ:
        en_yakin = "belirsiz"          # hiçbir profile yeterince benzemiyor
    risk, adimlar = risk_hesapla(row, benzerlikler)
    return {
        "pid": row.get("pid"),
        "name": row.get("name", ""),
        "closest": en_yakin,
        "similarities": {k: round(x, 3) for k, x in benzerlikler.items()},
        "risk": risk,
        "level": seviye(risk),
        "risk_adimlari": adimlar,
    }
