import numpy as np
from core.vocabulary import KELIMELER, AGIRLIK_A, AGIRLIK_B

GUN7 = 7 * 86400


def _sayi(n, anahtar):
    """Alan yoksa ya da None ise (yetki hatası) 0 kabul et."""
    deger = n.get(anahtar)
    return float(deger) if deger else 0.0


def kelime_listesi(row):
    """collector.to_word_list ile aynı mantık (psutil gerektirmesin diye burada da var)."""
    w = row.get("words", {})
    return ([w.get("location", "loc_unknown"), w.get("signature", "sig_unknown")]
            + list(w.get("ports") or [])
            + [f"dll_{m}" for m in (w.get("modules") or [])]
            + [f"cmd_{t}" for t in (w.get("cmd_tokens") or [])])


def sayisal_blok(n):
    """Blok A: hepsi 0-1 aralığına normalize edilir (Atallah'ın formülleri)."""
    v = [
        _sayi(n, "cpu_percent") / 100,
        min(_sayi(n, "ram_percent") / 20, 1),
        np.log1p(_sayi(n, "threads")) / np.log1p(200),
        np.log1p(_sayi(n, "disk_bytes_per_sec")) / np.log1p(100e6),
        min(_sayi(n, "remote_conn_count") / 20, 1),
        min(_sayi(n, "listen_port_count") / 5, 1),
        np.log1p(_sayi(n, "age_seconds")) / np.log1p(GUN7),
    ]
    return np.clip(np.array(v, dtype=float), 0.0, 1.0)


def kelime_blogu(row):
    """Blok B: Bag-of-Words, sözlükteki kelime süreçte varsa 1, yoksa 0."""
    mevcut = set(kelime_listesi(row))
    return np.array([1.0 if k in mevcut else 0.0 for k in KELIMELER])


def birlestir(blok_a, blok_b):
    return np.concatenate([AGIRLIK_A * blok_a, AGIRLIK_B * blok_b])


def vektorlestir(row):
    """collect() satırı -> ağırlıklı vektör (7 sayısal + sözlük boyutu kadar kelime)."""
    return birlestir(sayisal_blok(row.get("numeric", {})), kelime_blogu(row))


def profil_vektoru(sayisal=None, kelimeler=None):
    """Profili süreçle AYNI birleştirme fonksiyonundan geçirir.
    sayisal: {"cpu_percent": 0.9, ...} (zaten 0-1 normalize değerler)
    kelimeler: ["sig_unsigned", "loc_temp", ...]"""
    from core.vocabulary import SAYISAL_OZELLIKLER
    a = np.zeros(len(SAYISAL_OZELLIKLER))
    for ad, deger in (sayisal or {}).items():
        if ad not in SAYISAL_OZELLIKLER:
            raise ValueError(f"Bilinmeyen sayısal özellik: {ad}")
        a[SAYISAL_OZELLIKLER.index(ad)] = deger
    b = np.zeros(len(KELIMELER))
    for k in (kelimeler or []):
        if k not in KELIMELER:
            raise ValueError(f"Sözlükte olmayan kelime: {k}")
        b[KELIMELER.index(k)] = 1.0
    return birlestir(a, b)
