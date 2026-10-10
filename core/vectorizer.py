import numpy as np
from core.vocabulary import SAYISAL_OZELLIKLER, KELIMELER, MAKS_DEGERLER

BOYUT = len(SAYISAL_OZELLIKLER) + len(KELIMELER)

def surec_to_vektor(surec: dict) -> np.ndarray:
    """Bir sürecin sözlüğünü normalize edilmiş vektöre çevirir."""
    v = np.zeros(BOYUT)
    # Bölüm A: sayısal özellikler, 0-1 aralığına normalize
    for i, k in enumerate(SAYISAL_OZELLIKLER):
        v[i] = min(surec.get(k, 0) / MAKS_DEGERLER[k], 1.0)
    # Bölüm B: Bag-of-Words, kelime geçti mi (0/1)
    kelimeler = surec.get("kelimeler", [])
    for j, kelime in enumerate(KELIMELER):
        v[len(SAYISAL_OZELLIKLER) + j] = min(kelimeler.count(kelime), 1)
    return v

def profil_vektoru(**ozellikler) -> np.ndarray:
    """Profil değerleri zaten 0-1 aralığında verilir.
    Örnek: profil_vektoru(cpu=0.9, port_3333=1)"""
    v = np.zeros(BOYUT)
    for ad, deger in ozellikler.items():
        if ad in SAYISAL_OZELLIKLER:
            v[SAYISAL_OZELLIKLER.index(ad)] = deger
        elif ad in KELIMELER:
            v[len(SAYISAL_OZELLIKLER) + KELIMELER.index(ad)] = deger
        else:
            raise ValueError(f"Bilinmeyen özellik: {ad}")
    return v