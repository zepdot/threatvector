import numpy as np
import pytest

from core.cosine import cosine
from core.vocabulary import KELIMELER, SAYISAL_OZELLIKLER
from core.vectorizer import vektorlestir, sayisal_blok
from core.analyzer import analyze
from demo_core import satir


def test_elle_hesap():
    assert abs(cosine(np.array([1, 2, 0]), np.array([2, 1, 0])) - 0.8) < 1e-9


def test_sifir_vektor():
    assert cosine(np.zeros(5), np.ones(5)) == 0.0


def test_sklearn_ile_ayni():
    sk = pytest.importorskip("sklearn.metrics.pairwise")
    a, b = np.random.rand(26), np.random.rand(26)
    assert abs(cosine(a, b) - sk.cosine_similarity([a], [b])[0][0]) < 1e-9


def test_vektor_boyutu():
    v = vektorlestir(satir("x.exe"))
    assert len(v) == len(SAYISAL_OZELLIKLER) + len(KELIMELER)


def test_normalizasyon_0_1_araliginda():
    asiri = {"cpu_percent": 500, "ram_percent": 900, "threads": 99999,
             "disk_bytes_per_sec": 1e12, "remote_conn_count": 1000,
             "listen_port_count": 1000, "age_seconds": 1e9}
    b = sayisal_blok(asiri)
    assert b.min() >= 0 and b.max() <= 1


def test_bos_ve_none_alanlar_cokmez():
    row = {"pid": 1, "name": "x", "numeric": {"cpu_percent": None},
           "words": {"location": "loc_unknown", "signature": "sig_unknown",
                     "ports": [], "modules": [], "cmd_tokens": []}}
    assert 0 <= analyze(row)["risk"] <= 100


def test_imzali_normal_program_dusuk_risk():
    r = analyze(satir("chrome.exe", cpu=25, ram=6, thr=60, uzak=15, yas=20000,
                      ports=["port_443"]))
    assert r["closest"] == "normal" and r["level"] == "düşük"


def test_store_uygulamasi_risk_artirmaz():
    r = analyze(satir("WhatsApp.exe", konum="loc_windowsapps",
                      imza="sig_packaged", ports=["port_443"]))
    assert r["level"] == "düşük"


def test_sahte_miner_yuksek_risk():
    r = analyze(satir("miner.exe", cpu=90, thr=8, yas=60, konum="loc_temp",
                      imza="sig_unsigned", ports=["port_3333"],
                      cmd=["stratum", "pool"]))
    assert r["closest"] == "cryptominer" and r["level"] == "yüksek"


def test_sig_unknown_riski_artirmaz():
    ayni = dict(cpu=3, thr=20, konum="loc_system")
    bilinmeyen = analyze(satir("a", imza="sig_unknown", **ayni))["risk"]
    imzali = analyze(satir("a", imza="sig_signed", **ayni))["risk"]
    assert bilinmeyen >= imzali   # imzalı indirim alır, unknown almaz
    assert bilinmeyen < 40
