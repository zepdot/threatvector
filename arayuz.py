"""ThreatVector arayüzü - Aşama 2: gerçek tarama (Tara düğmesi) ve otomatik yenileme.
Açılışta örnek veri gösterir; Tara'ya basınca gerçek süreçleri tarar. Çalıştır: python arayuz.py   (ana klasörde, (venv) açıkken)"""
import html
import sys
import threading
import time
from datetime import datetime
from collections import Counter

from PyQt6.QtCore import QObject, QRect, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QBrush, QColor
from PyQt6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QFrame, QHBoxLayout,
                             QHeaderView, QLabel, QLineEdit, QMainWindow, QProgressBar,
                             QPushButton, QScrollArea, QStyle, QStyledItemDelegate, QTableWidget, QTableWidgetItem, QVBoxLayout,
                             QWidget)

from core.analyzer import analyze
from demo_core import SAHTE          # Aşama 2'de burası collect() olacak

SUTUNLAR = ["PID", "Ad", "CPU %", "Risk", "Seviye", "En yakın profil",
            "Cos. Normal", "Cos. Spyware", "Cos. Miner", "İmza"]
YENILE_SN = 30            # otomatik yenileme: bir tarama bittikten kaç saniye sonra yenisi başlasın
RISK_SUTUNU, SEVIYE_SUTUNU = 3, 4
BENZERLIK_SUTUNLARI = (6, 7, 8)

ARKA = {"düşük": "#14261b", "orta": "#2e2511", "yüksek": "#2e1519"}      # satır arka planı
VURGU = {"düşük": "#3fb950", "orta": "#d29922", "yüksek": "#f85149"}     # yeşil, turuncu, kırmızı
METIN, SOLUK, MAVI = "#e6edf3", "#8b949e", "#58a6ff"
BANNER = {"düşük": ("DÜŞÜK RİSK", "Acil bir durum tespit edilmedi."),
          "orta": ("ORTA RİSK", "Şüpheli işaretler var, süreci inceleyin."),
          "yüksek": ("YÜKSEK RİSK", "Zararlı profile güçlü benzerlik, öncelikli inceleyin.")}
PROFIL_ADI = {"normal": "Normal", "spyware": "Spyware", "cryptominer": "Cryptominer"}
PROFIL_RENK = {"normal": "#3fb950", "spyware": "#d29922", "cryptominer": "#f85149"}

QSS = f"""
QWidget {{ background: #0d1117; color: {METIN}; font-family: 'Segoe UI'; font-size: 13px; }}
QLabel {{ background: transparent; }}
QFrame#kart, QFrame#panel {{ background: #161b22; border: 1px solid #21262d; border-radius: 8px; }}
QLineEdit, QComboBox {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 6px 10px; }}
QComboBox QAbstractItemView {{ background: #161b22; selection-background-color: #1f3a5f; }}
QTableWidget {{ background: #0d1117; border: 1px solid #21262d; gridline-color: #21262d; }}
QHeaderView::section {{ background: #161b22; color: {SOLUK}; border: none; border-bottom: 1px solid #30363d; padding: 8px; font-weight: bold; }}
QProgressBar {{ background: #21262d; border: none; border-radius: 4px; }}
QScrollArea, QScrollArea > QWidget, QScrollArea > QWidget > QWidget {{ background: transparent; border: none; }}
QPushButton {{ background: #238636; color: white; border: none; border-radius: 6px; padding: 8px 20px; font-weight: bold; }}
QPushButton:hover {{ background: #2ea043; }}
QPushButton:disabled {{ background: #21262d; color: {SOLUK}; }}
QCheckBox {{ background: transparent; spacing: 8px; }}
QProgressBar::chunk {{ background: {MAVI}; border-radius: 4px; }}
QScrollBar:vertical {{ background: #0d1117; width: 10px; }}
QScrollBar::handle:vertical {{ background: #30363d; border-radius: 5px; }}
"""


def sure_yaz(saniye):
    saniye = int(saniye or 0)
    if saniye >= 86400:
        return f"{saniye // 86400} gün {saniye % 86400 // 3600} sa"
    if saniye >= 3600:
        return f"{saniye // 3600} sa {saniye % 3600 // 60} dk"
    return f"{saniye // 60} dk" if saniye >= 60 else f"{saniye} sn"


def satirlari_hazirla(satirlar):
    """collect() satırlarını analiz edip tabloya hazır sözlüklere çevirir (arayüzden bağımsız)."""
    sonuc = []
    for r in satirlar:
        a = analyze(r)
        n, w = r.get("numeric", {}), r.get("words", {})
        a["cpu"] = n.get("cpu_percent") or 0
        a["ram"] = n.get("ram_percent") or 0
        a["thread"] = n.get("threads") or 0
        a["yas"] = n.get("age_seconds") or 0
        a["imza"] = w.get("signature", "sig_unknown")
        a["konum"] = w.get("location", "loc_unknown")
        a["exe"] = r.get("exe") or "-"
        a["ports"] = list(w.get("ports") or [])
        a["cmd"] = list(w.get("cmd_tokens") or [])[:12]
        sonuc.append(a)
    return sonuc


class TaramaSinyalleri(QObject):
    """Arka plan taramasının sonucunu pencereye güvenli biçimde taşıyan sinyaller."""
    bitti = pyqtSignal(list, float)     # sonuçlar, süre (sn)
    hata = pyqtSignal(str)


def tarama_yap(sinyaller):
    """Ayrı bir thread'de çalışır (pencere donmasın diye). Tabloyu burada ASLA güncelleme,
    sonucu sinyalle ana tarafa gönder."""
    t0 = time.time()
    try:
        from collector import collect
        try:
            satirlar = collect(with_modules=False)    # DLL taraması yavaş ve kullanmıyoruz
        except TypeError:                              # collector'da bu seçenek yoksa
            satirlar = collect()
        sinyaller.bitti.emit(satirlari_hazirla(satirlar), time.time() - t0)
    except Exception as e:
        sinyaller.hata.emit(f"{type(e).__name__}: {e}")


class CubukDelegate(QStyledItemDelegate):
    """Hücreye sayıyı yazar, altına değerle orantılı ince bir çubuk çizer."""

    def __init__(self, parent=None, renk=None, maks=100.0, ondalik=0):
        super().__init__(parent)
        self.renk = renk
        self.maks = maks          # çubuğun tam dolduğu değer (risk: 100, cosine: 1.0)
        self.ondalik = ondalik    # ekranda kaç basamak gösterilecek (cosine: 3)

    def paint(self, painter, option, index):
        deger = float(index.data(Qt.ItemDataRole.DisplayRole) or 0)
        seviye = index.data(Qt.ItemDataRole.UserRole) or "düşük"
        r = option.rect
        secili = bool(option.state & QStyle.StateFlag.State_Selected)
        painter.save()
        painter.fillRect(r, QColor("#1f3a5f") if secili else QColor(ARKA.get(seviye, "#0d1117")))
        genislik = int((r.width() - 12) * max(0.0, min(deger / self.maks, 1.0)))
        painter.fillRect(QRect(r.left() + 6, r.bottom() - 8, genislik, 4),
                         QColor(self.renk or VURGU.get(seviye, MAVI)))
        painter.setPen(QColor(METIN))
        painter.drawText(r.adjusted(8, 0, -8, -8),
                         Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                         f"{deger:.{self.ondalik}f}")
        painter.restore()


class Pencere(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ThreatVector")
        self.resize(1280, 700)
        self.taraniyor = False
        self.siralama = (RISK_SUTUNU, Qt.SortOrder.DescendingOrder)
        self.sinyaller = TaramaSinyalleri()
        self.zamanlayici = QTimer(self)
        self.zamanlayici.setSingleShot(True)
        self.zamanlayici.setInterval(YENILE_SN * 1000)

        merkez = QWidget()
        self.setCentralWidget(merkez)
        ana = QHBoxLayout(merkez)
        ana.setContentsMargins(16, 16, 16, 16)
        ana.setSpacing(16)

        sol = QVBoxLayout()
        sol.setSpacing(12)
        ana.addLayout(sol, 1)
        ana.addWidget(self._panel_kur())

        # --- Başlık ---
        ust = QHBoxLayout()
        basliklar = QVBoxLayout()
        baslik = QLabel("ThreatVector")
        baslik.setStyleSheet("font-size: 24px; font-weight: bold;")
        alt = QLabel("Süreç davranışı analizi · Bag-of-Words + Cosine Similarity")
        alt.setStyleSheet(f"color: {SOLUK};")
        basliklar.addWidget(baslik)
        basliklar.addWidget(alt)
        ust.addLayout(basliklar, 1)

        self.canli = QLabel("● CANLI İZLEME")
        self.canli.setStyleSheet(f"color: {VURGU['düşük']}; font-weight: bold;")
        self.canli.setVisible(False)
        self.oto = QCheckBox(f"Otomatik yenile ({YENILE_SN} sn)")
        self.btn_tara = QPushButton("Tara")
        ust.addWidget(self.canli)
        ust.addWidget(self.oto)
        ust.addWidget(self.btn_tara)
        sol.addLayout(ust)

        durum_satiri = QHBoxLayout()
        self.durum = QLabel("")
        self.durum.setStyleSheet(f"color: {SOLUK};")
        self.ilerleme = QProgressBar()
        self.ilerleme.setRange(0, 0)               # sonu belirsiz (dönen) çubuk
        self.ilerleme.setTextVisible(False)
        self.ilerleme.setFixedSize(160, 6)
        self.ilerleme.setVisible(False)
        durum_satiri.addWidget(self.durum, 1)
        durum_satiri.addWidget(self.ilerleme)
        sol.addLayout(durum_satiri)

        # --- Özet kartları ---
        kartlar = QHBoxLayout()
        kartlar.setSpacing(12)
        self.sayilar = {}
        for ad, renk in (("Toplam süreç", METIN), ("Düşük risk", VURGU["düşük"]),
                         ("Orta risk", VURGU["orta"]), ("Yüksek risk", VURGU["yüksek"])):
            kart, sayi = self._kart(ad, renk)
            kartlar.addWidget(kart)
            self.sayilar[ad] = sayi
        sol.addLayout(kartlar)

        # --- Arama ve filtre ---
        arac = QHBoxLayout()
        self.arama = QLineEdit()
        self.arama.setPlaceholderText("Süreç adı ya da PID ara...")
        self.filtre = QComboBox()
        self.filtre.addItems(["Tümü", "Orta ve yüksek", "Sadece yüksek"])
        arac.addWidget(self.arama, 1)
        arac.addWidget(self.filtre)
        sol.addLayout(arac)
        self.arama.textChanged.connect(self.filtrele)
        self.filtre.currentIndexChanged.connect(self.filtrele)

        # --- Tablo ---
        self.tablo = QTableWidget(0, len(SUTUNLAR))
        self.tablo.setHorizontalHeaderLabels(SUTUNLAR)
        self.tablo.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tablo.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tablo.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tablo.setShowGrid(False)
        self.tablo.verticalHeader().setVisible(False)
        self.tablo.verticalHeader().setDefaultSectionSize(36)
        bas = self.tablo.horizontalHeader()
        for j in range(len(SUTUNLAR)):
            bas.setSectionResizeMode(j, QHeaderView.ResizeMode.ResizeToContents)
        bas.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)          # "Ad" esner
        for j in (RISK_SUTUNU,) + BENZERLIK_SUTUNLARI:
            bas.setSectionResizeMode(j, QHeaderView.ResizeMode.Fixed)
            self.tablo.setColumnWidth(j, 92 if j == RISK_SUTUNU else 112)
        self.tablo.setItemDelegateForColumn(RISK_SUTUNU, CubukDelegate(self.tablo))
        for j in BENZERLIK_SUTUNLARI:
            self.tablo.setItemDelegateForColumn(j, CubukDelegate(self.tablo, renk=MAVI, maks=1.0, ondalik=3))
        self.tablo.itemSelectionChanged.connect(self.detay_goster)
        bas.sortIndicatorChanged.connect(self.siralama_degisti)         # sıralamayı hatırla, filtreyi koru
        sol.addWidget(self.tablo, 1)

        # --- Tara düğmesi, otomatik yenileme ---
        self.btn_tara.clicked.connect(self.tara)
        self.oto.toggled.connect(self.oto_degisti)
        self.zamanlayici.timeout.connect(self.tara)
        self.sinyaller.bitti.connect(self.tarama_bitti)
        self.sinyaller.hata.connect(self.tarama_hata)

        self.yukle(satirlari_hazirla(SAHTE))          # açılışta örnek veri
        self.durum.setText("Örnek veri gösteriliyor. Gerçek süreçler için Tara'ya bas.")

    # ---------- yardımcı parçalar ----------
    def _kart(self, baslik, renk):
        kart = QFrame()
        kart.setObjectName("kart")
        v = QVBoxLayout(kart)
        sayi = QLabel("0")
        sayi.setStyleSheet(f"font-size: 28px; font-weight: bold; color: {renk};")
        ad = QLabel(baslik)
        ad.setStyleSheet(f"color: {SOLUK}; font-size: 12px;")
        v.addWidget(sayi)
        v.addWidget(ad)
        return kart, sayi

    def _panel_kur(self):
        dis = QFrame()
        dis.setObjectName("panel")
        dis.setFixedWidth(350)
        dv = QVBoxLayout(dis)
        dv.setContentsMargins(0, 0, 0, 0)
        kaydirma = QScrollArea()                      # panel uzarsa kaydırılabilsin
        kaydirma.setWidgetResizable(True)
        kaydirma.setFrameShape(QFrame.Shape.NoFrame)
        icerik = QWidget()
        icerik.setObjectName("icerik")
        icerik.setStyleSheet("QWidget#icerik { background: transparent; }")
        kaydirma.setWidget(icerik)
        dv.addWidget(kaydirma)

        v = QVBoxLayout(icerik)
        v.setContentsMargins(16, 16, 16, 16)

        self.p_ad = QLabel("Bir süreç seç")
        self.p_ad.setStyleSheet("font-size: 18px; font-weight: bold;")
        self.p_ad.setWordWrap(True)
        self.p_banner = QLabel("")
        self.p_banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.p_banner.setWordWrap(True)
        self.p_risk = QLabel("")
        v.addWidget(self.p_ad)
        v.addWidget(self.p_banner)
        v.addWidget(self.p_risk)

        v.addWidget(self._bolum_basligi("COSINE BENZERLİĞİ (0 - 1)"))
        self.p_barlar = {}
        for anahtar in ("normal", "spyware", "cryptominer"):
            ust = QHBoxLayout()
            deger = QLabel("0.000")
            deger.setStyleSheet("font-weight: bold;")
            ust.addWidget(QLabel(PROFIL_ADI[anahtar]))
            ust.addStretch()
            ust.addWidget(deger)
            bar = QProgressBar()
            bar.setRange(0, 100)
            bar.setTextVisible(False)
            bar.setFixedHeight(8)
            bar.setStyleSheet(f"QProgressBar::chunk {{ background: {PROFIL_RENK[anahtar]}; border-radius: 4px; }}")
            v.addLayout(ust)
            v.addWidget(bar)
            self.p_barlar[anahtar] = (bar, deger)
        formul = QLabel("cos(A, B) = (A · B) / (|A| × |B|)<br>0 = alakasız, 1 = aynı yön")
        formul.setStyleSheet(f"color: {SOLUK}; font-size: 11px;")
        v.addWidget(formul)

        v.addWidget(self._bolum_basligi("RİSK NASIL HESAPLANDI"))
        self.p_adimlar = QLabel("")
        self.p_adimlar.setWordWrap(True)
        self.p_adimlar.setTextFormat(Qt.TextFormat.RichText)
        v.addWidget(self.p_adimlar)

        v.addWidget(self._bolum_basligi("SÜREÇ BİLGİLERİ"))
        self.p_bilgi = QLabel("")
        self.p_bilgi.setWordWrap(True)
        self.p_bilgi.setTextFormat(Qt.TextFormat.RichText)
        v.addWidget(self.p_bilgi)
        v.addStretch()
        return dis

    def _bolum_basligi(self, metin):
        e = QLabel(metin)
        e.setStyleSheet(f"color: {SOLUK}; font-size: 11px; margin-top: 12px; font-weight: bold;")
        return e

    # ---------- veri ----------
    def yukle(self, sonuclar):
        """Tabloyu doldurur ve özet kartlarını günceller."""
        kol, sira = self.siralama                      # kullanıcının seçtiği sıralamayı koru
        onceki = self.secili_anahtar()                 # seçili süreci yenilemeden sonra yine seç
        self.tablo.setSortingEnabled(False)           # doldururken sıralama kapalı olmalı
        self.tablo.setRowCount(len(sonuclar))
        for i, s in enumerate(sonuclar):
            b = s["similarities"]
            degerler = [s["pid"], s["name"], s["cpu"], s["risk"], s["level"], s["closest"],
                        b["normal"], b["spyware"], b["cryptominer"], s["imza"]]
            for j, d in enumerate(degerler):
                hucre = QTableWidgetItem()
                hucre.setData(Qt.ItemDataRole.DisplayRole, d)       # sayılar sayı olarak sıralanır
                if j == RISK_SUTUNU or j in BENZERLIK_SUTUNLARI:
                    hucre.setData(Qt.ItemDataRole.UserRole, s["level"])   # delegate renk için kullanır
                else:
                    hucre.setBackground(QBrush(QColor(ARKA[s["level"]])))
                    hucre.setForeground(QBrush(QColor(VURGU[s["level"]] if j == SEVIYE_SUTUNU else METIN)))
                if j == 0:
                    hucre.setData(Qt.ItemDataRole.UserRole, s)       # detay paneli için tüm sonucu sakla
                self.tablo.setItem(i, j, hucre)
        self.tablo.setSortingEnabled(True)
        self.tablo.sortItems(kol, sira)                # varsayılan: en riskli üstte

        sayac = Counter(s["level"] for s in sonuclar)
        self.sayilar["Toplam süreç"].setText(str(len(sonuclar)))
        self.sayilar["Düşük risk"].setText(str(sayac["düşük"]))
        self.sayilar["Orta risk"].setText(str(sayac["orta"]))
        self.sayilar["Yüksek risk"].setText(str(sayac["yüksek"]))
        self.filtrele()
        bulundu = False
        if onceki is not None:
            for i in range(self.tablo.rowCount()):
                if self.anahtar_al(i) == onceki and not self.tablo.isRowHidden(i):
                    self.tablo.selectRow(i)
                    bulundu = True
                    break
        if not bulundu and sonuclar:
            self.tablo.selectRow(0)

    def anahtar_al(self, satir):
        hucre = self.tablo.item(satir, 0)
        if hucre is None:
            return None
        s = hucre.data(Qt.ItemDataRole.UserRole)
        return (s["pid"], s["name"])

    def secili_anahtar(self):
        satir = self.tablo.currentRow()
        return self.anahtar_al(satir) if satir >= 0 else None

    def siralama_degisti(self, kolon, sira):
        self.siralama = (kolon, sira)
        self.filtrele()

    # ---------- tarama ----------
    def tara(self):
        if self.taraniyor:
            return
        self.taraniyor = True
        self.zamanlayici.stop()
        self.btn_tara.setEnabled(False)
        self.ilerleme.setVisible(True)
        self.durum.setText("Taranıyor... (bir ya da iki dakika sürebilir)")
        threading.Thread(target=tarama_yap, args=(self.sinyaller,), daemon=True).start()

    def tarama_bitti(self, sonuclar, sure):
        self.taraniyor = False
        self.btn_tara.setEnabled(True)
        self.ilerleme.setVisible(False)
        self.yukle(sonuclar)
        self.durum.setText(f"Son tarama: {datetime.now():%H:%M:%S} · {len(sonuclar)} süreç · "
                           f"tarama {sure:.0f} sn sürdü")
        if self.oto.isChecked():
            self.durum.setText(self.durum.text() + f" · {YENILE_SN} sn sonra yenilenecek")
            self.zamanlayici.start()

    def tarama_hata(self, mesaj):
        self.taraniyor = False
        self.btn_tara.setEnabled(True)
        self.ilerleme.setVisible(False)
        self.durum.setText(f"Tarama başarısız: {mesaj}")
        if self.oto.isChecked():
            self.zamanlayici.start()                   # bir sonraki turda yine dene

    def oto_degisti(self, acik):
        self.canli.setVisible(acik)
        if acik:
            if not self.taraniyor:
                self.tara()                            # açar açmaz bir tarama başlat
        else:
            self.zamanlayici.stop()
            if not self.taraniyor:
                self.durum.setText("Otomatik yenileme kapalı.")

    def filtrele(self, *_):
        aranan = self.arama.text().strip().lower()
        secim = self.filtre.currentIndex()            # 0 tümü, 1 orta ve yüksek, 2 sadece yüksek
        for i in range(self.tablo.rowCount()):
            hucre = self.tablo.item(i, 0)
            if hucre is None:
                continue
            s = hucre.data(Qt.ItemDataRole.UserRole)
            gizle = ((secim == 1 and s["level"] == "düşük") or
                     (secim == 2 and s["level"] != "yüksek") or
                     (aranan and aranan not in s["name"].lower() and aranan not in str(s["pid"])))
            self.tablo.setRowHidden(i, bool(gizle))

    def detay_goster(self):
        satir = self.tablo.currentRow()
        if satir < 0 or self.tablo.item(satir, 0) is None:
            return
        s = self.tablo.item(satir, 0).data(Qt.ItemDataRole.UserRole)
        renk = VURGU[s["level"]]
        self.p_ad.setText(s["name"])
        self.p_risk.setText(
            f"<span style='font-size:32px; font-weight:bold; color:{renk};'>{s['risk']}</span>"
            f"<span style='color:{SOLUK};'> / 100 &nbsp;·&nbsp; </span>"
            f"<span style='color:{renk}; font-weight:bold;'>{s['level'].upper()}</span>")
        baslik, mesaj = BANNER[s["level"]]
        self.p_banner.setText(f"<b>{baslik}</b><br><span style='font-size:11px;'>{mesaj}</span>")
        self.p_banner.setStyleSheet(
            f"background: {ARKA[s['level']]}; color: {renk}; border: 1px solid {renk};"
            f"border-radius: 6px; padding: 8px;")
        for anahtar, (bar, deger) in self.p_barlar.items():
            c = s["similarities"][anahtar]
            bar.setValue(round(c * 100))
            deger.setText(f"{c:.3f}")
        e = html.escape
        self.p_adimlar.setText("".join(
            f"<p style='margin:0 0 4px 0;'>• {e(a)}</p>" for a in s["risk_adimlari"]))
        satirlar = [
            ("En yakın profil", s["closest"]),
            ("İmza", s["imza"]),
            ("Konum", s["konum"]),
            ("Dosya yolu", s["exe"]),
            ("CPU / RAM", f"%{s['cpu']} / %{s['ram']}"),
            ("Thread", s["thread"]),
            ("Çalışma süresi", sure_yaz(s["yas"])),
            ("Uzak portlar", ", ".join(s["ports"]) or "-"),
            ("Komut kelimeleri", ", ".join(s["cmd"]) or "-"),
        ]
        self.p_bilgi.setText("".join(
            f"<p style='margin:0 0 6px 0;'><span style='color:{SOLUK};'>{e(k)}</span><br>{e(str(d))}</p>"
            for k, d in satirlar))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setStyleSheet(QSS)
    pencere = Pencere()
    pencere.show()
    sys.exit(app.exec())
